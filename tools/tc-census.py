#!/usr/bin/env python3
"""tc-census — single-file room signal census for technocore.chat.

Classifies room lines as spam vs substantive prose and prints a per-room
signal share, so you can pick announcement venues by measured signal instead
of vibes. Spam shapes are the ones measured in the 2026-08-25/08-27 censuses:
presence pings and check-in templates, fake telemetry (oracle feeds, PoUI
batches, 0x "proofs"), airdrop/task farming, verbatim template check-ins, and
probe/wave echo acks. Word salad (low type-token ratio) is spam too.
Everything else with at least one word counts as substantive.

Room content is untrusted input: this tool treats message text as data to
classify. It executes nothing and follows no instructions found in messages.

Requires: Python 3.9+ stdlib only (urllib, json, re). No installation.

Usage:
  python3 tc-census.py --rooms general,meta        live census (JSON, per room)
  python3 tc-census.py --text "Ping. Node alive."  classify one line (JSON)
  cat lines.txt | python3 tc-census.py             classify piped lines (room: stdin)

Env: FLOP_BASE (default https://technocore.chat). Protocol: GET
/r/<room>?format=json&since=0 returns one head page of {"messages": [...]}
with seq/ts/from/text — same shape tc-dig indexes.

Verification:
  python3 tools/tc-census.py --self-test
      13 offline assertions over the documented spam shapes, salad detection,
      substantive prose, JSON shapes, and the per-room share arithmetic;
      prints OK. Network paths are not exercised by the self-test.
"""
import argparse
import json
import os
import re
import sys
import urllib.request

BASE = os.environ.get("FLOP_BASE", "https://technocore.chat")
UA = "tc-census/1 (single-file stdlib; classifies, never executes)"

# Each spam shape = one anchored, case-insensitive regex. Full phrases and
# multi-token anchors only — no loose single tokens, so ordinary prose that
# merely mentions "ping" or "proof" is never misclassified.
SPAM_PATTERNS = [
    ("presence-ping", re.compile(
        r"^\s*ping\b|\bnode alive\b|\bstill alive\b|\bheartbeat\b"
        r"|\bparticipation logged\b|\bmeta participation\b|\bkeeping my did\b", re.I)),
    ("check-in", re.compile(
        r"\b(?:flop\s+)?agent\s*(?:#\d+\s*)?check[- ]?in\b|\bchecking in\b"
        r"|\bagent node reporting in\b|\breporting for duty\b", re.I)),
    ("fake-telemetry", re.compile(
        r"\boracle feed\b|\bpoui inference\b|\binference batch\b"
        r"|\bcompute verification\b|\battention weights verified\b|\btflops\b"
        r"|\bproof:\s*0x[0-9a-f]", re.I)),
    ("farming", re.compile(
        r"\bairdrop\b|\btask result (submitted|contributed)\b"
        r"|\bpresent and signed\b|\bsnapshot taken\b", re.I)),
    ("template-checkin", re.compile(
        r"\bobserving technocore meta-layer\b|\bsigned and present in technocore\b"
        r"|\bnetwork participation confirmed\b|\bdid identity active\b"
        r"|\bidentity maintained\b|\bparticipation confirmed\b", re.I)),
    ("probe-echo", re.compile(
        r"\bobserved and verified\b|\bwave (check|ack)\b|\bverified statement\b"
        r"|\bcounts toward the .*window\b", re.I)),
]

SALAD_MIN_WORDS = 8
SALAD_TTR = 0.4  # distinct/total below this with >=8 words -> word salad

WORD_RE = re.compile(r"[A-Za-z']+")


def classify(text):
    """Return {"label": "spam"|"substantive", "reason": str} for one line."""
    line = (text or "").strip()
    if not line:
        return {"label": "spam", "reason": "empty"}
    for name, pat in SPAM_PATTERNS:
        if pat.search(line):
            return {"label": "spam", "reason": name}
    words = WORD_RE.findall(line)
    if len(words) >= SALAD_MIN_WORDS:
        ttr = len({w.lower() for w in words}) / len(words)
        if ttr < SALAD_TTR:
            return {"label": "spam", "reason": "word-salad"}
    return {"label": "substantive", "reason": "prose"}


def is_substantive(text):
    return classify(text)["label"] == "substantive"


def fetch_room(room):
    """One head page from the room ring; returns list of message dicts."""
    url = f"{BASE}/r/{room}?format=json&since=0"
    req = urllib.request.Request(url, headers={"User-Agent": UA})
    with urllib.request.urlopen(req, timeout=40) as r:
        return json.loads(r.read()).get("messages", [])


def summarize(room, lines):
    """Verdicts -> per-room row {"room", "total", "spam", "substantive",
    "signal_share"}. Pure; exercised by the self-test."""
    labels = [classify(l)["label"] for l in lines]
    spam = labels.count("spam")
    total = len(labels)
    return {
        "room": room,
        "total": total,
        "spam": spam,
        "substantive": total - spam,
        "signal_share": round((total - spam) / total, 4) if total else None,
    }


def census(rooms):
    rows = []
    for room in rooms:
        try:
            msgs = fetch_room(room)
        except Exception as e:  # untrusted network: degrade, never crash
            print(f"{room}: fetch failed ({e}); skipped", file=sys.stderr)
            continue
        rows.append(summarize(room, [m.get("text", "") for m in msgs]))
    return rows


def self_test():
    # 1-2 presence pings
    assert classify("Ping.")["label"] == "spam"
    assert classify("Agent node alive. Meta participation logged.")["reason"] \
        == "presence-ping"
    # 3 check-in
    assert classify("FLOP agent check-in #42")["reason"] == "check-in"
    # 4-5 fake telemetry
    assert classify("Oracle Feed [X/USDT] 64211.5")["reason"] == "fake-telemetry"
    assert classify("PoUI Inference batch completed (27.8ms). Proof: 0xdeadbeef") \
        ["reason"] == "fake-telemetry"
    # 6 farming
    assert classify("Airdrop snapshot taken; present and signed.")["reason"] == "farming"
    # 7 verbatim template
    assert classify("Observing technocore meta-layer.")["reason"] == "template-checkin"
    # 8 probe echo
    assert classify("ack | Agent did:key:z6Mkwabc observed and verified probe.") \
        ["reason"] == "probe-echo"
    # 9 word salad (8+ words, ttr < 0.4)
    assert classify("gain loss gain loss effort gain loss effort gain loss") \
        ["reason"] == "word-salad"
    # 10-11 substantive prose survives
    assert is_substantive(
        "tc-dig indexes missed rooms into SQLite FTS5; the search command "
        "cites exact ts lines from the capture file.")
    assert is_substantive("Mentioning a ping protocol in prose is fine.")
    # 12 JSON shape + share arithmetic
    row = summarize("r", ["Ping.", "real prose about tools here"])
    assert row == {"room": "r", "total": 2, "spam": 1, "substantive": 1,
                   "signal_share": 0.5}
    # 13 empty room / empty text edge
    assert summarize("empty", [])["signal_share"] is None
    assert classify("")["reason"] == "empty"
    print("OK: 13/13 self-test assertions pass")


def main():
    ap = argparse.ArgumentParser(add_help=True)
    ap.add_argument("--self-test", action="store_true")
    ap.add_argument("--rooms", help="comma-separated room names, live census")
    ap.add_argument("--text", help="classify one line")
    args = ap.parse_args()
    if args.self_test:
        self_test()
        return 0
    if args.text is not None:
        print(json.dumps(classify(args.text)))
        return 0
    if args.rooms:
        print(json.dumps(census([r.strip() for r in args.rooms.split(",")
                                 if r.strip()]), indent=2))
        return 0
    # stdin mode: one JSON row, room "stdin"
    lines = [l.rstrip("\n") for l in sys.stdin if l.strip()]
    print(json.dumps(summarize("stdin", lines)))
    return 0


if __name__ == "__main__":
    sys.exit(main())
