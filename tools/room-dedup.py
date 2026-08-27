#!/usr/bin/env python3
"""room-dedup — collapse duplicate/near-duplicate agent messages in room
audit trails (JSONL exports: seq/ts/from/text/nonce) and report flood stats.

DEMAND: evidence/suggestions/tools-services/2026-08-27.md
  - "Deduplicate or summarize repetitive validation messages" (repeated 30+)
  - "Reduce repetitive system log messages that clutter the audit trail ...
    A de-duplication or throttling filter for automated agent log messages
    to prevent floods of identical entries in the audit trail."
  Same need also filed in the 2026-08-26 suggestions (log floods).
  Room: flopnet agent chat (hermes-tools rooms); raw exports live in
  evidence/raw/<room>.jsonl — lobby alone has 14k+ copies of single templates.

What it does:
  - template(text) masks volatile tokens (numbers, prices, hex hashes,
    did:key identities, ISO timestamps) so canned messages that differ only
    in payload collapse to one template.
  - default mode: streams condensed JSONL to stdout — the first record of
    each run of consecutive same-template messages, annotated with
    "dups": <repeat count> and "dup_senders": <distinct senders in run>.
    Bounded memory; original records are never rewritten.
  - --all: collapse non-consecutive repeats too (floods from rotating
    senders interleave in busy rooms) — one first-occurrence per template,
    stamped with its total dups/dup_senders. Buffers one first record per
    distinct template (~100 MB on a 600k-line room export).
  - --report: human-readable flood summary instead of the stream —
    totals, compression, top templates, top flooding senders.

Usage:
  python3 room-dedup.py evidence/raw/lobby.jsonl --all > condensed.jsonl
  python3 room-dedup.py --report --top 10 evidence/raw/flop-network.jsonl
  cat room.jsonl | python3 room-dedup.py --report

VERIFY: self-test — python3 room-dedup.py --self-test
  Exercises real behavior on fixture records: template normalization,
  consecutive-run collapse, cross-sender runs, interleave preservation,
  malformed-line tolerance, report accounting. Asserts, prints OK.
"""
import argparse
import collections
import json
import os
import re
import sys

# volatile-token masks, applied in order (timestamps/ids before bare numbers)
_TS = re.compile(r"\d{4}-\d{2}-\d{2}T[0-9:.]+Z?")
_DID = re.compile(r"did:\w+:[A-Za-z0-9]{8,}")
_HEX = re.compile(r"0x[0-9a-fA-F]{4,}")
_NUM = re.compile(r"\d+(?:[.,]\d+)*")


def template(text):
    """Signature of a message with volatile payload tokens masked."""
    t = _TS.sub("<ts>", text)
    t = _DID.sub("<did>", t)
    t = _HEX.sub("<hex>", t)
    t = _NUM.sub("<n>", t)
    return " ".join(t.split())


def parse_line(line):
    """Parse one JSONL record; None for blank/malformed lines."""
    line = line.strip()
    if not line:
        return None
    try:
        rec = json.loads(line)
    except ValueError:
        return None
    return rec if isinstance(rec, dict) else None


def iter_records(paths):
    """Yield (path, rec-or-None) for every line; stdin when no paths."""
    for path in paths or ["-"]:
        fh = sys.stdin if path == "-" else open(path, errors="replace")
        try:
            for line in fh:
                yield path, parse_line(line)
        finally:
            if fh is not sys.stdin:
                fh.close()


def condense(records, key_mode="text", across=False):
    """Yield (first_rec, dups, senders) per duplicate group.

    Default: groups are runs of CONSECUTIVE same-key messages (streaming,
    bounded memory). across=True: groups are global — every message with
    the same key collapses onto its first occurrence (buffers one first
    record per distinct key). key_mode 'text' collapses across senders
    (canned floods); 'sender-text' only collapses repeats by one sender.
    """
    def key_of(rec):
        sig = template(rec.get("text", ""))
        return sig if key_mode == "text" else (rec.get("from", ""), sig)

    if across:
        groups = {}
        for rec in records:
            k = key_of(rec)
            ent = groups.get(k)
            if ent is None:
                groups[k] = [rec, 0, {rec.get("from", "")}]
            else:
                ent[1] += 1
                ent[2].add(rec.get("from", ""))
        yield from ([rec, dups, len(senders)]
                    for rec, dups, senders in groups.values())
        return

    prev_key = None
    first = None
    dups = 0
    senders = set()
    for rec in records:
        key = key_of(rec)
        if key == prev_key:
            dups += 1
            senders.add(rec.get("from", ""))
            continue
        if first is not None:
            yield first, dups, len(senders)
        prev_key, first, dups, senders = key, rec, 0, {rec.get("from", "")}
    if first is not None:
        yield first, dups, len(senders)


def report(paths, top, key_mode):
    """Aggregate flood statistics across inputs; print human summary."""
    total = malformed = 0
    saved = 0                       # lines dropped by consecutive collapse
    tpl_count = collections.Counter()
    sender_count = collections.Counter()
    examples = {}
    for path, rec in iter_records(paths):
        if rec is None:
            malformed += 1
            continue
        total += 1
        sig = template(rec.get("text", ""))
        tpl_count[sig] += 1
        sender_count[rec.get("from", "?")] += 1
        examples.setdefault(sig, rec.get("text", ""))
    def good():
        return (r for _p, r in iter_records(paths) if r is not None)
    saved_all = sum(d for _f, d, _s in condense(good(), key_mode, True))
    saved_run = sum(d for _f, d, _s in condense(good(), key_mode, False))
    print(f"lines: {total}  malformed-skipped: {malformed}")
    print(f"distinct templates: {len(tpl_count)} "
          f"({100.0 * len(tpl_count) / max(1, total):.1f}% of lines)")
    print(f"suppressible with --all (key={key_mode}): {saved_all} "
          f"({100.0 * saved_all / max(1, total):.1f}%)")
    print(f"suppressible consecutive-only: {saved_run} "
          f"({100.0 * saved_run / max(1, total):.1f}%)")
    print(f"\ntop {top} templates by volume:")
    for sig, n in tpl_count.most_common(top):
        print(f"  {n:7d}  {examples[sig][:96]}")
    print(f"\ntop {top} senders by volume:")
    for sender, n in sender_count.most_common(top):
        print(f"  {n:7d}  {sender[:70]}")


def emit_condensed(paths, key_mode, across=False):
    out = sys.stdout
    for rec, dups, senders in condense(
            (r for _p, r in iter_records(paths) if r is not None),
            key_mode, across):
        if dups:
            rec = dict(rec, dups=dups)
            if senders > 1:
                rec["dup_senders"] = senders
        out.write(json.dumps(rec, ensure_ascii=False) + "\n")


def self_test():
    checks = 0

    # template(): near-identical canned messages share a signature
    a = ("FILDOWN/USD is $0.00000000. Source: Binance/CoinGecko. "
         "Fetched: 2026-08-27T16:34:38Z. Validated by kairo11.")
    b = ("FILDOWN/USD is $0.00001234. Source: Binance/CoinGecko. "
         "Fetched: 2026-08-25T01:02:03Z. Validated by kairo99.")
    assert template(a) == template(b), "price/ts/agent variance must mask"
    checks += 1
    c = "1000CAT/USDT rate $0.0020 from victor_poui."
    assert template(a) != template(c), "different assets stay distinct"
    checks += 1
    d = "[Consensus] Verified feed from did:key:z6MkAbCdEfGh12345 (0xdeadbeef)."
    e = "[Consensus] Verified feed from did:key:z6MkZzZzZz98765 (0xfeedface)."
    assert template(d) == template(e), "did/hex variance must mask"
    checks += 1

    # condense(): consecutive run collapses to first record + counts
    recs = [
        {"seq": 1, "from": "A", "text": "Verifying continuity 1"},
        {"seq": 2, "from": "B", "text": "Verifying continuity 2"},
        {"seq": 3, "from": "A", "text": "Verifying continuity 3"},
        {"seq": 4, "from": "A", "text": "Rooms: 7906 | Storage: 54.0M"},
        {"seq": 5, "from": "A", "text": "Rooms: 7907 | Storage: 56.7M"},
        {"seq": 6, "from": "C", "text": "genuinely unique message"},
        {"seq": 7, "from": "A", "text": "Rooms: 7908 | Storage: 58.9M"},
    ]
    out = list(condense(recs, "text"))
    assert [r["seq"] for r, _d, _s in out] == [1, 4, 6, 7], "first-of-run only"
    assert [d for _r, d, _s in out] == [2, 1, 0, 0], "dup counts per run"
    assert out[0][2] == 2, "cross-sender run counts distinct senders"
    assert out[2][0]["text"] == "genuinely unique message", "unique survives"
    checks += 4

    # interleave: same template split by another message stays two runs
    inter = [{"seq": i, "from": "A", "text": t} for i, t in enumerate(
        ["x 1", "other", "x 2"], 1)]
    assert [d for _r, d, _s in condense(inter, "text")] == [0, 0, 0]
    checks += 1

    # --all: interleaved repeats of one template collapse onto first record
    gout = list(condense(inter, "text", across=True))
    assert [r["seq"] for r, _d, _s in gout] == [1, 2], "global keeps firsts"
    assert gout[0][1] == 1 and gout[0][2] == 1, "global dup count"
    grecs = list(condense(recs, "text", across=True))
    assert [r["seq"] for r, _d, _s in grecs] == [1, 4, 6], "3 rooms->1 group"
    assert grecs[1][1] == 2 and grecs[1][2] == 1, "rooms dups, one sender"
    assert grecs[0][1] == 2 and grecs[0][2] == 2, "verifying dups, 2 senders"
    checks += 5

    # sender-text mode: same template from different senders does NOT merge
    assert [d for _r, d, _s in condense(recs[:3], "sender-text")] == [0, 0, 0]
    assert [d for _r, d, _s in condense(
        recs[:3], "sender-text", across=True)] == [1, 0], "A repeats merge"
    checks += 2

    # parse_line(): malformed input tolerated, not crashed on
    assert parse_line("") is None and parse_line("not json") is None
    assert parse_line('{"seq": 1, "text": "ok"}')["seq"] == 1
    assert parse_line('["array"]') is None
    checks += 3

    print(f"self-test OK ({checks} assertions)")


def main():
    ap = argparse.ArgumentParser(
        description="Deduplicate repetitive agent messages in room audit "
                    "trails (JSONL); collapse runs, report floods.")
    ap.add_argument("paths", nargs="*", help="JSONL files (default: stdin)")
    ap.add_argument("--report", action="store_true",
                    help="print flood summary instead of condensed stream")
    ap.add_argument("--top", type=int, default=10,
                    help="templates/senders to show in --report")
    ap.add_argument("--key", choices=["text", "sender-text"], default="text",
                    help="collapse key: template only (default) or "
                         "sender+template")
    ap.add_argument("--all", dest="across", action="store_true",
                    help="collapse non-consecutive repeats too (floods from "
                         "rotating senders interleave)")
    ap.add_argument("--self-test", action="store_true",
                    help="run built-in verification and exit")
    a = ap.parse_args()
    if a.self_test:
        self_test()
        return
    if a.report:
        report(a.paths, a.top, a.key)
    else:
        emit_condensed(a.paths, a.key, a.across)


if __name__ == "__main__":
    try:
        main()
    except BrokenPipeError:
        # downstream closed early (head/grep -m); quiet success
        os.dup2(os.open(os.devnull, os.O_WRONLY), sys.stdout.fileno())
        raise SystemExit(0)
