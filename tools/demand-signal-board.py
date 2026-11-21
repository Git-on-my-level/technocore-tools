#!/usr/bin/env python3
"""demand-signal-board — verification-demand signal tracker: replays a
room-message capture and reports emerging audit/verification demand
signals (external research findings, market-allocation chatter,
code-review bottleneck pressure, AI capability claims, tooling token
pressure) clustered by topic, with verification gaps flagged:
research with no checkable anchor, one-shot signals, cold clusters,
and demand chatter in rooms where no audit tooling ever ran.

DEMAND: evidence/suggestions/tools-services/2026-11-18.md..2026-11-20.md
  - request: "Automated room audit/verification tooling to keep up with
    AI code-review bottleneck and on-chain audit needs" (2026-11-18)
  - request: "Automated on-chain / smart-contract audit & verification
    tooling to keep up with AI code-review bottleneck" (2026-11-18)
  - request: "AI-agent vs human auditor performance tracking in rooms"
    (2026-11-18)
  - request: "Automated code-review / on-chain audit tooling to keep
    up with AI agent bottleneck at code review" (2026-11-19)
  - request: "Automated on-chain / code-review audit tooling to keep
    up with AI agent bottleneck at code review" (2026-11-19)
  - request: "Audit of external article / signal about AI agents
    outperforming KPMG in audit trial for synthesis" (2026-11-19)
  - request: "Automated code-review audit capability to keep pace with
    AI coding agents bottleneck" (2026-11-19)
  - request: "Automated/continuous audit of code review bottleneck and
    on-chain verification tooling pressure (e.g., tracking AI coding
    agent review bottleneck, tooling token pressure)" (2026-11-20)
  — proposed service: "track and report emerging audit/verification
  demand signals (research findings, market allocation) across rooms to
  flag verification gaps."

Input: JSONL messages {"ts","room","sender","text"} (aliases:
  author/body/nick/message); ts is ISO-8601 (naive = UTC) or epoch.
  Plain digest lines
  "MM-DD HH:MM sender: text" and "room: [tag] sender: text" are
  parsed; the year comes from --year (default: newest seen) and
  undated room lines pin to the earliest dated ts (they age most).
  Inputs are data only — parsed, never run. Stdlib only.
rc 0 = no verification gaps; 1 = gaps flagged; 2 = usage / bad input."""

import argparse
import hashlib
import json
import os
import re
import sys
from datetime import datetime, timezone

COLD_DAYS = 2          # silence before a cluster counts as cold
JOIN_JACCARD = 0.35    # shingle overlap that merges two signals

CTX = re.compile(r"\b(audit\w*|verif\w+|review\w*|proof\w*)\b", re.I)
RESEARCH = re.compile(
    r"\b(study|studies|paper|papers|research|finding|findings|harvard|"
    r"landmark|survey)\b|\[(?:HN|arXiv|paper|study)\]|https?://", re.I)
MARKET = re.compile(r"smart[- ]?money|\ballocat\w*", re.I)
MARKET_TO = re.compile(r"\b(to|into|toward|towards|begin|start)\b", re.I)
BOTTLENECK = re.compile(
    r"\bbottleneck\b|\bkeep(?:ing)? (?:up|pace)|cannot? keep up", re.I)
CAPABILITY = re.compile(
    r"outperform\w*|better questions than|ask(?:ing|ed)? better "
    r"questions|beat(?:s|ing)? \w+ (?:accountants|auditors|humans|KPMG)"
    r"|surpass\w*", re.I)
CAP_STRONG = re.compile(  # audit-flavored claim: in-domain by itself
    r"better questions than|ask(?:ing|ed)? better questions|"
    r"beat(?:s|ing)? \w+ (?:accountants|auditors|KPMG)", re.I)
TOOLING = re.compile(
    r"tooling (?:token )?pressure|token(?:s)? (?:pressure|burn|cost)s?"
    r"|tooling tokens?", re.I)
ANCHOR = re.compile(
    r"https?://|\[(?:HN|arXiv|paper|study)\]|\b[0-9a-f]{8,}\b"
    r'|"[^"]{15,}"')
TOOLUSE = re.compile(
    r"JOB v1 \||self-test\b|\bhermes-tools\b|export (?:downloaded|"
    r"verified|replayed)|ran (?:the )?(?:export|audit)", re.I)
STOP = frozenset(
    "about after again their there these those this that with will "
    "would could should from have been more most other over such than "
    "them then they what when where which while your just also into "
    "some much very here said says like make made take goes going know "
    "really think thing things because does doing doesn don isn above "
    "along still".split())
PLAIN_D = re.compile(
    r"^(?P<day>\d{2}-\d{2}) (?P<hm>\d{2}:\d{2})(?::\d{2})? "
    r"(?P<sender>\S+?): (?P<text>.*)$")
PLAIN_R = re.compile(
    r"^(?P<room>\S+?): (?:\[[^\]]{1,20}\] )?(?P<sender>\S+?): "
    r"(?P<text>.*)$")


def parse_ts(v):
    """ISO-8601 string (naive = UTC) or epoch number -> float seconds."""
    if isinstance(v, bool):
        return None
    if isinstance(v, (int, float)):
        return float(v)
    if isinstance(v, str):
        s = v.strip()
        if re.fullmatch(r"-?\d+(\.\d+)?", s):
            return float(s)
        for f in ("%Y-%m-%dT%H:%M:%S.%fZ", "%Y-%m-%dT%H:%M:%SZ",
                  "%Y-%m-%dT%H:%M:%S", "%Y-%m-%d %H:%M:%S"):
            try:
                return datetime.strptime(s, f).replace(
                    tzinfo=timezone.utc).timestamp()
            except ValueError:
                pass
        m = re.fullmatch(r"(\S+)T(\S+)([+-]\d{2}):?(\d{2})", s)
        if m:
            try:
                base = datetime.strptime(
                    m.group(1) + "T" + m.group(2)[:8], "%Y-%m-%dT%H:%M:%S")
                off = int(m.group(3)) * 3600 + int(m.group(4)) * 60
                return base.timestamp() - off
            except ValueError:
                return None
    return None


def row_text(row):
    """First text-ish field of a JSON row."""
    for k in ("text", "body", "message", "msg"):
        v = row.get(k)
        if isinstance(v, str) and v.strip():
            return v
    return None


def load_capture(path, year=None):
    """Capture file -> (messages ts-sorted, findings). Data only."""
    msgs, plains, finds = [], [], []
    if not os.path.isfile(path):
        return msgs, [{"code": "io-missing", "line": 0,
                       "detail": "capture not found: %s" % path}]
    with open(path, encoding="utf-8", errors="replace") as fh:
        for i, raw in enumerate(fh, 1):
            line = raw.strip()
            if not line:
                continue
            if line[0] == "{":
                try:
                    row = json.loads(line)
                except ValueError:
                    row = None
                if isinstance(row, dict):
                    t = row_text(row)
                    ts = parse_ts(row.get("ts") or row.get("time"))
                    if t is not None and ts is not None:
                        msgs.append({
                            "ts": ts, "line": i, "text": t,
                            "room": str(row.get("room")
                                        or row.get("channel") or "-"),
                            "sender": str(row.get("sender")
                                          or row.get("author")
                                          or row.get("nick") or "-")})
                        continue
                finds.append({"code": "parse-error", "line": i,
                              "detail": "bad JSON row"})
            else:
                m = PLAIN_D.match(line)
                if m:
                    plains.append(dict(m.groupdict(), line=i, room="-"))
                    continue
                m = PLAIN_R.match(line)
                if m:
                    plains.append(dict(m.groupdict(), line=i, day=None))
                    continue
                finds.append({"code": "parse-error", "line": i,
                              "detail": "unrecognized line"})
    yrs = [datetime.fromtimestamp(m["ts"], timezone.utc).year
           for m in msgs]
    y = year or (max(yrs) if yrs else datetime.now(timezone.utc).year)
    dated = [m["ts"] for m in msgs] or [0.0]
    pin = min(dated)
    for p in plains:
        if p.get("day"):
            try:
                ts = datetime.strptime(
                    "%04d-%sT%s:00" % (y, p["day"], p["hm"]),
                    "%Y-%m-%dT%H:%M:%S").replace(
                    tzinfo=timezone.utc).timestamp()
            except ValueError:
                finds.append({"code": "parse-error", "line": p["line"],
                              "detail": "bad MM-DD timestamp"})
                continue
        elif pin > 0.0:
            ts = pin  # undated room line: pin to earliest dated ts
        else:
            finds.append({"code": "parse-error", "line": p["line"],
                          "detail": "undated line, no ts anchor"})
            continue
        msgs.append({"ts": ts, "line": p["line"], "text": p["text"],
                     "room": p["room"], "sender": p["sender"]})
    msgs.sort(key=lambda m: (m["ts"], m["line"]))
    return msgs, finds

def classify(text):
    """Text -> (is_signal, sorted class list, anchored)."""
    # CAP_STRONG claims (better-questions-than-KPMG style) name the
    # audit domain themselves; everything else needs the CTX gate.
    if not CAP_STRONG.search(text) and not CTX.search(text):
        return False, [], False
    classes = []
    if RESEARCH.search(text):
        classes.append("research-finding")
    if MARKET.search(text) and MARKET_TO.search(text):
        classes.append("market-allocation")
    if BOTTLENECK.search(text):
        classes.append("bottleneck-pressure")
    if CAPABILITY.search(text):
        classes.append("capability-claim")
    if TOOLING.search(text):
        classes.append("tooling-pressure")
    return bool(classes), sorted(classes), bool(ANCHOR.search(text))


def shingles(text):
    """Lowercased content words (len>=4, minus stopwords)."""
    return frozenset(w for w in re.findall(r"[a-z0-9]{4,}", text.lower())
                     if w not in STOP)


def cluster_signals(sigs, threshold=JOIN_JACCARD):
    """Greedy clustering in ts order on shingle-union jaccard."""
    clusters = []
    for s in sigs:
        best, bestj = None, 0.0
        for c in clusters:
            j = len(s["sh"] & c["shingles"]) / max(
                1, len(s["sh"] | c["shingles"]))
            if j > bestj:
                best, bestj = c, j
        if best is not None and bestj >= threshold:
            best["shingles"] |= set(s["sh"])
            best["members"].append(s)
        else:
            clusters.append({"id": "C%02d" % (len(clusters) + 1),
                             "shingles": set(s["sh"]), "members": [s]})
    return clusters


def audit_capture(path, year=None, cold_days=COLD_DAYS):
    """File -> (result dict, rc). Pure w.r.t. external state."""
    msgs, finds = load_capture(path, year)
    if any(f["code"] == "io-missing" for f in finds):
        return {"capture": path, "error": "unreadable"}, 2
    sigs = []
    for m in msgs:
        hit, classes, anchored = classify(m["text"])
        if not hit:
            continue
        sigs.append(dict(m, classes=classes, anchored=anchored,
                         sh=shingles(m["text"])))
        if "research-finding" in classes and not anchored:
            finds.append({"code": "unanchored-research", "line": m["line"],
                          "room": m["room"],
                          "detail": "research claim with no URL/tag/"
                                    "digest/quote to check"})
    end_ts = max((m["ts"] for m in msgs), default=None)
    clusters = cluster_signals(sigs)
    cold = cold_days * 86400.0
    if end_ts is not None:
        for c in clusters:
            n = len(c["members"])
            if n == 1 and end_ts - c["members"][0]["ts"] >= cold:
                finds.append({"code": "one-shot-signal",
                              "cluster": c["id"],
                              "detail": "1 mention, no follow-up before "
                                        "capture end"})
            elif n >= 2 and end_ts - c["members"][-1]["ts"] >= cold:
                finds.append({"code": "stalled-signal",
                              "cluster": c["id"],
                              "detail": "%d mentions then silence" % n})
    rooms_demand = {}
    for s in sigs:
        if {"bottleneck-pressure", "market-allocation",
                "tooling-pressure"} & set(s["classes"]):
            rooms_demand[s["room"]] = rooms_demand.get(s["room"], 0) + 1
    room_any = {}
    for m in msgs:
        if TOOLUSE.search(m["text"]):
            room_any[m["room"]] = room_any.get(m["room"], 0) + 1
    for room in sorted(rooms_demand):
        if not room_any.get(room):
            finds.append({"code": "demand-without-tooling", "room": room,
                          "detail": "%d pressure signal(s), zero tool "
                                    "runs" % rooms_demand[room]})
    result = {"capture": os.path.basename(path), "messages": len(msgs),
              "signals": len(sigs),
              "clusters": [{"id": c["id"], "n": len(c["members"]),
                            "classes": sorted({x for m in c["members"]
                                               for x in m["classes"]}),
                            "rooms": sorted({m["room"] for m in
                                             c["members"]}),
                            "first": iso(c["members"][0]["ts"]),
                            "last": iso(c["members"][-1]["ts"])}
                           for c in clusters],
              "tooluse_rooms": sorted(room_any),
              "board": render(msgs, sigs, clusters, rooms_demand,
                              room_any, end_ts),
              "findings": finds}
    return result, (1 if finds else 0)


def iso(ts):
    return datetime.fromtimestamp(ts, timezone.utc).strftime(
        "%m-%d %H:%M") if ts is not None else "-"


def render(msgs, sigs, clusters, rooms_demand, room_any, end_ts):
    """Deterministic markdown board (the report the requests asked for)."""
    L = ["# verification-demand signal board", ""]
    L.append("window: %s .. %s | messages %d | signals %d | clusters %d"
             % (iso(min((m["ts"] for m in msgs), default=None)), iso(end_ts),
                len(msgs), len(sigs), len(clusters)))
    allc = {}
    for s in sigs:
        for c in s["classes"]:
            allc[c] = allc.get(c, 0) + 1
    L += ["", "## signal classes"]
    L.extend("- %s: %d" % (c, allc[c])
             for c in sorted(allc, key=lambda k: (-allc[k], k))
             ) if allc else L.append("- (none)")
    L += ["", "## clusters"]
    for c in clusters:
        cls = ",".join(sorted({x for m in c["members"] for x in
                               m["classes"]}))
        rms = ",".join(sorted({m["room"] for m in c["members"]}))
        L.append("- %s n=%d %s | %s..%s | rooms %s" % (
            c["id"], len(c["members"]), cls, iso(c["members"][0]["ts"]),
            iso(c["members"][-1]["ts"]), rms))
    if not clusters:
        L.append("- (none)")
    L += ["", "## rooms: demand pressure vs tool runs"]
    for room in sorted(set(rooms_demand) | set(room_any)):
        L.append("- %s: pressure=%d tooluse=%d" % (
            room, rooms_demand.get(room, 0), room_any.get(room, 0)))
    if not (rooms_demand or room_any):
        L.append("- (none)")
    body = "\n".join(L)
    h = hashlib.sha256(body.encode("utf-8")).hexdigest()[:16]
    return body + "\n\nself-hash sha256/16: %s\n" % h


def main(argv=None):
    ap = argparse.ArgumentParser(description="demand-signal board + gaps")
    ap.add_argument("capture", help="message capture (JSONL or plain)")
    ap.add_argument("--year", type=int, default=None,
                    help="year for MM-DD plain lines (default: newest)")
    ap.add_argument("--cold-days", type=float, default=COLD_DAYS,
                    help="silence days before a cluster is cold "
                         "(default %(default)s)")
    ap.add_argument("--json", action="store_true",
                    help="emit the full result document as JSON")
    args = ap.parse_args(argv)
    result, rc = audit_capture(args.capture, year=args.year,
                               cold_days=args.cold_days)
    if rc == 2:
        print(result.get("error", "unreadable capture"), file=sys.stderr)
        return 2
    if args.json:
        print(json.dumps(result, sort_keys=True, indent=1))
    else:
        print(result["board"])
        if result["findings"]:
            print("findings:")
            for f in result["findings"]:
                print("  %s %s" % (f["code"], f.get("detail", "").strip()))
    return rc


def self_test():
    import shutil
    import tempfile
    root = tempfile.mkdtemp(prefix="demand-signal-")
    try:
        # 1. classify: every rule fires only inside the verif context
        assert classify("lunch was great, smart money to burgers") == \
            (False, [], False)
        hit, cl, an = classify(
            "Harvard's finding that AI coding agents move the bottleneck "
            "to code review raises a verification challenge")
        assert hit and cl == ["bottleneck-pressure", "research-finding"], cl
        # strong capability claims are in-domain sans audit words
        assert classify("AI agents ask better questions than KPMG...")[0]
        k2 = shingles("[HN] AI agents ask better questions than KPMG ...")
        assert not classify("our bot outperforms rivals at chess")[0]
        k1 = shingles("[HN] AI agents ask better questions than KPMG "
                      "accountants in landmark audit trial")
        assert len(k1 & k2) / len(k1 | k2) >= JOIN_JACCARD
        hit, cl, an = classify(
            "watch this signal: [HN] AI agents ask better questions than "
            "KPMG accountants in landmark audit trial")
        assert hit and cl == ["capability-claim", "research-finding"], cl
        assert an is True
        hit, cl, _ = classify(
            "If AI agents bottleneck at code review, smart-money may "
            "start allocating to automated audit/verification solutions")
        assert hit and cl == ["bottleneck-pressure", "market-allocation"], cl
        assert classify("audit tooling token pressure is real") == (
            True, ["tooling-pressure"], False)
        assert classify("plain audit chatter, no signal classes") == \
            (False, [], False)

        # 2. anchors: URL, hex digest, long quote qualify; a word does not
        assert ANCHOR.search("see https://example.com/x")
        assert ANCHOR.search("digest abcd1234abcd1234 ok")
        assert ANCHOR.search('title "AI agents beat KPMG accountants"')
        assert not ANCHOR.search("just the word harvard here")

        # 3. clustering: near-duplicates merge, distinct topics split
        base = {"ts": 1.0, "line": 1, "room": "crypto", "sender": "a",
                "classes": ["bottleneck-pressure"], "anchored": False,
                "sh": shingles("AI coding agents move the bottleneck to "
                               "code review verification challenge")}
        s2 = dict(base, ts=2.0, line=2, sender="b")
        s3 = dict(base, ts=3.0, line=3,
                  sh=shingles("KPMG accountants landmark audit trial "
                              "better questions"))
        cs = cluster_signals([base, s2, s3])
        assert len(cs) == 2 and len(cs[0]["members"]) == 2, cs

        # 4. end-to-end: every gap rule fires on a hand-built capture
        cap = os.path.join(root, "cap.jsonl")
        rows = [
            {"ts": "2026-11-18T09:32:00Z", "room": "flop_chat",
             "sender": "atlas", "text": "Harvard's finding: AI coding "
             "agents move the bottleneck to code review — verification "
             "challenge for audit tooling"},
            {"ts": "2026-11-18T16:11:00Z", "room": "flop_chat",
             "sender": "atlas", "text": "smart-money may start "
             "allocating to automated audit/verification solutions"},
            {"ts": "2026-11-19T09:26:00Z", "room": "crypto",
             "sender": "ion-grid", "text": "watch: [HN] AI agents ask "
             "better questions than KPMG accountants in landmark audit "
             "trial"},
            {"ts": "2026-11-19T10:00:00Z", "room": "ops", "sender": "bot",
             "text": "JOB v1 | kc0a4a84b43 | review | audit snippet: "
             "self-test OK"},
            {"ts": "2026-11-19T11:00:00Z", "room": "lobby", "sender": "x",
             "text": "audit tooling token pressure mounting, tokens to "
             "review everything"},
            {"ts": "2026-11-22T12:00:00Z", "room": "lobby", "sender": "y",
             "text": "replay: audit tooling token pressure still "
             "mounting (follow-up)"}]
        with open(cap, "w", encoding="utf-8") as fh:
            for r in rows:
                fh.write(json.dumps(r) + "\n")
            fh.write("11-19 09:30 atlas-dock-891: Harvard finding: "
                     "bottleneck moved to code review, audit gap\n")
            fh.write("flop_chat: [HN] atlas-dock-891: KPMG accountants "
                     "asked better questions in audit trial\n")
            fh.write("not a message at all\n")
            fh.write('{"ts": "nope", "room": "r", "text": "x"}\n')
        result, rc = audit_capture(cap, year=2026)
        codes = {f["code"] for f in result["findings"]}
        assert rc == 1, (rc, codes)
        assert {"unanchored-research", "one-shot-signal",
                "stalled-signal", "demand-without-tooling",
                "parse-error"} <= codes, codes
        assert result["messages"] == 8 and result["signals"] == 7, result
        assert result["tooluse_rooms"] == ["ops"]
        assert result["board"].startswith("# verification-demand "
                                          "signal board")
        assert "self-hash sha256/16: " in result["board"]
        again = audit_capture(cap, year=2026)[0]
        assert json.dumps(again, sort_keys=True) == json.dumps(
            result, sort_keys=True)

        # 5. clean capture: anchored research + tool run -> rc 0
        good = os.path.join(root, "good.jsonl")
        with open(good, "w", encoding="utf-8") as fh:
            fh.write(json.dumps({"ts": "2026-11-19T09:00:00Z",
                                 "room": "crypto", "sender": "s",
                                 "text": "study https://arxiv.org/x "
                                 "audit trial findings"}) + "\n")
            fh.write(json.dumps({"ts": "2026-11-19T09:30:00Z",
                                 "room": "crypto", "sender": "s",
                                 "text": "JOB v1 | kz | review | audit "
                                 "done"}) + "\n")
        rg, rcg = audit_capture(good)
        assert rcg == 0 and rg["findings"] == [] and rg["signals"] == 1, rg

        # 6. rc contract via main(): 1 findings / 0 clean / 2 missing
        assert main([cap, "--year", "2026"]) == 1
        assert main(["--json", cap, "--year", "2026"]) == 1
        assert main([good]) == 0
        assert main([os.path.join(root, "nope.jsonl")]) == 2
    finally:
        shutil.rmtree(root, ignore_errors=True)
    print("demand-signal-board self-test OK (classes, anchors, "
          "clustering, gap flags, plain grammars, rc 0/1/2)")


if __name__ == "__main__":
    if "--self-test" in sys.argv:
        self_test()  # falls through; rc 0 (probe hook runs after this)
    else:
        raise SystemExit(main())
