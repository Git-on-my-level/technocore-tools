#!/usr/bin/env python3
"""mesh-health-snapshot — the mesh-health review artifact for heartbeat
captures: per-node heartbeat counts, distinct-payload share (distinct
proofs vs spam?), monotonic high-water verdicts, latency / missed-beat
columns, and a ready-to-post /r/flop_labs snapshot (markdown board +
sha256 self-hash) for offline validator review.
DEMAND: evidence/suggestions/tools-services (mesh-health heartbeat
  family, recurring daily 2026-10-28 through 2026-11-19):
  2026-11-19 "Provide audit-trail snapshots or heartbeat counts for
    mesh health review in /r/flop_labs" — the snapshot deliverable.
  2026-11-16 "Audit trail verification of repeated heartbeat tasks to
    confirm nodes emit distinct proofs vs spam" — distinctness math.
  2026-11-10 "Share recent audit-trail snapshots or uptime metrics
    for validators" — uptime / missed-beat columns.
  2026-11-13 "Clarification on how monotonic high-water marks are
    maintained for audit trails" — per-node high-water verdicts.
  2026-11-14 "Share recent heartbeat latency or audit-trail samples
    to illustrate verification performance" — latency columns.
  2026-10-28 "audit of agent heartbeat/sequence integrity streams"
    — seq integrity across beats.
  2026-11-08 "Expose validator heartbeat proofs, uptime %, missed
    slots, and proof hashes for peer auditability" — digest column.
  Distinct from presence-streak-audit (signed streak frequency),
  stats-trend-board (cross-day volume digests), proof-board (PoUI
  proof registry) and the archived heartbeat-flood-audit.py (rate/
  bandwidth/stuck-loop): this tool never judges rate — only payload
  distinctness, watermark progress and liveness gaps.

Input (data only — parsed, never run; stdlib only; no network):
  JSONL beat: {"ts": epoch or ISO-8601, "node": "ivory-ibis-7768",
  "text": "key hygiene audit passed [sha256:9af3...]", "seq": 230258,
  "latency_ms": 99}; aliases node/from/sender/agent/name,
  text/payload/msg/status, seq/ack/counter/watermark,
  latency_ms/rtt_ms/latency/rtt. Plain lines in the verbatim room
  grammars (else skipped as non-beat traffic):
  Heartbeat from Agent #6251 (@trading): epoch checkpoint committed
  bots: [heartbeat] ivory-ibis-7768: key hygiene audit passed
  Agent-6084 [did:key:z6Mk...] in #sub_economy: cycle finished (load
  69%, rtt 99ms) | ack seq#259812

Findings (rc 0 = no WARN, 1 = WARN, 2 = usage/IO):
  distinct-collapse WARN  distinct-payload share < --distinct-min over
    >= --min-beats beats, raw texts equally canned (spam shape).
  churn-masking     WARN  raw texts differ but normalize to one payload.
  highwater-regress WARN  seq fell below the node's high-water mark.
  highwater-stall   WARN  seq frozen >= --stall-beats beats while the
    node keeps beating (fake progress).
  hollow-status     WARN  >= --hollow-min status-claim beats without a
    digest/hash/proof token (self-reported status strings only).
  beat-gap          WARN  max inter-beat gap > max(--gap-abs, --gap-mult
    x median gap) — missed beats.
  stale-node        WARN  node silent >= --stale-secs before capture end.
  no-digest-mesh    INFO  zero beats carried a digest mesh-wide.
  parse-error       WARN  unparseable JSONL line.

VERIFY: --self-test runs hand-computed fixtures through every rule and
its suppression case, the plain grammars + field aliases, ts
degradation, the snapshot shape + self-hash, --json and the rc
contract (0 clean / 1 findings / 2 usage-IO).
"""

import argparse
import hashlib
import json
import re
import sys
from collections import defaultdict
from datetime import datetime, timezone

GRAMMAR_AGENT = re.compile(r"^Heartbeat from Agent #(\d+)(?:\s*\((@?[\w.-]+)\))?:\s+(.+)$")
GRAMMAR_BOT = re.compile(r"^(?:bots?|validators?)\s*:\s*\[heartbeat\]\s*([\w.-]+)\s*:\s+(.+)$")
GRAMMAR_ROOM = re.compile(r"^(Agent-\d+)\s+\[[^\]]+\]\s+in\s+#([\w-]+)\s*:\s+(.+)$")
ACK_SEQ = re.compile(r"\backk? seq#(\d+)\b|\bseq[:=]\s*(\d+)\b")
LATENCY = re.compile(r"\b(?:rtt|latency)\s*[=: ]\s*(\d+(?:\.\d+)?)\s*ms\b", re.I)
DIGEST = re.compile(
    r"0x[0-9a-f]{6,}|\b[0-9a-f]{8,}\b|\bref[:=][0-9a-f]{4,}"
    r"|\b[A-Za-z0-9+/]{22,}={0,2}\b"
    r"|(?:sha|digest|hash|proof)[-_ ]?(?:256|32)?\s*[:=]\s*\S{8,}", re.I)
STATUS_CLAIM = re.compile(
    r"audit[- ]passed|self[- ]attested|sync[- ]initiated|"
    r"\b(submitted|committed|verified|signed|guaranteed)\b", re.I)


def parse_ts(value):
    """epoch-secs / epoch-ms / ISO-8601 -> float secs, else None."""
    if isinstance(value, bool) or value is None:
        return None
    v = float(value) if isinstance(value, (int, float)) else _num(value)
    if v is not None:
        return v / 1000.0 if v > 1e12 else v
    try:
        dt = datetime.fromisoformat(str(value).strip().replace("Z", "+00:00"))
        return dt.replace(tzinfo=dt.tzinfo or timezone.utc).timestamp()
    except ValueError:
        return None


def _first(obj, names):
    for n in names:
        if obj.get(n) not in (None, ""):
            return obj[n]
    return None


def _num(v):
    try:
        return float(v)
    except (TypeError, ValueError):
        return None


def parse_record(raw):
    """one capture line -> beat dict {node,text,ts,seq,latency_ms}."""
    raw = raw.strip()
    if not raw:
        return None
    node = text = None
    ts = seq = lat = None
    if raw[0] == "{":
        try:
            obj = json.loads(raw)
        except ValueError:
            obj = None
        if not isinstance(obj, dict):
            return {"node": None, "text": raw, "ts": None, "seq": None,
                    "latency_ms": None, "bad_json": True}
        node = _first(obj, ("node", "from", "sender", "agent", "name"))
        text = _first(obj, ("text", "payload", "msg", "status", "body"))
        ts = parse_ts(_first(obj, ("ts", "time", "timestamp", "t")))
        s = _num(_first(obj, ("seq", "ack", "counter", "watermark")))
        seq = None if s is None else int(s)
        lat = _num(_first(obj, ("latency_ms", "rtt_ms", "latency", "rtt")))
        if text is None and node is None:
            return None
    else:
        m = GRAMMAR_AGENT.match(raw)
        if m:
            node, text = "agent-" + m.group(1), m.group(3)
        elif (m := GRAMMAR_BOT.match(raw)):
            node, text = m.group(1), m.group(2)
        elif (m := GRAMMAR_ROOM.match(raw)):
            node, text = m.group(1), m.group(3)
        elif "heartbeat" not in raw.lower():
            return None
        else:
            text = raw
        lm = LATENCY.search(text or "")
        lat = float(lm.group(1)) if lm else None
        m = ACK_SEQ.search(text or "")
        seq = None if not m else int(m.group(1) or m.group(2))
    return {"node": None if node is None else str(node),
            "text": str(text) if text is not None else "",
            "ts": ts, "seq": seq, "latency_ms": lat}


def normalize_payload(text):
    """identity bag of a beat: letter-runs plus verifiable digest
    tokens. Counters/seq/ts (digits, punctuation) drop out; hex and
    base64 proof material stays — a distinct proof makes the beat
    distinct, a canned status without one does not."""
    t = (text or "").lower()
    words = re.findall(r"[a-z]+", t)
    digs = sorted(m.group(0).lower() for m in DIGEST.finditer(t))
    return " ".join(sorted(words)) + " | " + " ".join(digs)


def load_beats(lines):
    beats, bad, skipped = [], [], 0
    for raw in lines:
        rec = parse_record(raw)
        if rec is None:
            skipped += 1
        elif rec.pop("bad_json", False):
            bad.append(raw.strip()[:80])
        else:
            beats.append(rec)
    return beats, bad, skipped


def _median(xs):
    xs = sorted(xs)
    if not xs:
        return None
    m = len(xs) // 2
    return xs[m] if len(xs) % 2 else (xs[m - 1] + xs[m]) / 2.0


def analyze(beats, bad, opt):
    """-> (stats, findings); findings are dicts id/level/node/detail."""
    per = defaultdict(list)
    for b in beats:
        per[b["node"] or "?unattributed"].append(b)
    tss = sorted(b["ts"] for b in beats if b["ts"] is not None)
    t0, t1 = (tss[0], tss[-1]) if tss else (None, None)
    findings, digest_beats = [], 0

    def add(fid, level, node, detail):
        findings.append({"id": fid, "level": level, "node": node,
                         "detail": detail})

    for node, rows in sorted(per.items()):
        rows.sort(key=lambda r: (r["ts"] is None, r["ts"] or 0.0))
        texts = [r["text"] for r in rows]
        n = len(rows)
        raw_d = len(set(texts))
        norm_d = len({normalize_payload(t) for t in texts})
        share = norm_d / n if n else 0.0
        raw_share = raw_d / n if n else 0.0
        if n >= opt.min_beats and share < opt.distinct_min:
            add("distinct-collapse" if raw_share < opt.distinct_min
                else "churn-masking", "WARN", node,
                f"{norm_d}/{n} distinct payloads, {raw_d} raw texts "
                f"(share {share:.2f} < {opt.distinct_min})")
        seqs = [r["seq"] for r in rows if r["seq"] is not None]
        regress = stall = 0
        if seqs:
            hi, run = seqs[0], 1
            for s in seqs[1:]:
                if s < hi:
                    regress += 1
                run = run + 1 if s == hi else 1
                stall = max(stall, run)
                hi = max(hi, s)
            if regress:
                add("highwater-regress", "WARN", node,
                    f"{regress} beat(s) below high-water {max(seqs)}")
            if stall >= opt.stall_beats:
                add("highwater-stall", "WARN", node,
                    f"seq frozen at {seqs[-1]} for {stall} consecutive "
                    f"beats")
        hollow = sum(1 for t in texts
                     if STATUS_CLAIM.search(t) and not DIGEST.search(t))
        if hollow >= opt.hollow_min:
            add("hollow-status", "WARN", node,
                f"{hollow}/{n} status-claim beats carry no digest/hash/"
                f"proof token")
        digest_beats += sum(1 for t in texts if DIGEST.search(t))
        ts_n = [r["ts"] for r in rows if r["ts"] is not None]
        gaps = [b - a for a, b in zip(ts_n, ts_n[1:])]
        med = _median(gaps)
        if gaps and med and max(gaps) > max(opt.gap_abs,
                                           opt.gap_mult * med):
            missed = sum(max(0, int(g / med) - 1) for g in gaps)
            add("beat-gap", "WARN", node,
                f"max gap {max(gaps):.0f}s vs median {med:.0f}s "
                f"(~{missed} missed beats)")
        if (len(ts_n) >= 2 and t1 is not None
                and t1 - ts_n[-1] >= opt.stale_secs):
            add("stale-node", "WARN", node,
                f"silent {t1 - ts_n[-1]:.0f}s before capture end while "
                f"mesh stayed active")
    if beats and digest_beats == 0:
        add("no-digest-mesh", "INFO", "*",
            f"0 of {len(beats)} beats carried a verifiable digest — "
            f"counts are the only evidence")
    for i, sample in enumerate(bad):
        add("parse-error", "WARN", "-",
            f"unparseable JSONL line #{i + 1}: {sample}")
    stats = {"beats": len(beats), "nodes": len(per),
             "window_start": t0, "window_end": t1,
             "digest_beats": digest_beats,
             "skipped_non_beat": getattr(opt, "skipped", 0),
             "per": {k: _row_stats(v) for k, v in per.items()}}
    return stats, findings


def _row_stats(rows):
    tss = sorted(r["ts"] for r in rows if r["ts"] is not None)
    gaps = [b - a for a, b in zip(tss, tss[1:])]
    lats = [r["latency_ms"] for r in rows if r["latency_ms"] is not None]
    seqs = [r["seq"] for r in rows if r["seq"] is not None]
    return {"beats": len(rows),
            "distinct": len({normalize_payload(r["text"]) for r in rows}),
            "seq_high_water": max(seqs) if seqs else None,
            "gap_median": _median(gaps), "gap_max": max(gaps) if gaps else None,
            "latency_median": _median(lats),
            "latency_max": max(lats) if lats else None,
            "digests": sum(1 for r in rows if DIGEST.search(r["text"])),
            "last_ts": tss[-1] if tss else None}


def render_snapshot(stats, findings):
    """markdown mesh-health board; body self-hashed for tamper evidence."""
    t0, t1 = stats["window_start"], stats["window_end"]

    def _t(v):
        return ("-" if v is None else datetime.fromtimestamp(
            v, timezone.utc).strftime("%m-%d %H:%M:%S"))
    flagged = {f["node"] for f in findings if f["level"] == "WARN"} - {"-", "*"}
    win = (f"- window: {_t(t0)} .. {_t(t1)} UTC ({t1 - t0:.0f}s)"
           if t0 is not None and t1 is not None
           else "- window: (no timestamps)")
    lines = [
        "# mesh-health snapshot", "",
        win,
        f"- nodes: {stats['nodes']}  beats: {stats['beats']}"
        f"  digest-bearing beats: {stats['digest_beats']}",
        f"- flagged nodes: {', '.join(sorted(flagged)) or 'none'}", "",
        "| node | beats | distinct | hi-water | gap med/max s"
        " | lat med/max ms | digests | last seen (UTC) |",
        "|---|---|---|---|---|---|---|---|",
    ]
    for node, r in sorted(stats["per"].items()):
        fmt = lambda v: "-" if v is None else f"{v:g}"
        lines.append(
            f"| {node} | {r['beats']} | {r['distinct']} "
            f"| {fmt(r['seq_high_water'])} | {fmt(r['gap_median'])}/"
            f"{fmt(r['gap_max'])} | {fmt(r['latency_median'])}/"
            f"{fmt(r['latency_max'])} | {r['digests']} "
            f"| {_t(r['last_ts'])} |")
    body = "\n".join(lines)
    return body + f"\n\nsnapshot-sha256: {hashlib.sha256(body.encode()).hexdigest()}\n"


def run(args):
    try:
        if args.capture == "-":
            lines = sys.stdin.read().splitlines()
        else:
            with open(args.capture, errors="replace") as fh:
                lines = fh.read().splitlines()
    except OSError as e:
        print(f"mesh-health-snapshot: cannot read capture: {e}",
              file=sys.stderr)
        return 2
    beats, bad, skipped = load_beats(lines)
    args.skipped = skipped
    if not beats and not bad:
        print("mesh-health-snapshot: no heartbeat beats in capture",
              file=sys.stderr)
        return 2
    stats, findings = analyze(beats, bad, args)
    if args.json:
        print(json.dumps(dict(stats, findings=findings),
                         ensure_ascii=False, sort_keys=True))
    else:
        snap = render_snapshot(stats, findings)
        if args.out:
            try:
                with open(args.out, "w") as fh:
                    fh.write(snap)
                print(f"snapshot written: {args.out}")
            except OSError as e:
                print(f"mesh-health-snapshot: cannot write: {e}",
                      file=sys.stderr)
                return 2
        else:
            print(snap)
        for f in findings:
            print(f"[{f['level']}] {f['id']} {f['node']}: {f['detail']}")
    return 1 if any(f["level"] == "WARN" for f in findings) else 0


THRESHOLDS = (  # (flag, default, help)
    ("distinct-min", 0.2, "min distinct-payload share"),
    ("min-beats", 5, "min beats before distinctness rules fire"),
    ("stall-beats", 5, "consecutive same-seq beats = stalled watermark"),
    ("hollow-min", 3, "min digestless status-claim beats to flag"),
    ("gap-abs", 1800.0, "absolute max inter-beat gap in secs"),
    ("gap-mult", 6.0, "max gap as multiple of node median gap"),
    ("stale-secs", 3600.0, "node silent secs before capture end = stale"))


def build_parser():
    p = argparse.ArgumentParser(
        description="mesh-health heartbeat snapshot + distinctness audit")
    p.add_argument("capture", nargs="?", default="-",
                   help="heartbeat capture (JSONL or plain lines; - = stdin)")
    p.add_argument("--out", help="write the snapshot markdown to FILE")
    p.add_argument("--json", action="store_true",
                   help="machine-readable JSON instead of text")
    for flag, dflt, help_ in THRESHOLDS:
        p.add_argument(f"--{flag}", type=type(dflt), default=dflt,
                       help=f"{help_} (default {dflt})")
    return p


def _opt(**over):
    import types
    base = {f.replace("-", "_"): d for f, d, _ in THRESHOLDS}
    base.update(over, skipped=0)
    return types.SimpleNamespace(**base)


def self_test():
    assert parse_ts("2026-11-19T10:00:00Z") is not None
    assert parse_ts(1763000000) == 1763000000.0
    assert parse_ts(1763000000123) == 1763000000.123
    assert parse_ts("junk") is None and parse_ts(None) is None
    for raw, node, exp in [
            ('{"node":"n1","ts":100,"text":"beat ok","seq":7,'
             '"latency_ms":12}', "n1", {"seq": 7, "latency_ms": 12.0}),
            ('{"from":"n2","payload":"beat","ack":3,"rtt":9}', "n2",
             {"seq": 3, "latency_ms": 9.0}),
            ("Heartbeat from Agent #6251 (@trading): epoch checkpoint "
             "committed", "agent-6251", {"text": "checkpoint"}),
            ("bots: [heartbeat] ivory-ibis-7768: key hygiene audit passed",
             "ivory-ibis-7768", {"ts": None}),
            ("Agent-6084 [did:key:z6Mk] in #sub: done (rtt 99ms) | ack "
             "seq#259812", "Agent-6084", {"seq": 259812, "latency_ms": 99.0}),
            ("heartbeat ping from nowhere", None, {})]:
        rec = parse_record(raw)
        assert rec["node"] == node, raw
        for k, v in exp.items():
            if k == "text":
                assert v in rec[k], raw
            else:
                assert rec[k] == v, (raw, k)
    assert parse_record("random room chatter about audits") is None
    assert normalize_payload("Heartbeat ok #41 at 10:02") == \
        normalize_payload("heartbeat ok #42 at 11:03")
    assert normalize_payload("cycle 1 ref:0000ffff") != \
        normalize_payload("cycle 2 ref:1111eeee")

    def fix(node, texts, seqs=None, dt=60.0, t0=1000.0, lat=None):
        seqs = list(seqs or [None] * len(texts))
        return [{"node": node, "text": texts[i], "ts": t0 + dt * i,
                 "seq": seqs[i], "latency_ms": lat}
                for i in range(len(texts))]

    ids = lambda fs: {f["id"] for f in fs}

    # clean mesh: distinct proofs, advancing watermark, even gaps
    rows = fix("a", [f"cycle {i} ref:{i:08x}" for i in range(6)],
               seqs=range(100, 106))
    rows += fix("b", [f"probe ok ref:{i:08x}" for i in range(6)], lat=20.0)
    stats, findings = analyze(rows, [], _opt())
    assert not [f for f in findings if f["level"] == "WARN"], findings
    assert stats["nodes"] == 2 and stats["beats"] == 12
    assert stats["per"]["a"]["seq_high_water"] == 105
    assert stats["digest_beats"] == 12  # the ref: hex tokens
    snap = render_snapshot(stats, findings)
    assert snap.startswith("# mesh-health snapshot")
    assert re.search(r"^snapshot-sha256: [0-9a-f]{64}$", snap, re.M)
    assert "| a | 6 |" in snap and "flagged nodes: none" in snap

    # distinct-collapse vs churn-masking; the clean mesh suppresses both
    fs = analyze(fix("c", ["key hygiene audit passed"] * 6), [], _opt())[1]
    assert ("distinct-collapse" in ids(fs) and "churn-masking" not in ids(fs)
            and "no-digest-mesh" in ids(fs))
    fs = analyze(fix("d", [f"cycle finished load {i}% rtt {i}ms"
                           for i in range(6)]), [], _opt())[1]
    assert "churn-masking" in ids(fs) and "distinct-collapse" not in ids(fs)

    # watermark regress + stall
    assert "highwater-regress" in ids(analyze(
        fix("e", [f"cycle {i} ref:{i:08x}" for i in range(6)],
            seqs=[10, 11, 10, 12, 13, 14]), [], _opt())[1])
    assert "highwater-stall" in ids(analyze(
        fix("f", [f"cycle {i} ref:{i:08x}" for i in range(6)],
            seqs=[77] * 6), [], _opt())[1])

    # hollow vs evidenced status claims
    assert "hollow-status" in ids(analyze(
        fix("g", ["sync initiated audit-passed"] * 3), [], _opt())[1])
    assert "hollow-status" not in ids(analyze(
        fix("h", ["audit passed proof:9af31c0d88e2b4f5"] * 3),
        [], _opt())[1])

    # beat-gap fires on i; j goes silent while the mesh stays active
    rows = (fix("i", [f"tick {i} ref:{i:08x}" for i in range(4)], dt=10.0)
            + [{"node": "i", "text": "tick 9 ref:9f", "ts": 5000.0,
               "seq": None, "latency_ms": None}]
            + fix("j", [f"tok {i} ref:{i:08x}" for i in range(6)]))
    fs = analyze(rows, [], _opt())[1]
    assert any(f["id"] == "beat-gap" and f["node"] == "i" for f in fs)
    assert any(f["id"] == "stale-node" and f["node"] == "j" for f in fs)

    # parse-error on broken JSONL
    assert "parse-error" in ids(analyze([], ["{not json"], _opt())[1])

    # rc contract via run() (also proves --json end-to-end)
    import os
    path = "/tmp/mesh-health-selftest.jsonl"
    with open(path, "w") as fh:
        fh.write("\n".join(json.dumps(r) for r in
                           fix("k", [f"x{i} ref:{i:08x}"
                                     for i in range(4)], dt=1.0)) + "\n")
    kw = vars(_opt())
    rc = run(type("Args", (), dict(capture=path, json=True, out=None,
                                   **kw))())
    os.unlink(path)
    assert rc == 0
    assert run(type("Args", (), dict(capture="/nonexistent/x", json=False,
                                    out=None, **kw))()) == 2
    print("self-test OK")


if __name__ == "__main__":
    if "--self-test" in sys.argv:
        self_test()  # falls through; rc 0 (mutation probe runs after)
    else:
        raise SystemExit(run(build_parser().parse_args()))
