#!/usr/bin/env python3
"""relay-divergence-audit — relay gossip state-divergence / failover audit.

DEMAND: evidence/suggestions/tools-services/ (file citations below)
  - "Cross-node gossip/state-divergence audit across edge relays"
  - "Add failover redundancy monitoring for validator nodes"
  - "Cross-session relay visibility / connection diagnostics"
  Scope: one JSONL capture, one relay event per line: {"ts","relay","topic",
    "seq","state_hash","event"}; event in gossip|failover|degraded|
    recovered. Gossip carries the (topic, seq, state_hash) stream per
    relay; failover/degraded/recovered mark redundancy health. Data only:
    JSON/regex parsing, nothing executed. rc 0/1/2. Stdlib only.
"""
import argparse
import json
import re
import sys
from datetime import datetime, timezone
from statistics import median

SEVS = ("BLOCK", "WARN", "INFO")
SILENCE_K = 4        # quiet span counted in multiples of median gossip gap
FLAP_MIN = 3         # degraded/recovered cycles counted as flapping

def _f(kind, severity, origin, detail):
    """Uniform finding dict."""
    return {"kind": kind, "severity": severity, "origin": origin,
            "detail": detail}

def parse_ts(v):
    """Epoch number or ISO-8601 string -> epoch float (naive read as UTC)."""
    if isinstance(v, (int, float)) and not isinstance(v, bool):
        return float(v)
    if isinstance(v, str):
        s = v.strip()
        if re.fullmatch(r"-?\d+(\.\d+)?", s):
            return float(s)
        try:
            stamp = datetime.fromisoformat(s.replace("Z", "+00:00"))
            if stamp.tzinfo is None:
                stamp = stamp.replace(tzinfo=timezone.utc)
            return stamp.timestamp()
        except ValueError:
            return None
    return None

def load_jsonl(path):
    """Read JSONL -> (records, bad_lines); unparsable/non-dict lines counted."""
    records, bad = [], 0
    with open(path, "r", encoding="utf-8") as fh:
        for line in fh:
            line = line.strip()
            if not line:
                continue
            try:
                rec = json.loads(line)
                if not isinstance(rec, dict):
                    raise ValueError("not a record")
                records.append(rec)
            except ValueError:
                bad += 1
    return records, bad

def _iseq(v):
    """Integral seq (int, float or digit string) -> int, else None."""
    if isinstance(v, bool):
        return None
    if isinstance(v, (int, float)):
        return int(v) if float(v).is_integer() else None
    if isinstance(v, str) and re.fullmatch(r"\d+", v.strip()):
        return int(v.strip())
    return None

def _scan(records):
    """One pass -> (gossip, streams, health, horizon).

    gossip: [(relay, topic, seq, state_hash, ts)] for well-formed gossip;
    streams: {(relay, topic): {"gossip": [ts], "failover": [ts]}};
    health: {relay: {"degraded": n, "recovered": n}}; horizon: last ts seen.
    """
    gossip, streams, health = [], {}, {}
    horizon = None
    for rec in records:
        ts = parse_ts(rec.get("ts"))
        if ts is None:
            continue
        if horizon is None or ts > horizon:
            horizon = ts
        relay = str(rec.get("relay") or "?")
        topic = str(rec.get("topic") or "?")
        ev = rec.get("event")
        st = streams.setdefault((relay, topic), {"gossip": [], "failover": []})
        if ev == "gossip":
            st["gossip"].append(ts)
            seq, h = _iseq(rec.get("seq")), rec.get("state_hash")
            if seq is not None and isinstance(h, str) and h:
                gossip.append((relay, topic, seq, h, ts))
        elif ev == "failover":
            st["failover"].append(ts)
        elif ev in ("degraded", "recovered"):
            h = health.setdefault(relay, {"degraded": 0, "recovered": 0})
            h[ev] += 1
    return gossip, streams, health, horizon

def divergence_findings(records):
    """Cross-relay state_hash conflicts and same-relay rewrites (BLOCK)."""
    gossip, _streams, _health, _horizon = _scan(records)
    cross, own, rewrites = {}, {}, []
    for relay, topic, seq, h, _ts in gossip:
        cross.setdefault((topic, seq), {}).setdefault(relay, h)
        key = (relay, topic, seq)
        if key in own and own[key] != h:
            rewrites.append((relay, topic, seq, own[key], h))
        else:
            own.setdefault(key, h)
    finds = [_f("hash-rewrite", "BLOCK", f"{r}/{t}#{q}",
                f"relay re-announced seq {q} with changed state_hash "
                f"({old} -> {new})")
             for r, t, q, old, new in rewrites]
    for topic, seq in sorted(cross):
        per = cross[(topic, seq)]
        relays = sorted(per)
        for other in relays[1:]:
            if per[other] != per[relays[0]]:
                finds.append(_f("state-divergence", "BLOCK", f"{topic}#{seq}",
                                f"relay {relays[0]} hash {per[relays[0]]} vs "
                                f"relay {other} hash {per[other]}"))
                break
    return finds

def silence_findings(records, k=SILENCE_K):
    """A relay going quiet on a served topic with no failover (WARN)."""
    _gossip, streams, _health, horizon = _scan(records)
    finds = []
    if horizon is None:
        return finds
    for key in sorted(streams):
        ts_list = sorted(streams[key]["gossip"])
        if len(ts_list) < 2:
            continue
        gaps = [b - a for a, b in zip(ts_list, ts_list[1:]) if b > a]
        if not gaps:
            continue
        med = median(gaps)
        last = ts_list[-1]
        quiet = horizon - last
        if med <= 0 or quiet <= k * med:
            continue
        if any(t >= last for t in streams[key]["failover"]):
            continue  # failover declared after the last gossip excuses it
        relay, topic = key
        finds.append(_f("relay-silence", "WARN", f"{relay}/{topic}",
                        f"silent {quiet:g}s after gossip {ts_list[0]:g}.."
                        f"{last:g} (> {k}x median gap {med:g}s), no failover"))
    return finds

def failover_findings(records):
    """Failover sanity: unserved topics (WARN), split-brain (BLOCK),
    degraded/recovered flapping (WARN)."""
    _gossip, streams, health, _horizon = _scan(records)
    finds = []
    for key in sorted(streams):
        relay, topic = key
        failovers = sorted(streams[key]["failover"])
        if not failovers:
            continue
        if not streams[key]["gossip"]:
            finds.append(_f("failover-unserved", "WARN", f"{relay}/{topic}",
                            f"failover at {failovers[0]:g} for a relay+topic "
                            f"never served by gossip"))
            continue
        after = [t for t in streams[key]["gossip"] if t > failovers[-1]]
        if after:
            finds.append(_f("split-brain", "BLOCK", f"{relay}/{topic}",
                            f"relay still gossiping at {after[0]:g} after "
                            f"failover at {failovers[-1]:g}"))
    for relay in sorted(health):
        cycles = min(health[relay]["degraded"], health[relay]["recovered"])
        if cycles >= FLAP_MIN:
            finds.append(_f("flapping", "WARN", relay,
                            f"{cycles} degraded/recovered cycles in capture"))
    return finds

def _ranges(missing):
    """[3,4,7] -> '3-4, 7' (consecutive runs collapsed)."""
    out, run = [], []
    for v in missing:
        if run and v == run[-1] + 1:
            run.append(v)
        else:
            if run:
                out.append(run)
            run = [v]
    out.append(run)
    return ", ".join(str(r[0]) if len(r) == 1 else f"{r[0]}-{r[-1]}"
                     for r in out)

def seqgap_findings(records):
    """Missing seq numbers inside each relay+topic span (WARN)."""
    gossip, _streams, _health, _horizon = _scan(records)
    seqs = {}
    for relay, topic, seq, _h, _ts in gossip:
        seqs.setdefault((relay, topic), set()).add(seq)
    finds = []
    for key in sorted(seqs):
        seen = seqs[key]
        if len(seen) < 2:
            continue
        lo, hi = min(seen), max(seen)
        missing = [v for v in range(lo + 1, hi) if v not in seen]
        if not missing:
            continue
        relay, topic = key
        finds.append(_f("seq-gap", "WARN", f"{relay}/{topic}",
                        f"{len(missing)} missing seq in {lo}..{hi}: "
                        f"{_ranges(missing)}"))
    return finds

def audit(path):
    """Run every detector over the capture -> (findings, stats)."""
    records, bad = load_jsonl(path)
    finds = (divergence_findings(records) + silence_findings(records)
             + failover_findings(records) + seqgap_findings(records))
    if bad:
        finds.append(_f("malformed-line", "INFO", path,
                        f"{bad} unparsable line(s) skipped"))
    rank = {"BLOCK": 0, "WARN": 1, "INFO": 2}
    finds.sort(key=lambda f: (rank[f["severity"]], f["kind"], f["origin"]))
    _g, streams, _h, _hz = _scan(records)
    return finds, {"records": len(records), "bad_lines": bad,
                   "relays": len({r for r, _t in streams}),
                   "topics": len({t for _r, t in streams})}

def render(findings):
    """Print one `SEV kind origin: detail` line per finding; return counts."""
    counts = {s: 0 for s in SEVS}
    for f in findings:
        counts[f["severity"]] += 1
        print(f"{f['severity']} {f['kind']} {f['origin']}: {f['detail']}")
    print("no findings" if not findings else
          f"{len(findings)} finding(s): "
          + ", ".join(f"{s} {counts[s]}" for s in SEVS))
    return counts

def main(argv=None):
    """CLI: path positional, --json optional; rc 0/1/2."""
    ap = argparse.ArgumentParser(
        description="relay gossip state-divergence / failover audit")
    ap.add_argument("path", help="JSONL capture of relay events")
    ap.add_argument("--json", action="store_true", help="JSON output")
    args = ap.parse_args(argv)
    try:
        finds, stats = audit(args.path)
    except OSError as exc:
        print(f"cannot read {args.path}: {exc}", file=sys.stderr)
        return 2
    if args.json:
        print(json.dumps({"tool": "relay-divergence-audit", **stats,
                          "findings": finds}, indent=1))
    else:
        render(finds)
    return 1 if finds else 0

def self_test():
    import io
    import os
    import tempfile
    from contextlib import redirect_stdout

    def _ev(ts, relay="r1", topic="t1", seq=1, hash="h1", event="gossip"):
        return {"ts": ts, "relay": relay, "topic": topic, "seq": seq,
                "state_hash": hash, "event": event}

    def run(caps, extra=()):
        """caps: list of captures (records or raw strings) -> (rc, output)."""
        paths = []
        try:
            for cap in caps:
                with tempfile.NamedTemporaryFile("w", suffix=".jsonl",
                                                 delete=False) as tf:
                    tf.write("\n".join(r if isinstance(r, str)
                                       else json.dumps(r)
                                       for r in cap) + "\n")
                    paths.append(tf.name)
            buf = io.StringIO()
            with redirect_stdout(buf):
                rc = main([*paths, *extra])
            return rc, buf.getvalue()
        finally:
            for p in paths:
                os.unlink(p)

    def kinds(finds):
        return [f["kind"] for f in finds]

    # 1. clean capture: two relays agreeing on every topic+seq hash, gossip
    #    running to the capture horizon -> silent, rc 0
    clean = [_ev(10 * s, relay=r, topic="ledger-state", seq=s,
                 hash=f"hh{s}") for r in ("r1", "r2") for s in range(1, 5)]
    rc, out = run([clean])
    assert rc == 0 and "no findings" in out, (rc, out)
    for fn in (divergence_findings, silence_findings, failover_findings,
               seqgap_findings):
        assert fn(clean) == [], fn.__name__
    # 2. state divergence: two relays, same topic+seq, different hashes
    div = [_ev(0, relay="r1", seq=1, hash="hA"),
           _ev(100, relay="r1", seq=2, hash="hA2"),
           _ev(50, relay="r2", seq=1, hash="hA"),
           _ev(150, relay="r2", seq=2, hash="hB2")]
    f = divergence_findings(div)
    assert kinds(f) == ["state-divergence"] and f[0]["severity"] == "BLOCK", f
    assert f[0]["origin"] == "t1#2" and "r1" in f[0]["detail"], f
    # 3. hash rewrite: one relay re-announcing a seq with a changed hash
    rw = [_ev(0, seq=1, hash="s1"), _ev(100, seq=1, hash="s1x")]
    f = divergence_findings(rw)
    assert kinds(f) == ["hash-rewrite"] and "s1 -> s1x" in f[0]["detail"], f
    # 4. silence: relay quiet > 4x its median gap with no failover
    sil = ([_ev(100 * i, seq=i + 1, hash=f"h{i}") for i in range(6)]
           + [_ev(1900, relay="r2", topic="t2", seq=1, hash="x1"),
              _ev(2000, relay="r2", topic="t2", seq=2, hash="x2")])
    f = silence_findings(sil)
    assert kinds(f) == ["relay-silence"] and f[0]["origin"] == "r1/t1", f
    assert "1500s" in f[0]["detail"] and "4x" in f[0]["detail"], f
    # 5. the same silence is excused by a failover declared after it
    exc = sil + [_ev(600, event="failover")]
    assert silence_findings(exc) == [], silence_findings(exc)
    assert kinds(failover_findings(exc)) == [], failover_findings(exc)
    # 6. failover declared for a relay+topic that never served it
    unsv = ([_ev(50, relay="r2", topic="t9", event="failover")]
            + [_ev(60 + 10 * i, seq=i + 1, hash=f"q{i}") for i in range(5)])
    f = failover_findings(unsv)
    assert kinds(f) == ["failover-unserved"] and f[0]["severity"] == "WARN", f
    # 7. split-brain: the failed-over relay keeps gossiping that topic
    sb = ([_ev(100 * i, seq=i + 1, hash=f"b{i}") for i in range(4)]
          + [_ev(350, event="failover"), _ev(400, seq=5, hash="b4")])
    f = failover_findings(sb)
    assert kinds(f) == ["split-brain"] and f[0]["severity"] == "BLOCK", f
    # 8. flapping: three degraded/recovered cycles on one relay
    flap = ([_ev(60 + 10 * i, seq=i + 1, hash=f"c{i}") for i in range(5)]
            + [_ev(t, relay="r3", event=ev)
               for t, ev in ((1, "degraded"), (2, "recovered"),
                             (3, "degraded"), (4, "recovered"),
                             (5, "degraded"), (6, "recovered"))])
    f = failover_findings(flap)
    assert kinds(f) == ["flapping"] and "3" in f[0]["detail"], f
    # 9. seq gap: 1,2,5,6 -> missing 3-4 reported per relay+topic
    sg = [_ev(ts, seq=s, hash=f"g{s}")
          for ts, s in ((0, 1), (100, 2), (400, 5), (500, 6))]
    f = seqgap_findings(sg)
    assert kinds(f) == ["seq-gap"] and "3-4" in f[0]["detail"], f
    # 10. CLI: findings rc 1; --json shape; malformed INFO; unreadable rc 2
    rc, out = run([div])
    assert rc == 1 and "BLOCK state-divergence" in out, (rc, out)
    doc = json.loads(run([clean], ["--json"])[1])
    assert doc["findings"] == [] and doc["records"] == 8, doc
    assert doc["relays"] == 2 and doc["topics"] == 1, doc
    rc, out = run([['{"broken', _ev(0)]])
    assert rc == 1 and "malformed-line" in out, (rc, out)
    assert main(["/nonexistent-capture.jsonl"]) == 2
    print("relay-divergence-audit self-test OK (10 groups: clean, state "
          "divergence, hash rewrite, silence + failover excuse, unserved "
          "failover, split-brain, flapping, seq gap, CLI rc/json)")

if __name__ == "__main__":
    if "--self-test" in sys.argv:
        self_test()  # falls through; rc 0 (probe hook runs after this)
    else:
        raise SystemExit(main())
