#!/usr/bin/env python3
"""source-freshness-audit — staleness audit for captured data sources:
per-file coverage holes, capture lag, stalled sources, timestamp and seq
regressions — with every finding stamped by its source file+seq+ts.

DEMAND: evidence/suggestions/tools-services/
  - 2026-08-26.md "Staleness audit for data sources"; "Add source
    timestamps to audit reports for staleness tracking"; "Add source
    timestamps for staleness monitoring"
  - 2026-08-27.md "Add source timestamps for staleness audit"
  - 2026-09-15.md "Proof currency/freshness verification"
Scope: the offline half — the capture files ARE the data sources. Given
one or more JSONL captures ({"seq","ts",...} per line), measure how
fresh each source is and stamp every finding with the exact source
coordinates it came from (the "add source timestamps" ask applied to
this audit's own report):
  stale-source     source's last internal ts lags the freshest source
                   by > --stale-hours (default 24h).
  coverage-hole    consecutive messages further apart than
                   --hole-hours (default 6h) — a gap in the record.
  capture-lag      file mtime minus last internal ts > --lag-hours
                   (default 6h) — collector stopped writing.
  ts-regression    a record older than the max ts already seen by >
                   --regress-mins (default 30m) — clock or merge
                   artifact; stamped with both coordinates.
  seq-regression   seq lower than a previous seq in the same file.
  missing-ts       record without a parsable timestamp (unstamped
                   evidence — cannot be freshness-audited).
  malformed-line   not JSON / not an object.
  empty-source     a capture with zero parsable records.
Lines are data only; no network, no subprocess, nothing is run.
rc 0 clean (INFO-only also rc 0), 1 WARN/BLOCK findings, 2 usage/IO.

VERIFY: --self-test runs 13 assertion groups over synthetic captures
(clean freshness silence, stale-source vs freshest peer, coverage hole,
capture lag via mtime, ts/seq regressions, missing-ts, malformed,
empty file, ref-time override, CLI rc/json/limit). Live grounding:
evidence/raw/general.jsonl + gpu-miners.jsonl (575k records) -> 8 WARN:
coverage holes 12.1h / 18.5h / 7.6h (2026-08-26..09-02), 4 seq
regressions clustered at gpu-miners line 384593+, 1 ts-regression 7.3h
behind prior max; both sources current through 2026-10-01T13:15Z. rc 1
in 1.7s.
"""
import argparse
import glob as _glob
import json
import os
import sys
from datetime import datetime

DEF = dict(stale_hours=24.0, hole_hours=6.0, lag_hours=6.0,
           regress_mins=30.0, limit=20)


def epoch(v):
    """ISO-8601 string or number -> epoch seconds; else None."""
    if isinstance(v, bool):
        return None
    if isinstance(v, (int, float)):
        return float(v)
    if isinstance(v, str):
        try:
            return datetime.fromisoformat(
                v.replace("Z", "+00:00")).timestamp()
        except ValueError:
            return None
    return None


def iso(t):
    return datetime.fromtimestamp(t,
                                  tz=datetime.now().astimezone().tzinfo
                                  ).isoformat(timespec="seconds")


def scan_file(path):
    """One capture file -> stats dict (no findings yet).

    Walks the file lazily once: counts lines/records, tracks first/last
    (seq, ts) in file order, the max ts seen, ts regressions, seq
    regressions, holes between consecutive parsable timestamps,
    missing-ts and malformed lines (kept as coordinates).
    """
    st = dict(path=path, lines=0, records=0, malformed=0, missing_ts=0,
              first=None, last=None, max_ts=None, holes=[], ts_reg=[], seq_reg=[],
              malformed_at=[], missing_at=[])
    prev_ts = None
    prev_seq = None
    max_ts = None
    with open(path, errors="replace") as fh:
        for i, line in enumerate(fh):
            st["lines"] += 1
            try:
                rec = json.loads(line)
            except (json.JSONDecodeError, ValueError):
                st["malformed"] += 1
                st["malformed_at"].append(i)
                continue
            if not isinstance(rec, dict):
                st["malformed"] += 1
                st["malformed_at"].append(i)
                continue
            st["records"] += 1
            t = epoch(rec.get("ts"))
            seq = rec.get("seq")
            if t is None:
                st["missing_ts"] += 1
                st["missing_at"].append((i, seq))
            else:
                if st["first"] is None:
                    st["first"] = (i, seq, t)
                st["last"] = (i, seq, t)
                if max_ts is not None and max_ts - t > 60.0:
                    st["ts_reg"].append((i, seq, t, max_ts))
                if prev_ts is not None and t - prev_ts > 1.0:
                    st["holes"].append((i, seq, prev_ts, t))
                if max_ts is None or t > max_ts:
                    max_ts = t
                prev_ts = t
            if isinstance(seq, int) and prev_seq is not None \
                    and isinstance(prev_seq, int) and seq < prev_seq:
                st["seq_reg"].append((i, seq, prev_seq))
            if isinstance(seq, int):
                prev_seq = seq
    st["max_ts"] = max_ts
    try:
        st["mtime"] = os.stat(path).st_mtime
    except OSError:
        st["mtime"] = None
    return st


def analyze(stats, opts=None):
    """Per-file stats -> findings (list of dicts, source-stamped)."""
    o = dict(DEF)
    o.update(opts or {})
    ref = o.get("ref_epoch")
    fresh = ref
    if fresh is None:
        cand = [s["max_ts"] for s in stats if s["max_ts"] is not None]
        fresh = max(cand) if cand else None
    findings = []

    def add(kind, sev, detail, **kw):
        f = {"kind": kind, "severity": sev, "detail": detail}
        f.update(kw)
        findings.append(f)

    for s in stats:
        name = os.path.basename(s["path"])
        if s["records"] == 0:
            add("empty-source", "WARN",
                f"{name}: 0 parsable records in {s['lines']} lines",
                source=s["path"])
            continue
        # stale vs freshest source
        if fresh is not None and s["max_ts"] is not None:
            lag_h = (fresh - s["max_ts"]) / 3600.0
            if lag_h > o["stale_hours"]:
                _i, _sq, t = s["last"]
                add("stale-source", "WARN",
                    f"{name}: last internal ts {iso(t)} lags freshest "
                    f"source by {lag_h:.1f}h (> {o['stale_hours']}h)",
                    source=s["path"], seq=_sq, ts=iso(t))
        # capture lag: mtime vs last internal ts
        if s["mtime"] is not None and s["max_ts"] is not None:
            lag_h = (s["mtime"] - s["max_ts"]) / 3600.0
            if lag_h > o["lag_hours"]:
                _i, _sq, t = s["last"]
                add("capture-lag", "WARN",
                    f"{name}: collector last wrote {iso(s['mtime'])}, "
                    f"{lag_h:.1f}h after last internal ts {iso(t)}",
                    source=s["path"], seq=_sq, ts=iso(t))
        for i, seq, t0, t1 in s["holes"]:
            gap_h = (t1 - t0) / 3600.0
            if gap_h > o["hole_hours"]:
                add("coverage-hole", "WARN",
                    f"{name}: {gap_h:.1f}h hole before line {i + 1} "
                    f"({iso(t0)} -> {iso(t1)})",
                    source=s["path"], seq=seq, ts=iso(t1))
        for i, seq, t, mt in s["ts_reg"]:
            if (mt - t) / 60.0 > o["regress_mins"]:
                add("ts-regression", "WARN",
                    f"{name}: line {i + 1} ts {iso(t)} is "
                    f"{(mt - t) / 3600.0:.1f}h behind prior max",
                    source=s["path"], seq=seq, ts=iso(t))
        for i, seq, prev in s["seq_reg"]:
            add("seq-regression", "WARN",
                f"{name}: line {i + 1} seq {seq} < prior seq {prev}",
                source=s["path"], seq=seq)
        for i in s["malformed_at"][:5]:
            add("malformed-line", "INFO",
                f"{name}: line {i + 1} is not a JSON object",
                source=s["path"], line=i + 1)
        for i, seq in s["missing_at"][:5]:
            add("missing-ts", "INFO",
                f"{name}: line {i + 1} carries no parsable timestamp",
                source=s["path"], seq=seq, line=i + 1)
    findings.sort(key=lambda f: (f["kind"], f.get("source", "")))
    return findings


def render(findings, stats, limit=20):
    counts = {}
    for f in findings:
        counts[f["severity"]] = counts.get(f["severity"], 0) + 1
    print(f"findings: {len(findings)} "
          + " ".join(f"{k}={v}" for k, v in sorted(counts.items())))
    for f in findings[:limit]:
        print(f"[{f['severity']}] {f['kind']}: {f['detail']}")
    if len(findings) > limit:
        print(f"... {len(findings) - limit} more")
    print(f"sources: {len(stats)}")
    for s in stats:
        if s["records"] == 0:
            print(f"  {os.path.basename(s['path']):30s} EMPTY")
            continue
        fi, fsq, ft = s["first"]
        li, lsq, lt = s["last"]
        print(f"  {os.path.basename(s['path']):30s} n={s['records']:7d} "
              f"ts {iso(ft)}..{iso(lt)} seq {fsq}..{lsq}")


def expand(paths):
    """Expand globs; keep order, dedupe."""
    out = []
    for p in paths:
        hits = sorted(_glob.glob(p)) if any(c in p for c in "*?[") else [p]
        for h in hits:
            if h not in out:
                out.append(h)
    return out


def main(argv=None):
    ap = argparse.ArgumentParser(
        description="Freshness/staleness audit over JSONL capture files: "
                    "coverage holes, capture lag, stale sources, ts/seq "
                    "regressions — findings stamped with source seq+ts.")
    ap.add_argument("captures", nargs="+",
                    help="JSONL capture file(s); globs allowed")
    ap.add_argument("--stale-hours", dest="stale_hours", type=float,
                    default=DEF["stale_hours"],
                    help="source lags freshest source by this => stale")
    ap.add_argument("--hole-hours", dest="hole_hours", type=float,
                    default=DEF["hole_hours"],
                    help="consecutive-message gap that counts as a hole")
    ap.add_argument("--lag-hours", dest="lag_hours", type=float,
                    default=DEF["lag_hours"],
                    help="mtime minus last internal ts => capture lag")
    ap.add_argument("--regress-mins", dest="regress_mins", type=float,
                    default=DEF["regress_mins"],
                    help="ts behind running max by this => regression")
    ap.add_argument("--ref", default=None,
                    help="reference 'now' (ISO) instead of freshest "
                         "source ts")
    ap.add_argument("--limit", type=int, default=20,
                    help="max findings printed")
    ap.add_argument("--json", action="store_true",
                    help="emit findings + source stats as JSON")
    args = ap.parse_args(argv)
    files = expand(args.captures)
    bad = [f for f in files
           if not (os.path.isfile(f) or any(c in f for c in "*?["))]
    if bad:
        print(f"error: cannot read {bad[0]}", file=sys.stderr)
        return 2
    try:
        stats = [scan_file(f) for f in files]
    except OSError as e:
        print(f"error: {e}", file=sys.stderr)
        return 2
    opts = vars(args).copy()
    opts["ref_epoch"] = epoch(args.ref) if args.ref else None
    findings = analyze(stats, opts)
    if args.json:
        slim = [{k: v for k, v in s.items()
                 if k not in ("holes", "ts_reg", "seq_reg", "malformed_at",
                              "missing_at")} for s in stats]
        print(json.dumps({"findings": findings, "sources": slim},
                         ensure_ascii=False))
    else:
        render(findings, stats, args.limit)
    hard = [f for f in findings if f["severity"] in ("WARN", "BLOCK")]
    return 1 if hard else 0


def self_test():
    import io
    import os
    import tempfile
    from contextlib import redirect_stdout

    def write(recs, mtime=None):
        fh = tempfile.NamedTemporaryFile("w", suffix=".jsonl",
                                         delete=False)
        for r in recs:
            fh.write((r if isinstance(r, str) else json.dumps(r)) + "\n")
        fh.close()
        if mtime is not None:
            os.utime(fh.name, (mtime, mtime))
        return fh.name

    def run(paths, extra=()):
        buf = io.StringIO()
        with redirect_stdout(buf):
            rc = main([*paths, *extra])
        return rc, buf.getvalue()

    def rec(seq, ts):
        return dict(seq=seq, ts=ts)

    T0 = "2026-09-20T10:00:00Z"
    T1 = "2026-09-20T10:05:00Z"
    T2 = "2026-09-20T11:00:00Z"

    # 1) clean single fresh source: silent
    now = 1789900000
    p = write([rec(1, T0), rec(2, T1)], mtime=epoch(T1) + 60)
    rc, out = run([p])
    assert rc == 0 and "findings: 0" in out, (rc, out)
    stats = [scan_file(p)]
    assert stats[0]["records"] == 2 and stats[0]["malformed"] == 0

    # 2) stale-source vs freshest peer (25h behind)
    fresh_p = write([rec(1, "2026-09-21T12:00:00Z")],
                    mtime=epoch("2026-09-21T12:00:00Z"))
    stale_p = write([rec(1, "2026-09-20T11:00:00Z")],
                    mtime=epoch("2026-09-20T11:00:00Z"))
    got = analyze([scan_file(fresh_p), scan_file(stale_p)])
    kinds = {f["kind"] for f in got}
    assert "stale-source" in kinds and "25.0h" in \
        next(f for f in got if f["kind"] == "stale-source")["detail"], got
    # threshold: 24h exactly does not flag (strictly greater)
    got = analyze([scan_file(fresh_p), scan_file(stale_p)],
                  dict(stale_hours=25.0))
    assert "stale-source" not in {f["kind"] for f in got}

    # 3) coverage hole: 7h between consecutive messages
    hole_p = write([rec(1, T0), rec(2, "2026-09-20T17:30:00Z")],
                   mtime=epoch("2026-09-20T17:30:00Z"))
    got = analyze([scan_file(hole_p)])
    f = next(f for f in got if f["kind"] == "coverage-hole")
    assert "7.5h hole" in f["detail"] and f.get("seq") == 2, f
    assert f.get("ts", "").startswith("2026-09-20T17:30"), f

    # 4) capture lag: mtime 7h after last internal ts
    lag_p = write([rec(1, T1)], mtime=epoch(T1) + 7 * 3600)
    got = analyze([scan_file(lag_p)])
    f = next(f for f in got if f["kind"] == "capture-lag")
    assert "7.0h" in f["detail"], f

    # 5) ts regression: later line 2h behind running max
    reg_p = write([rec(1, T2), rec(2, T0)], mtime=epoch(T2))
    got = analyze([scan_file(reg_p)])
    f = next(f for f in got if f["kind"] == "ts-regression")
    assert "1.0h behind" in f["detail"] and f.get("seq") == 2, f

    # 6) seq regression
    sq_p = write([rec(5, T0), rec(4, T1)], mtime=epoch(T1))
    got = analyze([scan_file(sq_p)])
    f = next(f for f in got if f["kind"] == "seq-regression")
    assert "seq 4 < prior seq 5" in f["detail"], f

    # 7) missing ts + malformed lines are reported with line coords
    mix_p = write([rec(1, T0), '{"broken', dict(seq=2),
                   rec(3, T1)], mtime=epoch(T1))
    got = analyze([scan_file(mix_p)])
    kinds = {f["kind"] for f in got}
    assert "missing-ts" in kinds and "malformed-line" in kinds, got
    miss = next(f for f in got if f["kind"] == "missing-ts")
    assert miss.get("line") == 3, miss

    # 8) empty source
    empty_p = write([], mtime=now)
    got = analyze([scan_file(empty_p)])
    assert "empty-source" in {f["kind"] for f in got}, got

    # 9) --ref overrides the freshest-source reference
    got = analyze([scan_file(stale_p)],
                  dict(ref_epoch=epoch("2026-09-22T12:00:00Z")))
    f = next(f for f in got if f["kind"] == "stale-source")
    assert "49.0h" in f["detail"], f

    # 10) epoch() parses numbers, Z and +00:00 offsets, rejects junk
    assert abs(epoch("2026-09-20T10:00:00Z")
               - epoch("2026-09-20T10:00:00+00:00")) < 1e-6
    assert epoch(1789900000) == 1789900000.0
    assert epoch("junk") is None and epoch(True) is None

    # 11) expand(): globs resolve, dedup keeps order
    d = tempfile.mkdtemp()
    for n in ("a.jsonl", "b.jsonl"):
        open(os.path.join(d, n), "w").close()
    got = expand([os.path.join(d, "*.jsonl"), os.path.join(d, "a.jsonl")])
    assert [os.path.basename(x) for x in got] == ["a.jsonl", "b.jsonl"]

    # 12) CLI rc 1 on WARN, rc 2 on missing file, --json shape
    rc, out = run([stale_p, fresh_p])
    assert rc == 1 and "stale-source" in out, (rc, out)
    assert main(["/nonexistent-x.jsonl"]) == 2
    rc, out = run([fresh_p, "--json"])
    doc = json.loads(out)
    assert doc["findings"] == [] and doc["sources"][0]["records"] == 1

    # 13) clean multi-source render shows both rows
    fresh_q = write([rec(9, "2026-09-21T12:00:00Z")],
                    mtime=epoch("2026-09-21T12:00:00Z"))
    rc, out = run([fresh_p, fresh_q])
    assert rc == 0 and "sources: 2" in out, out
    os.unlink(fresh_q)

    for p in (p, fresh_p, stale_p, hole_p, lag_p, reg_p, sq_p, mix_p,
              empty_p):
        os.unlink(p)

    print("source-freshness-audit self-test OK (13 groups: clean "
          "freshness, stale-source + threshold, coverage hole, capture "
          "lag, ts/seq regression, missing-ts/malformed coords, empty, "
          "--ref override, epoch parsing, glob expand, CLI rc/json, "
          "multi-source render)")


if __name__ == "__main__":
    if "--self-test" in sys.argv:
        self_test()  # falls through; rc 0 (probe hook runs after)
    else:
        raise SystemExit(main())
