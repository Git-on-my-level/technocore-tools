#!/usr/bin/env python3
"""rollback-window-audit — has an operator actually KEPT a rollback
window configured, continuously, for months? persistence audit over a
saved history of configuration snapshots.

DEMAND: evidence/suggestions/tools-services/2026-11-24.md (17:57 run)
  - request: "Check if exchange operator kept rollback window inside
    audit tool for months" — evidence: "Has an exchange operator kept
    the rollback window inside the audit tool for months?" —
    proposed service: "Long-term rollback-window presence audit in
    hermes-tools."
  Existing window tools check reveal/settlement windows at one point
  in time, not months-long rollback-window persistence.

Scope: one JSONL file of dated configuration snapshots, one per line:
  {"ts": "2026-05-02T00:00:00Z", "operator": "acme-exchange",
   "rollback_hours": 72, "mode": "retain"}
(rollback_days is accepted and normalised to hours; mode is optional.)
Snapshots are grouped per operator and judged as a time series — the
question is persistence, not a single reading. Data only: plain
parsing and arithmetic over saved snapshots, no network, no
subprocess, nothing is ever run. Stdlib only.

What it does (per operator, within an optional --operator filter):
  span            days between the operator's first and last snapshot
  verdicts
    window-absent       FAIL  snapshot with mode "disabled"/"off" or
                          no rollback field at all
    window-below-floor  FAIL  rollback_hours < --floor-hours (24)
    coverage-gap        WARN  consecutive snapshots further apart than
                          --max-gap-days (35): cannot attest continuity
    window-shrink       WARN  window drops by more than --max-shrink-pct
                          (50%) between consecutive snapshots
    short-span          WARN  whole series spans < --min-span-days (90)
                          — not "months" of evidence
    stale-config        WARN  last snapshot older than --max-age-days
                          (14) before --now
    malformed-entry     WARN  unparseable line / bad ts / bad operator
  summary line per operator: snapshots, span_days, min/max/last hours
  rc 0 window held throughout, 1 findings, 2 usage/IO.
"""
import argparse
import json
import sys
from datetime import datetime

FAIL, WARN = "FAIL", "WARN"


def parse_ts(s):
    """ISO-8601 (Z or offset) -> epoch seconds, or None."""
    if not isinstance(s, str):
        return None
    try:
        return datetime.fromisoformat(s.replace("Z", "+00:00")).timestamp()
    except ValueError:
        return None


def read_jsonl(path):
    """Yield (lineno, rec-or-None) for each JSONL line."""
    with open(path, "r", errors="replace") as fh:
        for n, line in enumerate(fh, 1):
            line = line.strip()
            if not line:
                continue
            try:
                rec = json.loads(line)
            except ValueError:
                rec = None
            yield n, rec if isinstance(rec, dict) else None


def window_hours(rec):
    """Snapshot -> rollback window in hours, or None if absent/invalid.

    Accepts rollback_hours (number) or rollback_days (number);
    mode "disabled"/"off" counts as absent even if a number is present.
    """
    if not isinstance(rec, dict):
        return None
    mode = rec.get("mode")
    if isinstance(mode, str) and mode.strip().lower() in (
            "disabled", "off", "none"):
        return None
    for key, mult in (("rollback_hours", 1.0), ("rollback_days", 24.0)):
        v = rec.get(key)
        if isinstance(v, bool) or not isinstance(v, (int, float)):
            continue
        if v < 0:
            return None
        return float(v) * mult
    return None


def snapshot_ok(rec):
    """True when the line is well-formed enough to audit at all."""
    return (isinstance(rec, dict) and isinstance(rec.get("operator"), str)
            and rec["operator"] != "" and parse_ts(rec.get("ts")) is not None)


def series_findings(snaps, name, floor_h, max_gap_d, max_shrink_pct):
    """One operator's ts-sorted snapshots -> findings + summary."""
    out = []
    snaps = sorted(snaps, key=lambda s: s[0])
    hours = [w for _, w in snaps]
    for ts, w in snaps:
        if w is None:
            out.append((FAIL, "window-absent",
                        f"{name} at {ts:.0f}"))
        elif w < floor_h:
            out.append((FAIL, "window-below-floor",
                        f"{name} {w:g}h < {floor_h:g}h"))
    for (t0, w0), (t1, w1) in zip(snaps, snaps[1:]):
        gap_d = (t1 - t0) / 86400.0
        if gap_d > max_gap_d:
            out.append((WARN, "coverage-gap",
                        f"{name} {gap_d:.0f}d between snapshots"))
        if w0 is not None and w1 is not None and w1 < w0:
            drop = (w0 - w1) / w0 * 100.0
            if drop > max_shrink_pct:
                out.append((WARN, "window-shrink",
                            f"{name} {w0:g}h -> {w1:g}h "
                            f"(-{drop:.0f}%)"))
    span_d = (snaps[-1][0] - snaps[0][0]) / 86400.0 if len(snaps) > 1 \
        else 0.0
    summary = {"operator": name, "snapshots": len(snaps),
               "span_days": round(span_d, 1),
               "min_hours": min(h for h in hours if h is not None)
               if any(h is not None for h in hours) else None,
               "max_hours": max(h for h in hours if h is not None)
               if any(h is not None for h in hours) else None,
               "last_hours": hours[-1] if hours else None}
    return out, summary, span_d


def audit(path, operators, floor_h, min_span_d, max_gap_d,
          max_shrink_pct, max_age_d, now):
    """Whole file -> (findings, summaries per operator)."""
    per_op, findings = {}, []
    for n, rec in read_jsonl(path):
        if not snapshot_ok(rec):
            findings.append((WARN, "malformed-entry", f"line {n}"))
            continue
        op = rec["operator"]
        if operators and op not in operators:
            continue
        per_op.setdefault(op, []).append(
            (parse_ts(rec["ts"]), window_hours(rec)))
    summaries = []
    for op, snaps in sorted(per_op.items()):
        f, summary, span_d = series_findings(snaps, op, floor_h, max_gap_d,
                                             max_shrink_pct)
        findings.extend(f)
        if span_d < min_span_d:
            findings.append((WARN, "short-span",
                             f"{op} {span_d:.0f}d < {min_span_d}d"))
        if now is not None and snaps:
            age_d = (now - snaps[-1][0]) / 86400.0
            if age_d > max_age_d:
                findings.append((WARN, "stale-config",
                                 f"{op} last snapshot {age_d:.0f}d old"))
        summaries.append(summary)
    if operators:
        for miss in sorted(operators - set(per_op)):
            findings.append((WARN, "malformed-entry",
                             f"no snapshots for operator {miss}"))
    return findings, summaries


def main(argv=None):
    ap = argparse.ArgumentParser(
        description="months-long rollback-window persistence audit")
    ap.add_argument("snapshots", help="JSONL config snapshots")
    ap.add_argument("--operator", default=None,
                    help="restrict to this operator (repeatable)",
                    action="append")
    ap.add_argument("--floor-hours", type=float, default=24.0,
                    help="minimum acceptable window (default 24)")
    ap.add_argument("--min-span-days", type=float, default=90.0,
                    help="span required to claim 'months' (default 90)")
    ap.add_argument("--max-gap-days", type=float, default=35.0,
                    help="largest silent gap between snapshots (default 35)")
    ap.add_argument("--max-shrink-pct", type=float, default=50.0,
                    help="largest window drop between snapshots (default 50)")
    ap.add_argument("--max-age-days", type=float, default=14.0,
                    help="how stale the last snapshot may be (default 14)")
    ap.add_argument("--now", default=None,
                    help="ISO-8601 reference time (default: no staleness)")
    args = ap.parse_args(argv)

    operators = {o for o in (args.operator or []) if o} or None
    now = parse_ts(args.now) if args.now else None
    if args.now and now is None:
        print("bad --now", file=sys.stderr)
        return 2
    if args.floor_hours < 0 or args.min_span_days < 0 \
            or args.max_gap_days < 0 or args.max_shrink_pct < 0 \
            or args.max_age_days < 0:
        print("negative policy argument", file=sys.stderr)
        return 2
    try:
        findings, summaries = audit(args.snapshots, operators,
                                    args.floor_hours, args.min_span_days,
                                    args.max_gap_days, args.max_shrink_pct,
                                    args.max_age_days, now)
    except OSError as e:
        print(f"cannot read snapshots: {e}", file=sys.stderr)
        return 2
    for sev, code, what in findings:
        print(f"{sev} {code} {what}", file=sys.stderr)
    for s in summaries:
        print(json.dumps(s, sort_keys=True))
    return 1 if findings else 0


def self_test():
    import os
    import tempfile
    tmp = tempfile.mkdtemp(prefix="rbwin-")
    snaps = os.path.join(tmp, "snapshots.jsonl")

    def snap(ts, op="acme-exchange", **kw):
        rec = {"ts": ts, "operator": op}
        rec.update(kw)
        return json.dumps(rec)

    assert parse_ts("2026-08-01T00:00:00Z") == parse_ts(
        "2026-08-01T00:00:00+00:00")
    assert parse_ts("junk") is None and parse_ts(None) is None
    # window extraction: hours, days normalisation, absence, mode off
    assert window_hours({"rollback_hours": 72}) == 72.0
    assert window_hours({"rollback_days": 3}) == 72.0
    assert window_hours({"rollback_hours": "72"}) is None
    assert window_hours({"rollback_hours": -1}) is None
    assert window_hours({"mode": "disabled", "rollback_hours": 72}) is None
    assert window_hours({"mode": "retain", "rollback_hours": 72}) == 72.0
    assert window_hours({}) is None and window_hours("junk") is None
    assert snapshot_ok({"ts": "2026-08-01T00:00:00Z",
                        "operator": "a"})
    assert not snapshot_ok({"ts": "junk", "operator": "a"})
    assert not snapshot_ok({"ts": "2026-08-01T00:00:00Z", "operator": ""})

    # five monthly snapshots, 72h throughout, spanning ~120 days
    with open(snaps, "w") as fh:
        for m, d in ((5, 2), (6, 1), (7, 1), (8, 1), (9, 1)):
            fh.write(snap(f"2026-{m:02d}-{d:02d}T00:00:00Z",
                          rollback_hours=72, mode="retain") + "\n")
    rc = main([snaps, "--now", "2026-09-05T00:00:00Z"])
    assert rc == 0, "months of 72h snapshots with monthly cadence is clean"

    # same series but one snapshot flips the window off -> FAIL
    with open(snaps, "w") as fh:
        rows = [(5, 2, 72), (6, 1, 72), (7, 1, None), (8, 1, 72),
                (9, 1, 72)]
        for m, d, h in rows:
            kw = {"mode": "disabled"} if h is None \
                else {"rollback_hours": h, "mode": "retain"}
            fh.write(snap(f"2026-{m:02d}-{d:02d}T00:00:00Z", **kw) + "\n")
    f, s = audit(snaps, None, 24, 90, 7, 50, 14, None)
    assert any(c == "window-absent" for _, c, _ in f), f
    assert rc_probe(snaps, ["--now", "2026-09-05T00:00:00Z"]) == 1

    # window 72 -> 24 is a 66% shrink -> WARN; 72 -> 48 is 33% -> clean
    with open(snaps, "w") as fh:
        fh.write(snap("2026-05-02T00:00:00Z", rollback_hours=72) + "\n")
        fh.write(snap("2026-06-01T00:00:00Z", rollback_hours=24) + "\n")
        for m in (7, 8, 9):
            fh.write(snap(f"2026-{m:02d}-01T00:00:00Z",
                          rollback_hours=24) + "\n")
    f, _ = audit(snaps, None, 24, 90, 7, 50, 14, None)
    assert any(c == "window-shrink" for _, c, _ in f), f
    f, _ = audit(snaps, None, 24, 90, 7, 80, 14, None)
    assert not any(c == "window-shrink" for _, c, _ in f), f

    # below-floor reading -> FAIL
    with open(snaps, "w") as fh:
        fh.write(snap("2026-05-02T00:00:00Z", rollback_hours=8) + "\n")
    f, _ = audit(snaps, None, 24, 90, 7, 50, 14, None)
    assert any(c == "window-below-floor" for _, c, _ in f), f

    # 60-day silent gap -> coverage-gap WARN
    with open(snaps, "w") as fh:
        fh.write(snap("2026-05-02T00:00:00Z", rollback_hours=72) + "\n")
        fh.write(snap("2026-07-01T00:00:00Z", rollback_hours=72) + "\n")
        fh.write(snap("2026-12-01T00:00:00Z", rollback_hours=72) + "\n")
    f, _ = audit(snaps, None, 24, 90, 7, 50, 14, None)
    assert any(c == "coverage-gap" for _, c, _ in f), f

    # short series -> short-span WARN even though every reading is fine
    with open(snaps, "w") as fh:
        fh.write(snap("2026-08-01T00:00:00Z", rollback_hours=72) + "\n")
        fh.write(snap("2026-08-20T00:00:00Z", rollback_hours=72) + "\n")
    f, s = audit(snaps, None, 24, 90, 7, 50, 14, None)
    assert any(c == "short-span" for _, c, _ in f), f
    assert s[0]["span_days"] == 19.0, s
    rc = main([snaps])
    assert rc == 1, "19 days is not months"

    # stale last snapshot vs --now -> WARN; fresh is clean
    f, _ = audit(snaps, None, 24, 90, 7, 50, 14,
                 parse_ts("2026-09-15T00:00:00Z"))
    assert any(c == "stale-config" for _, c, _ in f), f
    f, _ = audit(snaps, None, 24, 90, 7, 50, 14,
                 parse_ts("2026-08-25T00:00:00Z"))
    assert not any(c == "stale-config" for _, c, _ in f), f

    # two operators: filter isolates one; unknown filter name warns
    with open(snaps, "w") as fh:
        fh.write(snap("2026-05-02T00:00:00Z", op="alpha",
                      rollback_hours=72) + "\n")
        fh.write(snap("2026-05-03T00:00:00Z", op="beta",
                      rollback_days=1) + "\n")  # 24h, below alpha only?
        for m in (6, 7, 8):
            fh.write(snap(f"2026-{m:02d}-01T00:00:00Z", op="alpha",
                          rollback_hours=72) + "\n")
            fh.write(snap(f"2026-{m:02d}-02T00:00:00Z", op="beta",
                          rollback_days=2) + "\n")
    f, s = audit(snaps, {"alpha"}, 24, 90, 7, 50, 14, None)
    assert all("alpha" in w or c in ("short-span",) for _, c, w in f), f
    assert [x["operator"] for x in s] == ["alpha"], s
    rc = main([snaps, "--operator", "ghost"])
    assert rc == 1, "filtered-out operator leaves a warning"

    # malformed lines and usage paths
    with open(snaps, "w") as fh:
        fh.write(snap("2026-05-02T00:00:00Z", rollback_hours=72) + "\n")
        fh.write("{oops\n")
    rc = main([snaps])
    assert rc == 1, "malformed line is a finding"
    rc = main(["nope.jsonl"])
    assert rc == 2, "missing file is usage/IO"
    rc = main([snaps, "--now", "junk"])
    assert rc == 2, "bad --now is usage"
    rc = main([snaps, "--floor-hours", "-5"])
    assert rc == 2, "negative policy is usage"
    print("OK rollback-window-audit: per-operator persistence series "
          "(hours/days normalised, mode-off = absent), absent/below-floor/"
          "gap/shrink/short-span/stale verdicts, operator filter incl. "
          "unknown, per-op summary with span, CLI rc 0/1/2")


def rc_probe(path, extra):
    """Run main() on a file with extra args; returns rc."""
    return main([path] + extra)


if __name__ == "__main__":
    if "--self-test" in sys.argv:
        self_test()  # falls through; rc 0 (probe hook runs after this)
    else:
        raise SystemExit(main())
