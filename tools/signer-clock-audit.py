#!/usr/bin/env python3
"""signer-clock-audit — signer timestamp-unit, flip and skew audit.

DEMAND: evidence/suggestions/tools-services/ (file citations below)
  - "audit signer configs for timestamp mismatch causing skipped confirmations"
  - "audit delegate agent-did config after ms-timestamp signing caused soft reorg"
  - "Complaint about audit trail timestamp issues causing proof rejections."
  - "Signing-cycle coordination"
  Scope: audits a JSONL capture of signer event streams, one record per
  line: ts, signer, did, event (signed|confirmed|skipped|reorg), ts_value,
  ts_unit_hint (s|ms|ns|empty), lag_ms. Infers each ts_value's epoch unit
  from its magnitude, flags config hints that disagree with it, mid-stream
  unit flips, non-monotonic streams, skipped confirmations and reorgs
  downstream of a flip, and cross-signer lag skew with no coordination
  record on file. Inputs are data only: plain parsing, no network, no
  subprocess, nothing is run from input. rc 0 clean, 1 findings, 2
  usage/IO. Stdlib only.
"""
import argparse
import io
import json
import os
import sys
import tempfile
from contextlib import redirect_stderr, redirect_stdout
from statistics import median

SEVS = ("BLOCK", "WARN", "INFO")
HINTS = ("s", "ms", "ns")


def num(v):
    """Numeric and not bool -> float; else None."""
    if isinstance(v, bool):
        return None
    return float(v) if isinstance(v, (int, float)) else None


def infer_unit(v):
    """Epoch magnitude -> unit label.

    1e9 <= v < 1e11 reads as epoch seconds, 1e12 <= v < 1e15 as epoch
    milliseconds, v >= 1e15 as epoch nanoseconds; anything else (negative,
    sub-second, ambiguous gap) -> None.
    """
    n = num(v)
    if n is None or n < 0:
        return None
    if 1e9 <= n < 1e11:
        return "s"
    if 1e12 <= n < 1e15:
        return "ms"
    if n >= 1e15:
        return "ns"
    return None


def load_jsonl(path):
    """Parse a JSONL capture -> (records, bad_lines).

    One record per line; blank lines are skipped; a line that is not a
    JSON object yields a None record and its 1-based number lands in
    bad_lines.
    """
    records, bad = [], []
    with open(path, "r", encoding="utf-8") as fh:
        for i, line in enumerate(fh, 1):
            s = line.strip()
            if not s:
                continue
            try:
                rec = json.loads(s)
            except ValueError:
                rec = None
            if not isinstance(rec, dict):
                bad.append(i)
            records.append(rec)
    return records, bad


def streams(records):
    """{signer: [(global_index, record)]} over well-formed signer rows."""
    out = {}
    for i, rec in enumerate(records):
        if not rec:
            continue
        sg = rec.get("signer")
        if isinstance(sg, str) and sg:
            out.setdefault(sg, []).append((i, rec))
    return out


def flips_by_signer(records):
    """{signer: [(stream_position, record)]} where the ts unit flipped.

    A flip is a ~1000x or ~1e6x jump between consecutive ts_values of one
    signer whose inferred unit label actually changed (s<->ms, ms<->ns or
    s<->ns) — i.e. the delegate config changed clock units mid-stream.
    """
    out = {}
    for sg in sorted(streams(records)):
        prev = None  # (stream position, value)
        for pos, (_gi, rec) in enumerate(streams(records)[sg]):
            n = num(rec.get("ts_value"))
            if n is None or n <= 0:
                continue
            if prev is not None:
                pu, cu = infer_unit(prev[1]), infer_unit(n)
                lo, hi = sorted((prev[1], n))
                ratio = hi / lo
                if pu and cu and pu != cu and (1e2 <= ratio <= 1e4
                                               or 1e5 <= ratio <= 1e7):
                    out.setdefault(sg, []).append((pos, rec))
            prev = (pos, n)
    return out


def unit_mismatch_findings(records):
    """Config-hint vs inferred unit (WARN) and mid-stream flips (BLOCK)."""
    finds = []
    for rec in records:
        if not rec:
            continue
        n = num(rec.get("ts_value"))
        hint = rec.get("ts_unit_hint")
        if n is None or hint not in HINTS:
            continue
        got = infer_unit(n)
        if got != hint:
            finds.append({"kind": "unit-hint-mismatch", "severity": "WARN",
                          "origin": rec.get("signer") or "?",
                          "detail": "ts_value %g infers %s but ts_unit_hint=%s"
                                    % (n, got, hint)})
    for sg in sorted(flips_by_signer(records)):
        for _pos, rec in flips_by_signer(records)[sg]:
            finds.append({"kind": "ts-unit-flip", "severity": "BLOCK",
                          "origin": sg,
                          "detail": "ts_value changed epoch units mid-stream "
                                    "at %s event (ts_value=%s)"
                                    % (rec.get("event"), rec.get("ts_value"))})
    return finds


def monotonic_findings(records):
    """ts_value moving backwards within one signer's stream -> WARN."""
    finds = []
    for sg in sorted(streams(records)):
        prev = None  # (stream position, value)
        for pos, (_gi, rec) in enumerate(streams(records)[sg]):
            n = num(rec.get("ts_value"))
            if n is None:
                continue
            if prev is not None and n < prev[1]:
                finds.append({"kind": "non-monotonic-ts", "severity": "WARN",
                              "origin": sg,
                              "detail": "ts_value %g at stream pos %d below "
                                        "earlier %g" % (n, pos, prev[1])})
            prev = (pos, n)
    return finds


def skip_findings(records, window=3):
    """Skips/reorgs downstream of a unit flip.

    - a skipped confirmation within `window` stream events after a flip
      -> WARN
    - a reorg on a signer whose stream flipped -> BLOCK, attributed to
      that signer's config
    """
    finds = []
    flips = flips_by_signer(records)
    for sg in sorted(flips):
        fpos = [p for p, _r in flips[sg]]
        for pos, (_gi, rec) in enumerate(streams(records)[sg]):
            ev = rec.get("event")
            behind = [p for p in fpos if 0 < pos - p <= window]
            if ev == "skipped" and behind:
                finds.append({"kind": "skip-after-unit-flip", "severity": "WARN",
                              "origin": sg,
                              "detail": "confirmation skipped %d event(s) "
                                        "after a ts unit flip"
                                        % (pos - max(behind))})
            elif ev == "reorg":
                finds.append({"kind": "reorg-after-unit-flip", "severity": "BLOCK",
                              "origin": sg,
                              "detail": "reorg attributed to signer %s: stream "
                                        "flipped ts units %d time(s)"
                                        % (sg, len(fpos))})
    return finds


def skew_findings(records, threshold_ms=5000.0):
    """Cross-signer lag spread beyond threshold with no coordination record.

    Medians of per-signer lag_ms are compared across signers; a spread
    beyond threshold_ms is only a finding when the fastest and slowest
    signers do not share a did — a shared did is the coordination record
    proving one signing-cycle config owns both streams.
    """
    lags, dids = {}, {}
    for rec in records:
        if not rec:
            continue
        sg = rec.get("signer")
        if not (isinstance(sg, str) and sg):
            continue
        lag = num(rec.get("lag_ms"))
        if lag is not None:
            lags.setdefault(sg, []).append(lag)
        d = rec.get("did")
        if isinstance(d, str) and d:
            dids.setdefault(sg, set()).add(d)
    if len(lags) < 2:
        return []
    med = {sg: median(v) for sg, v in lags.items()}
    fast = min(med, key=lambda k: med[k])
    slow = max(med, key=lambda k: med[k])
    spread = med[slow] - med[fast]
    if spread <= threshold_ms:
        return []
    if dids.get(fast, set()) & dids.get(slow, set()):
        return []  # shared did: coordinated signing cycle, skew is expected
    return [{"kind": "cross-signer-skew", "severity": "WARN",
             "origin": "%s/%s" % (fast, slow),
             "detail": "lag_ms spread %.0f (median %s=%.0f, %s=%.0f) beyond "
                       "%.0f with no coordination record"
                       % (spread, fast, med[fast], slow, med[slow],
                          threshold_ms)}]


def audit(path):
    """Load the capture and run every check; returns the findings list."""
    records, bad = load_jsonl(path)
    finds = [{"kind": "malformed-line", "severity": "WARN",
              "origin": "line:%d" % ln,
              "detail": "line is not a JSON object; skipped"} for ln in bad]
    finds += unit_mismatch_findings(records)
    finds += monotonic_findings(records)
    finds += skip_findings(records)
    finds += skew_findings(records)
    return finds


def render(findings):
    """Print 'SEV kind origin: detail' per finding; return severity counts."""
    counts = {}
    for f in findings:
        sev = f.get("severity", "INFO")
        counts[sev] = counts.get(sev, 0) + 1
        print("%-5s %-22s %s: %s" % (sev, f.get("kind", "?"),
                                     f.get("origin", "?"), f.get("detail", "")))
    return counts


def main(argv=None):
    """CLI: path positional, --json optional. 0 clean / 1 findings / 2 IO."""
    ap = argparse.ArgumentParser(
        description="Audit signer timestamp units, flips, skips and "
                    "cross-signer skew.")
    ap.add_argument("path", help="JSONL capture of signer event streams")
    ap.add_argument("--json", action="store_true",
                    help="emit findings as a JSON array")
    args = ap.parse_args(argv)
    try:
        findings = audit(args.path)
    except OSError as exc:
        print("error: cannot read %s: %s" % (args.path, exc), file=sys.stderr)
        return 2
    if args.json:
        print(json.dumps(findings, sort_keys=True))
    else:
        render(findings)
    return 1 if findings else 0


def _rec(signer, event, ts_value, hint, ts=0, lag_ms=None, did=None):
    """Compact signer-stream fixture record."""
    return dict(ts=ts, signer=signer, did=did, event=event,
                ts_value=ts_value, ts_unit_hint=hint, lag_ms=lag_ms)


def _run_capture(recs, extra=None):
    """Write recs to a temp JSONL file, run main quietly -> (rc, stdout)."""
    with tempfile.NamedTemporaryFile("w", suffix=".jsonl", delete=False) as tf:
        for r in recs:
            tf.write((r if isinstance(r, str) else json.dumps(r)) + "\n")
        path = tf.name
    try:
        buf = io.StringIO()
        with redirect_stdout(buf):
            rc = main([path] + list(extra or []))
        return rc, buf.getvalue()
    finally:
        os.unlink(path)


def self_test():
    # unit inference from epoch magnitude
    assert infer_unit(1700000000) == "s"
    assert infer_unit(1700000000123) == "ms"
    assert infer_unit(1.7e18) == "ns"
    assert infer_unit(42) is None and infer_unit("x") is None
    # ms-then-s flip within one signer stream
    flip = [
        _rec("s1", "signed", 1700000000123, "", ts=1),
        _rec("s1", "signed", 1700000005, "s", ts=2),
        _rec("s1", "skipped", 1700000006, "s", ts=3),
        _rec("s1", "reorg", 1700000007, "s", ts=4),
    ]
    fl = flips_by_signer(flip)
    assert list(fl) == ["s1"] and fl["s1"][0][0] == 1
    f = unit_mismatch_findings(flip)
    assert any(x["kind"] == "ts-unit-flip" and x["severity"] == "BLOCK"
               for x in f)
    f = skip_findings(flip)
    assert {x["kind"] for x in f} == {"skip-after-unit-flip",
                                      "reorg-after-unit-flip"}
    assert monotonic_findings(flip) and \
        monotonic_findings(flip)[0]["kind"] == "non-monotonic-ts"
    # steady stream: no flips, no monotonic breaks, no findings at all
    steady = [
        _rec("s1", "signed", 1700000000, "s", ts=1),
        _rec("s1", "confirmed", 1700000005, "s", ts=2),
    ]
    assert flips_by_signer(steady) == {} and monotonic_findings(steady) == []
    rc, out = _run_capture(steady)
    assert rc == 0, out
    # config hint disagrees with the inferred unit
    f = unit_mismatch_findings([_rec("s2", "signed", 1700000000123, "s")])
    assert f and f[0]["kind"] == "unit-hint-mismatch" \
        and f[0]["severity"] == "WARN"
    # cross-signer skew with and without a coordination record
    skew = [
        _rec("a", "signed", 1700000000, "s", lag_ms=10, did="did:web:alpha"),
        _rec("b", "signed", 1700000001, "s", lag_ms=9000, did="did:web:beta"),
    ]
    assert skew_findings(skew) and \
        skew_findings(skew)[0]["kind"] == "cross-signer-skew"
    coord = [
        _rec("a", "signed", 1700000000, "s", lag_ms=10, did="did:web:alpha"),
        _rec("b", "signed", 1700000001, "s", lag_ms=9000, did="did:web:alpha"),
    ]
    assert skew_findings(coord) == []  # shared did = coordination record
    # CLI rc paths
    rc, out = _run_capture(flip)
    assert rc == 1 and "ts-unit-flip" in out
    err = io.StringIO()
    with redirect_stderr(err):
        rc_missing = main(["/nonexistent/signer-stream.jsonl"])
    assert rc_missing == 2
    print("self-test OK (infer_unit, flip detect, hint mismatch, monotonic, "
          "skip/reorg after flip, skew+coordination, CLI rc=0/1/2)")


if __name__ == "__main__":
    if "--self-test" in sys.argv:
        self_test()  # falls through; rc 0 (probe hook runs after this)
    else:
        raise SystemExit(main())
