#!/usr/bin/env python3
"""zk-bench-audit — proof-time regression, guarantee, envelope, sample audit.

DEMAND: evidence/suggestions/tools-services/ (file citations below)
  - "Benchmark comparison of old vs. new zk_audit subcircuit"
  - "Benchmarking and capacity planning for zk_audit throughput"
  - "Need for stress testing and capacity planning for zk_audit beyond 4k operations."
  - "Per-trade or per-batch zk_audit throughput guarantees for large settlements"
  - "Need faster zk_audit queue and higher proof throughput for large ETH batches."
  Scope: audits a JSONL capture of circuit benchmark samples, one record
  per line: ts, circuit, version, batch_size, ops, proof_ms, verify_ms,
  claimed_guarantee_ms. Compares mean proof_ms of the newest version of a
  circuit+batch_size cell against its predecessor (regression/improvement),
  checks per-batch guarantee claims against measured proof_ms, flags ops
  claims extrapolated past the measured envelope (> 4k operations with no
  sample that large), thin sample counts behind claimed numbers, and
  verify_ms spikes. Inputs are data only: plain parsing, no network, no
  subprocess, nothing is run from input. rc 0 clean, 1 findings, 2
  usage/IO. Stdlib only.
"""
import argparse
import io
import json
import os
import re
import sys
import tempfile
from contextlib import redirect_stderr, redirect_stdout
from statistics import mean, median

SEVS = ("BLOCK", "WARN", "INFO")
REGRESSION_RATIO = 1.15


def num(v):
    """Numeric and not bool -> float; else None."""
    if isinstance(v, bool):
        return None
    return float(v) if isinstance(v, (int, float)) else None


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


def version_key(v):
    """Total-order sort key for a version tag: numeric prefix, then the tag."""
    s = str(v)
    m = re.match(r"\s*v?(\d+(?:\.\d+)*)", s)
    if m:
        return (1, float(m.group(1)), s)
    return (0, 0.0, s)


def regression_findings(records):
    """Newest vs previous version mean proof_ms per (circuit, batch_size).

    Newest version's mean more than REGRESSION_RATIO times the previous
    version's mean -> BLOCK; at least that much faster -> INFO improvement.
    """
    groups = {}
    for rec in records:
        if not rec:
            continue
        cir = rec.get("circuit")
        bs = num(rec.get("batch_size"))
        pm = num(rec.get("proof_ms"))
        ver = rec.get("version")
        if not (isinstance(cir, str) and cir) or bs is None or pm is None \
                or ver is None:
            continue
        groups.setdefault((cir, bs), {}).setdefault(str(ver), []).append(pm)
    finds = []
    for cir, bs in sorted(groups):
        vers = groups[(cir, bs)]
        if len(vers) < 2:
            continue
        order = sorted(vers, key=version_key)
        new, old = order[-1], order[-2]
        nm, om = mean(vers[new]), mean(vers[old])
        if om <= 0:
            continue
        ratio = nm / om
        origin = "%s@%g" % (cir, bs)
        if ratio > REGRESSION_RATIO:
            finds.append({"kind": "proof-regression", "severity": "BLOCK",
                          "origin": origin,
                          "detail": "v%s mean proof_ms %.1f is %.2fx v%s mean "
                                    "%.1f" % (new, nm, ratio, old, om)})
        elif ratio < 1.0 / REGRESSION_RATIO:
            finds.append({"kind": "proof-improvement", "severity": "INFO",
                          "origin": origin,
                          "detail": "v%s mean proof_ms %.1f is %.2fx v%s mean "
                                    "%.1f (faster)" % (new, nm, ratio, old, om)})
    return finds


def guarantee_findings(records):
    """Per-batch guarantee: proof_ms above claimed_guarantee_ms.

    WARN for an isolated violation; BLOCK once a circuit has three or
    more violating batches (systematic guarantee breach).
    """
    viol = {}
    for rec in records:
        if not rec:
            continue
        pm = num(rec.get("proof_ms"))
        cg = num(rec.get("claimed_guarantee_ms"))
        if pm is None or cg is None or pm <= cg:
            continue
        cir = rec.get("circuit")
        cir = cir if isinstance(cir, str) and cir else "?"
        viol.setdefault(cir, []).append((rec, pm, cg))
    finds = []
    for cir in sorted(viol):
        rows = viol[cir]
        sev = "BLOCK" if len(rows) >= 3 else "WARN"
        for rec, pm, cg in rows:
            finds.append({"kind": "guarantee-violation", "severity": sev,
                          "origin": cir,
                          "detail": "proof_ms %g exceeds claimed_guarantee_ms "
                                    "%g (batch_size %s)"
                                    % (pm, cg, rec.get("batch_size"))})
    return finds


def envelope_findings(records, max_ops=4000):
    """Ops claims extrapolated beyond the measured envelope.

    A row claiming ops beyond max_ops with no measured proof_ms sample at
    that size or larger in the same circuit is an extrapolated claim.
    """
    measured = {}
    for rec in records:
        if not rec:
            continue
        cir = rec.get("circuit")
        ops = num(rec.get("ops"))
        if isinstance(cir, str) and cir and ops is not None \
                and num(rec.get("proof_ms")) is not None:
            measured.setdefault(cir, []).append(ops)
    finds = []
    for rec in records:
        if not rec:
            continue
        cir = rec.get("circuit")
        ops = num(rec.get("ops"))
        if not (isinstance(cir, str) and cir) or ops is None or ops <= max_ops:
            continue
        if not any(o >= ops for o in measured.get(cir, [])):
            finds.append({"kind": "extrapolated-claim", "severity": "WARN",
                          "origin": cir,
                          "detail": "ops %g beyond %g with no measured sample "
                                    "at that size" % (ops, max_ops)})
    return finds


def sample_findings(records, min_samples=3, spike_mult=5.0):
    """Thin samples behind claimed numbers; verify_ms spikes vs median."""
    claimed = {}
    verifies = {}
    for rec in records:
        if not rec:
            continue
        cir = rec.get("circuit")
        if not (isinstance(cir, str) and cir):
            continue
        cg = num(rec.get("claimed_guarantee_ms"))
        bs = num(rec.get("batch_size"))
        if cg is not None:
            key = (cir, bs)
            claimed.setdefault(key, 0)
            if num(rec.get("proof_ms")) is not None:
                claimed[key] += 1
        vm = num(rec.get("verify_ms"))
        if vm is not None:
            verifies.setdefault(cir, []).append(vm)
    finds = []
    for cir, bs in sorted(claimed, key=lambda k: (k[0], k[1] if k[1] is not None else -1.0)):
        n = claimed[(cir, bs)]
        if n < min_samples:
            finds.append({"kind": "thin-sample", "severity": "WARN",
                          "origin": "%s@%s" % (cir, bs),
                          "detail": "claimed_guarantee_ms backed by %d measured "
                                    "sample(s), need %d" % (n, min_samples)})
    for cir in sorted(verifies):
        med = median(verifies[cir])
        if med <= 0:
            continue
        for v in verifies[cir]:
            if v > spike_mult * med:
                finds.append({"kind": "verify-spike", "severity": "WARN",
                              "origin": cir,
                              "detail": "verify_ms %g is more than %gx median "
                                        "%.1f" % (v, spike_mult, med)})
                break  # one spike finding per circuit is enough to alert
    return finds


def audit(path):
    """Load the capture and run every check; returns the findings list."""
    records, bad = load_jsonl(path)
    finds = [{"kind": "malformed-line", "severity": "WARN",
              "origin": "line:%d" % ln,
              "detail": "line is not a JSON object; skipped"} for ln in bad]
    finds += regression_findings(records)
    finds += guarantee_findings(records)
    finds += envelope_findings(records)
    finds += sample_findings(records)
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
        description="Audit circuit benchmark regressions, guarantee claims "
                    "and sample sizes.")
    ap.add_argument("path", help="JSONL capture of circuit benchmark samples")
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


def _rec(circuit, version, batch_size, ops, proof_ms, verify_ms, claim):
    """Compact benchmark sample builder (claim=None -> no guarantee field)."""
    rec = dict(ts=0, circuit=circuit, version=version, batch_size=batch_size,
               ops=ops, proof_ms=proof_ms, verify_ms=verify_ms)
    if claim is not None:
        rec["claimed_guarantee_ms"] = claim
    return rec


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
    # version ordering: numeric prefix wins, then tag fallback
    assert version_key("v10") > version_key("v2") > version_key("1.9")
    assert version_key("old") < version_key("1")
    # old vs new comparison per circuit+batch_size
    reg = [
        _rec("zk_audit_core", "1", 100, 4000, 100.0, 10.0, None),
        _rec("zk_audit_core", "1", 100, 4000, 110.0, 10.0, None),
        _rec("zk_audit_core", "2", 100, 4000, 145.0, 10.0, None),
        _rec("zk_audit_core", "2", 100, 4000, 143.0, 10.0, None),
    ]
    f = regression_findings(reg)
    assert f and f[0]["kind"] == "proof-regression" \
        and f[0]["severity"] == "BLOCK"
    imp = reg[:2] + [_rec("zk_audit_core", "2", 100, 4000, 80.0, 10.0, None),
                     _rec("zk_audit_core", "2", 100, 4000, 82.0, 10.0, None)]
    f = regression_findings(imp)
    assert f and f[0]["kind"] == "proof-improvement" \
        and f[0]["severity"] == "INFO"
    flat = reg[:2] + [_rec("zk_audit_core", "2", 100, 4000, 100.0, 10.0, None),
                      _rec("zk_audit_core", "2", 100, 4000, 102.0, 10.0, None)]
    assert regression_findings(flat) == []
    # per-batch guarantee violations escalate by count
    f = guarantee_findings([_rec("zk_mul", "1", 10, 100, 120.0, 5.0, 100.0)])
    assert f and f[0]["kind"] == "guarantee-violation" \
        and f[0]["severity"] == "WARN"
    f = guarantee_findings([_rec("zk_mul", "1", 10 + i, 100, 120.0 + i, 5.0,
                                 100.0) for i in range(3)])
    assert len(f) == 3 and {x["severity"] for x in f} == {"BLOCK"}
    # ops beyond the measured envelope
    env = [
        _rec("zk_big", "1", 1, 8000, None, 5.0, 900.0),
        _rec("zk_big", "1", 1, 1000, 100.0, 5.0, 200.0),
    ]
    f = envelope_findings(env)
    assert f and f[0]["kind"] == "extrapolated-claim" \
        and f[0]["severity"] == "WARN"
    env2 = [
        _rec("zk_big", "1", 1, 8000, 900.0, 5.0, 950.0),
        _rec("zk_big", "1", 1, 1000, 100.0, 5.0, 200.0),
    ]
    assert envelope_findings(env2) == []  # now measured at that size
    # thin sample behind a claimed number
    f = sample_findings([_rec("zk_thin", "1", 10, 100, 100.0, 5.0, 150.0)])
    assert f and f[0]["kind"] == "thin-sample"
    ok3 = [_rec("zk_thin", "1", 10, 100, 100.0 + i, 5.0, 150.0)
           for i in range(3)]
    assert not [x for x in sample_findings(ok3) if x["kind"] == "thin-sample"]
    # verify_ms spike vs median
    spike = [_rec("zk_v", "1", 10, 100, 100.0, 5.0, None) for _ in range(4)] \
        + [_rec("zk_v", "1", 10, 100, 100.0, 60.0, None)]
    assert sample_findings(spike)[0]["kind"] == "verify-spike"
    # CLI rc paths
    clean = [_rec("zk_add", "1", 100, 500, 100.0 + i, 8.0, 150.0)
             for i in range(3)] \
        + [_rec("zk_add", "2", 100, 500, 102.0 + i, 8.0, 160.0)
           for i in range(3)]
    rc, out = _run_capture(clean)
    assert rc == 0, out
    regcli = [_rec("zk_add", "1", 100, 500, 100.0 + i, 8.0, 160.0)
              for i in range(3)] \
        + [_rec("zk_add", "2", 100, 500, 150.0 + i, 8.0, 160.0)
           for i in range(3)]
    rc, out = _run_capture(regcli)
    assert rc == 1 and "proof-regression" in out
    err = io.StringIO()
    with redirect_stderr(err):
        rc_missing = main(["/nonexistent/zk-bench.jsonl"])
    assert rc_missing == 2
    print("self-test OK (version order, regression/improvement/flat, "
          "guarantee escalation, envelope, thin sample, verify spike, "
          "CLI rc=0/1/2)")


if __name__ == "__main__":
    if "--self-test" in sys.argv:
        self_test()  # falls through; rc 0 (probe hook runs after this)
    else:
        raise SystemExit(main())
