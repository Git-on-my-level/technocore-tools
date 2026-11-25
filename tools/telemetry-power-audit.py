#!/usr/bin/env python3
"""telemetry-power-audit — internal-consistency audit for node telemetry
captures: flags power readings that contradict the token rate they were
sampled at, and metadata (meter location, sampling interval, node count)
that moves mid-series without a re-baseline.

DEMAND: evidence/suggestions/tools-services/2026-11-24.md
  - request: "Detect/metigate internal power inconsistency in node
    telemetry (idle vs load power)" — evidence: "Seq 303175 has an
    internal power inconsistency: 389 W idle exceeds 157 W at 214 tok/s,
    so first freeze meter location, sampling interval, node count and
    whether labels were swapped" — proposed service: "Add
    telemetry-consistency checks (power/token-rate) to hermes-tools
    audit reports."

Input: JSONL, one telemetry sample per line:
  {"ts":"2026-11-24T09:00:01Z","node":"gpu-07","seq":303175,
   "power_w":389.0,"tok_s":0.0,"meter":"pdu-b3.rack12",
   "sample_interval_s":1.0,"cluster_nodes":8,"event":"sample"}
ts is ISO-8601 (naive = UTC) or epoch seconds; power_w is required;
tok_s drives the load tier (labels are NOT trusted — a declared
state:"idle" that contradicts tok_s is exactly what we hunt). event
"rebaseline" legitimises a meter/interval/node-count change onward.
Findings:
  power-load-inversion   idle-median power exceeds loaded-median power
  labels-swapped         two nodes' idle/load medians mirror each other
  non-monotonic-power    median power falls as tok_s tier rises
  meter-changed / sample-interval-changed / cluster-nodes-changed
                         frozen metadata moved without a re-baseline
  sample-interval-drift  declared interval vs observed ts cadence
Inputs are data only — parsed, never run. No network, no subprocess
shells. Stdlib only. rc 0 = no findings; 1 = findings; 2 = usage /
unreadable input."""

import argparse
import io
import json
import os
import sys
import tempfile
from datetime import datetime, timezone
from statistics import median

IDLE_TOK_S = 1.0        # tok_s <= this -> idle tier
LOAD_TOK_S = 50.0       # tok_s >= this -> loaded tier
MIN_SAMPLES = 3         # per tier before a median is trusted
REL_TOL = 0.05          # inversion tolerance: idle > load*(1+REL_TOL)
DRIFT_TOL = 0.5         # |observed-declared|/declared interval gap
MIRROR_TOL = 0.10       # cross-node mirrored-value tolerance
TIERS = [("idle", 0.0, IDLE_TOK_S), ("low", IDLE_TOK_S, 25.0),
         ("high", 25.0, LOAD_TOK_S), ("loaded", LOAD_TOK_S, float("inf"))]

CODES = ("power-load-inversion", "labels-swapped", "non-monotonic-power",
         "meter-changed", "sample-interval-changed", "cluster-nodes-changed",
         "sample-interval-drift")


def parse_ts(v):
    """ISO-8601 string (naive = UTC) or epoch number -> float seconds."""
    if isinstance(v, bool):
        return None
    if isinstance(v, (int, float)):
        return float(v)
    if isinstance(v, str):
        s = v.strip()
        if s.endswith("Z"):
            s = s[:-1] + "+00:00"
        try:
            dt = datetime.fromisoformat(s)
        except ValueError:
            return None
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        return dt.timestamp()
    return None


def num(v):
    """Coerce to float; None for missing/non-numeric."""
    if isinstance(v, bool) or not isinstance(v, (int, float)):
        return None
    return float(v)



def tier_of(tok_s):
    for name, lo, hi in TIERS:
        if lo <= tok_s < hi:
            return name
    return None


def parse_stream(fh):
    """Parse an open JSONL stream -> (records, skipped)."""
    records, skipped = [], 0
    for raw in fh:
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        try:
            obj = json.loads(line)
        except ValueError:
            skipped += 1
            continue
        if not isinstance(obj, dict):
            skipped += 1
            continue
        ts = parse_ts(obj.get("ts"))
        pw = num(obj.get("power_w"))
        node = obj.get("node")
        if ts is None or pw is None or not isinstance(node, str):
            skipped += 1
            continue
        tok = num(obj.get("tok_s"))
        records.append({"ts": ts, "node": node, "power_w": pw, "tok_s": tok,
                        "seq": obj.get("seq"),
                        "tier": tier_of(tok) if tok is not None else None,
                        "event": obj.get("event", "sample"),
                        "meter": obj.get("meter"),
                        "interval": num(obj.get("sample_interval_s")),
                        "cluster_nodes": num(obj.get("cluster_nodes"))})
    return records, skipped


def load_records(path):
    """Read JSONL capture (path or '-' for stdin) -> (records, skipped)."""
    fh = sys.stdin if path == "-" else open(
        path, "r", encoding="utf-8", errors="replace")
    with fh:
        return parse_stream(fh)


def check_power_consistency(stats, cfg):
    """Per-node idle vs loaded median comparison + tier monotonicity.

    stats: {node: {"tiers": {tier: [powers...]}, "seq": last_seq}}.
    Returns findings (list of dicts)."""
    findings = []
    for node in sorted(stats):
        tiers = stats[node]["tiers"]
        idle = tiers.get("idle", [])
        loaded = tiers.get("loaded", [])
        seq = stats[node]["seq"]
        if len(idle) >= cfg["min_samples"] and len(loaded) >= cfg["min_samples"]:
            im, lm = median(idle), median(loaded)
            if im > lm * (1.0 + cfg["rel_tol"]):
                ratio = im / lm if lm > 0 else float("inf")
                sev = "high" if ratio >= 1.5 else "medium"
                findings.append({"code": "power-load-inversion", "node": node,
                                 "severity": sev,
                                 "detail": "idle median %.1f W exceeds loaded "
                                           "median %.1f W (%.0f%% of load) at "
                                           "seq %s" % (im, lm, 100 * ratio, seq)})
        present = [(name, median(pw)) for name, pw in
                   ((t, tiers.get(t, [])) for t, _, _ in TIERS)
                   if len(pw) >= cfg["min_samples"]]
        for (lo, plo), (hi, phi) in zip(present, present[1:]):
            if plo > phi * (1.0 + cfg["rel_tol"]):
                findings.append({"code": "non-monotonic-power", "node": node,
                                 "severity": "medium",
                                 "detail": "median power falls %.1f W (%s tier) "
                                           "-> %.1f W (%s tier) as tok_s rises "
                                           "at seq %s" % (plo, lo, phi, hi, seq)})
    return findings


def check_label_swap(stats, cfg):
    """Two nodes whose idle/loaded medians mirror each other -> the classic
    swapped-label signature (A.idle ~ B.load and A.load ~ B.idle)."""
    findings = []
    pairs = []
    for node in sorted(stats):
        tiers = stats[node]["tiers"]
        idle, loaded = tiers.get("idle", []), tiers.get("loaded", [])
        if len(idle) >= cfg["min_samples"] and len(loaded) >= cfg["min_samples"]:
            pairs.append((node, median(idle), median(loaded)))
    for i, (a, ai, al) in enumerate(pairs):
        for b, bi, bl in pairs[i + 1:]:
            if al <= 0 or bl <= 0:
                continue
            if (abs(ai - bl) / max(ai, bl) <= cfg["mirror_tol"]
                    and abs(al - bi) / max(al, bi) <= cfg["mirror_tol"]):
                findings.append({"code": "labels-swapped", "node": a,
                                 "severity": "high",
                                 "detail": "idle/load medians (%.1f/%.1f W) mirror "
                                           "node %s (%.1f/%.1f W) — labels likely "
                                           "swapped" % (ai, al, b, bi, bl)})
    return findings


def check_frozen_metadata(records, cfg):
    """meter / sample_interval_s / cluster_nodes must be constant per node
    unless an intervening 'rebaseline' event was logged."""
    findings, last = [], {}
    for rec in records:
        node = rec["node"]
        prior = last.setdefault(node, {"meter": None, "interval": None,
                                       "cluster_nodes": None, "seq": None})
        if rec["event"] == "rebaseline":
            prior.update(meter=rec["meter"], interval=rec["interval"],
                         cluster_nodes=rec["cluster_nodes"], seq=rec["seq"])
            continue
        for field, code in (("meter", "meter-changed"),
                            ("interval", "sample-interval-changed"),
                            ("cluster_nodes", "cluster-nodes-changed")):
            new, old = rec[field], prior[field]
            if old is not None and new is not None and new != old:
                findings.append({"code": code, "node": node, "severity": "medium",
                                 "detail": "%s %s -> %s after seq %s without a "
                                           "rebaseline" % (field, old, new, prior["seq"])})
            if new is not None:
                prior[field] = new
        prior["seq"] = rec["seq"]
    return findings


def check_cadence(records, cfg):
    """Declared sample_interval_s vs observed median inter-sample gap."""
    findings, per_node = [], {}
    for rec in records:
        if rec["interval"] is not None:
            per_node.setdefault(rec["node"], []).append(rec)
    for node in sorted(per_node):
        rows = sorted(per_node[node], key=lambda r: r["ts"])
        declared = median([r["interval"] for r in rows])
        gaps = [b["ts"] - a["ts"] for a, b in zip(rows, rows[1:]) if b["ts"] > a["ts"]]
        if declared > 0 and len(gaps) >= cfg["min_samples"]:
            observed = median(gaps)
            if abs(observed - declared) / declared > cfg["drift_tol"]:
                findings.append({"code": "sample-interval-drift", "node": node,
                                 "severity": "low",
                                 "detail": "declared interval %.2fs vs observed "
                                           "median gap %.2fs at seq %s"
                                           % (declared, observed, rows[-1]["seq"])})
    return findings


def analyze(records, cfg=None):
    """Full audit: -> (findings, per-node summary). Findings are sorted by
    (severity rank, code, node) for deterministic output."""
    cfg = cfg or {}
    cfg = {"min_samples": cfg.get("min_samples", MIN_SAMPLES),
           "rel_tol": cfg.get("rel_tol", REL_TOL),
           "drift_tol": cfg.get("drift_tol", DRIFT_TOL),
           "mirror_tol": cfg.get("mirror_tol", MIRROR_TOL)}
    stats = {}
    for rec in records:
        st = stats.setdefault(rec["node"], {"tiers": {}, "seq": rec["seq"],
                                            "n": 0})
        st["n"] += 1
        st["seq"] = rec["seq"] if rec["seq"] is not None else st["seq"]
        if rec["tier"]:
            st["tiers"].setdefault(rec["tier"], []).append(rec["power_w"])
    findings = (check_power_consistency(stats, cfg) + check_label_swap(stats, cfg)
                + check_frozen_metadata(records, cfg) + check_cadence(records, cfg))
    rank = {"high": 0, "medium": 1, "low": 2}
    findings.sort(key=lambda f: (rank[f["severity"]], f["code"], f["node"]))
    return findings, stats


def render(findings, stats, skipped):
    lines = []
    for node in sorted(stats):
        tiers = stats[node]["tiers"]
        bits = ["%s=%s" % (t, ("%.0fW" % median(pw)) if len(pw) >= MIN_SAMPLES
                           else "n/a") for t, pw in
                ((t, tiers.get(t, [])) for t, _, _ in TIERS)]
        lines.append("node %-14s n=%-4d %s" % (node, stats[node]["n"],
                                               " ".join(bits)))
    for f in findings:
        lines.append("[%s] %s %s: %s" % (f["severity"], f["code"], f["node"],
                                         f["detail"]))
    if skipped:
        lines.append("(skipped %d malformed line(s))" % skipped)
    lines.append("%d finding(s)" % len(findings) if findings
                 else "OK: no power-consistency findings")
    return "\n".join(lines)


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("capture", nargs="?", default="-",
                    help="JSONL telemetry capture ('-' = stdin)")
    ap.add_argument("--min-samples", type=int, default=MIN_SAMPLES)
    ap.add_argument("--rel-tol", type=float, default=REL_TOL)
    args = ap.parse_args(argv)
    if args.min_samples < 1 or not 0 <= args.rel_tol < 1:
        print("usage: bad tolerance arguments", file=sys.stderr)
        return 2
    try:
        records, skipped = load_records(args.capture)
    except OSError as exc:
        print("cannot read capture: %s" % exc, file=sys.stderr)
        return 2
    if not records:
        print("no valid telemetry records", file=sys.stderr)
        return 2
    findings, stats = analyze(records, {"min_samples": args.min_samples,
                                        "rel_tol": args.rel_tol})
    print(render(findings, stats, skipped))
    return 1 if findings else 0


def self_test():
    import subprocess

    def rec(node, ts, power, tok, seq, **kw):
        r = {"ts": ts, "node": node, "seq": seq, "power_w": power, "tok_s": tok}
        r.update(kw)
        return r

    def parse(recs):
        return parse_stream(io.StringIO(jsonl(recs)))[0]


    base = 1763870000.0
    def ts(i):
        return datetime.fromtimestamp(base + i, tz=timezone.utc).isoformat()

    # 1. clean capture: monotone power vs tok_s, frozen metadata, honest cadence
    clean = [rec("gpu-1", ts(i), 150.0 + 0.4 * i, 200.0, 1000 + i,
                 meter="pdu-a1", sample_interval_s=1.0, cluster_nodes=8)
             for i in range(12)] + \
            [rec("gpu-1", ts(100 + i), 90.0, 0.0, 1100 + i,
                 meter="pdu-a1", sample_interval_s=1.0, cluster_nodes=8)
             for i in range(6)]
    findings, stats = analyze(parse(clean))
    assert not analyze(parse(clean))[0], \
        "clean capture must yield no findings, got %r" % findings
    assert stats["gpu-1"]["n"] == 18

    # 2. the demand's exact signature: 389 W idle vs 157 W at 214 tok/s
    seq303175 = ([rec("node-7", ts(i), 389.0, 0.0, 303160 + i) for i in range(4)]
                 + [rec("node-7", ts(50 + i), 157.0, 214.0, 303174 + i)
                    for i in range(4)])
    findings, _ = analyze(parse(seq303175))
    codes = [f["code"] for f in findings]
    assert "power-load-inversion" in [f["code"] for f in analyze(parse(seq303175))[0]], \
        "389W idle vs 157W@214tok/s must invert"
    inv = next(f for f in findings if f["code"] == "power-load-inversion")
    assert inv["severity"] == "high" and "389.0 W" in inv["detail"]

    # 3. mirrored pair -> labels-swapped (A idle=380/load=160, B idle=160/load=380)
    swap = ([rec("gpu-2", ts(i), 380.0, 0.0, 10 + i) for i in range(4)]
            + [rec("gpu-2", ts(40 + i), 160.0, 250.0, 50 + i) for i in range(4)]
            + [rec("gpu-3", ts(i), 165.0, 0.0, 10 + i) for i in range(4)]
            + [rec("gpu-3", ts(40 + i), 375.0, 250.0, 50 + i) for i in range(4)])
    findings, _ = analyze(parse(swap))
    assert any(f["code"] == "labels-swapped" for f in findings), \
        "mirrored medians must flag labels-swapped"

    # 4. frozen metadata moves without rebaseline -> three change findings;
    #    with a rebaseline event the same change is legitimate
    drift_meta = [rec("gpu-4", ts(i), 100.0, 0.0, 200 + i, meter="pdu-a1",
                      sample_interval_s=1.0, cluster_nodes=4) for i in range(4)]
    drift_meta += [rec("gpu-4", ts(50 + i), 100.0, 0.0, 250 + i, meter="pdu-b9",
                       sample_interval_s=5.0, cluster_nodes=12) for i in range(4)]
    findings, _ = analyze(parse(drift_meta))
    codes = [f["code"] for f in findings]
    assert "meter-changed" in codes and "sample-interval-changed" in codes \
        and "cluster-nodes-changed" in codes, codes
    rebased = drift_meta[:4] + [rec("gpu-4", ts(49), 100.0, 0.0, 249,
                                    event="rebaseline", meter="pdu-b9",
                                    sample_interval_s=5.0, cluster_nodes=12)] \
        + drift_meta[4:]
    findings, _ = analyze(parse(rebased))
    assert not any(f["code"].endswith("changed") for f in findings), \
        "rebaseline must legitimise metadata changes"

    # 5. declared interval vs observed cadence (declare 1s, sample every ~10s)
    sparse = [rec("gpu-5", base + 10.0 * i, 100.0, 0.0, 300 + i,
                  sample_interval_s=1.0) for i in range(8)]
    findings, _ = analyze(parse(sparse))
    assert any(f["code"] == "sample-interval-drift" for f in findings)

    # 6. mid-tier inversion: idle 100 W, low 120 W, high 90 W, loaded 200 W
    sag = ([rec("gpu-6", ts(i), 100.0, 0.0, 400 + i) for i in range(4)]
           + [rec("gpu-6", ts(40 + i), 120.0, 10.0, 440 + i) for i in range(4)]
           + [rec("gpu-6", ts(80 + i), 90.0, 40.0, 480 + i) for i in range(4)]
           + [rec("gpu-6", ts(120 + i), 200.0, 210.0, 520 + i) for i in range(4)])
    findings, _ = analyze(parse(sag))
    assert any(f["code"] == "non-monotonic-power" for f in findings)

    # 7. end-to-end CLI: dirty capture -> rc 1, clean capture -> rc 0
    with tempfile.NamedTemporaryFile("w", suffix=".jsonl", delete=False) as fh:
        fh.write(jsonl(seq303175))
        dirty = fh.name
    with tempfile.NamedTemporaryFile("w", suffix=".jsonl", delete=False) as fh:
        fh.write(jsonl(clean))
        tidy = fh.name
    try:
        for path, expect in ((dirty, 1), (tidy, 0)):
            r = subprocess.run([sys.executable, os.path.abspath(__file__), path],
                               capture_output=True, text=True, timeout=60)
            assert r.returncode == expect, (path, r.returncode, r.stdout)
    finally:
        os.unlink(dirty)
        os.unlink(tidy)
    print("telemetry-power-audit self-test OK (inversion/swap/freeze/"
          "cadence/monotonicity + CLI rc)")


def jsonl(recs):
    return "\n".join(json.dumps(r) for r in recs) + "\n"


if __name__ == "__main__":
    if "--self-test" in sys.argv:
        self_test()  # returns; probe hook may run after this line
    else:
        sys.exit(main())
