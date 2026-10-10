#!/usr/bin/env python3
"""gpu-hours-audit — GPU rental uptime, proof-of-compute and retention audit.

DEMAND: evidence/suggestions/tools-services/ (file citations below)
  - "GPU uptime/hours audit for compute rentals"
  - "Compute completion auditability"
  - "Decentralized AI compute proof verification"
  - "request for compute/hash rate info for zk_audit proofs"
  - "Retain GPU-mapping audit records for at least seven years, or longer if the applicable legal, contractual, or incident-hold policy requires it. Each recor"
  Scope: one JSONL capture, one GPU rental record per line: {"ts","gpu_id",
    "renter","event","hours","hash_rate","proof_hash","job_id",
    "record_age_days"}; event in rental_start|rental_end|uptime_claim|proof|
    job_completed|record_purge. A rental_start pairs with the next end; an
    unpaired start stays open to the gpu's last ts. rc 0/1/2. Stdlib only;
    data is parsed, never executed.
"""
import argparse
import json
import re
import sys
from datetime import datetime, timezone
from statistics import median

SEVS = ("BLOCK", "WARN", "INFO")
RETENTION_MIN_DAYS = 2555     # seven years of GPU-mapping audit records
HASH_TOLERANCE = 0.20         # claim hash_rate vs proof-sample median

def _f(kind, severity, origin, detail):
    """Uniform finding dict."""
    return {"kind": kind, "severity": severity, "origin": origin,
            "detail": detail}

def num(v):
    """Numeric and not bool -> float, else None."""
    if isinstance(v, (int, float)) and not isinstance(v, bool):
        return float(v)
    return None

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

def _gid(rec):
    gid = rec.get("gpu_id")
    return str(gid) if gid not in (None, "") else "?"

def scan_gpus(records):
    """Per-gpu scan -> {gpu: {"windows","overlaps","unclosed","horizon"}}.

    Starts pair FIFO with the next end; a start while one is open overlaps
    it; leftover starts stay open to the gpu's last record ts (horizon).
    """
    raw = {}
    for idx, rec in enumerate(records):
        ts = parse_ts(rec.get("ts"))
        if ts is None:
            continue
        g = raw.setdefault(_gid(rec), {"evs": [], "horizon": ts})
        g["evs"].append((ts, idx, rec))
        g["horizon"] = max(g["horizon"], ts)
    out = {}
    for gpu, g in raw.items():
        opens, windows, overlaps = [], [], []
        for ts, _idx, rec in sorted(g["evs"], key=lambda e: (e[0], e[1])):
            ev = rec.get("event")
            if ev == "rental_start":
                if opens:
                    overlaps.append((opens[0], ts))
                opens.append(ts)
            elif ev == "rental_end" and opens:
                start = opens.pop(0)
                if ts >= start:
                    windows.append((start, ts, True))
        for start in opens:
            windows.append((start, max(g["horizon"], start), False))
        out[gpu] = {"windows": sorted(windows), "overlaps": overlaps,
                    "unclosed": list(opens), "horizon": g["horizon"]}
    return out

def window_findings(records, scan=None):
    """Rental-window integrity: overlapping windows BLOCK, unclosed WARN."""
    if scan is None:
        scan = scan_gpus(records)
    finds = []
    for gpu in sorted(scan):
        g = scan[gpu]
        for prev, cur in g["overlaps"]:
            finds.append(_f("window-overlap", "BLOCK", gpu,
                            f"rental_start at {cur:g} while window opened "
                            f"at {prev:g} is still open"))
        for start in g["unclosed"]:
            finds.append(_f("unclosed-window", "WARN", gpu,
                            f"rental_start at {start:g} never closed (held "
                            f"open to horizon {g['horizon']:g})"))
    return finds

def claim_findings(records, windows=None):
    """Uptime claims vs rental windows: over-total and uncovered BLOCKs."""
    if windows is None:
        windows = {g: s["windows"] for g, s in scan_gpus(records).items()}
    claims = {}
    for rec in records:
        ts = parse_ts(rec.get("ts"))
        if rec.get("event") != "uptime_claim" or ts is None:
            continue
        c = claims.setdefault(_gid(rec), {"hours": 0.0, "ts": []})
        hours = num(rec.get("hours"))
        if hours is not None and hours > 0:
            c["hours"] += hours
        c["ts"].append(ts)
    finds = []
    for gpu in sorted(claims):
        segs = windows.get(gpu, [])
        total_h = sum(e - s for s, e, _c in segs) / 3600.0
        c = claims[gpu]
        if c["hours"] > total_h + 1e-9:
            finds.append(_f("claim-over-total", "BLOCK", gpu,
                            f"uptime claims sum {c['hours']:g}h over "
                            f"{total_h:g}h of rental window"))
        stray = [t for t in sorted(c["ts"])
                 if not any(s <= t <= e for s, e, _c in segs)]
        if stray:
            finds.append(_f("claim-uncovered", "BLOCK", gpu,
                            f"{len(stray)} uptime_claim outside every rental "
                            f"window (first at {stray[0]:g})"))
    return finds

def hashrate_findings(records):
    """Claim hash_rate drift vs the gpu's proof-sample median (WARN)."""
    proofs, claims = {}, {}
    for rec in records:
        ev, gpu, ts = rec.get("event"), _gid(rec), parse_ts(rec.get("ts"))
        if ev == "proof":
            rate = num(rec.get("hash_rate"))
            if rate is not None and rate > 0:
                proofs.setdefault(gpu, []).append(rate)
        elif ev == "uptime_claim" and ts is not None:
            claims.setdefault(gpu, []).append((ts, num(rec.get("hash_rate"))))
    finds = []
    for gpu in sorted(claims):
        samples = proofs.get(gpu)
        if not samples:
            finds.append(_f("no-proofs", "WARN", gpu,
                            f"{len(claims[gpu])} uptime_claim but no "
                            f"proof/hash_rate samples to check"))
            continue
        med = median(samples)
        for ts, rate in sorted(claims[gpu]):
            if rate is None or med <= 0:
                continue
            dev = abs(rate - med) / med
            if dev > HASH_TOLERANCE:
                finds.append(_f("hashrate-drift", "WARN", gpu,
                                f"claim at {ts:g} hash_rate {rate:g} vs "
                                f"proof median {med:g} ({dev * 100:.0f}% off)"))
    return finds

def completion_findings(records, windows=None):
    """Job completion proofability: unproven jobs and out-of-window jobs."""
    if windows is None:
        windows = {g: s["windows"] for g, s in scan_gpus(records).items()}
    finds = []
    for rec in records:
        ts = parse_ts(rec.get("ts"))
        if rec.get("event") != "job_completed" or ts is None:
            continue
        gpu = _gid(rec)
        job = rec.get("job_id")
        origin = str(job) if job not in (None, "") else gpu
        if not rec.get("proof_hash"):
            finds.append(_f("job-unproven", "BLOCK", origin,
                            f"job on {gpu} completed at {ts:g} with no "
                            f"proof_hash"))
        if not any(s <= ts <= e for s, e, _c in windows.get(gpu, [])):
            finds.append(_f("job-outside-window", "BLOCK", origin,
                            f"job on {gpu} completed at {ts:g} outside "
                            f"every rental window"))
    return finds

def retention_findings(records):
    """record_purge before the seven-year floor (BLOCK retention violation)."""
    finds = []
    for rec in records:
        if rec.get("event") != "record_purge":
            continue
        age = num(rec.get("record_age_days"))
        if age is not None and age < RETENTION_MIN_DAYS:
            finds.append(_f("purge-early", "BLOCK", _gid(rec),
                            f"record_purge at {age:g} days < "
                            f"{RETENTION_MIN_DAYS} (7y floor)"))
    return finds

def audit(path):
    """Run every detector over the capture -> (findings, stats)."""
    records, bad = load_jsonl(path)
    scan = scan_gpus(records)
    windows = {g: s["windows"] for g, s in scan.items()}
    finds = (window_findings(records, scan) + claim_findings(records, windows)
             + hashrate_findings(records)
             + completion_findings(records, windows)
             + retention_findings(records))
    if bad:
        finds.append(_f("malformed-line", "INFO", path,
                        f"{bad} unparsable line(s) skipped"))
    rank = {"BLOCK": 0, "WARN": 1, "INFO": 2}
    finds.sort(key=lambda f: (rank[f["severity"]], f["kind"], f["origin"]))
    return finds, {"records": len(records), "bad_lines": bad,
                   "gpus": len(scan)}

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
        description="GPU rental uptime/compute-proof/retention audit")
    ap.add_argument("path", help="JSONL capture of GPU rental events")
    ap.add_argument("--json", action="store_true", help="JSON output")
    args = ap.parse_args(argv)
    try:
        finds, stats = audit(args.path)
    except OSError as exc:
        print(f"cannot read {args.path}: {exc}", file=sys.stderr)
        return 2
    if args.json:
        print(json.dumps({"tool": "gpu-hours-audit", **stats,
                          "findings": finds}, indent=1))
    else:
        render(finds)
    return 1 if finds else 0

def self_test():
    import io
    import os
    import tempfile
    from contextlib import redirect_stdout

    def _ev(ts, gpu="gpu-1", event="proof", **kw):
        rec = {"ts": ts, "gpu_id": gpu, "event": event}
        rec.update(kw)
        return rec

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

    # 1. clean capture (window, proofs, claim, job, 7y purge) -> rc 0
    clean = [_ev(0, event="rental_start", renter="acme"),
             _ev(1000, event="proof", hash_rate=100.0, proof_hash="p1"),
             _ev(2000, event="proof", hash_rate=110.0, proof_hash="p2"),
             _ev(3000, event="uptime_claim", hours=1.5, hash_rate=105.0),
             _ev(3500, event="job_completed", job_id="j1", proof_hash="h1"),
             _ev(36000, event="rental_end"),
             _ev(40000, event="record_purge", record_age_days=2555)]
    rc, out = run([clean])
    assert rc == 0 and "no findings" in out, (rc, out)
    for fn in (window_findings, claim_findings, hashrate_findings,
               completion_findings, retention_findings):
        assert fn(clean) == [], fn.__name__
    # 2. windows: overlap BLOCK; unclosed WARN; clean gpu-2 stays silent
    ov = [_ev(0, event="rental_start"), _ev(100, event="rental_start"),
          _ev(200, event="rental_end"), _ev(300, event="rental_end")]
    f = window_findings(ov)
    assert kinds(f) == ["window-overlap"] and f[0]["severity"] == "BLOCK", f
    un = [_ev(0, event="rental_start"), _ev(500, event="proof", hash_rate=1)]
    f = window_findings(un)
    assert kinds(f) == ["unclosed-window"] and f[0]["severity"] == "WARN", f
    f = window_findings(ov + [_ev(0, gpu="gpu-2", event="rental_start"),
                              _ev(10, gpu="gpu-2", event="rental_end")])
    assert len(f) == 1 and f[0]["origin"] == "gpu-1", f
    # 3. claims: 25h on a 10h window BLOCKs; out-of-window claim BLOCKs
    oc = [_ev(0, event="rental_start"), _ev(36000, event="rental_end"),
          _ev(1000, event="uptime_claim", hours=10.0),
          _ev(2000, event="uptime_claim", hours=15.0)]
    f = claim_findings(oc)
    assert kinds(f) == ["claim-over-total"] and "25h" in f[0]["detail"], f
    uc = [_ev(0, event="rental_start"), _ev(3600, event="rental_end"),
          _ev(9999, event="uptime_claim", hours=0.5)]
    assert kinds(claim_findings(uc)) == ["claim-uncovered"]
    # 4. hashrate: median 100, claim 130 (30%) WARNs, 118 (18%) passes; a
    #    claim with no proof samples WARNs no-proofs
    hr = ([_ev(0, event="rental_start"), _ev(36000, event="rental_end")]
          + [_ev(10 * i, event="proof", hash_rate=100.0) for i in (1, 2)]
          + [_ev(30, event="uptime_claim", hours=0.1, hash_rate=130.0),
             _ev(40, event="uptime_claim", hours=0.1, hash_rate=118.0)])
    f = hashrate_findings(hr)
    assert kinds(f) == ["hashrate-drift"] and "30%" in f[0]["detail"], f
    assert kinds(hashrate_findings(
        [_ev(100, event="uptime_claim", hours=0.1)])) == ["no-proofs"]
    # 5. jobs: no proof_hash BLOCKs (origin = job id); job outside every
    #    window BLOCKs
    ju = [_ev(0, event="rental_start"), _ev(3600, event="rental_end"),
          _ev(100, event="job_completed", job_id="j9")]
    f = completion_findings(ju)
    assert kinds(f) == ["job-unproven"] and f[0]["origin"] == "j9", f
    jo = ju[:2] + [_ev(9999, event="job_completed", job_id="j8",
                       proof_hash="h")]
    assert kinds(completion_findings(jo)) == ["job-outside-window"]
    # 6. retention: purge at 100 days BLOCKs; exactly 2555 days tolerated
    f = retention_findings([_ev(0, gpu="gpu-2", event="record_purge",
                                record_age_days=100)])
    assert kinds(f) == ["purge-early"] and f[0]["severity"] == "BLOCK", f
    assert retention_findings(
        [_ev(0, event="record_purge", record_age_days=2555)]) == []
    # 7. ISO timestamps parse like epochs (10h window, 3h claim at 5h)
    iso = [_ev("2026-09-01T00:00:00Z", event="rental_start"),
           _ev("2026-09-01T10:00:00Z", event="rental_end"),
           _ev("2026-09-01T05:00:00Z", event="uptime_claim", hours=3.0)]
    assert claim_findings(iso) == [], claim_findings(iso)
    # 8. CLI: findings rc 1; --json shape; malformed INFO; unreadable rc 2
    rc, out = run([[_ev(0, event="record_purge", record_age_days=5)]])
    assert rc == 1 and "BLOCK purge-early" in out, (rc, out)
    doc = json.loads(run([clean], ["--json"])[1])
    assert doc["findings"] == [] and doc["records"] == 7, doc
    rc, out = run([['{"broken', _ev(0, event="rental_start")]])
    assert rc == 1 and "malformed-line" in out, (rc, out)
    assert main(["/nonexistent-capture.jsonl"]) == 2
    print("gpu-hours-audit self-test OK (8 groups: clean, windows, claims, "
          "hashrate, jobs, retention, ISO ts, CLI rc/json)")

if __name__ == "__main__":
    if "--self-test" in sys.argv:
        self_test()  # falls through; rc 0 (probe hook runs after this)
    else:
        raise SystemExit(main())
