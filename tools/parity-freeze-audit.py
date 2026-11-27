#!/usr/bin/env python3
"""parity-freeze-audit — make throughput/uptime claims checkable: freeze
prompt+seed, hash every response, recompute the stats behind the claim.

DEMAND: evidence/suggestions/tools-services/2026-11-24.md
  (11:57 run) - request: "Verify throughput/uptime claims via output
  parity (freeze prompt+seed, hash responses)" — evidence: "throughput
  and uptime claims are unauditable without output parity - freeze
  prompt+seed, hash every response, then the 100h/92% stat becomes
  chec" — proposed service: prompt/seed-freeze and response-hash audit
  mode; (17:57 run) - request: "Make throughput/uptime claims auditable
  via output parity (freeze prompt+seed, hash responses)"; (23:57 run)
  folds the same ask into run-metadata certification.
  No existing tool freezes prompt+seed digests or chains response
  hashes (runtime-trace-receipts signs traces, burn-cycle-receipts
  hashes spend ledgers — neither certifies provider parity claims).

Scope: one JSONL parity log, one response event per line:
  {"run": "r-91", "provider": "prov-a", "ts": "2026-11-23T10:00:01Z",
   "prompt": "Summarise ...", "seed": 41, "response": "...",
   "latency_ms": 812}
The frozen configuration per (provider, run) is sha256 over the
canonical {prompt, seed}; every response is hashed and chained in ts
order d_i = sha256(d_{i-1} || canonical(response)) so edits, reorders
and insertions break the head. Uptime is recomputed by bucketing the
event window into --interval-s slots (default 3600): a bucket with at
least one response is "up". Claims come from a JSON file
  {"prov-a": {"uptime_pct": 92.0, "window_hours": 100,
              "responses_per_hour": 360}}
and are compared with tolerance. Data only: hashing and arithmetic over
saved events, no network, no subprocess, nothing is ever run. Stdlib
only.

What it does:
  verdicts
    frozen-config-drift  FAIL  same (provider, run) with two different
                              prompt/seed digests
    missing-frozen-field  FAIL  event without prompt or seed
    chain-head-mismatch   FAIL  --verify head does not recompute
    uptime-claim-overstated FAIL observed uptime below claim -
                              --tolerance-pct
    throughput-claim-overstated FAIL observed responses/hour below
                              claim - --tolerance-pct
    seed-collision        WARN  same seed reused with a different prompt
    response-gap          WARN  consecutive responses further apart
                              than --max-gap-s
    latency-outlier       WARN  latency > --max-latency-ms
    malformed-event       WARN  unparseable line / missing fields
    no-claims             WARN  claims file absent, stats only
    claim-without-evidence WARN  claim names a provider with no events
  emit     per provider+run: frozen digest, chain head, events, span,
           uptime_pct, responses_per_hour (JSONL with --emit)
  verify   recompute a chain and compare against --verify <head>
  rc 0 all checks pass, 1 findings, 2 usage/IO.
"""
import argparse
import hashlib
import json
import sys
from datetime import datetime

FAIL, WARN = "FAIL", "WARN"


def canonical(rec):
    """Stable serialization independent of key order/whitespace."""
    return json.dumps(rec, sort_keys=True, separators=(",", ":"))


def parse_ts(s):
    """ISO-8601 (Z or offset) -> epoch seconds, or None."""
    if not isinstance(s, str):
        return None
    try:
        return datetime.fromisoformat(s.replace("Z", "+00:00")).timestamp()
    except ValueError:
        return None


def frozen_digest(prompt, seed):
    """Freeze the run configuration: sha256 over canonical prompt+seed."""
    return hashlib.sha256(canonical(
        {"prompt": prompt, "seed": seed}).encode()).hexdigest()


def chain_hash(prev, response):
    """Chain one response onto the running head."""
    return hashlib.sha256(
        (prev + canonical({"response": response})).encode()).hexdigest()


def read_events(path, findings):
    """(lineno, rec-or-None) per JSONL line; malformed lines WARN."""
    out = []
    try:
        with open(path, encoding="utf-8", errors="replace") as fh:
            for n, line in enumerate(fh, 1):
                line = line.strip()
                if not line:
                    continue
                try:
                    rec = json.loads(line)
                except ValueError:
                    findings.append((WARN, "malformed-event",
                                     f"line {n}: unparseable JSON"))
                    rec = None
                out.append((n, rec if isinstance(rec, dict) else None))
                if rec is not None and not isinstance(rec, dict):
                    findings.append((WARN, "malformed-event",
                                     f"line {n}: not an object"))
    except OSError as e:
        print(f"cannot read parity log: {e}", file=sys.stderr)
        raise
    return out


def load_claims(path):
    """Optional claims JSON: {provider: {uptime_pct, responses_per_hour}}."""
    if not path:
        return None
    try:
        with open(path, encoding="utf-8") as fh:
            data = json.load(fh)
        return data if isinstance(data, dict) else None
    except (OSError, ValueError):
        return None


def audit(events, findings, interval_s, max_gap_s, max_latency_ms):
    """Core pass: freeze configs, chain responses, compute stats."""
    per_key = {}
    seed_index = {}
    for n, rec in events:
        if rec is None:
            continue
        prov, run = rec.get("provider"), rec.get("run")
        if not isinstance(prov, str) or not isinstance(run, str):
            findings.append((WARN, "malformed-event",
                             f"line {n}: missing provider/run"))
            continue
        ts = parse_ts(rec.get("ts"))
        prompt, seed = rec.get("prompt"), rec.get("seed")
        if prompt is None or seed is None:
            findings.append((FAIL, "missing-frozen-field",
                             f"line {n}: {prov}/{run} event without "
                             "prompt or seed"))
            continue
        if ts is None:
            findings.append((WARN, "malformed-event",
                             f"line {n}: bad ts"))
            continue
        fd = frozen_digest(prompt, seed)
        slot = per_key.setdefault((prov, run),
                                  {"frozen": fd, "events": [],
                                   "chain": hashlib.sha256(
                                       b"parity").hexdigest()})
        if slot["frozen"] != fd:
            findings.append((FAIL, "frozen-config-drift",
                             f"{prov}/{run}: prompt/seed changed "
                             f"mid-run (line {n})"))
        if isinstance(seed, int) or isinstance(seed, str):
            prev_prompt = seed_index.setdefault((prov, seed), prompt)
            if prev_prompt != prompt:
                findings.append((WARN, "seed-collision",
                                 f"{prov}: seed {seed!r} reused with a "
                                 "different prompt"))
        slot["events"].append((ts, rec))
        lat = rec.get("latency_ms")
        if isinstance(lat, (int, float)) and max_latency_ms and \
                lat > max_latency_ms:
            findings.append((WARN, "latency-outlier",
                             f"line {n}: latency {lat}ms"))

    summary = {}
    for (prov, run), slot in sorted(per_key.items()):
        evs = sorted(slot["events"], key=lambda t: (t[0], t[1].get(
            "response", "")))
        head = slot["chain"]
        for ts, rec in evs:
            head = chain_hash(head, rec.get("response"))
            slot["chain"] = head
        span = evs[-1][0] - evs[0][0]
        for (t0, r0), (t1, r1) in zip(evs, evs[1:]):
            if max_gap_s and t1 - t0 > max_gap_s:
                findings.append((WARN, "response-gap",
                                 f"{prov}/{run}: {t1 - t0:.0f}s between "
                                 "responses"))
        buckets = {int(ts // interval_s) for ts, _ in evs}
        n_buckets = int(span // interval_s) + 1
        uptime = 100.0 * len(buckets) / n_buckets if n_buckets else 0.0
        hours = max(span / 3600.0, 1e-9)
        summary[f"{prov}/{run}"] = {
            "provider": prov, "run": run, "frozen": slot["frozen"],
            "chain_head": head, "events": len(evs),
            "span_s": round(span, 3), "uptime_pct": round(uptime, 4),
            "responses_per_hour": round(len(evs) / hours, 4)}
    return summary


def check_claims(summary, claims, findings, tolerance_pct):
    """Compare recomputed stats against the provider's published claims."""
    if claims is None:
        return
    seen = set()
    for key, stats in summary.items():
        claim = claims.get(stats["provider"])
        if not isinstance(claim, dict):
            continue
        seen.add(stats["provider"])
        up_claim = claim.get("uptime_pct")
        if isinstance(up_claim, (int, float)) and \
                stats["uptime_pct"] < up_claim - tolerance_pct:
            findings.append((FAIL, "uptime-claim-overstated",
                             f"{key}: observed {stats['uptime_pct']}% < "
                             f"claimed {up_claim}%"))
        tp_claim = claim.get("responses_per_hour")
        if isinstance(tp_claim, (int, float)) and \
                stats["responses_per_hour"] < tp_claim - tolerance_pct:
            findings.append((FAIL, "throughput-claim-overstated",
                             f"{key}: observed {stats['responses_per_hour']}"
                             f"/h < claimed {tp_claim}/h"))
    for prov in sorted(claims):
        if prov not in seen:
            findings.append((WARN, "claim-without-evidence",
                             f"claims for unknown provider {prov!r}"))


def main(argv=None):
    ap = argparse.ArgumentParser(
        description="freeze prompt+seed, hash responses, audit "
                    "uptime/throughput claims")
    ap.add_argument("paritylog", help="JSONL response-event log")
    ap.add_argument("--claims", default=None,
                    help="JSON file of provider claims")
    ap.add_argument("--interval-s", type=int, default=3600,
                    help="uptime bucket size (default 3600)")
    ap.add_argument("--max-gap-s", type=float, default=0,
                    help="WARN when responses are further apart")
    ap.add_argument("--max-latency-ms", type=float, default=0,
                    help="WARN when a response is slower")
    ap.add_argument("--tolerance-pct", type=float, default=1.0,
                    help="claim slack before FAIL (default 1.0)")
    ap.add_argument("--verify", default=None,
                    help="expected chain head of the first provider/run")
    ap.add_argument("--emit", default=None,
                    help="write per-run records as JSONL here")
    args = ap.parse_args(argv)
    if args.interval_s <= 0:
        print("bad --interval-s", file=sys.stderr)
        return 2

    findings = []
    try:
        events = read_events(args.paritylog, findings)
    except OSError:
        return 2
    summary = audit(events, findings, args.interval_s,
                    args.max_gap_s, args.max_latency_ms)
    claims = load_claims(args.claims)
    if args.claims and claims is None:
        print("bad or unreadable --claims file", file=sys.stderr)
        return 2
    check_claims(summary, claims, findings, args.tolerance_pct)
    if args.verify is not None:
        heads = [s["chain_head"] for s in summary.values()]
        if not heads or heads[0] != args.verify:
            findings.append((FAIL, "chain-head-mismatch",
                             "recomputed head != --verify"))
    if args.emit:
        try:
            with open(args.emit, "w", encoding="utf-8") as fh:
                for stats in summary.values():
                    fh.write(canonical(stats) + "\n")
        except OSError as e:
            print(f"cannot write --emit: {e}", file=sys.stderr)
            return 2
    for sev, code, what in findings:
        print(f"{sev} {code} {what}", file=sys.stderr)
    print(json.dumps({"runs": len(summary),
                      "findings": len(findings),
                      "stats": summary}, sort_keys=True))
    return 1 if findings else 0


def self_test():
    import os
    import tempfile
    tmp = tempfile.mkdtemp(prefix="parity-")
    log = os.path.join(tmp, "parity.jsonl")
    claims = os.path.join(tmp, "claims.json")

    def ev(run, ts, prompt, seed, response, provider="prov-a",
           latency_ms=100):
        return json.dumps({"run": run, "provider": provider, "ts": ts,
                           "prompt": prompt, "seed": seed,
                           "response": response,
                           "latency_ms": latency_ms})

    assert frozen_digest("p", 41) == frozen_digest("p", 41)
    assert frozen_digest("p", 41) != frozen_digest("p", 42)
    assert frozen_digest("p", 41) != frozen_digest("q", 41)
    h = hashlib.sha256(b"parity").hexdigest()
    assert chain_hash(h, "a") != chain_hash(h, "b")
    assert chain_hash(chain_hash(h, "a"), "b") != chain_hash(
        chain_hash(h, "b"), "a"), "order must matter"
    assert parse_ts("2026-11-23T10:00:00Z") == parse_ts(
        "2026-11-23T10:00:00+00:00")
    assert parse_ts(None) is None and parse_ts("junk") is None

    # five responses inside three hour-buckets -> uptime 3/3, clean
    with open(log, "w") as fh:
        fh.write(ev("r1", "2026-11-23T10:00:00Z", "P", 1, "a1") + "\n")
        fh.write(ev("r1", "2026-11-23T10:30:00Z", "P", 1, "a2") + "\n")
        fh.write(ev("r1", "2026-11-23T11:45:00Z", "P", 1, "a3") + "\n")
        fh.write(ev("r1", "2026-11-23T12:20:00Z", "P", 1, "a4") + "\n")
        fh.write(ev("r1", "2026-11-23T12:50:00Z", "P", 1, "a5") + "\n")
    rc = main([log])
    assert rc == 0, "clean parity log passes"
    out = audit(read_events(log, []), [], 3600, 0, 0)
    s = out["prov-a/r1"]
    assert s["events"] == 5 and abs(s["uptime_pct"] - 100.0) < 1e-9, s
    head = s["chain_head"]
    assert main([log, "--verify", head]) == 0, "head recomputes"
    # editing one response must break the chain head
    with open(log, "w") as fh:
        fh.write(ev("r1", "2026-11-23T10:00:00Z", "P", 1, "a1") + "\n")
        fh.write(ev("r1", "2026-11-23T10:30:00Z", "P", 1, "TAMPERED")
                 + "\n")
        fh.write(ev("r1", "2026-11-23T11:45:00Z", "P", 1, "a3") + "\n")
        fh.write(ev("r1", "2026-11-23T12:20:00Z", "P", 1, "a4") + "\n")
        fh.write(ev("r1", "2026-11-23T12:50:00Z", "P", 1, "a5") + "\n")
    assert main([log, "--verify", head]) == 1, "edited response breaks head"

    # frozen-config drift: same run, changed prompt mid-run
    with open(log, "w") as fh:
        fh.write(ev("r1", "2026-11-23T10:00:00Z", "P", 1, "a1") + "\n")
        fh.write(ev("r1", "2026-11-23T11:00:00Z", "P2", 1, "a2") + "\n")
    f = []
    audit(read_events(log, f), f, 3600, 0, 0)
    assert any(c == "frozen-config-drift" for _, c, _ in f), f

    # missing frozen fields
    with open(log, "w") as fh:
        fh.write(json.dumps({"run": "r9", "provider": "prov-a",
                             "ts": "2026-11-23T10:00:00Z",
                             "response": "x"}) + "\n")
    f = []
    audit(read_events(log, f), f, 3600, 0, 0)
    assert any(c == "missing-frozen-field" for _, c, _ in f), f

    # honest vs overstated uptime claims over three hour-buckets
    with open(log, "w") as fh:
        fh.write(ev("r1", "2026-11-23T10:00:00Z", "P", 1, "a") + "\n")
        fh.write(ev("r1", "2026-11-23T11:00:00Z", "P", 1, "b") + "\n")
        fh.write(ev("r1", "2026-11-23T12:00:00Z", "P", 1, "c") + "\n")
    with open(claims, "w") as fh:
        json.dump({"prov-a": {"uptime_pct": 92.0}}, fh)
    assert main([log, "--claims", claims]) == 0, "honest claim passes"
    with open(claims, "w") as fh:
        json.dump({"prov-a": {"uptime_pct": 99.0,
                              "responses_per_hour": 1.0}}, fh)
    assert main([log, "--claims", claims]) == 0, \
        "100% observed meets a 99% claim"
    # throughput 2 responses over 2.5h = 0.8/h
    with open(log, "w") as fh:
        fh.write(ev("r1", "2026-11-23T10:00:00Z", "P", 1, "a") + "\n")
        fh.write(ev("r1", "2026-11-23T12:30:00Z", "P", 1, "b") + "\n")
    f = []
    s = audit(read_events(log, f), f, 3600, 0, 0)["prov-a/r1"]
    assert abs(s["uptime_pct"] - 200.0 / 3) < 1e-3, s
    assert abs(s["responses_per_hour"] - 0.8) < 1e-6, s
    with open(claims, "w") as fh:
        json.dump({"prov-a": {"responses_per_hour": 100}}, fh)
    rc = main([log, "--claims", claims])
    assert rc == 1, "overstated throughput must FAIL"
    f = []
    check_claims({"prov-a/r1": s},
                 {"prov-a": {"responses_per_hour": 100}}, f, 1.0)
    assert any(c == "throughput-claim-overstated" for _, c, _ in f), f
    with open(claims, "w") as fh:
        json.dump({"prov-a": {"uptime_pct": 92.0}}, fh)
    rc = main([log, "--claims", claims])
    assert rc == 1, "66.7% observed against a 92% claim must FAIL"
    f = []
    check_claims({"prov-a/r1": s}, {"prov-a": {"uptime_pct": 92.0}},
                 f, 1.0)
    assert any(c == "uptime-claim-overstated" for _, c, _ in f), f
    # gap / latency / seed-collision verdicts
    with open(log, "w") as fh:
        fh.write(ev("r1", "2026-11-23T10:00:00Z", "P", 1, "a",
                    latency_ms=9500) + "\n")
        fh.write(ev("r2", "2026-11-23T13:00:01Z", "P", 1, "b") + "\n")
    rc = main([log, "--max-gap-s", "3600", "--max-latency-ms", "9000"])
    assert rc == 1, "gap and latency verdicts fire"
    with open(log, "w") as fh:
        fh.write(ev("r1", "2026-11-23T10:00:00Z", "P", 7, "a") + "\n")
        fh.write(ev("r2", "2026-11-23T11:00:00Z", "Q", 7, "b") + "\n")
    f = []
    audit(read_events(log, f), f, 3600, 0, 0)
    assert any(c == "seed-collision" for _, c, _ in f), f
    # missing frozen fields
    with open(log, "w") as fh:
        fh.write(json.dumps({"run": "r9", "provider": "prov-a",
                             "ts": "2026-11-23T10:00:00Z",
                             "response": "x"}) + "\n")
    f = []
    audit(read_events(log, f), f, 3600, 0, 0)
    assert any(c == "missing-frozen-field" for _, c, _ in f), f
    # claims naming an unseen provider; malformed lines; missing file
    with open(claims, "w") as fh:
        json.dump({"prov-z": {"uptime_pct": 90.0}}, fh)
    f = []
    check_claims({"prov-a/r1": s}, {"prov-z": {"uptime_pct": 90.0}},
                 f, 1.0)
    assert any(c == "claim-without-evidence" for _, c, _ in f), f
    with open(log, "w") as fh:
        fh.write("{oops\n" + ev("r1", "2026-11-23T10:00:00Z", "P",
                               1, "a") + "\n")
    assert main([log]) == 1, "malformed line is a finding"
    assert main(["nope.jsonl"]) == 2, "missing file is usage/IO"
    assert main([log, "--interval-s", "0"]) == 2, "bad interval"
    assert main([log, "--verify", "deadbeef"]) == 1, "head mismatch"
    emit = os.path.join(tmp, "emit.jsonl")
    assert main([log, "--emit", emit]) == 1
    lines = [json.loads(l) for l in open(emit)]
    assert lines and lines[0]["provider"] == "prov-a", lines
    print("OK parity-freeze-audit: frozen prompt+seed digests, chained "
          "response hashes (edit/order sensitive), bucketed uptime and "
          "responses/hour vs claims with tolerance, drift/seed-collision"
          "/gap/latency verdicts, --verify head, --emit, rc 0/1/2")


if __name__ == "__main__":
    if "--self-test" in sys.argv:
        self_test()  # falls through; rc 0 (probe hook runs after this)
    else:
        raise SystemExit(main())
