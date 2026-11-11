#!/usr/bin/env python3
"""pool-action-verify — cross-checks infrastructure action claims
against an ops event log: "was the audit log really batched on
Ethereum / cached at the edge / was the encrypted backup actually
indexed inside the audit pool?" A claim is CONFIRMED only when a
matching completion event exists in the time slack; a fail/rollback
event CONTRADICTS it; silence leaves it UNVERIFIED.

DEMAND: evidence/suggestions/tools-services/2026-11-10.md (11:55 run)
  - "Did audit tools batch the audit log on Ethereum earlier today?" /
    "Has the monitoring stack cached the audit log at the edge in
    recent epochs?" / "Did HARD paths index an encrypted backup inside
    the audit pool this morning?" — proposed service: "Add chain/edge/
    batch verification queries to confirm audit-log batching, caching,
    and indexing actions."
Scope: the offline half of that service — replay a saved ops/event
export and adjudicate each filed action claim against the recorded
events, with per-claim evidence lines. Data is parsed, never run.

Inputs (JSONL):
  claims (--claims, required): {"id": "c1",
                                "action": "batch",      # or cache/index/...
                                "target": "audit-log ethereum",
                                "ts": 1762700100}
  events (--events, required): {"ts": 1762700105, "actor": "monitoring",
                                "action": "batched",
                                "target": "audit-log ethereum",
                                "status": "ok",   # ok|fail|rollback
                                "detail": "tx 0x..."}

Matching: normalized action prefix ("batch" matches "batched") and
normalized target token-subset, with |event.ts - claim.ts| <=
--slack-secs (default 900). Verdict per claim: CONFIRMED /
CONTRADICTED / UNVERIFIED. rc 0 = every claim confirmed, 1 = any
claim unverified or contradicted, 2 = usage/IO error.
"""

import argparse
import json
import sys
from collections import defaultdict

_WS = " "
_OK = {"ok", "done", "success", "complete", "completed"}
_FAIL = {"fail", "failed", "error", "rollback", "reverted", "aborted"}


def norm(text):
    """Normalize an action/target for matching."""
    return _WS.join(str(text).lower().split())


def tokens(text):
    """Token set of a normalized target."""
    return set(norm(text).replace("-", " ").split())


def action_matches(claim_action, event_action):
    """'batch' matches 'batch'/'batched'/'batching' (prefix rule)."""
    ca, ea = norm(claim_action), norm(event_action)
    return bool(ca) and (ea.startswith(ca) or ca.startswith(ea))


def target_matches(claim_target, event_target):
    """Token-subset match: claim 'audit log ethereum' matches event
    'audit log to ethereum mainnet'."""
    ct, et = tokens(claim_target), tokens(event_target)
    return bool(ct) and (ct <= et or et < ct)


def parse_jsonl(path):
    """Read a JSONL file; '-' means stdin. Returns (records, errors)."""
    fh = sys.stdin if path == "-" else open(path, errors="replace")
    recs, errs = [], []
    try:
        for i, line in enumerate(fh, 1):
            line = line.strip()
            if not line:
                continue
            try:
                obj = json.loads(line)
            except ValueError as e:
                errs.append({"line": i, "error": str(e)})
                continue
            if isinstance(obj, dict):
                recs.append(obj)
            else:
                errs.append({"line": i, "error": "not a JSON object"})
    finally:
        if fh is not sys.stdin:
            fh.close()
    return recs, errs


def _num(v):
    return isinstance(v, (int, float)) and not isinstance(v, bool)


def adjudicate(claims, events, slack):
    """Verdict + evidence per claim. Returns list of result dicts."""
    results = []
    for i, claim in enumerate(claims):
        cid = claim.get("id", "claim %d" % (i + 1))
        base = {"id": cid, "action": claim.get("action"),
                "target": claim.get("target"), "ts": claim.get("ts")}
        if "action" not in claim or "target" not in claim:
            results.append(dict(base, verdict="MALFORMED",
                                evidence="claim needs action + target"))
            continue
        best = None
        for ev in events:
            if not action_matches(claim["action"], ev.get("action", "")):
                continue
            if not target_matches(claim["target"], ev.get("target", "")):
                continue
            if _num(claim.get("ts")) and _num(ev.get("ts")):
                if abs(float(ev["ts"]) - float(claim["ts"])) > slack:
                    continue
            status = norm(ev.get("status", "ok"))
            weight = 2 if status in _OK else (0 if status in _FAIL
                                              else 1)
            ev_line = "ts=%s actor=%s action=%r target=%r status=%s" % (
                ev.get("ts"), ev.get("actor", "?"), ev.get("action"),
                ev.get("target"), ev.get("status", "ok"))
            if best is None or weight > best[0]:
                best = (weight, ev_line)
        if best is None:
            results.append(dict(base, verdict="UNVERIFIED",
                                evidence="no matching event within "
                                         "%ss slack" % slack))
        elif best[0] == 2:
            results.append(dict(base, verdict="CONFIRMED",
                                evidence=best[1]))
        elif best[0] == 0:
            results.append(dict(base, verdict="CONTRADICTED",
                                evidence=best[1]))
        else:
            results.append(dict(base, verdict="UNVERIFIED",
                                evidence="ambiguous status: " + best[1]))
    return results


def summarize(results):
    """Counts per verdict."""
    counts = defaultdict(int)
    for r in results:
        counts[r["verdict"]] += 1
    return dict(counts)


def fmt_report(results):
    """Human-readable adjudication report."""
    if not results:
        return "no claims to verify"
    counts = summarize(results)
    lines = ["%d claim(s): %s" % (
        len(results),
        ", ".join("%s=%d" % kv for kv in sorted(counts.items())))]
    for r in results:
        lines.append("  - [%s] %s %r @%s"
                     % (r["verdict"], r["action"], r["target"],
                        r["ts"]))
        lines.append("      evidence: %s" % r["evidence"])
    return "\n".join(lines)


def build_parser():
    ap = argparse.ArgumentParser(
        prog="pool-action-verify.py",
        description="Adjudicate infrastructure action claims (batch / "
                    "cache / index / ...) against an ops event log: "
                    "CONFIRMED, CONTRADICTED, or UNVERIFIED per claim.")
    ap.add_argument("--claims", required=True,
                    help="claims JSONL file (or '-')")
    ap.add_argument("--events", required=True,
                    help="events JSONL file (or '-')")
    ap.add_argument("--slack-secs", type=float, default=900.0,
                    help="max |event.ts - claim.ts| for a match "
                         "(default 900)")
    ap.add_argument("--json", action="store_true",
                    help="emit results as JSON")
    return ap


def main(argv=None):
    opt = build_parser().parse_args(argv)
    try:
        claims, cerrs = parse_jsonl(opt.claims)
        events, eerrs = parse_jsonl(opt.events)
    except OSError as e:
        print("error: %s" % e, file=sys.stderr)
        return 2
    results = adjudicate(claims, events, opt.slack_secs)
    if opt.json:
        print(json.dumps({"results": results,
                          "summary": summarize(results),
                          "parse_errors": cerrs + eerrs},
                         ensure_ascii=False))
    else:
        print(fmt_report(results))
        for e in cerrs + eerrs:
            print("parse error line %d: %s" % (e["line"], e["error"]),
                  file=sys.stderr)
    bad = any(r["verdict"] != "CONFIRMED" for r in results)
    return 1 if bad else 0


def self_test():
    import os
    import shutil
    import tempfile

    # matchers: prefix action, token-subset target
    assert action_matches("batch", "batched")
    assert action_matches("cached", "cache")
    assert not action_matches("cache", "batch")
    assert target_matches("audit log ethereum",
                          "audit log to ethereum mainnet")
    assert target_matches("edge cache audit-log", "audit log edge")
    assert not target_matches("audit log", "backup pool")
    assert not target_matches("", "anything")

    claims = [
        {"id": "c-batch", "action": "batch", "target": "audit-log ethereum",
         "ts": 1000},
        {"id": "c-cache", "action": "cache", "target": "audit-log edge",
         "ts": 1000},
        {"id": "c-index", "action": "index",
         "target": "encrypted backup audit-pool", "ts": 1000},
        {"id": "c-late", "action": "batch", "target": "audit-log ethereum",
         "ts": 5000},
        {"id": "c-bad", "action": "seal", "ts": 1000},
    ]
    events = [
        {"ts": 1005, "actor": "tooling", "action": "batched",
         "target": "audit-log to ethereum", "status": "ok"},
        {"ts": 1007, "actor": "hard-paths", "action": "indexed",
         "target": "encrypted backup inside audit-pool", "status": "fail"},
        {"ts": 120000, "actor": "tooling", "action": "batched",
         "target": "audit-log ethereum", "status": "ok"},
    ]
    res = {r["id"]: r for r in adjudicate(claims, events, 900.0)}
    assert res["c-batch"]["verdict"] == "CONFIRMED", res["c-batch"]
    assert res["c-cache"]["verdict"] == "UNVERIFIED", res["c-cache"]
    assert res["c-index"]["verdict"] == "CONTRADICTED", res["c-index"]
    # event exists but far outside slack -> unverified
    assert res["c-late"]["verdict"] == "UNVERIFIED", res["c-late"]
    assert res["c-bad"]["verdict"] == "MALFORMED", res["c-bad"]
    assert summarize(list(res.values()))["CONFIRMED"] == 1

    # ambiguous status (neither ok nor fail) stays UNVERIFIED
    amb = adjudicate([{"id": "a1", "action": "cache",
                       "target": "edge", "ts": 1}],
                     [{"ts": 2, "action": "cache", "target": "edge",
                       "status": "started"}], 900.0)
    assert amb[0]["verdict"] == "UNVERIFIED", amb

    # determinism
    assert adjudicate(claims, events, 900.0) == \
        adjudicate(claims, events, 900.0)

    # end-to-end over temp files: mixed -> rc 1; all-confirmed -> rc 0
    root = tempfile.mkdtemp(prefix="pool-verify-")
    try:
        cpath = os.path.join(root, "claims.jsonl")
        epath = os.path.join(root, "events.jsonl")
        with open(cpath, "w") as fh:
            for c in claims:
                fh.write(json.dumps(c) + "\n")
        with open(epath, "w") as fh:
            for e in events:
                fh.write(json.dumps(e) + "\n")
        assert main(["--claims", cpath, "--events", epath]) == 1
        rep = fmt_report(adjudicate(claims, events, 900.0))
        assert "[CONFIRMED] batch" in rep and "[CONTRADICTED] index" in rep
        assert "[UNVERIFIED] cache" in rep and "MALFORMED" in rep, rep
        ok_e = [{"ts": 1002, "actor": "tooling", "action": "batched",
                 "target": "audit-log ethereum", "status": "ok"}]
        ok_e_path = os.path.join(root, "ok-events.jsonl")
        with open(ok_e_path, "w") as fh:
            fh.write(json.dumps(ok_e[0]) + "\n")
        ok_c = [{"id": "only", "action": "batch",
                 "target": "ethereum audit-log", "ts": 1000}]
        ok_c_path = os.path.join(root, "ok-claims.jsonl")
        with open(ok_c_path, "w") as fh:
            fh.write(json.dumps(ok_c[0]) + "\n")
        assert main(["--claims", ok_c_path, "--events",
                     ok_e_path]) == 0
    finally:
        shutil.rmtree(root, ignore_errors=True)
    print("pool-action-verify self-test OK (prefix/token matchers, "
          "confirmed vs contradicted vs unverified, slack window, "
          "malformed claim, ambiguous status, determinism, end-to-end "
          "rc 1 vs 0)")


if __name__ == "__main__":
    if "--self-test" in sys.argv:
        self_test()  # falls through; rc 0 (mutation probe runs after)
    else:
        raise SystemExit(main())
