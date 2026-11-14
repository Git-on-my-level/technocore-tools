#!/usr/bin/env python3
"""retry-budget-audit — audit declared retry budgets against the retry
attempts actually made: over-budget attempts, retries with no declared
budget, mid-stream budget revisions, budgets exhausted then abandoned,
retry storms, attempt-sequence gaps and retry waste.

DEMAND: evidence/suggestions/tools-services/2026-10-27.md
  - request: "manual audit of retry budget in the price room" —
    evidence: "Is a key manager auditing a retry budget in the price
    room manually?" — proposed service: automated retry-budget audit
    instead of manual. Recurs in 2026-10-26.md: "Rollup nodes batched
    a retry budget inside the audit tool that morning" — proposed
    service: change-log/diff of retry-budget mutations. No existing
    tool audits retry budgets (job-coalesce drops retry as volatile;
    settlement-rail flags only failed-then-cleared).
Input: one JSONL file, one record per line, in file order:
  attempt  {"key": str, "attempt": int >= 1, "ts": t,
            "outcome": "ok"|"retry"|"fail"|"abort", "budget"?: int}
  declare  {"event": "budget", "key": str, "budget": int, "ts": t}
  t is epoch seconds or ISO-8601 text. An inline "budget" on an
  attempt puts that budget in force for it (and later attempts).
  "ok"/"fail"/"abort" end a retry run; "retry" continues it.
Findings (rc 0 clean / 1 findings / 2 usage-IO):
  no-records         FAIL  file has no usable records
  bad-record         WARN  line is not a usable attempt/declaration
  unbudgeted-retry   BLOCK attempt against a key with no budget set
  over-budget        BLOCK attempt number above the budget in force
  budget-revision    WARN  budget changed mid-stream (drift visibility)
  unknown-outcome    WARN  outcome outside ok/retry/fail/abort
  duplicate-attempt  WARN  same key+attempt number seen twice
  attempt-gap        WARN  non-consecutive attempt numbers in one run
  retry-storm        WARN  >= --storm attempts within --window-min
  gave-up-at-budget  WARN  run ended in fail with the budget consumed
  retry-waste        INFO  >= --waste retries but eventually ok
Inputs are data only: plain json parsing, no network, no subprocess,
nothing executed. Stdlib only.
"""
import argparse
import json
import sys
from datetime import datetime

OUTCOMES = ("ok", "retry", "fail", "abort")
TERMINAL = ("ok", "fail", "abort")
SEVS = ("BLOCK", "WARN", "INFO")


def _f(sev, kind, key, detail):
    """Uniform finding dict."""
    return {"severity": sev, "kind": kind, "key": key, "detail": detail}


def parse_ts(v):
    """Timestamp value -> epoch float, else None."""
    if isinstance(v, bool):
        return None
    if isinstance(v, (int, float)):
        return float(v)
    if isinstance(v, str) and v.strip():
        t = v.strip()
        if t.endswith("Z"):
            t = t[:-1] + "+00:00"
        try:
            return datetime.fromisoformat(t).timestamp()
        except ValueError:
            return None
    return None


def _budget_val(v):
    """True for a usable budget integer (>= 0, not bool)."""
    return (isinstance(v, int) and not isinstance(v, bool) and v >= 0
            and v == v)


def read_records(lines):
    """Parse input lines -> (attempt_records, budget_records, bad_count).

    attempt: dict(key, attempt, ts, outcome, budget|None, lineno)
    budget:  dict(key, budget, ts, lineno)
    """
    attempts, budgets, bad = [], [], 0
    for lineno, raw in enumerate(lines, 1):
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        try:
            rec = json.loads(line)
        except ValueError:
            bad += 1
            continue
        if not isinstance(rec, dict):
            bad += 1
            continue
        ts = parse_ts(rec.get("ts"))
        if rec.get("event") == "budget":
            if (isinstance(rec.get("key"), str) and rec["key"]
                    and _budget_val(rec.get("budget"))):
                budgets.append({"key": rec["key"], "budget": rec["budget"],
                                "ts": ts, "lineno": lineno})
            else:
                bad += 1
            continue
        att = rec.get("attempt")
        if (isinstance(rec.get("key"), str) and rec["key"]
                and isinstance(att, int) and not isinstance(att, bool)
                and att >= 1):
            bud = rec.get("budget") if _budget_val(rec.get("budget")) \
                else None
            attempts.append({"key": rec["key"], "attempt": att, "ts": ts,
                             "outcome": rec.get("outcome"), "budget": bud,
                             "lineno": lineno})
        else:
            bad += 1
    return attempts, budgets, bad


def audit(attempts, budgets, bad, storm, window_secs, waste):
    findings = []
    if bad:
        findings.append(_f("WARN", "bad-record", "-",
                           "%d unusable input line(s)" % bad))
    if not attempts and not budgets:
        findings.append(_f("BLOCK", "no-records", "-",
                           "no usable attempt or budget records"))
        return findings, {}, {"keys": 0}

    # key -> budget in force (None until declared), prior value for drift
    budget_in_force = {}
    prior_value = {}
    keys_state = {}
    # key -> list of runs; a run is the attempt list since last terminal
    runs = {}
    seen_pair = set()

    def note_budget(key, value):
        if key in prior_value and prior_value[key] != value:
            findings.append(_f(
                "WARN", "budget-revision", key,
                "budget %r -> %r mid-stream" % (prior_value[key], value)))
        prior_value[key] = value
        budget_in_force[key] = value

    def key_state(key):
        return keys_state.setdefault(
            key, {"budget": None, "attempts": 0, "retries": 0,
                  "ok": 0, "fail": 0, "abort": 0, "max_attempt": 0,
                  "ts_list": []})

    # merge stream: budgets and attempts in file order
    stream = [("b", r) for r in budgets] + [("a", r) for r in attempts]
    stream.sort(key=lambda p: p[1]["lineno"])
    for kind, rec in stream:
        key = rec["key"]
        st = key_state(key)
        if kind == "b":
            note_budget(key, rec["budget"])
            st["budget"] = rec["budget"]
            continue
        if rec["budget"] is not None:
            note_budget(key, rec["budget"])
            st["budget"] = rec["budget"]
        att, outcome = rec["attempt"], rec["outcome"]
        st["attempts"] += 1
        st["max_attempt"] = max(st["max_attempt"], att)
        if rec["ts"] is not None:
            st["ts_list"].append(rec["ts"])
        if outcome not in OUTCOMES:
            findings.append(_f("WARN", "unknown-outcome", key,
                               "outcome %r at line %d" % (outcome,
                                                          rec["lineno"])))
        pair = (key, att)
        if pair in seen_pair:
            findings.append(_f("WARN", "duplicate-attempt", key,
                               "attempt %d logged again at line %d"
                               % (att, rec["lineno"])))
        seen_pair.add(pair)
        if budget_in_force.get(key) is None:
            findings.append(_f("BLOCK", "unbudgeted-retry", key,
                               "attempt %d with no budget declared "
                               "(line %d)" % (att, rec["lineno"])))
        elif att > budget_in_force[key]:
            findings.append(_f("BLOCK", "over-budget", key,
                               "attempt %d over budget %d (line %d)"
                               % (att, budget_in_force[key],
                                  rec["lineno"])))
        cur = runs.setdefault(key, [[]])
        prev = cur[-1][-1]["attempt"] if cur[-1] else None
        if prev is not None and att != prev and att != prev + 1:
            findings.append(_f("WARN", "attempt-gap", key,
                               "attempt %d follows %d in one run "
                               "(line %d)" % (att, prev, rec["lineno"])))
        cur[-1].append(rec)
        if outcome in TERMINAL:
            st[outcome] += 1
            if outcome == "fail" and budget_in_force.get(key) is not None \
                    and att >= budget_in_force[key]:
                findings.append(_f("WARN", "gave-up-at-budget", key,
                                   "failed final attempt %d with budget "
                                   "%d consumed" % (att,
                                                    budget_in_force[key])))
            runs[key].append([])
        elif outcome == "retry":
            st["retries"] += 1

    # retry storms: >= storm attempts inside window_secs for one key
    for key, st in keys_state.items():
        ts_list = sorted(t for t in st["ts_list"] if t is not None)
        if st["retries"] >= storm and ts_list:
            lo = 0
            for hi in range(len(ts_list)):
                while ts_list[hi] - ts_list[lo] > window_secs:
                    lo += 1
                if hi - lo + 1 >= storm:
                    findings.append(_f("WARN", "retry-storm", key,
                                       "%d attempts within %g min"
                                       % (hi - lo + 1,
                                          window_secs / 60.0)))
                    break

    totals = {"keys": len(keys_state),
              "attempts": sum(s["attempts"] for s in keys_state.values()),
              "retries": sum(s["retries"] for s in keys_state.values())}
    for key, st in keys_state.items():
        if st["ok"] and st["retries"] >= waste:
            findings.append(_f("INFO", "retry-waste", key,
                               "%d retries before success (budget %r)"
                               % (st["retries"], st["budget"])))
    return findings, keys_state, totals


def report(findings, keys_state, totals, as_json=False):
    """Render findings + per-key budget summary."""
    if as_json:
        return json.dumps({"findings": findings,
                           "keys": keys_state,
                           "totals": totals}, indent=2, default=str)
    order = {s: i for i, s in enumerate(SEVS)}
    shown = sorted(findings, key=lambda f: order[f["severity"]])
    out = ["findings:"] if shown else ["findings: none"]
    for f in shown:
        out.append("%s %s [%s] %s" % (f["severity"], f["kind"],
                                      f["key"], f["detail"]))
    out.append("retry-budget summary (%d key(s), %d attempt(s), "
               "%d retry(ies)):" % (totals.get("keys", 0),
                                    totals.get("attempts", 0),
                                    totals.get("retries", 0)))
    for key in sorted(keys_state):
        s = keys_state[key]
        out.append("    %-24s budget=%r used=%d retries=%d ok=%d "
                   "fail=%d abort=%d" % (key, s["budget"],
                                         s["max_attempt"], s["retries"],
                                         s["ok"], s["fail"], s["abort"]))
    return "\n".join(out)


def self_test():
    lines = [
        '{"event":"budget","key":"price-room/rate-fetch","budget":3,"ts":100}',
        '{"key":"price-room/rate-fetch","attempt":1,"outcome":"retry","ts":101}',
        '{"key":"price-room/rate-fetch","attempt":2,"outcome":"ok","ts":102}',
    ]
    a, b, bad = read_records(lines)
    assert bad == 0 and len(a) == 2 and len(b) == 1, (a, b, bad)
    f, ks, tot = audit(a, b, bad, storm=4, window_secs=1800, waste=99)
    assert not f, f  # attempts within budget -> clean
    assert ks["price-room/rate-fetch"]["max_attempt"] == 2
    assert tot["attempts"] == 2 and tot["retries"] == 1, tot

    # over-budget attempt
    a2, b2, _ = read_records([
        '{"event":"budget","key":"k","budget":2,"ts":1}',
        '{"key":"k","attempt":1,"outcome":"retry","ts":2}',
        '{"key":"k","attempt":2,"outcome":"retry","ts":3}',
        '{"key":"k","attempt":3,"outcome":"ok","ts":4}',
    ])
    f2, _, _ = audit(a2, b2, 0, storm=9, window_secs=1, waste=99)
    kinds = {x["kind"] for x in f2}
    assert "over-budget" in kinds and "gave-up-at-budget" not in kinds, f2

    # unbudgeted retries
    a3, _, _ = read_records(
        ['{"key":"k","attempt":1,"outcome":"retry","ts":1}'])
    f3, _, _ = audit(a3, [], 0, storm=9, window_secs=1, waste=99)
    assert any(x["kind"] == "unbudgeted-retry" for x in f3), f3

    # mid-stream budget revision (the 10-26 "batched a retry budget" ask)
    a4, b4, _ = read_records([
        '{"event":"budget","key":"k","budget":5,"ts":1}',
        '{"key":"k","attempt":1,"outcome":"retry","ts":2}',
        '{"event":"budget","key":"k","budget":2,"ts":3}',
        '{"key":"k","attempt":2,"outcome":"fail","ts":4}',
    ])
    f4, _, _ = audit(a4, b4, 0, storm=9, window_secs=1, waste=99)
    kinds4 = {x["kind"] for x in f4}
    assert "budget-revision" in kinds4 and "gave-up-at-budget" in kinds4, f4

    # inline budget on the attempt record itself
    a5, _, _ = read_records([
        '{"key":"k","attempt":1,"outcome":"retry","ts":1,"budget":1}',
        '{"key":"k","attempt":2,"outcome":"ok","ts":2}',
    ])
    f5, _, _ = audit(a5, [], 0, storm=9, window_secs=1, waste=99)
    assert any(x["kind"] == "over-budget" for x in f5), f5

    # gave-up-at-budget: final fail consumes the whole budget
    a6, b6, _ = read_records([
        '{"event":"budget","key":"k","budget":3,"ts":0}',
        '{"key":"k","attempt":1,"outcome":"retry","ts":1}',
        '{"key":"k","attempt":2,"outcome":"retry","ts":2}',
        '{"key":"k","attempt":3,"outcome":"fail","ts":3}',
    ])
    f6, ks6, _ = audit(a6, b6, 0, storm=9, window_secs=1, waste=99)
    assert any(x["kind"] == "gave-up-at-budget" for x in f6), f6
    assert ks6["k"]["retries"] == 2 and ks6["k"]["fail"] == 1, ks6

    # retry storm: 4 attempts within the window
    a7, b7, _ = read_records([
        '{"event":"budget","key":"k","budget":9,"ts":0}',
        '{"key":"k","attempt":1,"outcome":"retry","ts":10}',
        '{"key":"k","attempt":2,"outcome":"retry","ts":20}',
        '{"key":"k","attempt":3,"outcome":"retry","ts":30}',
        '{"key":"k","attempt":4,"outcome":"retry","ts":40}',
        '{"key":"k","attempt":5,"outcome":"ok","ts":50}',
    ])
    f7, _, _ = audit(a7, b7, 0, storm=4, window_secs=120, waste=99)
    assert any(x["kind"] == "retry-storm" for x in f7), f7

    # duplicate attempt number and a sequence gap
    a8, b8, _ = read_records([
        '{"event":"budget","key":"k","budget":9,"ts":0}',
        '{"key":"k","attempt":1,"outcome":"retry","ts":1}',
        '{"key":"k","attempt":1,"outcome":"retry","ts":2}',
        '{"key":"k","attempt":3,"outcome":"ok","ts":3}',
    ])
    f8, _, _ = audit(a8, b8, 0, storm=9, window_secs=1, waste=99)
    kinds8 = {x["kind"] for x in f8}
    assert {"duplicate-attempt", "attempt-gap"} <= kinds8, f8

    # retry waste: eventually ok after many retries
    recs = ['{"event":"budget","key":"k","budget":9,"ts":0}']
    for i in range(1, 5):
        recs.append('{"key":"k","attempt":%d,"outcome":"retry","ts":%d}'
                    % (i, i))
    recs.append('{"key":"k","attempt":5,"outcome":"ok","ts":9}')
    a9, b9, _ = read_records(recs)
    f9, _, _ = audit(a9, b9, 0, storm=99, window_secs=1, waste=4)
    assert any(x["kind"] == "retry-waste" and x["severity"] == "INFO"
               for x in f9), f9

    # ISO-8601 timestamps parse; Z suffix handled
    assert parse_ts("2026-10-27T03:36:00Z") is not None
    assert parse_ts("not-a-time") is None and parse_ts(True) is None
    assert parse_ts(105) == 105.0

    # malformed input -> bad-record / no-records
    a10, b10, bad10 = read_records(["{oops", '{"key":"k"}',
                                    '{"key":"k","attempt":0,'
                                    '"outcome":"retry","ts":1}'])
    assert bad10 == 3 and not a10 and not b10, (a10, b10, bad10)
    f10, _, _ = audit([], [], 3, storm=9, window_secs=1, waste=99)
    f11, _, _ = audit([], [], 0, storm=9, window_secs=1, waste=99)
    assert any(x["kind"] == "no-records" for x in f11), f11

    # report renders both shapes and orders BLOCK first
    mixed = f2 + [_f("WARN", "budget-revision", "k", "test warn")]
    txt = report(mixed, {}, {"keys": 0, "attempts": 0, "retries": 0})
    assert "over-budget" in txt and txt.index("BLOCK") < txt.index("WARN"), txt
    j = report(f2, {}, {"keys": 0, "attempts": 0, "retries": 0},
               as_json=True)
    assert json.loads(j)["findings"], j
    print("OK retry-budget-audit self-test")


def main(argv=None):
    ap = argparse.ArgumentParser(
        description="Audit retry budgets against the retry attempts "
                    "actually made")
    ap.add_argument("file", nargs="?", help="JSONL file (default stdin)")
    ap.add_argument("--storm", type=int, default=4,
                    help="attempts inside the window that make a storm "
                         "(default 4)")
    ap.add_argument("--window-min", type=float, default=30.0,
                    help="storm window in minutes (default 30)")
    ap.add_argument("--waste", type=int, default=5,
                    help="retries-before-success that count as waste "
                         "(default 5)")
    ap.add_argument("--json", action="store_true",
                    help="structured JSON output")
    ap.add_argument("--self-test", action="store_true",
                    help="run built-in self-test")
    args = ap.parse_args(argv)

    if args.self_test:
        self_test()
        return 0

    if args.file:
        try:
            with open(args.file, "r", errors="replace") as fh:
                lines = fh.readlines()
        except OSError as exc:
            print("cannot read %s: %s" % (args.file, exc), file=sys.stderr)
            return 2
    else:
        lines = sys.stdin.readlines()

    attempts, budgets, bad = read_records(lines)
    findings, keys_state, totals = audit(attempts, budgets, bad,
                                         storm=args.storm,
                                         window_secs=args.window_min * 60.0,
                                         waste=args.waste)
    print(report(findings, keys_state, totals, as_json=args.json))
    return 1 if findings else 0


if __name__ == "__main__":
    if "--self-test" in sys.argv:
        self_test()  # falls through; rc 0
    else:
        raise SystemExit(main())
