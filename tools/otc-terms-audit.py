#!/usr/bin/env python3
"""otc-terms-audit — OTC deal terms-commitment vs volume, price, disclosure audit.

DEMAND: evidence/suggestions/tools-services/ (file citations below)
  - "Want better audit trail for token sales / OTC deals"
  - "ability to commit to paper terms before volume push"
  - "Require external audit reports and TVL transparency for protocols claiming "unified liquidity""
  - "Deliver audits with per-venue funding prints, OI, or holder-count data to substantiate claims."
  Scope: audit a captured deal ledger, one JSONL record per line:
    {"ts","deal_id","event" of terms_committed|volume_push|executed|disclosed,
    "terms":{"max_volume","price_floor","lock_until"},"venue","volume",
    "price","disclosure":{"tvl","oi","holder_count"}}. Flags activity on a
    deal before any terms_committed, terms rewritten after volume push
    began, duplicate commitments with conflicting terms, cumulative
    executed volume past the committed ceiling, prints under the committed
    price floor, execution after lock_until expiry, and venues carrying
    volume_push/executed activity without full tvl/oi/holder-count
    disclosure. Records are data only: plain json parsing, no network, no
    subprocess, nothing executed. rc 0 clean, 1 findings, 2 usage/IO.
    Stdlib only.
"""
import argparse
import io
import json
import os
import sys
import tempfile
from contextlib import redirect_stdout
from datetime import datetime, timezone

EVENTS = ("terms_committed", "volume_push", "executed", "disclosed")
ACTIVITY = ("volume_push", "executed")
FLAGS = ("tvl", "oi", "holder_count")
SEVS = ("BLOCK", "WARN", "INFO")


def _f(sev, kind, origin, detail):
    """Uniform finding dict."""
    return {"severity": sev, "kind": kind, "origin": origin, "detail": detail}


def _num(v):
    """True for real (non-bool) numbers."""
    return isinstance(v, (int, float)) and not isinstance(v, bool)


def parse_ts(v):
    """Timestamp value -> epoch float, else None (int/float or ISO-8601 str)."""
    if isinstance(v, bool):
        return None
    if isinstance(v, (int, float)):
        return float(v)
    if not isinstance(v, str) or not v.strip():
        return None
    try:
        dt = datetime.fromisoformat(v.strip().replace("Z", "+00:00"))
    except ValueError:
        return None
    if dt.tzinfo is None:  # naive values are pinned to UTC for determinism
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.timestamp()


def load_jsonl(path):
    """Read JSONL -> (records, bad_line_numbers); blank lines skipped."""
    records, bad = [], []
    with open(path, "r", encoding="utf-8") as fh:
        for n, line in enumerate(fh, 1):
            s = line.strip()
            if not s:
                continue
            try:
                rec = json.loads(s)
            except ValueError:
                bad.append(n)
                continue
            if isinstance(rec, dict):
                records.append(rec)
            else:
                bad.append(n)
    return records, bad


def _by_deal(records):
    """Group recognized event records by deal_id, preserving input order."""
    by = {}
    for r in records:
        if r.get("event") in EVENTS:
            by.setdefault(str(r.get("deal_id", "?")), []).append(r)
    return by


def _marked(evs):
    """[(ts_or_None, record)] for one deal's events."""
    return [(parse_ts(r.get("ts")), r) for r in evs]


def _terms_sig(r):
    """Comparable (max_volume, price_floor, lock_until) of a commitment."""
    t = r.get("terms") if isinstance(r.get("terms"), dict) else {}
    return (t.get("max_volume"), t.get("price_floor"), t.get("lock_until"))


def _first_terms(marked):
    """Terms dict of the earliest terms_committed record ({} when none)."""
    best, best_t = None, None
    for t, r in marked:
        if r.get("event") != "terms_committed":
            continue
        if best is None or (t is not None and (best_t is None or t < best_t)):
            best, best_t = r, t
    if best is None:
        return {}
    return best.get("terms") if isinstance(best.get("terms"), dict) else {}


def commit_findings(records):
    """Paper-first discipline: commit before activity, no post-hoc rewrites."""
    out = []
    for deal, evs in _by_deal(records).items():
        marked = _marked(evs)
        commits = [(t, r) for t, r in marked if r.get("event") == "terms_committed"]
        cts = [t for t, _ in commits if t is not None]
        first_commit = min(cts) if cts else None
        acts = [t for t, r in marked if r.get("event") in ACTIVITY and t is not None]
        first_act = min(acts) if acts else None
        for t, r in marked:
            if r.get("event") in ACTIVITY and (first_commit is None
                                               or (t is not None and t < first_commit)):
                out.append(_f("BLOCK", "uncommitted-activity", deal,
                              "%s at %s precedes any terms_committed"
                              % (r.get("event"), r.get("ts"))))
                break
        if first_act is not None:
            for t, r in commits:
                if t is not None and t > first_act:
                    out.append(_f("WARN", "terms-rewrite", deal,
                                  "terms_committed after volume push already began"))
                    break
        if len({_terms_sig(r) for _, r in commits}) > 1:
            out.append(_f("BLOCK", "terms-conflict", deal,
                          "duplicate terms_committed carry conflicting terms"))
    return out


def volume_findings(records):
    """Committed ceiling and lock window vs executed volume."""
    out = []
    for deal, evs in _by_deal(records).items():
        marked = _marked(evs)
        terms = _first_terms(marked)
        if not terms:
            continue
        cum, counted = 0.0, False
        for _, r in marked:
            if r.get("event") == "executed" and _num(r.get("volume")):
                cum += float(r["volume"])
                counted = True
        mx = terms.get("max_volume")
        if counted and _num(mx) and cum > float(mx):
            out.append(_f("BLOCK", "volume-overrun", deal,
                          "cumulative executed volume %.6g exceeds committed "
                          "max_volume %.6g" % (cum, float(mx))))
        lock = parse_ts(terms.get("lock_until"))
        if lock is not None:
            for t, r in marked:
                if r.get("event") == "executed" and t is not None and t > lock:
                    out.append(_f("WARN", "lock-expired", deal,
                                  "executed at %s after lock_until %s"
                                  % (r.get("ts"), terms.get("lock_until"))))
                    break
    return out


def price_findings(records):
    """Prints under the committed price floor."""
    out = []
    for deal, evs in _by_deal(records).items():
        marked = _marked(evs)
        terms = _first_terms(marked)
        floor = terms.get("price_floor")
        if not _num(floor):
            continue
        worst = None
        for _, r in marked:
            p = r.get("price")
            if r.get("event") in ACTIVITY and _num(p) and float(p) < float(floor):
                if worst is None or float(p) < worst:
                    worst = float(p)
        if worst is not None:
            out.append(_f("WARN", "price-under-floor", deal,
                          "prints as low as %.6g under committed floor %.6g"
                          % (worst, float(floor))))
    return out


def disclosure_findings(records):
    """Per-venue transparency flags behind volume-carrying activity."""
    out = []
    venues = {}
    for r in records:
        v = r.get("venue")
        if not isinstance(v, str) or not v.strip():
            continue
        slot = venues.setdefault(v.strip(), {"activity": 0, "have": set(), "seen": False})
        if r.get("event") in ACTIVITY:
            slot["activity"] += 1
        elif r.get("event") == "disclosed":
            slot["seen"] = True
            flags = r.get("disclosure") if isinstance(r.get("disclosure"), dict) else {}
            for k in FLAGS:
                if flags.get(k) is True:
                    slot["have"].add(k)
    for v in sorted(venues):
        slot = venues[v]
        if slot["activity"] <= 0:
            continue
        missing = [k for k in FLAGS if k not in slot["have"]]
        if not slot["seen"]:
            out.append(_f("WARN", "no-disclosure", v,
                          "venue has volume_push/executed activity but no "
                          "disclosed record at all"))
        elif missing:
            out.append(_f("WARN", "disclosure-gap", v,
                          "disclosure missing %s" % ",".join(missing)))
    return out


def audit(path):
    """Load the ledger and run every check; returns the findings list."""
    records, bad = load_jsonl(path)
    findings = [_f("WARN", "bad-line", "line:%d" % n,
                   "unparseable or non-object JSONL line") for n in bad]
    for r in records:
        if r.get("event") not in EVENTS:
            findings.append(_f("WARN", "unknown-event", str(r.get("deal_id", "?")),
                               "event %r not one of %s"
                               % (r.get("event"), "/".join(EVENTS))))
    return (findings + commit_findings(records) + volume_findings(records)
            + price_findings(records) + disclosure_findings(records))


def render(findings):
    """Print one human line per finding; return severity counts."""
    counts = {s: 0 for s in SEVS}
    for f in findings:
        counts[f["severity"]] = counts.get(f["severity"], 0) + 1
        print("%-5s %-20s %s: %s"
              % (f["severity"], f["kind"], f["origin"], f["detail"]))
    return counts


def main(argv=None):
    """CLI: path to captured JSONL ledger, optional --json. Returns 0/1/2."""
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("path", help="captured OTC deal JSONL file")
    ap.add_argument("--json", dest="as_json", action="store_true",
                    help="emit findings as JSON")
    args = ap.parse_args(argv)
    try:
        findings = audit(args.path)
    except OSError as exc:
        print("io error: %s" % exc, file=sys.stderr)
        return 2
    if args.as_json:
        print(json.dumps(findings, sort_keys=True))
    else:
        render(findings)
    return 1 if findings else 0


def _write(rows):
    """Fixture rows -> temp JSONL path (caller must os.unlink)."""
    fh = tempfile.NamedTemporaryFile(delete=False, suffix=".jsonl",
                                     mode="w", encoding="utf-8")
    try:
        for r in rows:
            fh.write(json.dumps(r) + "\n")
    finally:
        fh.close()
    return fh.name


def self_test():
    """Hand-computed fixtures cover every rule plus the CLI rc contract."""
    clean = [
        {"ts": "2026-04-01T00:00:00Z", "deal_id": "D-1", "event": "terms_committed",
         "terms": {"max_volume": 100.0, "price_floor": 0.90, "lock_until": "2026-05-01T00:00:00Z"}},
        {"ts": "2026-04-02T00:00:00Z", "deal_id": "D-1", "event": "disclosed",
         "venue": "desk-alpha", "disclosure": {"tvl": True, "oi": True, "holder_count": True}},
        {"ts": "2026-04-02T00:00:00Z", "deal_id": "D-1", "event": "volume_push",
         "venue": "desk-alpha", "volume": 40.0, "price": 0.95},
        {"ts": "2026-04-03T00:00:00Z", "deal_id": "D-1", "event": "executed",
         "venue": "desk-alpha", "volume": 60.0, "price": 0.97},
    ]
    messy = [
        # E-1: volume push before any paper exists
        {"ts": "2026-04-01T00:00:00Z", "deal_id": "E-1", "event": "volume_push", "venue": "desk-beta", "volume": 5.0, "price": 0.95},
        {"ts": "2026-04-02T00:00:00Z", "deal_id": "E-1", "event": "terms_committed",
         "terms": {"max_volume": 50.0, "price_floor": 0.90, "lock_until": "2026-06-01T00:00:00Z"}},
        # E-2: duplicate commitments with conflicting terms
        {"ts": "2026-04-01T00:00:00Z", "deal_id": "E-2", "event": "terms_committed",
         "terms": {"max_volume": 10.0, "price_floor": 0.80, "lock_until": "2026-06-01T00:00:00Z"}},
        {"ts": "2026-04-01T01:00:00Z", "deal_id": "E-2", "event": "terms_committed",
         "terms": {"max_volume": 20.0, "price_floor": 0.80, "lock_until": "2026-06-01T00:00:00Z"}},
        # E-3: overrun, under-floor prints, lock expiry, post-hoc rewrite
        {"ts": "2026-04-01T00:00:00Z", "deal_id": "E-3", "event": "terms_committed",
         "terms": {"max_volume": 10.0, "price_floor": 1.00, "lock_until": "2026-04-05T00:00:00Z"}},
        {"ts": "2026-04-02T00:00:00Z", "deal_id": "E-3", "event": "volume_push", "venue": "desk-beta", "volume": 4.0, "price": 0.91},
        {"ts": "2026-04-06T00:00:00Z", "deal_id": "E-3", "event": "executed", "venue": "desk-beta", "volume": 11.0, "price": 0.92},
        {"ts": "2026-04-07T00:00:00Z", "deal_id": "E-3", "event": "terms_committed",
         "terms": {"max_volume": 99.0, "price_floor": 0.10, "lock_until": "2026-08-01T00:00:00Z"}},
        # E-4: desk-gamma partial disclosure, desk-delta none at all
        {"ts": "2026-04-01T00:00:00Z", "deal_id": "E-4", "event": "terms_committed",
         "terms": {"max_volume": 500.0, "price_floor": 0.50, "lock_until": "2026-07-01T00:00:00Z"}},
        {"ts": "2026-04-02T00:00:00Z", "deal_id": "E-4", "event": "disclosed",
         "venue": "desk-gamma", "disclosure": {"tvl": True, "oi": False}},
        {"ts": "2026-04-03T00:00:00Z", "deal_id": "E-4", "event": "volume_push", "venue": "desk-gamma", "volume": 20.0, "price": 0.60},
        {"ts": "2026-04-03T00:00:00Z", "deal_id": "E-4", "event": "volume_push", "venue": "desk-delta", "volume": 1.0, "price": 0.60},
    ]
    p_clean = _write(clean)
    p_messy = _write(messy)
    try:
        assert parse_ts("2026-04-02T00:10:00Z") - parse_ts("2026-04-02T00:00:00Z") == 600.0
        assert parse_ts(None) is None and parse_ts(90) == 90.0
        assert sorted(_by_deal(messy)) == ["E-1", "E-2", "E-3", "E-4"]
        assert [x for x in commit_findings(messy) if x["kind"] == "uncommitted-activity"][0]["severity"] == "BLOCK"
        assert any(x["kind"] == "uncommitted-activity" and x["origin"] == "E-1" for x in commit_findings(messy))
        assert any(x["kind"] == "terms-rewrite" and x["origin"] == "E-3" for x in commit_findings(messy))
        assert any(x["kind"] == "terms-conflict" and x["origin"] == "E-2" for x in commit_findings(messy))
        assert [x for x in volume_findings(messy) if x["kind"] == "volume-overrun"][0]["severity"] == "BLOCK"
        assert any(x["kind"] == "lock-expired" and x["origin"] == "E-3" for x in volume_findings(messy))
        assert any(x["kind"] == "price-under-floor" and x["origin"] == "E-3" for x in price_findings(messy))
        assert any(x["kind"] == "no-disclosure" and x["origin"] == "desk-delta" for x in disclosure_findings(messy))
        assert any(x["kind"] == "disclosure-gap" and x["origin"] == "desk-gamma"
                   and "oi" in x["detail"] for x in disclosure_findings(messy))
        assert audit(p_clean) == []
        with redirect_stdout(io.StringIO()):
            rc0 = main([p_clean])
            rc1 = main([p_messy])
            rc2 = main(["/no/such/otc-fixture.jsonl"])
            zero = render([])
        assert rc0 == 0 and rc1 == 1 and rc2 == 2, (rc0, rc1, rc2)
        assert zero == {"BLOCK": 0, "WARN": 0, "INFO": 0}, zero
    finally:
        os.unlink(p_clean)
        os.unlink(p_messy)
    print("otc-terms-audit self-test OK (parse/group, commit-before-activity, "
          "rewrite, terms conflict, volume overrun, lock expiry, price floor, "
          "venue disclosure gap/missing, render, rc 0/1/2)")


if __name__ == "__main__":
    if "--self-test" in sys.argv:
        self_test()  # falls through; rc 0 (probe hook runs after this)
    else:
        raise SystemExit(main())
