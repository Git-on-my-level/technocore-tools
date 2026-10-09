#!/usr/bin/env python3
"""settlement-rail-audit — merchant settlement rail stage, ETA, slot and reserve audit.

DEMAND: evidence/suggestions/tools-services/ (file citations below)
  - "Real-time, transparent auditability for merchant settlement and transaction trails"
  - "Need visibility into settlement processing status and estimated clearance times"
  - "Proof-to-settlement ETA estimation"
  - "audit trail integration with settlement rails"
  - "Audit slot scheduling for settlement timing"
  - "Proof-of-reserve audit trail for settlement backing"
  Scope: audit a captured settlement trail, one JSONL record per line:
    stage events {"ts","rail","ref","stage" of submitted|processing|
    cleared|failed,"amount","asset","eta_min","slot"} plus optional
    {"event":"reserve_attestation","rail","asset","backing_amount","ts"}.
    Flags stage skips/unknowns/order/dupes/amount drift, clearance dwell
    past eta_min, missing eta, failed-then-cleared without retry, stalled
    processing, rail+slot double-booking, cleared volume over (or
    without) proof-of-reserve backing. Data only: plain json parsing, no
    network, no subprocess, nothing executed. rc 0 clean, 1 findings,
    2 usage/IO. Stdlib only.
"""
import argparse
import io
import json
import os
import sys
import tempfile
from contextlib import redirect_stdout
from datetime import datetime, timezone

STAGES = ("submitted", "processing", "cleared", "failed")
TERMINAL = ("cleared", "failed")
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

def split_records(records):
    """Partition into (stage events, reserve attestations, unrecognized)."""
    stage, attest, other = [], [], []
    for r in records:
        if r.get("event") == "reserve_attestation":
            attest.append(r)
        elif "stage" in r:
            stage.append(r)
        else:
            other.append(r)
    return stage, attest, other

def stage_findings(records):
    """Per-ref stage machine: skips, unknown stages, order, dupes, amounts."""
    stage, _, _ = split_records(records)
    out = []
    by_ref = {}
    for r in stage:
        ref = str(r.get("ref", "?"))
        if r.get("stage") not in STAGES:
            out.append(_f("WARN", "unknown-stage", ref,
                          "stage %r not one of %s"
                          % (r.get("stage"), "/".join(STAGES))))
        by_ref.setdefault(ref, []).append(
            (parse_ts(r.get("ts")), r.get("stage"), r.get("amount")))
    for ref, evs in by_ref.items():
        names = [st for _, st, _ in evs]
        if "cleared" in names and "submitted" not in names:
            out.append(_f("BLOCK", "stage-skip", ref,
                          "cleared without any submitted record"))
        counts = {}
        for _, st, _ in evs:
            counts[st] = counts.get(st, 0) + 1
        for st, n in counts.items():
            if n > 1:
                out.append(_f("WARN", "duplicate-stage", ref,
                              "stage %s recorded %d times for one ref" % (st, n)))
        prev = None
        for ts, st, _ in evs:
            if ts is not None and prev is not None and ts < prev:
                out.append(_f("WARN", "ts-out-of-order", ref,
                              "stage %s at %d goes backwards" % (st, int(ts))))
            if ts is not None:
                prev = ts
        amts = sorted({a for _, _, a in evs if _num(a)})
        if len(amts) > 1:
            out.append(_f("WARN", "amount-mismatch", ref,
                          "stage amounts differ across one ref: %s" % amts))
    return out

def eta_findings(records):
    """Clearance dwell vs eta_min, unbacked retries, stalled processing."""
    stage, _, _ = split_records(records)
    out = []
    horizon, max_eta = None, None
    for r in stage:
        ts = parse_ts(r.get("ts"))
        if ts is not None and (horizon is None or ts > horizon):
            horizon = ts
        if _num(r.get("eta_min")):
            sec = float(r["eta_min"]) * 60.0
            if max_eta is None or sec > max_eta:
                max_eta = sec
    stall_limit = max_eta if max_eta is not None else 86400.0  # 1440 min
    by_ref = {}
    for r in stage:
        by_ref.setdefault(str(r.get("ref", "?")), []).append(r)
    for ref, evs in by_ref.items():
        marked = [(parse_ts(e.get("ts")), e) for e in evs]
        subs = [(t, e) for t, e in marked if e.get("stage") == "submitted"]
        clrs = [(t, e) for t, e in marked if e.get("stage") == "cleared"]
        for _, e in subs:
            if not _num(e.get("eta_min")):
                out.append(_f("WARN", "eta-missing", ref,
                              "submitted record carries no numeric eta_min"))
                break
        st_ts = [t for t, _ in subs if t is not None]
        cl_ts = [t for t, _ in clrs if t is not None]
        if st_ts and cl_ts:
            dwell = max(cl_ts) - min(st_ts)
            etas = [float(e["eta_min"]) for _, e in subs if _num(e.get("eta_min"))]
            if etas and dwell > min(etas) * 60.0:
                out.append(_f("WARN", "eta-overrun", ref,
                              "clearance dwell %ds exceeds tightest eta_min %ds"
                              % (int(dwell), int(min(etas) * 60.0))))
        for tf, fe in marked:
            if fe.get("stage") != "failed" or tf is None:
                continue
            if (any(e.get("stage") == "cleared" and t is not None and t > tf
                    for t, e in marked)
                    and not any(e.get("stage") == "submitted" and t is not None
                                and t > tf for t, e in marked)):
                out.append(_f("BLOCK", "unbacked-retry", ref,
                              "cleared after failed with no retry submission"))
                break
        last = None
        for t, e in marked:
            if t is not None and (last is None or t > last[0]):
                last = (t, e)
        if (horizon is not None and last is not None
                and last[1].get("stage") == "processing"
                and not any(e.get("stage") in TERMINAL for _, e in marked)
                and horizon - last[0] > stall_limit):
            out.append(_f("WARN", "stalled-processing", ref,
                          "processing for %ds with no terminal stage (limit %ds)"
                          % (int(horizon - last[0]), int(stall_limit))))
    return out

def slot_findings(records):
    """Same rail+slot held by two refs with overlapping time windows."""
    stage, _, _ = split_records(records)
    out = []
    occ = {}
    for r in stage:
        rail, slot = r.get("rail"), r.get("slot")
        ts = parse_ts(r.get("ts"))
        if rail in (None, "") or slot in (None, "") or ts is None:
            continue
        key = (str(rail), str(slot))
        ref = str(r.get("ref", "?"))
        w = occ.setdefault(key, {})
        lo, hi = w.get(ref, (ts, ts))
        w[ref] = (min(lo, ts), max(hi, ts))
    for (rail, slot), refs in occ.items():
        ids = sorted(refs)
        for i in range(len(ids)):
            for j in range(i + 1, len(ids)):
                a, b = refs[ids[i]], refs[ids[j]]
                if a[0] < b[1] and b[0] < a[1]:
                    out.append(_f("BLOCK", "slot-double-book",
                                  "%s slot=%s" % (rail, slot),
                                  "refs %s [%d,%d] and %s [%d,%d] overlap"
                                  % (ids[i], a[0], a[1], ids[j], b[0], b[1])))
    return out

def reserve_findings(records):
    """Cleared settlement volume vs latest proof-of-reserve attestation."""
    stage, attest, _ = split_records(records)
    out = []
    cleared = {}
    for r in stage:
        if r.get("stage") != "cleared" or not _num(r.get("amount")):
            continue
        key = (str(r.get("asset", "?")), str(r.get("rail", "?")))
        cleared[key] = cleared.get(key, 0.0) + float(r["amount"])
    latest = {}
    for r in attest:
        ts = parse_ts(r.get("ts"))
        if ts is None:
            ts = 0.0
        key = (str(r.get("asset", "?")), str(r.get("rail", "?")))
        if key not in latest or ts >= latest[key][0]:
            latest[key] = (ts, r)
    for key in sorted(cleared):
        asset, rail = key
        vol = cleared[key]
        origin = "%s/%s" % (asset, rail)
        if key not in latest:
            out.append(_f("WARN", "no-attestation", origin,
                          "%.6g %s cleared on %s with no reserve_attestation"
                          % (vol, asset, rail)))
            continue
        back = latest[key][1].get("backing_amount")
        if _num(back) and vol > float(back):
            out.append(_f("BLOCK", "over-settlement", origin,
                          "cleared %.6g exceeds backing %.6g" % (vol, float(back))))
    return out

def audit(path):
    """Load the trail and run every check; returns the findings list."""
    records, bad = load_jsonl(path)
    findings = [_f("WARN", "bad-line", "line:%d" % n,
                   "unparseable or non-object JSONL line") for n in bad]
    _, _, other = split_records(records)
    for r in other:
        findings.append(_f("WARN", "unknown-record",
                           str(r.get("ref") or r.get("rail") or "?"),
                           "neither a stage event nor a reserve_attestation"))
    return (findings + stage_findings(records) + eta_findings(records)
            + slot_findings(records) + reserve_findings(records))

def render(findings):
    """Print one human line per finding; return severity counts."""
    counts = {s: 0 for s in SEVS}
    for f in findings:
        counts[f["severity"]] = counts.get(f["severity"], 0) + 1
        print("%-5s %-18s %s: %s"
              % (f["severity"], f["kind"], f["origin"], f["detail"]))
    return counts

def main(argv=None):
    """CLI: path to captured JSONL trail, optional --json. Returns 0/1/2."""
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("path", help="captured settlement JSONL file")
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
        {"ts": "2026-03-01T00:00:00Z", "rail": "R1", "ref": "S-1", "stage": "submitted", "amount": 10.0, "asset": "USDC", "eta_min": 60, "slot": "a1"},
        {"ts": "2026-03-01T00:30:00Z", "rail": "R1", "ref": "S-1", "stage": "cleared", "amount": 10.0, "asset": "USDC", "slot": "a1"},
        {"ts": "2026-03-01T00:05:00Z", "rail": "R1", "ref": "S-2", "stage": "submitted", "amount": 5.0, "asset": "USDC", "eta_min": 120, "slot": "a2"},
        {"ts": "2026-03-01T00:20:00Z", "rail": "R1", "ref": "S-2", "stage": "cleared", "amount": 5.0, "asset": "USDC", "slot": "a2"},
        {"event": "reserve_attestation", "ts": "2026-03-01T00:00:00Z", "rail": "R1", "asset": "USDC", "backing_amount": 100.0},
    ]
    messy = [
        # B-1: out-of-order ts plus amount drift across stages
        {"ts": "2026-03-01T00:00:00Z", "rail": "R1", "ref": "B-1", "stage": "submitted", "amount": 3.0, "asset": "USDC", "eta_min": 60},
        {"ts": "2026-03-01T00:05:00Z", "rail": "R1", "ref": "B-1", "stage": "processing", "amount": 3.0, "asset": "USDC"},
        {"ts": "2026-03-01T00:04:00Z", "rail": "R1", "ref": "B-1", "stage": "cleared", "amount": 4.0, "asset": "USDC"},
        # B-2: cleared with no submitted, unknown stage, duplicate cleared
        {"ts": "2026-03-01T00:06:00Z", "rail": "R1", "ref": "B-2", "stage": "cleared", "amount": 2.0, "asset": "USDC"},
        {"ts": "2026-03-01T00:07:00Z", "rail": "R1", "ref": "B-2", "stage": "held", "amount": 2.0, "asset": "USDC"},
        {"ts": "2026-03-01T00:08:00Z", "rail": "R1", "ref": "B-2", "stage": "cleared", "amount": 2.0, "asset": "USDC"},
        # B-3 stalled processing (B-9 pushes the horizon); B-4 no eta_min
        {"ts": "2026-03-01T00:08:00Z", "rail": "R1", "ref": "B-3", "stage": "processing", "amount": 1.0, "asset": "USDC", "eta_min": 30},
        {"ts": "2026-03-01T00:10:00Z", "rail": "R1", "ref": "B-4", "stage": "submitted", "amount": 7.0, "asset": "USDC"},
        # B-5 dwell 30 min vs promised 10; B-6 failed->cleared, never resubmitted
        {"ts": "2026-03-01T00:00:00Z", "rail": "R1", "ref": "B-5", "stage": "submitted", "amount": 6.0, "asset": "USDC", "eta_min": 10},
        {"ts": "2026-03-01T00:30:00Z", "rail": "R1", "ref": "B-5", "stage": "cleared", "amount": 6.0, "asset": "USDC"},
        {"ts": "2026-03-01T00:00:00Z", "rail": "R1", "ref": "B-6", "stage": "submitted", "amount": 8.0, "asset": "USDC", "eta_min": 60},
        {"ts": "2026-03-01T00:05:00Z", "rail": "R1", "ref": "B-6", "stage": "failed", "amount": 8.0, "asset": "USDC"},
        {"ts": "2026-03-01T00:09:00Z", "rail": "R1", "ref": "B-6", "stage": "cleared", "amount": 8.0, "asset": "USDC"},
        # X-1/Y-1 double-book rail R2 slot s9; Z-1/W-1 disjoint on s8
        {"ts": "2026-03-01T01:00:00Z", "rail": "R2", "ref": "X-1", "stage": "submitted", "amount": 1.0, "asset": "USDC", "eta_min": 60, "slot": "s9"},
        {"ts": "2026-03-01T02:00:00Z", "rail": "R2", "ref": "X-1", "stage": "cleared", "amount": 1.0, "asset": "USDC", "slot": "s9"},
        {"ts": "2026-03-01T01:30:00Z", "rail": "R2", "ref": "Y-1", "stage": "submitted", "amount": 1.0, "asset": "USDC", "eta_min": 60, "slot": "s9"},
        {"ts": "2026-03-01T03:00:00Z", "rail": "R2", "ref": "Y-1", "stage": "cleared", "amount": 1.0, "asset": "USDC", "slot": "s9"},
        {"ts": "2026-03-01T04:00:00Z", "rail": "R2", "ref": "Z-1", "stage": "submitted", "amount": 1.0, "asset": "USDC", "eta_min": 60, "slot": "s8"},
        {"ts": "2026-03-01T05:00:00Z", "rail": "R2", "ref": "Z-1", "stage": "cleared", "amount": 1.0, "asset": "USDC", "slot": "s8"},
        {"ts": "2026-03-01T05:30:00Z", "rail": "R2", "ref": "W-1", "stage": "submitted", "amount": 1.0, "asset": "USDC", "eta_min": 60, "slot": "s8"},
        {"ts": "2026-03-01T06:00:00Z", "rail": "R2", "ref": "W-1", "stage": "cleared", "amount": 1.0, "asset": "USDC", "slot": "s8"},
        # B-9 advances the horizon; EURC cleared with no attestation anywhere
        {"ts": "2026-03-01T12:00:00Z", "rail": "R3", "ref": "B-9", "stage": "submitted", "amount": 2.0, "asset": "EURC", "eta_min": 60},
        {"ts": "2026-03-01T12:30:00Z", "rail": "R3", "ref": "B-9", "stage": "cleared", "amount": 2.0, "asset": "EURC"},
        {"event": "reserve_attestation", "ts": "2026-03-01T00:00:00Z", "rail": "R1", "asset": "USDC", "backing_amount": 1.0},
    ]
    p_clean = _write(clean)
    p_messy = _write(messy)
    try:
        assert parse_ts("2026-03-01T00:10:00Z") - parse_ts("2026-03-01T00:00:00Z") == 600.0
        assert parse_ts(None) is None and parse_ts(60) == 60.0
        st, at, ot = split_records(messy)
        assert len(st) + len(at) + len(ot) == len(messy) and len(at) == 1 and not ot
        assert [x for x in stage_findings(messy) if x["kind"] == "stage-skip"][0]["severity"] == "BLOCK"
        assert any(x["kind"] == "unknown-stage" for x in stage_findings(messy))
        assert any(x["kind"] == "ts-out-of-order" for x in stage_findings(messy))
        assert any(x["kind"] == "duplicate-stage" for x in stage_findings(messy))
        assert any(x["kind"] == "amount-mismatch" for x in stage_findings(messy))
        assert any(x["kind"] == "eta-missing" and x["origin"] == "B-4" for x in eta_findings(messy))
        assert any(x["kind"] == "eta-overrun" and x["origin"] == "B-5" for x in eta_findings(messy))
        assert any(x["kind"] == "unbacked-retry" and x["severity"] == "BLOCK" for x in eta_findings(messy))
        assert any(x["kind"] == "stalled-processing" and x["origin"] == "B-3" for x in eta_findings(messy))
        slots = slot_findings(messy)
        assert len(slots) == 1 and slots[0]["kind"] == "slot-double-book" \
            and slots[0]["severity"] == "BLOCK" and "s9" in slots[0]["origin"]
        assert any(x["kind"] == "over-settlement" and x["severity"] == "BLOCK" for x in reserve_findings(messy))
        assert any(x["kind"] == "no-attestation" and x["origin"] == "EURC/R3" for x in reserve_findings(messy))
        assert audit(p_clean) == []
        with redirect_stdout(io.StringIO()):
            rc0 = main([p_clean])
            rc1 = main([p_messy])
            rc2 = main(["/no/such/settlement-fixture.jsonl"])
            zero = render([])
        assert rc0 == 0 and rc1 == 1 and rc2 == 2, (rc0, rc1, rc2)
        assert zero == {"BLOCK": 0, "WARN": 0, "INFO": 0}, zero
    finally:
        os.unlink(p_clean)
        os.unlink(p_messy)
    print("settlement-rail-audit self-test OK (parse/split, stage skip/unknown/"
          "order/dup/amount, eta missing/overrun, unbacked retry, stall, slot "
          "clash, reserve over/missing, render, rc 0/1/2)")


if __name__ == "__main__":
    if "--self-test" in sys.argv:
        self_test()  # falls through; rc 0 (probe hook runs after this)
    else:
        raise SystemExit(main())
