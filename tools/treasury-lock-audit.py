#!/usr/bin/env python3
"""treasury-lock-audit — DAO treasury disbursement-lock + validator-quorum
history audit: ingest captured treasury announcement lines (JSONL records
{"ts","text"} or plain text, optionally led by an ISO timestamp) of the
form "[DAO-4AD3CD] treasury audit #9 passed · disbursement locked ·
validators=24" and build the per-DAO ledger the archive asks for, flagging
audit-number gaps/replays/conflicts, quorum drops and floors, lock states
that contradict the audit outcome, lock flapping, stale locks, malformed
DAO lines and out-of-order timestamps. Lines are data only — plain regex
parsing, no network, no subprocess, nothing is executed.

DEMAND: evidence/suggestions/tools-services/2026-09-18.md (09:51 run)
  - "Need a way to audit treasury disbursement lock status and validator
    quorum history" — evidence: "[DAO-4AD3CD] treasury audit #9 passed ·
    disbursement locked · validators=24" / "[DAO-38DB62] treasury audit
    #15 passed · disbursement locked · validators=20" / "[DAO-DA0C5A]
    treasury audit #8 passed · disbursement locked · validators=12" —
    proposed service: "hermes-tools could provide a historical ledger of
    treasury audits with quorum details and lock/expiry tracking."
Scope: this instrument is that ledger over a capture file. Announcements
carry no explicit TTL, so expiry is approximated by lock age against the
file's freshest timestamp (--stale-hours, needs timestamps; skipped when
absent). Unmet by the 21 existing tools/new entries (quorum-price-audit
is cross-exchange market-feed divergence; audit-chain seals records but
reads no treasury semantics).

VERIFY: `treasury-lock-audit.py --self-test` runs hand-computed fixtures
against every finding rule plus the CLI rc contract (0 clean / 1 findings
/ 2 usage-IO) and the --json export shape. Stdlib only.
"""
import argparse
import io
import json
import re
import sys
from datetime import datetime, timezone

DAO_RE = re.compile(
    r"\[(DAO-[0-9A-Fa-f]{6})\]\s+treasury\s+audit\s*#(\d+)\s+"
    r"(passed|failed)"
    r"(?:\s*.\s*disbursement\s+(locked|unlocked))?"
    r"(?:\s*.\s*validators\s*=\s*(\d+))?", re.I)
DAOISH_RE = re.compile(r"\[DAO-[^\]]*\]", re.I)
TS_RE = re.compile(r"^\s*(\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}"
                   r"(?:\.\d+)?(?:Z|[+-]\d{2}:?\d{2})?)\s+")
SEVS = ("BLOCK", "WARN", "INFO")
DEF = dict(floor=3, ratio=0.5, stale_h=72.0)


def parse_ts(v):
    """ISO-8601 string -> epoch float; else None."""
    if not isinstance(v, str) or not v.strip():
        return None
    t = v.strip()
    if t.endswith("Z"):
        t = t[:-1] + "+00:00"
    try:
        dt = datetime.fromisoformat(t)
    except ValueError:
        return None
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.timestamp()


def parse_ann(text):
    """One announcement text -> {dao,num,outcome,lock,validators} or None.

    lock/validators are None when the announcement omits them.
    """
    if not isinstance(text, str):
        return None
    m = DAO_RE.search(text)
    if not m:
        return None
    dao, num, outcome, lock, vals = m.groups()
    return {"dao": dao.upper(), "num": int(num), "outcome": outcome.lower(),
            "lock": lock.lower() if lock else None,
            "validators": int(vals) if vals else None}


def load_lines(path):
    """Yield (index, ts_or_None, text). JSONL objects contribute their
    own "ts"; plain lines may lead with an ISO timestamp."""
    out = []
    with open(path, errors="replace") as fh:
        for i, raw in enumerate(fh):
            line = raw.strip()
            if not line:
                continue
            ts, text = None, line
            try:
                rec = json.loads(line)
            except ValueError:
                rec = None
            if isinstance(rec, dict):
                text = rec.get("text") if isinstance(rec.get("text"), str) else ""
                ts = parse_ts(rec.get("ts"))
            else:
                m = TS_RE.match(line)
                if m:
                    ts, text = parse_ts(m.group(1)), line[m.end():]
            if text:
                out.append((i, ts, text))
    return out


def _f(sev, kind, dao, detail):
    return {"severity": sev, "kind": kind, "dao": dao, "detail": detail}


def audit_ledger(events, floor=DEF["floor"], ratio=DEF["ratio"],
                 stale_h=DEF["stale_h"], as_of=None):
    """events: [{idx,ts,dao,num,outcome,lock,validators}] (malformed lines
    pre-excluded) -> (findings, rows). Ordered per-DAO ledger walk."""
    findings = []
    for ev in events:  # accept ISO strings; compare as epoch floats
        if isinstance(ev.get("ts"), str):
            ev["ts"] = parse_ts(ev["ts"])
    ref = as_of if as_of is not None else max(
        (e["ts"] for e in events if e["ts"] is not None), default=None)
    per = {}
    for ev in events:
        per.setdefault(ev["dao"], []).append(ev)
    rows = []
    for dao in sorted(per):
        evs = per[dao]
        timed = all(e["ts"] is not None for e in evs)
        if timed:
            seq = [e["ts"] for e in evs]
            if any(b < a for a, b in zip(seq, seq[1:])):
                findings.append(_f("WARN", "ts-out-of-order", dao,
                                   "arrival order disagrees with timestamps"))
            evs = sorted(evs, key=lambda e: (e["ts"], e["idx"]))
        seen, toggles, fails, prev = {}, 0, 0, None
        for ev in evs:
            sig = (ev["num"], ev["outcome"], ev["lock"], ev["validators"])
            if ev["num"] in seen:
                if seen[ev["num"]] == sig:
                    findings.append(_f("INFO", "duplicate-announcement", dao,
                                       "audit #%d restated identically"
                                       % ev["num"]))
                else:
                    findings.append(_f("BLOCK", "audit-conflict", dao,
                                       "audit #%d announced twice with "
                                       "different outcome/lock/quorum"
                                       % ev["num"]))
            else:
                seen[ev["num"]] = sig
            if prev is not None:
                if ev["num"] > prev["num"] + 1:
                    findings.append(_f("WARN", "audit-gap", dao,
                                       "#%d -> #%d skips %d audit(s)"
                                       % (prev["num"], ev["num"],
                                          ev["num"] - prev["num"] - 1)))
                elif ev["num"] < prev["num"]:
                    findings.append(_f("BLOCK", "audit-regress", dao,
                                       "#%d follows #%d (replay/renumber)"
                                       % (ev["num"], prev["num"])))
                if (ev["num"] > prev["num"]
                        and ev["validators"] is not None
                        and prev["validators"] is not None
                        and prev["validators"] > 0
                        and ev["validators"] < prev["validators"] * ratio):
                    findings.append(_f("WARN", "quorum-drop", dao,
                                       "validators %d -> %d (< %.0f%% of prior)"
                                       % (prev["validators"], ev["validators"],
                                          ratio * 100)))
                if (ev["lock"] and prev["lock"]
                        and ev["lock"] != prev["lock"]):
                    toggles += 1
            if ev["validators"] is None or ev["lock"] is None:
                missing = []
                if ev["validators"] is None:
                    missing.append("validators")
                if ev["lock"] is None:
                    missing.append("disbursement state")
                findings.append(_f("INFO", "missing-field", dao,
                                   "audit #%d omits %s"
                                   % (ev["num"], " + ".join(missing))))
            if ev["validators"] is not None and ev["validators"] < floor:
                findings.append(_f("BLOCK", "quorum-floor", dao,
                                   "validators=%d below floor %d"
                                   % (ev["validators"], floor)))
            if ev["outcome"] == "passed" and ev["lock"] == "unlocked":
                findings.append(_f("WARN", "pass-unlocked", dao,
                                   "audit #%d passed but disbursement unlocked"
                                   % ev["num"]))
            if ev["outcome"] == "failed" and ev["lock"] == "locked":
                findings.append(_f("BLOCK", "fail-locked", dao,
                                   "audit #%d failed but disbursement locked"
                                   % ev["num"]))
            if ev["outcome"] == "failed":
                fails += 1
            prev = ev
        if toggles > fails + 1:
            findings.append(_f("WARN", "lock-flap", dao,
                               "%d lock toggle(s) vs %d failed audit(s)"
                               % (toggles, fails)))
        last = evs[-1]
        if timed and stale_h and last["lock"] == "locked" and ref is not None:
            age_h = (ref - last["ts"]) / 3600.0
            if age_h > stale_h:
                findings.append(_f("WARN", "stale-lock", dao,
                                   "locked for %.1fh (> %.0fh) since audit #%d"
                                   % (age_h, stale_h, last["num"])))
        vals = [e["validators"] for e in evs if e["validators"] is not None]
        rows.append({"dao": dao, "events": len(evs),
                     "first": min(e["num"] for e in evs),
                     "last": max(e["num"] for e in evs),
                     "passed": sum(1 for e in evs if e["outcome"] == "passed"),
                     "failed": fails,
                     "min_vals": min(vals) if vals else None,
                     "max_vals": max(vals) if vals else None,
                     "last_vals": vals[-1] if vals else None,
                     "lock": last["lock"] or "unknown",
                     "last_ts": last["ts"], "audited_nums": len(seen)})
    return findings, rows


def render(findings):
    counts = {s: sum(1 for x in findings if x["severity"] == s)
              for s in SEVS}
    print("findings: %d (BLOCK %d / WARN %d / INFO %d)"
          % (len(findings), counts["BLOCK"], counts["WARN"], counts["INFO"]))
    for x in findings:
        print("%-5s %-22s %s" % (x["severity"], x["kind"], x["dao"]))
        print("      %s" % x["detail"])


def render_report(rows):
    print("dao        events span   p/f    vals(min-max,last) lock      last_ts")
    for r in rows:
        vals = ("-" if r["min_vals"] is None else
                "%d-%d,%d" % (r["min_vals"], r["max_vals"], r["last_vals"]))
        print("%-10s %-6d #%-4d %d/%d    %-18s %-9s %s"
              % (r["dao"], r["events"], r["last"], r["passed"], r["failed"],
                 vals, r["lock"],
                 datetime.fromtimestamp(r["last_ts"], timezone.utc)
                 .strftime("%m-%dT%H:%M") if r["last_ts"] else "-"))


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("file", help="captured announcements (text/JSONL)")
    ap.add_argument("--json", action="store_true", help="JSON export")
    ap.add_argument("--min-validators", type=int, default=DEF["floor"],
                    help="quorum floor (default %(default)s)")
    ap.add_argument("--drop-ratio", type=float, default=DEF["ratio"],
                    help="quorum-drop threshold as fraction of prior (0.5)")
    ap.add_argument("--stale-hours", type=float, default=DEF["stale_h"],
                    help="locked-older-than warning; 0 disables (72)")
    ap.add_argument("--as-of", help="override now for stale math (ISO-8601)")
    args = ap.parse_args(argv)
    try:
        lines = load_lines(args.file)
    except OSError as e:
        print("cannot read %s: %s" % (args.file, e), file=sys.stderr)
        return 2
    findings, events, ignored = [], [], 0
    for idx, ts, text in lines:
        ann = parse_ann(text)
        if ann is not None:
            events.append(dict(idx=idx, ts=ts, **ann))
        elif DAOISH_RE.search(text):
            findings.append(_f("WARN", "malformed-dao-line", "-",
                               "line %d: DAO mention does not parse: %.60r"
                               % (idx, text)))
        else:
            ignored += 1
    f2, rows = audit_ledger(events, floor=args.min_validators,
                            ratio=args.drop_ratio, stale_h=args.stale_hours,
                            as_of=parse_ts(args.as_of))
    findings += f2
    if args.json:
        print(json.dumps({"daos": rows, "findings": findings,
                          "ignored_lines": ignored}, ensure_ascii=False))
    else:
        render(findings)
        print("ledger: %d DAO(s), %d announcement(s), %d ignored line(s)"
              % (len(rows), len(events), ignored))
        render_report(rows)
    return 1 if findings else 0


def self_test():
    import os
    import tempfile
    from contextlib import redirect_stdout

    # --- parse_ann: exact archive form + tolerance + rejection
    ev = parse_ann("[DAO-4AD3CD] treasury audit #9 passed · disbursement "
                   "locked · validators=24")
    assert ev == {"dao": "DAO-4AD3CD", "num": 9, "outcome": "passed",
                  "lock": "locked", "validators": 24}, ev
    loose = parse_ann("[dao-da0c5a] Treasury Audit #8 PASSED - Disbursement "
                      "Unlocked | Validators=12")
    assert loose["dao"] == "DAO-DA0C5A" and loose["lock"] == "unlocked" \
        and loose["validators"] == 12, loose
    assert parse_ann("[DAO-38DB62] treasury audit #15 failed") == \
        {"dao": "DAO-38DB62", "num": 15, "outcome": "failed",
         "lock": None, "validators": None}
    assert parse_ts("2026-09-18T09:51:00Z") == parse_ts(
        "2026-09-18T09:51:00+00:00")
    assert parse_ts("not-a-time") is None and parse_ts("") is None

    def ann(dao, num, outcome, lock, vals, ts=None, idx=0):
        return dict(idx=idx, ts=ts, dao=dao, num=num, outcome=outcome,
                    lock=lock, validators=vals)

    # --- clean contiguous ledger: no findings (24->20 is no drop at 0.5)
    evs = [ann("DAO-4AD3CD", n, "passed", "locked", v)
           for n, v in ((7, 24), (8, 20), (9, 24))]
    f, rows = audit_ledger(evs)
    assert f == [], f
    assert rows[0]["first"] == 7 and rows[0]["last"] == 9
    assert rows[0]["lock"] == "locked" and rows[0]["failed"] == 0
    # gap: #7 -> #9
    got = audit_ledger([ann("DAO-000001", 7, "passed", "locked", 24),
                        ann("DAO-000001", 9, "passed", "locked", 24)])[0]
    assert [x["kind"] for x in got] == ["audit-gap"], got
    # same-number conflict vs identical restatement
    base = [ann("DAO-000001", 9, "passed", "locked", 24)]
    got = audit_ledger(base + [ann("DAO-000001", 9, "failed", "unlocked", 12)])[0]
    assert [x["kind"] for x in got] == ["audit-conflict"] and \
        got[0]["severity"] == "BLOCK", got
    got = audit_ledger(base + base)[0]
    assert [x["kind"] for x in got] == ["duplicate-announcement"] and \
        got[0]["severity"] == "INFO", got
    # regress: #9 then #7 (different content)
    got = audit_ledger([ann("DAO-000001", 9, "passed", "locked", 24),
                        ann("DAO-000001", 7, "passed", "locked", 24)])[0]
    assert [x["kind"] for x in got] == ["audit-regress"], got
    # quorum drop (24 -> 11 < 12) vs benign (24 -> 13)
    drop = [ann("DAO-000001", 1, "passed", "locked", 24),
            ann("DAO-000001", 2, "passed", "locked", 11)]
    assert [x["kind"] for x in audit_ledger(drop)[0]] == ["quorum-drop"]
    drop[1]["validators"] = 13
    assert audit_ledger(drop)[0] == []
    assert [x["kind"] for x in audit_ledger(drop, ratio=0.6)[0]] == \
        ["quorum-drop"]
    # floor
    got = audit_ledger([ann("DAO-000001", 1, "passed", "locked", 2)])[0]
    assert [x["kind"] for x in got] == ["quorum-floor"] and \
        got[0]["severity"] == "BLOCK", got
    # outcome/lock contradictions
    got = audit_ledger([ann("DAO-000001", 1, "passed", "unlocked", 24)])[0]
    assert [x["kind"] for x in got] == ["pass-unlocked"], got
    got = audit_ledger([ann("DAO-000001", 1, "failed", "locked", 24)])[0]
    assert [x["kind"] for x in got] == ["fail-locked"], got
    # missing fields
    got = audit_ledger([ann("DAO-000001", 1, "passed", None, None)])[0]
    assert [x["kind"] for x in got] == ["missing-field"], got
    # flap: the unjustified unlock trips pass-unlocked; the aggregate
    # toggle count (2) vs zero failures adds lock-flap on top
    flap = [ann("DAO-000001", 1, "passed", "locked", 4),
            ann("DAO-000001", 2, "passed", "unlocked", 4),
            ann("DAO-000001", 3, "passed", "locked", 4)]
    assert [x["kind"] for x in audit_ledger(flap)[0]] == ["pass-unlocked",
                                                           "lock-flap"]
    flap[1]["outcome"] = "failed"  # unlock justified: 2 toggles vs 1 fail
    assert audit_ledger(flap)[0] == []
    # ts ordering: arrival ts non-monotonic; ts-sorted order is #1..#3
    t = ["2026-09-18T09:%02d:00Z" % m for m in (51, 52, 53)]
    shuf = [ann("DAO-000001", 2, "passed", "locked", 4, ts=t[1], idx=0),
            ann("DAO-000001", 1, "passed", "locked", 4, ts=t[0], idx=1),
            ann("DAO-000001", 3, "passed", "locked", 4, ts=t[2], idx=2)]
    f, rows = audit_ledger(shuf)
    assert [x["kind"] for x in f] == ["ts-out-of-order"], f
    assert rows[0]["first"] == 1 and rows[0]["last"] == 3
    # stale lock vs fresh, --as-of controlled, 0 disables
    old = [ann("DAO-000001", 1, "passed", "locked", 4, ts=1735689600.0)]
    f, _ = audit_ledger(old, as_of=1735689600.0 + 73 * 3600)
    assert [x["kind"] for x in f] == ["stale-lock"], f
    assert audit_ledger(old, as_of=1735689600.0 + 71 * 3600)[0] == []
    assert audit_ledger(old, stale_h=0,
                        as_of=1735689600.0 + 999 * 3600)[0] == []
    # no timestamps at all -> no time findings; arrival order IS the ledger
    f, rows = audit_ledger([ann("DAO-000001", 2, "passed", "locked", 4, idx=0),
                            ann("DAO-000001", 1, "passed", "locked", 4, idx=1)])
    assert [x["kind"] for x in f] == ["audit-regress"], f
    assert rows[0]["lock"] == "locked", rows

    # --- end-to-end: files, rc contract, malformed + ignored, json shape
    ev_line = "[DAO-4AD3CD] treasury audit #9 passed · disbursement " \
              "locked · validators=24"
    body = "\n".join([
        "2026-09-18T09:50:00Z " + ev_line.replace("#9", "#8"),
        json.dumps({"ts": "2026-09-18T09:51:00Z", "text": ev_line}),
        "[DAO-4AD3CD] treasury audit #11 passed · disbursement locked",
        "[DAO-BADID] treasury audit passed locked",
        "unrelated chatter about bounties",
    ]) + "\n"
    with tempfile.NamedTemporaryFile("w", suffix=".txt", delete=False) as tf:
        tf.write(body)
        path = tf.name
    try:
        buf = io.StringIO()
        with redirect_stdout(buf):
            assert main([path]) == 1
        out = buf.getvalue()
        assert "audit-gap" in out and "1 ignored" in out, out
        assert "malformed-dao-line" in out and "DAO-4AD3CD" in out, out
        buf = io.StringIO()
        with redirect_stdout(buf):
            assert main([path, "--json"]) == 1
        doc = json.loads(buf.getvalue())
        kinds = {x["kind"] for x in doc["findings"]}
        assert kinds == {"audit-gap", "malformed-dao-line", "missing-field"}, kinds
        assert doc["ignored_lines"] == 1 and len(doc["daos"]) == 1
        assert doc["daos"][0]["last"] == 11 and doc["daos"][0]["lock"] == "locked"
        assert main(["/nonexistent.txt"]) == 2
    finally:
        os.unlink(path)
    # clean file -> rc 0
    with tempfile.NamedTemporaryFile("w", suffix=".txt", delete=False) as tf:
        tf.write(ev_line + "\n")
        path = tf.name
    try:
        buf = io.StringIO()
        with redirect_stdout(buf):
            assert main([path]) == 0
        assert "ledger: 1 DAO(s)" in buf.getvalue(), buf.getvalue()
    finally:
        os.unlink(path)
    print("treasury-lock-audit self-test OK (parse tolerance, gap/conflict/"
          "dup/regress, quorum drop+floor, lock contradictions, flap, ts "
          "ordering, stale-lock, malformed/ignored, CLI rc 0/1/2, json)")


if __name__ == "__main__":
    if "--self-test" in sys.argv:
        self_test()  # falls through; rc 0 (probe hook runs after this line)
    else:
        raise SystemExit(main())
