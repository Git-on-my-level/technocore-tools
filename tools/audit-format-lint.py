#!/usr/bin/env python3
"""audit-format-lint — lint captured audit-tool output JSONL against the
shared format contract so audit tools stay interoperable.

DEMAND: evidence/suggestions/tools-services/ (file citations below)
  - "Feature request: standardize audit output format for tool interoperability"
  - "Expose audit data (signature validity, format errors) per room in a structured, queryable way."
  - "Clarification that rendered chat is not the audit log, and JSONL bytes are the authoritative record"
  - "Historical audit log export"
  - "aggregate/summary view of audit results"
  Scope: historical audit-log exports — JSONL records {"tool","ts",
    "severity","kind","detail","room","seq","record_id","rendered":bool}
    emitted by any audit tool — checked against the interop contract:
    required keys and room scoping, ISO-8601 timestamps carrying a
    timezone, the severity vocabulary, per-(tool,room) seq presence and
    monotonicity, duplicate record ids, and rendered-view authority (the
    JSONL bytes are the authoritative record; rendered chat is a view).
    Records are data only: plain JSON parsing, no network, no subprocess,
    nothing is executed. rc 0 clean, 1 findings, 2 usage/IO. Stdlib only.
"""
import argparse
import json
import sys
from datetime import datetime

REQUIRED = ("tool", "ts", "severity", "kind", "detail")
SEVERITIES = ("INFO", "WARN", "BLOCK")


def load_jsonl(path):
    """Read a JSONL export -> (records, bad_line_numbers)."""
    records, bad = [], []
    with open(path, "r", encoding="utf-8", errors="replace") as fh:
        for n, line in enumerate(fh, 1):
            line = line.strip()
            if not line:
                continue
            try:
                rec = json.loads(line)
            except ValueError:
                bad.append(n)
                continue
            if isinstance(rec, dict):
                records.append(rec)
            else:
                bad.append(n)
    return records, bad


def _origin(rec, i):
    """Stable origin for a finding: record_id when present, else position."""
    rid = rec.get("record_id")
    return rid if isinstance(rid, str) and rid else "rec:%d" % i


def _f(sev, kind, origin, detail):
    """One finding in the shared family shape."""
    return {"severity": sev, "kind": kind, "origin": origin, "detail": detail}


def room_scoped(tool):
    """True when a tool name marks its records as room-scoped."""
    return isinstance(tool, str) and bool(tool) and \
        (tool.endswith("-audit") or "room" in tool)


def parse_iso_tz(v):
    """ISO-8601 string with a mandatory timezone -> datetime, else None."""
    if not isinstance(v, str) or not v.strip():
        return None
    s = v.strip()
    if s[-1] in "Zz":
        s = s[:-1] + "+00:00"
    try:
        dt = datetime.fromisoformat(s)
    except ValueError:
        return None
    return dt if dt.tzinfo is not None else None


def schema_findings(records):
    """Required keys tool/ts/severity/kind/detail must be present and
    non-empty; room-scoped tools must stamp a room on every record."""
    out = []
    for i, rec in enumerate(records):
        origin = _origin(rec, i)
        for key in REQUIRED:
            v = rec.get(key)
            if v is None or (isinstance(v, str) and not v.strip()):
                out.append(_f("BLOCK", "missing-" + key, origin,
                              "record lacks a usable %r field" % key))
        if room_scoped(rec.get("tool")) and not rec.get("room"):
            out.append(_f("WARN", "room-missing", origin,
                          "tool %r is room-scoped but the record carries no "
                          "room" % rec.get("tool")))
    return out


def ts_findings(records):
    """ts must parse as ISO-8601 AND carry an explicit timezone offset —
    naive timestamps are ambiguous across rooms and tools."""
    out = []
    for i, rec in enumerate(records):
        if parse_iso_tz(rec.get("ts")) is None:
            out.append(_f("BLOCK", "bad-ts", _origin(rec, i),
                          "ts %r is not ISO-8601 with timezone"
                          % (rec.get("ts"),)))
    return out


def vocab_findings(records):
    """severity must come from the INFO/WARN/BLOCK vocabulary; kind must
    not be blank."""
    out = []
    for i, rec in enumerate(records):
        origin = _origin(rec, i)
        sev = rec.get("severity")
        if sev is not None and sev not in SEVERITIES:
            out.append(_f("BLOCK", "bad-severity", origin,
                          "severity %r not in %s" % (sev, "/".join(SEVERITIES))))
        kind = rec.get("kind")
        if isinstance(kind, str) and not kind.strip():
            out.append(_f("WARN", "empty-kind", origin,
                          "kind is blank — not queryable"))
    return out


def seq_findings(records):
    """Per (tool,room) the seq field must be present and strictly
    increasing: a jump > 1 warns (lost records), going backwards blocks."""
    out = []
    last = {}                          # (tool, room) -> last seq seen
    for i, rec in enumerate(records):
        origin = _origin(rec, i)
        seq = rec.get("seq")
        if seq is None:
            out.append(_f("WARN", "seq-missing", origin,
                          "record carries no seq for (tool,room) ordering"))
            continue
        if not isinstance(seq, int) or isinstance(seq, bool):
            out.append(_f("WARN", "seq-not-integer", origin,
                          "seq %r is not an integer" % (seq,)))
            continue
        key = (rec.get("tool"), rec.get("room"))
        prev = last.get(key)
        if prev is not None:
            if seq < prev:
                out.append(_f("BLOCK", "seq-backwards", origin,
                              "seq %d goes backwards after %d in %r"
                              % (seq, prev, key)))
            elif seq > prev + 1:
                out.append(_f("WARN", "seq-gap", origin,
                              "seq jumps %d -> %d in %r (lost records?)"
                              % (prev, seq, key)))
        last[key] = seq
    return out


def dup_findings(records):
    """A record_id must identify one record across the whole export."""
    out = []
    seen = set()
    for i, rec in enumerate(records):
        rid = rec.get("record_id")
        if not isinstance(rid, str) or not rid:
            continue
        if rid in seen:
            out.append(_f("BLOCK", "duplicate-record-id", rid,
                          "record_id appears more than once in the export"))
        seen.add(rid)
    return out


def authority_findings(records):
    """Rendered chat is not the audit log: every rendered=true row is a
    convenience view and its record_id must also exist as a rendered=false
    row; an export made only of rendered rows is rejected outright."""
    out = []
    raw_ids = {r.get("record_id") for r in records
               if r.get("rendered") is not True}
    rendered = 0
    for i, rec in enumerate(records):
        if rec.get("rendered") is True:
            rendered += 1
            if rec.get("record_id") not in raw_ids:
                out.append(_f("WARN", "rendered-only", _origin(rec, i),
                              "rendered=true row has no authoritative "
                              "rendered=false twin in the JSONL bytes"))
    if records and rendered == len(records):
        out.append(_f("BLOCK", "rendered-export", "-",
                      "every record has rendered=true — rendered chat is "
                      "not the audit log; export the JSONL bytes"))
    return out


def audit(path):
    """Load the export and concatenate every check's findings."""
    records, bad = load_jsonl(path)
    findings = []
    for n in bad:
        findings.append(_f("WARN", "malformed-line", "line:%d" % n,
                           "line is not a JSON object; record skipped"))
    for check in (schema_findings, ts_findings, vocab_findings, seq_findings,
                  dup_findings, authority_findings):
        findings.extend(check(records))
    return findings


def render(findings):
    """Print one human line per finding; return severity counts."""
    counts = {}
    for x in findings:
        sev = x.get("severity", "WARN")
        counts[sev] = counts.get(sev, 0) + 1
        print("%-5s %-20s %s: %s"
              % (sev, x["kind"], x.get("origin"), x["detail"]))
    return counts


def main(argv=None):
    """CLI: one export path; --json emits machine-readable findings."""
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("file", help="captured audit-output JSONL export")
    ap.add_argument("--json", action="store_true",
                    help="emit one JSON object with all findings")
    args = ap.parse_args(argv)
    try:
        findings = audit(args.file)
    except OSError as e:
        print("cannot read %s: %s" % (args.file, e), file=sys.stderr)
        return 2
    if args.json:
        print(json.dumps({"findings": findings}, ensure_ascii=False))
    else:
        counts = render(findings)          # aggregate/summary view
        print("%d finding(s): %s" % (
            len(findings),
            ", ".join("%s=%d" % kv for kv in sorted(counts.items())) or "clean"))
    return 1 if findings else 0


def self_test():
    import io
    import os
    import tempfile
    from contextlib import redirect_stderr, redirect_stdout

    def rec(tool="probe-verify", ts="2026-09-30T10:00:00+00:00", sev="INFO",
            kind="checked", detail="fine", room=None, seq=None, rid=None,
            rendered=False):
        r = {"tool": tool, "ts": ts, "severity": sev, "kind": kind,
             "detail": detail}
        if room is not None:
            r["room"] = room
        if seq is not None:
            r["seq"] = seq
        if rid is not None:
            r["record_id"] = rid
        if rendered is not None:
            r["rendered"] = rendered
        return r

    def kinds(f):
        return [x["kind"] for x in f]

    paths = []

    def capture(recs, raw=""):
        fh = tempfile.NamedTemporaryFile("w", suffix=".jsonl", delete=False,
                                         encoding="utf-8")
        for r in recs:
            fh.write(json.dumps(r) + "\n")
        if raw:
            fh.write(raw)
        fh.close()
        paths.append(fh.name)
        return fh.name

    try:
        # --- clean export passes every check
        clean = [rec(room="r1", seq=1, rid="a1"), rec(room="r1", seq=2, rid="a2"),
                 rec(room="r1", seq=3, rid="a3")]
        assert audit(capture(clean)) == []
        # --- schema: missing key, room scoping
        f = schema_findings([rec(detail=None)])
        assert kinds(f) == ["missing-detail"] and f[0]["severity"] == "BLOCK"
        assert kinds(schema_findings([rec(tool="room-relay")])) == ["room-missing"]
        assert schema_findings([rec(tool="room-relay", room="r9")]) == []
        assert schema_findings([rec(tool="offline-check")]) == []
        # --- ts: naive and garbage timestamps block
        assert ts_findings([rec(ts="2026-09-30T10:00:00")])[0]["kind"] == "bad-ts"
        assert kinds(ts_findings([rec(ts="yesterday")])) == ["bad-ts"]
        assert ts_findings([rec(ts="2026-09-30T10:00:00Z")]) == []
        assert ts_findings([rec(ts="2026-09-30T12:00:00+02:00")]) == []
        # --- vocab: severity vocabulary and blank kinds
        f = vocab_findings([rec(sev="FATAL")])
        assert kinds(f) == ["bad-severity"] and f[0]["severity"] == "BLOCK"
        assert kinds(vocab_findings([rec(kind="   ")])) == ["empty-kind"]
        assert vocab_findings([rec(sev="WARN", kind="gap")]) == []
        # --- seq: gap warns, backwards blocks, rooms are independent
        assert kinds(seq_findings([rec(seq=1), rec(seq=3)])) == ["seq-gap"]
        f = seq_findings([rec(seq=5), rec(seq=2)])
        assert kinds(f) == ["seq-backwards"] and f[0]["severity"] == "BLOCK"
        two_rooms = [rec(room="r1", seq=1), rec(room="r2", seq=1),
                     rec(room="r1", seq=2), rec(room="r2", seq=2)]
        assert seq_findings(two_rooms) == []
        assert kinds(seq_findings([rec(seq=None)])) == ["seq-missing"]
        # --- duplicate record ids
        f = dup_findings([rec(rid="dup"), rec(rid="dup")])
        assert kinds(f) == ["duplicate-record-id"] and f[0]["severity"] == "BLOCK"
        # --- authority: rendered-only rows, fully rendered export
        mixed = [rec(rid="m1", seq=1), rec(rid="m2", seq=2, rendered=True),
                 rec(rid="m1", seq=1, rendered=True)]
        assert kinds(authority_findings(mixed)) == ["rendered-only"]
        all_rendered = [rec(rid="z%d" % i, seq=i, rendered=True) for i in (1, 2)]
        f = authority_findings(all_rendered)
        assert "rendered-export" in kinds(f) and f[-1]["severity"] == "BLOCK"
        assert authority_findings(clean) == []
        # --- malformed line surfaces through audit
        assert kinds(audit(capture([], raw="{oops\n"))) == ["malformed-line"]
        # --- CLI rc contract: 0 clean, 1 findings, 2 unreadable path
        p_clean, p_dirty = capture(clean), capture([rec(ts="nope")])
        with redirect_stdout(io.StringIO()), redirect_stderr(io.StringIO()):
            rc = (main([p_clean]), main([p_dirty]), main(["/no/such/log.jsonl"]))
        assert rc == (0, 1, 2), rc
    finally:
        for p in paths:
            try:
                os.unlink(p)
            except OSError:
                pass
    print("self-test OK (schema/room scoping, ts timezone, severity vocab, "
          "seq gap/backwards/per-room, duplicate ids, rendered authority, "
          "malformed, CLI rc 0/1/2)")


if __name__ == "__main__":
    if "--self-test" in sys.argv:
        self_test()  # falls through; rc 0 (probe hook runs after this)
    else:
        raise SystemExit(main())
