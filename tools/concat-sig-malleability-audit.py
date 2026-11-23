#!/usr/bin/env python3
"""concat-sig-malleability-audit — offline audit of signatures taken over
concatenated payload fields, detecting malleability: envelopes where the
signed bytes verify for more than one field reading.

DEMAND: evidence/suggestions/tools-services/2026-09-08.md (09:35 run)
  - request: "Continuous background data-integrity verification for
    concatenated-payload signatures without locking" — evidence:
    "Auditing data integrity across a signature over a concatenated
    payload without locking production tables" (11:10) — proposed
    service: "Concat-signature canonicalisation audit to detect
    malleability." This tool is the offline auditor half: it never sees
    the network or the signer; operators feed it captured signing
    envelopes and get the finding rows. Siblings sig-surface-audit
    (crypto coverage), sig-claim-audit (claim vs artifact) and
    transcript-notary (digest trails) do not check framing ambiguity.

Input: one JSONL file, one signing envelope per line:
  {"id": str, "sep": str, "fields": [str, ...], "sig": str,
   "framing": "raw"|"len-prefix"|"tlv" (default "raw"),
   "domain": str|null (domain-separation tag, default null)}

Findings (rule hits, deterministic):
  sep-in-field         BLOCK  a field value contains the separator, so
                             re-splitting the signed bytes on the
                             separator yields a tuple the signature
                             still verifies for (misbinding)
  concat-collision     BLOCK  two envelopes sign byte-identical
                             concatenated payloads built from different
                             field tuples (reframe: one signature, many
                             readings)
  sig-reuse            BLOCK  identical signature string over different
                             payloads (malleability / envelope reuse)
  empty-field          WARN   a field is empty; adjacent separators are
                             ambiguous with an omitted field
  cross-context        WARN   byte-identical payload appears under
                             different context labels with no domain
                             tag to separate them (replay across uses)
  no-canonical-framing WARN   raw concatenation of >=2 fields with no
                             length prefix or TLV framing: any future
                             value containing the separator silently
                             rebinds the signature
Bookkeeping: malformed-line WARN, bad-record WARN (fields not a list of
strings, empty/non-string sep or sig).
Verdict: rc 0 no findings, 1 findings found, 2 usage/IO. Envelope data is
data only: string math and dictionaries, no network, no subprocess;
nothing in the input ever runs. Stdlib only.

VERIFY: `concat-sig-malleability-audit.py --self-test` runs assertion
groups over every detector (unit) plus an end-to-end CLI pass on a
synthetic envelope capture (rc 0/1/2, collision pairs, determinism).
"""
import argparse
import contextlib
import io
import json
import sys
import tempfile
import os

BLOCK, WARN = "BLOCK", "WARN"


def valid(rec):
    """True when a parsed record has the required envelope shape."""
    if not isinstance(rec, dict):
        return False
    fields = rec.get("fields")
    (sep, sig) = (rec.get("sep"), rec.get("sig"))
    return (isinstance(fields, list)
            and all(isinstance(f, str) for f in fields)
            and isinstance(sep, str) and sep != ""
            and isinstance(sig, str) and sig != "")


def joined(sep, fields):
    """The bytes a raw-concat scheme signs for this tuple."""
    return sep.join(fields)


def field_has_sep(sep, fields):
    """Indices of fields that embed the separator itself."""
    return [i for i, f in enumerate(fields) if sep in f]


def framing_of(rec):
    """Canonical-framing mode claimed by the envelope."""
    return rec.get("framing") or "raw"


def audit(records):
    """Return (findings, board) for parsed envelope records.

    findings: list of (severity, rule, ids, detail) tuples, stable order.
    board: counts per rule for the report footer.
    """
    findings = []
    seen = {}       # (sep, joined payload) -> list of (id, tuple(fields))
    sigmap = {}     # sig -> first (id, payload) that used it
    payload_ctx = {}  # (sep, joined payload) -> {context: first id}
    bad = 0

    for rec in records:
        if not valid(rec):
            bad += 1
            findings.append((WARN, "bad-record",
                             [str(rec.get("id", "?"))],
                             "envelope lacks fields/sep/sig shape"))
            continue
        (rid, sep, fields) = (rec.get("id", "?"), rec["sep"], rec["fields"])
        payload = joined(sep, fields)

        hits = field_has_sep(sep, fields)
        if hits:
            findings.append((BLOCK, "sep-in-field", [rid],
                             "fields %s contain separator %r; resplitting "
                             "the signed bytes yields a different tuple"
                             % (hits, sep)))

        group = seen.setdefault((sep, payload), [])
        if any(tuple(fields) != prev for _, prev in group):
            findings.append((BLOCK, "concat-collision",
                             [rid] + [pid for pid, _ in group],
                             "payload %r signed under different field "
                             "tuples" % payload))
        group.append((rid, tuple(fields)))

        if "" in fields:
            findings.append((WARN, "empty-field", [rid],
                             "empty field at index %d; ambiguous with an "
                             "omitted field" % fields.index("")))

        prev = sigmap.get(rec["sig"])
        if prev is not None and prev[1] != payload:
            findings.append((BLOCK, "sig-reuse", [prev[0], rid],
                             "signature %r also covers payload %r"
                             % (rec["sig"], prev[1])))
        else:
            sigmap.setdefault(rec["sig"], (rid, payload))

        ctx = rec.get("context")
        if ctx is not None:
            ctxs = payload_ctx.setdefault((sep, payload), {})
            other = next((c for c in ctxs if c != ctx), None)
            if other is not None and not rec.get("domain"):
                findings.append((WARN, "cross-context",
                                 [ctxs[other], rid],
                                 "payload %r used as %r and %r with no "
                                 "domain tag" % (payload, other, ctx)))
            ctxs.setdefault(ctx, rid)

        if (framing_of(rec) == "raw" and len(fields) >= 2):
            findings.append((WARN, "no-canonical-framing", [rid],
                             "raw concat of %d fields with no length "
                             "prefix/TLV: a value containing the "
                             "separator rebinds the signature"
                             % len(fields)))

    if bad:
        pass  # bad-record rows already carry the count via repetition
    board = {}
    for sev, rule, _, _ in findings:
        board[rule] = board.get(rule, 0) + 1
    return findings, board


def verdict(findings):
    """rc from findings: 0 clean, 1 findings, per the header contract."""
    return 1 if findings else 0


def report(findings, board):
    """Human-readable rows, one per finding, plus a footer."""
    lines = []
    for sev, rule, ids, detail in findings:
        lines.append("%s\t%s\t%s\t%s" % (sev, rule, ",".join(ids), detail))
    if board:
        lines.append("-- %d finding(s): %s" % (
            len(findings),
            ", ".join("%s=%d" % kv for kv in sorted(board.items()))))
    else:
        lines.append("-- clean: no malleability findings")
    return "\n".join(lines)


def read_records(path):
    """Parse JSONL; malformed lines become placeholder records."""
    records = []
    with open(path, "r", encoding="utf-8", errors="replace") as fh:
        for lineno, line in enumerate(fh, 1):
            line = line.strip()
            if not line:
                continue
            try:
                records.append((lineno, json.loads(line)))
            except ValueError:
                records.append((lineno, {"id": "line-%d" % lineno,
                                         "__malformed__": True}))
    return records


def main(argv=None):
    ap = argparse.ArgumentParser(
        description="Audit concat-payload signatures for malleability.")
    ap.add_argument("capture", help="JSONL signing-envelope capture")
    ap.add_argument("--json", action="store_true",
                    help="emit findings as JSON lines")
    args = ap.parse_args(argv)
    try:
        raw = read_records(args.capture)
    except OSError as exc:
        print("cannot read capture: %s" % exc, file=sys.stderr)
        return 2
    findings = []
    for _, rec in raw:
        if isinstance(rec, dict) and rec.get("__malformed__"):
            findings.append((WARN, "malformed-line",
                             [str(rec["id"])], "not valid JSON"))
    recs = [rec for _, rec in raw if not (isinstance(rec, dict)
                                          and rec.get("__malformed__"))]
    audit_findings, board = audit(recs)
    findings.extend(audit_findings)
    for _, rec in raw:
        if isinstance(rec, dict) and rec.get("__malformed__"):
            board["malformed-line"] = board.get("malformed-line", 0) + 1
    if args.json:
        for sev, rule, ids, detail in findings:
            print(json.dumps({"severity": sev, "rule": rule,
                              "ids": ids, "detail": detail}))
    else:
        print(report(findings, board))
    return verdict(findings)


def self_test():
    """Assertion groups over every detector plus an end-to-end CLI pass."""
    # sep-in-field: separator embedded in a signed field is a misbinding
    assert field_has_sep("|", ["al|ice", "100"]) == [0]
    assert field_has_sep("|", ["alice", "100"]) == []
    # joined bytes: what the signature actually covers
    assert joined("|", ["x", "y|z"]) == joined("|", ["x|y", "z"]) == "x|y|z"

    # concat-collision: one payload, two readings, signature covers both
    recs = [{"id": "e1", "sep": "|", "fields": ["x", "y|z"], "sig": "s1"},
            {"id": "e2", "sep": "|", "fields": ["x|y", "z"], "sig": "s2"}]
    rules = {r for _, r, _, _ in audit(recs)[0]}
    assert "concat-collision" in rules, rules
    # the same tuple twice is a duplicate envelope, not a collision
    dup = [dict(recs[0], id="e3")]
    crules = {r for _, r, _, _ in audit(recs + dup)[0]}
    assert "concat-collision" in crules
    uniq = {r for _, r, _, _ in audit([recs[0],
                                       dict(recs[0], sig="s9")])[0]}
    assert "concat-collision" not in uniq, uniq

    # sep-in-field fires per envelope and names the field index
    sfind = [f for f in audit(recs[:1])[0] if f[1] == "sep-in-field"]
    assert sfind and "[1]" in sfind[0][3], sfind

    # sig-reuse: one signature string over different payloads
    reuse = [{"id": "r1", "sep": "|", "fields": ["a", "b"], "sig": "k"},
             {"id": "r2", "sep": "|", "fields": ["c", "d"], "sig": "k"}]
    rules = {r for _, r, _, _ in audit(reuse)[0]}
    assert "sig-reuse" in rules, rules
    # same sig over the identical payload is normal resubmission, clean
    rfind = [f for f in audit([reuse[0], dict(reuse[1],
                                              fields=["a", "b"])])[0]
             if f[1] == "sig-reuse"]
    assert rfind == [], rfind

    # empty-field ambiguity
    emp = [{"id": "q1", "sep": ",", "fields": ["a", "", "c"], "sig": "z"}]
    rules = {r for _, r, _, _ in audit(emp)[0]}
    assert "empty-field" in rules, rules

    # cross-context replay without a domain tag
    xc = [{"id": "c1", "sep": "|", "fields": ["pay", "1"], "sig": "s",
           "context": "payment"},
          {"id": "c2", "sep": "|", "fields": ["pay", "1"], "sig": "t",
           "context": "audit"}]
    rules = {r for _, r, _, _ in audit(xc)[0]}
    assert "cross-context" in rules, rules
    dom = [dict(xc[1], domain="flop/pay/v1")]
    rules = {r for _, r, _, _ in audit(xc[:1] + dom)[0]}
    assert "cross-context" not in rules, rules

    # no-canonical-framing only for raw concat of >=2 fields
    raw2 = [{"id": "f1", "sep": "|", "fields": ["a", "b"], "sig": "s",
             "framing": "raw"}]
    lp = [dict(raw2[0], framing="len-prefix")]
    one = [dict(raw2[0], fields=["solo"])]
    assert "no-canonical-framing" in {r for _, r, _, _ in
                                      audit(raw2)[0]}
    assert "no-canonical-framing" not in {r for _, r, _, _ in
                                          audit(lp + one)[0]}

    # verdict + report wiring
    assert verdict([]) == 0 and verdict([(WARN, "x", ["i"], "d")]) == 1
    txt = report([], {})
    assert "clean" in txt

    # bad-record shape guard
    bad = audit([{"id": "b1", "sep": "", "fields": ["a"], "sig": "s"}])[0]
    assert bad and bad[0][1] == "bad-record", bad

    # end-to-end CLI on a synthetic capture: rc 0 clean, 1 findings, 2 IO
    def write_tmp(lines):
        path = tempfile.mktemp(suffix=".jsonl")
        with open(path, "w", encoding="utf-8") as fh:
            fh.write("\n".join(lines) + "\n")
        return path

    clean = write_tmp(['{"id":"n1","sep":".","fields":["a","b"],'
                       '"sig":"s1","framing":"len-prefix","domain":"d"}'])
    dirty = write_tmp(['{"id":"m1","sep":"|","fields":["x","y|z"],'
                       '"sig":"s1"}',
                       'not json at all'])
    quiet = io.StringIO()
    with contextlib.redirect_stdout(quiet):
        rc_clean = main([clean])
        rc_dirty = main([dirty])
    assert rc_clean == 0, rc_clean
    assert rc_dirty == 1, rc_dirty
    assert main([dirty + ".missing"]) == 2
    # determinism: identical input, identical findings twice
    recs_dirty = [r for _, r in read_records(dirty)
                  if not (isinstance(r, dict) and r.get("__malformed__"))]
    assert audit(recs_dirty)[0] == audit(recs_dirty)[0]
    for p in (clean, dirty):
        os.unlink(p)
    print("concat-sig-malleability-audit self-test OK")


if __name__ == "__main__":
    if "--self-test" in sys.argv:
        self_test()
    else:
        sys.exit(main())
