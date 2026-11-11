#!/usr/bin/env python3
"""proof-schema-lint — conformance checker for offline continuity-proof
schemas and the proof records that cite them: pin the accepted hash-algo
tags, the merkle-root encoding/width, and the timestamp format +
granularity once, then lint every submitted proof against it.

DEMAND: evidence/suggestions/tools-services/2026-11-10.md (both runs)
  - 05:56 "Clarify expected proof format and whether audit trail is
    standardized for offline signature proofs submitted to /r/flop_labs
    — What proof format is expected (e.g., zk-SNARK, Merkle-proof)? Is
    the audit trail standardized?" — proposed service: "room-audit
    schema/report specifying accepted proof formats and audit-trail
    standards".
  - 11:55 "Could you share the exact proof schema (e.g., merkle root,
    timestamp granularity) so nodes can verify continuity off-chain" —
    proposed service: "publish/serve audit proof schemas (merkle root
    format, timestamp granularity) for external verification".
Scope: both halves of the ask — lint the declared schema itself, then
verify submitted proof records conform (root charset/width, algo tag,
timestamp granularity magnitude, required fields).

Data only: files are parsed and checked, never interpreted or run.

Usage:
  proof-schema-lint.py lint SCHEMA.json
  proof-schema-lint.py verify SCHEMA.json PROOFS.jsonl

Schema document (JSON):
  {"version": 1,
   "hash_algos": ["sha256", "blake2b"],          # accepted algo tags
   "merkle_root": {"encoding": "hex", "width": 64},   # hex chars
   "timestamp": {"field": "ts", "format": "epoch",   # epoch|iso8601
                 "granularity": "s"},                 # s|ms|ns
   "required": ["proof_id", "algo", "merkle_root", "ts"]}

Proof records (JSONL) are checked against the schema. rc 0 = conformant,
1 = violations found, 2 = usage/IO error.
"""

import argparse
import json
import re
import sys

KNOWN_ALGOS = {"sha256", "sha3-256", "blake2b", "keccak256", "poseidon"}
GRANULARITIES = {"s": 1, "ms": 1e3, "ns": 1e9}
# plausible epoch-magnitude bands (upper bounds) per granularity
_EPOCH_NOW = 1.8e9
GRAN_BANDS = {"s": (1e8, 1e10), "ms": (1e11, 1e13), "ns": (1e15, 1e19)}
_ISO = re.compile(r"^\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}"
                  r"(\.\d+)?(Z|[+-]\d{2}:?\d{2})$")
_HEX = re.compile(r"^[0-9a-f]+$")


def load_json_lines(path):
    """Read a JSONL file; '-' means stdin. Returns (records, errors)."""
    fh = sys.stdin if path == "-" else open(path, errors="replace")
    recs, errs = [], []
    try:
        for i, line in enumerate(fh, 1):
            line = line.strip()
            if not line:
                continue
            try:
                recs.append(json.loads(line))
            except ValueError as e:
                errs.append({"line": i, "error": str(e)})
    finally:
        if fh is not sys.stdin:
            fh.close()
    return recs, errs


def load_doc(path):
    """Load one JSON document (schema file)."""
    with open(path, errors="replace") as fh:
        return json.load(fh)


def lint_schema(doc):
    """Validate a declared proof schema. Returns list of findings."""
    out = []
    if not isinstance(doc, dict):
        return ["schema: not a JSON object"]
    v = doc.get("version")
    if not isinstance(v, int) or v < 1:
        out.append("schema.version: missing or not a positive integer")
    algos = doc.get("hash_algos")
    if not isinstance(algos, list) or not algos:
        out.append("schema.hash_algos: must be a non-empty list")
    else:
        unknown = [a for a in algos if a not in KNOWN_ALGOS]
        if unknown:
            out.append("schema.hash_algos: unrecognized algo tags %s "
                       "(known: %s)" % (unknown, sorted(KNOWN_ALGOS)))
    root = doc.get("merkle_root")
    if not isinstance(root, dict):
        out.append("schema.merkle_root: must be an object")
    else:
        if root.get("encoding") != "hex":
            out.append("schema.merkle_root.encoding: only 'hex' is "
                       "standardized for off-chain roots")
        w = root.get("width")
        if w not in (32, 64, 128):
            out.append("schema.merkle_root.width: %r not in (32, 64, 128) "
                       "hex chars" % (w,))
    ts = doc.get("timestamp")
    if not isinstance(ts, dict):
        out.append("schema.timestamp: must be an object")
    else:
        if not ts.get("field"):
            out.append("schema.timestamp.field: missing")
        fmt = ts.get("format")
        if fmt not in ("epoch", "iso8601"):
            out.append("schema.timestamp.format: %r not epoch|iso8601"
                       % (fmt,))
        gran = ts.get("granularity")
        if fmt == "epoch" and gran not in GRANULARITIES:
            out.append("schema.timestamp.granularity: %r not in s|ms|ns "
                       "(required for epoch format)" % (gran,))
        if fmt == "iso8601" and gran not in (None, "s", "ms", "ns"):
            out.append("schema.timestamp.granularity: %r invalid" % (gran,))
    req = doc.get("required")
    if not isinstance(req, list) or not req:
        out.append("schema.required: must be a non-empty list of fields")
    return out


def _ts_violations(value, fmt, gran):
    """Check one timestamp value against format + granularity."""
    bad = []
    if fmt == "iso8601":
        if not isinstance(value, str) or not _ISO.match(value):
            bad.append("not iso8601 (%r)" % (value,))
        return bad
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        bad.append("epoch timestamp not numeric (%r)" % (value,))
        return bad
    lo, hi = GRAN_BANDS[gran]
    if not (lo <= value < hi):
        bad.append("epoch magnitude %g outside %s band (%g..%g) — "
                   "granularity mismatch?" % (value, gran, lo, hi))
    frac = float(value) - int(value)
    if gran == "s" and frac:
        bad.append("sub-second digits in a seconds-granularity timestamp")
    if gran in ("s", "ms") and int(value) % 10 == 0 and value > lo * 10:
        pass  # trailing zeros are legal; magnitude band decides
    return bad


def verify_proofs(schema, records, parse_errors):
    """Check each proof record against the schema. Returns findings."""
    out = []
    for e in parse_errors:
        out.append({"proof": "line %d" % e["line"],
                    "violations": ["unparsable JSON: %s" % e["error"]]})
    tsc = schema.get("timestamp", {}) if isinstance(schema, dict) else {}
    ts_field = tsc.get("field", "ts")
    fmt = tsc.get("format", "epoch")
    gran = tsc.get("granularity", "s")
    root_c = schema.get("merkle_root", {}) if isinstance(schema, dict) \
        else {}
    rwidth = root_c.get("width", 64)
    algos = set(schema.get("hash_algos", [])) if isinstance(schema, dict) \
        else set()
    want_ver = schema.get("version")
    required = schema.get("required", []) if isinstance(schema, dict) \
        else []
    for i, rec in enumerate(records, 1):
        pid = rec.get("proof_id", "line %d" % i) if isinstance(rec, dict) \
            else "line %d" % i
        if not isinstance(rec, dict):
            out.append({"proof": pid,
                        "violations": ["proof record is not an object"]})
            continue
        viol = []
        for field in required:
            if field not in rec or rec[field] in (None, ""):
                viol.append("missing required field %r" % field)
        if want_ver is not None and "version" in rec \
                and rec["version"] != want_ver:
            viol.append("version %r != schema version %r"
                        % (rec["version"], want_ver))
        algo = rec.get("algo")
        if algo is not None and algos and algo not in algos:
            viol.append("algo %r not in accepted %s"
                        % (algo, sorted(algos)))
        root = rec.get("merkle_root")
        if root is not None:
            if not isinstance(root, str) or not _HEX.match(root.lower()):
                viol.append("merkle_root not lowercase-hex (%r)" % (root,))
            elif len(root) != rwidth:
                viol.append("merkle_root width %d != schema %d"
                            % (len(root), rwidth))
        if ts_field in rec:
            for msg in _ts_violations(rec[ts_field], fmt, gran):
                viol.append("timestamp %s: %s" % (ts_field, msg))
        if viol:
            out.append({"proof": pid, "violations": viol})
    return out


def fmt_report(mode, target, findings):
    """Human-readable report."""
    lines = []
    if not findings:
        lines.append("%s %s: conformant (no violations)" % (mode, target))
    else:
        lines.append("%s %s: %d violation(s)" % (mode, target,
                                                 len(findings)))
        for f in findings:
            who = f if isinstance(f, str) else f["proof"]
            lines.append("  - %s" % who)
            if isinstance(f, dict):
                for v in f["violations"]:
                    lines.append("      %s" % v)
    return "\n".join(lines)


def build_parser():
    ap = argparse.ArgumentParser(
        prog="proof-schema-lint.py",
        description="Lint a continuity-proof schema and verify proof "
                    "records conform to it (merkle-root width/charset, "
                    "algo tag, timestamp format + granularity, required "
                    "fields).")
    sub = ap.add_subparsers(dest="mode", required=True)
    p_lint = sub.add_parser("lint", help="validate a schema document")
    p_lint.add_argument("schema")
    p_ver = sub.add_parser("verify",
                           help="check proof records against a schema")
    p_ver.add_argument("schema")
    p_ver.add_argument("proofs", nargs="?", default="-")
    return ap


def main(argv=None):
    opt = build_parser().parse_args(argv)
    try:
        if opt.mode == "lint":
            doc = load_doc(opt.schema)
            findings = lint_schema(doc)
            target = opt.schema
        else:
            schema = load_doc(opt.schema)
            records, errs = load_json_lines(opt.proofs)
            findings = verify_proofs(schema, records, errs)
            target = opt.proofs
    except (OSError, ValueError) as e:
        print("error: %s" % e, file=sys.stderr)
        return 2
    print(fmt_report(opt.mode, target, findings))
    return 1 if findings else 0


def self_test():
    import os
    import shutil
    import tempfile

    good_schema = {"version": 1,
                   "hash_algos": ["sha256", "keccak256"],
                   "merkle_root": {"encoding": "hex", "width": 64},
                   "timestamp": {"field": "ts", "format": "epoch",
                                 "granularity": "s"},
                   "required": ["proof_id", "algo", "merkle_root", "ts"]}
    assert lint_schema(good_schema) == [], lint_schema(good_schema)

    bad_schema = {"version": "one", "hash_algos": ["md5"],
                  "merkle_root": {"encoding": "base58", "width": 7},
                  "timestamp": {"field": "", "format": "rfc",
                                "granularity": "us"},
                  "required": []}
    findings = lint_schema(bad_schema)
    assert len(findings) >= 6, findings

    root64 = "ab" * 32
    proofs = [
        {"proof_id": "p1", "algo": "sha256", "merkle_root": root64,
         "ts": 1762700000, "version": 1},
        {"proof_id": "p2", "algo": "md5", "merkle_root": "zz" * 32,
         "ts": 1762700000},                       # bad algo + charset
        {"proof_id": "p3", "algo": "sha256", "merkle_root": "ab" * 31,
         "ts": 1762700000.5},                     # width + sub-second
        {"proof_id": "p4", "algo": "sha256", "merkle_root": root64,
         "ts": 1762700000000},                    # ms magnitude in s band
        {"proof_id": "p5", "algo": "sha256", "merkle_root": root64,
         "ts": 1762700000, "version": 2},         # version drift
        {"proof_id": "p6", "algo": "sha256"},     # missing required
    ]
    res = {f["proof"]: f["violations"]
           for f in verify_proofs(good_schema, proofs, [])}
    assert "p1" not in res, res
    assert "p6" in res and any("required" in v for v in res["p6"])
    assert any("algo" in v for v in res["p2"])
    assert any("lowercase-hex" in v for v in res["p2"])
    assert any("width" in v for v in res["p3"])
    assert any("sub-second" in v for v in res["p3"])
    assert any("band" in v for v in res["p4"]), res["p4"]
    assert any("version" in v for v in res["p5"])

    # iso8601 variant
    iso_schema = dict(good_schema)
    iso_schema["required"] = ["proof_id", "algo", "merkle_root", "when"]
    iso_schema["timestamp"] = {"field": "when", "format": "iso8601"}
    assert lint_schema(iso_schema) == []
    iso_proofs = [
        {"proof_id": "q1", "algo": "sha256", "merkle_root": root64,
         "when": "2026-11-10T11:42:00Z"},
        {"proof_id": "q2", "algo": "sha256", "merkle_root": root64,
         "when": "10/11/2026 11:42"},
    ]
    ires = {f["proof"] for f in verify_proofs(iso_schema, iso_proofs,
                                              [])}
    assert "q1" not in ires and "q2" in ires, ires

    # end-to-end over temp files: bad record -> rc 1; clean -> rc 0
    root = tempfile.mkdtemp(prefix="proof-schema-")
    try:
        spath = os.path.join(root, "schema.json")
        with open(spath, "w") as fh:
            json.dump(good_schema, fh)
        ppath = os.path.join(root, "proofs.jsonl")
        with open(ppath, "w") as fh:
            for p in proofs:
                fh.write(json.dumps(p) + "\n")
        assert main(["verify", spath, ppath]) == 1
        cpath = os.path.join(root, "clean.jsonl")
        with open(cpath, "w") as fh:
            fh.write(json.dumps(proofs[0]) + "\n")
        assert main(["verify", spath, cpath]) == 0
        assert main(["lint", spath]) == 0
        rep = fmt_report("verify", "x", verify_proofs(
            good_schema, [proofs[1]], []))
        assert "p2" in rep and "algo" in rep, rep
    finally:
        shutil.rmtree(root, ignore_errors=True)
    print("proof-schema-lint self-test OK (schema lint pos/neg, algo/"
          "charset/width/granularity/version/required violations, iso8601, "
          "end-to-end rc 1 vs 0)")


if __name__ == "__main__":
    if "--self-test" in sys.argv:
        self_test()  # falls through; rc 0 (mutation probe runs after)
    else:
        raise SystemExit(main())
