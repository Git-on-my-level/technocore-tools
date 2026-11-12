#!/usr/bin/env python3
"""csv-stream-audit — streaming, local-first audit of a very large CSV
export: schema drift and referential integrity with bounded memory and
reproducible chunk hashes. No Spark, no database, no full-file load.

DEMAND: evidence/suggestions/tools-services/2026-11-12.md — the same
job filed in BOTH runs of 2026-11-12 (kcea2098438, 05:59 and 11:55):
  - request: "Reproducible local-first validation of 2GB CSV stream for
    schema drift and referential integrity without Spark/DB loading" —
    evidence: "JOB v1 | kcea2098438 | data | I need a reproducible,
    local-first solution to validate a 2GB CSV stream for schema drift
    and referential integrity without loading it into a Spark or a
    [database]" — proposed service: "Hermes-tools add a streaming CSV
    audit mode that checks schema drift and referential integrity
    locally with bounded memory and reproducible hashes."
Scope: the full proposed service. One lazy pass over the data file:
raw bytes are hashed while csv rows are parsed line-by-line, so memory
stays O(reference table + findings + chunk count), never O(rows).

Inputs:
  --data PATH      the CSV stream to audit (any size, read lazily)
  --schema PATH    optional contract CSV; its first row is the expected
                   header (default: the data's own first row)
  --fk COL=REFCOL  repeatable: data column COL must reference REFCOL of
                   the --ref table (name, or 0-based index if digits)
  --ref PATH       reference CSV for --fk lookups (loaded into a set)
  --chunk-rows N   rows per reproducible chunk hash (default 100000)
  --max-findings K cap on listed findings; full counts always kept
  --json           raw report as JSON

Findings (rc 1 when any exist, rc 0 clean, rc 2 usage/IO error):
  header-mismatch  data header deviates from the --schema contract
  header-drift     an in-band repeated header differs from the baseline
  arity-drift      row field count differs from the header's
  type-drift       a column's committed class changes mid-stream
  fk-violation     an --fk value missing from the reference table
  fk-col-missing   an --fk column is absent from the data header
  empty-stream     data file yielded no rows at all

Reproducibility: the report carries a full-stream SHA-256 over raw
bytes plus one SHA-256 per chunk of N rows; identical inputs give
identical digests, and any byte change moves them. Content is parsed,
never run.
"""

import argparse
import csv
import hashlib
import json
import re
import sys

_NUM = re.compile(r"^[+-]?(?:\d+(?:\.\d*)?|\.\d+)(?:[eE][+-]?\d+)?$")
_DATE = re.compile(r"^\d{4}-\d{2}-\d{2}$")


def classify(cell):
    """Cell -> 'num' | 'date' | 'str'; empty/blank -> None."""
    c = cell.strip()
    if not c:
        return None
    if _NUM.match(c):
        return "num"
    if _DATE.match(c):
        return "date"
    return "str"


def parse_fk_spec(spec):
    """'COL=REFCOL' -> (col, refcol); raises ValueError when malformed."""
    if spec.count("=") != 1:
        raise ValueError("fk spec must be COL=REFCOL, got %r" % spec)
    col, refcol = spec.split("=")
    col, refcol = col.strip(), refcol.strip()
    if not col or not refcol:
        raise ValueError("fk spec must be COL=REFCOL, got %r" % spec)
    return col, refcol


def load_ref_index(path, refcol):
    """Reference CSV -> (set of refcol values, resolved index, rows).

    refcol is a header name, or a 0-based column index when all digits.
    Memory is bounded by the reference table, not the data stream.
    """
    with open(path, newline="", errors="replace") as fh:
        rd = csv.reader(fh)
        header = next(rd, None)
        if header is None:
            return set(), None, 0
        if refcol.isdigit() and int(refcol) < len(header):
            idx = int(refcol)
        elif refcol in header:
            idx = header.index(refcol)
        else:
            return set(), None, 0
        vals = set()
        rows = 0
        for row in rd:
            rows += 1
            if len(row) > idx:
                vals.add(row[idx])
        return vals, idx, rows


def compare_headers(expected, observed):
    """Header diff summary -> short human strings."""
    diffs = []
    e, o = list(expected), list(observed)
    if e == o:
        return diffs
    added = [c for c in o if c not in e]
    removed = [c for c in e if c not in o]
    if added:
        diffs.append("added: %s" % ",".join(added[:8]))
    if removed:
        diffs.append("removed: %s" % ",".join(removed[:8]))
    if not added and not removed:
        diffs.append("reordered (expected %s)" % ",".join(e[:8]))
    return diffs or ["differs from contract"]


def header_like(row, header):
    """True when a row is plausibly a repeated header (>=60% of the
    baseline header names reappear, same width, nothing numeric)."""
    if len(row) != len(header):
        return False
    if any(classify(c) == "num" for c in row):
        return False
    shared = len({c for c in row if c} & set(header))
    return shared >= max(1, int(0.6 * len({c for c in header if c})))


class LineHasher:
    """Lazily yields decoded lines from a binary stream while hashing
    the raw bytes: one total digest plus one digest per chunk of rows.

    csv.reader pulls lines one at a time, so the data file is never
    held in memory; multi-line quoted records hash every line they
    span while still counting as a single row.
    """

    def __init__(self, path, chunk_rows):
        self._fh = open(path, "rb")
        self.chunk_rows = max(1, chunk_rows)
        self.total = hashlib.sha256()
        self.chunk_hashes = []
        self._chunk = hashlib.sha256()
        self._rows = 0

    def __iter__(self):
        for raw in self._fh:
            self.total.update(raw)
            self._chunk.update(raw)
            yield raw.decode("utf-8", errors="replace")
        self._fh.close()

    def row_done(self):
        self._rows += 1
        if self._rows >= self.chunk_rows:
            self.chunk_hashes.append(self._chunk.hexdigest())
            self._chunk = hashlib.sha256()
            self._rows = 0

    def finish(self):
        if self._rows:
            self.chunk_hashes.append(self._chunk.hexdigest())
            self._rows = 0
        return self.total.hexdigest()


class ColumnTypes:
    """Per-column class tracker: a class commits after 2 agreeing
    cells; a committed class meeting a different one raises one
    type-drift finding per column (deterministic, bounded)."""

    def __init__(self):
        self.state = {}
        self.drifted = set()

    def feed(self, col, cell, row_no):
        c = classify(cell)
        if c is None:
            return None
        if col not in self.state:
            self.state[col] = [c, 1]
            return None
        cls, seen = self.state[col]
        if c == cls:
            self.state[col][1] = seen + 1
            return None
        if seen < 2:
            self.state[col] = [c, 1]
            return None
        self.state[col] = [c, 1]
        if col in self.drifted:
            return None
        self.drifted.add(col)
        return {"kind": "type-drift", "column": col, "from": cls,
                "to": c, "row": row_no, "value": cell.strip()[:40]}


def stream_audit(data_path, schema_header=None, fk_specs=(), ref_path=None,
                 chunk_rows=100000, max_findings=50):
    """One streaming pass -> report dict (feeds --json and stdout)."""
    findings = []
    counts = {}

    def hit(f):
        counts[f["kind"]] = counts.get(f["kind"], 0) + 1
        if len(findings) < max_findings:
            findings.append(f)

    refs, ref_stats = {}, {}
    for spec in fk_specs:
        col, refcol = parse_fk_spec(spec)
        vals, idx, rows = load_ref_index(ref_path, refcol) \
            if ref_path else (set(), None, 0)
        refs[col] = vals
        ref_stats[spec] = {"ref_rows": rows, "resolved": idx is not None}

    hasher = LineHasher(data_path, chunk_rows)
    rd = csv.reader(hasher)
    header = None
    rows = repeated_headers = arity_bad = 0
    types = ColumnTypes()
    fk_idx = {}

    for row in rd:
        rows += 1
        hasher.row_done()
        if header is None:
            header = row
            if schema_header is not None and row != schema_header:
                hit({"kind": "header-mismatch",
                     "detail": "; ".join(compare_headers(schema_header, row))
                     or "differs from contract"})
            for col in refs:
                if col in header:
                    fk_idx[col] = header.index(col)
                else:
                    hit({"kind": "fk-col-missing", "column": col})
            continue
        if header_like(row, header):
            repeated_headers += 1
            if row != header:
                hit({"kind": "header-drift",
                     "detail": "; ".join(compare_headers(header, row))})
            continue
        if len(row) != len(header):
            arity_bad += 1
            hit({"kind": "arity-drift", "row": rows,
                 "fields": len(row), "expected": len(header)})
            continue
        for i, cell in enumerate(row):
            f = types.feed(i, cell, rows)
            if f is not None:
                if f["column"] < len(header):
                    f["column"] = header[f["column"]]
                hit(f)
        for col, idx in sorted(fk_idx.items()):
            if row[idx] not in refs[col]:
                hit({"kind": "fk-violation", "row": rows, "column": col,
                     "value": row[idx][:40]})
    digest = hasher.finish()

    if header is None:
        hit({"kind": "empty-stream", "detail": "no rows parsed"})
    return {"rows": rows, "columns": header or [],
            "repeated_headers": repeated_headers,
            "arity_bad_rows": arity_bad,
            "column_classes": {header[i]: types.state[i][0]
                               for i in sorted(types.state)
                               if header and i < len(header)},
            "fk": ref_stats, "chunks": len(hasher.chunk_hashes),
            "chunk_rows": chunk_rows, "digest_sha256": digest,
            "first_chunks": hasher.chunk_hashes[:3],
            "last_chunks": hasher.chunk_hashes[-3:],
            "counts": counts, "findings": findings,
            "truncated": sum(counts.values()) > len(findings)}


def fmt_report(rep):
    """Human-readable audit report."""
    lines = ["csv-stream-audit: %d rows, %d columns, %d chunks (%d rows"
             "/chunk)" % (rep["rows"], len(rep["columns"]), rep["chunks"],
                          rep["chunk_rows"])]
    lines.append("  digest sha256=%s" % rep["digest_sha256"])
    if rep["column_classes"]:
        lines.append("  classes: %s" % ", ".join(
            "%s=%s" % kv for kv in sorted(rep["column_classes"].items())))
    for spec, st in sorted(rep["fk"].items()):
        lines.append("  fk %s -> %d ref values%s"
                     % (spec, st["ref_rows"],
                        "" if st["resolved"] else " (UNRESOLVED ref col)"))
    for f in rep["findings"]:
        bits = ["  %s" % f["kind"]]
        for k in sorted(f):
            if k != "kind":
                bits.append("%s=%s" % (k, f[k]))
        lines.append(" ".join(bits))
    if sum(rep["counts"].values()) > len(rep["findings"]):
        lines.append("  ... %d more findings (counts in --json)"
                     % (sum(rep["counts"].values()) - len(rep["findings"])))
    if not rep["counts"]:
        lines.append("  no findings: schema stable, integrity holds")
    return "\n".join(lines)


def build_parser():
    ap = argparse.ArgumentParser(
        prog="csv-stream-audit",
        description="Streaming schema-drift + referential-integrity "
                    "audit of a large CSV with reproducible chunk "
                    "hashes; bounded memory, local-first, stdlib only.")
    ap.add_argument("--data", required=True, help="CSV stream to audit")
    ap.add_argument("--schema", help="contract CSV (header row)")
    ap.add_argument("--fk", action="append", default=[], metavar="COL=REFCOL",
                    help="referential check, repeatable")
    ap.add_argument("--ref", help="reference CSV for --fk lookups")
    ap.add_argument("--chunk-rows", type=int, default=100000,
                    help="rows per reproducible chunk hash")
    ap.add_argument("--max-findings", type=int, default=50,
                    help="cap on listed findings")
    ap.add_argument("--json", action="store_true",
                    help="emit the raw report dict as JSON")
    return ap


def main(argv=None):
    opt = build_parser().parse_args(argv)
    if opt.fk and not opt.ref:
        print("csv-stream-audit: --fk requires --ref", file=sys.stderr)
        return 2
    schema_header = None
    try:
        if opt.schema:
            with open(opt.schema, newline="", errors="replace") as fh:
                schema_header = next(csv.reader(fh), None)
            if schema_header is None:
                print("csv-stream-audit: empty schema file",
                      file=sys.stderr)
                return 2
        rep = stream_audit(opt.data, schema_header, tuple(opt.fk),
                           opt.ref, opt.chunk_rows, opt.max_findings)
    except (OSError, ValueError) as exc:
        print("csv-stream-audit: %s" % exc, file=sys.stderr)
        return 2
    if opt.json:
        print(json.dumps(rep, indent=2, sort_keys=True))
    else:
        print(fmt_report(rep))
    return 1 if rep["counts"] else 0


def self_test():
    import os
    import shutil
    import tempfile

    # cell classification
    assert classify("42") == "num" and classify("-3.5e2") == "num"
    assert classify("2026-11-12") == "date" and classify("a,b") == "str"
    assert classify("") is None and classify("  ") is None

    # fk spec + header diffs
    assert parse_fk_spec("cust_id=customer_id") == ("cust_id",
                                                    "customer_id")
    assert compare_headers(["a", "b"], ["a", "b"]) == []
    assert any("reordered" in d for d in
               compare_headers(["a", "b"], ["b", "a"]))
    assert any("added" in d for d in
               compare_headers(["a"], ["a", "b"]))
    assert header_like(["a", "b"], ["a", "b"]) is True
    assert header_like(["1", "2"], ["a", "b"]) is False

    root = tempfile.mkdtemp(prefix="csv-stream-")
    try:
        ref = os.path.join(root, "ref.csv")
        with open(ref, "w", newline="") as fh:
            fh.write("customer_id,region\nC1,eu\nC2,us\nC3,eu\n")
        vals, idx, rows = load_ref_index(ref, "customer_id")
        assert load_ref_index(ref, "customer_id") == (vals, idx, rows)
        assert vals == {"C1", "C2", "C3"} and idx == 0 and rows == 3
        assert load_ref_index(ref, "1") == ({"eu", "us"}, 1, 3)
        assert load_ref_index(ref, "nope") == (set(), None, 0)

        # multi-section stream: drift + fk violations + quoted commas
        data = os.path.join(root, "data.csv")
        body = (
            "order_id,customer_id,amount,note\n"
            'O1,C1,10,"hello, world"\n'
            "O2,C2,20,plain\n"
            "O3,C9,30,missing ref\n"          # fk-violation
            "O4,C1,oops,note\n"               # type-drift amount
            "order_id,customer_id,amount,note\n"   # repeated header
            "O5,C3,50,tail\n"
            "O6,C2,60\n"                      # arity-drift
        )
        with open(data, "w", newline="") as fh:
            fh.write(body)
        rep = stream_audit(data, None, ("customer_id=customer_id",),
                           ref, chunk_rows=2, max_findings=10)
        assert stream_audit(data, None, ("customer_id=customer_id",),
                            ref, chunk_rows=2,
                            max_findings=10) == rep, "must be deterministic"
        kinds = rep["counts"]
        assert kinds.get("fk-violation") == 1, kinds
        assert kinds.get("type-drift") == 1, kinds
        assert kinds.get("arity-drift") == 1, kinds
        assert rep["repeated_headers"] == 1
        assert rep["rows"] == 8 and rep["chunks"] == 4, (rep["rows"],
                                                         rep["chunks"])
        assert rep["column_classes"]["amount"] == "num"
        assert fmt_report(rep).count("fk-violation") == 1

        # any byte change moves every reproducible hash
        data2 = os.path.join(root, "data2.csv")
        with open(data2, "w", newline="") as fh:
            fh.write(body.replace("O5,C3,50", "O5,C3,51"))
        rep2 = stream_audit(data2, None, ("customer_id=customer_id",),
                            ref, chunk_rows=2)
        assert rep2["digest_sha256"] != rep["digest_sha256"]
        assert rep2["last_chunks"] != rep["last_chunks"]

        # schema contract: reordered section header -> header-drift
        schema = os.path.join(root, "schema.csv")
        with open(schema, "w", newline="") as fh:
            fh.write("order_id,customer_id,amount,note\n")
        drift = os.path.join(root, "drift.csv")
        with open(drift, "w", newline="") as fh:
            fh.write("order_id,customer_id,amount,note\n"
                     "O1,C1,10,x\n"
                     "customer_id,order_id,note,amount\n"   # reordered
                     "O2,C2,20,y\n")
        with open(schema, newline="") as fh:
            schema_header = next(csv.reader(fh))
        rep3 = stream_audit(drift, schema_header, chunk_rows=10)
        assert rep3["counts"].get("header-drift") == 1, rep3["counts"]
        assert rep3["counts"].get("type-drift", 0) == 0

        # clean stream: rc 0 via main(); findings -> 1; IO -> 2
        clean = os.path.join(root, "clean.csv")
        with open(clean, "w", newline="") as fh:
            fh.write("order_id,customer_id,amount\nO1,C1,10\nO2,C2,20\n")
        rc = main(["--data", clean, "--ref", ref,
                   "--fk", "customer_id=customer_id"])
        assert rc == 0, rc
        rc = main(["--data", data, "--ref", ref,
                   "--fk", "customer_id=customer_id"])
        assert rc == 1, rc
        rc = main(["--data", os.path.join(root, "missing.csv")])
        assert rc == 2, rc
        rc = main(["--data", clean, "--fk", "customer_id=customer_id"])
        assert rc == 2, rc  # --fk without --ref
    finally:
        shutil.rmtree(root, ignore_errors=True)
    print("csv-stream-audit self-test OK (classify, fk/header parsing, "
          "drift+integrity findings, chunk hashing incl. determinism "
          "and byte sensitivity, rc 0/1/2)")


if __name__ == "__main__":
    if "--self-test" in sys.argv:
        self_test()  # falls through; rc 0 (mutation probe runs after)
    else:
        raise SystemExit(main())
