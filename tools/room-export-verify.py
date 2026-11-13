#!/usr/bin/env python3
"""room-export-verify — independent-verifiability audit for room exports:
a non-author holding only the exported files checks seq ordering, eviction
tracking (first_seq read snapshots vs eviction tombstones) and the
tamper-evident hash chain, then re-derives a verification receipt.

DEMAND: evidence/suggestions/tools-services/2026-11-13.md — filed in BOTH
runs of the day:
  - 05:56 request: "Make room export independently verifiable (checkable
    by non-author, with sequence ordering and eviction tracking)" —
    evidence: "if the export is the audit trail, make it checkable by
    someone who did not make it. Export JSONL in seq order, record
    first_seq at every read so an eviction g[ap is detectable]" — proposed
    service: "hermes-tools adds export integrity mode (JSONL seq-ordered,
    first_seq snapshots, tamper-evidence for external verification)"
  - 11:56 request: "Make room export checkable by third parties (export
    integrity/verifiability)" — proposed service: "tamper-evident,
    independently verifiable room exports (JSONL in seq order with
    first_seq snapshots and content hashes) for external audit"
  Adjacent same-file ask: "Preserve audit trail beyond 48h room reaping
  and unsigned /kv LWW notes" — verifying a stored export is the offline
  half of surviving the reap.

Scope: every input is data (JSON fields are read, never run). Export
line: {"seq":int,"ts":str,"author":str,"kind":str,"body"?:any,
"prev"?:hex,"hash"?:hex}; kind=="evicted" marks an eviction tombstone
for that seq. Reads line: {"ts":str,"reader":str,"first_seq":int} —
first_seq recorded at every read. Exit codes: 0 = export verifies clean;
1 = findings; 2 = usage / unreadable input.
"""

import argparse
import hashlib
import json
import os
import sys
import tempfile

GENESIS = "0" * 64
TOMBSTONE = "evicted"
CHECKPOINT_EVERY = 8  # receipt checkpoint cadence (small rooms: every 8th seq)


def canonical(obj):
    """Deterministic serialization used for hashing."""
    return json.dumps(obj, sort_keys=True, separators=(",", ":"))


def rec_hash(prev, record):
    """Chain hash: covers prior hash + this record's content (minus links)."""
    payload = {k: v for k, v in record.items() if k not in ("hash", "prev", "_line")}
    return hashlib.sha256((prev + canonical(payload)).encode("utf-8")).hexdigest()


def parse_jsonl(path, what):
    """Read one JSONL file -> (rows, errors). Rows carry their 1-based _line."""
    rows, errors = [], []
    if not os.path.isfile(path):
        errors.append({"code": "io-missing", "line": 0,
                       "detail": "%s file not found: %s" % (what, path)})
        return rows, errors
    try:
        fh = open(path, encoding="utf-8")
    except OSError as exc:
        errors.append({"code": "io-unreadable", "line": 0, "detail": str(exc)})
        return rows, errors
    with fh:
        for n, line in enumerate(fh, 1):
            line = line.strip()
            if not line:
                continue
            try:
                row = json.loads(line)
            except ValueError as exc:
                errors.append({"code": "parse-error", "line": n,
                               "detail": str(exc)})
                continue
            if not isinstance(row, dict):
                errors.append({"code": "parse-error", "line": n,
                               "detail": "not a JSON object"})
                continue
            row["_line"] = n
            rows.append(row)
    return rows, errors


def check_seq_order(records):
    """Export must be one strictly forward seq trail (order + uniqueness)."""
    findings, seen = [], {}
    prev_seq = None
    for rec in records:
        seq = rec.get("seq")
        if not isinstance(seq, int) or isinstance(seq, bool):
            findings.append({"code": "seq-missing", "line": rec["_line"],
                             "detail": "record lacks integer seq"})
            continue
        if seq in seen:
            findings.append({"code": "seq-duplicate", "line": rec["_line"],
                             "detail": "seq %d already exported at line %d "
                                       "(history fork)" % (seq, seen[seq])})
        else:
            seen[seq] = rec["_line"]
        if prev_seq is not None and seq < prev_seq:
            findings.append({"code": "seq-regression", "line": rec["_line"],
                             "detail": "seq %d after %d: export not in seq "
                                       "order" % (seq, prev_seq)})
        prev_seq = seq
    return findings


def verify_chain(records):
    """Recompute the hash chain; declared links must match content."""
    findings = []
    if records and not any(("hash" in r) or ("prev" in r) for r in records):
        findings.append({"code": "chain-absent", "line": 0,
                         "detail": "no hash/prev fields anywhere: export "
                                   "carries no tamper-evidence"})
        return findings
    prev = GENESIS
    for rec in records:
        want = rec_hash(prev, rec)
        declared_prev = rec.get("prev")
        if declared_prev is not None and declared_prev != prev:
            findings.append({"code": "chain-broken", "line": rec["_line"],
                             "detail": "prev %s... != chain %s... "
                                       "(reordered or spliced)"
                                       % (str(declared_prev)[:12], prev[:12])})
        declared_hash = rec.get("hash")
        if declared_hash is not None and declared_hash != want:
            findings.append({"code": "chain-tampered", "line": rec["_line"],
                             "detail": "declared %s... != computed %s... "
                                       "(content changed after hashing)"
                                       % (str(declared_hash)[:12], want[:12])})
        prev = want
    return findings


def check_evictions(records, reads):
    """first_seq snapshots vs export coverage: evictions must be explainable.

    Invariants: first_seq never regresses; every seq in [first read's
    first_seq, last first_seq) is present as a live record or an eviction
    tombstone; the export is not stale w.r.t. the room's current floor.
    """
    findings, live, tomb = [], {}, {}
    for rec in records:
        seq = rec.get("seq")
        if not isinstance(seq, int) or isinstance(seq, bool):
            continue
        if rec.get("kind") == TOMBSTONE:
            tomb[seq] = rec["_line"]
        else:
            live[seq] = rec["_line"]
    for seq in sorted(set(live) & set(tomb)):
        findings.append({"code": "tombstone-conflict", "seq": seq,
                         "detail": "seq %d exported both live (line %d) and "
                                   "as eviction tombstone (line %d)"
                                   % (seq, live[seq], tomb[seq])})
    floors, prev_floor = [], None
    for rd in reads:
        f = rd.get("first_seq")
        if not isinstance(f, int) or isinstance(f, bool):
            findings.append({"code": "read-malformed", "line": rd["_line"],
                             "detail": "read lacks integer first_seq"})
            continue
        if prev_floor is not None and f < prev_floor:
            findings.append({"code": "first-seq-regression", "line": rd["_line"],
                             "detail": "first_seq %d after %d: reaped history "
                                       "reappeared (tamper or stale reader)"
                                       % (f, prev_floor)})
        floors.append(f)
        prev_floor = f if prev_floor is None else max(prev_floor, f)
    if floors:
        f_first, f_last = floors[0], floors[-1]
        if f_first > 1:
            findings.append({"code": "floor-offset", "seq": f_first,
                             "detail": "earliest read starts at first_seq %d: "
                                       "seqs 1..%d unverifiable from this "
                                       "export" % (f_first, f_first - 1)})
        for s in range(f_first, f_last):
            if s not in live and s not in tomb:
                findings.append({"code": "silent-eviction", "seq": s,
                                 "detail": "seq %d neither exported nor "
                                           "tombstoned: eviction nobody can "
                                           "verify (hole)" % s})
        max_seq = max(list(live) + list(tomb), default=None)
        if max_seq is not None and f_last > max_seq + 1:
            findings.append({"code": "export-stale", "seq": f_last,
                             "detail": "room first_seq %d beyond exported max "
                                       "seq %d: export lags the room"
                                       % (f_last, max_seq)})
    return findings


def derive_receipt(export_path, records):
    """Content-derived receipt a third party re-computes from the export."""
    chain_head, checkpoints, seqs = GENESIS, [], []
    for rec in records:
        chain_head = rec_hash(chain_head, rec)
        seq = rec.get("seq")
        if isinstance(seq, int) and not isinstance(seq, bool):
            seqs.append(seq)
            if seq % CHECKPOINT_EVERY == 0:
                checkpoints.append({"seq": seq, "hash": chain_head})
    with open(export_path, "rb") as fh:
        export_sha = hashlib.sha256(fh.read()).hexdigest()
    return {"tool": "room-export-verify", "version": 1,
            "export_sha256": export_sha, "count": len(records),
            "seq_first": min(seqs) if seqs else None,
            "seq_last": max(seqs) if seqs else None,
            "chain_head": chain_head, "checkpoints": checkpoints}


def verify_receipt(export_path, records, receipt):
    """Non-author check: re-derive and compare a published receipt."""
    findings = []
    if not isinstance(receipt, dict):
        return [{"code": "receipt-malformed", "line": 0,
                 "detail": "receipt is not a JSON object"}]
    fresh = derive_receipt(export_path, records)
    for key in ("export_sha256", "chain_head", "count", "seq_first", "seq_last"):
        if key in receipt and receipt[key] != fresh[key]:
            findings.append({"code": "receipt-mismatch." + key, "line": 0,
                             "detail": "receipt %s %r != re-derived %r "
                                       "(export changed after receipt)"
                                       % (key, receipt[key], fresh[key])})
    return findings


def audit_export(export_path, reads_path, receipt=None):
    """Full audit -> (findings, receipt_dict). Pure; no side effects."""
    findings = []
    records, errors = parse_jsonl(export_path, "export")
    reads, rerrors = parse_jsonl(reads_path, "reads")
    io_errors = [e for e in errors + rerrors if e["code"].startswith("io-")]
    findings.extend(e for e in errors + rerrors if not e["code"].startswith("io-"))
    if io_errors:
        return io_errors, None
    findings.extend(check_seq_order(records))
    findings.extend(verify_chain(records))
    findings.extend(check_evictions(records, reads))
    if receipt is not None:
        findings.extend(verify_receipt(export_path, records, receipt))
    return findings, derive_receipt(export_path, records)


def load_receipt(path):
    if not path:
        return None
    with open(path, encoding="utf-8") as fh:
        return json.load(fh)


def main(argv=None):
    ap = argparse.ArgumentParser(
        description="Audit a room export for independent verifiability "
                    "(seq order, eviction tracking, hash chain, receipt).")
    ap.add_argument("--export", required=True, help="room export JSONL")
    ap.add_argument("--reads", required=True,
                    help="read snapshots JSONL (first_seq at every read)")
    ap.add_argument("--receipt", help="published receipt JSON to verify "
                                      "(absent = just derive a new one)")
    ap.add_argument("--out", help="write derived receipt JSON here")
    ap.add_argument("--json", action="store_true", help="machine-readable out")
    args = ap.parse_args(argv)
    try:
        receipt = load_receipt(args.receipt)
    except (OSError, ValueError) as exc:
        print("receipt unreadable: %s" % exc, file=sys.stderr)
        return 2
    findings, fresh = audit_export(args.export, args.reads, receipt)
    if fresh is None:
        for f in findings:
            print("error: %s: %s" % (f["code"], f["detail"]), file=sys.stderr)
        return 2
    if args.json:
        print(json.dumps({"findings": findings, "receipt": fresh},
                         indent=1, sort_keys=True))
    else:
        for f in findings:
            where = ("line %s" % f["line"]) if f.get("line") else ("seq %s" % f.get("seq", "?"))
            print("FINDING %s: %s: %s" % (where, f["code"], f["detail"]))
        print("%d record(s) audited; chain_head=%s...; %d finding(s)"
              % (fresh["count"], fresh["chain_head"][:12], len(findings)))
    if args.out:
        with open(args.out, "w", encoding="utf-8") as fh:
            json.dump(fresh, fh, indent=1, sort_keys=True)
            fh.write("\n")
    if findings:
        return 1
    print("OK: export independently verifiable (seq order, evictions "
          "explained, chain intact)" + (", receipt matches" if receipt is not None else ""))
    return 0


def write_room(path, seqs, tombstones=(), ts_fmt="2026-11-13T05:%M:%SZ"):
    """Test helper: write a correctly chained export covering `seqs`."""
    lines, prev = [], GENESIS
    for s in seqs:
        rec = {"seq": s, "ts": ts_fmt.replace("%M", "%02d" % (s % 60)),
               "author": "did:pkh:alice",
               "kind": TOMBSTONE if s in tombstones else "message"}
        if rec["kind"] != TOMBSTONE:
            rec["body"] = {"text": "note-%d" % s}
        h = rec_hash(prev, rec)
        rec["prev"], rec["hash"] = prev, h
        prev = h
        lines.append(canonical(rec))
    with open(path, "w", encoding="utf-8") as fh:
        fh.write("\n".join(lines) + "\n")
    return lines


def write_reads(path, floors):
    with open(path, "w", encoding="utf-8") as fh:
        for i, f in enumerate(floors):
            fh.write(canonical({"ts": "2026-11-13T06:%02d:00Z" % i,
                                "reader": "did:pkh:bob", "first_seq": f}) + "\n")


def self_test():
    root = tempfile.mkdtemp(prefix="room-export-verify-")
    try:
        exp = os.path.join(root, "room.jsonl")
        rds = os.path.join(root, "reads.jsonl")

        # 1. clean export: seqs 1..12, seq 5 evicted+tombstoned, floors walk 1->5->9
        write_room(exp, range(1, 13), tombstones={5})
        write_reads(rds, [1, 5, 9])
        findings, rcpt = audit_export(exp, rds)
        assert findings == [], findings
        assert rcpt["count"] == 12 and rcpt["seq_first"] == 1 and rcpt["seq_last"] == 12, rcpt
        assert len(rcpt["checkpoints"]) == 1 and rcpt["checkpoints"][0]["seq"] == 8, rcpt
        assert verify_receipt(exp, parse_jsonl(exp, "e")[0], rcpt) == []

        # receipt is deterministic and byte-sensitive
        assert derive_receipt(exp, parse_jsonl(exp, "e")[0]) == rcpt

        # 2. tampered body -> chain flags the exact line; receipt sha diverges
        lines = open(exp, encoding="utf-8").read().splitlines()
        lines[6] = lines[6].replace("note-7", "note-7-forged")
        tam = os.path.join(root, "tampered.jsonl")
        open(tam, "w", encoding="utf-8").write("\n".join(lines) + "\n")
        f2 = verify_chain(parse_jsonl(tam, "e")[0])
        assert any(x["code"] == "chain-tampered" and x["line"] == 7 for x in f2), f2
        f2 = audit_export(tam, rds)[0]
        assert any(x["code"] == "chain-tampered" for x in f2), f2
        assert rcpt["export_sha256"] != derive_receipt(tam, parse_jsonl(tam, "e")[0])["export_sha256"]

        # 3. silent eviction: floors jump 1->9 but seqs 6..8 absent, no tombstones
        write_room(exp, [1, 2, 3, 4, 5, 9, 10, 11, 12], tombstones={5})
        f3 = check_evictions(parse_jsonl(exp, "e")[0], parse_jsonl(rds, "r")[0])
        holes = {x["seq"] for x in f3 if x["code"] == "silent-eviction"}
        assert holes == {6, 7, 8}, f3

        # 4. seq regression + duplicate -> ordering findings
        write_room(exp, range(1, 6))
        good = open(exp, encoding="utf-8").read().splitlines()
        dup = good[1] + "\n" + good[0] + "\n" + good[0]   # seq 2,1,1
        bad = os.path.join(root, "bad.jsonl")
        with open(bad, "w", encoding="utf-8") as fh:
            fh.write(dup + "\n")
        f4 = check_seq_order(parse_jsonl(bad, "e")[0])
        codes = {x["code"] for x in f4}
        assert "seq-duplicate" in codes and "seq-regression" in codes, f4

        # 5. floor regression + stale export + floor offset + live/tomb conflict
        write_room(exp, range(1, 13), tombstones={5})
        recs = parse_jsonl(exp, "e")[0]
        both = [dict(r) for r in recs] + [dict(recs[5], kind=TOMBSTONE, _line=99)]
        write_reads(rds, [3, 3, 20])
        f5 = check_evictions(both, parse_jsonl(rds, "r")[0])
        codes5 = {x["code"] for x in f5}
        assert {"tombstone-conflict", "floor-offset", "export-stale"} <= codes5, f5
        assert {x["seq"] for x in f5 if x["code"] == "silent-eviction"} == set(range(13, 20)), f5
        write_reads(rds, [5, 3])
        f5b = check_evictions(recs, parse_jsonl(rds, "r")[0])
        assert any(x["code"] == "first-seq-regression" for x in f5b), f5b

        # 6. chain-less export cannot be verified by a non-author
        bare = os.path.join(root, "bare.jsonl")
        with open(bare, "w", encoding="utf-8") as fh:
            for s in (1, 2):
                fh.write(canonical({"seq": s, "ts": "t", "author": "a", "kind": "message"}) + "\n")
        f6 = verify_chain(parse_jsonl(bare, "e")[0])
        assert any(x["code"] == "chain-absent" for x in f6), f6

        # 7. receipt mismatch: forged chain_head / stale export file
        forged = dict(rcpt, chain_head=GENESIS)
        assert any(x["code"] == "receipt-mismatch.chain_head"
                   for x in verify_receipt(exp, recs, forged))
        assert any(x["code"] == "receipt-mismatch.export_sha256"
                   for x in verify_receipt(tam, recs, rcpt))

        # 8. main() contract: rc 0 clean / 1 findings / 2 missing input
        write_room(exp, range(1, 13), tombstones={5})
        write_reads(rds, [1, 5, 9])
        out = os.path.join(root, "receipt.json")
        assert main(["--export", exp, "--reads", rds, "--out", out]) == 0
        assert json.load(open(out, encoding="utf-8"))["count"] == 12
        assert main(["--export", tam, "--reads", rds]) == 1
        assert main(["--export", os.path.join(root, "nope.jsonl"),
                     "--reads", rds]) == 2
        # published receipt that matches -> rc 0; stale one -> rc 1
        assert main(["--export", exp, "--reads", rds, "--receipt", out]) == 0
        stale = json.load(open(out, encoding="utf-8"))
        stale["chain_head"] = GENESIS
        stalep = os.path.join(root, "stale.json")
        json.dump(stale, open(stalep, "w", encoding="utf-8"))
        assert main(["--export", exp, "--reads", rds, "--receipt", stalep]) == 1
        assert main(["--export", bare, "--reads", rds]) == 1

        # parse errors surface as findings, not crashes
        junk = os.path.join(root, "junk.jsonl")
        open(junk, "w", encoding="utf-8").write('{"seq": 1}\nnot json\n')
        fj = audit_export(junk, rds)[0]
        assert any(x["code"] == "parse-error" for x in fj), fj
    finally:
        import shutil
        shutil.rmtree(root, ignore_errors=True)
    print("room-export-verify self-test OK (chain tamper + splice, seq "
          "order/fork, silent evictions vs first_seq snapshots, tombstone "
          "conflict, stale export, receipt derive/mismatch, rc 0/1/2)")


if __name__ == "__main__":
    if "--self-test" in sys.argv:
        self_test()  # falls through; rc 0 (mutation probe runs after)
    else:
        raise SystemExit(main())
