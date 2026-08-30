#!/usr/bin/env python3
"""audit-chain — tamper-evident seals + integrity reports for room/event
audit-trail exports (JSONL records with seq/ts/from/nonce, like
evidence/raw/<room>.jsonl).

DEMAND: evidence/suggestions/tools-services/2026-08-29.md
  - "审计服务必须提供可验证的审计轨迹，这需要系统性地验证审计过程中的
    序列连续性、操作时间戳的完整性与一致性" — the audit service must
    provide verifiable audit trails: systematic checks of sequence
    continuity and timestamp integrity/consistency; "增加密码学或日志链
    技术（如默克尔树、链式哈希）" — add chained-hash / merkle-tree
    techniques so audit steps are verifiable and tamper-evident and users
    can independently verify authenticity. (validators room, dozens of
    repeating senders; re-filed in the 07:48 and 14:00 runs. Unmet by
    room-dedup / dep-blindspot / keymat-audit.)

What it does (read-only; inputs are data, never executed):
  - seal FILE: hash every record. Unparsable lines hash as raw bytes and
    are flagged. Leaf d_i = sha256(canonical(record_i)) where canonical =
    sorted keys + compact separators — key order / whitespace in the
    export cannot change the seal. Chain h_i = sha256(h_{i-1} || d_i)
    from an all-zero genesis; merkle root over all leaves (odd level:
    duplicate last). Seal JSON (default FILE.seal.json) carries record
    count, chain head, merkle root, and a 16-hex prefix of every leaf.
  - verify FILE: recompute and compare. Any edit, insert, delete, reorder
    or truncation diverges the chain; per-leaf prefixes pinpoint the FIRST
    divergent record (index + seq/ts). Exit 0 intact / 1 tampered / 2 no
    seal. Independent anyone-can-run verification: the seal is tiny, the
    log is the witness.
  - report FILE: integrity findings without a seal — seq duplicates /
    gaps / reorders, missing-invalid-regressing timestamps, per-sender
    nonce regressions (nonce is strictly-increasing per DID per room;
    any equal-or-lower reuse is a replay — see
    notes/2026-08-27-nonce-retry-probe.md). Real exports are messy
    (lobby.jsonl: 32k seq gaps, 2.5k nonce regressions from ring-buffer
    rotation) — findings are counted and exemplified, never rewritten.

Usage:
  python3 audit-chain.py seal evidence/raw/lobby.jsonl
  python3 audit-chain.py verify evidence/raw/lobby.jsonl
  python3 audit-chain.py report --json evidence/raw/general.jsonl
  python3 audit-chain.py seal log.jsonl --out tonight.seal.json
  python3 audit-chain.py verify log.jsonl --seal tonight.seal.json

VERIFY: self-test — python3 audit-chain.py --self-test
  Seal/verify round-trips on fixtures; asserts text edit / insert /
  delete / reorder / truncate are each caught at the exact first
  divergent index; canonical-form stability under key reordering and
  whitespace; empty-log genesis; odd/even merkle shapes; integrity
  accounting for dup/gap/reorder seq, ts regressions, nonce replays,
  unparsable lines. Asserts, prints OK.
"""
import argparse
import hashlib
import json
import os
import sys
import tempfile
from datetime import datetime

GENESIS = "0" * 64          # chain head of an empty log
PREFIX_BYTES = 8            # 16 hex chars of each leaf kept in the seal
EXAMPLES = 5                # max examples kept per finding class


def canonical(record):
    """Stable serialization: key order / spacing cannot move the digest."""
    return json.dumps(record, sort_keys=True, ensure_ascii=False,
                      separators=(",", ":"))


def leaf_digest(raw_line):
    """-> (digest_bytes, record|None, parsable). Blank -> (None,..,None)."""
    s = raw_line.strip()
    if not s:
        return None, None, None
    try:
        rec = json.loads(s)
    except ValueError:
        return hashlib.sha256(raw_line.encode("utf-8")).digest(), None, False
    return hashlib.sha256(canonical(rec).encode("utf-8")).digest(), rec, True


def scan(path):
    """Stream records. -> (leaf blob bytearray, chain head hex, stats)."""
    blob = bytearray()
    head = bytes.fromhex(GENESIS)
    n = bad = 0
    with open(path, encoding="utf-8", errors="replace") as fh:
        for raw in fh:
            d, rec, ok = leaf_digest(raw)
            if d is None:
                continue
            head = hashlib.sha256(head + d).digest()
            blob += d
            n += 1
            bad += 0 if ok else 1
    return blob, head.hex(), {"records": n, "unparsable": bad}


def merkle_root(blob, n):
    """Merkle root over the 32-byte leaves in blob; odd level duplicates."""
    if n == 0:
        return hashlib.sha256(b"").hexdigest()
    cur, cnt = bytes(blob), n
    while cnt > 1:
        if cnt % 2:
            cur += cur[-32:]
            cnt += 1
        cur = b"".join(hashlib.sha256(cur[i:i + 64]).digest()
                       for i in range(0, cnt * 32, 64))
        cnt //= 2
    return cur.hex()


def make_seal(path, source_name=None):
    blob, head, stats = scan(path)
    prefixes = [bytes(blob[i:i + PREFIX_BYTES]).hex()
                for i in range(0, len(blob), 32)]
    return {
        "tool": "audit-chain", "version": 1,
        "source": source_name or os.path.basename(path),
        "algorithm": "sha256; leaf=canonical-JSON (sorted keys, compact); "
                     "chain=h[i]=sha256(h[i-1]||leaf); merkle duplicates "
                     "last leaf on odd levels; unparsable lines hash raw",
        "records": stats["records"], "unparsable": stats["unparsable"],
        "chain_head": head, "merkle_root": merkle_root(blob, len(prefixes)),
        "leaf_prefixes": prefixes,
    }


def record_at(path, index):
    """The index-th hashed line's (seq, ts) summary for divergence reports."""
    with open(path, encoding="utf-8", errors="replace") as fh:
        i = 0
        for raw in fh:
            d, rec, ok = leaf_digest(raw)
            if d is None:
                continue
            if i == index:
                if rec is None:
                    return {"index": index, "line": raw.strip()[:60]}
                return {"index": index, "seq": rec.get("seq"),
                        "ts": rec.get("ts"), "from": str(rec.get("from"))[:24]}
            i += 1
    return {"index": index}


def verify_against(path, seal):
    """-> (ok, verdict dict). Pinpoints the first divergent record."""
    blob, head, stats = scan(path)
    got = [bytes(blob[i:i + PREFIX_BYTES]).hex()
           for i in range(0, len(blob), 32)]
    want = seal.get("leaf_prefixes", [])
    v = {"records": stats["records"], "sealed": seal.get("records"),
         "first_divergence": None, "checks": {}}
    div = None
    for i, (a, b) in enumerate(zip(got, want)):
        if a != b:
            div = dict(record_at(path, i), kind="record diverges from seal",
                       expected_prefix=b, got_prefix=a)
            break
    if div is None:
        if len(got) < len(want):
            div = dict(record_at(path, len(got)),
                       kind="log ends early (records removed)",
                       expected_prefix=want[len(got)], got_prefix=None)
        elif len(got) > len(want):
            div = dict(record_at(path, len(want)),
                       kind="log longer than seal (records appended)",
                       expected_prefix=None, got_prefix=got[len(want)])
    v["first_divergence"] = div
    v["checks"] = {"chain_head": head == seal.get("chain_head"),
                   "merkle_root": merkle_root(blob, len(got))
                   == seal.get("merkle_root"),
                   "records": stats["records"] == seal.get("records")}
    v["ok"] = div is None and all(v["checks"].values())
    return v["ok"], v


def parse_ts(ts):
    if not isinstance(ts, str) or not ts:
        return None
    try:
        return datetime.fromisoformat(ts.replace("Z", "+00:00"))
    except ValueError:
        return None


def integrity_of(path):
    """Sequence/timestamp/nonce findings. Reports, never rewrites."""
    f = {"seq": {"duplicates": 0, "gaps": 0, "reorders": 0, "examples": []},
         "ts": {"missing_or_invalid": 0, "regressions": 0, "examples": []},
         "nonce": {"regressions": 0, "examples": []},
         "records": 0, "unparsable": 0}
    last_seq = last_dt = None
    last_nonce = {}

    def note(kind, msg):
        if len(f[kind]["examples"]) < EXAMPLES:
            f[kind]["examples"].append(msg)

    with open(path, encoding="utf-8", errors="replace") as fh:
        for i, raw in enumerate(fh):
            d, rec, ok = leaf_digest(raw)
            if d is None:
                continue
            f["records"] += 1
            if not ok:
                f["unparsable"] += 1
                continue
            seq, ts = rec.get("seq"), rec.get("ts")
            if isinstance(seq, int) and isinstance(last_seq, int):
                if seq == last_seq:
                    f["seq"]["duplicates"] += 1
                    note("seq", f"record {i}: seq {seq} repeats {last_seq}")
                elif seq < last_seq:
                    f["seq"]["reorders"] += 1
                    note("seq", f"record {i}: seq {seq} after {last_seq}")
                elif seq > last_seq + 1:
                    f["seq"]["gaps"] += 1
                    note("seq", f"record {i}: seq jumps {last_seq}->{seq}")
            if isinstance(seq, int) or last_seq is None:
                last_seq = seq if isinstance(seq, int) else last_seq
            dt = parse_ts(ts)
            if dt is None:
                if ts is not None:
                    f["ts"]["missing_or_invalid"] += 1
                    note("ts", f"record {i}: bad ts {ts!r}")
            elif last_dt is not None and dt < last_dt:
                f["ts"]["regressions"] += 1
                note("ts", f"record {i}: ts {ts} before previous")
            if dt is not None:
                last_dt = dt
            sender, nonce = rec.get("from"), rec.get("nonce")
            if isinstance(sender, str) and isinstance(nonce, int):
                prev = last_nonce.get(sender)
                if prev is not None and nonce <= prev:
                    f["nonce"]["regressions"] += 1
                    note("nonce", f"record {i} (seq {seq}): {sender[:20]} "
                                  f"nonce {nonce} <= last {prev}")
                last_nonce[sender] = nonce if prev is None else max(prev, nonce)
    return f


def selftest():
    td = tempfile.mkdtemp(prefix="audit-chain-")

    def wf(name, lines):
        p = os.path.join(td, name)
        with open(p, "w", encoding="utf-8") as fh:
            fh.write("\n".join(lines) + "\n")
        return p

    r1 = {"seq": 1, "ts": "2026-08-29T01:00:00Z", "from": "did:key:zA",
          "text": "alpha", "nonce": 100}
    r2 = {"seq": 2, "ts": "2026-08-29T01:00:01Z", "from": "did:key:zB",
          "text": "beta", "nonce": 700}
    r3 = {"seq": 3, "ts": "2026-08-29T01:00:02Z", "from": "did:key:zA",
          "text": "gamma", "nonce": 101}
    r4 = {"seq": 4, "ts": "2026-08-29T01:00:03Z", "from": "did:key:zB",
          "text": "delta", "nonce": 701}
    lines = [json.dumps(r) for r in (r1, r2, r3, r4)]
    p = wf("clean.jsonl", lines)

    # canonical stability: key order / spacing must not move the leaf
    d1, _, ok1 = leaf_digest(json.dumps(r1))
    d2, _, ok2 = leaf_digest(json.dumps({k: r1[k] for k in reversed(r1)},
                                        indent=2))
    assert ok1 and ok2 and d1 == d2
    assert leaf_digest(json.dumps(r2))[0] != d1

    seal = make_seal(p, "clean.jsonl")
    assert seal["records"] == 4 and seal["unparsable"] == 0
    assert len(seal["chain_head"]) == 64 and len(seal["merkle_root"]) == 64
    ok, v = verify_against(p, seal)
    assert ok and v["first_divergence"] is None, v

    # merkle shapes: odd leaf count must still verify; roots must differ
    p3 = wf("odd.jsonl", lines[:3])
    seal3 = make_seal(p3)
    assert seal3["records"] == 3
    assert verify_against(p3, seal3)[0]
    assert seal3["merkle_root"] != seal["merkle_root"]

    # empty log: genesis head, empty-prefix verify round-trips
    p0 = wf("empty.jsonl", [])
    seal0 = make_seal(p0)
    assert seal0["records"] == 0 and seal0["chain_head"] == GENESIS
    assert verify_against(p0, seal0)[0]

    # text edit at record 1 -> first divergence exactly index 1
    pt = wf("tampered.jsonl", [lines[0], json.dumps(dict(r2, text="evtl"))]
            + lines[2:])
    ok, v = verify_against(pt, seal)
    assert not ok and v["first_divergence"]["index"] == 1, v
    assert v["first_divergence"]["seq"] == 2

    # deletion of record 2 -> shift detected at index 2
    pd = wf("deleted.jsonl", lines[:2] + lines[3:])
    ok, v = verify_against(pd, seal)
    assert not ok and v["first_divergence"]["index"] == 2, v

    # swap records 0 and 1 -> divergence at index 0
    pr = wf("reordered.jsonl", [lines[1], lines[0]] + lines[2:])
    ok, v = verify_against(pr, seal)
    assert not ok and v["first_divergence"]["index"] == 0, v

    # insertion -> divergence at the insertion index
    pi = wf("inserted.jsonl", lines[:2] + [json.dumps(dict(r1, seq=9))] + lines[2:])
    ok, v = verify_against(pi, seal)
    assert not ok and v["first_divergence"]["index"] == 2, v

    # truncation -> prefixes agree, count check fails, kind names it
    ptr = wf("truncated.jsonl", lines[:3])
    ok, v = verify_against(ptr, seal)
    assert not ok and v["first_divergence"]["kind"] == "log ends early (records removed)", v

    # integrity: dup seq, gap, reorder, ts regression, nonce replay
    bad = [
        {"seq": 5, "ts": "2026-08-29T02:00:00Z", "from": "zC", "nonce": 1},
        {"seq": 5, "ts": "2026-08-29T02:00:01Z", "from": "zC", "nonce": 2},
        {"seq": 9, "ts": "2026-08-29T02:00:02Z", "from": "zC", "nonce": 3},
        {"seq": 8, "ts": "2026-08-29T01:59:00Z", "from": "zC", "nonce": 3},
        {"seq": 10, "ts": "garbage", "from": "zC", "nonce": 4},
    ]
    pb = wf("bad.jsonl", [json.dumps(r) for r in bad] + ["not json"])
    f = integrity_of(pb)
    assert f["seq"]["duplicates"] == 1 and f["seq"]["gaps"] == 2
    assert f["seq"]["reorders"] == 1, f["seq"]
    assert f["ts"]["missing_or_invalid"] == 1 and f["ts"]["regressions"] == 1
    assert f["nonce"]["regressions"] == 1, f["nonce"]
    fc = integrity_of(p)
    assert all(fc[k][c] == 0 for k in ("seq", "ts", "nonce")
               for c in fc[k] if isinstance(fc[k][c], int)), fc

    # unparsable lines join the chain (raw-byte leaf) and are tamper-checked
    pu = wf("mixed.jsonl", [lines[0], "not json", lines[1]])
    su = make_seal(pu)
    assert su["unparsable"] == 1 and verify_against(pu, su)[0]
    pu2 = wf("mixed2.jsonl", [lines[0], "NOT json", lines[1]])
    ok, v = verify_against(pu2, su)
    assert not ok and v["first_divergence"]["index"] == 1, v

    print("OK: audit-chain self-test passed "
          f"({seal['records']} recs, head {seal['chain_head'][:12]}…)")


def main(argv=None):
    ap = argparse.ArgumentParser(prog="audit-chain")
    ap.add_argument("--self-test", action="store_true",
                    help="run built-in verification")
    sub = ap.add_subparsers(dest="cmd")
    for name, help_ in (("seal", "hash a log into a tamper-evident seal"),
                        ("verify", "check a log against its seal"),
                        ("report", "seq/ts/nonce integrity findings")):
        sp = sub.add_parser(name, help=help_)
        sp.add_argument("file")
        sp.add_argument("--json", action="store_true",
                        help="machine-readable output")
    sub.choices["seal"].add_argument("--out", help="seal path "
                                     "(default FILE.seal.json)")
    sub.choices["verify"].add_argument("--seal", help="seal path "
                                       "(default FILE.seal.json)")
    args = ap.parse_args(argv)

    if args.self_test or args.cmd is None:
        selftest()
        return

    default_seal = args.file + ".seal.json"
    if args.cmd == "seal":
        out = args.out or default_seal
        s = make_seal(args.file)
        with open(out, "w", encoding="utf-8") as fh:
            json.dump(s, fh)
        print(f"sealed {s['records']} records ({s['unparsable']} unparsable) "
              f"head={s['chain_head']} merkle={s['merkle_root']} -> {out}")
        return
    if args.cmd == "verify":
        spath = args.seal or default_seal
        if not os.path.exists(spath):
            print(f"audit-chain: no seal at {spath} (run: seal first)",
                  file=sys.stderr)
            raise SystemExit(2)
        with open(spath, encoding="utf-8") as fh:
            ok, v = verify_against(args.file, json.load(fh))
        if args.json:
            print(json.dumps(v, ensure_ascii=False))
        elif ok:
            print(f"OK: {v['records']} records match seal "
                  f"(chain+merkle+count verified)")
        else:
            d = v["first_divergence"]
            print(f"TAMPERED: {json.dumps(d, ensure_ascii=False)}")
            print(f"checks: {v['checks']}")
        raise SystemExit(0 if ok else 1)
    f = integrity_of(args.file)
    if args.json:
        print(json.dumps(f, ensure_ascii=False))
        return
    print(f"{f['records']} records ({f['unparsable']} unparsable)")
    for kind in ("seq", "ts", "nonce"):
        part = f[kind]
        counts = " ".join(f"{k}={v}" for k, v in part.items()
                          if isinstance(v, int))
        print(f"{kind}: {counts}")
        for ex in part["examples"]:
            print(f"  - {ex}")
    return


if __name__ == "__main__":
    # bare call (not sys.exit(main())) so exit codes are raised inside
    # main() and module-level verification hooks appended after this
    # block still execute on the success path
    try:
        main()
    except BrokenPipeError:
        # downstream closed early (head/grep -m); quiet success
        sys.stdout.close()
        raise SystemExit(0)
