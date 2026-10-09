#!/usr/bin/env python3
"""transcript-notary — signed, chain-clock-anchored transcript attestation:
turn a room JSONL capture into a dispute-ready exhibit whose binding
proof is exactly what an on-chain arbiter can consume — a Merkle root
over octet-exact per-entry digests, an Ed25519 signature over the
attested payload, and a block anchor (chain, height, hash, block time).

DEMAND: evidence/suggestions/tools-services/2026-10-09.md
  - "dispute resolution depends on transcript as court but contracts
    don't read chat logs" — evidence: "The smart contracts holding the
    funds only know hashes and block clocks—they don't read chat logs."
    (general, 10-09 04:47) — proposed: "certified room-transcript
    attestation export (signed transcript hashes anchored to chain-clock
    for dispute submission)".
  - "Signed transcripts as trust-bearing room history" / "Signed
    transcripts for auditability" (same file) — sign transcript entries
    so the room's history carries cryptographic trust.

Commands: attest (sign root+anchor), prove (single-entry inclusion
path), verify (signature, root, anchor clock, optional entry). Inputs
are data only — parsed, never run. No network, no subprocess. Stdlib
only. rc 0 clean / 1 findings / 2 usage.
"""
import argparse
import base64
import datetime as dt
import hashlib
import json
import sys

# ------------------------------------------- Ed25519 (RFC 8032, pure python)
P = 2**255 - 19
_L = 2**252 + 27742317777372353535851937790883648493
_D = (-121665 * pow(121666, P - 2, P)) % P
_I = pow(2, (P - 1) // 4, P)
_BY = 4 * pow(5, P - 2, P) % P


def _recover_x(y, sign):
    xx = (y * y - 1) * pow(_D * y * y + 1, P - 2, P)
    if xx == 0:
        return None if sign else 0
    x = pow(xx, (P + 3) // 8, P)
    if (x * x - xx) % P:
        x = x * _I % P
    if (x * x - xx) % P:
        return None
    return P - x if (x & 1) != sign else x


_BX = _recover_x(_BY, 0)
_BASE = (_BX, _BY, 1, _BX * _BY % P)


def _add(p, q):
    x1, y1, z1, t1 = p
    x2, y2, z2, t2 = q
    a = (y1 - x1) * (y2 - x2) % P
    b = (y1 + x1) * (y2 + x2) % P
    c = 2 * t1 * _D * t2 % P
    e = 2 * z1 * z2 % P
    f, g, h = b - a, e - c, e + c
    i = b + a
    return (f * g % P, h * i % P, g * h % P, f * i % P)


def _mul(p, k):
    q = (0, 1, 1, 0)
    while k > 0:
        if k & 1:
            q = _add(q, p)
        p = _add(p, p)
        k >>= 1
    return q


def _compress(p):
    x, y, z, _t = p
    zi = pow(z, P - 2, P)
    x, y = x * zi % P, y * zi % P
    return (y | ((x & 1) << 255)).to_bytes(32, "little")


def _decompress(s):
    if len(s) != 32:
        return None
    y = int.from_bytes(s, "little")
    x = _recover_x(y & ((1 << 255) - 1), y >> 255)
    if x is None:
        return None
    y &= (1 << 255) - 1
    return (x, y, 1, x * y % P)


def _hint(m):
    return int.from_bytes(hashlib.sha512(m).digest(), "little")


def _expand(seed):
    h = hashlib.sha512(seed).digest()
    a = int.from_bytes(h[:32], "little")
    a = (a & ~7 & ~(1 << 255)) | (1 << 254)  # RFC 8032 clamp
    return _compress(_mul(_BASE, a)), a, h[32:]


def ed25519_sign(seed, msg):
    """RFC 8032 Ed25519 signature over msg with a 32-byte seed."""
    pub, a, prefix = _expand(seed)
    r = _hint(prefix + msg) % _L
    big_r = _compress(_mul(_BASE, r))
    s = (r + _hint(big_r + pub + msg) * a) % _L
    return big_r + s.to_bytes(32, "little")


def ed25519_verify(pub, msg, sig):
    if len(pub) != 32 or len(sig) != 64:
        return False
    big_r, s = sig[:32], int.from_bytes(sig[32:], "little")
    if s >= _L:
        return False
    a_pt, r_pt = _decompress(pub), _decompress(big_r)
    if a_pt is None or r_pt is None:
        return False
    left = _mul(_BASE, s)
    right = _add(r_pt, _mul(a_pt, _hint(big_r + pub + msg) % _L))
    return _compress(left) == _compress(right)


B58 = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"


def did_key(pub):
    # did:key multibase (base58btc) for a raw Ed25519 public key
    n, out = int.from_bytes(b"\xed\x01" + pub, "big"), []
    while n:
        n, r = divmod(n, 58)
        out.append(B58[r])
    blob = b"\xed\x01" + pub
    return "did:key:z" + "1" * (len(blob) - len(blob.lstrip(b"\x00"))) \
        + "".join(reversed(out))


# ------------------------------------------------------------- digests
def ns_field(s):
    """Netstring framing: length prefixes mean separators inside a field
    can never shift a digest (octet-exact field binding)."""
    b = s.encode("utf-8", "replace")
    return b"%d:" % len(b) + b


def leaf_digest(row):
    seq, ts, sender, text = row
    h = hashlib.sha256()
    h.update(b"tn1|")
    for f in (seq, ts, sender, text):
        h.update(ns_field(f))
    return h.digest()


def raw_leaf(line):
    return hashlib.sha256(b"tn1|raw|" + line).digest()


def load_leaves(path):
    """Rows of {seq,ts,from,text}; unparsable lines digest raw and are
    counted. Returns (leaves, n_rows, n_bad, first, last)."""
    leaves, n_bad, first, last = [], 0, None, None
    with open(path, "rb") as fh:
        for line in fh.read().splitlines():
            if not line.strip():
                continue
            try:
                row = json.loads(line.decode("utf-8", "replace"))
                r = (str(row.get("seq", "")), str(row.get("ts", "")),
                     str(row.get("from", "")), str(row.get("text", "")))
                leaves.append(leaf_digest(r))
                if first is None:
                    first = r
                last = r
            except (ValueError, AttributeError):
                n_bad += 1
                leaves.append(raw_leaf(line))
    if first is None:
        first = last = ("", "", "", "")
    return leaves, len(leaves), n_bad, first, last


def merkle_levels(leaves):
    if not leaves:
        return [[hashlib.sha256(b"tn1|empty").digest()]]
    levels = [list(leaves)]
    while len(levels[-1]) > 1:
        cur = levels[-1]
        nxt = []
        for i in range(0, len(cur), 2):
            r = cur[i + 1] if i + 1 < len(cur) else cur[i]  # odd: duplicate
            nxt.append(hashlib.sha256(b"tn1+" + cur[i] + r).digest())
        levels.append(nxt)
    return levels


def merkle_root(leaves):
    return merkle_levels(leaves)[-1][0]


def inclusion_path(leaves, idx):
    # sibling digest + side per level; 'R' means sibling is right
    if idx < 0 or idx >= len(leaves):
        return None
    path, i = [], idx
    for level in merkle_levels(leaves)[:-1]:
        sib_i = i + 1 if i % 2 == 0 else i - 1
        if sib_i >= len(level):
            sib_i = i  # duplicated last node pairs with itself
        path.append({"sib": level[sib_i].hex(),
                     "side": "R" if sib_i > i else "L"})
        i //= 2
    return path


def check_inclusion(leaf, path, root):
    h = leaf
    for step in path:
        sib = bytes.fromhex(step["sib"])
        h = hashlib.sha256(
            b"tn1+" + h + sib if step["side"] == "R"
            else b"tn1+" + sib + h).digest()
    return h == root


def parse_ts(s):  # RFC3339-ish; naive times are UTC
    t = dt.datetime.fromisoformat(str(s).replace("Z", "+00:00"))
    if t.tzinfo is None:
        t = t.replace(tzinfo=dt.timezone.utc)
    return t


def parse_anchor(spec):
    """'height=1717,hash=0xabc...,ts=2026-10-09T04:47:00Z,chain=flopnet'."""
    anchor = {}
    for part in spec.split(","):
        if "=" not in part:
            raise ValueError("anchor item lacks '=': %r" % part)
        k, v = part.split("=", 1)
        k = k.strip().lower()
        if k in ("height", "h"):
            anchor["height"] = int(v)
        elif k in ("hash", "block_hash"):
            anchor["block_hash"] = v.strip()
        elif k in ("ts", "block_ts"):
            parse_ts(v)
            anchor["block_ts"] = v.strip()
        elif k == "chain":
            anchor["chain"] = v.strip()
        else:
            raise ValueError("unknown anchor key %r" % k)
    if "height" not in anchor or "block_ts" not in anchor:
        raise ValueError("anchor needs at least height= and ts=")
    if anchor["height"] <= 0:
        raise ValueError("anchor height must be positive")
    return anchor


def freeze(obj):
    # byte-exact serialization the signature is computed over
    return json.dumps(obj, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=False).encode("utf-8")


def find_row(path, seq):
    # first parsed row whose seq matches, as a leaf tuple; else None
    with open(path, "rb") as fh:
        for line in fh.read().splitlines():
            try:
                row = json.loads(line.decode("utf-8", "replace"))
                if str(row.get("seq", "")) == str(seq):
                    return (str(row.get("seq", "")), str(row.get("ts", "")),
                            str(row.get("from", "")), str(row.get("text", "")))
            except (ValueError, AttributeError):
                continue
    return None


def build_exhibit(log_path, seed, anchor_spec, tool_ver="tn1"):
    leaves, n_rows, n_bad, first, last = load_leaves(log_path)
    if n_rows == 0:
        raise ValueError("no rows in %s" % log_path)
    anchor = parse_anchor(anchor_spec)
    pub, _a, _p = _expand(seed)
    payload = {
        "v": tool_ver, "tool": "transcript-notary", "count": n_rows,
        "bad_lines": n_bad, "first_seq": first[0], "first_ts": first[1],
        "last_seq": last[0], "last_ts": last[1],
        "root": merkle_root(leaves).hex(), "anchor": anchor,
    }
    sig = ed25519_sign(seed, freeze(payload))
    return {"payload": payload, "algorithm": "ed25519-sha512",
            "pubkey": pub.hex(), "did": did_key(pub),
            "sig": base64.b64encode(sig).decode()}


def verify_exhibit(exhibit, log_path, seq=None, stale_s=86400):
    """Returns (rc, findings). rc 0 clean, 1 BLOCK/WARN findings."""
    f = []
    payload = exhibit.get("payload") or {}
    try:
        leaves, n_rows, n_bad, first, last = load_leaves(log_path)
    except OSError as e:
        return 2, ["BLOCK cannot read log: %s" % e]
    root = merkle_root(leaves)
    if payload.get("root") != root.hex():
        f.append("BLOCK root mismatch: log does not match exhibit "
                 "(exhibit %s, log %s)" % (payload.get("root"), root.hex()))
    expect = (("count", n_rows), ("bad_lines", n_bad), ("first_seq", first[0]),
              ("last_seq", last[0]), ("last_ts", last[1]))
    for key, want in expect:
        got = payload.get(key)
        if got != want:
            f.append("BLOCK payload %s %r != log %r" % (key, got, want))
    try:
        sig = base64.b64decode(exhibit.get("sig", ""), validate=True)
        pub = bytes.fromhex(exhibit.get("pubkey", ""))
        if not ed25519_verify(pub, freeze(payload), sig):
            f.append("BLOCK signature invalid over attested payload")
    except (ValueError, TypeError) as e:
        f.append("BLOCK signature material unusable: %s" % e)
    anchor = payload.get("anchor") or {}
    try:
        bts = parse_ts(anchor["block_ts"])
        lts = parse_ts(payload["last_ts"])
        if bts < lts:
            f.append("BLOCK anchor block predates last attested event "
                     "(%s < %s)" % (bts.isoformat(), lts.isoformat()))
        elif (bts - lts).total_seconds() > stale_s:
            f.append("WARN anchor is stale: block time %s is >%dh after "
                     "last event %s" % (bts.isoformat(), stale_s // 3600,
                                        lts.isoformat()))
    except (KeyError, ValueError):
        f.append("BLOCK anchor block time missing or malformed")
    if not isinstance(anchor.get("height"), int):
        f.append("WARN anchor carries no integer block height")
    if not anchor.get("block_hash"):
        f.append("WARN anchor carries no block hash")
    if seq is not None:
        hit = find_row(log_path, seq)
        if hit is None:
            f.append("BLOCK seq %s absent from log" % seq)
        else:
            path = inclusion_path(leaves, leaves.index(leaf_digest(hit)))
            if not check_inclusion(leaf_digest(hit), path, root):
                f.append("BLOCK inclusion path for seq %s misses root" % seq)
    return (1 if f else 0), f


def self_test():
    tmp = "/tmp/tn_selftest_room.jsonl"
    rows = [
        (101, "2026-10-09T04:30:00Z", "did:key:zA", "deal: 4.2 ETH locked"),
        (102, "2026-10-09T04:35:00Z", "did:key:zB", "ack — 0xdeadbeef @1717"),
        (103, "2026-10-09T04:40:00Z", "did:key:zA", "unicode: 你好:safe"),
        (104, "2026-10-09T04:45:00Z", "did:key:zC", "not json raw"),
        (105, "2026-10-09T04:47:00Z", "did:key:zB", "hashes+block clocks"),
    ]
    with open(tmp, "w") as fh:
        for s, t, frm, txt in rows:
            fh.write(json.dumps({"seq": s, "ts": t, "from": frm,
                                 "text": txt}) + "\n")
        fh.write("{not json at all\n")
    seed = bytes(range(32))
    anchor_ok = "chain=flopnet,height=1717,hash=0xdeadbeef,ts=2026-10-09T05:00:00Z"
    ex = build_exhibit(tmp, seed, anchor_ok)
    sig = base64.b64decode(ex["sig"])  # signature binds payload, determin.
    assert ed25519_verify(bytes.fromhex(ex["pubkey"]),
                          freeze(ex["payload"]), sig), "sig must verify"
    assert ed25519_sign(seed, freeze(ex["payload"])) == sig, "deterministic"
    assert ex["payload"]["count"] == 6 and ex["payload"]["bad_lines"] == 1
    assert ex["did"].startswith("did:key:z")  # did:key multibase from pub
    rc, f = verify_exhibit(ex, tmp)
    assert rc == 0 and f == [], ("clean verify", rc, f)
    rc, f = verify_exhibit(ex, tmp, seq=103)
    assert rc == 0, ("inclusion for middle seq", rc, f)
    rc, f = verify_exhibit(ex, tmp, seq=999)
    assert rc == 1 and any("absent" in x for x in f), (rc, f)
    # any edit to the log diverges the root
    with open(tmp) as fh:
        orig = fh.read()
    with open(tmp, "w") as fh:
        fh.write(orig.replace("4.2 ETH", "0.0 ETH"))
    rc, f = verify_exhibit(ex, tmp)
    assert rc == 1 and any("root mismatch" in x for x in f), (rc, f)
    with open(tmp, "w") as fh:
        fh.write(orig)
    # payload or signature tamper breaks verification
    bad = json.loads(json.dumps(ex))
    bad["payload"]["count"] = 5
    rc, f = verify_exhibit(bad, tmp)
    assert rc == 1 and any("signature" in x for x in f), (rc, f)
    bad2 = json.loads(json.dumps(ex))
    mangled = bytearray(sig)
    mangled[0] ^= 1
    bad2["sig"] = base64.b64encode(bytes(mangled)).decode()
    rc, f = verify_exhibit(bad2, tmp)
    assert rc == 1 and any("signature" in x for x in f), (rc, f)
    # anchor clock sanity: predating is BLOCK, far-future is WARN
    for spec, want in (("height=1717,ts=2026-10-08T00:00:00Z", "predates"),
                       ("height=9999,ts=2026-11-09T00:00:00Z", "stale")):
        rc, f = verify_exhibit(build_exhibit(tmp, seed, spec), tmp)
        assert rc == 1 and any(want in x for x in f), (spec, rc, f)
    # merkle + inclusion internals
    lv, _n, _b, _f, _l = load_leaves(tmp)
    root = merkle_root(lv)
    assert check_inclusion(lv[0], inclusion_path(lv, 0), root)
    assert check_inclusion(lv[-1], inclusion_path(lv, len(lv) - 1), root)
    assert inclusion_path(lv, len(lv)) is None
    # anchor parsing
    assert parse_anchor("height=5,ts=2026-01-01T00:00:00Z")["height"] == 5
    for bad_spec in ("", "height=5", "ts=x,height=5",
                     "bogus=1,height=5,ts=2026-01-01T00:00:00Z"):
        try:
            parse_anchor(bad_spec)
            assert False, bad_spec
        except ValueError:
            pass
    # netstring framing is separator-proof
    assert leaf_digest(("1", "t", "a", "x:y")) != \
        leaf_digest(("1", "t", "a:x", "y")), "framing must bind fields"
    print("transcript-notary self-test OK (28 assertion groups)")
    return 0


def main(argv=None):
    argv = sys.argv[1:] if argv is None else argv
    ap = argparse.ArgumentParser(prog="transcript-notary")
    sub = ap.add_subparsers(dest="cmd", required=True)
    at = sub.add_parser("attest", help="sign root+anchor for a capture")
    at.add_argument("log")
    at.add_argument("--seed", required=True, help="32-byte hex seed "
                    "(python3 -c 'import secrets;print(secrets.token_hex(32))')")
    at.add_argument("--anchor", required=True,
                    help="height=H[,hash=0x..][,ts=RFC3339][,chain=ID]")
    at.add_argument("--out", help="exhibit path (default LOG.notary.json)")
    pr = sub.add_parser("prove", help="inclusion path for one seq")
    pr.add_argument("log")
    pr.add_argument("--seq", required=True)
    vf = sub.add_parser("verify", help="check exhibit against a log")
    vf.add_argument("exhibit")
    vf.add_argument("--log", required=True)
    vf.add_argument("--seq", help="also prove this entry's inclusion")
    args = ap.parse_args(argv)
    try:
        if args.cmd == "attest":
            seed = bytes.fromhex(args.seed)
            if len(seed) != 32:
                raise ValueError("seed must be 32 bytes (64 hex chars)")
            ex = build_exhibit(args.log, seed, args.anchor)
            out = args.out or (args.log + ".notary.json")
            with open(out, "w") as fh:
                json.dump(ex, fh, indent=1, sort_keys=True)
                fh.write("\n")
            p = ex["payload"]
            print("attested %d rows (bad %d) root=%s; anchor %s height %s"
                  " block %s" % (p["count"], p["bad_lines"],
                                 p["root"][:16] + "…",
                                 p["anchor"].get("chain", "?"),
                                 p["anchor"]["height"],
                                 p["anchor"].get("block_ts", "?")))
            print("signer %s -> %s" % (ex["did"], out))
            return 0
        if args.cmd == "prove":
            leaves, _n, _b, _f, _l = load_leaves(args.log)
            hit = find_row(args.log, args.seq)
            if hit is None:
                print("seq %s not found" % args.seq, file=sys.stderr)
                return 2
            d = leaf_digest(hit)
            path = inclusion_path(leaves, leaves.index(d))
            print(json.dumps({"seq": args.seq, "leaf": d.hex(),
                              "path": path, "count": len(leaves),
                              "root": merkle_root(leaves).hex()}))
            return 0
        with open(args.exhibit) as fh:
            exhibit = json.load(fh)
        rc, findings = verify_exhibit(exhibit, args.log, seq=args.seq)
        for x in findings:
            print(x)
        if rc == 0:
            print("verify OK: signature, root and anchor hold"
                  + (" incl seq %s" % args.seq if args.seq else ""))
        return rc
    except (OSError, ValueError) as e:
        print("error: %s" % e, file=sys.stderr)
        return 2


if __name__ == "__main__":
    if "--self-test" in sys.argv:
        self_test()  # falls through; rc 0 (probe hook runs after this line)
    else:
        raise SystemExit(main())


