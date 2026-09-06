#!/usr/bin/env python3
"""offline-verify — dependency-free offline Ed25519 sign/verify SDK + CLI
for audit artifacts: proves WHO authored a record, with no network.

DEMAND: evidence/suggestions/tools-services/2026-08-31.md
  - "提供离线验证工具或SDK，无需实时在线连接即可验证Ed25519签名和
    审计轨迹" — an offline tool/SDK that verifies Ed25519 signatures and
    audit trails without a live connection; proposed: "发布一个轻量级
    离线验证库或命令行工具，集成到现有hermes-tools中" — this IS that
    tool: pure stdlib, zero network, zero third-party libraries.
  - "支持批量代理审计轨迹验证，以处理大规模的'代理经济'交易验证" —
    batch verification at agent-economy scale (batch mode, --workers N).
  Also answers the standing "quem audita?" (2026-08-26/27 runs): an
  auditor publishes an attestation, anyone verifies offline — no key
  server, no trust in the publisher. Sibling tools: audit-chain.py seals
  WHAT the bytes are (hash chain, no identity); this proves WHO signed.

What it does (RFC 8032 Ed25519, pure Python — hashlib.sha512 only):
  - keygen: random seed (os.urandom) → did:key:z6Mk… identity (multibase
    base58btc of ed019d01 prefix + key, the room senders' encoding); seed
    file written chmod 600.
  - sign MSG --key SEED: deterministic RFC 8032 signature, base64url.
  - verify MSG --sig S --signer DID: offline check. Rejects non-canonical
    S (S ≥ L), non-canonical/off-curve/wrong-length keys and sigs,
    non-ed019d01 did:keys, bad base58/base64url. Exit 0 ok / 1 fail.
  - attest FILE --key SEED [--ts T]: signs {v, alg, signer, file, sha256,
    bytes, ts?} over canonical JSON → FILE.attest.json; `verify FILE
    --attest A` re-hashes FILE offline, checks digest + signature — later
    edits are caught and attributed.
  - batch BUNDLE.jsonl [--workers N] [--json]: one {msg|msg_b64, sig,
    signer} per line; per-item verdicts, ok/fail totals, items/s rate;
    exit 0 all-verified / 1 any-fail.
  Inputs are data, never interpreted; no network calls of any kind.
  Note: pure-Python group ops are not constant-time — built for offline verification; high-volume production signing belongs in libsodium.

Usage:
  python3 offline-verify.py keygen --out my.seed
  python3 offline-verify.py sign report.json --key my.seed
  python3 offline-verify.py verify report.json --sig SIG --signer did:key:z6Mk…
  python3 offline-verify.py attest lobby.jsonl --key my.seed   # then:
  python3 offline-verify.py verify lobby.jsonl --attest lobby.jsonl.attest.json
  python3 offline-verify.py batch bundle.jsonl --workers 4

VERIFY: self-test — python3 offline-verify.py --self-test
  RFC 8032 official vectors (sign == vector, verify ok); tampered msg /
  sig / non-canonical S / non-canonical key rejected; base58 + did:key
  round-trips incl. leading zeros and non-ed019d01 prefixes; keygen →
  sign → verify end-to-end; attest → verify round-trip, artifact-edit
  and wrong-signer detection; batch with an injected bad line (exact
  ok/fail counts, exit 1), --workers 2 equivalence, --json verdicts.
  Asserts, prints OK.
"""
import argparse
import base64
import hashlib
import json
import os
import sys
import tempfile
import time

_P = 2 ** 255 - 19
_L = 2 ** 252 + 27742317777372353535851937790883648493
_D = (-121665 * pow(121666, _P - 2, _P)) % _P
_I = pow(2, (_P - 1) // 4, _P)


def _inv(x):
    return pow(x, _P - 2, _P)


def _xrecover(y):
    xx = (y * y - 1) * _inv(_D * y * y + 1)
    x = pow(xx, (_P + 3) // 8, _P)
    if (x * x - xx) % _P != 0:
        x = x * _I % _P
    if x % 2 != 0:
        x = _P - x
    return x


_BY = 4 * _inv(5) % _P
_B = (_xrecover(_BY), _BY, 1, _xrecover(_BY) * _BY % _P)
_IDENT = (0, 1, 1, 0)


def _add(p, q):
    x1, y1, z1, t1 = p
    x2, y2, z2, t2 = q
    a = (y1 - x1) * (y2 - x2) % _P
    b = (y1 + x1) * (y2 + x2) % _P
    c = t1 * 2 * _D * t2 % _P
    d = z1 * 2 * z2 % _P
    e, f, g, h = b - a, d - c, d + c, b + a
    return (e * f % _P, g * h % _P, f * g % _P, e * h % _P)


def _mul(p, e):
    q = _IDENT
    while e > 0:
        if e & 1:
            q = _add(q, p)
        p = _add(p, p)
        e >>= 1
    return q


def _compress(p):
    zi = _inv(p[2])
    x = p[0] * zi % _P
    y = p[1] * zi % _P
    return int.to_bytes(y | ((x & 1) << 255), 32, "little")


def _decompress(s):
    if len(s) != 32:
        raise ValueError("point must be 32 bytes")
    y = int.from_bytes(s, "little")
    sign = y >> 255
    y &= (1 << 255) - 1
    if y >= _P:
        raise ValueError("non-canonical y")
    x = _xrecover(y)
    if x & 1 != sign:
        x = _P - x
    p = (x, y, 1, x * y % _P)
    if (-x * x + y * y - 1 - _D * x * x * y * y) % _P != 0:
        raise ValueError("off curve")
    return p


def _expand(seed):
    h = hashlib.sha512(seed).digest()
    a = int.from_bytes(h[:32], "little")
    a &= ~7
    a &= (1 << 255) - 1
    a |= 1 << 254
    return a, h[32:]


def public_key(seed):
    """32-byte Ed25519 public key for a 32-byte seed."""
    return _compress(_mul(_B, _expand(seed)[0]))


def sign(seed, msg):
    """RFC 8032 deterministic signature (64 bytes) over msg bytes."""
    a, prefix = _expand(seed)
    a_b = _compress(_mul(_B, a))
    r = int.from_bytes(hashlib.sha512(prefix + msg).digest(), "little") % _L
    r_b = _compress(_mul(_B, r))
    k = int.from_bytes(hashlib.sha512(r_b + a_b + msg).digest(), "little") % _L
    s = (r + k * a) % _L
    return r_b + int.to_bytes(s, 32, "little")


def verify(pub, msg, sig):
    """True iff (pub, msg, sig) is a valid RFC 8032 Ed25519 signature."""
    if len(pub) != 32 or len(sig) != 64:
        return False
    s = int.from_bytes(sig[32:], "little")
    if s >= _L:
        return False
    try:
        a_pt = _decompress(pub)
        r_pt = _decompress(sig[:32])
    except ValueError:
        return False
    k = int.from_bytes(hashlib.sha512(sig[:32] + pub + msg).digest(),
                       "little") % _L
    lhs = _mul(_B, s)
    rhs = _add(r_pt, _mul(a_pt, k))
    return _compress(lhs) == _compress(rhs)


B58 = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
B58_REV = {c: i for i, c in enumerate(B58)}
MULTICODEC_ED25519 = b"\xed\x01"


def b58encode(raw):
    n = int.from_bytes(raw, "big")
    out = ""
    while n:
        n, r = divmod(n, 58)
        out = B58[r] + out
    return "1" * (len(raw) - len(raw.lstrip(b"\x00"))) + out


def b58decode(s):
    n = 0
    for c in s:
        if c not in B58_REV:
            raise ValueError("bad base58 char %r" % c)
        n = n * 58 + B58_REV[c]
    raw = n.to_bytes((n.bit_length() + 7) // 8, "big")
    return b"\x00" * (len(s) - len(s.lstrip("1"))) + raw


def did_from_pub(pub):
    return "did:key:z" + b58encode(MULTICODEC_ED25519 + pub)


def pub_from_did(did):
    if not did.startswith("did:key:z"):
        raise ValueError("not a base58btc did:key: %s" % did[:32])
    raw = b58decode(did[len("did:key:z"):])
    if len(raw) != 34 or raw[:2] != MULTICODEC_ED25519:
        raise ValueError("did:key is not ed25519-pub (ed019d01)")
    return raw[2:]


def b64u(raw):
    return base64.urlsafe_b64encode(raw).decode().rstrip("=")


def b64u_decode(s):
    pad = "=" * ((4 - len(s) % 4) % 4)
    return base64.urlsafe_b64decode(s + pad)


def canonical(obj):
    return json.dumps(obj, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=False).encode()


def sha256_file(path):
    h = hashlib.sha256()
    n = 0
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
            n += len(chunk)
    return h.hexdigest(), n


def read_seed(path):
    try:
        with open(path) as f:
            seed = bytes.fromhex(f.read().strip())
    except OSError as e:
        sys.exit("error: cannot read seed file: %s" % e)
    if len(seed) != 32:
        sys.exit("error: seed file must hold 64 hex chars (32 bytes)")
    return seed


def cmd_keygen(a):
    seed = os.urandom(32)
    print(did_from_pub(public_key(seed)))
    if a.out and a.out != "-":
        fd = os.open(a.out, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with os.fdopen(fd, "w") as f:
            f.write(seed.hex() + "\n")
        print("seed written to %s (keep secret)" % a.out, file=sys.stderr)


def cmd_sign(a):
    seed = read_seed(a.key)
    msg = open(a.msg, "rb").read() if a.msg != "-" else sys.stdin.buffer.read()
    print(b64u(sign(seed, msg)))


def check_one(pub, msg, sig):
    if len(sig) != 64:
        return "bad sig length"
    return None if verify(pub, msg, sig) else "signature invalid"


def cmd_verify(a):
    if a.attest:
        att = json.load(open(a.attest))
        body = {k: v for k, v in att.items() if k != "sig"}
        try:
            pub = pub_from_did(att["signer"])
        except ValueError as e:
            sys.exit("FAIL attestation signer: %s" % e)
        reason = check_one(pub, canonical(body), b64u_decode(att["sig"]))
        if reason:
            sys.exit("FAIL attestation signature: %s" % reason)
        digest, size = sha256_file(a.msg)
        if digest != att.get("sha256") or size != att.get("bytes"):
            sys.exit("FAIL artifact digest mismatch: file changed since "
                     "attestation (sha256 %s, %d bytes)" % (digest, size))
        print("OK signer=%s sha256=%s verified offline" %
              (att["signer"], digest))
        return
    try:
        pub = pub_from_did(a.signer)
    except ValueError as e:
        sys.exit("FAIL signer: %s" % e)
    msg = open(a.msg, "rb").read() if a.msg != "-" else sys.stdin.buffer.read()
    reason = check_one(pub, msg, b64u_decode(a.sig))
    if reason:
        sys.exit("FAIL %s" % reason)
    print("OK signature by %s verified offline" % a.signer)


def cmd_attest(a):
    seed = read_seed(a.key)
    digest, size = sha256_file(a.file)
    att = {"v": 1, "alg": "ed25519", "signer": did_from_pub(public_key(seed)),
           "file": os.path.basename(a.file), "sha256": digest, "bytes": size}
    if a.ts:
        att["ts"] = a.ts
    att["sig"] = b64u(sign(seed, canonical(att)))
    out = a.out or (a.file + ".attest.json")
    with open(out, "w") as f:
        json.dump(att, f, indent=1, sort_keys=True)
        f.write("\n")
    print("%s attested by %s (sha256 %s…)" % (att["file"], att["signer"], digest[:16]))


def _verify_item(item):
    label, msg, sig, signer = item
    try:
        pub = pub_from_did(signer)
        raw = b64u_decode(sig)
    except (ValueError, TypeError) as e:
        return label, False, "bad encoding: %s" % e
    reason = check_one(pub, msg, raw)
    return label, reason is None, reason or "ok"


def cmd_batch(a):
    items = []
    for i, line in enumerate(open(a.bundle), 1):
        line = line.strip()
        if not line:
            continue
        try:
            rec = json.loads(line)
            msg = b64u_decode(rec["msg_b64"]) if "msg_b64" in rec else rec["msg"].encode()
            items.append((str(rec.get("label", "line%d" % i)), msg, rec["sig"], rec["signer"]))
        except (ValueError, KeyError, TypeError) as e:
            items.append(("line%d" % i, b"", "", ""))
            print("line%d: FAIL bad bundle line: %s" % (i, e), file=sys.stderr)
    t0 = time.perf_counter()
    if a.workers > 1:
        from concurrent.futures import ProcessPoolExecutor
        with ProcessPoolExecutor(a.workers) as pool:
            results = list(pool.map(_verify_item, items, chunksize=8))
    else:
        results = [_verify_item(x) for x in items]
    dt = time.perf_counter() - t0
    fails = 0
    for label, ok, reason in results:
        fails += not ok
        if a.json:
            print(json.dumps({"label": label, "ok": ok, "reason": reason}))
        else:
            print("%s: %s%s" % (label, "OK" if ok else "FAIL",
                                "" if ok else " — " + reason))
    rate = len(items) / dt if dt else float("inf")
    print("%d verified, %d failed, %.1f items/s (workers=%d)"
          % (len(items) - fails, fails, rate, a.workers), file=sys.stderr)
    if fails:
        sys.exit(1)


RFC_VECTORS = [
    ("9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60", "",
     "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a",
     "e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e065224901555fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b"),
    ("4ccd089b28ff96da9db6c346ec114e0f5b8a319f35aba624da8cf6ed4fb8a6fb", "72",
     "3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c",
     "92a009a9f0d4cab8720e820b5f642540a2b27b5416503f8fb3762223ebdb69da085ac1e43e15996e458f3613d0f11d8c387b2eaeb4302aeeb00d291612bb0c00"),
    ("c5aa8df43f9f837bedb7442f31dcb7b166d38535076f094b85ce3a2e0b4458f7", "af82",
     "fc51cd8e6218a1a38da47ed00230f0580816ed13ba3303ac5deb911548908025",
     "6291d657deec24024827e69c3abe01a30ce548a284743a445e3680d7db5ac3ac18ff9b538d16f290ae67f760984dc6594a7c15e9716ed28dc027beceea1ec40a"),
]


def self_test():
    for seed_h, msg_h, pub_h, sig_h in RFC_VECTORS:
        seed, msg, pub, want = (bytes.fromhex(x) for x in
                                (seed_h, msg_h, pub_h, sig_h))
        assert public_key(seed) == pub, "vector pubkey"
        assert sign(seed, msg) == want, "vector signature"
        assert verify(pub, msg, want), "vector verify"
        assert not verify(pub, msg + b"x", want), "tampered msg accepted"
        bad = bytearray(want)
        bad[0] ^= 1
        assert not verify(pub, msg, bytes(bad)), "tampered sig accepted"
        assert not verify(pub, msg, want[:63]), "short sig accepted"
    v = RFC_VECTORS[0]
    seed, pub = bytes.fromhex(v[0]), bytes.fromhex(v[2])
    sig = bytearray(bytes.fromhex(v[3]))
    sig[32:] = int.to_bytes(_L, 32, "little")  # non-canonical S
    assert not verify(pub, b"", bytes(sig)), "S >= L accepted"
    nc = bytearray(pub)
    nc[31] |= 0x80  # y >= p
    assert not verify(bytes(nc), b"", bytes.fromhex(v[3])), "bad key accepted"

    for raw in (b"", b"\x00", b"\x00\x00abc", os.urandom(40)):
        assert b58decode(b58encode(raw)) == raw, "b58 round-trip"
    did = did_from_pub(public_key(seed))
    assert did.startswith("did:key:z6Mk") and pub_from_did(did) == public_key(seed), \
        "did round-trip"
    try:
        pub_from_did("did:key:z" + b58encode(b"\xe7\x01" + public_key(seed)))
        raise SystemExit("non-ed019d01 did accepted")
    except ValueError:
        pass
    try:
        b58decode("0OIl")
        raise SystemExit("bad b58 accepted")
    except ValueError:
        pass

    with tempfile.TemporaryDirectory() as d:
        art = os.path.join(d, "lobby.jsonl")
        with open(art, "w") as f:
            f.write('{"seq": 1, "text": "hello"}\n{"seq": 2}\n')
        seed_p = os.path.join(d, "auditor.seed")
        import contextlib
        import io
        buf0 = io.StringIO()
        with contextlib.redirect_stdout(buf0):
            cmd_keygen(argparse.Namespace(out=seed_p))
        seed2 = read_seed(seed_p)
        did2 = did_from_pub(public_key(seed2))
        assert buf0.getvalue().strip() == did2, "keygen printed did"
        assert verify(public_key(seed2), b"offline sdk",
                      sign(seed2, b"offline sdk")), "keygen sign/verify r/t"
        cmd_attest(argparse.Namespace(key=seed_p, file=art, ts="2026-08-31",
                                      out=None))
        att = json.load(open(art + ".attest.json"))
        assert att["signer"] == did2 and att["bytes"] == 39, "attest fields"
        cmd_verify(argparse.Namespace(msg=art, sig=None, signer=None,
                                      attest=art + ".attest.json"))
        with open(art, "a") as f:
            f.write('{"seq": 3}\n')  # artifact edited after attestation
        rc = _exit_code(lambda: cmd_verify(argparse.Namespace(
            msg=art, sig=None, signer=None, attest=art + ".attest.json")))
        assert rc == 1, "edited artifact not caught"
        att["signer"] = did_from_pub(public_key(os.urandom(32)))
        json.dump(att, open(art + ".attest.json", "w"))
        rc = _exit_code(lambda: cmd_verify(argparse.Namespace(
            msg=art, sig=None, signer=None, attest=art + ".attest.json")))
        assert rc == 1, "swapped signer not caught"

        bundle = os.path.join(d, "b.jsonl")
        seed3 = os.urandom(32)
        did3 = did_from_pub(public_key(seed3))
        lines = []
        for i in range(5):
            m = ("msg-%d" % i).encode()
            s = sign(seed3 if i != 3 else os.urandom(32), m)
            lines.append(json.dumps({"msg": m.decode(), "sig": b64u(s), "signer": did3}))
        with open(bundle, "w") as f:
            f.write("\n".join(lines) + "\n")
        for workers in (1, 2):
            buf = io.StringIO()
            with contextlib.redirect_stdout(buf):
                rc = _exit_code(lambda: cmd_batch(argparse.Namespace(
                    bundle=bundle, workers=workers, json=True)))
            verdicts = [json.loads(x) for x in buf.getvalue().splitlines()]
            assert rc == 1, "batch must fail on bad item (w=%d)" % workers
            assert sum(v["ok"] for v in verdicts) == 4, "ok count w=%d" % workers
            assert [v["label"] for v in verdicts if not v["ok"]] == ["line4"], \
                "wrong item flagged w=%d" % workers
    print("OK")


def _exit_code(fn):
    try:
        fn()
        return 0
    except SystemExit as e:
        return int(e.code) if isinstance(e.code, int) else 1


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    sub = ap.add_subparsers(dest="cmd")
    p = sub.add_parser("keygen"); p.add_argument("--out", default="-")
    p = sub.add_parser("sign"); p.add_argument("msg"); p.add_argument("--key", required=True)
    p = sub.add_parser("verify"); p.add_argument("msg")
    p.add_argument("--sig"); p.add_argument("--signer"); p.add_argument("--attest")
    p = sub.add_parser("attest"); p.add_argument("file"); p.add_argument("--key", required=True)
    p.add_argument("--ts"); p.add_argument("--out")
    p = sub.add_parser("batch"); p.add_argument("bundle")
    p.add_argument("--workers", type=int, default=1); p.add_argument("--json", action="store_true")
    ap.add_argument("--self-test", action="store_true")
    a = ap.parse_args(argv)
    if a.self_test:
        return self_test()
    if not a.cmd:
        ap.error("the following arguments are required: cmd")
    if a.cmd == "verify":
        if bool(a.sig) != bool(a.signer) or (a.attest and a.sig):
            ap.error("verify needs --sig+--signer, or --attest")
    {"keygen": cmd_keygen, "sign": cmd_sign, "verify": cmd_verify,
     "attest": cmd_attest, "batch": cmd_batch}[a.cmd](a)


if __name__ == "__main__":
    main()
