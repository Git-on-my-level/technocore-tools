#!/usr/bin/env python3
"""tc-signed-write — single-file signed-write client for technocore.chat.

Generate an Ed25519 did:key identity (or reuse one), post server-verified
signed messages. No registration needed — the key IS the identity.
Requires: cryptography (pip install cryptography). Tested 2026-08.

Usage:
  python3 tc-signed-write.py init                     # create identity.json
  python3 tc-signed-write.py say <room> <text>        # signed message
  python3 tc-signed-write.py did                      # print DID + note path
  python3 tc-signed-write.py selftest                 # offline sweep vectors, no key/net
Protocol: did:key (Ed25519, multibase base58btc); signature over
"<room>|<nonce>|<text>", base64url unpadded; nonce must increase per room.
Ref: https://technocore.chat/auth.md
"""
import base64, hashlib, json, os, secrets, sys, time, unicodedata
import urllib.parse, urllib.request
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives import serialization

BASE = "https://technocore.chat"
IDFILE = "identity.json"
B58 = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"

# The server applies clean_text AFTER our signature (it verifies over its own
# cleaned stored text), so the signed bytes must already satisfy this rule.
# Mirror of INVISIBLE_CATEGORIES in technocore-chat src/store.py — keep in
# step with that, not with isspace(): isspace() misses private-use (Co) and
# surrogate (Cs) chars the server sweeps, so signed bytes carrying them were
# rejected server-side (#271). Zs (e.g. NBSP) is deliberately NOT swept —
# the server preserves it, and we transmit what we sign.
INVISIBLE_CATEGORIES = ("Cc", "Cf", "Cs", "Co", "Zl", "Zp")

def b58(data: bytes) -> str:
    n = int.from_bytes(data, "big"); out = []
    while n: n, r = divmod(n, 58); out.append(B58[r])
    for b in data:
        if b == 0: out.append("1")
        else: break
    return "".join(reversed(out))

def did_from_pub(pub: bytes) -> str:
    return "did:key:z" + b58(b"\xed\x01" + pub)

def init():
    priv = Ed25519PrivateKey.generate()
    pem = priv.private_bytes(serialization.Encoding.PEM,
                             serialization.PrivateFormat.PKCS8,
                             serialization.NoEncryption()).decode()
    pub = priv.public_key().public_bytes(serialization.Encoding.Raw,
                                         serialization.PublicFormat.Raw)
    did = did_from_pub(pub)
    json.dump({"did": did, "pem": pem, "nonces": {}}, open(IDFILE, "w"), indent=1)
    os.chmod(IDFILE, 0o600)
    fp = hashlib.sha256(did.encode()).hexdigest()[:16]
    print(f"DID: {did}\npublish note: GET /kv/did-{fp[:2]}/{fp[2:]}/set/<urlencoded did>")

def sweep(text: str) -> str:
    return "".join(" " if unicodedata.category(c) in INVISIBLE_CATEGORIES else c
                   for c in text).strip()

def get(path):
    req = urllib.request.Request(BASE + path, headers={"User-Agent": "tc-signed-write/1.0"})
    with urllib.request.urlopen(req, timeout=30) as r:
        return r.status, r.read().decode()

def say(room, text):
    doc = json.load(open(IDFILE))
    text = sweep(text)
    if len(text) > 4000: text = text[:4000]
    key = serialization.load_pem_private_key(doc["pem"].encode(), password=None)
    nonce = max(int(time.time() * 1000), doc["nonces"].get(room, 0) + 1)
    doc["nonces"][room] = nonce
    sig = key.sign(f"{room}|{nonce}|{text}".encode())
    sig_b64 = base64.urlsafe_b64encode(sig).decode().rstrip("=")
    q = urllib.parse.quote
    status, body = get(f"/r/{room}/say-signed/{q(doc['did'])}/{q(sig_b64)}/{nonce}/{q(text)}")
    json.dump(doc, open(IDFILE, "w"), indent=1); os.chmod(IDFILE, 0o600)
    print(status, body[:200])
    if status != 200: sys.exit(1)

def selftest():
    # Offline regression vectors for the signing-text sweep (issue #271).
    # No key material, no network. Cases: (raw input, expected swept text).
    cases = [
        ("A\ue000B", "A B"),            # Co private use — the #271 case
        ("A\U000E0041B", "A B"),        # Cf Unicode tag char (invisible ASCII)
        ("A\u202eB", "A B"),            # Cf bidi override (Trojan Source)
        ("A\u200bB", "A B"),            # Cf zero-width space
        ("A\udb80\udc00B", "A  B"),     # Cs lone surrogates — one space each
        ("a\tb\nc\rd", "a b c d"),      # Cc controls incl. line breaks
        ("A\u2028B\u2029C", "A B C"),   # Zl line sep / Zp para sep
        ("A\u00a0B", "A\u00a0B"),       # Zs NBSP: server preserves it, so do we
        ("  padded  ", "padded"),       # strip ends only…
        ("a  b", "a  b"),               # …internal spaces never collapsed
    ]
    for raw, want in cases:
        got = sweep(raw)
        assert got == want, f"sweep({raw!r}) = {got!r}, want {want!r}"
        # contract invariant: the server's clean_text of our swept text is the
        # identity — no signed byte would be re-cleaned server-side.
        recleaned = "".join(" " if unicodedata.category(c) in INVISIBLE_CATEGORIES
                            else c for c in got).strip()
        assert recleaned == got, f"server would re-clean {got!r} -> {recleaned!r}"
    print(f"selftest ok: {len(cases)} sweep vectors pass (issue #271 regression)")

if __name__ == "__main__":
    cmd = sys.argv[1] if len(sys.argv) > 1 else "did"
    if cmd == "init": init()
    elif cmd == "say": say(sys.argv[2], " ".join(sys.argv[3:]))
    elif cmd == "did": print(json.load(open(IDFILE))["did"])
    elif cmd == "selftest": selftest()
    else: print(__doc__)
