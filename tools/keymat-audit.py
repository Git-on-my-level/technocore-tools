#!/usr/bin/env python3
"""keymat-audit — verify crypto key-material claims in audit reports.

DEMAND: evidence/suggestions/tools-services/2026-08-28.md
  - "crypto-key-material correctness audit that verifies claimed
    algorithms/curves against the actual spec and flags mismatches"
  - "Enhance hermes-tools to automatically distinguish and correctly label
    key material types (private vs public keys) during audits"
  Filed after REF-20260828-0011 audited a did:key as "PKCS8 private key
  encryption" when the fleet manual's did:key spec is an Ed25519 PUBLIC key
  encoding (multibase base58btc). Same need echoed in the 13:47 run.

What it does (structure, not string-matching): did:key:z... tokens are
base58btc-decoded and checked against the multicodec table (0xed
ed25519-pub / 0xe7 secp256k1-pub / 0xec x25519-pub) including payload
length — and did:key is always a PUBLIC encoding, so "private"/"PKCS8"
claims against it are mismatches. PEM blocks are labelled by header
(PKCS#8 / PKCS#1 / SEC1 / SPKI / OpenSSH) with the algorithm read from
DER OIDs in the body; ssh-* public lines are wire-format checked.
check_claim() compares a claim sentence against those parsed facts and
reports ok / mismatch / unverified with concrete reasons; audit mode
flags claim mismatches and invalid material line by line (exit 1 on any
mismatch, so audit gates can consume it).

Usage:
  python3 keymat-audit.py report.txt            # audit a report (or stdin)
  python3 keymat-audit.py report.txt --json     # JSONL findings
  python3 keymat-audit.py --claim "PKCS8 private key encryption" \
                          --material did:key:z6MkfrMzLBQam...
  python3 keymat-audit.py --classify key.txt    # what material IS this

VERIFY: self-test — python3 keymat-audit.py --self-test
  Round-trips real encodings (base58, DER-built PKCS#8/SPKI, SSH wire),
  parses the fleet DID from operations/agents/IDENTITY.md, asserts the
  REF-20260828-0011 scenario is flagged. Asserts, prints OK.
"""
import argparse
import base64
import json
import re
import sys

B58 = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
B58_REV = {c: i for i, c in enumerate(B58)}

# multicodec codes used by did:key (varint prefix on the pubkey payload)
DID_CODECS = {
    0xED: ("ed25519-pub", 32, "ed25519"),
    0xE7: ("secp256k1-pub", 33, "secp256k1"),
    0xEC: ("x25519-pub", 32, "x25519"),
}

# OIDs we can name when a PEM body parses as DER
OID_ALGS = {
    "1.3.101.112": "ed25519", "1.3.101.113": "ed448",
    "1.3.101.110": "x25519",
    "1.2.840.113549.1.1.1": "rsa", "1.2.840.113549.1.1.10": "rsa",
    "1.2.840.10045.2.1": "ec",
    "1.3.132.0.10": "secp256k1", "1.2.840.10045.3.1.7": "p256",
}

# PEM block header -> (kind, private?, public?)
PEM_KINDS = {
    "PRIVATE KEY": ("pem-pkcs8-private", True, False),
    "ENCRYPTED PRIVATE KEY": ("pem-pkcs8-private", True, False),
    "RSA PRIVATE KEY": ("pem-pkcs1-rsa-private", True, False),
    "EC PRIVATE KEY": ("pem-sec1-ec-private", True, False),
    "PUBLIC KEY": ("pem-spki-public", False, True),
    "OPENSSH PRIVATE KEY": ("pem-openssh-private", True, False),
    "CERTIFICATE": ("pem-certificate", False, True),
}

PEM_RE = re.compile(
    r"-----BEGIN ([A-Z0-9 ]+)-----(.*?)-----END \1-----", re.S)
DID_RE = re.compile(r"\bdid:key:([A-Za-z0-9]{8,})")
SSH_RE = re.compile(
    r"\b(ssh-ed25519|ssh-rsa|ssh-dss|ecdsa-sha2-[a-z0-9-]+)"
    r"[ \t]+([A-Za-z0-9+/]{16,}={0,2})")
DID_RE = re.compile(r"\bdid:key:([A-Za-z0-9]+)")
# claim keywords -> normalized fact to check
CLAIM_RULES = [
    (re.compile(r"pkcs\s*#?\s*8", re.I), "pkcs8"),
    (re.compile(r"\bprivate\b", re.I), "private"),
    (re.compile(r"\bpublic\b", re.I), "public"),
    (re.compile(r"ed25519", re.I), "ed25519"),
    (re.compile(r"x25519", re.I), "x25519"),
    (re.compile(r"\bed448\b", re.I), "ed448"),
    (re.compile(r"\brsa\b", re.I), "rsa"),
    (re.compile(r"secp256k1", re.I), "secp256k1"),
    (re.compile(r"\bp256\b|prime256v1", re.I), "p256"),
]
# algorithm aliases: claim name -> set of parsed names that satisfy it
ALG_ALIAS = {
    "ed25519": {"ed25519"}, "x25519": {"x25519"}, "ed448": {"ed448"},
    "rsa": {"rsa"}, "secp256k1": {"secp256k1"}, "p256": {"p256"},
}


def b58decode(s):
    """Strict base58btc decode -> bytes, or None on any bad character."""
    n = 0
    for c in s:
        if c not in B58_REV:
            return None
        n = n * 58 + B58_REV[c]
    body = n.to_bytes((n.bit_length() + 7) // 8, "big") if n else b""
    pad = 0
    for c in s:
        if c == "1":
            pad += 1
        else:
            break
    return b"\x00" * pad + body


def b58encode(b):
    """base58btc encode (mirror of b58decode; used to build fixtures)."""
    n = int.from_bytes(b, "big")
    out = []
    while n:
        n, r = divmod(n, 58)
        out.append(B58[r])
    pad = 0
    for by in b:
        if by == 0:
            pad += 1
        else:
            break
    return "1" * pad + "".join(reversed(out))


def read_varint(b, i):
    """LEB128 varint at b[i:] -> (value, next_index) or None."""
    val, shift = 0, 0
    while i < len(b) and shift < 63:
        by = b[i]
        val |= (by & 0x7F) << shift
        i += 1
        if not by & 0x80:
            return val, i
        shift += 7
    return None


def _dk(tok, codec=None, algorithm=None, valid=False, note="",
          private=None, public=None):
    """Common shape for a did:key classification result."""
    return {"kind": "did-key", "token": tok, "codec": codec,
            "algorithm": algorithm, "valid": valid, "note": note,
            "private": private, "public": public}


def parse_did_key(tok):
    """Classify one did:key token against the multibase/multicodec spec."""
    body = tok[len("did:key:"):] if tok.startswith("did:key:") else tok
    if not body or body[0] != "z":
        return _dk(tok, note="unsupported multibase %r (only z=base58btc "
                             "is in the did:key spec's common profiles)"
                   % (body[:1] if body else ""))
    raw = b58decode(body[1:])
    if raw is None:
        return _dk(tok, note="invalid base58btc characters")
    v = read_varint(raw, 0)
    if not v:
        return _dk(tok, note="truncated multicodec prefix")
    code, payload = v[0], raw[v[1]:]
    if code not in DID_CODECS:
        return _dk(tok, codec="0x%x" % code,
                   note="unknown multicodec 0x%x" % code)
    name, want_len, alg = DID_CODECS[code]
    if len(payload) != want_len:
        return _dk(tok, codec=name, note="%s payload must be %d bytes, "
                                      "got %d" % (name, want_len, len(payload)))
    return _dk(tok, codec=name, algorithm=alg, valid=True,
               private=False, public=True)

def _oid_dotted(v):
    """DER OID content bytes -> dotted string, or None."""
    subs, cur = [], 0
    for by in v:
        cur = (cur << 7) | (by & 0x7F)
        if not by & 0x80:
            subs.append(cur)
            cur = 0
    if not subs or any(s > 2 ** 31 for s in subs):
        return None
    s0 = subs[0]
    if s0 < 40:
        head = [0, s0]
    elif s0 < 80:
        head = [1, s0 - 40]
    else:
        head = [2, s0 - 80]
    return ".".join(str(x) for x in head + subs[1:])


def der_algorithms(der):
    """Name algorithms from OIDs found anywhere in a DER blob."""
    found, stack = [], [(der, 0)]
    while stack:
        blob, i = stack.pop()
        while i < len(blob):
            if i + 2 > len(blob):
                break
            tag = blob[i]
            ln = blob[i + 1]
            j = i + 2
            if ln & 0x80:
                nb = ln & 0x7F
                if not 1 <= nb <= 4 or i + 2 + nb > len(blob):
                    break
                ln = int.from_bytes(blob[i + 2:i + 2 + nb], "big")
                j = i + 2 + nb
            if j + ln > len(blob):
                break
            val = blob[j:j + ln]
            if tag == 0x06 and _oid_dotted(val):
                dotted = _oid_dotted(val)
                if dotted in OID_ALGS:
                    found.append(OID_ALGS[dotted])
            elif tag in (0x30, 0x31) and len(stack) < 12:
                stack.append((val, 0))
            i = j + ln
    return found


def classify_pem(text):
    """Classify every PEM block; DER-parse bodies where possible."""
    out = []
    for m in PEM_RE.finditer(text):
        label = m.group(1).strip()
        kind, priv, pub = PEM_KINDS.get(label, ("pem-" + label.lower()
                                                .replace(" ", "-"), None, None))
        b64 = re.sub(r"\s+", "", m.group(2))
        algs = []
        try:
            der = base64.b64decode(b64, validate=True)
            algs = der_algorithms(der)
        except Exception:
            algs = []
        out.append({"kind": kind, "token": label, "codec": label,
                    "algorithm": algs[0] if algs else None,
                    "algorithms": algs, "valid": True,
                    "note": ("DER algorithm: " + ", ".join(algs)) if algs
                            else "PEM recognized by header; "
                                 "body not DER-parseable",
                    "private": priv, "public": pub})
    return out


def classify_ssh(text):
    """Classify ssh public-key lines, validating the wire format."""
    out = []
    for m in SSH_RE.finditer(text):
        alg, b64 = m.group(1), m.group(2)
        try:
            wire = base64.b64decode(b64, validate=True)
        except Exception:
            wire = b""
        ln = int.from_bytes(wire[:4], "big") if wire else -1
        ok = 4 + ln <= len(wire) and wire[4:4 + ln] == alg.encode()
        out.append({"kind": "ssh-public", "token": alg + " " + b64[:24],
                    "codec": alg, "algorithm": alg[len("ssh-"):]
                    if alg.startswith("ssh-") else alg,
                    "valid": ok, "note": "" if ok else
                    "wire format does not match " + alg,
                    "private": False, "public": True})
    return out


def classify_material(text):
    """Aggregate every key-material finding in `text` into one summary."""
    mats = [parse_did_key(m.group(0)) for m in DID_RE.finditer(text)]
    mats += classify_pem(text)
    mats += classify_ssh(text)
    algs = sorted({a for m in mats for a in
                   ([m["algorithm"]] if m.get("algorithm") else [])})
    return {"materials": mats, "algorithms": algs,
            "has_private": any(m.get("private") for m in mats),
            "has_public": any(m.get("public") for m in mats),
            "kinds": sorted({m["kind"] for m in mats if m.get("kind")})}


def check_claim(claim, info):
    """Verdict of a natural-language claim against parsed key facts."""
    if not info or not info.get("materials"):
        return {"status": "unverified",
                "issues": ["no key material found to check against"],
                "checks": []}
    hits = [name for pat, name in CLAIM_RULES if pat.search(claim)]
    issues, checks = [], []
    algs, kinds = info["algorithms"], info["kinds"]
    if "pkcs8" in hits:
        checks.append("pkcs8")
        if "pem-pkcs8-private" not in kinds:
            if "did-key" in kinds:
                issues.append("did:key is a PUBLIC multibase key encoding "
                              "(did:key spec), not PKCS#8")
            elif kinds:
                issues.append("material is %s, not a PKCS#8 PEM block"
                              % "/".join(kinds))
    if "private" in hits and "public" not in hits:
        checks.append("private")
        if info["has_public"] and not info["has_private"]:
            issues.append("material is a PUBLIC key; claim says private")
    if "public" in hits and "private" not in hits:
        checks.append("public")
        if info["has_private"] and not info["has_public"]:
            issues.append("material is a PRIVATE key; claim says public")
    for a in hits:
        if a in ALG_ALIAS:
            checks.append(a)
            if algs and not (ALG_ALIAS[a] & set(algs)):
                issues.append("claim names %s; material parses as %s"
                              % (a, "/".join(algs)))
    if not checks:
        return {"status": "nothing-to-check", "issues": [], "checks": []}
    if issues:
        return {"status": "mismatch", "issues": issues, "checks": checks}
    if not any(m.get("valid") for m in info["materials"]):
        return {"status": "unverified",
                "issues": ["key material present but none parses cleanly"],
                "checks": checks}
    return {"status": "ok", "issues": [], "checks": checks}


def audit_lines(text):
    """Findings over report text: claim mismatches + invalid material."""
    findings = []
    ginfo = classify_material(text)
    for n, line in enumerate(text.splitlines(), 1):
        linfo = classify_material(line)
        for m in linfo["materials"]:
            if not m.get("valid"):
                findings.append({"line": n, "type": "invalid-material",
                                 "material": m["kind"], "issues": [m["note"]]})
        if not any(pat.search(line) for pat, _n in CLAIM_RULES):
            continue
        info = linfo if linfo["materials"] else (
            ginfo if len(ginfo["materials"]) == 1 else None)
        if not info:
            continue
        v = check_claim(line, info)
        if v["status"] in ("mismatch", "unverified"):
            findings.append({"line": n, "type": v["status"],
                             "claim": ", ".join(v["checks"]),
                             "material": "/".join(info["kinds"]),
                             "issues": v["issues"]})
    return findings


def print_findings(findings, as_json):
    for f in findings:
        if as_json:
            print(json.dumps(f, ensure_ascii=False))
        else:
            print(f"L{f['line']} {f['type'].upper()} "
                  f"[{f.get('claim') or '-'}] vs {f['material']}: "
                  + "; ".join(f["issues"]))
    if not findings:
        print("no key-material claims contradicted the parsed facts")


def self_test():
    checks = 0

    # base58: strict round-trip, leading zeros, alphabet enforcement
    blob = b"\x00\x01\x02\xfe" * 5
    assert b58decode(b58encode(blob)) == blob, "b58 round-trip"
    assert b58encode(b"\x00\xff").startswith("1"), "leading zero -> '1'"
    assert b58decode("0OIl") is None, "non-alphabet chars rejected"
    checks += 3

    # did:key: the real fleet DID (operations/agents/IDENTITY.md) parses
    fleet = "did:key:z6MkfrMzLBQamXhs5wvwJCZAw1FSrhDmK25HmNBcwQRnxpJT"
    fm = parse_did_key(fleet)
    assert fm["valid"] and fm["codec"] == "ed25519-pub", "fleet DID codec"
    assert fm["public"] and not fm["private"], "did:key is a public encoding"
    checks += 2

    # did:key: synthetic keys, wrong length, unknown codec, bad multibase
    dk = "did:key:z" + b58encode(b"\xed\x01" + bytes(range(32)))
    assert parse_did_key(dk)["algorithm"] == "ed25519", "synthetic ed25519"
    bad_len = "did:key:z" + b58encode(b"\xed\x01" + b"\x07" * 31)
    assert parse_did_key(bad_len)["valid"] is False, "31-byte payload"
    unknown = "did:key:z" + b58encode(b"\xef\x01" + bytes(range(32)))
    assert "unknown multicodec" in parse_did_key(unknown)["note"]
    assert parse_did_key("did:key:u12345678")["valid"] is False, "non-z mb"
    checks += 4

    # PEM PKCS#8 + SPKI fixtures built as real DER in-test
    def tlv(tag, val):
        raw = len(val).to_bytes((len(val).bit_length() + 7) // 8, "big")
        ln = bytes([len(val)]) if len(val) < 128 else bytes([0x80 | len(raw)]) + raw
        return bytes([tag]) + ln + val

    def pem(label, der):
        b64 = "\n".join(base64.encodebytes(der).decode().split())
        return "-----BEGIN %s-----\n%s\n-----END %s-----" % (label, b64, label)

    oid_ed = b"\x2b\x65\x70"            # 1.3.101.112 ed25519
    oid_rsa = b"\x2a\x86\x48\x86\xf7\x0d\x01\x01\x01"  # rsaEncryption
    pki = tlv(0x30, tlv(0x02, b"\x00")
              + tlv(0x30, tlv(0x06, oid_ed))
              + tlv(0x04, bytes(range(32))))
    spki = tlv(0x30, tlv(0x30, tlv(0x06, oid_rsa))
               + tlv(0x03, b"\x00" + b"\xab" * 8))
    pem_pkcs8, pem_spki = pem("PRIVATE KEY", pki), pem("PUBLIC KEY", spki)
    ci = classify_material(pem_pkcs8 + "\n" + pem_spki)
    assert ci["has_private"] and ci["has_public"], "PEM priv/pub detected"
    assert "ed25519" in ci["algorithms"] and "rsa" in ci["algorithms"], \
        "DER OIDs named both algorithms"
    checks += 2

    # ssh-ed25519 public line with valid wire format
    wire = (len(b"ssh-ed25519").to_bytes(4, "big") + b"ssh-ed25519"
            + (32).to_bytes(4, "big") + bytes(range(32)))
    ssh_line = "ssh-ed25519 " + base64.b64encode(wire).decode()
    si = classify_material(ssh_line)
    assert si["materials"][0]["valid"], "ssh wire format validated"
    assert si["algorithms"] == ["ed25519"], "ssh algorithm labelled"
    checks += 2

    # the filed REF-20260828-0011 scenario: did:key audited as PKCS8
    dk_info = classify_material("key %s per manual" % dk)
    v = check_claim("PKCS8 private key encryption", dk_info)
    assert v["status"] == "mismatch" and any("not PKCS#8" in i
                                             for i in v["issues"]), v
    assert check_claim("Ed25519 public key encoding", dk_info)["status"] \
        == "ok", "correct did:key claim passes"
    v2 = check_claim("RSA private key", classify_material(pem_pkcs8))
    assert v2["status"] == "mismatch" and any("rsa" in i.lower()
                                              for i in v2["issues"]), v2
    assert check_claim("PKCS#8 private key", classify_material(pem_pkcs8))[
        "status"] == "ok", "honest PKCS8 claim passes"
    assert check_claim("anything", {})["status"] == "unverified"
    checks += 5

    # audit_lines: report text with the mislabel is flagged by line
    report = ("REF-1 routine continuity check, nothing to see\n"
              "REF-20260828-0011 audit of 'PKCS8 private key encryption.' "
              "identity %s\n"
              "REF-3 noted invalid identity did:key:z0O0O0O0O\n" % dk)
    seen = {(f["type"], f["line"]) for f in audit_lines(report)}
    assert ("mismatch", 2) in seen, "misfiled REF flagged on its line"
    assert ("invalid-material", 3) in seen, "unparseable did:key flagged"
    assert all(ln != 1 for _t, ln in seen), "clean line untouched"
    checks += 3

    print(f"self-test OK ({checks} assertions)")


def main():
    ap = argparse.ArgumentParser(
        description="Audit crypto key-material claims in text: parse "
                    "did:key/PEM/SSH material structurally, compare against "
                    "claims (private/public, PKCS8, algorithm), flag "
                    "mismatches. Exit 1 if any mismatch found.")
    ap.add_argument("paths", nargs="*", help="report files (default: stdin)")
    ap.add_argument("--json", action="store_true",
                    help="emit findings as JSON lines")
    ap.add_argument("--claim", help="check one claim (with --material)")
    ap.add_argument("--material", help="material: literal or @file")
    ap.add_argument("--classify", action="store_true",
                    help="only classify the key material found in input")
    ap.add_argument("--self-test", action="store_true",
                    help="run built-in verification and exit")
    a = ap.parse_args()

    if a.self_test:
        self_test()
        return

    def read_input():
        if not a.paths:
            return sys.stdin.read()
        return "".join(open(p, errors="replace").read() for p in a.paths)

    if a.claim is not None:
        mat = a.material or ""
        if mat.startswith("@"):
            mat = open(mat[1:], errors="replace").read()
        verdict = check_claim(a.claim, classify_material(mat))
        msg = verdict["status"].upper() + (
            ": " + "; ".join(verdict["issues"]) if verdict["issues"] else "")
        print(json.dumps(verdict, ensure_ascii=False) if a.json else msg)
        raise SystemExit(1 if verdict["status"] == "mismatch" else 0)

    text = read_input()
    if a.classify:
        info = classify_material(text)
        keys = ("algorithms", "has_private", "has_public", "kinds")
        print(json.dumps({k: info[k] for k in keys}, ensure_ascii=False))
        return
    findings = audit_lines(text)
    print_findings(findings, a.json)
    bad = any(f["type"] in ("mismatch", "invalid-material") for f in findings)
    raise SystemExit(1 if bad else 0)


if __name__ == "__main__":
    try:
        main()
    except BrokenPipeError:
        # downstream closed early (head/grep -m); quiet success
        sys.stdout.close()
        raise SystemExit(0)
