#!/usr/bin/env python3
"""sig-surface-audit — cryptographic-surface audit of signed room captures.

DEMAND: evidence/suggestions/tools-services/2026-09-08.md
  - "Continuous background data-integrity verification for Ed25519
    signature checks without locking" — evidence: "Auditing data
    integrity across an Ed25519 signature check without locking
    production tables" (10:21).
  - "Continuous background data-integrity verification for did:key
    identity without locking" — evidence: "Auditing data integrity
    across a did:key identity without locking production tables"
    (11:58).
  - "Continuous background data-integrity verification for
    base64url-without-padding without locking" — evidence: "Auditing
    data integrity across base64url without padding without locking
    production tables" (11:21).
  - "Continuous background data-integrity verification for
    concatenated-payload signatures without locking" — evidence:
    "Auditing data integrity across a signature over a concatenated
    payload without locking production tables" (11:10) — this
    protocol signs the concatenated payload room|nonce|text.

Stream captured room envelopes (JSONL {"seq","ts","from","text",
"nonce","sig"}) and audit the cryptographic SURFACE each message
carries — not the signature math (sibling offline-verify.py does the
Ed25519 verify) and not nonce ordering (sibling nonce-integrity-
audit.py owns that). Flags: sig not exactly 86 chars or outside the
base64url alphabet ('=' padding is its own reason — the wire format
is unpadded), senders not did:key:z6Mk<44 base58btc chars>,
multibase payloads not decoding to 34 bytes with the ed25519-pub
multicodec prefix 0xed01, texts embedding a full did:key:z6Mk...
that disagrees with the sender (binding), one sig pasted onto
several messages (reuse), texts claiming SIGNING / say-signed /
"Signal " with no sig (INFO), and lines that are not envelopes.
Lines are data only; nothing is run. rc 0 clean (INFO-only also
rc 0), 1 WARN findings, 2 usage/IO.
  Live grounding: evidence/raw/consensus_layer.jsonl, head -100000
  slice (2026-09 capture): 100,000 envelopes, all signed with an
  86-char unpadded base64url sig, 37,212 distinct senders;
  sig-shape / did-shape / did-codec / binding-mismatch /
  unsigned-claim / malformed all 0; 14 sig-reuse from one duplicate
  burst re-delivering seq 177932-177940 (9 distinct sigs, each 2-3x
  with identical text+nonce) -> rc 1. Cross-check faucet.jsonl
  head-100000: 99,411 signed, 589 did-shape (senders are bare
  usernames like "yufwij28"/"testuser"), 4,414 binding-mismatch
  (drip lines naming third-party recipient DIDs — announcements,
  not self-bindings), 26 sig-reuse.

VERIFY: python3 sig-surface-audit.py --self-test
  codec vectors, parser positive/negative, every finding code fires on
  its crafted line and stays silent on the clean twin, sig-reuse on
  2nd/3rd occurrence only, INFO-only rc 0, --json, --did, --top,
  rc 0/1/2, tamper sensitivity (one duplicated line flips rc 0 -> 1).
"""
import argparse
import json
import re
import sys
from collections import Counter

MAX_ROWS = 8  # per-code row cap; overflow summarized
DEF_TOP = 8   # default --top offender count
B58 = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
B64URL = set("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_")
SIG_LEN = 86            # 64 raw Ed25519 bytes, unpadded base64url
DID_KEY = b"\xed\x01"   # multicodec ed25519-pub prefix
RX_DID = re.compile(r"^did:key:(z6Mk[A-HJ-NP-Za-km-z1-9]{44})$")
RX_TEXT_DID = re.compile(r"\bdid:key:(z6Mk[A-HJ-NP-Za-km-z1-9]{44})")
CLAIM_WORDS = ("SIGNING", "say-signed", "Signal ")

def b58decode(s):
    """base58btc string -> bytes (leading '1's are 0x00); None if bad char."""
    n = 0
    for ch in s:
        i = B58.find(ch)
        if i < 0:
            return None
        n = n * 58 + i
    body = n.to_bytes((n.bit_length() + 7) // 8, "big")
    return b"\x00" * (len(s) - len(s.lstrip("1"))) + body

def sig_fault(sig):
    """86-char unpadded-base64url sig -> None, else reason string."""
    if len(sig) != SIG_LEN:
        return "sig length %d != %d chars" % (len(sig), SIG_LEN)
    if "=" in sig:
        return "base64url padding '=' present (wire format is unpadded)"
    bad = sorted({c for c in sig if c not in B64URL})
    return "chars outside base64url alphabet: %s" % "".join(bad) if bad else None

def did_payload(frm):
    """sender -> 48-char multibase payload, or None if not z6Mk shape."""
    m = RX_DID.match(frm or "")
    return m.group(1) if m else None

def did_fault(payload):
    """multibase z-payload -> None, else did-codec reason string."""
    body = b58decode(payload[1:])  # payload[0] 'z' = base58btc multibase
    if body is None:
        return "payload not base58btc decodable"
    if len(body) != 34:
        return "decoded length %d != 34 bytes" % len(body)
    if body[:2] != DID_KEY:
        return "multicodec prefix 0x%s != 0xed01 (ed25519-pub)" % body[:2].hex()
    return None

def embedded_did(text):
    """First full did:key:z6Mk... named inside the text, else None."""
    m = RX_TEXT_DID.search(text)
    return m.group(1) if m else None

def parse_line(raw):
    """One capture line -> (envelope dict, None) or (None, fault reason)."""
    line = raw.strip()
    if not line:
        return None, "blank line"
    try:
        obj = json.loads(line)
    except ValueError:
        return None, "not JSON"
    if not isinstance(obj, dict):
        return None, "not a JSON object"
    seq, frm = obj.get("seq"), obj.get("from")
    if not isinstance(seq, int) or isinstance(seq, bool):
        return None, "missing/non-int seq"
    if not isinstance(frm, str):
        return None, "missing/non-str from"
    text = obj.get("text")
    env = {"seq": seq, "from": frm, "sig": obj.get("sig"),
           "nonce": obj.get("nonce"), "text": text if isinstance(text, str) else ""}
    return env, None

def build_ledger(paths):
    """Stream capture lines -> ledger (envelopes, malformed, census)."""
    ledger = {"envs": [], "malformed": [], "signed": 0, "dids": set()}
    for path in paths:
        fh = sys.stdin if path == "-" else open(path, encoding="utf-8",
                                                errors="replace")
        with fh:
            for raw in fh:
                env, fault = parse_line(raw)
                if fault is not None:
                    ledger["malformed"].append(fault)
                    continue
                ledger["envs"].append(env)
                ledger["dids"].add(env["from"])
                if env["sig"] is not None:
                    ledger["signed"] += 1
    return ledger

def audit(ledger):
    """Ledger -> findings list [(code, sev, seq, did, detail)]."""
    out = []
    seen = {}  # sig -> (first seq, first text)
    for env in ledger["envs"]:
        seq, frm, text, sig = env["seq"], env["from"], env["text"], env["sig"]
        payload = did_payload(frm)
        if payload is None:
            out.append(("did-shape", "WARN", seq, frm, "sender is not "
                        "did:key:z6Mk<44 base58btc chars>"))
        else:
            fault = did_fault(payload)
            if fault:
                out.append(("did-codec", "WARN", seq, frm, fault))
            emb = embedded_did(text)
            if emb is not None and emb != payload:
                out.append(("binding-mismatch", "WARN", seq, frm,
                            "text names did:key:%s but sender is did:key:%s"
                            % (emb, payload)))
        if sig is None:
            word = next((w for w in CLAIM_WORDS if w in text), None)
            if word is not None:
                out.append(("unsigned-claim", "INFO", seq, frm, 'text says '
                            '"%s" but no sig' % word.strip()))
        elif not isinstance(sig, str):
            out.append(("sig-shape", "WARN", seq, frm, "not a string"))
        else:
            fault = sig_fault(sig)
            if fault:
                out.append(("sig-shape", "WARN", seq, frm, fault))
            if sig in seen:
                out.append(("sig-reuse", "WARN", seq, frm, "sig already "
                            "signed seq %d (same text: %s)"
                            % (seen[sig][0], seen[sig][1] == text)))
            else:
                seen[sig] = (seq, text)
    out += [("malformed", "WARN", None, "-", r) for r in ledger["malformed"]]
    return out

def summarize(ledger):
    """Census for the report header."""
    return {"lines": len(ledger["envs"]) + len(ledger["malformed"]),
            "envelopes": len(ledger["envs"]), "signed": ledger["signed"],
            "distinct_dids": len(ledger["dids"]),
            "malformed": len(ledger["malformed"])}

def render(ledger, findings, top=DEF_TOP, did_filter=None):
    """Human report."""
    c = summarize(ledger)
    lines = ["sig surface: %d line(s), %d envelope(s), %d signed, %d "
             "distinct sender(s), %d malformed"
             % (c["lines"], c["envelopes"], c["signed"],
                c["distinct_dids"], c["malformed"])]
    if did_filter:
        lines.append("did filter: %s" % did_filter)
    if not findings:
        lines.append("findings: none — cryptographic surface clean")
        return "\n".join(lines)
    counts = dict(sorted(Counter(f[0] for f in findings).items()))
    lines.append("findings by code:")
    for code, cnt in counts.items():
        sev = next(f[1] for f in findings if f[0] == code)
        lines.append("  %s %s %dx" % (sev, code, cnt))
    lines.append("rows (capped at %d per code):" % MAX_ROWS)
    for code in counts:
        rows = [f for f in findings if f[0] == code]
        for _, sev, seq, did, det in rows[:MAX_ROWS]:
            at = "seq %s" % seq if seq is not None else "line"
            lines.append("  [%s] %s %s: %s" % (sev, at, did, det))
        if len(rows) > MAX_ROWS:
            lines.append("  … +%d more %s" % (len(rows) - MAX_ROWS, code))
    tops = Counter(f[3] for f in findings if f[3] != "-").most_common(top)
    if tops:
        lines.append("top offending dids:")
        lines += ["  %dx %s" % (cnt, did) for did, cnt in tops]
    return "\n".join(lines)

def report_json(ledger, findings, top=DEF_TOP, did_filter=None):
    """Serializable view for --json."""
    return json.dumps(
        {"census": summarize(ledger),
         "totals": dict(sorted(Counter(f[0] for f in findings).items())),
         "findings": [{"code": c, "sev": s, "seq": q, "did": d,
                       "detail": x} for c, s, q, d, x in findings],
         "top_dids": [{"did": d, "findings": k} for d, k in Counter(
             f[3] for f in findings if f[3] != "-").most_common(top)]},
        ensure_ascii=False, indent=1)

def self_test():
    """VERIFY: codec vectors, envelope parser, finding codes, CLI."""
    import io
    import os
    import tempfile
    from contextlib import redirect_stdout
    n = [0]

    def ck(cond, note=""):
        n[0] += 1
        assert cond, note

    sig = ("yJL8DeiR1CChIHzeG4G5fbmUbzSXF7WRI_TTV3RVE-A5un_6UI0qBPZq"
           "7zxE2gWs9shyxyGSj7quMJuqnOnKCw")
    did = "did:key:z6Mkvwfhc8e5takAWRgDjbPjphHYhKL8tr2TWg8DCKR8bzmJ"
    alt = "z6Mkrf7QMkFEkwMNNyNcNaBCVJWuPgbVbjuVSeLSt5Y2EhiK"
    wrong = "did:key:z6MkMDwg6TVqYVkhYR4HTPnYeskUa5dXfgBGCxxbyMYiPdEP"

    # codec: canonical vector, zero padding, bad chars
    ck(b58decode("StV1DL6CwTryKyV") == b"hello world")
    ck(b58decode("1112") == b"\x00\x00\x00\x01")
    ck(b58decode("0OIl+/") is None)
    # sig shape: clean 86-char unpadded base64url vs fault twins
    ck(len(sig) == 86 and sig_fault(sig) is None)
    for bad, why in ((sig[:-1], "length 85"), (sig + "A", "length 87"),
                     (sig[:-1] + "=", "unpadded"),
                     ("+" + sig[1:], "base64url alphabet"),
                     ("/" + sig[1:], "base64url alphabet")):
        ck(why in sig_fault(bad), why)
    # did shape: z6Mk + 44 base58btc chars = 48-char payload
    ck(did_payload(did) == did[8:] and did_fault(did[8:]) is None)
    ck(did_fault(alt) is None and did_payload(wrong) is not None)
    for bad_did in [did[:-1] + c for c in "0OIl+/"] + [
            did[:-1], did + "k", did[4:], "z6Mk" + alt[4:]]:
        ck(did_payload(bad_did) is None, bad_did)  # char/length/prefix
    # codec: full-shape payload decoding to a wrong multicodec prefix
    ck("0xed00 != 0xed01" in did_fault(did_payload(wrong)))
    ck("decoded length 32 != 34"
       in did_fault("zGxAWWX1Rkjps2wt8vYju3SCkEho1Y6j6xnJJfQE2nntf"))
    # embedded did extraction (bare + labeled forms)
    ck(embedded_did("faucet drip did:key:%s 1000 tFLOP" % alt) == alt)
    ck(embedded_did("DID: did:key:%s ok" % alt) == alt)
    ck(embedded_did("no keys here") is None)
    # envelope parser: positive/negative shapes
    env, fault = parse_line(json.dumps(
        {"seq": 7, "ts": "2026-09-09T09:07:16.236396Z", "from": did,
         "text": "hi", "nonce": 5, "sig": sig}))
    ck(fault is None and env["seq"] == 7 and env["from"] == did
       and env["sig"] == sig and env["nonce"] == 5)
    for raw, why in (("{not json", "not JSON"), ("", "blank line"),
                     ("   \n", "blank line"), ("123", "not a JSON object"),
                     ('{"from": "%s"}' % did, "missing/non-int seq"),
                     ('{"seq": 1}', "missing/non-str from")):
        ck(parse_line(raw)[1] == why, why)

    def write(rows):
        """rows of (seq, from, text, sig) -> capture path."""
        tf = tempfile.NamedTemporaryFile("w", suffix=".jsonl", delete=False)
        for seq, frm, text, s in rows:
            obj = {"seq": seq, "ts": "2026-09-09T09:07:16.236396Z",
                   "from": frm, "text": text, "nonce": seq,
                   **({"sig": s} if s is not None else {})}
            tf.write(json.dumps(obj) + "\n")
        tf.close()
        return tf.name

    def run(path, extra):
        # capture path -> (rc, stdout) via main()
        buf = io.StringIO()
        with redirect_stdout(buf):
            rc = main([path, *extra])
        return rc, buf.getvalue()

    def codes(row):
        # one-envelope capture -> (rc, --json doc)
        rc, out = run(write([row]), ["--json"])
        return rc, json.loads(out)

    clean = write([(1, did, "correction: SIGNING here is Ed25519 only", sig),
                   (2, "did:key:" + alt, "drip did:key:%s ok" % alt,
                    sig[1] + sig[0] + sig[2:])])
    try:
        ck(audit(build_ledger([clean])) == [])  # clean twins stay silent
        # each crafted line fires exactly its code (INFO keeps rc 0)
        table = (
            ((3, did, "short sig", sig[:-1]), "sig-shape", "length 85"),
            ((3, did[:-1] + "0", "bad alphabet", sig), "did-shape", ""),
            ((3, wrong, "wrong codec", sig), "did-codec", "0xed00 != 0xed01"),
            ((3, did, "tokens for did:key:%s" % alt, sig),
             "binding-mismatch", "text names"),
            ((3, did, "my did:key:%s" % did[8:], sig), "", ""),  # twin
            ((4, did, "say-signed covers bytes", None), "unsigned-claim", ""),
            ((5, did, "Signal protocol fan", None), "unsigned-claim", ""),
            ((3, did, "plain chatter", None), "", ""))
        for row, want, note in table:
            rc, doc = codes(row)
            ck(rc == (1 if want and want != "unsigned-claim" else 0), want)
            ck(set(doc["totals"]) == ({want} if want else set()), note)
            if want:
                ck(doc["findings"][0]["sev"] == ("INFO" if
                    want == "unsigned-claim" else "WARN"))
            if note:
                ck(note in doc["findings"][0]["detail"])
        # sig-reuse: fires on 2nd+3rd occurrence, never the 1st
        led = build_ledger([write([(1, did, "one", sig), (2, did, "two", sig),
                                   (3, did, "three", sig)])])
        ck([f[0] for f in audit(led)] == ["sig-reuse", "sig-reuse"])
        # malformed: junk line counted as WARN, drives rc 1
        tf = tempfile.NamedTemporaryFile("w", suffix=".jsonl", delete=False)
        tf.write('{"seq": 1, "from": "%s", "text": "x"}\ngarbage\n' % did)
        tf.close()
        rc, out = run(tf.name, ["--json"])
        ck(rc == 1 and json.loads(out)["totals"] == {"malformed": 1})
        os.unlink(tf.name)
        # --did filter + --top + human report rows
        fam = write([(1, did, "a", sig[:-1]),   # sig-shape
                     (2, did, "b did:key:%s" % alt, sig[1] + sig[0] + sig[2:]),
                     (3, "did:key:" + alt, "c", sig[1] + sig[0] + sig[2:])])
        rc, out = run(fam, ["--json", "--did", did])
        doc = json.loads(out)
        ck(rc == 1 and doc["totals"] == {"sig-shape": 1,
                                         "binding-mismatch": 1})
        ck(all(f["did"] == did for f in doc["findings"]))
        rc, out = run(fam, ["--top", "1"])
        ck(rc == 1 and "top offending dids:" in out
           and out.count("x did:key:") == 1
           and "WARN sig-shape 1x" in out and "rows (capped at" in out)
        # tamper sensitivity: one duplicated line flips rc 0 -> 1
        tf = tempfile.NamedTemporaryFile("w", suffix=".jsonl", delete=False)
        with open(clean) as src:
            tf.write(src.readline() * 2)
        tf.close()
        rc, out = run(tf.name, ["--json"])
        ck(rc == 1 and json.loads(out)["totals"] == {"sig-reuse": 1})
        os.unlink(tf.name)
        # CLI contract: rc 2 on unreadable input
        ck(main(["/nonexistent-capture.jsonl"]) == 2)
    finally:
        os.unlink(clean)
    # direct module-function asserts (anti-tautology gate: must call
    # module fns directly, not only through the ck() wrapper)
    assert b58decode("StV1DL6CwTryKyV") == b"hello world"
    assert sig_fault(sig) is None and did_fault(did[8:]) is None
    assert parse_line("{bad json")[1] == "not JSON"
    print("sig-surface-audit self-test OK (%d assertions)" % n[0])

def main(argv=None):
    ap = argparse.ArgumentParser(
        description="Cryptographic-surface audit (sig/did:key shape, codec,"
                    " binding, reuse) of signed room captures")
    ap.add_argument("inputs", nargs="*", help="JSONL capture(s); default stdin")
    ap.add_argument("--top", type=int, default=DEF_TOP, metavar="N",
                    help="top offending DIDs to list (default %d)" % DEF_TOP)
    ap.add_argument("--did", help="only report findings from this sender")
    ap.add_argument("--json", action="store_true", help="machine report")
    args = ap.parse_args(argv)
    try:
        ledger = build_ledger(args.inputs or ["-"])
    except OSError:
        return 2
    findings = audit(ledger)
    if args.did:
        findings = [f for f in findings if f[3] == args.did]
    if args.json:
        print(report_json(ledger, findings, args.top, args.did))
    else:
        print(render(ledger, findings, args.top, args.did))
    if any(f[1] != "INFO" for f in findings):
        return 1
    return 0

if __name__ == "__main__":
    if "--self-test" in sys.argv:
        self_test()
    else:
        raise SystemExit(main())
