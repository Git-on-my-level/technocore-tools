#!/usr/bin/env python3
"""reward-word-read-audit — is the light client reading the block
reward one SIGNED word at a time? completeness, signature and
assembly audit over saved read events.

DEMAND: evidence/suggestions/tools-services/2026-11-24.md (17:57 run)
  - request: "Determine if light client reads block reward inside
    audit tool one signed word at a time" — evidence: "Is a light
    client reading the block reward inside the audit tool one signed
    word at a time?" — proposed service: "Fine-grained light-client
    block-reward read audit."
  No existing tool audits per-word signed reads (validator cert tools
  check whole certificates, not word-granular access patterns).

Scope: one JSONL read-event log from the light client, one per line:
  {"height": 812345, "word": 0, "value": "0x0000012c",
   "client": "lc-7", "sig": "hex"}
The block reward is stored as a sequence of signed 32-bit two's
complement words. Each event must carry an HMAC-SHA256 signature (hex
--key) over the canonical {client, height, word, value} record — that
is what makes a read "signed". The audit groups events by
(client, height), checks the word sequence, re-assembles the reward,
and emits a per-block digest for later comparison. Data only: hashing
and arithmetic over saved events, no network, no subprocess, nothing
is ever run. Stdlib only.

What it does:
  verdicts (per client+height)
    unsigned-word     FAIL  missing/short sig or HMAC mismatch
    missing-word      FAIL  a word index in 0..words-1 never read
    word-out-of-range FAIL  word index >= --words (default 8)
    value-not-word    WARN  value not 8 hex digits
    reread-word       WARN  same word read more than once
    malformed-event   WARN  unparseable line / missing fields
    cross-client-divergence WARN same height, different assembled
                          reward across clients
  emit      per client+height: {client, height, words, reward,
            digest} as JSONL; reward = sum of the signed words
            (two's complement), digest chains canonical word records.
  rc 0 every block complete and signed, 1 findings, 2 usage/IO.
"""
import argparse
import hashlib
import hmac
import json
import sys
import tempfile
import os

FAIL, WARN = "FAIL", "WARN"


def canonical(rec):
    """Stable serialization independent of key order/whitespace."""
    return json.dumps(rec, sort_keys=True, separators=(",", ":"))


def parse_key(hexkey):
    """hex string -> bytes, or None if not valid hex."""
    if not isinstance(hexkey, str) or not hexkey:
        return None
    try:
        return bytes.fromhex(hexkey)
    except ValueError:
        return None


def read_jsonl(path):
    """Yield (lineno, rec-or-None) for each JSONL line."""
    with open(path, "r", errors="replace") as fh:
        for n, line in enumerate(fh, 1):
            line = line.strip()
            if not line:
                continue
            try:
                rec = json.loads(line)
            except ValueError:
                rec = None
            yield n, rec if isinstance(rec, dict) else None


def parse_event(rec, words):
    """Read-event -> (client, height, word, value) or None if invalid."""
    if not isinstance(rec, dict):
        return None
    try:
        height = int(rec["height"])
        word = int(rec["word"])
    except (KeyError, TypeError, ValueError):
        return None
    client, value, sig = rec.get("client"), rec.get("value"), \
        rec.get("sig")
    if not isinstance(client, str) or not client:
        return None
    if height < 0 or word < 0:
        return None
    if not isinstance(value, str):
        return None
    return client, height, word, value, sig


def signed_word(value):
    """8-hex-digit string -> signed 32-bit int, or None if malformed."""
    if not isinstance(value, str):
        return None
    v = value[2:] if value.startswith("0x") else value
    if len(v) != 8:
        return None
    try:
        n = int(v, 16)
    except ValueError:
        return None
    return n - (1 << 32) if n >= (1 << 31) else n



def sign(message, key):
    """HMAC-SHA256 hex over a string message."""
    return hmac.new(key, message.encode(), hashlib.sha256).hexdigest()


def verify_word_sig(client, height, word, value, sig, key):
    """Constant-time check of one read event's signature."""
    if not isinstance(sig, str) or len(sig) != 64:
        return False
    msg = canonical({"client": client, "height": height,
                     "word": word, "value": value})
    return hmac.compare_digest(sign(msg, key), sig)


def block_receipt(client, height, word_values, key):
    """Assembled reward + chained digest for one client+height."""
    body = [{"word": w, "value": v} for w, v in
            sorted(word_values.items())]
    d = ""
    for rec in body:
        d = hashlib.sha256((d + canonical(rec)).encode()).hexdigest()
    reward = 0
    for rec in body:
        sw = signed_word(rec["value"])
        if sw is not None:
            reward += sw
    rcpt = {"client": client, "height": height, "words": len(body),
            "reward": reward, "digest": d}
    rcpt["sig"] = sign(canonical(rcpt), key)
    return rcpt


def audit(path, key, words):
    """Whole log -> (findings, receipts per (client, height))."""
    findings, groups = [], {}
    for n, rec in read_jsonl(path):
        ent = parse_event(rec, words)
        if ent is None:
            findings.append((WARN, "malformed-event", f"line {n}"))
            continue
        client, height, word, value, sig = ent
        if word >= words:
            findings.append((FAIL, "word-out-of-range",
                             f"line {n} word {word} >= {words}"))
            continue
        if signed_word(value) is None:
            findings.append((WARN, "value-not-word",
                             f"line {n} {value!r}"))
        if not verify_word_sig(client, height, word, value, sig, key):
            findings.append((FAIL, "unsigned-word",
                             f"line {n} {client}/{height}/{word}"))
        g = groups.setdefault((client, height), {})
        if word in g:
            findings.append((WARN, "reread-word",
                             f"{client}/{height}/{word}"))
        g[word] = value
    receipts = {}
    for (client, height), wv in sorted(groups.items()):
        missing = [w for w in range(words) if w not in wv]
        for w in missing:
            findings.append((FAIL, "missing-word",
                             f"{client}/{height}/{w}"))
        receipts[(client, height)] = block_receipt(
            client, height, wv, key)
    by_height = {}
    for (client, height), rcpt in receipts.items():
        by_height.setdefault(height, {})[client] = rcpt
    for height, per in sorted(by_height.items()):
        rewards = {r["reward"] for r in per.values()}
        if len(per) > 1 and len(rewards) > 1:
            findings.append((WARN, "cross-client-divergence",
                             f"height {height}: "
                             f"{sorted(per.items())}"))
    return findings, receipts


def main(argv=None):
    ap = argparse.ArgumentParser(
        description="per-word signed block-reward read audit")
    ap.add_argument("events", help="light-client read events JSONL")
    ap.add_argument("--key", required=True, help="hex HMAC key")
    ap.add_argument("--words", type=int, default=8,
                    help="words per block reward (default 8)")
    ap.add_argument("--emit", default=None,
                    help="write per-block receipts JSONL here")
    args = ap.parse_args(argv)

    key = parse_key(args.key)
    if key is None:
        print("bad --key: need hex", file=sys.stderr)
        return 2
    if args.words <= 0:
        print("bad --words", file=sys.stderr)
        return 2
    try:
        findings, receipts = audit(args.events, key, args.words)
    except OSError as e:
        print(f"cannot read events: {e}", file=sys.stderr)
        return 2
    for sev, code, what in findings:
        print(f"{sev} {code} {what}", file=sys.stderr)
    lines = [canonical(r) for r in receipts.values()]
    if args.emit:
        with open(args.emit, "w") as fh:
            fh.write("\n".join(lines) + ("\n" if lines else ""))
    for ln in lines:
        print(ln)
    return 1 if findings else 0


def make_event(client, height, word, value, key):
    """Build one signed read-event record (test/producer helper)."""
    rec = {"client": client, "height": height, "word": word,
           "value": value}
    rec["sig"] = sign(canonical(rec), key)
    return rec


def self_test():
    tmp = tempfile.mkdtemp(prefix="rwwrd-")
    events = os.path.join(tmp, "events.jsonl")
    emitted = os.path.join(tmp, "receipts.jsonl")
    key = parse_key("cd" * 32)
    assert key is not None and parse_key("zz") is None

    # two's complement: negatives, positives, rejects
    assert signed_word("0x0000012c") == 300
    assert signed_word("ffffffff") == -1
    assert signed_word("0xffffff9c") == -100
    assert signed_word("80000000") == -(1 << 31)
    assert signed_word("7fffffff") == (1 << 31) - 1
    assert signed_word("0x12") is None, "wrong width"
    assert signed_word("0x0000zz12") is None
    assert signed_word(7) is None

    ev = make_event("lc-7", 812345, 0, "0x0000012c", key)
    assert isinstance(ev["sig"], str) and len(ev["sig"]) == 64
    assert verify_word_sig("lc-7", 812345, 0, "0x0000012c",
                           ev["sig"], key)
    # sig covers client, height, word and value
    assert not verify_word_sig("lc-8", 812345, 0, "0x0000012c",
                               ev["sig"], key)
    assert not verify_word_sig("lc-7", 812346, 0, "0x0000012c",
                               ev["sig"], key)
    assert not verify_word_sig("lc-7", 812345, 1, "0x0000012c",
                               ev["sig"], key)
    assert not verify_word_sig("lc-7", 812345, 0, "0x0000012d",
                               ev["sig"], key)
    assert not verify_word_sig("lc-7", 812345, 0, "0x0000012c",
                               ev["sig"] + "0", key)
    assert not verify_word_sig("lc-7", 812345, 0, "0x0000012c",
                               None, key)

    # assembly: 300 + (-100) + 1 = 201; digest is order/churn stable
    # but content sensitive
    r1 = block_receipt("lc-7", 812345,
                       {0: "0x0000012c", 1: "0xffffff9c",
                        2: "0x00000001"}, key)
    assert r1["reward"] == 201 and r1["words"] == 3, r1
    r2 = block_receipt("lc-7", 812345,
                       {1: "0xffffff9c", 0: "0x0000012c",
                        2: "0x00000001"}, key)
    assert r1["digest"] == r2["digest"], "word order must not matter"
    r3 = block_receipt("lc-7", 812345,
                       {0: "0x0000012c", 1: "0xffffff9c",
                        2: "0x00000002"}, key)
    assert r3["digest"] != r1["digest"], "content must matter"
    body = {k: v for k, v in r1.items() if k != "sig"}
    assert hmac.compare_digest(sign(canonical(body), key), r1["sig"])
    assert r3["reward"] == 202

    # a complete 3-word block for two clients, word-at-a-time
    words = [("0x0000012c", "0xffffff9c", "0x00000001"),
             ("0x0000012c", "0xffffff9c", "0x00000001")]
    with open(events, "w") as fh:
        for ci, client in enumerate(("lc-7", "lc-9")):
            for w, v in enumerate(words[ci]):
                rec = make_event(client, 812345, w, v, key)
                fh.write(json.dumps(rec) + "\n")
    rc = main([events, "--key", "cd" * 32, "--words", "3",
               "--emit", emitted])
    assert rc == 0, "complete signed word-at-a-time reads are clean"
    with open(emitted) as fh:
        rcpts = [json.loads(l) for l in fh if l.strip()]
    assert len(rcpts) == 2 and all(r["reward"] == 201
                                   for r in rcpts), rcpts

    # drop word 2 for lc-9 -> missing-word FAIL
    with open(events, "w") as fh:
        for client in ("lc-7", "lc-9"):
            for w, v in enumerate(words[0]):
                if client == "lc-9" and w == 2:
                    continue
                fh.write(json.dumps(
                    make_event(client, 812345, w, v, key)) + "\n")
    f, r = audit(events, key, 3)
    assert any(c == "missing-word" and "lc-9/812345/2" in w
               for _, c, w in f), f
    rc = main([events, "--key", "cd" * 32, "--words", "3"])
    assert rc == 1, "incomplete block is a finding"


    # reread + out-of-range + bad value + forged sig
    with open(events, "w") as fh:
        fh.write(json.dumps(make_event("lc-7", 1, 0, "0x00000001",
                                       key)) + "\n")
        fh.write(json.dumps(make_event("lc-7", 1, 0, "0x00000001",
                                       key)) + "\n")
        fh.write(json.dumps(make_event("lc-7", 1, 5, "0x00000001",
                                       key)) + "\n")
        bad = make_event("lc-7", 1, 1, "0x00000002", key)
        bad["value"] = "0x00000003"  # sig no longer matches
        fh.write(json.dumps(bad) + "\n")
        wide = make_event("lc-7", 1, 2, "0x1", key)
        fh.write(json.dumps(wide) + "\n")
    f, r = audit(events, key, 4)
    codes = {c for _, c, _ in f}
    assert {"reread-word", "word-out-of-range", "unsigned-word",
            "value-not-word", "missing-word"} <= codes, f
    # word 5 exceeds --words 4 -> FAIL; forged value breaks its HMAC
    rc = main([events, "--key", "cd" * 32, "--words", "4"])
    assert rc == 1, "reread/forged/wide/mixed findings flag"

    # cross-client divergence at the same height
    with open(events, "w") as fh:
        for client, vals in (("lc-7", ("0x00000001", "0x00000002")),
                             ("lc-9", ("0x00000001", "0x00000005"))):
            for w, v in enumerate(vals):
                fh.write(json.dumps(
                    make_event(client, 7, w, v, key)) + "\n")
    f, r = audit(events, key, 2)
    assert any(c == "cross-client-divergence" for _, c, _ in f), f
    # agree -> no divergence
    with open(events, "w") as fh:
        for client in ("lc-7", "lc-9"):
            for w, v in enumerate(("0x00000001", "0x00000002")):
                fh.write(json.dumps(
                    make_event(client, 7, w, v, key)) + "\n")
    f, r = audit(events, key, 2)
    assert not any(c == "cross-client-divergence" for _, c, _ in f), f
    rc = main([events, "--key", "cd" * 32, "--words", "2"])
    assert rc == 0, "agreeing clients are clean"

    # malformed lines and usage paths
    with open(events, "w") as fh:
        fh.write("{oops\n")
    rc = main([events, "--key", "cd" * 32, "--words", "2"])
    assert rc == 1, "malformed line is a finding"
    rc = main(["nope.jsonl", "--key", "cd" * 32])
    assert rc == 2, "missing events file is usage/IO"
    rc = main([events, "--key", "nothex"])
    assert rc == 2, "bad key is usage"
    rc = main([events, "--key", "cd" * 32, "--words", "0"])
    assert rc == 2, "bad --words is usage"
    print("OK reward-word-read-audit: two's-complement word parsing "
          "(negatives/width rejects), HMAC per-word sigs cover "
          "client/height/word/value (tamper-rejecting), missing/reread/"
          "forged/wide/malformed verdicts, order-insensitive chained "
          "block digest + signed assembly receipt, cross-client "
          "divergence, emit, CLI rc 0/1/2")


if __name__ == "__main__":
    if "--self-test" in sys.argv:
        self_test()  # falls through; rc 0 (probe hook runs after this)
    else:
        raise SystemExit(main())
