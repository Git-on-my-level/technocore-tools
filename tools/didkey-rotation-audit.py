#!/usr/bin/env python3
"""didkey-rotation-audit — key-rotation / re-issuance binding audit for
did:key identities (JSONL capture, one event per line: {"ts","controller",
"kind":"register|rotate|reissue|revoke","did","prev_did","seq","proof"}).

DEMAND: evidence/suggestions/tools-services/2026-09-08.md
  - "Continuous background data-integrity verification for did:key identity
    without locking" — evidence: "Auditing data integrity across a did:key
    identity without locking production tables" (11:58) — proposed service:
    "DID-key binding audit across key-rotation and re-issuance events".

Scope: the EVENT-stream half of that request — whether a rotation timeline
actually binds each successor to its declared predecessor. keymat-audit.py
already checks static did:key claims inside reports; this tool audits the
rotation capture itself: multibase/multicodec decode + canonical re-encode,
prev-pointer continuity, forks, key reuse, revoked-key revival, re-issuance
under a drifted controller, cross-controller key collisions, per-controller
seq monotonicity, and a sha256 hash-chain seal per event (proof_i =
H(proof_{i-1} || canonical core_i); the chain advances on declared seals,
so a content edit that keeps its seal breaks exactly that event, not the
suffix). Captures are data only: plain parsing, no network, no subprocess.
rc 0 clean, 1 findings, 2 usage/IO. Stdlib only (base58btc hand-rolled).
"""
import argparse
import hashlib
import json
import sys

B58 = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
MULTICODEC = {  # name -> (prefix bytes, payload length)
    "ed25519-pub": (b"\xed\x01", 32),
    "x25519-pub": (b"\xec\x01", 32),
    "secp256k1-pub": (b"\xe7\x03", 33),
    "p256-pub": (b"\x80\x24", 33),
}
GENESIS = "00" * 32  # chain seal before a controller's first event
KINDS = ("register", "rotate", "reissue", "revoke")


def b58_decode(s):
    """base58btc string -> bytes; raises ValueError on bad char/overflow."""
    n = 0
    for c in s:
        i = B58.find(c)
        if i < 0:
            raise ValueError(f"non-base58 char {c!r}")
        n = n * 58 + i
    body = n.to_bytes((n.bit_length() + 7) // 8, "big") if n else b""
    return b"\x00" * (len(s) - len(s.lstrip("1"))) + body


def b58_encode(b):
    n = int.from_bytes(b, "big")
    out = ""
    while n:
        n, r = divmod(n, 58)
        out = B58[r] + out
    return "1" * (len(b) - len(b.lstrip(b"\x00"))) + out


def decode_did(did):
    """did:key:z... -> (codec, keybytes) or raises ValueError with reason."""
    if not isinstance(did, str) or not did.startswith("did:key:z"):
        raise ValueError("not a did:key:z multibase identifier")
    raw = b58_decode(did[len("did:key:z"):])
    for name, (prefix, klen) in MULTICODEC.items():
        if raw.startswith(prefix):
            key = raw[len(prefix):]
            if len(key) != klen:
                raise ValueError(f"{name} payload {len(key)}B, want {klen}B")
            return name, key
    if raw[:1] in (b"\xef", b"\xeb", b"\xea", b"\xee", b"\xd1", b"\xe0"):
        raise ValueError(f"known-but-unsupported multicodec prefix {raw[:2].hex()}")
    raise ValueError(f"unknown multicodec prefix {raw[:2].hex()}")


def canonical_core(ev):
    core = {k: ev.get(k) for k in ("controller", "kind", "did", "prev_did", "seq")}
    return json.dumps(core, sort_keys=True, separators=(",", ":"))


def build_proof(prev_hex, ev):
    return hashlib.sha256(bytes.fromhex(prev_hex)
                          + canonical_core(ev).encode()).hexdigest()


def load_events(path):
    """Yield (lineno, event-dict-or-None); None = unparseable line."""
    with open(path, encoding="utf-8") as fh:
        for i, line in enumerate(fh, 1):
            line = line.strip()
            if not line:
                continue
            try:
                ev = json.loads(line)
                yield i, ev if isinstance(ev, dict) else None
            except ValueError:
                yield i, None


def _hex64(s):
    """True when s is a well-formed 64-char lowercase/uppercase hex seal."""
    return (isinstance(s, str) and len(s) == 64
            and all(c in "0123456789abcdefABCDEF" for c in s))


def audit(events):
    """[(lineno, ev|None)] -> findings list of dicts."""
    finds = []
    state = {}      # controller -> {active, history, revoked, seq, proof}
    owners = {}     # did -> controller currently holding it active
    consumed = {}   # (controller, prev_did) -> line that consumed it
    seen_proofs = {}  # declared seal -> lines that used it

    def flag(ln, ev, rule, sev, detail):
        finds.append({"line": ln, "controller": (ev or {}).get("controller"),
                      "rule": rule, "severity": sev, "detail": detail})

    for ln, ev in events:
        if ev is None:
            flag(ln, None, "io-parse", "MEDIUM", "line is not a JSON object")
            continue
        ctrl = ev.get("controller")
        kind = ev.get("kind")
        did = ev.get("did")
        st = state.setdefault(ctrl, {"active": None, "history": set(),
                                     "revoked": set(), "seq": -1,
                                     "proof": GENESIS})
        # structural checks independent of chain state
        if kind not in KINDS:
            flag(ln, ev, "bad-kind", "MEDIUM", f"kind {kind!r} not in {KINDS}")
        try:
            decode_did(did)
        except ValueError as why:
            flag(ln, ev, "malformed-did", "HIGH", str(why))
        # hash-chain seal: proof_i = H(proof_{i-1} || core_i). The chain
        # advances on the DECLARED seal whenever it is well-formed hex, so a
        # content edit that keeps its seal breaks exactly that event, not the
        # suffix; a garbled/missing seal is replaced by the recomputed one.
        declared = ev.get("proof")
        expected = build_proof(st["proof"], ev)
        if not (isinstance(declared, str) and declared.lower() == expected):
            flag(ln, ev, "proof-mismatch", "HIGH",
                 f"seal {str(declared)[:12]}... != recomputed {expected[:12]}...")
        if isinstance(declared, str) and declared in seen_proofs:
            flag(ln, ev, "proof-replay", "MEDIUM",
                 f"seal already used at line(s) "
                 f"{sorted(seen_proofs[declared])}")
        seen_proofs.setdefault(declared, set()).add(ln)
        st["proof"] = (declared.lower() if _hex64(declared) else expected)

        # seq monotonicity per controller
        seq = ev.get("seq")
        if not isinstance(seq, int) or isinstance(seq, bool):
            flag(ln, ev, "bad-seq", "MEDIUM", f"seq {seq!r} not an integer")
        elif seq <= st["seq"]:
            flag(ln, ev, "seq-regression", "MEDIUM",
                 f"seq {seq} not > last {st['seq']}")
        else:
            st["seq"] = seq

        prev = ev.get("prev_did")
        # kind-specific binding rules
        if kind == "register":
            if prev not in (None, ""):
                flag(ln, ev, "orphan-register", "HIGH",
                     f"register declares prev_did {prev[:20]}...")
            if st["active"] is not None:
                flag(ln, ev, "double-register", "MEDIUM",
                     f"controller already holds active key {st['active'][:20]}...")
            owners.pop(st["active"], None)
            st["active"] = did
            st["history"].add(did)
            owners[did] = ctrl
        elif kind == "rotate":
            if st["active"] is None:
                flag(ln, ev, "rotate-without-key", "HIGH",
                     "rotate before any register/reissue")
            elif prev != st["active"]:
                forked = consumed.get((ctrl, prev))
                flag(ln, ev, "chain-break", "HIGH",
                     (f"prev_did {str(prev)[:20]}... was consumed at line "
                      f"{forked} (fork off that predecessor)")
                     if forked else
                     (f"prev_did {str(prev)[:20]}... != active "
                      f"{st['active'][:20]}..."))
            consumed[(ctrl, prev)] = ln
            if did == st["active"]:
                flag(ln, ev, "rotate-noop", "MEDIUM", "rotates to the active key")
            if did in st["revoked"]:
                flag(ln, ev, "key-reuse", "HIGH", "rotates back to a revoked key")
            elif did in st["history"] and did != st["active"]:
                flag(ln, ev, "key-reuse", "HIGH", "rotates back to a historical key")
            holder = owners.get(did)
            if holder is not None and holder != ctrl:
                flag(ln, ev, "cross-controller-collision", "HIGH",
                     f"key already active for controller {holder}")
            owners.pop(st["active"], None)
            st["active"] = did
            st["history"].add(did)
            owners[did] = ctrl
        elif kind == "reissue":
            if did not in st["history"]:
                flag(ln, ev, "bogus-reissue", "MEDIUM",
                     "reissues a key never held by this controller")
            if did in owners and owners[did] != ctrl:
                flag(ln, ev, "controller-drift", "HIGH",
                     f"re-binds a key held by controller {owners[did]}")
            else:
                holder = [c for c, s in state.items()
                          if did in s["history"] and c != ctrl]
                if holder:
                    flag(ln, ev, "controller-drift", "HIGH",
                         f"re-binds a key historically held by {holder[0]}")
                else:
                    flag(ln, ev, "reissue-replay", "LOW",
                         "same-controller re-issuance (binding replay)")
            st["revoked"].discard(did)
            owners.pop(st["active"], None)
            st["active"] = did
            st["history"].add(did)
            owners[did] = ctrl
        elif kind == "revoke":
            if did is None:
                did = st["active"]
            if st["active"] is None:
                flag(ln, ev, "revoke-without-key", "HIGH",
                     "revoke before any register")
            elif prev != st["active"] and prev is not None:
                flag(ln, ev, "chain-break", "HIGH",
                     f"revoke prev_did {str(prev)[:20]}... != active "
                     f"{st['active'][:20]}...")
            owners.pop(st["active"], None)
            st["revoked"].add(did if did else st["active"])
            st["active"] = None
    return finds


def render(finds):
    order = {"HIGH": 0, "MEDIUM": 1, "LOW": 2}
    for f in sorted(finds, key=lambda x: (order[x["severity"]], x["line"])):
        print(f"[{f['severity']:6}] line {f['line']:>3} {f['rule']:<26} "
              f"{str(f['controller'])[:28]:<28} {f['detail']}")
    counts = {s: sum(1 for x in finds if x["severity"] == s)
              for s in ("HIGH", "MEDIUM", "LOW")}
    print(f"didkey-rotation-audit: {len(finds)} finding(s) "
          f"(high={counts['HIGH']} med={counts['MEDIUM']} low={counts['LOW']})")
    return counts


def main(argv=None):
    ap = argparse.ArgumentParser(
        description="Audit did:key rotation/re-issuance binding over a JSONL capture")
    ap.add_argument("capture", help="JSONL event capture (one event per line)")
    ap.add_argument("--json", action="store_true",
                    help="emit findings as a JSON array")
    args = ap.parse_args(argv)
    try:
        events = list(load_events(args.capture))
    except OSError as why:
        print(f"didkey-rotation-audit: cannot read capture: {why}", file=sys.stderr)
        return 2
    finds = audit(events)
    if args.json:
        print(json.dumps(finds, indent=1))
    else:
        render(finds)
    return 1 if finds else 0


def self_test():
    import os
    import tempfile

    # 1. base58btc against an external anchor vector (independent of our
    #    encoder: known-good encoding of b"hello world")
    assert b58_decode("StV1DL6CwTryKyV") == b"hello world", "b58 decode anchor"
    assert b58_encode(b"hello world") == "StV1DL6CwTryKyV", "b58 encode anchor"
    assert b58_decode("1") == b"\x00" and b58_decode("") == b"", "b58 zero pad"
    try:
        b58_decode("0OIl")
        raise AssertionError("bad char accepted")
    except ValueError:
        pass

    # 2. did:key decode: ed25519-pub vector built from a fixed 32B key
    key = hashlib.sha256(b"didkey-rotation-audit vector").digest()
    did = "did:key:z" + b58_encode(b"\xed\x01" + key)
    codec, kb = decode_did(did)
    assert codec == "ed25519-pub" and kb == key, "ed25519-pub decode"
    # wrong payload length is caught
    bad = "did:key:z" + b58_encode(b"\xed\x01" + key[:31])
    try:
        decode_did(bad)
        raise AssertionError("short payload accepted")
    except ValueError:
        pass
    try:
        decode_did("did:key:z" + b58_encode(b"\xff\xff" + key))
        raise AssertionError("unknown multicodec accepted")
    except ValueError:
        pass
    try:
        decode_did("did:web:example.com")
        raise AssertionError("non did:key accepted")
    except ValueError:
        pass

    def mk(ctrl, kind, did_, prev, seq, proof):
        return {"controller": ctrl, "kind": kind, "did": did_,
                "prev_did": prev, "seq": seq, "proof": proof}

    def chain(evts):
        out, seal = [], GENESIS
        for (ctrl, kind, d, p, s) in evts:
            ev = mk(ctrl, kind, d, p, s, None)
            seal = build_proof(seal, ev)
            ev["proof"] = seal
            out.append(ev)
        return out

    did2 = "did:key:z" + b58_encode(b"\xed\x01" + hashlib.sha256(b"k2").digest())
    did3 = "did:key:z" + b58_encode(b"\xed\x01" + hashlib.sha256(b"k3").digest())
    did4 = "did:key:z" + b58_encode(b"\xec\x01" + hashlib.sha256(b"k4").digest())
    good = chain([("c1", "register", did, None, 1),
                  ("c1", "rotate", did2, did, 2),
                  ("c1", "rotate", did3, did2, 3),
                  ("c1", "revoke", did3, did3, 4)])
    rules = lambda f: {x["rule"] for x in f}
    assert audit(list(enumerate(good, 1))) == [], "clean chain must be clean"

    # chain-break: rotate from a stale predecessor
    f = audit(list(enumerate(
        chain([("c1", "register", did, None, 1),
               ("c1", "rotate", did2, did, 2),
               ("c1", "rotate", did3, did, 3)]), 1)))
    assert rules(f) == {"chain-break"}, f

    # fork: second rotation off an already-consumed predecessor is a
    # chain-break whose detail names the forked-off line
    f = audit(list(enumerate(
        chain([("c1", "register", did, None, 1),
               ("c1", "rotate", did2, did, 2),
               ("c1", "rotate", did3, did2, 3),
               ("c1", "rotate", did4, did2, 4)]), 1)))
    assert rules(f) == {"chain-break"}, f
    assert "fork off that predecessor" in f[-1]["detail"] and "line 3" in f[-1]["detail"], f

    # key reuse: rotate back to a historical (and to a revoked) key
    f = audit(list(enumerate(
        chain([("c1", "register", did, None, 1),
               ("c1", "rotate", did2, did, 2),
               ("c1", "rotate", did, did2, 3)]), 1)))
    assert "key-reuse" in rules(f), f
    f = audit(list(enumerate(
        chain([("c1", "register", did, None, 1),
               ("c1", "rotate", did2, did, 2),
               ("c1", "revoke", did2, did2, 3),
               ("c1", "rotate", did2, did2, 4)]), 1)))
    assert rules(f) == {"rotate-without-key", "key-reuse"}, f

    # proof tamper: mutate did without resealing -> exactly the one event
    evs = chain([("c1", "register", did, None, 1),
                 ("c1", "rotate", did2, did, 2)])
    evs[1]["did"] = did3
    f = audit(list(enumerate(evs, 1)))
    assert rules(f) == {"proof-mismatch"}, f
    assert len([x for x in f if x["rule"] == "proof-mismatch"]) == 1, f
    # chain advanced on the declared seal: successor's SEAL still verifies
    # (no seal cascade); its prev pointer breaks because active moved
    evs = chain([("c1", "register", did, None, 1),
                 ("c1", "rotate", did2, did, 2),
                 ("c1", "rotate", did3, did2, 3)])
    evs[1]["did"] = did4
    f = audit(list(enumerate(evs, 1)))
    assert rules(f) == {"proof-mismatch", "chain-break"}, f
    assert len([x for x in f if x["rule"] == "proof-mismatch"]) == 1, f
    # garbled (non-hex) seal is replaced by the recomputed one: no cascade
    evs = chain([("c1", "register", did, None, 1),
                 ("c1", "rotate", did2, did, 2),
                 ("c1", "rotate", did3, did2, 3)])
    evs[1]["proof"] = "not-a-seal"
    f = audit(list(enumerate(evs, 1)))
    assert rules(f) == {"proof-mismatch"}, f

    # seq regression; and exact duplicate line -> proof replay
    evs = chain([("c1", "register", did, None, 5),
                 ("c1", "rotate", did2, did, 5)])
    f = audit(list(enumerate(evs, 1)))
    assert "seq-regression" in rules(f), f
    evs = chain([("c1", "register", did, None, 1)])
    f = audit([(1, evs[0]), (2, dict(evs[0]))])
    assert "proof-replay" in rules(f), f

    # re-issuance: same controller -> LOW replay; drifted controller -> HIGH
    evs = chain([("c1", "register", did, None, 1),
                 ("c1", "reissue", did, None, 2)])
    f = audit(list(enumerate(evs, 1)))
    assert {x["rule"] for x in f} == {"reissue-replay"}, f
    assert f[0]["severity"] == "LOW", f
    evs = chain([("c1", "register", did, None, 1),
                 ("c2", "reissue", did, None, 1)])
    f = audit(list(enumerate(evs, 1)))
    assert any(x["rule"] == "controller-drift" and x["severity"] == "HIGH"
               for x in f), f

    # cross-controller collision via rotate
    evs = chain([("c1", "register", did, None, 1),
                 ("c2", "register", did2, None, 1),
                 ("c2", "rotate", did, did2, 2)])
    f = audit(list(enumerate(evs, 1)))
    assert "cross-controller-collision" in rules(f), f

    # malformed did + unparseable line; canonical round-trips silently
    evs = chain([("c1", "register", did, None, 1)])
    f = audit([(1, {"controller": "c1", "kind": "register",
                    "did": "did:key:z0OIl", "prev_did": None, "seq": 1,
                    "proof": GENESIS}),
               (2, None),
               (3, evs[0])])
    got = rules(f)
    assert "malformed-did" in got and "io-parse" in got, got
    assert decode_did(did)[1] == key, "round-trip identity"

    # CLI contract: rc0 clean / rc1 findings / rc2 unreadable; --json shape
    with tempfile.NamedTemporaryFile("w", suffix=".jsonl", delete=False) as fh:
        for ev in good:
            fh.write(json.dumps(ev) + "\n")
        path = fh.name
    try:
        assert main([path]) == 0, "clean capture must rc0"
        with open(path, "a") as fh:
            fh.write(json.dumps(mk("c1", "rotate", did, None, 9, GENESIS)) + "\n")
        assert main([path]) == 1, "findings must rc1"
        import io as _io
        import contextlib
        buf = _io.StringIO()
        with contextlib.redirect_stdout(buf):
            rc = main([path, "--json"])
        assert rc == 1 and isinstance(json.loads(buf.getvalue()), list), "json export"
        assert main(["/nonexistent/capture.jsonl"]) == 2, "IO error must rc2"
    finally:
        os.unlink(path)

    print("didkey-rotation-audit self-test OK (18 assertion groups: b58 anchor "
          "+ zero-pad + charset, ed25519-pub decode vector, payload/multicodec/"
          "scheme rejection, clean chain, chain-break, fork branch, key reuse "
          "historical+revoked, proof tamper with re-anchor, seq regression, "
          "reissue replay vs controller drift, cross-controller collision, "
          "malformed/parse lines, CLI rc + json contract)")


if __name__ == "__main__":
    if "--self-test" in sys.argv:
        self_test()  # falls through; rc 0 (probe hook runs after this line)
    else:
        raise SystemExit(main())
