#!/usr/bin/env python3
"""sig-claim-audit — audit of signature / identity claims made in a
room transcript (JSONL claim records): flags claims that assert a
signature is valid with no verification artifact behind them, circular
self-attestation, retraction references to claims that do not exist,
speakers contradicting themselves on the same subject, and
attestations that bind only key possession where the claim is about
computation correctness. Deterministic; claims are data only.

DEMAND: evidence/suggestions/tools-services/2026-10-16.md
  - request (11:xx run): "verify identity/signature authenticity claims
    being made across the room (unve…/unverified)" — proposed service:
    hermes-tools verification of signature-authenticity claims.
  - request: "verify that signatures establish computation correctness,
    not just key possession" — proposed service: binding audit.
  - request (later run): "distinguishing key possession from computation
    correctness — evidence: 'Sign…'".
  This tool serves those asks offline: input is the claim-record
  export, output is named findings (rule id, claim id, detail) plus a
  verdict. Stdlib only; nothing is executed."""
import argparse
import hashlib
import json
import sys

SEVS = ("BLOCK", "WARN", "INFO")
ASSERTS = ("signature_valid", "signature_invalid", "identity",
           "computation")


def parse_claims(path):
    """file -> [claim dicts]; first bad line raises ValueError."""
    claims = []
    with open(path, encoding="utf-8") as fh:
        for lineno, line in enumerate(fh, 1):
            line = line.strip()
            if not line:
                continue
            try:
                c = json.loads(line)
            except ValueError as exc:
                raise ValueError("line {}: not JSON: {}".format(lineno, exc))
            if not isinstance(c, dict) or "id" not in c or \
                    c.get("asserts") not in ASSERTS:
                raise ValueError("line {}: need 'id' and 'asserts' in {}"
                                 .format(lineno, "/".join(ASSERTS)))
            claims.append(c)
    return claims


def claim_bind(c):
    """claim -> set of binding tokens (default empty)."""
    binds = c.get("binds", [])
    if not isinstance(binds, list):
        return set()
    return {str(b) for b in binds}


def audit(claims):
    """claims -> (findings, stats); findings are (rule, id, detail)."""
    finds = []
    by_id = {}
    for c in claims:
        cid = str(c["id"])
        if cid in by_id:
            finds.append(("claim-dup-id", cid,
                          "claim id used more than once"))
        by_id[cid] = c
    seen = {}
    for c in claims:
        cid = str(c["id"])
        asserts = c["asserts"]
        binds = claim_bind(c)
        if asserts == "signature_valid" and not c.get("verified_by"):
            finds.append(("claim-unverified", cid,
                          "asserts a valid signature with no verification "
                          "artifact"))
        ref = c.get("verified_by")
        if isinstance(ref, str) and ref == cid:
            finds.append(("claim-self-attest", cid,
                          "cites itself as its own verification artifact"))
        ret = c.get("retracts")
        if ret is not None:
            if str(ret) not in by_id:
                finds.append(("claim-bad-retract", cid,
                              "retracts '{}' which does not exist"
                              .format(ret)))
            elif str(ret) == cid:
                finds.append(("claim-self-retract", cid,
                              "retracts itself"))
        if asserts == "computation" and "computation" not in binds:
            detail = ("computation claim binds only {} — key possession "
                      "is not computation correctness".format(
                          sorted(binds) if binds else "nothing"))
            finds.append(("bind-possession-only", cid, detail))
        if asserts == "identity" and "key" not in binds:
            finds.append(("bind-keyless", cid,
                          "identity claim with no key binding"))
        key = (c.get("speaker"), c.get("subject"), asserts)
        if asserts in ("signature_valid", "signature_invalid"):
            seen.setdefault(key, []).append(cid)
    for (speaker, subject, asserts), cids in sorted(
            seen.items(), key=lambda kv: str(kv[1][0])):
        if asserts == "signature_valid":
            other = (speaker, subject, "signature_invalid")
            if other in seen:
                finds.append(("claim-contradicted", cids[0],
                              "speaker '{}' says valid and invalid for "
                              "subject '{}'".format(speaker, subject)))
    stats = {"claims": len(claims),
             "unverified": sum(1 for r, _, _ in finds
                               if r == "claim-unverified"),
             "possession_only": sum(1 for r, _, _ in finds
                                    if r == "bind-possession-only")}
    return finds, stats


def verdict(findings):
    """findings -> FAIL on hard rules, AT-RISK on any finding, else CLEAN."""
    hard = {"bind-possession-only", "claim-contradicted",
            "claim-self-attest"}
    if any(r in hard for r, _, _ in findings):
        return "FAIL"
    if findings:
        return "AT-RISK"
    return "CLEAN"


def findings_digest(findings):
    canon = "\n".join("{}|{}|{}".format(r, i, d) for r, i, d in findings)
    return hashlib.sha256(canon.encode()).hexdigest()[:16]


def main(argv):
    ap = argparse.ArgumentParser(
        description="audit transcript signature/identity claims for "
                    "unverified assertions and possession-only bindings")
    ap.add_argument("claims", help="JSONL claim-record export")
    ap.add_argument("--json", action="store_true",
                    help="machine-readable report")
    args = ap.parse_args(argv)
    try:
        claims = parse_claims(args.claims)
    except OSError:
        print("sig-claim-audit: cannot read {}".format(args.claims),
              file=sys.stderr)
        return 2
    except ValueError as exc:
        print("sig-claim-audit: {}".format(exc), file=sys.stderr)
        return 2
    finds, stats = audit(claims)
    digest = findings_digest(finds)
    if args.json:
        print(json.dumps({"tool": "sig-claim-audit",
                          "verdict": verdict(finds), "digest": digest,
                          "stats": stats,
                          "findings": [{"rule": r, "claim": i, "detail": d}
                                       for r, i, d in finds]},
                         ensure_ascii=False))
        return 1 if finds else 0
    print("sig-claim-audit: {} ({} claim(s), digest {})".format(
        verdict(finds), len(claims), digest))
    for r, i, d in finds:
        print("  [{}] {} {}: {}".format(
            SEVS[0] if r in ("bind-possession-only", "claim-contradicted",
                             "claim-self-attest") else SEVS[1], r, i, d))
    return 1 if finds else 0


def self_test():
    import io
    import os
    import tempfile
    from contextlib import redirect_stdout

    def c(**kw):
        return json.dumps(kw)

    def find(lines):
        return audit([json.loads(x) for x in lines])

    # 1. clean: verified signature claim bound to a key
    good = [c(id="c1", speaker="a", subject="tx1",
              asserts="signature_valid", verified_by="artifact:x1",
              binds=["key"])]
    finds, stats = find(good)
    assert finds == [] and verdict(finds) == "CLEAN", finds
    assert stats["claims"] == 1 and stats["unverified"] == 0

    # 2. filed ask: unverified validity claims across the room -> WARN
    unv = [c(id="c2", speaker="b", subject="tx2",
             asserts="signature_valid", binds=["key"]),
           c(id="c3", speaker="b", subject="tx3",
             asserts="signature_valid", verified_by="artifact:x3",
             binds=["key"])]
    finds, stats = find(unv)
    assert [r for r, _, _ in finds] == ["claim-unverified"], finds
    assert stats["unverified"] == 1 and verdict(finds) == "AT-RISK"

    # 3. filed ask: possession-only binding on a computation claim
    poss = [c(id="c4", speaker="d", subject="job1", asserts="computation",
              verified_by="artifact:x4", binds=["key"])]
    finds, _ = find(poss)
    assert finds[0][0] == "bind-possession-only" and \
        "not computation correctness" in finds[0][2], finds
    assert verdict(finds) == "FAIL"
    bound = [c(id="c5", speaker="d", subject="job1", asserts="computation",
               verified_by="artifact:x5", binds=["key", "computation"])]
    assert find(bound)[0] == [], find(bound)

    # 4. self-attestation, bad/self retracts, contradiction, keyless id
    messy = [c(id="c6", speaker="e", subject="tx6",
               asserts="signature_valid", verified_by="c6", binds=["key"]),
             c(id="c7", speaker="e", subject="tx7",
               asserts="signature_valid", verified_by="artifact:x7",
               retracts="nope", binds=["key"]),
             c(id="c8", speaker="f", subject="tx8",
               asserts="signature_valid", verified_by="artifact:x8",
               retracts="c8", binds=["key"]),
             c(id="c9", speaker="g", subject="tx9",
               asserts="signature_valid", verified_by="artifact:x9",
               binds=["key"]),
             c(id="c10", speaker="g", subject="tx9",
               asserts="signature_invalid", verified_by="artifact:x10",
               binds=["key"]),
             c(id="c11", speaker="h", subject="id1", asserts="identity",
               verified_by="artifact:x11", binds=[])]
    finds, _ = find(messy)
    rules = {r for r, _, _ in finds}
    assert rules == {"claim-self-attest", "claim-bad-retract",
                     "claim-self-retract", "claim-contradicted",
                     "bind-keyless"}, rules
    contra = [f for f in finds if f[0] == "claim-contradicted"]
    assert contra and contra[0][1] == "c9" and "'tx9'" in contra[0][2]
    assert verdict(finds) == "FAIL"

    # 5. end-to-end CLI: rc, verdict text, digest determinism, rc 2
    with tempfile.TemporaryDirectory() as d:
        p = os.path.join(d, "claims.jsonl")
        with open(p, "w") as fh:
            fh.write("\n".join(poss) + "\n")
        buf = io.StringIO()
        with redirect_stdout(buf):
            rc = main([p, "--json"])
        doc = json.loads(buf.getvalue())
        assert rc == 1 and doc["verdict"] == "FAIL", doc
        assert doc["stats"]["possession_only"] == 1, doc
        buf = io.StringIO()
        with redirect_stdout(buf):
            main([p, "--json"])
        assert json.loads(buf.getvalue())["digest"] == doc["digest"]
        buf = io.StringIO()
        with redirect_stdout(buf):
            rc = main([p])
        assert rc == 1 and "bind-possession-only" in buf.getvalue()
        bad = os.path.join(d, "bad.jsonl")
        with open(bad, "w") as fh:
            fh.write('{"id": "z", "asserts": "trust_me"}\n')
        buf = io.StringIO()
        with redirect_stdout(buf):
            rc = main([bad])
        assert rc == 2, rc

    print("sig-claim-audit self-test OK (5 groups: verified key-bound "
          "claim is CLEAN, unverified validity claims WARNed and "
          "counted, possession-only binding on computation claims "
          "FAILs while key+computation binding passes, self-attestation "
          "/ bad and self retracts / speaker contradiction / keyless "
          "identity bookkeeping, end-to-end CLI with deterministic "
          "digest and rc 2 on malformed export)")


if __name__ == "__main__":
    if "--self-test" in sys.argv:
        self_test()  # falls through; rc 0 (probe hook runs after this)
    else:
        raise SystemExit(main(sys.argv[1:]))
