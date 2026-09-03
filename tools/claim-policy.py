#!/usr/bin/env python3
"""claim-policy — named auditor + explicit per-claim verifier policy.

DEMAND: evidence/suggestions/tools-services/2026-09-03.md
  - "who audits the attestation ledger?" / "no accountable auditor named"
    → "expose and enforce a named auditor role and versioned verifier
    policy per claim" (01:18 run)
  - "make verifier policy explicit per claim — named verifier or quorum,
    policy version, and acceptance criteria" / "No named verifier/quorum
    + canonicalization = no auditable claim" (07:30 run; same ask on
    2026-09-02: "nobody proved who verifies or under what policy").

What it does (read-only over JSON data; nothing from input is run):
  - policy registry file: {"policy_version": "vp1", "auditor": did,
    "quorum": {"k": 2, "verifiers": [did, ...]}, "require": ["id",
    "digest", "ts"], "prev_digest": null}
  - `init` mints vp1; `next` mints vp<N+1> chained to its predecessor by
    sha256 over the canonical JSON of the previous policy — a tamper-
    evident versioned governance trail.
  - `chain` verifies a policy lineage: digests link, versions strictly
    increase, every policy structurally valid.
  - `check CLAIMS.jsonl --policy POLICY` enforces, per claim:
      policy-bound   claim.policy_version == policy.policy_version
      authorization  every signature in sigs/verifier is the named
                     auditor or a quorum member
      quorum         >= k distinct authorized signatures per claim
      acceptance     every field in policy.require present and canonical
                     (id non-empty, digest = 64 hex, ts ISO-8601)
      replay         duplicate claim ids flagged on the later claim
    Verdict ACCEPT / REJECT(reasons...) per claim + summary; --json for
    machine-readable output. Exit 0 all-accept, 1 any-reject, 2 usage/IO.

Usage:
  claim-policy.py init --auditor did:key:z6MkA --quorum 2,did:B,did:C -o p.json
  claim-policy.py next p.json --auditor did:key:z6MkA -o p2.json
  claim-policy.py chain p.json p2.json
  claim-policy.py check claims.jsonl --policy p2.json [--json]

VERIFY: self-test — python3 claim-policy.py --self-test
  Real behavior on fixtures: policy structure validation (bad auditor,
  k>n, dup verifiers, bad version); digest chain link + version
  regression detection; claim acceptance; unauthorized signer; quorum
  shortfall vs met; policy-unbound version; missing digest; duplicate-id
  replay; main() exit codes 0/1 via captured stdout. Asserts, OK.
"""
import argparse
import datetime
import hashlib
import json
import os
import re
import sys
import tempfile

DID = re.compile(r"^did:\w+:[A-Za-z0-9]{8,}$")
HEX64 = re.compile(r"^[0-9a-f]{64}$")
VER = re.compile(r"^vp(\d+)$")
REQUIREABLE = ("id", "digest", "ts")


def canonical(rec):
    return json.dumps(rec, sort_keys=True, ensure_ascii=False,
                      separators=(",", ":"))


def policy_digest(p):
    return hashlib.sha256(canonical(p).encode()).hexdigest()


def make_policy(auditor, quorum=None, require=("id", "digest", "ts")):
    pol = {"policy_version": "vp1", "auditor": auditor,
           "quorum": quorum, "require": list(require), "prev_digest": None}
    return pol


def validate_policy(p):
    """Structural violations of a policy record -> list of reasons."""
    bad = []
    if not isinstance(p, dict):
        return ["policy not an object"]
    m = VER.match(str(p.get("policy_version", "")))
    if not m:
        bad.append("policy_version must be vp<N>")
    if not DID.match(str(p.get("auditor", ""))):
        bad.append("auditor must be a named did")
    q = p.get("quorum")
    if q is not None:
        if (not isinstance(q, dict) or not isinstance(q.get("k"), int)
                or not isinstance(q.get("verifiers"), list)):
            bad.append("quorum needs {k, verifiers[]}")
        else:
            k, vs = q["k"], q["verifiers"]
            if any(not DID.match(str(v)) for v in vs):
                bad.append("quorum verifier not a did")
            if len(set(vs)) != len(vs):
                bad.append("quorum verifiers duplicated")
            if not 1 <= k <= max(1, len(vs)):
                bad.append(f"quorum k={k} out of range 1..{len(vs)}")
    req = p.get("require")
    if not isinstance(req, list) or not req:
        bad.append("require must list acceptance fields")
    elif any(r not in REQUIREABLE for r in req):
        bad.append(f"require fields limited to {REQUIREABLE}")
    if p.get("prev_digest") is not None \
            and not HEX64.match(str(p.get("prev_digest"))):
        bad.append("prev_digest not sha256 hex")
    return bad


def next_policy(prev, auditor=None):
    """Mint vp<N+1> bound to its predecessor by digest."""
    pol = dict(prev)
    pol["policy_version"] = "vp%d" % (int(VER.match(prev["policy_version"])
                                           .group(1)) + 1)
    if auditor:
        pol["auditor"] = auditor
    pol["prev_digest"] = policy_digest(prev)
    return pol


def chain_ok(policies):
    """Digest-linked, strictly increasing, all valid -> (bool, reason)."""
    for p in policies:
        v = validate_policy(p)
        if v:
            return False, "invalid policy: " + "; ".join(v)
    for prev, cur in zip(policies, policies[1:]):
        if cur.get("prev_digest") != policy_digest(prev):
            return False, "digest link broken at " + str(
                cur.get("policy_version"))
        if int(VER.match(cur["policy_version"]).group(1)) <= int(
                VER.match(prev["policy_version"]).group(1)):
            return False, "version did not increase"
    return True, "linked"


def _field_ok(name, val):
    if name == "id":
        return isinstance(val, str) and val.strip() != ""
    if name == "digest":
        return isinstance(val, str) and bool(HEX64.match(val))
    if name == "ts":
        if not isinstance(val, str):
            return False
        try:
            datetime.datetime.fromisoformat(val.replace("Z", "+00:00"))
            return True
        except ValueError:
            return False
    return False


def check_claims(path, policy):
    """Enforce one policy over a JSONL claim file -> summary dict."""
    authorized = {policy["auditor"]}
    q = policy.get("quorum")
    if q:
        authorized |= set(q["verifiers"])
    need = q["k"] if q else 1
    verdicts, accepted, rejected, replays = [], 0, 0, 0
    seen = set()
    with open(path, encoding="utf-8") as fh:
        for lineno, line in enumerate(fh, 1):
            line = line.strip()
            if not line:
                continue
            try:
                rec = json.loads(line)
            except ValueError:
                verdicts.append((f"<line {lineno}>", "REJECT",
                                 ["not json"]))
                rejected += 1
                continue
            cid = rec.get("id", f"<line {lineno}>")
            reasons = []
            if str(rec.get("policy_version")) != policy["policy_version"]:
                reasons.append("policy-unbound")
            if "sigs" in rec:
                sigs = rec["sigs"]
            else:
                sigs = [rec.get("verifier")]
            sigs = [s for s in (sigs or []) if DID.match(str(s))]
            if not sigs:
                reasons.append("no valid signature")
            rogue = [s for s in sigs if s not in authorized]
            if rogue:
                reasons.append("unauthorized signer: " + ",".join(rogue))
            if len(set(sigs) & authorized) < need:
                reasons.append(f"quorum unmet ({len(set(sigs) & authorized)}"
                               f"/{need})")
            for name in policy["require"]:
                if not _field_ok(name, rec.get(name)):
                    reasons.append("acceptance: " + name)
            if cid in seen:
                reasons.append("replay of earlier claim id")
                replays += 1
            seen.add(cid)
            if reasons:
                verdicts.append((cid, "REJECT", reasons))
                rejected += 1
            else:
                verdicts.append((cid, "ACCEPT", []))
                accepted += 1
    return {"policy_version": policy["policy_version"],
            "auditor": policy["auditor"],
            "quorum_k": need if q else 1,
            "total": accepted + rejected, "accepted": accepted,
            "rejected": rejected, "replays": replays,
            "verdicts": verdicts}


def _quorum_arg(text):
    """'2,did:A,did:B' -> {"k":2,"verifiers":[...]}."""
    parts = [p.strip() for p in text.split(",") if p.strip()]
    if len(parts) < 3:
        raise argparse.ArgumentTypeError(
            "quorum needs k plus at least 2 verifiers (k,did,did)")
    k = int(parts[0])
    return {"k": k, "verifiers": parts[1:]}


def _load(path):
    with open(path, encoding="utf-8") as fh:
        return json.load(fh)


def selftest():
    A, B, C, E = ("did:key:z6MkAuditor0001", "did:key:z6MkVerifer0002",
                  "did:key:z6MkVerifer0003", "did:key:z6MkOutsider9")
    pol = make_policy(A, quorum={"k": 2, "verifiers": [B, C]})
    assert validate_policy(pol) == [], validate_policy(pol)
    p2 = next_policy(pol, auditor=A)
    assert p2["policy_version"] == "vp2" and validate_policy(p2) == []
    assert p2["prev_digest"] == policy_digest(pol)
    ok, why = chain_ok([pol, p2])
    assert ok, why
    ok, why = chain_ok([p2, pol])
    assert not ok and why == "digest link broken at vp1", why
    p_bad = next_policy(p2, auditor="not-a-did")
    assert validate_policy(p_bad) == ["auditor must be a named did"]
    assert validate_policy(dict(pol, quorum={"k": 5, "verifiers": [B, C]}))
    assert validate_policy(dict(pol, quorum={"k": 1, "verifiers": [B, B]}))
    assert validate_policy(dict(pol, policy_version="v9"))
    assert validate_policy(dict(pol, require=["nope"]))
    # claims: accept / quorum-met / unauthorized / unbound / no-digest /
    # replay-of-id; plus one single-sig claim under a no-quorum policy
    td = tempfile.mkdtemp(prefix="claim-policy-")
    claims = os.path.join(td, "claims.jsonl")
    rows = [
        {"id": "c1", "ts": "2026-09-03T07:00:00Z", "digest": "a" * 64,
         "policy_version": "vp2", "sigs": [B, C]},
        {"id": "c2", "ts": "2026-09-03T07:01:00Z", "digest": "b" * 64,
         "policy_version": "vp2", "sigs": [A, B]},
        {"id": "c3", "ts": "2026-09-03T07:02:00Z", "digest": "c" * 64,
         "policy_version": "vp2", "sigs": [E]},
        {"id": "c4", "ts": "2026-09-03T07:03:00Z", "digest": "d" * 64,
         "policy_version": "vp1", "sigs": [B, C]},
        {"id": "c5", "ts": "2026-09-03T07:04:00Z", "digest": "short",
         "policy_version": "vp2", "sigs": [B, C]},
        {"id": "c1", "ts": "2026-09-03T07:05:00Z", "digest": "a" * 64,
         "policy_version": "vp2", "sigs": [B, C]},
        "not json",
    ]
    with open(claims, "w", encoding="utf-8") as fh:
        fh.write("\n".join(json.dumps(r) if isinstance(r, dict) else r
                           for r in rows) + "\n")
    r = check_claims(claims, p2)
    assert r["total"] == 7 and r["accepted"] == 2, r
    assert r["rejected"] == 5 and r["replays"] == 1, r
    v_c1 = [v for v in r["verdicts"] if v[0] == "c1"]
    assert len(v_c1) == 2, v_c1
    assert v_c1[0][1] == "ACCEPT", v_c1[0]
    assert v_c1[1][1] == "REJECT", v_c1[1]
    assert "replay of earlier claim id" in v_c1[1][2]
    by = {v[0]: v for v in r["verdicts"] if v[0] != "c1"}
    assert by["c2"][1] == "ACCEPT" and by["c4"][1] == "REJECT"
    assert "unauthorized signer: " + E in by["c3"][2]
    assert "policy-unbound" in by["c4"][2]
    assert "acceptance: digest" in by["c5"][2]
    assert by["<line 7>"][1] == "REJECT" and by["<line 7>"][2] == ["not json"]
    solo = make_policy(A)
    solo2 = {"id": "s1", "ts": "2026-09-03T08:00:00Z", "digest": "e" * 64,
             "policy_version": "vp1", "verifier": A}
    solo_path = os.path.join(td, "solo.jsonl")
    with open(solo_path, "w", encoding="utf-8") as fh:
        fh.write(json.dumps(solo2) + "\n")
    assert check_claims(solo_path, solo)["accepted"] == 1
    # CLI surface: init/next/chain/check exit codes + summary line
    import contextlib
    import io
    p_path = os.path.join(td, "p.json")
    buf = io.StringIO()
    with contextlib.redirect_stdout(buf):
        rc = main(["init", "--auditor", A,
                   "--quorum", f"2,{B},{C}", "-o", p_path])
    assert rc == 0 and _load(p_path)["policy_version"] == "vp1"
    p2_path = os.path.join(td, "p2.json")
    chk = io.StringIO()
    with contextlib.redirect_stdout(chk):
        assert main(["next", p_path, "-o", p2_path]) == 0
        assert main(["chain", p_path, p2_path]) == 0
        assert main(["chain", p2_path, p_path]) == 1
        assert main(["check", claims, "--policy", p2_path]) == 1
    assert "REJECT 5" in chk.getvalue() and "replays 1" in chk.getvalue()
    clean = os.path.join(td, "clean.jsonl")
    with open(clean, "w", encoding="utf-8") as fh:
        fh.write(json.dumps({"id": "k1", "ts": "2026-09-03T09:00:00Z",
                             "digest": "f" * 64, "policy_version": "vp2",
                             "sigs": [B, C]}) + "\n")
    out = io.StringIO()
    with contextlib.redirect_stdout(out):
        rc = main(["check", clean, "--policy", p2_path, "--json"])
    j = json.loads(out.getvalue())
    assert rc == 0 and j["accepted"] == 1 and j["rejected"] == 0
    print("OK claim-policy self-test: policy validation, digest chain + "
          "version regression, authorization/quorum/acceptance/replay "
          "verdicts, exit codes, --json")


def main(argv=None):
    ap = argparse.ArgumentParser(
        prog="claim-policy",
        description="named auditor + per-claim verifier policy registry")
    sub = ap.add_subparsers(dest="cmd", required=True)
    pi = sub.add_parser("init", help="mint a vp1 policy")
    pi.add_argument("--auditor", required=True)
    pi.add_argument("--quorum", type=_quorum_arg, default=None)
    pi.add_argument("-o", "--out", default="-")
    pn = sub.add_parser("next", help="mint vp<N+1> chained to POLICY")
    pn.add_argument("policy")
    pn.add_argument("--auditor")
    pn.add_argument("-o", "--out", default="-")
    pc = sub.add_parser("chain", help="verify a policy lineage")
    pc.add_argument("policies", nargs="+")
    pk = sub.add_parser("check", help="check CLAIMS against POLICY")
    pk.add_argument("claims")
    pk.add_argument("--policy", required=True)
    pk.add_argument("--json", action="store_true")
    args = ap.parse_args(argv)
    try:
        if args.cmd == "init":
            pol = make_policy(args.auditor, args.quorum)
            bad = validate_policy(pol)
            if bad:
                print("invalid policy: " + "; ".join(bad), file=sys.stderr)
                return 2
            blob = json.dumps(pol, indent=2) + "\n"
            if args.out == "-":
                sys.stdout.write(blob)
            else:
                open(args.out, "w", encoding="utf-8").write(blob)
            return 0
        if args.cmd == "next":
            prev = _load(args.policy)
            bad = validate_policy(prev)
            if bad:
                print("previous policy invalid: " + "; ".join(bad),
                      file=sys.stderr)
                return 2
            pol = next_policy(prev, args.auditor)
            if validate_policy(pol):
                print("minted policy invalid", file=sys.stderr)
                return 2
            blob = json.dumps(pol, indent=2) + "\n"
            if args.out == "-":
                sys.stdout.write(blob)
            else:
                open(args.out, "w", encoding="utf-8").write(blob)
            return 0
        if args.cmd == "chain":
            pols = [_load(p) for p in args.policies]
            ok, why = chain_ok(pols)
            print(("CHAIN OK: " if ok else "CHAIN BROKEN: ") + why)
            return 0 if ok else 1
        pol = _load(args.policy)
        bad = validate_policy(pol)
        if bad:
            print("invalid policy: " + "; ".join(bad), file=sys.stderr)
            return 2
        r = check_claims(args.claims, pol)
        if args.json:
            print(json.dumps(r, indent=2))
        else:
            print(f"policy {r['policy_version']} auditor {r['auditor']} "
                  f"quorum k={r['quorum_k']}")
            for cid, verdict, reasons in r["verdicts"]:
                tail = (" [" + "; ".join(reasons) + "]") if reasons else ""
                print(f"  {verdict} {cid}{tail}")
            print(f"total {r['total']}  ACCEPT {r['accepted']}  "
                  f"REJECT {r['rejected']}  replays {r['replays']}")
        return 0 if r["rejected"] == 0 else 1
    except (OSError, ValueError, json.JSONDecodeError) as exc:
        print(f"claim-policy: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    if "--self-test" in sys.argv:
        selftest()
    else:
        raise SystemExit(main())
