#!/usr/bin/env python3
"""listing-facts-audit — listing claim vs fact-registry verification audit.

DEMAND: evidence/suggestions/tools-services/ (file citations below)
  - "Aave V4 mainnet verification (contract addr, audit firm, TVL, launch date)"
  - "Audit TVL, validator count, and audit numbers for QuFi on BTC testnet"
  - "Verification of zk_audit contract addresses, deployment tx hashes, and audit reports."
  - "ERC-20 contract verification for listing audit"
  Scope: reconcile captured listing claims against a fact registry; JSONL
    with two record kinds, discriminated on "kind". claim: {"kind":"claim",
    "protocol","contract","deploy_tx","audit_firm","tvl","validators",
    "launch_date","ts"}; fact: {"kind":"fact","protocol","contract",
    "deploy_tx","audit_firm","audit_report_sha256","tvl","validators",
    "launch_date","source"}. Flags malformed contract addresses and
    deployment tx hashes, claims no fact record binds, TVL and validator
    drift past 0.10/0.50 relative bands, audit-firm mismatch, claim launch
    dates preceding the registry record, conflicting claims on one
    contract, and unused registry entries. Records are data only: plain
    regex/json parsing, no network, no subprocess, nothing executed.
    rc 0 clean, 1 findings, 2 usage/IO. Stdlib only.
"""
import argparse
import io
import json
import os
import re
import sys
import tempfile
from contextlib import redirect_stdout
from datetime import datetime, timezone

ADDR_RE = re.compile(r"\A0x[0-9a-fA-F]{40}\Z")
TX_RE = re.compile(r"\A0x[0-9a-fA-F]{64}\Z")
SEVS = ("BLOCK", "WARN", "INFO")


def addr_valid(c):
    """True when c is 0x + 40 hex chars (hex case-insensitive)."""
    return isinstance(c, str) and ADDR_RE.match(c) is not None


def txhash_valid(h):
    """True when h is 0x + 64 hex chars (deployment tx hash)."""
    return isinstance(h, str) and TX_RE.match(h) is not None


def _f(sev, kind, origin, detail):
    """Uniform finding dict."""
    return {"severity": sev, "kind": kind, "origin": origin, "detail": detail}


def _num(v):
    """True for real (non-bool) numbers."""
    return isinstance(v, (int, float)) and not isinstance(v, bool)


def parse_ts(v):
    """Date/timestamp value -> epoch float, else None (ISO-8601 or number)."""
    if isinstance(v, bool):
        return None
    if isinstance(v, (int, float)):
        return float(v)
    if not isinstance(v, str) or not v.strip():
        return None
    try:
        dt = datetime.fromisoformat(v.strip().replace("Z", "+00:00"))
    except ValueError:
        return None
    if dt.tzinfo is None:  # naive values are pinned to UTC for determinism
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.timestamp()


def load_jsonl(path):
    """Read JSONL -> (records, bad_line_numbers); blank lines skipped."""
    records, bad = [], []
    with open(path, "r", encoding="utf-8") as fh:
        for n, line in enumerate(fh, 1):
            s = line.strip()
            if not s:
                continue
            try:
                rec = json.loads(s)
            except ValueError:
                bad.append(n)
                continue
            if isinstance(rec, dict):
                records.append(rec)
            else:
                bad.append(n)
    return records, bad


def fact_index(facts):
    """Index fact records by lowercase contract address and by protocol."""
    idx = {"contract": {}, "protocol": {}}
    for f in facts:
        c = f.get("contract")
        if isinstance(c, str) and c.strip():
            idx["contract"].setdefault(c.strip().lower(), []).append(f)
        p = f.get("protocol")
        if isinstance(p, str) and p.strip():
            idx["protocol"].setdefault(p.strip(), []).append(f)
    return idx


def match_fact(claim, idx):
    """First fact bound by contract address, else by protocol, else None."""
    c = claim.get("contract")
    if isinstance(c, str) and c.strip().lower() in idx["contract"]:
        return idx["contract"][c.strip().lower()][0]
    p = claim.get("protocol")
    if isinstance(p, str) and p.strip() in idx["protocol"]:
        return idx["protocol"][p.strip()][0]
    return None


def _origin(c, i):
    """Stable finding origin for the i-th claim record."""
    return "%s#%d" % (c.get("protocol", "?"), i)


def _rel(a, b):
    """Relative gap |a-b|/|b| for numbers with nonzero denominator, else None."""
    if not _num(a) or not _num(b) or float(b) == 0.0:
        return None
    return abs(float(a) - float(b)) / abs(float(b))


def _band(gap):
    """Severity for a relative gap: None, WARN past 0.10, BLOCK past 0.50."""
    if gap is None:
        return None
    if gap > 0.50:
        return "BLOCK"
    if gap > 0.10:
        return "WARN"
    return None


def binding_findings(claims, idx):
    """Address/tx format, fact verifiability, conflicts, unused registry rows."""
    out = []
    for i, c in enumerate(claims):
        origin = _origin(c, i)
        con = c.get("contract")
        if not addr_valid(con):
            out.append(_f("BLOCK", "malformed-contract", origin,
                          "contract %r is not 0x + 40 hex chars" % (con,)))
        tx = c.get("deploy_tx")
        if tx not in (None, "") and not txhash_valid(tx):
            out.append(_f("BLOCK", "malformed-tx", origin,
                          "deploy_tx %r is not 0x + 64 hex chars" % (tx,)))
        if match_fact(c, idx) is None:
            out.append(_f("WARN", "unverifiable", origin,
                          "no fact record matches by contract or protocol"))
    by_con = {}
    for c in claims:
        con = c.get("contract")
        if isinstance(con, str) and con.strip():
            by_con.setdefault(con.strip().lower(), []).append(c)
    for con, cs in by_con.items():
        if len(cs) < 2:
            continue
        firms = {str(c.get("audit_firm")) for c in cs if c.get("audit_firm")}
        txs = {str(c.get("deploy_tx")) for c in cs if c.get("deploy_tx")}
        if len(firms) > 1 or len(txs) > 1:
            out.append(_f("BLOCK", "claim-conflict", con,
                          "%d claims cite %d firms / %d deploy tx hashes"
                          % (len(cs), len(firms), len(txs))))
    cited = set(by_con)
    cited |= {c.get("protocol").strip() for c in claims
              if isinstance(c.get("protocol"), str) and c.get("protocol").strip()}
    for bucket in ("contract", "protocol"):
        for key, fl in idx[bucket].items():
            if key not in cited:
                for f in fl:
                    out.append(_f("INFO", "unused-fact", key,
                                  "registry fact from %s never cited by a claim"
                                  % f.get("source", "?")))
    return out


def drift_findings(claims, idx):
    """Numeric drift bands, firm mismatch, launch-date ordering vs facts."""
    out = []
    for i, c in enumerate(claims):
        f = match_fact(c, idx)
        if f is None:
            continue
        origin = _origin(c, i)
        gap = _rel(c.get("tvl"), f.get("tvl"))
        sev = _band(gap)
        if sev:
            out.append(_f(sev, "tvl-drift", origin,
                          "claim tvl %r vs fact tvl %r (rel gap %.3f)"
                          % (c.get("tvl"), f.get("tvl"), gap)))
        gap = _rel(c.get("validators"), f.get("validators"))
        sev = _band(gap)
        if sev:
            out.append(_f(sev, "validator-drift", origin,
                          "claim validators %r vs fact validators %r (rel gap %.3f)"
                          % (c.get("validators"), f.get("validators"), gap)))
        cf, ff = c.get("audit_firm"), f.get("audit_firm")
        if (isinstance(cf, str) and cf.strip() and isinstance(ff, str)
                and ff.strip() and cf.strip() != ff.strip()):
            out.append(_f("BLOCK", "firm-mismatch", origin,
                          "claim cites firm %r, registry says %r" % (cf, ff)))
        cl, fl = parse_ts(c.get("launch_date")), parse_ts(f.get("launch_date"))
        if cl is not None and fl is not None and cl < fl:
            out.append(_f("WARN", "launch-ordering", origin,
                          "claim launch %s precedes registry record date %s"
                          % (c.get("launch_date"), f.get("launch_date"))))
    return out


def audit(path):
    """Load claims and facts, run binding and drift checks."""
    records, bad = load_jsonl(path)
    findings = [_f("WARN", "bad-line", "line:%d" % n,
                   "unparseable or non-object JSONL line") for n in bad]
    claims, facts = [], []
    for r in records:
        if r.get("kind") == "claim":
            claims.append(r)
        elif r.get("kind") == "fact":
            facts.append(r)
        else:
            findings.append(_f("WARN", "unknown-kind", str(r.get("protocol", "?")),
                               "record kind %r is neither claim nor fact"
                               % (r.get("kind"),)))
    idx = fact_index(facts)
    return findings + binding_findings(claims, idx) + drift_findings(claims, idx)


def render(findings):
    """Print one human line per finding; return severity counts."""
    counts = {s: 0 for s in SEVS}
    for f in findings:
        counts[f["severity"]] = counts.get(f["severity"], 0) + 1
        print("%-5s %-18s %s: %s"
              % (f["severity"], f["kind"], f["origin"], f["detail"]))
    return counts


def main(argv=None):
    """CLI: path to captured JSONL registry, optional --json. Returns 0/1/2."""
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("path", help="captured listing claims/facts JSONL file")
    ap.add_argument("--json", dest="as_json", action="store_true",
                    help="emit findings as JSON")
    args = ap.parse_args(argv)
    try:
        findings = audit(args.path)
    except OSError as exc:
        print("io error: %s" % exc, file=sys.stderr)
        return 2
    if args.as_json:
        print(json.dumps(findings, sort_keys=True))
    else:
        render(findings)
    return 1 if findings else 0


def _write(rows):
    """Fixture rows -> temp JSONL path (caller must os.unlink)."""
    fh = tempfile.NamedTemporaryFile(delete=False, suffix=".jsonl",
                                     mode="w", encoding="utf-8")
    try:
        for r in rows:
            fh.write(json.dumps(r) + "\n")
    finally:
        fh.close()
    return fh.name


def self_test():
    """Hand-computed fixtures cover every rule plus the CLI rc contract."""
    a1 = "0x" + "1f" * 20
    a2 = "0x" + "2e" * 20
    tx1 = "0x" + "ab" * 32
    clean = [
        {"kind": "fact", "protocol": "AaveV4", "contract": a1, "deploy_tx": tx1,
         "audit_firm": "Trail of Bits", "audit_report_sha256": "0x" + "cd" * 32,
         "tvl": 1000.0, "validators": 24, "launch_date": "2026-01-10",
         "source": "registry"},
        {"kind": "claim", "protocol": "AaveV4", "contract": a1, "deploy_tx": tx1,
         "audit_firm": "Trail of Bits", "tvl": 950.0, "validators": 24,
         "launch_date": "2026-01-12", "ts": "2026-02-01T00:00:00Z"},
    ]
    messy = [
        # QuFi claim: nothing in the registry binds it
        {"kind": "claim", "protocol": "QuFi", "contract": "0x" + "3d" * 20,
         "deploy_tx": tx1, "audit_firm": "OtterSec", "tvl": 500.0,
         "validators": 9, "launch_date": "2026-03-01", "ts": "2026-03-02T00:00:00Z"},
        # zk_audit claim: short contract, non-hex tx
        {"kind": "claim", "protocol": "zk_audit", "contract": "0x123",
         "deploy_tx": "0xzz" + "ab" * 31, "audit_firm": "NCC", "tvl": 10.0,
         "validators": 4, "launch_date": "2026-02-01", "ts": "2026-02-02T00:00:00Z"},
        # two claims on a2 with different firms -> conflict; both drift vs fact
        {"kind": "claim", "protocol": "AaveV4", "contract": a2, "deploy_tx": tx1,
         "audit_firm": "Wrong Bros", "tvl": 1600.0, "validators": 40,
         "launch_date": "2026-01-05", "ts": "2026-02-01T00:00:00Z"},
        {"kind": "claim", "protocol": "AaveV4", "contract": a2,
         "audit_firm": "OtterSec", "tvl": 1100.0, "validators": 25,
         "launch_date": "2026-01-20", "ts": "2026-02-05T00:00:00Z"},
        {"kind": "fact", "protocol": "AaveV4", "contract": a2, "deploy_tx": tx1,
         "audit_firm": "Trail of Bits", "audit_report_sha256": "0x" + "ef" * 32,
         "tvl": 1000.0, "validators": 24, "launch_date": "2026-01-10",
         "source": "registry"},
        # Ghost fact: never cited by any claim
        {"kind": "fact", "protocol": "Ghost", "contract": "0x" + "9c" * 20,
         "audit_firm": "Least Authority", "audit_report_sha256": "0x" + "01" * 32,
         "tvl": 5.0, "validators": 2, "launch_date": "2026-01-01",
         "source": "registry"},
        {"kind": "note", "protocol": "junk"},
    ]
    p_clean = _write(clean)
    p_messy = _write(messy)
    try:
        assert addr_valid(a1) and addr_valid("0x" + "1F" * 20) and not addr_valid("0x123")
        assert not addr_valid("0X" + "1f" * 20) and not addr_valid(None) and not addr_valid("0x" + "1f" * 41)
        assert txhash_valid(tx1) and not txhash_valid(a1) and not txhash_valid("zz" + "ab" * 31)
        idx = fact_index([r for r in messy if r.get("kind") == "fact"])
        assert sorted(idx["contract"]) == sorted([a2, "0x" + "9c" * 20]) \
            and list(idx["protocol"]) == ["AaveV4", "Ghost"]
        assert match_fact({"contract": a2.upper(), "protocol": "X"}, idx)["tvl"] == 1000.0
        assert match_fact({"contract": "0x" + "7b" * 20, "protocol": "Ghost"}, idx)["tvl"] == 5.0
        assert match_fact({"contract": "0x" + "7b" * 20, "protocol": "Nope"}, idx) is None
        bind = binding_findings([r for r in messy if r.get("kind") == "claim"], idx)
        assert [x for x in bind if x["kind"] == "malformed-contract"][0]["severity"] == "BLOCK"
        assert any(x["kind"] == "malformed-tx" for x in bind)
        assert any(x["kind"] == "unverifiable" and x["origin"].startswith("QuFi") for x in bind)
        assert [x for x in bind if x["kind"] == "claim-conflict"][0]["severity"] == "BLOCK"
        assert any(x["kind"] == "unused-fact" and x["severity"] == "INFO"
                   and x["origin"] == "0x" + "9c" * 20 for x in bind)
        drift = drift_findings([r for r in messy if r.get("kind") == "claim"], idx)
        assert [x for x in drift if x["kind"] == "tvl-drift"
                and x["origin"] == "AaveV4#2"][0]["severity"] == "BLOCK"
        assert any(x["kind"] == "validator-drift" and x["severity"] == "BLOCK"
                   and x["origin"] == "AaveV4#2" for x in drift)
        assert any(x["kind"] == "firm-mismatch" and x["severity"] == "BLOCK" for x in drift)
        assert any(x["kind"] == "launch-ordering" and x["severity"] == "WARN"
                   and x["origin"] == "AaveV4#2" for x in drift)
        assert audit(p_clean) == []
        with redirect_stdout(io.StringIO()):
            rc0 = main([p_clean])
            rc1 = main([p_messy])
            rc2 = main(["/no/such/listing-fixture.jsonl"])
            zero = render([])
        assert rc0 == 0 and rc1 == 1 and rc2 == 2, (rc0, rc1, rc2)
        assert zero == {"BLOCK": 0, "WARN": 0, "INFO": 0}, zero
    finally:
        os.unlink(p_clean)
        os.unlink(p_messy)
    print("listing-facts-audit self-test OK (addr/tx format, fact index and "
          "fallback binding, malformed/unverifiable/conflict/unused, tvl and "
          "validator drift bands, firm mismatch, launch ordering, rc 0/1/2)")


if __name__ == "__main__":
    if "--self-test" in sys.argv:
        self_test()  # falls through; rc 0 (probe hook runs after this)
    else:
        raise SystemExit(main())
