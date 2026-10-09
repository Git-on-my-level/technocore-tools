#!/usr/bin/env python3
"""validator-cert-audit — cross-chain validator work-certificate audit.

DEMAND: evidence/suggestions/tools-services/
  - "Cross-chain validator work certificate audit comparison"
  - "More equitable fee splits for smaller validators"
  - "Validator-set honesty guarantees at sampling stage"
  - "Collusion/community detection across DID graph for task integrity"
  - "Support for sharding verification across multiple validators to reduce latency."
  Scope: integrity/equity audit over a JSONL capture of validator work
  certificates: {"ts","chain","validator","cert_id","work_hash",
  "fee_share","stake","sampled","sample_round","shard",
  "co_attesters":[...]}, one record per line. Flags cross-chain double
  claims, cert_id reuse, fee_share outside the stake-band floor/cap,
  sampling skew vs fair share, collusion pairs/triangles in the
  co-attestation graph, shard coverage holes, single-validator shards.
  Data only: plain parsing, no network, no subprocess. rc 0 clean,
  1 findings, 2 usage/IO. Stdlib only.
"""
import argparse
import itertools
import json
import sys

SEVS = ("BLOCK", "WARN", "INFO")
BLOCK, WARN, INFO = SEVS
FEE_CAP = 0.020         # protocol fee_share ceiling for every stake band
FEE_FLOOR = ((1000.0, 0.005), (None, 0.010))  # stake<1000 -> 0.5%, else 1.0%
OVERSELECT = 3.0        # selection ratio over fair share that trips a WARN
MIN_SAMPLED = 4         # sampled certs required before skew is judged
QUIET_WARN = 4          # unsampled certs while active -> WARN from here
QUIET_BLOCK = 6         # ...and this many means total silence -> BLOCK
CO_ATTEST_SHARE = 0.8   # mutual co-attestation share above which pairs bond

def load_jsonl(path):
    """path -> (records, bad_lines): dict per line, junk counted."""
    records, bad = [], 0
    with open(path, encoding="utf-8") as fh:
        for line in filter(str.strip, fh):
            try:
                obj = json.loads(line.strip())
            except ValueError:
                bad += 1
            else:
                if isinstance(obj, dict):
                    records.append(obj)
                else:
                    bad += 1
    return records, bad

def _num(v):
    """JSON scalar -> float, or None when missing/non-numeric."""
    return float(v) if isinstance(v, (int, float)) \
        and not isinstance(v, bool) else None

def _txt(v):
    """Non-empty string -> itself, else None."""
    return v if isinstance(v, str) and v else None

def _f(sev, kind, origin, detail):
    """Uniform finding dict."""
    return {"severity": sev, "kind": kind, "origin": origin, "detail": detail}

def _key(f):
    """Deterministic display order: severity, kind, origin, detail."""
    return (SEVS.index(f["severity"]), f["kind"], str(f["origin"]), f["detail"])

def fee_floor(stake):
    """Protocol floor on fee_share for the validator's stake band."""
    for cap, floor in FEE_FLOOR:
        if cap is None or stake < cap:
            return floor
    return FEE_FLOOR[-1][1]

def _shard_id(v):
    """Shard label -> int when numeric, else the raw string, else None."""
    if isinstance(v, bool) or v is None:
        return None
    if isinstance(v, (int, float)):
        return int(v)
    try:
        return int(v)  # numeric strings index shards too
    except (TypeError, ValueError):
        return v if isinstance(v, str) and v else None

def double_claim_findings(records):
    """Cross-chain double claims and cert_id reuse -> BLOCK findings."""
    by_work, by_cert, out = {}, {}, []
    for r in records:
        v, w, ch, c = (_txt(r.get("validator")), _txt(r.get("work_hash")),
                       _txt(r.get("chain")), _txt(r.get("cert_id")))
        if v and w and ch:
            by_work.setdefault((v, w), {})[ch] = True
        if c and w:
            first = by_cert.setdefault(c, w)
            if first != w:
                out.append(_f(BLOCK, "cert-id-reuse", c, "cert_id bound "
                              "to work %s and again to %s" % (first, w)))
    for (v, w), chains in sorted(by_work.items()):
        if len(chains) > 1:
            out.append(_f(BLOCK, "cross-chain-double-claim", v, "work %s "
                          "certified on chains %s"
                          % (w, "+".join(sorted(chains)))))
    return out

def fee_equity_findings(records):
    """fee_share under the stake-band floor or over the cap -> WARN."""
    out, seen = [], set()
    for r in records:
        v = _txt(r.get("validator"))
        fee, stake = _num(r.get("fee_share")), _num(r.get("stake"))
        if v is None or fee is None or stake is None:
            continue
        floor = fee_floor(stake)
        if fee < floor - 1e-12:
            kind, detail = ("fee-below-floor", "fee_share %.4f under %.3f "
                            "floor at stake %.0f" % (fee, floor, stake))
        elif fee > FEE_CAP + 1e-12:
            kind, detail = ("fee-above-cap",
                            "fee_share %.4f over %.3f cap" % (fee, FEE_CAP))
        else:
            continue
        if (v, kind) not in seen:  # one finding per validator per side
            seen.add((v, kind))
            out.append(_f(WARN, kind, v, detail))
    return out

def sampling_findings(records):
    """Selection skew vs fair share, and validators never sampled."""
    out, per, sampled_total = [], {}, 0
    if not records:
        return out
    for r in records:
        v = _txt(r.get("validator"))
        if v is None:
            continue
        st = per.setdefault(v, [0, 0])
        st[0] += 1
        if r.get("sampled") is True:
            st[1] += 1
            sampled_total += 1
    total = len(records)
    for v, (certs, sampled) in sorted(per.items()):
        if sampled == 0:
            if certs >= QUIET_WARN:
                sev = BLOCK if certs >= QUIET_BLOCK else WARN
                out.append(_f(sev, "never-sampled", v, "%d certs while "
                              "active, never sampled" % certs))
            continue
        if sampled < MIN_SAMPLED or sampled_total < MIN_SAMPLED:
            continue
        ratio = (sampled / sampled_total) / (certs / total)  # vs fair share
        if ratio > OVERSELECT:
            out.append(_f(WARN, "sampling-skew", v, "sampled=true on %d/%d "
                          "certs, %.1fx fair share" % (sampled, certs, ratio)))
    return out

def collusion_findings(records, share=CO_ATTEST_SHARE):
    """Mutual co-attestation bonds -> WARN pairs; closed triangle -> BLOCK."""
    certs, co = {}, {}
    for r in records:
        v = _txt(r.get("validator"))
        if v is None:
            continue
        certs[v] = certs.get(v, 0) + 1
        mates = r.get("co_attesters")
        if not isinstance(mates, list):
            continue
        for m in mates:
            m = _txt(m)
            if m and m != v:
                co[(v, m)] = co.get((v, m), 0) + 1
    heavy, out, checked = set(), [], set()
    for (v, m), n in sorted(co.items()):
        pair = (min(v, m), max(v, m))
        if pair in checked or (m, v) not in co:
            continue  # one-sided listings never form a mutual bond
        checked.add(pair)
        if n / certs[v] > share and co[(m, v)] / certs[m] > share:
            heavy.add(pair)
            out.append(_f(WARN, "collusion-pair", "%s+%s" % pair,
                          "co-attested on %.0f%% and %.0f%% of their certs"
                          % (n / certs[v] * 100, co[(m, v)] / certs[m] * 100)))
    nodes = sorted({x for e in heavy for x in e})
    for a, b, c in itertools.combinations(nodes, 3):
        if (a, b) in heavy and (a, c) in heavy and (b, c) in heavy:
            out.append(_f(BLOCK, "collusion-triangle", "%s+%s+%s" % (a, b, c),
                          "closed triangle of >%d%% co-attestation bonds"
                          % int(CO_ATTEST_SHARE * 100)))
    return out

def shard_findings(records):
    """Per-round shard coverage holes and single-validator shards."""
    rounds, shard_validators = {}, {}
    for r in records:
        v, rnd = _txt(r.get("validator")), _txt(r.get("sample_round"))
        sh = _shard_id(r.get("shard"))
        if v and rnd and sh is not None:
            rounds.setdefault(rnd, set()).add(sh)
            shard_validators.setdefault(sh, set()).add(v)
    universe = set().union(*rounds.values()) if rounds else set()
    out = []
    for rnd, shards in sorted(rounds.items()):
        missing = universe - shards
        ints = [s for s in shards if isinstance(s, int)]
        if ints:  # numeric shard ids imply the contiguous range
            missing |= set(range(min(ints), max(ints) + 1)) - shards
        if missing:
            out.append(_f(WARN, "shard-coverage-hole", "round %s" % rnd,
                          "no certs for shard(s) %s" % ", ".join(
                              sorted(str(s) for s in missing))))
    for sh in sorted(shard_validators, key=str):
        if len(shard_validators[sh]) == 1:
            out.append(_f(INFO, "single-validator-shard", "shard %s" % sh,
                          "attested only by %s"
                          % next(iter(shard_validators[sh]))))
    return out

def audit(path):
    """Run every check over the capture at path; -> sorted findings."""
    records, bad = load_jsonl(path)
    findings = (double_claim_findings(records) + fee_equity_findings(records)
                + sampling_findings(records) + collusion_findings(records)
                + shard_findings(records))
    if bad:
        findings.append(_f(WARN, "malformed-line", "-",
                           "%d unparsable/non-object line(s)" % bad))
    return sorted(findings, key=_key)

def render(findings):
    """Print `SEV kind origin: detail` lines; return severity counts."""
    counts = {s: 0 for s in SEVS}
    for f in sorted(findings, key=_key):
        counts[f["severity"]] += 1
        print("%-5s %-24s %s: %s" % (f["severity"], f["kind"], f["origin"],
                                     f["detail"]))
    print("%d finding(s): %d block, %d warn, %d info"
          % (len(findings), counts[BLOCK], counts[WARN], counts[INFO]))
    return counts

def main(argv=None):
    """CLI entry: 0 clean, 1 findings, 2 usage/IO."""
    ap = argparse.ArgumentParser(prog="validator-cert-audit", description=
        "Cross-chain validator work-certificate integrity/equity audit")
    ap.add_argument("input", help="JSONL validator certificate capture")
    ap.add_argument("--json", action="store_true", help="emit JSON findings")
    args = ap.parse_args(argv)
    try:
        findings = audit(args.input)
    except OSError as exc:
        print("cannot read capture: %s" % exc, file=sys.stderr)
        return 2
    if args.json:
        print(json.dumps({"count": len(findings), "findings": findings},
                         ensure_ascii=False, indent=1))
    else:
        render(findings)
    return 1 if findings else 0

def _write(recs, bad=0):
    """Fixture JSONL via tempfile; -> path (self-test helper)."""
    import tempfile
    fh = tempfile.NamedTemporaryFile("w", suffix=".jsonl", delete=False,
                                     encoding="utf-8")
    for r in recs:
        fh.write(json.dumps(r) + "\n")
    fh.write("{not json\n" * bad)
    fh.close()
    return fh.name

def _run_cli(args):
    """main(args) with stdout captured; -> (rc, text). Self-test helper."""
    import io
    from contextlib import redirect_stdout
    buf = io.StringIO()
    with redirect_stdout(buf):
        rc = main(args)
    return rc, buf.getvalue()

def _cert(**kw):
    """Baseline certificate record with overrides (self-test helper)."""
    base = dict(ts=1, chain="ch1", validator="vT", cert_id="cT",
                work_hash="wT", fee_share=0.010, stake=2000,
                sampled=False, sample_round="r0", shard=0,
                co_attesters=[])
    base.update(kw)
    return base

def self_test():
    import os

    assert fee_floor(100.0) == 0.005 and fee_floor(1000.0) == 0.010
    assert _shard_id("7") == 7 and _shard_id(2.0) == 2 \
        and _shard_id("s0") == "s0" and _shard_id(None) is None

    dirty = [_cert(ts=t, validator=v, cert_id=c, work_hash=w, **rest)
             for t, v, c, w, rest in (
                 (1, "vD", "c1", "w1", dict(chain="ch1", sampled=True)),
                 (2, "vD", "c2", "w1", dict(chain="ch2")),
                 (3, "vD", "cX", "w2", dict()), (4, "vD", "cX", "w3", dict()),
                 (5, "vE", "c5", "w5", dict(stake=100, fee_share=0.001)),
                 (6, "vF", "c6", "w6", dict(stake=5000, fee_share=0.030)),
                 (7, "vK", "c7", "w7", dict(stake=100, fee_share=0.005)))]
    dirty += [_cert(validator=v, ts=10 + k, cert_id="ct%s%d" % (v, k),
                   work_hash="wt%s%d" % (v, k), co_attesters=list(mates))
              for v, mates in (("vP", ["vQ", "vR"]), ("vQ", ["vP", "vR"]),
                               ("vR", ["vP", "vQ"])) for k in range(6)]
    dk = {f["kind"]: f["severity"] for f in double_claim_findings(dirty)}
    assert BLOCK == dk.get("cross-chain-double-claim") \
        == dk.get("cert-id-reuse"), dk
    fo = {f["origin"]: f["kind"] for f in fee_equity_findings(dirty)}
    assert fo.get("vE") == "fee-below-floor", fo
    assert fo.get("vF") == "fee-above-cap" and "vK" not in fo, fo
    coll = collusion_findings(dirty)
    assert sum(1 for f in coll if f["kind"] == "collusion-pair") == 3, coll
    assert any(f["kind"] == "collusion-triangle" for f in coll), coll

    misc = [_cert(validator=v, cert_id="cl%s%d" % (v, k),
                 work_hash="wl%s%d" % (v, k), co_attesters=[o] if k < 2 else [])
            for v, o in (("vM", "vN"), ("vN", "vM")) for k in range(4)]
    misc += [_cert(shard=s, sample_round="r1", cert_id=c, work_hash=w)
             for s, c, w in ((0, "a", "wa"), (2, "b", "wb"))]
    assert collusion_findings(misc) == []
    mk = {f["kind"] for f in shard_findings(misc)}
    assert "shard-coverage-hole" in mk and "single-validator-shard" in mk, mk

    skew = [_cert(validator="vS", cert_id="cs%d" % k, work_hash="ws%d" % k,
                 sampled=True) for k in range(4)]
    skew += [_cert(validator=v, cert_id="cq%s%d" % (v, k),
                  work_hash="wq%s%d" % (v, k)) for v, n in
             (("vBig", 10), ("vU", 4)) for k in range(n)]
    sf = sampling_findings(skew)
    assert any(f["kind"] == "sampling-skew" and f["origin"] == "vS" for f in sf), sf
    quiet = {f["origin"]: f["severity"] for f in sf if f["kind"] == "never-sampled"}
    assert quiet == {"vBig": BLOCK, "vU": WARN}, sf

    clean, spec = [], (("vA", 500.0, 0.006), ("vB", 2000.0, 0.011))
    for vi, (v, stake, fee) in enumerate(spec):
        for n, (rnd, shard) in enumerate((("r1", 0), ("r1", 1), ("r2", 0),
                                          ("r2", 1))):
            clean.append(_cert(
                validator=v, stake=stake, fee_share=fee, sampled=(n % 2 == 0),
                sample_round=rnd, shard=shard, cert_id="cc%s%d" % (v, n),
                work_hash="cw%s%d" % (v, n),
                co_attesters=[spec[1 - vi][0]] if n < 2 else []))

    paths = []
    try:
        paths.append(clean_path := _write(clean))
        assert audit(clean_path) == []
        assert _run_cli([clean_path])[0] == 0

        paths.append(dirty_path := _write(dirty, bad=1))
        pairs = {(f["kind"], f["severity"]) for f in audit(dirty_path)}
        want = {("cross-chain-double-claim", BLOCK), ("cert-id-reuse", BLOCK),
                ("fee-below-floor", WARN), ("fee-above-cap", WARN),
                ("collusion-pair", WARN), ("collusion-triangle", BLOCK),
                ("malformed-line", WARN)}
        assert want <= pairs, sorted(want - pairs)
        assert _run_cli([dirty_path])[0] == 1
        doc = json.loads(_run_cli([dirty_path, "--json"])[1])
        assert doc["count"] == len(doc["findings"]) > 0

        paths.append(mal_path := _write([_cert()], bad=1))
        rc, out = _run_cli([mal_path])
        assert rc == 1 and "malformed-line" in out
        assert _run_cli(["/nonexistent-certs.jsonl"])[0] == 2
    finally:
        for p in paths:
            if os.path.exists(p):
                os.unlink(p)

    print("validator-cert-audit self-test OK (15 assertion groups: floor"
          " band + shard-id units, cross-chain double-claim, cert-id reuse,"
          " fee floor/cap, collusion pairs + triangle, shard hole/single,"
          " sampling skew, clean rc 0, dirty kinds, CLI rc 1/2, --json)")

if __name__ == "__main__":
    if "--self-test" in sys.argv:
        self_test()  # falls through; rc 0 (probe hook runs after this)
    else:
        raise SystemExit(main())
