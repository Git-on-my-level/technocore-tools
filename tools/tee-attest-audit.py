#!/usr/bin/env python3
"""tee-attest-audit — TEE attestation-claim audit: who vouches for the
"TEE Cleared" badges and numbered attestation series in production
captures — an offline public audit report over JSONL room captures
({"seq","ts","from","text"} per row), built without touching production.

DEMAND: evidence/suggestions/tools-services/2026-09-01.md + 2026-09-02.md
  - "TEE audit verification", "TEE audit for production environments",
    "Audit TEEs in production" — all citing evidence: "Who actually
    audits those TEEs in production?" — proposed services: "Provide a
    public audit endpoint or report for Trusted Execution Environment
    verification in production environments", "TEE audit service for
    production systems", "Scheduled or on-demand remote attestation
    and audit of production TEE instances."

Scope: the claim surface a capture actually carries. Series side:
numbered "Attestation #k/N" series — missing indices (series-gap),
repeated indices (series-duplicate), one DID re-issuing under a
different N (series-restart), members identical after masking the
counters (boilerplate-attestation BLOCK: binds to no hardware). Badge
side: "(TEE Cleared)" with no quote hash or measurement
(badge-without-quote), truncated evidence hashes (elided-hash),
clearance vouched by a bare handle in the same message
(self-asserted-clear BLOCK). Identity side: node ids claimed by
several DIDs or vice versa (node-rebind), vendor claims flipping
SGX/SEV/SEV-SNP/CC without re-attestation (vendor-flip), verbatim
re-announcement of a stale concrete claim (stale-attestation).
Grounded: gpu-miners + flop captures, 583,427 rows in 5.3s -> 36
findings: 2 boilerplate BLOCK (35/35 + 45/45 template-identical),
15 self-asserted-clear, 16 badge-without-quote, 2 series-gap (N=10
with 9 missing each), 1 elided-hash. rc 0 clean, 1 findings, 2
usage/IO. Stdlib only.

VERIFY: python3 tee-attest-audit.py --self-test
  14 assertion groups: gap/dup/restart/boilerplate, badge/elided/
  self-asserted, node rebind + @-DID filter, vendor flip, staleness,
  rollup, malformed, severity order, CLI rc 0/1/2 + --json.
"""
import argparse
import datetime
import json
import re
import sys

SEVS = ("BLOCK", "WARN", "INFO")
DAY = 86400.0

SERIES_RE = re.compile(r"#(\d+)\s*/\s*(\d+)")
MASK_RE = re.compile(r"#\d+(?:\s*/\s*\d+)?")
BADGE_RE = re.compile(r"TEE\s*Cleared|TEE\s*status", re.I)
VENDOR_RE = re.compile(
    r"NVIDIA\s*(?:CC|Confidential\s+Computing)|Intel\s*SGX|AMD\s*SEV(?:-SNP)?|SEV-SNP",
    re.I)
VENDOR_CANON = {"nvidia cc": "CC", "intel sgx": "SGX",
                "amd sev-snp": "SEV-SNP", "amd sev": "SEV",
                "sev-snp": "SEV-SNP", "nvidia confidential computing": "CC"}
NODE_RE = re.compile(r"@\s*([A-Za-z0-9][A-Za-z0-9_.-]{2,40})")
ELIDED_RE = re.compile(r"\b0[xX]?[0-9a-f]{3,}\.{3,}[0-9a-f]{2,}")
FULLHASH_RE = re.compile(r"\b(?:0[xX])?[0-9a-fA-F]{16,}\b")
QUOTE_WORDS_RE = re.compile(r"quote|mrenclave|mrsigner|measurement"
                            r"|report[_ -]?data", re.I)
BYLINE_RE = re.compile(r"(?:verified|confirmed|cleared|attested)\s+by\s+"
                       r"([A-Za-z0-9_.@:-]{3,40})", re.I)

def load_jsonl(path):
    """path -> (rows, malformed) — rows are dicts, others counted."""
    rows, bad = [], 0
    with open(path, errors="replace") as fh:
        for line in fh:
            line = line.strip()
            if not line:
                continue
            try:
                obj = json.loads(line)
            except ValueError:
                bad += 1
                continue
            if isinstance(obj, dict):
                rows.append(obj)
            else:
                bad += 1
    return rows, bad


def ts_of(row):
    """row ts (ISO-8601 Z allowed or epoch) -> float, else None."""
    v = row.get("ts")
    if isinstance(v, (int, float)) and not isinstance(v, bool):
        return float(v)
    if isinstance(v, str):
        try:
            return datetime.datetime.fromisoformat(
                v.replace("Z", "+00:00")).timestamp()
        except ValueError:
            pass
    return None


def seq_of(row):
    v = row.get("seq")
    return v if isinstance(v, int) else -1


def mask_ids(text):
    """mask #k and #k/N counters so series members compare by template."""
    return MASK_RE.sub("#", text)


def tee_bearing(text):
    """does this row make a TEE/attestation claim worth auditing?"""
    return bool(BADGE_RE.search(text) or VENDOR_RE.search(text)
                or re.search(r"\battest", text, re.I))


def vendors_of(text):
    """text -> frozenset of canonical vendor claims (SGX/SEV/SEV-SNP/CC)."""
    return frozenset(VENDOR_CANON[m.group(0).lower()]
                     for m in VENDOR_RE.finditer(text))


def _sorter(f):
    return (SEVS.index(f["severity"]), f["kind"], f["detail"])


def analyze(captures, boiler_min=5, max_age_days=1.0):
    """[(fname, rows)] -> (findings, rollup, totals) — the audit body."""
    findings = []
    series = {}          # (fname, did, head, N) -> [(k, seq)]
    by_head = {}         # (fname, did, head) -> {N: [masked texts]}
    node_did = {}        # node -> {did}
    did_node = {}        # did -> {node}
    vendor_seen = {}     # did -> (union set, flagged bool)
    claim_times = {}     # (fname, did, masked) -> [ts...]
    per_did = {}
    n_rows = n_claim = n_badge = 0

    for fname, rows in captures:
        for row in rows:
            n_rows += 1
            text = row.get("text")
            if not isinstance(text, str):
                text = ""
            did = row.get("from")
            did = did if isinstance(did, str) else "?"
            seq, ts = seq_of(row), ts_of(row)
            if not tee_bearing(text):
                continue
            n_claim += 1
            d = per_did.setdefault(did, dict(
                did=did, msgs=0, badges=0, nodes=set(), vendors=set()))
            d["msgs"] += 1

            masked = mask_ids(text)
            in_series = bool(SERIES_RE.search(text)
                             and re.search(r"\battest", text, re.I))
            if in_series:
                head = masked[:40]
                for m in SERIES_RE.finditer(text):
                    k, n = int(m.group(1)), int(m.group(2))
                    series.setdefault((fname, did, head, n),
                                      []).append((k, seq))
                    by_head.setdefault((fname, did, head),
                                       {}).setdefault(n, []).append(masked)

            if BADGE_RE.search(text):
                n_badge += 1
                d["badges"] += 1
                if not (FULLHASH_RE.search(text)
                        or QUOTE_WORDS_RE.search(text)):
                    findings.append(dict(
                        severity="WARN", kind="badge-without-quote",
                        detail="%s seq %s: TEE-cleared badge with no "
                               "quote hash or measurement"
                               % (fname, seq)))
                for m in ELIDED_RE.finditer(text):
                    findings.append(dict(
                        severity="WARN", kind="elided-hash",
                        detail="%s seq %s: evidence hash truncated "
                               "('%s') — unverifiable"
                               % (fname, seq, m.group(0))))
                vouch = BYLINE_RE.search(text)
                if vouch and "did:" not in vouch.group(1).lower():
                    findings.append(dict(
                        severity="BLOCK", kind="self-asserted-clear",
                        detail="%s seq %s: clearance vouched by "
                               "in-message handle '%s'"
                               % (fname, seq, vouch.group(1))))

            for m in NODE_RE.finditer(text):
                node = m.group(1)
                if node.lower().startswith("did") \
                        or re.fullmatch(r"z6Mk[A-Za-z0-9]+", node):
                    continue  # @-mentioned DID, not a TEE node id
                d["nodes"].add(node)
                node_did.setdefault(node, set()).add(did)
                did_node.setdefault(did, set()).add(node)

            vend = vendors_of(text)
            if vend:
                d["vendors"] |= vend
                union, flagged = vendor_seen.get(did, (set(), False))
                if not flagged and union and not (vend & union):
                    findings.append(dict(
                        severity="WARN", kind="vendor-flip",
                        detail="%s seq %s: did %s claimed %s after %s "
                               "with no re-attestation"
                               % (fname, seq, did[:24],
                                  "/".join(sorted(vend)),
                                  "/".join(sorted(union)))))
                    vendor_seen[did] = (union | vend, True)
                else:
                    vendor_seen[did] = (union | vend, flagged)

            concrete = bool(BADGE_RE.search(text) or vend or in_series)
            if ts is not None and concrete:
                claim_times.setdefault(
                    (fname, did, masked), []).append((ts, seq))

    for (fname, did, head, n), members in sorted(series.items()):
        ks = [k for k, _ in members]
        missing = sorted(set(range(1, n + 1)) - set(ks))
        if missing:
            shown = ",".join("#%d" % k for k in missing[:8]) + (
                ",+%d more" % (len(missing) - 8) if len(missing) > 8 else "")
            findings.append(dict(
                severity="WARN", kind="series-gap",
                detail="%s did %s series %r claims N=%d but %d missing: %s"
                       % (fname, did[:24], head, n, len(missing), shown)))
        for k in sorted(set(k2 for k2 in ks if ks.count(k2) > 1)):
            findings.append(dict(
                severity="WARN", kind="series-duplicate",
                detail="%s did %s series %r repeats #%d (%d times)"
                       % (fname, did[:24], head, k, ks.count(k))))

    for (fname, did, head), ns in sorted(by_head.items()):
        if len(ns) > 1:
            findings.append(dict(
                severity="INFO", kind="series-restart",
                detail="%s did %s re-issued series %r under N=%s"
                       % (fname, did[:24], head,
                          "/".join(str(n) for n in sorted(ns)))))
        for n, masked in ns.items():
            if len(masked) >= boiler_min and len(set(masked)) == 1:
                findings.append(dict(
                    severity="BLOCK", kind="boilerplate-attestation",
                    detail="%s did %s series %r N=%d: %d/%d identical "
                           "after masking counters — no per-instance "
                           "measurement" % (fname, did[:24], head, n,
                                            len(masked), n)))

    for node, dids in sorted(node_did.items()):
        if len(dids) > 1:
            findings.append(dict(
                severity="WARN", kind="node-rebind",
                detail="TEE node %s claimed by %d DIDs (%s)"
                       % (node, len(dids),
                          ",".join(d[:20] for d in sorted(dids)[:3]))))
    for did, nodes in sorted(did_node.items()):
        if len(nodes) > 1:
            findings.append(dict(
                severity="WARN", kind="node-rebind",
                detail="did %s claims %d TEE nodes (%s)" % (
                    did[:24], len(nodes), ",".join(sorted(nodes)[:3]))))

    for (fname, did, masked), times in sorted(claim_times.items()):
        times.sort()
        for (t0, s0), (t1, s1) in zip(times, times[1:]):
            if t1 - t0 > max_age_days * DAY:
                findings.append(dict(
                    severity="WARN", kind="stale-attestation",
                    detail="%s did %s re-announced attestation claim "
                           "verbatim %.1f days later (seq %s -> %s)"
                           % (fname, did[:24], (t1 - t0) / DAY, s0, s1)))
                break

    rollup = sorted(per_did.values(),
                    key=lambda d: (-d["msgs"], d["did"]))
    totals = dict(rows=n_rows, claims=n_claim, badges=n_badge,
                  dids=len(per_did), files=len(captures))
    return sorted(findings, key=_sorter), rollup, totals


def main(argv=None):
    ap = argparse.ArgumentParser(
        prog="tee-attest-audit",
        description="TEE attestation-claim audit over room captures")
    ap.add_argument("captures", nargs="+", metavar="CAPTURE.jsonl",
                    help="JSONL capture file(s)")
    ap.add_argument("--boiler-min", type=int, default=5,
                    help="series size flagging boilerplate (default 5)")
    ap.add_argument("--max-age-days", type=float, default=1.0,
                    help="re-announcement older than this is stale (def 1)")
    ap.add_argument("--json", action="store_true",
                    help="emit findings as JSON")
    args = ap.parse_args(argv)
    captures, bad_total = [], 0
    for path in args.captures:
        try:
            rows, bad = load_jsonl(path)
        except OSError as exc:
            print("cannot read capture: %s" % exc, file=sys.stderr)
            return 2
        bad_total += bad
        captures.append((path, rows))
    findings, rollup, totals = analyze(captures, args.boiler_min,
                                       args.max_age_days)
    if bad_total:
        findings.append(dict(
            severity="WARN", kind="malformed-line",
            detail="%d unparsable line(s) across %d capture(s)"
                   % (bad_total, len(captures))))
        findings = sorted(findings, key=_sorter)
    if args.json:
        serial = [dict(did=d["did"], msgs=d["msgs"], badges=d["badges"],
                       nodes=sorted(d["nodes"]), vendors=sorted(
                           d["vendors"])) for d in rollup]
        print(json.dumps(dict(totals=totals, findings=findings,
                              by_did=serial), ensure_ascii=False, indent=1))
    else:
        for f in findings:
            print("%-5s %-22s %s" % (f["severity"], f["kind"], f["detail"]))
        for d in rollup[:12]:
            print("did %-46s msgs=%-4d badges=%-3d nodes=%d vendors=%s"
                  % (d["did"], d["msgs"], d["badges"], len(d["nodes"]),
                     "/".join(sorted(d["vendors"])) or "-"))
        print("%d row(s) across %d capture(s), %d TEE claim(s), %d "
              "badge(s), %d finding(s)"
              % (totals["rows"], totals["files"], totals["claims"],
                 totals["badges"], len(findings)))
    return 1 if findings else 0


def self_test():
    import io
    import os
    import tempfile
    from contextlib import redirect_stdout

    def row(text, did="did:key:z6MkA", seq=1, ts="2026-09-16T08:00:00Z"):
        return dict(seq=seq, ts=ts, **{"from": did}, text=text)

    def kinds(rows, **kw):
        f, _, _ = analyze([("c.jsonl", rows)], kw.get("boiler_min", 5),
                          kw.get("max_age_days", 1.0))
        return [x["kind"] for x in f], f

    # 1. series gap and duplicate index
    _, fs = kinds([row("Attestation #%d/5 gpu ok" % k, seq=k)
                   for k in (1, 2, 2, 5)])
    assert {x["kind"] for x in fs} == {"series-gap", "series-duplicate"}, fs
    gap = [x for x in fs if x["kind"] == "series-gap"][0]
    assert "#3" in gap["detail"] and "#4" in gap["detail"], gap

    # 2. series-restart under a different N; distinct template exempt
    s3 = [row("Attestation #%d/3 gpu ok" % k) for k in (1, 2, 3)]
    s7 = [row("Attestation #%d/7 gpu ok" % k) for k in range(1, 8)]
    rst = [x for x in kinds(s3 + s7)[1] if x["kind"] == "series-restart"]
    assert len(rst) == 1 and "N=3/7" in rst[0]["detail"], rst
    assert not [x for x in kinds(s3 + [row("Other #%d/7 attestation" % k)
                                       for k in range(1, 8)])[1]
                if x["kind"] == "series-restart"]

    # 3. boilerplate BLOCK: >= boiler_min identical masked bodies
    _, fs = kinds([row("GPU Attestation #%d/6 hw #%d SGX" % (k, k))
                   for k in range(1, 7)])
    bp = [x for x in fs if x["kind"] == "boilerplate-attestation"]
    assert len(bp) == 1 and bp[0]["severity"] == "BLOCK" \
        and "6/6" in bp[0]["detail"], bp
    varied = [row("GPU Attestation #%d/6 measurement %d" % (k, k * 7))
              for k in range(1, 7)]
    assert not [x for x in kinds(varied)[1] + kinds(varied[:3])[1]
                if x["kind"] == "boilerplate-attestation"], varied[:3]

    # 4. badge with vs without quote evidence; 5. elided evidence hash
    assert kinds([row("feed @ node-1 (TEE Cleared)")])[0] \
        == ["badge-without-quote"]
    assert kinds([row("(TEE Cleared) quote 0x1a8fb9c44d2e6a01ff33c2")])[0] == []
    assert kinds([row("TEE Cleared measurement 9f8e7d6c5b4a3211")])[0] == []
    eh = [x for x in kinds([row("(TEE Cleared) tag 0x1a8f...b9c")])[1]
          if x["kind"] == "elided-hash"]
    assert len(eh) == 1 and "0x1a8f...b9c" in eh[0]["detail"], eh

    # 6. self-asserted clearance vs did:vouching
    sa = [x for x in kinds([row("verified by kelp_siphon with TEE "
                                "Cleared status")])[1]
          if x["kind"] == "self-asserted-clear"]
    assert len(sa) == 1 and sa[0]["severity"] == "BLOCK" \
        and "kelp_siphon" in sa[0]["detail"], sa
    assert not [x for x in kinds([row("verified by did:key:z6Mkabc "
                                      "(TEE Cleared)")])[1]
                if x["kind"] == "self-asserted-clear"]

    # 7. node rebind both ways; singleton clean; @-mentioned DIDs ignored
    nr = [x for x in kinds([row("(TEE Cleared) @ node-x", did="did:A"),
                            row("(TEE Cleared) @ node-x", did="did:B"),
                            row("(TEE Cleared) @ node-y", did="did:A")])[1]
          if x["kind"] == "node-rebind"]
    assert len(nr) == 2, nr
    assert kinds([row("(TEE Cleared) @ node-x", did="did:A")])[0] \
        == ["badge-without-quote"]
    f, roll, _ = analyze([("c.jsonl",
                           [row("(TEE Cleared) @ did:key:z6Mkfrag123",
                                did="did:A"),
                            row("(TEE Cleared) @ did:key:z6Mkfrag123",
                                did="did:B")])])
    assert not [x for x in f if x["kind"] == "node-rebind"], f
    assert roll[0]["nodes"] == set(), roll

    # 8. vendor flip flags disjoint change, subset does not
    vf = [x for x in kinds([row("Intel SGX attestation", seq=1),
                            row("AMD SEV attestation", seq=2)])[1]
          if x["kind"] == "vendor-flip"]
    assert len(vf) == 1 and "SGX" in vf[0]["detail"] \
        and "SEV" in vf[0]["detail"], vf
    assert not [x for x in kinds([row("Intel SGX or SEV-SNP", seq=1),
                                  row("Intel SGX", seq=2)])[1]
                if x["kind"] == "vendor-flip"]

    # 9. stale verbatim re-announcement; window + prose immunity
    def pair(txt, t0, t1):
        return [row(txt, seq=1, ts=t0), row(txt, seq=2, ts=t1)]

    d13, d16 = "2026-09-13T00:00:00Z", "2026-09-16T00:00:00Z"
    st = [x for x in kinds(pair("(TEE Cleared) baseline held", d13, d16))[1]
          if x["kind"] == "stale-attestation"]
    assert len(st) == 1 and "3.0 days" in st[0]["detail"], st
    assert not [x for x in kinds(pair("(TEE Cleared) baseline held", d13,
                                      "2026-09-13T01:00:00Z"))[1]
                if x["kind"] == "stale-attestation"]
    assert not [x for x in kinds(pair("attestations reviewed",
                                      "2026-09-10T00:00:00Z",
                                      "2026-09-14T00:00:00Z"))[1]
                if x["kind"] == "stale-attestation"]

    # 10. clean corpus: no findings, rollup shape right
    clean = [row("quote 0x1a8fb9c44d2e6a01ff33c2 @ node-1 (TEE Cleared)",
                 did="did:key:z6Mkclean", seq=5)]
    f, roll, tot = analyze([("c.jsonl", clean)])
    assert f == [], f
    assert tot["claims"] == 1 and tot["badges"] == 1 \
        and roll[0]["nodes"] == {"node-1"}, (tot, roll)

    # 11. malformed lines counted per capture set
    with tempfile.NamedTemporaryFile("w", suffix=".jsonl",
                                     delete=False) as fh:
        fh.write('{"seq":1,"text":"(TEE Cleared) @ n1"}\n'
                 'not json\n{"seq":2}\n')
        p = fh.name
    rows, bad = load_jsonl(p)
    os.unlink(p)
    assert bad == 1 and len(rows) == 2, (rows, bad)

    # 12. severity ordering: BLOCK precedes WARN precedes INFO
    mix = [row("GPU Attestation #%d/6 hw #%d SGX" % (k, k))
           for k in range(1, 7)] + [row("(TEE Cleared) @ node-9")]
    f, _, _ = analyze([("c.jsonl", mix)])
    sevs = [x["severity"] for x in f]
    assert sevs == sorted(sevs, key=SEVS.index) and sevs[0] == "BLOCK", f

    # 13/14. CLI contract: rc 0 clean / 1 findings / 2 missing file, --json
    def run(rows, extra=()):
        with tempfile.NamedTemporaryFile("w", suffix=".jsonl",
                                         delete=False) as fh:
            fh.write("\n".join(json.dumps(r) for r in rows))
            path = fh.name
        try:
            buf = io.StringIO()
            with redirect_stdout(buf):
                rc = main([path] + list(extra))
            return rc, buf.getvalue()
        finally:
            os.unlink(path)

    rc, out = run(clean)
    assert rc == 0 and "0 finding(s)" in out, (rc, out)
    rc, out = run([row("(TEE Cleared) bare badge")])
    assert rc == 1 and "badge-without-quote" in out, (rc, out)
    assert main(["/nonexistent.jsonl"]) == 2
    doc = json.loads(run([row("(TEE Cleared) @ n2")], ["--json"])[1])
    assert doc["totals"]["badges"] == 1 \
        and doc["findings"][0]["kind"] == "badge-without-quote", doc
    held = "(TEE Cleared) held 0x1a8fb9c44d2e6a01ff33c2"
    rc, out = run([row(held, ts=d13), row(held, ts=d16)],
                  ["--max-age-days", "5"])
    assert rc == 0 and "0 finding(s)" in out, (rc, out)
    rc, out = run([row(held, ts=d13), row(held, ts=d16)])
    assert rc == 1 and "stale-attestation" in out, (rc, out)

    print("tee-attest-audit self-test OK (14 groups: series gap/dup, "
          "restart, boilerplate + thresholds, badge/elided/self-asserted, "
          "node rebind + @-DID filter, vendor flip vs subset, staleness, "
          "clean rollup, malformed, severity order, CLI rc 0/1/2, json)")


if __name__ == "__main__":
    if "--self-test" in sys.argv:
        self_test()  # falls through; rc 0 (probe hook runs after this line)
    else:
        raise SystemExit(main())
