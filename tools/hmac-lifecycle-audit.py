#!/usr/bin/env python3
"""hmac-lifecycle-audit — HMAC secret-epoch lifecycle audit: rotation
windows and shared-state exposure, offline over two JSONL captures:
a key registry ({"key_id","service","not_before","not_after"?) — one
row per epoch; not_after absent/null = key still active) and a usage
log ({"ts","key_id","service"?} — one row per MAC/tag authenticated).

DEMAND: evidence/suggestions/tools-services/2026-09-08.md
  - "Continuous background data-integrity verification for HMAC secret
    usage without locking" — evidence: "Auditing data integrity across
    a shared HMAC secret without locking production tables" (10:52) —
    proposed service: "HMAC-secret-lifecycle audit covering rotation
    and shared-state exposure".

Scope: the epoch algebra the proposal names. Registry side: same
key_id re-declared with conflicting windows (key-id-collision — an
auditor can no longer tell which epoch governs), exact duplicate rows,
two epochs of one service simultaneously active beyond --grace
(epoch-overlap — old and new secret both valid is the classic
rotation botch), holes between consecutive epochs (coverage-gap —
records there are unverifiable by construction), and keys whose epoch
never closed (rotation-stall once older than --max-age-days).
Usage side: MACs under a key_id the registry never declared
(unknown-key), MACs outside their epoch window on either side
(outside-window: pre-activation or post-revocation use), and MACs
presented under a different service than the one that owns the secret
(service-mismatch — the shared-state exposure the demand describes).
Read-only file access, so it runs as the scheduled background job
without locking production tables. rc 0 clean, 1 findings, 2 usage/IO.
Stdlib only.

VERIFY: python3 hmac-lifecycle-audit.py --self-test
  12 assertion groups: collision vs duplicate, overlap beyond/within
  grace, coverage gap, rotation stall + fresh-key immunity, unknown
  key, pre-activation / post-revocation use, service mismatch, clean
  corpus, malformed lines, per-service rollup, CLI rc 0/1/2 + --json.
"""
import argparse
import json
import sys

SEVS = ("BLOCK", "WARN", "INFO")
DAY = 86400.0
INF = float("inf")


def load_jsonl(path):
    """path -> (rows, malformed) — rows are dicts, others counted."""
    rows, bad = [], 0
    with open(path, encoding="utf-8") as fh:
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


def _num(v):
    """numeric field -> float, else None."""
    if isinstance(v, bool) or not isinstance(v, (int, float)):
        return None
    return float(v)


def epoch_of(row):
    """registry row -> (key_id, service, start, end) or None if unusable."""
    kid, svc = row.get("key_id"), row.get("service")
    nb = _num(row.get("not_before"))
    if not isinstance(kid, str) or not kid or not isinstance(svc, str) \
            or not svc or nb is None:
        return None
    na = _num(row.get("not_after"))
    return (kid, svc, nb, INF if na is None else na)


def registry_facts(rows, now, grace, max_age):
    """registry rows -> (epochs, findings). epochs: key_id -> first row."""
    epochs, findings = {}, []
    usable = []
    bad = 0
    for row in rows:
        ep = epoch_of(row)
        if ep is None:
            bad += 1
            continue
        usable.append(ep)
        kid, svc = ep[0], ep[1]
        if kid in epochs:
            if epochs[kid] == ep:
                findings.append(dict(
                    severity="WARN", kind="key-id-duplicate", service=svc,
                    detail="key %s declared identically twice in registry"
                           % kid))
            else:
                findings.append(dict(
                    severity="BLOCK", kind="key-id-collision", service=svc,
                    detail="key %s re-declared with conflicting "
                           "service/window: %s vs %s"
                           % (kid, _fmt(epochs[kid]), _fmt(ep))))
        else:
            epochs[kid] = ep
    if bad:
        findings.append(dict(
            severity="WARN", kind="malformed-line",
            detail="%d registry row(s) missing key_id/service/not_before"
                   % bad))

    by_svc = {}
    for ep in usable:
        by_svc.setdefault(ep[1], []).append(ep)

    for svc, eps in by_svc.items():
        eps = _dedupe(eps)
        # epoch-overlap: two secrets of one service both active > grace
        for a in range(len(eps)):
            for b in range(a + 1, len(eps)):
                ka, _sva, sa, ea = eps[a]
                kb, _svb, sb, eb = eps[b]
                ov = min(ea, eb) - max(sa, sb)
                if ov > grace:
                    findings.append(dict(
                        severity="BLOCK", kind="epoch-overlap", service=svc,
                        detail="service %s: keys %s and %s both active "
                               "%.0fs beyond grace %ds"
                               % (svc, ka, kb, ov, grace)))
        # coverage-gap: hole between consecutive epochs of one service
        end, prev_kid = None, "?"
        for kid, _sv, start, stop in sorted(eps, key=lambda e: e[2]):
            if end is not None and start > end:
                findings.append(dict(
                    severity="WARN", kind="coverage-gap", service=svc,
                    detail="service %s: no active key for %.0fs "
                           "(%.0f..%.0f) between %s and %s"
                           % (svc, start - end, end, start,
                              prev_kid, kid)))
            if stop == INF:
                break
            end = stop if end is None else max(end, stop)
            prev_kid = kid
        # rotation-stall: open-ended epoch older than max age
        for kid, _svs, sa, ea in eps:
            if ea == INF and now - sa > max_age:
                findings.append(dict(
                    severity="WARN", kind="rotation-stall", service=svc,
                    detail="service %s: key %s open-ended for %.0f days "
                           "(> %d) — rotation never closed"
                           % (svc, kid, (now - sa) / DAY,
                              int(max_age / DAY))))
    return epochs, findings


def _dedupe(eps):
    out = []
    for ep in eps:
        if ep not in out:
            out.append(ep)
    return out


def _fmt(ep):
    end = "open" if ep[3] == INF else "%.0f" % ep[3]
    return "[%s %s..%s]" % (ep[1], "%.0f" % ep[2], end)


def usage_findings(rows, epochs):
    """usage rows + governing epochs -> findings."""
    findings = []
    for row in rows:
        kid, ts = row.get("key_id"), _num(row.get("ts"))
        if not isinstance(kid, str) or not kid or ts is None:
            findings.append(dict(
                severity="WARN", kind="malformed-line", service="",
                detail="mac record missing ts/key_id"))
            continue
        ep = epochs.get(kid)
        if ep is None:
            findings.append(dict(
                severity="BLOCK", kind="unknown-key",
                service=_svc_of(row),
                detail="ts %.0f: key %s not declared in registry"
                       % (ts, kid)))
            continue
        _, owner, start, end = ep
        if ts < start:
            findings.append(dict(
                severity="BLOCK", kind="outside-window", service=owner,
                detail="ts %.0f: key %s used %.0fs BEFORE not_before "
                       "(%.0f)" % (ts, kid, start - ts, start)))
        elif ts > end:
            findings.append(dict(
                severity="BLOCK", kind="outside-window", service=owner,
                detail="ts %.0f: key %s used %.0fs AFTER not_after (%.0f)"
                       % (ts, kid, ts - end, end)))
        svc = row.get("service")
        if isinstance(svc, str) and svc and svc != owner:
            findings.append(dict(
                severity="WARN", kind="service-mismatch", service=owner,
                detail="ts %.0f: key %s owned by service %s used by "
                       "service %s — shared-state exposure"
                       % (ts, kid, owner, svc)))
    return findings


def _svc_of(row):
    svc = row.get("service")
    return svc if isinstance(svc, str) else ""


def analyze(reg_rows, mac_rows, now, grace=0.0, max_age=90 * DAY):
    """both captures -> sorted findings + rollup rows."""
    epochs, reg = registry_facts(reg_rows, now, grace, max_age)
    mac = usage_findings(mac_rows, epochs)
    findings = sorted(reg + mac, key=lambda f: (SEVS.index(f["severity"]),
                                                f["kind"], f["detail"]))
    stats = {}
    for _kid, svc, _nb, _na in epochs.values():
        stats.setdefault(svc, dict(service=svc, keys=0, macs=0, findings=0))
    for ep in epochs.values():
        stats[ep[1]]["keys"] += 1
    for row in mac_rows:
        ep = epochs.get(row.get("key_id")) \
            if isinstance(row.get("key_id"), str) else None
        if ep and _num(row.get("ts")) is not None:
            stats[ep[1]]["macs"] += 1
    for f in findings:
        svc = f.get("service")
        if svc in stats:
            stats[svc]["findings"] += 1
    rollup = sorted(stats.values(),
                    key=lambda s: (-s["findings"], s["service"]))
    return findings, rollup, len(reg_rows), len(mac_rows)


def main(argv=None):
    ap = argparse.ArgumentParser(
        prog="hmac-lifecycle-audit",
        description="HMAC secret-epoch rotation / shared-exposure audit")
    ap.add_argument("keys", help="key-epoch registry JSONL")
    ap.add_argument("macs", nargs="?", help="MAC usage log JSONL "
                    "(omit for registry-only audit)")
    ap.add_argument("--grace", type=float, default=0.0,
                    help="seconds two epochs may overlap (default 0)")
    ap.add_argument("--max-age-days", type=float, default=90.0,
                    help="open-ended key older than this stalls (def 90)")
    ap.add_argument("--now", type=float, default=None,
                    help="override wall clock for stall checks")
    ap.add_argument("--json", action="store_true",
                    help="emit findings as JSON")
    args = ap.parse_args(argv)
    try:
        reg_rows, reg_bad = load_jsonl(args.keys)
    except OSError as exc:
        print("cannot read registry: %s" % exc, file=sys.stderr)
        return 2
    mac_rows, mac_bad = [], 0
    if args.macs:
        try:
            mac_rows, mac_bad = load_jsonl(args.macs)
        except OSError as exc:
            print("cannot read usage log: %s" % exc, file=sys.stderr)
            return 2
    import time
    now = args.now if args.now is not None else time.time()
    findings, rollup, n_reg, n_mac = analyze(
        reg_rows, mac_rows, now, args.grace, args.max_age_days * DAY)
    if reg_bad or mac_bad:
        findings.append(dict(
            severity="WARN", kind="malformed-line",
            detail="%d unparsable line(s) (%d registry, %d usage)"
                   % (reg_bad + mac_bad, reg_bad, mac_bad)))
        findings = sorted(findings,
                          key=lambda f: (SEVS.index(f["severity"]),
                                         f["kind"], f["detail"]))
    if args.json:
        print(json.dumps(dict(
            registry_rows=n_reg, mac_records=n_mac, findings=findings,
            services=rollup), ensure_ascii=False, indent=1))
    else:
        for f in findings:
            print("%-5s %-17s %s" % (f["severity"], f["kind"], f["detail"]))
        for st in rollup:
            print("service %-10s keys=%d macs=%d findings=%d"
                  % (st["service"], st["keys"], st["macs"], st["findings"]))
        print("%d registry row(s), %d mac record(s) scanned, "
              "%d finding(s)" % (n_reg, n_mac, len(findings)))
    return 1 if findings else 0


def self_test():
    import io
    import os
    import tempfile
    from contextlib import redirect_stdout

    def key(kid, svc, nb, na=None):
        row = dict(key_id=kid, service=svc, not_before=nb)
        if na is not None:
            row["not_after"] = na
        return row

    def mac(ts, kid, svc=None):
        row = dict(ts=ts, key_id=kid)
        if svc:
            row["service"] = svc
        return row

    now = 1_000_000.0

    def kinds(rows_reg, rows_mac=None, **kw):
        f, _, _, _ = analyze(rows_reg, rows_mac or [], now,
                                kw.get("grace", 0.0),
                                kw.get("max_age", 90 * DAY))
        return [x["kind"] for x in f], f

    # 1. registry hygiene: conflict blocks, identical dup warns
    ks, fs = kinds([key("k1", "auth", 0), key("k1", "auth", 500),
                    key("k2", "pay", 0), key("k2", "pay", 0)])
    got = {(x["kind"], x["severity"]) for x in fs}
    assert ("key-id-collision", "BLOCK") in got, got
    assert ("key-id-duplicate", "WARN") in got, got

    # 2. epoch overlap: beyond grace blocks, within grace is clean
    ks, fs = kinds([key("a", "auth", 0, 100), key("b", "auth", 90)])
    assert [x["kind"] for x in fs] == ["epoch-overlap"], fs
    ks, fs = kinds([key("a", "auth", 0, 100), key("b", "auth", 90)],
                   grace=20)
    assert fs == [], fs
    # different services overlapping is fine — not the same secret slot
    ks, fs = kinds([key("a", "auth", 0, 100), key("b", "pay", 50)])
    assert fs == [], fs

    # 3. coverage gap between consecutive epochs of one service
    ks, fs = kinds([key("a", "auth", 0, 100), key("b", "auth", 200, 300)])
    gaps = [x for x in fs if x["kind"] == "coverage-gap"]
    assert len(gaps) == 1 and "for 100s" in gaps[0]["detail"], gaps
    # closed then re-opened with a still-active key later: no gap flagged
    ks, fs = kinds([key("a", "auth", 0, 100), key("b", "auth", 100)])
    assert [x["kind"] for x in fs if x["kind"] == "coverage-gap"] == [], fs

    # 4. rotation stall: open epoch older than max age; fresh key clean
    ks, fs = kinds([key("old", "auth", now - 11 * DAY)],
                   max_age=10 * DAY)
    stalls = [x for x in fs if x["kind"] == "rotation-stall"]
    assert len(stalls) == 1 and "key old" in stalls[0]["detail"] \
        and "11 days" in stalls[0]["detail"], stalls
    ks, fs = kinds([key("new", "auth", now - DAY)], max_age=10 * DAY)
    assert fs == [], fs

    # 5. usage: unknown key blocks
    ks, fs = kinds([key("a", "auth", 0)], [mac(10, "ghost")])
    assert [x["kind"] for x in fs] == ["unknown-key"], fs

    # 6. outside window on both sides; in-window passes
    ks, fs = kinds([key("a", "auth", 100, 200)],
                   [mac(99, "a"), mac(150, "a"), mac(300, "a")])
    ow = [x["detail"] for x in fs if x["kind"] == "outside-window"]
    assert len(ow) == 2 and any("BEFORE" in d for d in ow) \
        and any("AFTER" in d for d in ow), ow

    # 7. shared-state exposure: owner's key presented under another service
    ks, fs = kinds([key("a", "auth", 0)], [mac(10, "a", svc="pay")])
    sm = [x for x in fs if x["kind"] == "service-mismatch"]
    assert len(sm) == 1 and "auth" in sm[0]["detail"] \
        and "pay" in sm[0]["detail"], sm
    ks, fs = kinds([key("a", "auth", 0)], [mac(10, "a", svc="auth")])
    assert fs == [], fs

    # 8. clean corpus end-to-end: no findings, rollup shape right
    reg = [key("a", "auth", 0, 90), key("b", "auth", 90),
           key("p", "pay", 0)]
    macs = [mac(10, "a"), mac(95, "b"), mac(50, "p", svc="pay")]
    f, roll, nr, nm = analyze(reg, macs, now, 10.0, 90 * DAY)
    assert f == [], f
    assert [r["service"] for r in roll] == ["auth", "pay"], roll
    auth = roll[0]
    assert auth["keys"] == 2 and auth["macs"] == 2 \
        and auth["findings"] == 0, auth

    # 9. malformed registry row (missing not_before) is counted
    ks, fs = kinds([key("a", "auth", 0), dict(key_id="x", service="pay")])
    ml = [x for x in fs if x["kind"] == "malformed-line"]
    assert len(ml) == 1 and "1 registry row" in ml[0]["detail"], ml

    # 10. severity ordering: BLOCK precedes WARN in output
    ks, fs = kinds([key("a", "auth", 0, 10)],
                   [mac(99, "a"), mac(5, "a", svc="pay")])
    sevs = [x["severity"] for x in fs]
    assert sevs == sorted(sevs, key=SEVS.index) and sevs[0] == "BLOCK", fs

    # 11/12. CLI contract: rc 0 clean / 1 findings / 2 missing file, --json
    def run(rows_reg, rows_mac=None, extra=()):
        paths = []
        for rows, suffix in ((rows_reg, "k"), (rows_mac, "m")):
            if rows is None:
                continue
            with tempfile.NamedTemporaryFile("w", suffix=".jsonl",
                                             delete=False) as fh:
                fh.write("\n".join(json.dumps(r) for r in rows))
                paths.append(fh.name)
        try:
            buf = io.StringIO()
            with redirect_stdout(buf):
                rc = main(paths + list(extra))
            return rc, buf.getvalue()
        finally:
            for p in paths:
                os.unlink(p)

    rc, out = run(reg, macs, ["--grace", "10", "--now", str(now)])
    assert rc == 0 and "0 finding(s)" in out, (rc, out)
    rc, out = run(reg, [mac(10, "a"), mac(9999, "a")],
                  ["--grace", "10", "--now", str(now)])
    assert rc == 1 and "outside-window" in out, (rc, out)
    rc, out = run(reg, None, ["--now", str(now)])
    assert rc == 0 and "0 mac record(s)" in out, (rc, out)
    assert main(["/nonexistent.jsonl"]) == 2
    rc, out = run([key("g", "auth", 0)], [mac(5, "ghost")],
                  ["--json", "--now", str(now)])
    doc = json.loads(out)
    assert doc["mac_records"] == 1 \
        and doc["findings"][0]["kind"] == "unknown-key", doc

    print("hmac-lifecycle-audit self-test OK (12 groups: collision/"
          "duplicate, overlap beyond+within grace, coverage gap, stall + "
          "fresh immunity, unknown key, before/after window, service "
          "mismatch, clean corpus rollup, malformed, severity order, "
          "CLI rc 0/1/2, json)")


if __name__ == "__main__":
    if "--self-test" in sys.argv:
        self_test()  # falls through; rc 0 (probe hook runs after this line)
    else:
        raise SystemExit(main())
