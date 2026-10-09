#!/usr/bin/env python3
"""crossroom-identity-audit — cross-room DID identity/provenance audit.

DEMAND: evidence/suggestions/tools-services/
  - "Cross-room identity lookup and verification of agent ownership/provenance"
  - "Cross-room identity lookup with replayable audit trail"
  - "Confirm ownership and operational metrics for external agents/services referenced in room"
  - "Multi-account orchestration without credential friction"
  Scope: audits a capture of cross-room identity events for drift,
  conflicts and unreplayable provenance. Input is JSONL, one identity
  event per line: {"ts","room","did","alias","event","claims_owner",
  "service","metrics"} plus optional "seq"; events are introduced /
  active / left / ownership_claim / metrics_claim. Flags one did
  known under several aliases, service ownership conflicts and
  claimants that never appeared in the room, one alias orchestrating
  three or more dids, left-then-active gaps without re-introduction,
  metrics claims unverified or lacking active history, and room+did
  streams not strictly increasing in seq (ts when seq is absent).
  Data only: plain parsing, no network, no subprocess. rc 0 clean,
  1 findings, 2 usage/IO. Stdlib only.
"""
import argparse
import json
import sys

SEVS = ("BLOCK", "WARN", "INFO")
BLOCK, WARN, INFO = SEVS
PRESENCE = ("introduced", "active", "left")  # events that make a did visible
MIN_ACCOUNT_DIDS = 3   # dids behind one alias that trip orchestration

def load_jsonl(path):
    """path -> (records, bad_lines): dict per line, junk counted."""
    records, bad = [], 0
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
                records.append(obj)
            else:
                bad += 1
    return records, bad

def _num(v):
    """JSON scalar -> float, or None when missing/non-numeric."""
    if isinstance(v, bool) or not isinstance(v, (int, float)):
        return None
    return float(v)

def _txt(v):
    """Non-empty string -> itself, else None."""
    return v if isinstance(v, str) and v else None

def _f(sev, kind, origin, detail):
    """Uniform finding dict."""
    return {"severity": sev, "kind": kind, "origin": origin, "detail": detail}

def _key(f):
    """Deterministic display order: severity, kind, origin, detail."""
    return (SEVS.index(f["severity"]), f["kind"], str(f["origin"]), f["detail"])

def alias_drift_findings(records):
    """Same did known under different alias strings -> WARN."""
    per = {}
    for r in records:
        d, a = _txt(r.get("did")), _txt(r.get("alias"))
        if d and a:
            counts = per.setdefault(d, {})
            counts[a] = counts.get(a, 0) + 1
    out = []
    for d, aliases in sorted(per.items()):
        if len(aliases) > 1:
            names = ", ".join("%s(x%d)" % kv for kv in sorted(aliases.items()))
            out.append(_f(WARN, "alias-drift", d, "known under %d aliases: %s"
                          % (len(aliases), names)))
    return out

def ownership_conflict_findings(records):
    """Service ownership: outside claimants and contradicted claims."""
    present, claims = set(), {}
    for r in records:
        room, d, ev = _txt(r.get("room")), _txt(r.get("did")), _txt(r.get("event"))
        if not room or not d:
            continue
        if ev in PRESENCE:
            present.add((room, d))
        if ev == "ownership_claim":
            svc = _txt(r.get("service"))
            if svc:
                ts = _num(r.get("ts"))
                claims.setdefault(svc, []).append(
                    (ts if ts is not None else 0.0, room, d,
                     _txt(r.get("claims_owner")) or d))
    out, flagged = [], set()
    for svc, cl in sorted(claims.items()):
        for _ts, room, d, _owner in cl:
            if (room, d) not in present and (room, d) not in flagged:
                flagged.add((room, d))
                out.append(_f(BLOCK, "outside-claimant", "%s/%s" % (room, d),
                              "%s claimed ownership of %s without ever "
                              "appearing in the room" % (d, svc)))
        owners = {c[3] for c in cl}
        if len(owners) > 1:
            out.append(_f(BLOCK, "ownership-conflict", svc,
                          "claimed by %s; latest claim stands with %s until "
                          "contradicted" % (", ".join(sorted(owners)),
                                            sorted(cl)[-1][3])))
    return out

def multi_account_findings(records, min_dids=MIN_ACCOUNT_DIDS):
    """One alias spread over several dids -> WARN (orchestration)."""
    per = {}
    for r in records:
        d, a = _txt(r.get("did")), _txt(r.get("alias"))
        if d and a:
            per.setdefault(a, set()).add(d)
    out = []
    for a, dids in sorted(per.items()):
        if len(dids) >= min_dids:
            out.append(_f(WARN, "multi-account", a, "alias runs under %d "
                          "dids: %s" % (len(dids), ", ".join(sorted(dids)))))
    return out

def provenance_findings(records):
    """Trail replay: left-then-active gaps, unbacked metrics claims, and
    room+did event streams not strictly increasing in seq/ts."""
    per = {}
    for i, r in enumerate(records):
        room, d = _txt(r.get("room")), _txt(r.get("did"))
        if room and d:
            per.setdefault((room, d), []).append((i, r))
    out = []
    for (room, d), evs in sorted(per.items()):
        origin = "%s/%s" % (room, d)
        keys, left, ran_active = [], False, False
        for i, r in evs:
            ev = _txt(r.get("event"))
            key = _num(r.get("seq"))
            if key is None:
                key = _num(r.get("ts"))
            keys.append(key if key is not None else float(i))
            if ev == "active":
                if left:
                    out.append(_f(WARN, "unreplayable-trail", origin,
                                  "active again after leaving, with no "
                                  "re-introduction on record"))
                left = False
                ran_active = True
            elif ev == "introduced":
                left = False
            elif ev == "left":
                left = True
            elif ev == "metrics_claim":
                if r.get("metrics") is False:
                    out.append(_f(WARN, "metrics-unverified", origin,
                                  "metrics claim carries metrics=false"))
                elif not ran_active:
                    out.append(_f(WARN, "metrics-no-history", origin,
                                  "operational metrics claimed with no "
                                  "prior active history"))
        for j in range(1, len(keys)):
            if keys[j] <= keys[j - 1]:
                out.append(_f(WARN, "non-monotonic-trail", origin,
                              "order key %r at position %d not increasing "
                              "after %r" % (keys[j], j, keys[j - 1])))
    return out

def audit(path):
    """Run every check over the capture at path; -> sorted findings."""
    records, bad = load_jsonl(path)
    findings = (alias_drift_findings(records)
                + ownership_conflict_findings(records)
                + multi_account_findings(records) + provenance_findings(records))
    if bad:
        findings.append(_f(WARN, "malformed-line", "-",
                           "%d unparsable/non-object line(s)" % bad))
    return sorted(findings, key=_key)

def render(findings):
    """Print `SEV kind origin: detail` lines; return severity counts."""
    counts = {s: 0 for s in SEVS}
    for f in sorted(findings, key=_key):
        counts[f["severity"]] += 1
        print("%-5s %-22s %s: %s" % (f["severity"], f["kind"], f["origin"],
                                     f["detail"]))
    print("%d finding(s): %d block, %d warn, %d info"
          % (len(findings), counts[BLOCK], counts[WARN], counts[INFO]))
    return counts

def main(argv=None):
    """CLI entry: 0 clean, 1 findings, 2 usage/IO."""
    ap = argparse.ArgumentParser(
        prog="crossroom-identity-audit",
        description="Cross-room DID identity, ownership and provenance "
                    "audit over a JSONL capture of identity events")
    ap.add_argument("input", help="JSONL cross-room identity capture")
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
    for _ in range(bad):
        fh.write("{not json\n")
    fh.close()
    return fh.name

def self_test():
    import io
    import os
    from contextlib import redirect_stdout

    def run(args):
        """Capture stdout around main(args); -> (rc, output)."""
        buf = io.StringIO()
        with redirect_stdout(buf):
            rc = main(args)
        return rc, buf.getvalue()

    def rec(**kw):
        base = dict(ts=1, room="r1", did="d1", alias="nova",
                    event="introduced", claims_owner=None, service=None,
                    metrics=None)
        base.update(kw)
        return base

    drift = alias_drift_findings([
        rec(room="r1", did="d2", alias="beta", ts=1),
        rec(room="r2", did="d2", alias="beta2", ts=2)])
    assert len(drift) == 1 and drift[0]["severity"] == WARN, drift
    assert drift[0]["origin"] == "d2" and "beta2" in drift[0]["detail"], drift
    assert alias_drift_findings([rec(alias="beta"),
                                 rec(room="r2", alias="beta")]) == []

    own = ownership_conflict_findings([
        rec(did="d3", alias="g3", ts=10), rec(did="d4", alias="g4", ts=11),
        rec(did="d3", ts=12, event="ownership_claim", service="svc-y",
            claims_owner="d3"),
        rec(did="d4", ts=13, event="ownership_claim", service="svc-y",
            claims_owner="d4"),
        rec(did="d99", ts=20, event="ownership_claim", service="svc-z",
            claims_owner="d99")])
    okinds = {f["kind"]: f["severity"] for f in own}
    assert okinds.get("ownership-conflict") == BLOCK, own
    assert okinds.get("outside-claimant") == BLOCK, own

    multi = multi_account_findings([
        rec(did="d5", alias="gamma", room="r1"),
        rec(did="d6", alias="gamma", room="r2"),
        rec(did="d7", alias="gamma", room="r3"),
        rec(did="d8", alias="solo", room="r1")])
    assert len(multi) == 1 and multi[0]["origin"] == "gamma", multi
    assert multi[0]["severity"] == WARN, multi
    assert multi[0]["kind"] == "multi-account", multi

    prov = provenance_findings([
        rec(room="r4", did="d8x", alias="p", ts=1),
        rec(room="r4", did="d8x", alias="p", ts=2, event="active"),
        rec(room="r4", did="d8x", alias="p", ts=3, event="left"),
        rec(room="r4", did="d8x", alias="p", ts=4, event="active"),
        rec(room="r5", did="d9x", alias="q", ts=10, seq=5),
        rec(room="r5", did="d9x", alias="q", ts=11, event="active", seq=3),
        rec(room="r6", did="d10x", alias="m", ts=1),
        rec(room="r6", did="d10x", alias="m", ts=2, event="metrics_claim",
            metrics=False),
        rec(room="r6", did="d11x", alias="n", ts=1),
        rec(room="r6", did="d11x", alias="n", ts=2, event="metrics_claim",
            metrics=True)])
    pkinds = [f["kind"] for f in prov]
    assert pkinds.count("unreplayable-trail") == 1, prov
    assert pkinds.count("non-monotonic-trail") == 1, prov
    assert "metrics-unverified" in pkinds, prov
    assert "metrics-no-history" in pkinds, prov
    assert provenance_findings([
        rec(room="r7", did="d12x", alias="s", ts=1),
        rec(room="r7", did="d12x", alias="s", ts=2, event="active"),
        rec(room="r7", did="d12x", alias="s", ts=3, event="metrics_claim",
            metrics=True),
        rec(room="r7", did="d12x", alias="s", ts=4, event="left"),
        rec(room="r7", did="d12x", alias="s", ts=5)]) == []

    clean = [rec(ts=1), rec(ts=2, event="active"),
             rec(ts=3, event="ownership_claim", service="svc-x",
                 claims_owner="d1"),
             rec(ts=4, event="metrics_claim", metrics=True),
             rec(ts=5, event="left")]
    dirty = [
        rec(ts=1, room="r1", did="d2", alias="beta"),
        rec(ts=2, room="r2", did="d2", alias="beta2"),
        rec(ts=10, room="r1", did="d3", alias="g3"),
        rec(ts=11, room="r1", did="d3", alias="g3", event="active"),
        rec(ts=12, room="r1", did="d4", alias="g4"),
        rec(ts=13, room="r1", did="d3", alias="g3", event="ownership_claim",
            service="svc-y", claims_owner="d3"),
        rec(ts=14, room="r1", did="d4", alias="g4", event="ownership_claim",
            service="svc-y", claims_owner="d4"),
        rec(ts=20, room="r1", did="d99", alias="z", event="ownership_claim",
            service="svc-z", claims_owner="d99"),
        rec(ts=30, room="r1", did="d5", alias="gamma"),
        rec(ts=31, room="r2", did="d6", alias="gamma"),
        rec(ts=32, room="r3", did="d7", alias="gamma"),
        rec(ts=1, room="r4", did="d8", alias="p"),
        rec(ts=2, room="r4", did="d8", alias="p", event="active"),
        rec(ts=3, room="r4", did="d8", alias="p", event="left"),
        rec(ts=4, room="r4", did="d8", alias="p", event="active"),
        rec(ts=10, room="r5", did="d9", alias="q", seq=5),
        rec(ts=11, room="r5", did="d9", alias="q", event="active", seq=3)]

    paths = []
    try:
        clean_path = _write(clean)
        paths.append(clean_path)
        assert audit(clean_path) == []
        assert run([clean_path])[0] == 0

        dirty_path = _write(dirty)
        paths.append(dirty_path)
        pairs = {(f["kind"], f["severity"]) for f in audit(dirty_path)}
        for want in (("alias-drift", WARN), ("ownership-conflict", BLOCK),
                     ("outside-claimant", BLOCK), ("multi-account", WARN),
                     ("unreplayable-trail", WARN),
                     ("non-monotonic-trail", WARN)):
            assert want in pairs, (want, sorted(pairs))
        assert run([dirty_path])[0] == 1
        doc = json.loads(run([dirty_path, "--json"])[1])
        assert doc["count"] == len(doc["findings"]) > 0

        mal_path = _write([rec()], bad=1)
        paths.append(mal_path)
        rc, out = run([mal_path])
        assert rc == 1 and "malformed-line" in out
        assert run(["/nonexistent-identity.jsonl"])[0] == 2
    finally:
        for p in paths:
            if os.path.exists(p):
                os.unlink(p)

    print("crossroom-identity-audit self-test OK (12 assertion groups:"
          " alias drift + stability, ownership conflict, outside claimant,"
          " multi-account, unreplayable trail, non-monotonic seq, metrics"
          " unverified/no-history, replayable clean trail, clean corpus"
          " rc 0, dirty kinds, CLI rc 1/2, --json)")

if __name__ == "__main__":
    if "--self-test" in sys.argv:
        self_test()  # falls through; rc 0 (probe hook runs after this)
    else:
        raise SystemExit(main())
