#!/usr/bin/env python3
"""bond-enforcement-audit — bond/stake/slash enforcement coverage audit.

DEMAND: evidence/suggestions/tools-services/
  - "Implement enforcement mechanisms (bonds, staking, slashing) beyond reputation for audited sessions."
  - "Establish protocol-level enforcement beyond reputation for room transactions"
  - "User/peer reputation scoring"
  - "Verifier liability clarification"
  Scope: audits whether captured audited-room sessions were actually
  backed by protocol enforcement or by reputation alone. Input is
  JSONL, one enforcement event per line: {"ts","session","did",
  "role","event","amount","violation_kind","dispute_window_h"} with
  events bond_posted / bond_released / violation / slash /
  stake_change / settled. Flags violations recorded against a did
  that never posted a bond, orphan and double slashes, bonds
  released inside the dispute window, stake below the floor while
  the session is active, verifier_error liability with no verifier
  bond, and settled sessions with unreleased bonds (stuck escrow).
  rc 0 clean, 1 findings, 2 usage/IO. Stdlib only.
"""
import argparse
import json
import sys

SEVS = ("BLOCK", "WARN", "INFO")
BLOCK, WARN, INFO = SEVS
MIN_STAKE = 100.0        # protocol stake floor while a session is active
DEFAULT_WINDOW_H = 24.0  # dispute window when a violation omits it
VERIFIER_ERROR = "verifier_error"

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

def _parts(r):
    """(session, did, event, ts) of one record, ts defaulting to 0."""
    s, d, ev = _txt(r.get("session")), _txt(r.get("did")), _txt(r.get("event"))
    ts = _num(r.get("ts"))
    return s, d, ev, (0.0 if ts is None else ts)

def coverage_findings(records):
    """Bond coverage: reputation-only violations, starved stake, stuck
    escrow. verifier_error violations belong to liability_findings."""
    posted, released, settles, stakes = {}, {}, {}, []
    for r in records:
        s, d, ev, ts = _parts(r)
        if not s or not d:
            continue
        if ev == "bond_posted":
            posted.setdefault((s, d), []).append(ts)
        elif ev == "bond_released":
            released[(s, d)] = released.get((s, d), 0) + 1
        elif ev == "settled":
            settles[s] = min(settles.get(s, ts), ts)
        elif ev == "stake_change":
            amt = _num(r.get("amount"))
            if amt is not None:
                stakes.append((ts, s, d, amt))
    out = []
    for r in records:
        s, d, ev = _parts(r)[:3]
        if ev != "violation" or _txt(r.get("violation_kind")) == VERIFIER_ERROR:
            continue
        if s and d and not posted.get((s, d)):
            out.append(_f(BLOCK, "reputation-only-violation", "%s/%s" % (s, d),
                          "violation recorded but %s never posted a bond" % d))
    for ts, s, d, amt in stakes:
        settle = settles.get(s)
        if amt < MIN_STAKE and not (settle is not None and ts >= settle):
            out.append(_f(WARN, "stake-below-min", "%s/%s" % (s, d),
                          "stake %.0f under %.0f floor while session active"
                          % (amt, MIN_STAKE)))
    for key in sorted(posted):
        stuck = len(posted[key]) - released.get(key, 0)
        if key[0] in settles and stuck > 0:
            out.append(_f(INFO, "stuck-escrow", "%s/%s" % key,
                          "%d bond(s) unreleased after settle" % stuck))
    return out

def slash_findings(records):
    """Orphan slashes (no matching prior violation) and double slashes."""
    viol, slashes = {}, {}
    for i, r in enumerate(records):
        s, d, ev, ts = _parts(r)
        if not s or not d:
            continue
        if ev == "violation":
            viol.setdefault((s, d), []).append((ts, i))
        elif ev == "slash":
            slashes.setdefault((s, d), []).append((ts, i))
    out = []
    for key in sorted(slashes):
        vts, matched = sorted(viol.get(key, [])), set()
        for ts, _i in sorted(slashes[key]):
            prior = [v for v in vts if v[0] <= ts]
            if not prior:
                out.append(_f(BLOCK, "orphan-slash", "%s/%s" % key,
                              "slash at t=%.0f with no prior violation" % ts))
                continue
            unused = [v for v in prior if v not in matched]
            target = unused[-1] if unused else prior[-1]
            if target in matched:
                out.append(_f(BLOCK, "double-slash", "%s/%s" % key,
                              "violation at t=%.0f slashed more than once"
                              % target[0]))
            matched.add(target)
    return out

def window_findings(records, default_window_h=DEFAULT_WINDOW_H):
    """bond_released before the dispute window closed on the session."""
    viols, releases = {}, []
    for r in records:
        s, _d, ev, ts = _parts(r)
        if not s:
            continue
        if ev == "violation":
            win = _num(r.get("dispute_window_h"))
            viols.setdefault(s, []).append(
                (ts, win if win is not None and win >= 0 else default_window_h))
        elif ev == "bond_released":
            releases.append((ts, s))
    out = []
    for ts, s in sorted(releases):
        prior = [v for v in viols.get(s, ()) if v[0] <= ts]
        if not prior:
            continue
        last_ts = max(v[0] for v in prior)
        win = max(v[1] for v in prior if v[0] == last_ts)
        if 0 <= ts - last_ts < win * 3600.0:
            out.append(_f(WARN, "early-release", s,
                          "bond released %.0fs after last violation; "
                          "dispute window %.0fh" % (ts - last_ts, win)))
    return out

def liability_findings(records):
    """verifier_error attributed to a verifier that posted no bond."""
    posted = set()
    for r in records:
        s, d, ev = _parts(r)[:3]
        if ev == "bond_posted" and s and d:
            posted.add((s, d))
    out, seen = [], set()
    for r in records:
        s, d, ev = _parts(r)[:3]
        if ev != "violation" or _txt(r.get("violation_kind")) != VERIFIER_ERROR:
            continue
        if not s or not d or (s, d) in seen or (s, d) in posted:
            continue
        seen.add((s, d))
        out.append(_f(BLOCK, "verifier-no-bond", "%s/%s" % (s, d),
                      "%s carries verifier_error liability with no bond "
                      "posted in the session" % d))
    return out

def audit(path):
    """Run every check over the capture at path; -> sorted findings."""
    records, bad = load_jsonl(path)
    findings = (coverage_findings(records) + slash_findings(records)
                + window_findings(records) + liability_findings(records))
    if bad:
        findings.append(_f(WARN, "malformed-line", "-",
                           "%d unparsable/non-object line(s)" % bad))
    return sorted(findings, key=_key)

def render(findings):
    """Print `SEV kind origin: detail` lines; return severity counts."""
    counts = {s: 0 for s in SEVS}
    for f in sorted(findings, key=_key):
        counts[f["severity"]] += 1
        print("%-5s %-26s %s: %s" % (f["severity"], f["kind"], f["origin"],
                                     f["detail"]))
    print("%d finding(s): %d block, %d warn, %d info"
          % (len(findings), counts[BLOCK], counts[WARN], counts[INFO]))
    return counts

def main(argv=None):
    """CLI entry: 0 clean, 1 findings, 2 usage/IO."""
    ap = argparse.ArgumentParser(
        prog="bond-enforcement-audit", description="Bond/stake/slash "
        "enforcement coverage audit over a JSONL capture of session events")
    ap.add_argument("input", help="JSONL enforcement event capture")
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
        base = dict(ts=1, session="s1", did="d1", role="auditor",
                    event="bond_posted", amount=100)
        base.update(kw)
        return base

    cov = coverage_findings([
        rec(session="s2", did="d9", event="violation",
            violation_kind="fabricated_proof"),
        rec(session="s2", did="d8", event="bond_posted", amount=100),
        rec(session="s2", did="d8", event="violation",
            violation_kind="late_attestation")])
    assert len(cov) == 1, cov
    assert cov[0]["kind"] == "reputation-only-violation", cov
    assert cov[0]["severity"] == BLOCK and cov[0]["origin"] == "s2/d9", cov

    sl = slash_findings([
        rec(session="s3", did="d3", event="slash", ts=10),
        rec(session="s4", did="d4", event="violation", ts=10),
        rec(session="s4", did="d4", event="slash", ts=20),
        rec(session="s4", did="d4", event="slash", ts=30)])
    skinds = [f["kind"] for f in sl]
    assert skinds.count("orphan-slash") == 1, sl
    assert skinds.count("double-slash") == 1, sl
    assert all(f["severity"] == BLOCK for f in sl), sl

    win = window_findings([
        rec(session="s5", did="d5", event="violation", ts=100,
            dispute_window_h=24),
        rec(session="s5", did="d5", event="bond_released", ts=100 + 3600),
        rec(session="s9", did="d9", event="violation", ts=100,
            dispute_window_h=1),
        rec(session="s9", did="d9", event="bond_released", ts=100 + 3600)])
    assert len(win) == 1 and win[0]["kind"] == "early-release", win
    assert win[0]["severity"] == WARN and win[0]["origin"] == "s5", win

    starved = coverage_findings([
        rec(session="s6", did="d6", event="bond_posted", ts=0),
        rec(session="s6", did="d6", event="stake_change", ts=10, amount=50)])
    assert len(starved) == 1 and starved[0]["kind"] == "stake-below-min", starved
    assert coverage_findings([
        rec(session="s6b", did="d6", event="stake_change", ts=10, amount=300),
        rec(session="s6b", did="d6", event="settled", ts=5)]) == []

    escrow = coverage_findings([
        rec(session="s8", did="d8", event="bond_posted", ts=0),
        rec(session="s8", did="d8", event="settled", ts=50)])
    assert len(escrow) == 1 and escrow[0]["kind"] == "stuck-escrow", escrow
    assert escrow[0]["severity"] == INFO and escrow[0]["origin"] == "s8/d8"

    liab = liability_findings([
        rec(session="s7", did="d7", role="verifier", event="violation",
            violation_kind="verifier_error", ts=5),
        rec(session="s7b", did="d7b", role="verifier", event="bond_posted",
            ts=1),
        rec(session="s7b", did="d7b", role="verifier", event="violation",
            violation_kind="verifier_error", ts=5)])
    assert len(liab) == 1 and liab[0]["origin"] == "s7/d7", liab
    assert liab[0]["severity"] == BLOCK, liab
    assert liab[0]["kind"] == "verifier-no-bond", liab

    clean = [
        rec(ts=10, event="bond_posted", amount=250),
        rec(ts=1000, event="violation", violation_kind="late_attestation",
            dispute_window_h=24),
        rec(ts=2000, event="slash", amount=50),
        rec(ts=1000 + 24 * 3600 + 5, event="bond_released", amount=250),
        rec(ts=90000, event="stake_change", amount=300),
        rec(ts=200000, event="settled")]
    dirty = [
        rec(ts=1, session="s2", did="d9", event="violation",
            violation_kind="fabricated_proof"),
        rec(ts=0, session="s3", did="d3", event="bond_posted", amount=100),
        rec(ts=10, session="s3", did="d3", event="slash", amount=10),
        rec(ts=0, session="s4", did="d4", event="bond_posted", amount=100),
        rec(ts=10, session="s4", did="d4", event="violation",
            violation_kind="missed_check"),
        rec(ts=20, session="s4", did="d4", event="slash", amount=10),
        rec(ts=30, session="s4", did="d4", event="slash", amount=10),
        rec(ts=0, session="s5", did="d5", event="bond_posted", amount=100),
        rec(ts=100, session="s5", did="d5", event="violation",
            violation_kind="late", dispute_window_h=24),
        rec(ts=100 + 3600, session="s5", did="d5", event="bond_released"),
        rec(ts=0, session="s6", did="d6", event="bond_posted", amount=100),
        rec(ts=10, session="s6", did="d6", event="stake_change", amount=50),
        rec(ts=5, session="s7", did="d7", role="verifier", event="violation",
            violation_kind="verifier_error"),
        rec(ts=0, session="s8", did="d8", event="bond_posted", amount=100),
        rec(ts=1000, session="s8", did="d8", event="settled")]

    paths = []
    try:
        clean_path = _write(clean)
        paths.append(clean_path)
        assert audit(clean_path) == []
        assert run([clean_path])[0] == 0

        dirty_path = _write(dirty)
        paths.append(dirty_path)
        pairs = {(f["kind"], f["severity"]) for f in audit(dirty_path)}
        for want in (("reputation-only-violation", BLOCK),
                     ("orphan-slash", BLOCK), ("double-slash", BLOCK),
                     ("early-release", WARN), ("stake-below-min", WARN),
                     ("verifier-no-bond", BLOCK), ("stuck-escrow", INFO)):
            assert want in pairs, (want, sorted(pairs))
        assert run([dirty_path])[0] == 1
        doc = json.loads(run([dirty_path, "--json"])[1])
        assert doc["count"] == len(doc["findings"]) > 0

        mal_path = _write([rec()], bad=1)
        paths.append(mal_path)
        rc, out = run([mal_path])
        assert rc == 1 and "malformed-line" in out
        assert run(["/nonexistent-bonds.jsonl"])[0] == 2
    finally:
        for p in paths:
            if os.path.exists(p):
                os.unlink(p)

    print("bond-enforcement-audit self-test OK (13 assertion groups:"
          " reputation-only violation, orphan slash, double slash, early"
          " release + window boundary, stake floor + post-settle immunity,"
          " stuck escrow, verifier liability, clean corpus rc 0, dirty"
          " kinds, CLI rc 1/2, --json)")

if __name__ == "__main__":
    if "--self-test" in sys.argv:
        self_test()  # falls through; rc 0 (probe hook runs after this)
    else:
        raise SystemExit(main())
