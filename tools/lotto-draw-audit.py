#!/usr/bin/env python3
"""lotto-draw-audit — commit/reveal, drand winner, root-drift, payout audit.

DEMAND: evidence/suggestions/tools-services/ (file citations below)
  - "Make lottery draw actually auditable with public commit/drand"
  - "Get a proof hash or Merkle root for a verified data feed (AUDIO/USDT)"
  - "Token-drift proof tracking and alerting"
  Scope: audits a JSONL capture of lottery draw lifecycle events, one record
  per line: ts, draw_id, event (commit|reveal|draw|payout), tickets_root,
  ticket_count, deadline, drand_round, drand_sig, winner_idx, amount, plus
  an optional "tickets" id list on commit/draw rows. Checks commit-before-
  reveal ordering, reveal deadlines, drand winner determinism, tickets_root
  drift and recompute, drand_round reuse across draws, payout-without-draw
  and double payouts. Inputs are data only: plain parsing, no network, no
  subprocess, nothing is run from input. rc 0 clean, 1 findings, 2
  usage/IO. Stdlib only.
"""
import argparse
import hashlib
import io
import json
import os
import sys
import tempfile
from contextlib import redirect_stderr, redirect_stdout
from datetime import datetime, timezone

SEVS = ("BLOCK", "WARN", "INFO")
WITH_DRAND = ("commit", "reveal", "draw")


def num(v):
    """Numeric and not bool -> float; else None."""
    if isinstance(v, bool):
        return None
    return float(v) if isinstance(v, (int, float)) else None


def parse_ts(v):
    """Epoch number or ISO-8601 string -> epoch float (UTC); else None."""
    n = num(v)
    if n is not None:
        return n
    if isinstance(v, str):
        try:
            dt = datetime.fromisoformat(v.replace("Z", "+00:00"))
        except ValueError:
            return None
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        return dt.timestamp()
    return None


def load_jsonl(path):
    """Parse a JSONL capture -> (records, bad_lines).

    One record per line; blank lines are skipped; a line that is not a
    JSON object yields a None record and its 1-based number lands in
    bad_lines.
    """
    records, bad = [], []
    with open(path, "r", encoding="utf-8") as fh:
        for i, line in enumerate(fh, 1):
            s = line.strip()
            if not s:
                continue
            try:
                rec = json.loads(s)
            except ValueError:
                rec = None
            if not isinstance(rec, dict):
                bad.append(i)
            records.append(rec)
    return records, bad


def did_of(rec):
    """Stable draw id string for a record ('?' when absent)."""
    did = rec.get("draw_id")
    if did is None:
        return "?"
    return did if isinstance(did, str) else str(did)


def commit_reveal_findings(records):
    """Commit/reveal protocol checks.

    - reveal or draw whose commit is missing, or did not precede it -> BLOCK
    - reveal timestamp after the committed deadline -> BLOCK
    - one drand_round reused across different draws -> BLOCK
    """
    finds = []
    commits = {}
    drand = {}
    for rec in records:
        if not rec:
            continue
        did = did_of(rec)
        if rec.get("event") == "commit" and did not in commits:
            commits[did] = rec  # earliest commit per draw wins
        rnd = rec.get("drand_round")
        if rnd is not None and rec.get("event") in WITH_DRAND:
            if rnd in drand and drand[rnd] != did:
                finds.append({"kind": "drand-round-reuse", "severity": "BLOCK",
                              "origin": did,
                              "detail": "drand_round %s already used by draw %s" % (rnd, drand[rnd])})
            else:
                drand[rnd] = did
    for rec in records:
        if not rec or rec.get("event") not in ("reveal", "draw"):
            continue
        did = did_of(rec)
        ev = rec.get("event")
        rts = parse_ts(rec.get("ts"))
        com = commits.get(did)
        if com is None:
            finds.append({"kind": "missing-commit", "severity": "BLOCK",
                          "origin": did,
                          "detail": "%s at ts=%s has no commit on record" % (ev, rec.get("ts"))})
            continue
        cts = parse_ts(com.get("ts"))
        if rts is not None and cts is not None and rts <= cts:
            finds.append({"kind": "commit-not-before-reveal", "severity": "BLOCK",
                          "origin": did,
                          "detail": "%s ts=%s not after commit ts=%s" % (ev, rts, cts)})
        if ev == "reveal":
            dl = parse_ts(com.get("deadline"))
            if rts is not None and dl is not None and rts > dl:
                finds.append({"kind": "late-reveal", "severity": "BLOCK",
                              "origin": did,
                              "detail": "reveal ts=%s after committed deadline=%s" % (rts, dl)})
    return finds


def derive_winner(drand_sig, draw_id, ticket_count):
    """Deterministic winner index: sha256("<sig>|<draw_id>") mod ticket_count."""
    if ticket_count is None or ticket_count <= 0:
        return None
    key = "%s|%s" % (drand_sig, draw_id)
    return int(hashlib.sha256(key.encode()).hexdigest(), 16) % ticket_count


def winner_findings(records):
    """Draw determinism: recorded winner_idx must match the drand derivation."""
    finds = []
    for rec in records:
        if not rec or rec.get("event") != "draw":
            continue
        did = did_of(rec)
        sig = rec.get("drand_sig")
        cnt = num(rec.get("ticket_count"))
        idx = num(rec.get("winner_idx"))
        if cnt is None or cnt <= 0:
            finds.append({"kind": "unauditable-draw", "severity": "WARN",
                          "origin": did,
                          "detail": "draw with unusable ticket_count=%s" % rec.get("ticket_count")})
            continue
        if not isinstance(sig, str) or not sig or idx is None:
            finds.append({"kind": "unauditable-draw", "severity": "WARN",
                          "origin": did,
                          "detail": "draw missing drand_sig/winner_idx; not verifiable"})
            continue
        exp = derive_winner(sig, did, int(cnt))
        if idx != float(exp):
            finds.append({"kind": "winner-mismatch", "severity": "BLOCK",
                          "origin": did,
                          "detail": "recorded winner_idx=%s but sha256(drand_sig"
                                    "|draw_id) mod %d = %d"
                                    % (rec.get("winner_idx"), int(cnt), exp)})
    return finds


def tickets_root(ticket_ids):
    """Hash-chain root over sorted ticket ids: h = sha256(h + str(id))."""
    h = b""
    for tid in sorted(ticket_ids, key=lambda x: str(x)):
        h = hashlib.sha256(h + str(tid).encode()).digest()
    return h.hex()


def root_findings(records):
    """tickets_root drift between commit and draw; recompute over tickets."""
    finds = []
    roots = {}
    for rec in records:
        if not rec or rec.get("event") not in ("commit", "draw"):
            continue
        roots.setdefault(did_of(rec), {}).setdefault(rec.get("event"),
                                                    rec.get("tickets_root"))
    for did in sorted(roots):
        croot = roots[did].get("commit")
        droot = roots[did].get("draw")
        if isinstance(croot, str) and croot and isinstance(droot, str) and droot \
                and croot != droot:
            finds.append({"kind": "tickets-root-drift", "severity": "BLOCK",
                          "origin": did,
                          "detail": "tickets_root commit %s -> draw %s (token drift)" % (croot, droot)})
    for rec in records:
        if not rec or rec.get("event") not in ("commit", "draw"):
            continue
        tix = rec.get("tickets")
        root = rec.get("tickets_root")
        if isinstance(tix, list) and tix and isinstance(root, str) and root:
            calc = tickets_root(tix)
            if calc != root:
                finds.append({"kind": "tickets-root-mismatch", "severity": "BLOCK",
                              "origin": did_of(rec),
                              "detail": "tickets_root %s != recomputed chain %s" % (root, calc)})
    return finds


def payout_findings(records):
    """Payout sanity: no payout without a draw, no double payout."""
    finds = []
    drew, paid = set(), set()
    for rec in records:
        if not rec:
            continue
        did = did_of(rec)
        ev = rec.get("event")
        if ev == "draw":
            drew.add(did)
        elif ev == "payout":
            if did not in drew:
                finds.append({"kind": "payout-without-draw", "severity": "BLOCK",
                              "origin": did,
                              "detail": "payout ts=%s before/without any draw" % rec.get("ts")})
            if did in paid:
                finds.append({"kind": "double-payout", "severity": "BLOCK",
                              "origin": did,
                              "detail": "second payout recorded for the same draw"})
            paid.add(did)
    return finds


def audit(path):
    """Load the capture and run every check; returns the findings list."""
    records, bad = load_jsonl(path)
    finds = [{"kind": "malformed-line", "severity": "WARN",
              "origin": "line:%d" % ln,
              "detail": "line is not a JSON object; skipped"} for ln in bad]
    finds += commit_reveal_findings(records)
    finds += winner_findings(records)
    finds += root_findings(records)
    finds += payout_findings(records)
    return finds


def render(findings):
    """Print 'SEV kind origin: detail' per finding; return severity counts."""
    counts = {}
    for f in findings:
        sev = f.get("severity", "INFO")
        counts[sev] = counts.get(sev, 0) + 1
        print("%-5s %-26s %s: %s" % (sev, f.get("kind", "?"),
                                     f.get("origin", "?"), f.get("detail", "")))
    return counts


def main(argv=None):
    """CLI: path positional, --json optional. 0 clean / 1 findings / 2 IO."""
    ap = argparse.ArgumentParser(
        description="Audit lottery draw commit/reveal ordering, drand "
                    "winner determinism, root drift and payouts.")
    ap.add_argument("path", help="JSONL capture of draw lifecycle events")
    ap.add_argument("--json", action="store_true",
                    help="emit findings as a JSON array")
    args = ap.parse_args(argv)
    try:
        findings = audit(args.path)
    except OSError as exc:
        print("error: cannot read %s: %s" % (args.path, exc), file=sys.stderr)
        return 2
    if args.json:
        print(json.dumps(findings, sort_keys=True))
    else:
        render(findings)
    return 1 if findings else 0


def _rec(ts, draw, event, **kw):
    """Compact fixture record builder."""
    rec = dict(ts=ts, draw_id=draw, event=event)
    rec.update(kw)
    return rec


def _run_capture(recs, extra=None):
    """Write recs to a temp JSONL file, run main quietly -> (rc, stdout)."""
    with tempfile.NamedTemporaryFile("w", suffix=".jsonl", delete=False) as tf:
        for r in recs:
            tf.write((r if isinstance(r, str) else json.dumps(r)) + "\n")
        path = tf.name
    try:
        buf = io.StringIO()
        with redirect_stdout(buf):
            rc = main([path] + list(extra or []))
        return rc, buf.getvalue()
    finally:
        os.unlink(path)


def self_test():
    tix = ["t5", "t1", "t3", "t2", "t4"]
    sig = "b3f9c2a1d0e8feed"
    root = tickets_root(tix)
    win = derive_winner(sig, "draw-1", len(tix))
    # determinism + hash-chain root
    assert 0 <= win < len(tix)
    assert derive_winner(sig, "draw-1", len(tix)) == win
    assert tickets_root(list(reversed(tix))) == root  # sort makes it stable
    assert len(root) == 64
    clean = [
        _rec(100, "draw-1", "commit", tickets_root=root, tickets=list(tix),
             ticket_count=5, deadline=200, drand_round=77, drand_sig=sig),
        _rec(150, "draw-1", "reveal", drand_round=77, drand_sig=sig),
        _rec(300, "draw-1", "draw", tickets_root=root, tickets=list(tix),
             ticket_count=5, drand_round=77, drand_sig=sig, winner_idx=win),
        _rec(400, "draw-1", "payout", amount=250),
    ]
    # commit/reveal ordering family
    f = commit_reveal_findings([_rec(10, "d9", "reveal", drand_round=1)])
    assert f and f[0]["kind"] == "missing-commit" and f[0]["severity"] == "BLOCK"
    f = commit_reveal_findings([
        _rec(100, "d8", "commit", deadline=200, drand_round=5),
        _rec(100, "d8", "reveal", drand_round=5)])
    assert [x["kind"] for x in f] == ["commit-not-before-reveal"]
    f = commit_reveal_findings([
        _rec(100, "d7", "commit", deadline=200, drand_round=5),
        _rec(250, "d7", "reveal", drand_round=5)])
    assert [x["kind"] for x in f] == ["late-reveal"]
    f = commit_reveal_findings([
        _rec(10, "da", "reveal", drand_round=9),
        _rec(20, "db", "reveal", drand_round=9)])
    assert [x["kind"] for x in f if x["kind"] == "drand-round-reuse"]
    # winner determinism
    f = winner_findings([_rec(300, "draw-1", "draw", ticket_count=5,
                              drand_sig=sig, winner_idx=(win + 1) % 5)])
    assert f and f[0]["kind"] == "winner-mismatch" and f[0]["severity"] == "BLOCK"
    assert winner_findings([_rec(3, "z", "draw", ticket_count=5)])[0]["kind"] == "unauditable-draw"
    # root drift + recompute
    f = root_findings([
        _rec(100, "d5", "commit", tickets_root="aa" * 32),
        _rec(200, "d5", "draw", tickets_root="bb" * 32)])
    assert f and f[0]["kind"] == "tickets-root-drift"
    f = root_findings([_rec(200, "d4", "draw", tickets_root="cc" * 32,
                            tickets=list(tix))])
    assert f and f[0]["kind"] == "tickets-root-mismatch"
    # payouts
    assert payout_findings([_rec(10, "d3", "payout", amount=1)])[0]["kind"] \
        == "payout-without-draw"
    assert payout_findings([
        _rec(10, "d2", "draw"), _rec(20, "d2", "payout", amount=1),
        _rec(30, "d2", "payout", amount=1)])[0]["kind"] == "double-payout"
    # CLI rc paths
    rc, out = _run_capture(clean)
    assert rc == 0, out
    tampered = [dict(r) for r in clean]
    tampered[2] = dict(tampered[2], winner_idx=(win + 1) % 5)
    rc, out = _run_capture(tampered)
    assert rc == 1 and "winner-mismatch" in out
    rc, _ = _run_capture(["{not json"])
    assert rc == 1
    err = io.StringIO()
    with redirect_stderr(err):
        rc_missing = main(["/nonexistent/lotto-capture.jsonl"])
    assert rc_missing == 2
    print("self-test OK (determinism+root chain, commit/reveal order, "
          "deadline, drand reuse, winner, root drift/recompute, payouts, "
          "CLI rc=0/1/2)")


if __name__ == "__main__":
    if "--self-test" in sys.argv:
        self_test()  # falls through; rc 0 (probe hook runs after this)
    else:
        raise SystemExit(main())
