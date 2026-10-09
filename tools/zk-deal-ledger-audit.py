#!/usr/bin/env python3
"""zk-deal-ledger-audit — audit zk_audit paper-deal ledgers: offers, lock proposals, preimage hash terms, matching, settlement sequencing.

DEMAND: evidence/suggestions/tools-services/ (file citations below)
  - "Audit trails for zk_audit paper-trading workflows, including lock proposals, point-lock or preimage hash terms, and settlement sequence verification"
  - "Request for zk_audit deals/marketplace on paper"
  - "zk_audit deal discovery and matching"
  - "zk_audit marketplace discovery and verification"
  - "Resolve ambiguity around zk_audit offers from multiple anonymous or synthetic-seeming identities"
  Scope: a captured deal-ledger JSONL export (one record per line: {"ts",
    "deal_id","event" offer|lock|point_lock|preimage_commit|
    preimage_reveal|match|settle,"did","counter_did","terms":{price,qty,
    preimage_hash,lock_until},"preimage","shard"}). Checks offer linkage
    and match sides, preimage hash/order/expiry, point-lock hash reuse,
    synthetic clusters, anonymous offer dids, settlement order. Data
    only: JSON parsing, no network, no subprocess. rc 0/1/2. Stdlib only.
"""
import argparse
import collections
import hashlib
import json
import sys
from datetime import datetime, timezone

EVENTS = ("offer", "lock", "point_lock", "preimage_commit", "preimage_reveal", "match", "settle")
WASH_WINDOW_S = 300.0        # max pairwise ts delta inside an offer cluster


def parse_ts(v):
    """ISO-8601 string (trailing Z tolerated; naive read as UTC) or epoch
    number -> float seconds; None when unparseable."""
    if isinstance(v, (int, float)) and not isinstance(v, bool):
        return float(v)
    s = v.strip() if isinstance(v, str) else ""
    if not s:
        return None
    if s[-1] in "Zz":
        s = s[:-1] + "+00:00"
    try:
        dt = datetime.fromisoformat(s)
    except ValueError:
        return None
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.timestamp()


def load_jsonl(path):
    """Read a JSONL capture -> (records, bad_line_numbers)."""
    records, bad = [], []
    with open(path, "r", encoding="utf-8", errors="replace") as fh:
        for n, line in enumerate(fh, 1):
            line = line.strip()
            if not line:
                continue
            try:
                rec = json.loads(line)
            except ValueError:
                rec = None
            if isinstance(rec, dict):
                records.append(rec)
            else:
                bad.append(n)
    return records, bad


def _terms(rec):
    """rec["terms"] when it is a dict, else {} (terms may be absent)."""
    t = rec.get("terms")
    return t if isinstance(t, dict) else {}


def _f(sev, kind, origin, detail):
    """One finding in the shared family shape."""
    return {"severity": sev, "kind": kind, "origin": origin, "detail": detail}


def linkage_findings(records):
    """Lifecycle linkage: lock/point_lock/match/settle must reference a
    deal already opened by a prior offer (file order = 'prior'), and a
    match may only bind two sides that were both live offers."""
    out, offers = [], {}                # deal_id -> {did: offer ts}
    for rec in records:
        ev, deal, did = rec.get("event"), rec.get("deal_id"), rec.get("did")
        if ev == "offer":
            offers.setdefault(deal, {}).setdefault(did, rec.get("ts"))
        elif ev in ("lock", "point_lock", "match", "settle"):
            sides = offers.get(deal)
            if not sides:
                out.append(_f("BLOCK", "no-offer", deal,
                              "%s references deal %r with no prior offer"
                              % (ev, deal)))
            elif ev == "match":
                for side in (did, rec.get("counter_did")):
                    if side not in sides:
                        out.append(_f("BLOCK", "match-side-not-live-offer",
                                      deal, "match binds side %r which had no "
                                      "live offer on this deal" % (side,)))
    return out


def preimage_findings(records):
    """Hash-lock terms: sha256(preimage) must equal the committed
    preimage_hash; a reveal must postdate its preimage_commit (a reveal
    earlier than the commit was committed after the fact) and must not
    land after lock_until (expired lock accepted)."""
    out, commits = [], {}              # deal_id -> last prior commit state
    for rec in records:
        ev, deal, terms = rec.get("event"), rec.get("deal_id"), _terms(rec)
        if ev == "preimage_commit":
            commits[deal] = {"ts": parse_ts(rec.get("ts")), "raw": rec.get("ts"),
                             "hash": terms.get("preimage_hash"),
                             "until": parse_ts(terms.get("lock_until")),
                             "raw_until": terms.get("lock_until")}
            continue
        if ev != "preimage_reveal":
            continue
        rt, com = parse_ts(rec.get("ts")), commits.get(deal)
        committed = (com or {}).get("hash") or terms.get("preimage_hash")
        pre = rec.get("preimage")
        if not isinstance(pre, str) or not pre:
            out.append(_f("BLOCK", "reveal-without-preimage", deal,
                          "preimage_reveal carries no preimage to verify"))
        elif not isinstance(committed, str) or not committed.strip():
            out.append(_f("WARN", "reveal-without-commit", deal,
                          "no prior preimage_commit carries a "
                          "preimage_hash; hash-lock unverifiable"))
        elif hashlib.sha256(pre.encode("utf-8")).hexdigest() != \
                committed.strip().lower():
            out.append(_f("BLOCK", "preimage-mismatch", deal,
                          "sha256(preimage) != committed preimage_hash %s"
                          % committed))
        if com is not None and rt is not None and com["ts"] is not None \
                and rt < com["ts"]:
            out.append(_f("BLOCK", "reveal-before-commit", deal,
                          "reveal at %r precedes its preimage_commit at %r"
                          % (rec.get("ts"), com["raw"])))
        until = (com or {}).get("until") or parse_ts(terms.get("lock_until"))
        if rt is not None and until is not None and rt > until:
            out.append(_f("WARN", "expired-lock-accepted", deal,
                          "reveal at %r lands after lock_until %r — expired "
                          "lock accepted" % (rec.get("ts"),
                                             (com or {}).get("raw_until"))))
    return out


def lock_findings(records):
    """Point-lock reuse: one terms.preimage_hash locking >= 2 distinct
    deals is a hash-lock replay family — the same secret re-locking
    different paper deals; every deal after the first is suspect."""
    out, deals_by_hash = [], {}
    for rec in records:
        if rec.get("event") in ("lock", "point_lock"):
            h = _terms(rec).get("preimage_hash")
            if isinstance(h, str) and h.strip():
                deals_by_hash.setdefault(h, set()).add(rec.get("deal_id"))
    for h, deals in deals_by_hash.items():
        names = sorted(str(d) for d in deals if d is not None)
        if len(names) >= 2:
            out.append(_f("WARN", "point-lock-reuse", h[:16],
                          "preimage_hash re-locks %d distinct deals: %s"
                          % (len(names), ", ".join(names))))
    return out


def wash_findings(records):
    """Synthetic-identity ambiguity: >= 3 offers with identical terms from
    different dids whose pairwise ts deltas all stay under WASH_WINDOW_S;
    plus offer dids seen exactly once in the capture and only in offers."""
    out, groups, seen = [], {}, collections.Counter()
    for rec in records:
        seen.update(d for d in (rec.get("did"), rec.get("counter_did"))
                    if isinstance(d, str) and d)
        if rec.get("event") == "offer":
            key = json.dumps(_terms(rec), sort_keys=True, ensure_ascii=False)
            groups.setdefault(key, []).append((parse_ts(rec.get("ts")),
                                               rec.get("did")))
    for items in groups.values():
        dids = {d for _, d in items}
        stamps = [t for t, _ in items if t is not None]
        if len(dids) >= 3 and stamps and \
                max(stamps) - min(stamps) < WASH_WINDOW_S:
            out.append(_f("WARN", "synthetic-offer-cluster",
                          ",".join(sorted(str(d) for d in dids))[:40],
                          "%d identical-term offers from %d dids inside %gs "
                          "(synthetic-identity ambiguity)"
                          % (len(items), len(dids), WASH_WINDOW_S)))
    for rec in records:
        did = rec.get("did")
        if rec.get("event") == "offer" and isinstance(did, str) \
                and seen[did] == 1:
            out.append(_f("INFO", "anonymous-offer-did", did,
                          "did appears exactly once in the capture and only "
                          "in offers (anonymous identity)"))
    return out


def settle_findings(records):
    """Settlement sequence: every settle needs a prior match, one settle
    per deal, and settle timestamps must not go backwards."""
    out, matched, settled = [], set(), set()
    last_ts, last_deal = None, None
    for rec in records:
        ev, deal = rec.get("event"), rec.get("deal_id")
        if ev == "match":
            matched.add(deal)
        elif ev == "settle":
            if deal not in matched:
                out.append(_f("BLOCK", "settle-without-match", deal,
                              "settle on deal %r with no prior match" % (deal,)))
            if deal in settled:
                out.append(_f("BLOCK", "double-settle", deal,
                              "deal %r settled more than once" % (deal,)))
            settled.add(deal)
            t = parse_ts(rec.get("ts"))
            if t is not None and last_ts is not None and t < last_ts:
                out.append(_f("WARN", "settle-out-of-order", deal,
                              "settle ts %r goes backwards after deal %r"
                              % (rec.get("ts"), last_deal)))
            if t is not None:
                last_ts, last_deal = t, deal
    return out


def audit(path):
    """Load the capture and concatenate every check's findings."""
    records, bad = load_jsonl(path)
    findings = [_f("WARN", "malformed-line", "line:%d" % n,
                   "line is not a JSON object; record skipped") for n in bad]
    for rec in records:
        if rec.get("event") not in EVENTS:
            findings.append(_f("WARN", "unknown-event", rec.get("deal_id"),
                               "event %r is not a known ledger event"
                               % (rec.get("event"),)))
    for check in (linkage_findings, preimage_findings, lock_findings,
                  wash_findings, settle_findings):
        findings.extend(check(records))
    return findings


def render(findings):
    """Print one human line per finding; return severity counts."""
    counts = {}
    for x in findings:
        sev = x.get("severity", "WARN")
        counts[sev] = counts.get(sev, 0) + 1
        print("%-5s %-25s %s: %s" % (sev, x["kind"], x.get("origin"), x["detail"]))
    return counts


def main(argv=None):
    """CLI: one capture path; --json emits machine-readable findings."""
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("file", help="captured zk_audit paper-deal ledger JSONL")
    ap.add_argument("--json", action="store_true", help="JSON findings output")
    args = ap.parse_args(argv)
    try:
        findings = audit(args.file)
    except OSError as e:
        print("cannot read %s: %s" % (args.file, e), file=sys.stderr)
        return 2
    if args.json:
        print(json.dumps({"findings": findings}, ensure_ascii=False))
    else:
        counts = render(findings)
        print("%d finding(s): %s" % (len(findings), ", ".join(
            "%s=%d" % kv for kv in sorted(counts.items())) or "clean"))
    return 1 if findings else 0


def self_test():
    import io
    import os
    import tempfile
    from contextlib import redirect_stderr, redirect_stdout

    def ts(m): return "2026-09-30T10:%02d:00Z" % m

    pre = "paper-preimage-1"
    good_hash = hashlib.sha256(pre.encode("utf-8")).hexdigest()

    def terms():
        return {"price": 10, "qty": 2, "preimage_hash": good_hash,
                "lock_until": ts(59)}

    def off(deal, did, cdid, m):
        return {"ts": ts(m), "deal_id": deal, "event": "offer", "did": did,
                "counter_did": cdid, "terms": terms()}

    def ev(deal, event, m, did="did:a", cdid="did:b", **extra):
        rec = {"ts": ts(m), "deal_id": deal, "event": event, "did": did,
               "counter_did": cdid}
        rec.update(extra)
        return rec

    def kinds(f): return [x["kind"] for x in f]

    paths = []

    def capture(recs, raw=""):
        fh = tempfile.NamedTemporaryFile("w", suffix=".jsonl", delete=False,
                                         encoding="utf-8")
        fh.write("".join(json.dumps(r) + "\n" for r in recs) + raw)
        fh.close()
        paths.append(fh.name)
        return fh.name

    try:
        # linkage: happy path, no-offer, match side never a live offer
        head = [off("D1", "did:a", "did:b", 0), off("D1", "did:b", "did:a", 1)]
        clean = head + [ev("D1", "preimage_commit", 2, terms=terms()),
                        ev("D1", "preimage_reveal", 3, preimage=pre),
                        ev("D1", "match", 4), ev("D1", "settle", 5)]
        assert audit(capture(clean)) == []
        assert linkage_findings([ev("D9", "lock", 0)])[0]["kind"] == "no-offer"
        f = linkage_findings([off("D2", "did:a", "did:z", 1),
                              ev("D2", "match", 2, did="did:a", cdid="did:z")])
        assert kinds(f) == ["match-side-not-live-offer"]
        assert all(x["severity"] == "BLOCK" for x in f)
        # preimage: mismatch, expiry past lock_until, committed after reveal
        bad_pre = [dict(r, preimage="wrong") if r["event"] == "preimage_reveal"
                   else r for r in clean]
        f = preimage_findings(bad_pre)
        assert kinds(f) == ["preimage-mismatch"] and f[0]["severity"] == "BLOCK"
        past = "2026-09-30T11:00:00Z"       # one minute past lock_until
        late = [dict(r, ts=past) if r["event"] == "preimage_reveal" else r
                for r in clean]
        assert kinds(preimage_findings(late)) == ["expired-lock-accepted"]
        swapped = head + [ev("D1", "preimage_commit", 5, terms=terms()),
                          ev("D1", "preimage_reveal", 2, preimage=pre)]
        f = preimage_findings(swapped)
        assert kinds(f) == ["reveal-before-commit"] and f[0]["severity"] == "BLOCK"
        # point-lock reuse across two distinct deals
        reuse = [off("D3", "did:a", "did:b", 0), off("D4", "did:a", "did:b", 2),
                 ev("D3", "point_lock", 1, terms=terms()),
                 ev("D4", "point_lock", 3, terms=terms())]
        f = lock_findings(reuse)
        assert kinds(f) == ["point-lock-reuse"] and f[0]["severity"] == "WARN"
        assert "D3" in f[0]["detail"] and "D4" in f[0]["detail"]
        # wash cluster + anonymous one-shot dids
        wash = [off("W%d" % i, "did:w%d" % i, None, 10 + i) for i in (1, 2, 3)]
        f = wash_findings(wash)
        assert "synthetic-offer-cluster" in kinds(f)
        assert kinds(f).count("anonymous-offer-did") == 3
        slow = [off("W%d" % i, "did:v%d" % i, None, 10 + 6 * i) for i in (1, 2, 3)]
        assert "synthetic-offer-cluster" not in kinds(wash_findings(slow))
        # settle: without match, doubled, out of ts order
        assert settle_findings([off("D7", "did:a", "did:b", 0),
                                ev("D7", "settle", 1)])[0]["kind"] == \
            "settle-without-match"
        ds = [off("D8", "did:a", "did:b", 0), ev("D8", "match", 1),
              ev("D8", "settle", 2), ev("D8", "settle", 3)]
        assert "double-settle" in kinds(settle_findings(ds))
        oo = [off("A1", "did:a", "did:b", 0), ev("A1", "match", 1),
              ev("A1", "settle", 30), off("A2", "did:a", "did:b", 0),
              ev("A2", "match", 1), ev("A2", "settle", 20)]
        assert kinds(settle_findings(oo)) == ["settle-out-of-order"]
        assert kinds(audit(capture([], raw="not-json\n"))) == ["malformed-line"]
        # CLI rc contract: 0 clean, 1 findings, 2 unreadable path
        p_clean, p_dirty = capture(clean), capture(bad_pre)
        with redirect_stdout(io.StringIO()), redirect_stderr(io.StringIO()):
            rc = (main([p_clean]), main([p_dirty]), main(["/no/such/cap.jsonl"]))
        assert rc == (0, 1, 2), rc
        with redirect_stdout(io.StringIO()):
            assert main([p_dirty, "--json"]) == 1
    finally:
        for p in paths:
            if os.path.exists(p):
                os.unlink(p)
    print("self-test OK (linkage, preimage hash/order/expiry, point-lock "
          "reuse, wash + anonymous dids, settle sequence, malformed, CLI rc)")


if __name__ == "__main__":
    if "--self-test" in sys.argv:
        self_test()  # falls through; rc 0 (probe hook runs after this)
    else:
        raise SystemExit(main())
