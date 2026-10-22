#!/usr/bin/env python3
"""refund-path-audit — coverage audit of an archived HTLC refund-path
log (JSONL: window_set/window_change/refund/segment records): flags
unattested refund-window reductions (the "publishers plan to slash the
refund window during the audit" move), refunds that fall outside the
archived coverage segments, unsigned refund records, and refunds for
deals that never declared a window. Deterministic; log lines are data
only, nothing is executed.

DEMAND: evidence/suggestions/tools-services/2026-10-16.md
  - request (runs): "audit coverage of archived refund-path logs —
    evidence: 'The refund path has…'" — proposed service: hermes-tools
    refund-path log coverage audit.
  - request: "Audit-tooling background checks on HTLC refund windows,
    Ethereum key rotations …" — proposed service: refund-window
    background checks.
  Also 2026-10-17.md (05:57 run): "Publishers plan to slash the refund
    window during the audit." / "refund-window audit timelines and
    hash-lock rehearsal tooling".
  This tool serves those asks offline: input is the refund-path log
  export, output is named findings (rule id, ref, detail) per deal
  plus a verdict. Stdlib only."""
import argparse
import hashlib
import json
import sys

SEVS = ("BLOCK", "WARN", "INFO")
ACTIONS = ("window_set", "window_change", "refund",
           "segment_start", "segment_end")


def parse_log(path):
    """file -> [record dicts]; first bad line raises ValueError."""
    recs = []
    with open(path, encoding="utf-8") as fh:
        for lineno, line in enumerate(fh, 1):
            line = line.strip()
            if not line:
                continue
            try:
                rec = json.loads(line)
            except ValueError as exc:
                raise ValueError("line {}: not JSON: {}".format(lineno, exc))
            if not isinstance(rec, dict) or rec.get("action") not in ACTIONS:
                raise ValueError("line {}: 'action' must be one of {}"
                                 .format(lineno, "/".join(ACTIONS)))
            recs.append(rec)
    return recs


def coverage(recs):
    """records -> sorted [interval] list from segment markers."""
    spans = []
    start = None
    for rec in recs:
        if rec["action"] == "segment_start" and \
                isinstance(rec.get("ts"), (int, float)):
            if start is not None:
                spans.append((start, None))  # unterminated: open-ended
            start = rec["ts"]
        elif rec["action"] == "segment_end" and \
                isinstance(rec.get("ts"), (int, float)):
            if start is not None:
                spans.append((start, rec["ts"]))
                start = None
            else:
                spans.append((rec["ts"], rec["ts"]))  # stray end marker
    if start is not None:
        spans.append((start, None))
    return sorted(spans, key=lambda s: (s[0], s[1] is not None,
                                        s[1] or 0))


def in_coverage(ts, spans):
    """ts -> True if inside any archived segment."""
    return any(lo <= ts and (hi is None or ts <= hi) for lo, hi in spans)


def audit(recs):
    """records -> (findings, deals); findings are (rule, ref, detail)."""
    finds = []
    deals = {}
    spans = [s for s in coverage(recs)]
    have_segments = any(rec["action"].startswith("segment")
                        for rec in recs)
    for rec in recs:
        act, ref = rec["action"], str(rec.get("ref", "-"))
        ts = rec.get("ts")
        if act in ("window_set", "window_change"):
            d = deals.setdefault(ref, {"windows": [], "refunds": 0})
            hours = rec.get("window_hours")
            if not isinstance(hours, (int, float)) or hours <= 0:
                finds.append(("window-bad-hours", ref,
                              "{} claims window_hours {}".format(
                                  act, hours)))
                continue
            prev = d["windows"][-1] if d["windows"] else None
            d["windows"].append(hours)
            if act == "window_change":
                if prev is not None and hours < prev and \
                        rec.get("attested") is not True:
                    finds.append(("window-slash", ref,
                                  "refund window cut {}h -> {}h without "
                                  "an attestation".format(prev, hours)))
                if prev is None:
                    finds.append(("window-orphan-change", ref,
                                  "window_change with no prior "
                                  "window_set"))
        elif act == "refund":
            d = deals.setdefault(ref, {"windows": [], "refunds": 0})
            d["refunds"] += 1
            if not d["windows"]:
                finds.append(("refund-no-window", ref,
                              "refund for a deal with no declared "
                              "window"))
            if rec.get("signed") is not True:
                finds.append(("refund-unsigned", ref,
                              "refund record is not signed"))
            if have_segments and isinstance(ts, (int, float)) and \
                    not in_coverage(ts, spans):
                finds.append(("refund-outside-archive", ref,
                              "refund ts {} outside archived refund-path "
                              "segments".format(ts)))
    for ref, d in sorted(deals.items()):
        if d["windows"] and d["refunds"] == 0:
            finds.append(("refund-missing", ref,
                          "window declared but no refund record "
                          "archived"))
    return finds, deals


def verdict(findings):
    """findings -> FAIL on hard rules, AT-RISK on any finding, else CLEAN."""
    hard = {"window-slash", "refund-outside-archive", "window-bad-hours"}
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
        description="audit an archived refund-path log for window "
                    "slashing and coverage gaps")
    ap.add_argument("log", help="JSONL refund-path log export")
    ap.add_argument("--json", action="store_true",
                    help="machine-readable report")
    args = ap.parse_args(argv)
    try:
        recs = parse_log(args.log)
    except OSError:
        print("refund-path-audit: cannot read {}".format(args.log),
              file=sys.stderr)
        return 2
    except ValueError as exc:
        print("refund-path-audit: {}".format(exc), file=sys.stderr)
        return 2
    finds, deals = audit(recs)
    digest = findings_digest(finds)
    if args.json:
        print(json.dumps({"tool": "refund-path-audit",
                          "verdict": verdict(finds), "digest": digest,
                          "deals": deals,
                          "findings": [{"rule": r, "ref": i, "detail": d}
                                       for r, i, d in finds]},
                         ensure_ascii=False))
        return 1 if finds else 0
    print("refund-path-audit: {} ({} deal(s), digest {})".format(
        verdict(finds), len(deals), digest))
    for r, i, d in finds:
        print("  [{}] {} {}: {}".format(
            SEVS[0] if r in ("window-slash", "refund-outside-archive",
                             "window-bad-hours") else SEVS[1], r, i, d))
    return 1 if finds else 0


def self_test():
    import io
    import os
    import tempfile
    from contextlib import redirect_stdout

    def rec(**kw):
        return json.dumps(kw)

    def find(lines):
        return audit([json.loads(x) for x in lines])

    # 1. healthy path: covered segment, attested window, signed refund
    good = [rec(action="segment_start", ts=100),
            rec(action="window_set", ref="d1", ts=110, window_hours=72,
                attested=True),
            rec(action="refund", ref="d1", ts=150, signed=True),
            rec(action="segment_end", ts=200)]
    finds, deals = find(good)
    assert finds == [] and verdict(finds) == "CLEAN", finds
    assert deals["d1"]["windows"] == [72] and deals["d1"]["refunds"] == 1

    # 2. filed slash: unattested 72h -> 24h cut FAILs; attested cut is ok
    slash = [rec(action="window_set", ref="d2", ts=10, window_hours=72),
             rec(action="window_change", ref="d2", ts=20, window_hours=24),
             rec(action="refund", ref="d2", ts=30, signed=True)]
    finds, _ = find(slash)
    assert [r for r, _, _ in finds] == ["window-slash"], finds
    assert "72h -> 24h" in finds[0][2] and verdict(finds) == "FAIL"
    ok_cut = [rec(action="window_set", ref="d3", ts=10, window_hours=72),
              rec(action="window_change", ref="d3", ts=20, window_hours=48,
                  attested=True),
              rec(action="refund", ref="d3", ts=30, signed=True)]
    assert find(ok_cut)[0] == [], find(ok_cut)

    # 3. coverage: refund outside archived segments FAILs; open segment
    #    keeps later refunds covered
    gapped = [rec(action="segment_start", ts=100),
              rec(action="segment_end", ts=150),
              rec(action="window_set", ref="d4", ts=10, window_hours=72),
              rec(action="refund", ref="d4", ts=180, signed=True),
              rec(action="segment_start", ts=200),
              rec(action="refund", ref="d4", ts=210, signed=True)]
    finds, _ = find(gapped)
    outside = [f for f in finds if f[0] == "refund-outside-archive"]
    assert outside and outside[0][1] == "d4" and "180" in outside[0][2]
    assert len([f for f in finds if f[0] == "refund-outside-archive"]) == 1
    assert verdict(finds) == "FAIL"
    noseg = [rec(action="window_set", ref="d5", ts=10, window_hours=72),
             rec(action="refund", ref="d5", ts=999, signed=True)]
    assert find(noseg)[0] == [], find(noseg)  # no segments -> full cover

    # 4. unsigned refund, missing window, orphan change, bad hours
    messy = [rec(action="window_change", ref="d6", ts=5, window_hours=10),
             rec(action="refund", ref="d7", ts=15),
             rec(action="window_set", ref="d8", ts=20, window_hours=0)]
    finds, _ = find(messy)
    rules = {r for r, _, _ in finds}
    assert rules == {"window-orphan-change", "refund-no-window",
                     "refund-unsigned", "window-bad-hours",
                     "refund-missing"}, rules

    # 5. end-to-end CLI: rc, verdict, digest determinism, malformed rc 2
    with tempfile.TemporaryDirectory() as d:
        p = os.path.join(d, "refund.jsonl")
        with open(p, "w") as fh:
            fh.write("\n".join(slash) + "\n")
        buf = io.StringIO()
        with redirect_stdout(buf):
            rc = main([p, "--json"])
        doc = json.loads(buf.getvalue())
        assert rc == 1 and doc["verdict"] == "FAIL", doc
        buf = io.StringIO()
        with redirect_stdout(buf):
            main([p, "--json"])
        assert json.loads(buf.getvalue())["digest"] == doc["digest"]
        buf = io.StringIO()
        with redirect_stdout(buf):
            rc = main([p])
        assert rc == 1 and "window-slash" in buf.getvalue()
        bad = os.path.join(d, "bad.jsonl")
        with open(bad, "w") as fh:
            fh.write('{"action": "payout"}\n')
        buf = io.StringIO()
        with redirect_stdout(buf):
            rc = main([bad])
        assert rc == 2, rc

    print("refund-path-audit self-test OK (5 groups: healthy covered "
          "path is CLEAN, unattested 72h->24h slash FAILs while "
          "attested cuts pass, refund outside archived segments FAILs "
          "and open segments still cover, unsigned/no-window/orphan/"
          "bad-hours bookkeeping, end-to-end CLI with deterministic "
          "digest and rc 2 on malformed log)")


if __name__ == "__main__":
    if "--self-test" in sys.argv:
        self_test()  # falls through; rc 0 (probe hook runs after this)
    else:
        raise SystemExit(main(sys.argv[1:]))
