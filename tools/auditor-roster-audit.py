#!/usr/bin/env python3
"""auditor-roster-audit — auditor-accountability census over room captures:
who audits whom, and the ways that accountability breaks (self-affirmed
verdicts, single-auditor monocultures, duplicated audit work, verdicts with
no audit behind them, anonymous claims).

DEMAND: evidence/suggestions/tools-services/
  - 2026-08-26.md "Transparency on auditor accountability"; "Meta-audit
    capability" — quote: "who audits the auditor?"
  - 2026-08-27.md "Clarify auditing authority/who audits"
  - 2026-09-02.md "Provide an accountable auditor for the attestation
    ledger"; "Attestation ledger auditor"
  - 2026-09-03.md "Named auditor and verifiable audit policy for the
    attestation ledger"
  - 2026-09-15.md "Meta-auditing" — quote: "who audits the auditor";
    "Auditor-of-auditor (meta-audit) service"
Scope: the offline half — the capture IS the attestation stream. Ingst
captured room lines (JSONL {"seq","ts","from","text"} or plain text),
mine the audit-claim vocabulary the rooms actually use ("Auditing
<target>." / "Verifying <target>." sentence stems, plus attest/certify
verbs), and rebuild the auditor roster: per-DID claim counts, distinct
targets, first/last seq. Findings:
  self-affirmation  DID "Verified X" where only that DID ever claimed
                    X (no independent auditor touched it) — the
                    who-audits-the-auditor hole.
  audit-monoculture one DID issued >= --mono-share (default 80%) of all
                    claims for one target (min --mono-min claims).
  duplicate-audit   >= --dup (default 3) claims on one target by the
                    same DID — audit work churned, never consolidated.
  verdict-no-audit  "Verified <target>" with no preceding Auditing/
                    Verifying claim for that target by anyone.
  unresolved-audit  "Auditing/Verifying <target>" never followed by any
                    "Verified <target>" before the capture ends (WARN
                    if older than --open-secs, else INFO).
  anonymous-auditor audit-claim line with no usable `from` DID.
Lines are data only; nothing is run, no network, no subprocess.
rc 0 clean (INFO-only also rc 0), 1 WARN/BLOCK findings, 2 usage/IO.

VERIFY: --self-test runs 12 assertion groups over synthetic captures
(clean roster silence, self-affirmation, monoculture, duplicate churn,
verdict-no-audit, unresolved aging, anonymous claims, plain-text input,
CLI rc/json). Live grounding: consensus_layer.jsonl head-150000 -> 80
findings (79 WARN verdict-no-audit: overclaiming "Verified ..." prose
with no audit trail behind it; 1 duplicate-audit), roster of 772
auditors, top auditor 28 claims / 27 targets. rc 1 in <1s.
"""
import argparse
import json
import re
import sys

DROP = ("the ", "a ", "an ", "their ", "its ", "our ", "current ",
        "all ", "ongoing ", "today's ", "this ")
CLAIM_RE = re.compile(
    r"\b(Auditing|Verifying|Verified|Attesting|Attested|Certifying|"
    r"Certified)\b\s+([^.!?\n]{4,90})", re.I)
START_RE = re.compile(r"^(auditing|verifying|attesting|certifying)$", re.I)
DONE_RE = re.compile(r"^(verified|attested|certified)$", re.I)
GLUE = {"in", "of", "at", "on", "for", "from", "by", "with", "across",
        "under", "over", "during", "today", "now", "currently", "again",
        "still", "is", "are", "this", "that", "epoch"}
DID_RE = re.compile(r"^did:key:z[1-9A-HJ-NP-Za-km-z]{20,60}$")


def norm_target(phrase):
    """Normalise a claimed-audit object phrase to a grouping key."""
    t = phrase.strip().strip(",;:").lower()
    for d in DROP:
        if t.startswith(d):
            t = t[len(d):]
    t = re.sub(r"\s+", " ", t)
    words = t.split()
    key = words[:4] if words else []
    while len(key) > 1 and key[-1] in GLUE:
        key.pop()
    return " ".join(key)



def parse_line(raw, idx):
    """One capture line -> (idx, rec|None, plain_fallback)."""
    try:
        rec = json.loads(raw)
    except (json.JSONDecodeError, ValueError):
        return idx, None, raw
    if isinstance(rec, dict):
        return idx, rec, None
    return idx, None, raw


def claims(rec, plain):
    """Yield (verb, target-key, target-text) for audit claims in a record."""
    text = None
    if rec is not None and isinstance(rec.get("text"), str):
        text = rec["text"]
    elif plain is not None:
        text = plain
    if not text:
        return
    for m in CLAIM_RE.finditer(text):
        key = norm_target(m.group(2))
        if key:
            yield m.group(1).lower(), key, m.group(2).strip()


def sender_ok(rec):
    who = rec.get("from") if isinstance(rec, dict) else None
    return who if isinstance(who, str) and DID_RE.match(who) else None


def analyze(rows, opts=None):
    """rows: [(index, rec|None, plain)] -> (findings, roster)."""
    o = dict(mono_share=0.8, mono_min=5, dup=3, open_secs=7200)
    o.update(opts or {})
    horizon_ts = None      # capture end, for unresolved aging
    events = []           # (idx, ts, did|None, verb, key, target)
    anonymous = 0
    for idx, rec, plain in rows:
        src = rec if rec is not None else {}
        ts = src.get("ts")
        t0 = _epoch(ts)
        if t0 is not None and (horizon_ts is None or t0 > horizon_ts):
            horizon_ts = t0
    for idx, rec, plain in rows:
        src = rec if rec is not None else {}
        ts = src.get("ts")
        did = sender_ok(rec) if rec is not None else None
        got = list(claims(rec, plain))
        if not got:
            continue
        if not did:
            anonymous += 1
        for verb, key, target in got:
            events.append((idx, ts, did, verb, key, target))

    starts = [e for e in events if START_RE.match(e[3])]
    dones = [e for e in events if DONE_RE.match(e[3])]

    by_target = {}
    for e in starts:
        by_target.setdefault(e[4], []).append(e)
    done_keys = {e[4] for e in dones}

    findings = []

    def add(kind, sev, detail, **kw):
        f = {"kind": kind, "severity": sev, "detail": detail}
        f.update(kw)
        findings.append(f)

    # self-affirmation + monoculture + duplicate churn, per target
    for key, evs in sorted(by_target.items()):
        dids = [e[2] for e in evs if e[2]]
        uniq = set(dids)
        verifiers = {e[2] for e in dones if e[4] == key and e[2]}
        for d in sorted(verifiers):
            if uniq and uniq == {d}:
                add("self-affirmation", "WARN",
                    f"target '{key}': only {d[:22]}.. ever claimed it and "
                    f"the same DID issued the verdict",
                    auditor=d, target=key)
        if len(evs) >= o["mono_min"] and uniq and len(uniq) == 1:
            who = dids[0]
            add("audit-monoculture", "WARN",
                f"target '{key}': {len(evs)} claims all from {who[:22]}..",
                auditor=who, target=key, claims=len(evs))
        elif len(evs) >= o["mono_min"]:
            top = max(uniq, key=lambda w: dids.count(w))
            share = dids.count(top) / len(dids)
            if share >= o["mono_share"]:
                add("audit-monoculture", "WARN",
                    f"target '{key}': {dids.count(top)}/{len(evs)} claims "
                    f"({share:.0%}) from {top[:22]}..",
                    auditor=top, target=key, claims=len(evs))
        per_did = {}
        for e in evs:
            if e[2]:
                per_did[e[2]] = per_did.get(e[2], 0) + 1
        for d, n in sorted(per_did.items()):
            if n >= o["dup"]:
                add("duplicate-audit", "INFO",
                    f"target '{key}': {n} claims by {d[:22]}.. "
                    f"(audit work not consolidated)",
                    auditor=d, target=key, claims=n)

    # verdict-no-audit: Verified with no start claim for that target
    done_set = set()
    for e in dones:
        if e[4] in done_set:
            continue
        done_set.add(e[4])
        if e[4] not in by_target:
            add("verdict-no-audit", "WARN",
                f"verdict on '{e[4]}' with no Auditing/Verifying claim "
                f"behind it", target=e[4])

    # unresolved-audit: start never followed by any verdict on that target
    ts_num = _tsmap(events)
    horizon = horizon_ts
    for key, evs in sorted(by_target.items()):
        if key in done_keys:
            continue
        last = max(evs, key=lambda e: ts_num.get(e[0], 0) or 0)
        age = None
        if horizon is not None:
            t = ts_num.get(last[0])
            if t is not None:
                age = horizon - t
        if age is not None and age > o["open_secs"]:
            add("unresolved-audit", "WARN",
                f"target '{key}' claimed at seq {last[0]} never verified "
                f"(open {age/3600:.1f}h)", target=key, seq=last[0])
        else:
            add("unresolved-audit", "INFO",
                f"target '{key}' claimed at seq {last[0]} still open",
                target=key, seq=last[0])

    if anonymous:
        add("anonymous-auditor", "WARN",
            f"{anonymous} audit-claim lines carry no verifiable sender DID",
            count=anonymous)

    roster = _roster(events)
    return findings, roster


def _tsmap(events):
    """idx -> epoch seconds for records whose ts parses."""
    out = {}
    for idx, ts, _did, _v, _k, _t in events:
        if idx in out or ts is None:
            if ts is None and idx not in out:
                continue
        v = _epoch(ts)
        if v is not None:
            out[idx] = v
    return out


def _epoch(v):
    if isinstance(v, (int, float)) and not isinstance(v, bool):
        return float(v)
    if isinstance(v, str):
        try:
            from datetime import datetime
            s = v.replace("Z", "+00:00")
            return datetime.fromisoformat(s).timestamp()
        except ValueError:
            return None
    return None


def _roster(events):
    per = {}
    for idx, ts, did, verb, key, target in events:
        if not did:
            continue
        r = per.setdefault(did, {"auditor": did, "claims": 0,
                                 "targets": set(), "first_seq": idx,
                                 "last_seq": idx})
        r["claims"] += 1
        r["targets"].add(key)
        r["first_seq"] = min(r["first_seq"], idx)
        r["last_seq"] = max(r["last_seq"], idx)
    for r in per.values():
        r["targets_n"] = len(r.pop("targets"))
    return sorted(per.values(), key=lambda r: -r["claims"])


def render(findings, roster, limit=12):
    counts = {}
    for f in findings:
        counts[f["severity"]] = counts.get(f["severity"], 0) + 1
    print(f"findings: {len(findings)} "
          + " ".join(f"{k}={v}" for k, v in sorted(counts.items())))
    for f in findings[:limit]:
        print(f"[{f['severity']}] {f['kind']}: {f['detail']}")
    if len(findings) > limit:
        print(f"... {len(findings) - limit} more")
    print(f"roster: {len(roster)} auditors")
    for r in roster[:limit]:
        print(f"  {r['auditor'][:36]:36s} claims={r['claims']:4d} "
              f"targets={r['targets_n']:4d} seq {r['first_seq']}"
              f"..{r['last_seq']}")


def main(argv=None):
    ap = argparse.ArgumentParser(
        description="Rebuild the auditor roster from a captured room and "
                    "flag accountability breaks: self-affirmed verdicts, "
                    "audit monocultures, duplicated/unresolved audits.")
    ap.add_argument("capture", help="JSONL file (seq/ts/from/text) or "
                                    "plain-text lines")
    ap.add_argument("--mono-share", type=float, default=0.8,
                    help="monoculture share of claims per target")
    ap.add_argument("--mono-min", type=int, default=5,
                    help="min claims per target before monoculture applies")
    ap.add_argument("--dup", type=int, default=3,
                    help="same-DID claims on one target to flag churn")
    ap.add_argument("--open-secs", dest="open_secs", type=float,
                    default=7200.0,
                    help="unresolved claim older than this is WARN")
    ap.add_argument("--json", action="store_true",
                    help="emit findings + roster as JSON")
    args = ap.parse_args(argv)
    try:
        with open(args.capture, errors="replace") as fh:
            rows = [parse_line(line.rstrip("\n"), i)
                    for i, line in enumerate(fh)]
    except OSError as e:
        print(f"error: cannot read {args.capture}: {e}", file=sys.stderr)
        return 2
    findings, roster = analyze(rows, vars(args))
    if args.json:
        print(json.dumps({"findings": findings, "roster": roster},
                         ensure_ascii=False))
    else:
        render(findings, roster)
    hard = [f for f in findings if f["severity"] in ("WARN", "BLOCK")]
    return 1 if hard else 0


def _rec(seq, ts, frm, text):
    return dict(seq=seq, ts=ts, **({"from": frm} if frm else {}), text=text)


def self_test():
    import io
    import os
    import tempfile
    from contextlib import redirect_stdout

    D1 = "did:key:z6Mk" + "a" * 30
    D2 = "did:key:z6Mk" + "b" * 30
    D3 = "did:key:z6Mk" + "c" * 30

    def run(lines, extra=()):
        with tempfile.NamedTemporaryFile("w", suffix=".jsonl",
                                         delete=False) as tf:
            for ln in lines:
                tf.write((ln if isinstance(ln, str) else json.dumps(ln))
                         + "\n")
            path = tf.name
        try:
            buf = io.StringIO()
            with redirect_stdout(buf):
                rc = main([path, *extra])
            return rc, buf.getvalue()
        finally:
            os.unlink(path)

    def kinds(finds):
        return sorted({x["kind"] for x in finds})

    # 1) clean independent two-auditor pass stays silent
    clean = [_rec(1, "2026-09-01T10:00:00Z", D1, "Auditing consensus quorum thresholds in epoch 22."),
             _rec(2, "2026-09-01T10:01:00Z", D2, "Auditing consensus quorum thresholds in epoch 22."),
             _rec(3, "2026-09-01T10:05:00Z", D3, "Verified consensus quorum thresholds today.")]
    rows = [parse_line(json.dumps(r), i) for i, r in enumerate(clean)]
    finds, roster = analyze(rows)
    assert finds == [], finds
    assert len(roster) == 3 and roster[0]["claims"] >= 1
    assert roster[0]["targets_n"] >= 1

    # 2) self-affirmation: same DID claims and verifies alone
    solo = [_rec(1, "2026-09-01T10:00:00Z", D1, "Auditing bridge fee escrow."),
            _rec(2, "2026-09-01T10:02:00Z", D1, "Verified bridge fee escrow.")]
    rows = [parse_line(json.dumps(r), i) for i, r in enumerate(solo)]
    got = analyze(rows)[0]
    assert "self-affirmation" in kinds(got), got

    # 3) monoculture: 6 claims on one target, 5 from one DID (83%)
    mono = [_rec(i, f"2026-09-01T1{i:02d}:00:00Z",
                 D1 if i < 5 else D2,
                 "Verifying shard sync health.") for i in range(6)]
    rows = [parse_line(json.dumps(r), i) for i, r in enumerate(mono)]
    got = analyze(rows)[0]
    assert "audit-monoculture" in kinds(got), got
    assert "5/6" in next(x for x in got
                         if x["kind"] == "audit-monoculture")["detail"]
    # threshold respect: 4/6 (67%) does not flag at 80%
    rows = [parse_line(json.dumps(r), i)
            for i, r in enumerate(mono[:4] + [mono[5], _rec(9, "2026-09-01T13:00:00Z", D2, "Verifying shard sync health.")])]
    assert "audit-monoculture" not in kinds(analyze(rows)[0])

    # 4) duplicate churn: same DID, 3 claims, one target
    dup = [_rec(i, f"2026-09-01T10:0{i}:00Z", D1,
                "Auditing mempool fee estimation.") for i in range(3)]
    got = analyze([parse_line(json.dumps(r), i)
                   for i, r in enumerate(dup)])[0]
    assert "duplicate-audit" in kinds(got), got

    # 5) verdict with no audit behind it
    ghost = [_rec(1, "2026-09-01T10:00:00Z", D2,
                  "Verified nonce window alignment.")]
    got = analyze([parse_line(json.dumps(r), i)
                   for i, r in enumerate(ghost)])[0]
    assert "verdict-no-audit" in kinds(got), got

    # 6) unresolved ages to WARN past open-secs; fresh is INFO
    fresh = [_rec(1, "2026-09-01T10:00:00Z", D1, "Auditing validator attestation coverage."),
             _rec(2, "2026-09-01T10:01:00Z", D2, "unrelated chatter")]
    got = analyze([parse_line(json.dumps(r), i)
                   for i, r in enumerate(fresh)])[0]
    f = [x for x in got if x["kind"] == "unresolved-audit"]
    assert len(f) == 1 and f[0]["severity"] == "INFO", got
    old = [_rec(1, "2026-09-01T10:00:00Z", D1, "Auditing validator attestation coverage."),
           _rec(2, "2026-09-01T23:00:00Z", D2, "unrelated chatter")]
    got = analyze([parse_line(json.dumps(r), i)
                   for i, r in enumerate(old)],
                  dict(open_secs=3600))[0]
    f = [x for x in got if x["kind"] == "unresolved-audit"]
    assert f and f[0]["severity"] == "WARN", got

    # 7) anonymous audit claim (no from / malformed DID)
    anon = [_rec(1, "2026-09-01T10:00:00Z", None,
                 "Auditing gas limit policy."),
            _rec(2, "2026-09-01T10:01:00Z", "not-a-did",
                 "Verifying gas limit policy.")]
    got = analyze([parse_line(json.dumps(r), i)
                   for i, r in enumerate(anon)])[0]
    assert "anonymous-auditor" in kinds(got), got

    # 8) plain-text lines parse as claims too
    got = analyze([(0, None, "Auditing plain text trail."),
                   (1, None, "random line")])[0]
    assert "unresolved-audit" in kinds(got), got

    # 9) verdict closes the target started by another DID
    closed = [_rec(1, "2026-09-01T10:00:00Z", D1, "Auditing peer scoring weights."),
              _rec(2, "2026-09-01T10:03:00Z", D2, "Verified peer scoring weights.")]
    got = analyze([parse_line(json.dumps(r), i)
                   for i, r in enumerate(closed)])[0]
    assert not [x for x in got if x["kind"] == "self-affirmation"], got
    assert not [x for x in got if x["kind"] == "unresolved-audit"], got

    # 10) CLI: rc 0 clean, rc 1 on WARN, rc 2 unreadable, json output
    rc, out = run(clean)
    assert rc == 0 and "roster" in out, (rc, out)
    rc, out = run(solo)
    assert rc == 1 and "self-affirmation" in out, (rc, out)
    assert main(["/nonexistent-capture.jsonl"]) == 2
    rc, out = run(clean, ["--json"])
    doc = json.loads(out)
    assert doc["findings"] == [] and len(doc["roster"]) == 3

    # 11) target normalisation drops leading articles and caps length
    assert norm_target("fee market design") == "fee market design"
    assert norm_target("shard sync in epoch 22") == "shard sync"

    # 12) roster aggregates first/last seq across claims
    multi = [_rec(5, "2026-09-01T10:00:00Z", D1, "Auditing alpha feeds."),
             _rec(9, "2026-09-01T11:00:00Z", D1, "Auditing beta feeds.")]
    roster = analyze([parse_line(json.dumps(r), i)
                      for i, r in enumerate(multi)])[1]
    assert roster[0]["first_seq"] == 0 and roster[0]["last_seq"] == 1
    assert roster[0]["targets_n"] == 2

    print("auditor-roster-audit self-test OK (12 groups: clean pass, "
          "self-affirmation, monoculture+threshold, duplicate churn, "
          "verdict-no-audit, unresolved aging, anonymous, plain text, "
          "cross-DID closure, CLI rc/json, normalisation, roster)")


if __name__ == "__main__":
    if "--self-test" in sys.argv:
        self_test()  # falls through; rc 0 (probe hook runs after)
    else:
        raise SystemExit(main())
