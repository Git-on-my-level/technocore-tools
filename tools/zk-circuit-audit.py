#!/usr/bin/env python3
"""zk-circuit-audit — standardized audit registry + revocation gate for
ZK circuits: manifest certification checks and compliance scoring.

DEMAND: evidence/suggestions/tools-services/2026-09-04.md
  - "Let's standardize circuit audits and revocation mechanisms now" /
    "We must standardize revocation registries and interop protocols"
    (01:24 run) — interoperable ZK circuit audit framework with
    revocation registry support.
  - "The verifiability of ZK proofs is non-negotiable—our 2023 audit of
    Semaphore's circuit showed a 0.03% soundness gap under adversarial
    input, which is unacceptable for national ID" (07:25 run) — framework
    with "automated revocation status verification and interoperability
    compliance scoring"; same run asks for an audit registry with
    "standardized reporting, vulnerability tracking, and certification".
    Unmet by audit-chain / claim-policy (integrity of exports, claim
    verifier policy — neither tracks circuit audit/revocation status).

What it does (read-only over JSON/JSONL data; nothing from input runs):
  - registry JSONL (one record per circuit version) + revocations JSONL:
      {"circuit": "semaphore-identity", "version": 3,
       "artifact": "<64-hex sha256>", "status": "active",
       "audits": [{"auditor": "did:key:...", "date": "2026-05-01",
                   "verdict": "pass", "soundness_gap": 0.0}]}
      {"subject": "circuit:name@3" | "auditor:did:key:...",
       "ts": "2026-08-30T00:00:00Z", "reason": "..."}
    A revocation is effective only when ts <= --now. An effective auditor
    revocation voids that auditor's audits; an effective circuit
    revocation rejects the circuit version outright.
  - lint REGISTRY — hygiene: non-JSON rows, bad digests, bad/duplicate
    versions, non-did auditors, malformed dates, unknown
    verdicts/statuses, negative gaps, active-but-unaudited circuits.
  - check MANIFEST --registry R --revocations V — deployment gate, per
    entry: unknown circuit@version, artifact digest mismatch, revoked
    circuit, deprecated status, failed audit, zero surviving audits,
    stale audits (older than --window-days, default 180), soundness gap
    above --max-gap (default 1e-4 — Semaphore's 0.03% fails) -> REJECT;
    fewer than --min-auditors (default 2) distinct surviving auditors ->
    CONDITIONAL; else CERTIFIED. Score 0-100 per entry: 20 each for
    pinned-and-matching artifact, surviving audit, auditor quorum,
    freshness, soundness within threshold; revoked -> 0.
  - score --registry R --revocations V — same score for every active
    circuit; exit 1 if any active circuit scores below 60.

Usage:
  zk-circuit-audit.py lint circuits.jsonl
  zk-circuit-audit.py check deploy.json --registry circuits.jsonl \
      --revocations revocations.jsonl [--now 2026-09-04T00:00:00Z] [--json]
  zk-circuit-audit.py score --registry circuits.jsonl --revocations rev.jsonl

VERIFY: self-test — python3 zk-circuit-audit.py --self-test
  Real behavior on fixtures: lint flags (bad digest, dup rows, non-did
  auditor, malformed date, unknown verdict, negative gap, unaudited);
  check: CERTIFIED / CONDITIONAL (single auditor, revoked co-auditor) /
  REJECT (unknown version, digest mismatch, revoked circuit, voided
  collapse to unaudited, stale, 0.03% gap, deprecated); not-yet-effective
  ignored; exit codes 0/1/2; --json; scores 100/80/60/20/0. Asserts, OK.
"""
import argparse
import datetime as dt
import json
import os
import re
import sys
import tempfile

DID = re.compile(r"^did:\w+:[A-Za-z0-9]{8,}$")
HEX64 = re.compile(r"^[0-9a-f]{64}$")
VERDICTS = ("pass", "conditional", "fail")
STATUSES = ("active", "deprecated")
SUBJECT = re.compile(r"^(circuit:.+@\d+|auditor:.+)$")


def read_jsonl(path):
    """[(line, obj-or-None)] — unparsable lines stay None, never dropped."""
    rows = []
    with open(path, encoding="utf-8") as fh:
        for i, line in enumerate(fh, 1):
            line = line.strip()
            if line:
                try:
                    rows.append((i, json.loads(line)))
                except json.JSONDecodeError:
                    rows.append((i, None))
    return rows


def read_json(path):
    with open(path, encoding="utf-8") as fh:
        return json.load(fh)


def parse_day(text):
    return dt.date.fromisoformat(str(text))


def parse_ts(text):
    return dt.datetime.fromisoformat(str(text).replace("Z", "+00:00"))


def key_of(rec):
    return f"{rec.get('circuit')}@{rec.get('version')}"


def audit_problems(aud):
    """Structural problems of one audit record -> [reasons]."""
    bad = []
    if not isinstance(aud.get("auditor"), str) or not DID.match(aud["auditor"]):
        bad.append(f"auditor not a did: {aud.get('auditor')!r}")
    try:
        parse_day(aud.get("date"))
    except (TypeError, ValueError):
        bad.append(f"bad audit date: {aud.get('date')!r}")
    if aud.get("verdict") not in VERDICTS:
        bad.append(f"unknown verdict: {aud.get('verdict')!r}")
    gap = aud.get("soundness_gap", 0.0)
    if not isinstance(gap, (int, float)) or isinstance(gap, bool) or gap < 0:
        bad.append(f"bad soundness_gap: {gap!r}")
    return bad


def lint_registry(rows):
    """[(loc, reason)] over registry rows."""
    bad, seen = [], {}
    for i, rec in rows:
        loc = f"line {i}"
        if not isinstance(rec, dict):
            bad.append((loc, "not a JSON object"))
            continue
        key = key_of(rec)
        if key in seen:
            bad.append((loc, f"duplicate registration {key} (line {seen[key]})"))
        seen.setdefault(key, i)
        if not isinstance(rec.get("artifact"), str) or not HEX64.match(rec["artifact"]):
            bad.append((loc, f"artifact digest not 64-hex: {rec.get('artifact')!r}"))
        ver = rec.get("version")
        if not isinstance(ver, int) or isinstance(ver, bool) or ver < 1:
            bad.append((loc, f"version must be a positive int: {ver!r}"))
        status = rec.get("status", "active")
        if status not in STATUSES:
            bad.append((loc, f"unknown status: {status!r}"))
        audits = rec.get("audits", [])
        if not isinstance(audits, list):
            bad.append((loc, "audits must be a list"))
            continue
        for aud in audits:
            for why in audit_problems(aud if isinstance(aud, dict) else {}):
                bad.append((loc, why))
        if status == "active" and not audits:
            bad.append((loc, f"active circuit {key} has no audits"))
    return bad


def revocations_of(rows, now):
    """Effective revocations at `now` -> {subject: reason}; malformed
    revocation rows raise ValueError (they are small and load-bearing)."""
    out = {}
    for i, rec in rows:
        if not isinstance(rec, dict) or not isinstance(rec.get("subject"), str) \
                or not SUBJECT.match(rec["subject"]):
            raise ValueError(f"malformed revocation at line {i}")
        try:
            ts = parse_ts(rec.get("ts"))
        except (TypeError, ValueError):
            raise ValueError(f"malformed revocation ts at line {i}") from None
        if ts <= now:
            out[rec["subject"]] = str(rec.get("reason", "unspecified"))
    return out


def evaluate(rec, revoked, now, window_days, max_gap, min_auditors):
    """Audit state of one registry record -> findings dict."""
    hard, soft, surviving = [], [], []
    key = key_of(rec)
    if f"circuit:{key}" in revoked:
        hard.append(f"revoked: {revoked[f'circuit:{key}']}")
    if rec.get("status") == "deprecated":
        hard.append("registry status: deprecated")
    voided = 0
    for aud in rec.get("audits", []):
        if f"auditor:{aud.get('auditor')}" in revoked:
            voided += 1
            continue
        if aud.get("verdict") == "fail":
            hard.append(f"failed audit by {aud.get('auditor')}")
            continue
        surviving.append(aud)
    audited = bool(surviving)
    auditors = {a.get("auditor") for a in surviving}
    gaps = [a.get("soundness_gap", 0.0) for a in surviving]
    newest = max((parse_day(a["date"]) for a in surviving), default=None)
    if not audited:
        why = ("all audits voided (revoked auditors)" if voided
               else "no audits on record")
        hard.append(f"unaudited: {why}")
    fresh = audited and (now.date() - newest).days <= window_days
    if audited and not fresh:
        hard.append(f"stale audits (newest {newest}, window {window_days}d)")
    worst = max(gaps, default=0.0)
    sound_ok = audited and worst <= max_gap
    if audited and not sound_ok:
        who = surviving[gaps.index(worst)].get("auditor")
        hard.append(f"soundness gap {worst:.1e} > {max_gap:.0e} ({who})")
    quorum_ok = len(auditors) >= min_auditors
    if audited and not quorum_ok:
        note = f" ({voided} voided)" if voided else ""
        soft.append(f"quorum {len(auditors)} < {min_auditors}"
                    f" distinct auditors{note}")
    return {"key": key, "hard": hard, "soft": soft, "voided": voided,
            "audited": audited, "auditors": len(auditors), "newest": newest,
            "fresh": fresh, "sound_ok": sound_ok, "quorum_ok": quorum_ok,
            "revoked": f"circuit:{key}" in revoked}


def score_of(finding, pinned=True):
    """Compliance score 0-100: 20 per clean component; revoked -> 0."""
    if finding["revoked"]:
        return 0
    parts = (pinned, finding["audited"], finding["quorum_ok"],
             finding["fresh"], finding["sound_ok"])
    return 20 * sum(parts)


def verdict_of(finding):
    if finding["hard"]:
        return "REJECTED", list(finding["hard"])
    if finding["soft"]:
        return "CONDITIONAL", list(finding["soft"])
    return "CERTIFIED", []


def check_manifest(manifest, registry_rows, revoc_rows, opts):
    """Gate a deployment manifest -> summary dict."""
    now = opts["now"]
    revoked = revocations_of(revoc_rows, now)
    index = {}
    for i, rec in registry_rows:
        if isinstance(rec, dict):
            index[key_of(rec)] = rec
    entries = []
    for item in manifest.get("circuits", []):
        want = f"{item.get('circuit')}@{item.get('version')}"
        rec = index.get(want)
        if rec is None:
            entries.append({"entry": want, "verdict": "REJECTED",
                            "reasons": ["circuit version not in registry"],
                            "score": 0})
            continue
        pinned = item.get("artifact") == rec.get("artifact")
        finding = evaluate(rec, revoked, now, opts["window_days"],
                           opts["max_gap"], opts["min_auditors"])
        if not pinned:
            finding["hard"].append("artifact digest mismatch vs registry")
        verdict, reasons = verdict_of(finding)
        entries.append({"entry": want, "verdict": verdict, "reasons": reasons,
                        "score": score_of(finding, pinned)})
    tally = {v: sum(1 for e in entries if e["verdict"] == v)
             for v in ("CERTIFIED", "CONDITIONAL", "REJECTED")}
    return {"deployment": manifest.get("deployment", "?"),
            "now": now.isoformat(), "checked": len(entries), **tally,
            "revoked_subjects": len(revoked), "entries": entries}


def _aud(auditor, date, gap=0.0, verdict="pass"):
    return {"auditor": auditor, "date": date, "verdict": verdict,
            "soundness_gap": gap}


def _rec(name, ver, ch, audits, status="active"):
    return {"circuit": name, "version": ver, "artifact": ch * 64,
            "status": status, "audits": audits}


def selftest():
    A, B, C = ("did:key:z6MkAudit0r0001", "did:key:z6MkAudit0r0002",
               "did:key:z6MkAudit0r0003")
    now = dt.datetime.fromisoformat("2026-09-04T00:00:00+00:00")
    reg = [
        _rec("semaphore-identity", 3, "a",
             [_aud(A, "2026-08-01"), _aud(C, "2026-07-15", 1e-5)]),
        _rec("merkle-membership", 2, "b", [_aud(A, "2026-01-01")]),
        _rec("range-proof", 1, "c", [_aud(C, "2026-08-20", 3e-4)]),
        _rec("nullifier", 5, "d", [_aud(A, "2026-08-10")]),
        _rec("witness-guard", 2, "e",
             [_aud(B, "2026-05-01"), _aud(C, "2026-06-01")]),
        _rec("solo-revoked", 1, "f", [_aud(B, "2026-06-15")]),
        _rec("legacy-mix", 4, "1",
             [_aud(A, "2026-08-02"), _aud(C, "2026-08-03")], "deprecated"),
        _rec("rotation", 2, "2",
             [_aud(A, "2026-07-01"), _aud(C, "2026-07-02")]),
        _rec("future", 1, "3",
             [_aud(A, "2026-08-05"), _aud(C, "2026-08-06")]),
    ]
    revocs = [
        {"subject": f"auditor:{B}", "ts": "2026-08-30T00:00:00Z",
         "reason": "soundness finding overturned"},
        {"subject": "circuit:rotation@2", "ts": "2026-08-31T00:00:00Z",
         "reason": "trusted-setup ceremony compromised"},
        {"subject": f"auditor:{C}", "ts": "2026-12-01T00:00:00Z",
         "reason": "not yet effective"},
    ]
    td = tempfile.mkdtemp(prefix="zk-circuit-audit-")

    def dump(name, rows):
        path = os.path.join(td, name)
        with open(path, "w", encoding="utf-8") as fh:
            fh.write("\n".join(json.dumps(r) for r in rows) + "\n")
        return path

    reg_path, rev_path = dump("reg.jsonl", reg), dump("rev.jsonl", revocs)

    # lint: clean registry has no findings
    assert lint_registry(read_jsonl(reg_path)) == []
    dirty = dump("dirty.jsonl", [
        {"circuit": "x", "version": 1, "artifact": "nothex",
         "status": "active", "audits": []},
        _rec("x", 1, "a", [{"auditor": "not-a-did", "date": "2026-01-01",
                            "verdict": "pass", "soundness_gap": 0.0}]),
        {"circuit": "y", "version": 0, "artifact": "b" * 64, "status": "weird",
         "audits": [_aud(A, "13/13/2026", -1, "ok")]},
        "not json",
    ])
    reasons = " | ".join(why for _, why in lint_registry(read_jsonl(dirty)))
    for frag in ("artifact digest not 64-hex", "duplicate registration",
                 "auditor not a did", "version must be a positive int",
                 "unknown status", "bad audit date", "unknown verdict",
                 "bad soundness_gap", "active circuit x@1 has no audits",
                 "not a JSON object"):
        assert frag in reasons, frag

    # evaluate/verdict/score core semantics
    opts = {"now": now, "window_days": 180, "max_gap": 1e-4, "min_auditors": 2}
    revoked = revocations_of(read_jsonl(rev_path), now)
    assert len(revoked) == 2 and f"auditor:{C}" not in revoked
    ev = {r["circuit"]: evaluate(r, revoked, now, 180, 1e-4, 2) for r in reg}
    assert verdict_of(ev["semaphore-identity"]) == ("CERTIFIED", [])
    assert score_of(ev["semaphore-identity"]) == 100
    assert verdict_of(ev["nullifier"])[0] == "CONDITIONAL"
    assert score_of(ev["nullifier"]) == 80
    assert verdict_of(ev["merkle-membership"])[0] == "REJECTED"
    assert "stale audits" in ev["merkle-membership"]["hard"][0]
    assert score_of(ev["merkle-membership"]) == 60   # stale + single auditor
    assert any("soundness gap 3.0e-04" in h for h in ev["range-proof"]["hard"])
    assert score_of(ev["range-proof"]) == 60         # gap + single auditor
    assert verdict_of(ev["witness-guard"])[0] == "CONDITIONAL"
    assert "1 voided" in ev["witness-guard"]["soft"][0]
    assert score_of(ev["witness-guard"]) == 80
    assert verdict_of(ev["solo-revoked"])[0] == "REJECTED"
    assert any("unaudited: all audits voided" in h
               for h in ev["solo-revoked"]["hard"])
    assert score_of(ev["solo-revoked"]) == 20        # pinned artifact only
    # check: manifest gate, exit codes, --json
    manifest = {"deployment": "bridge-v4", "circuits": [
        {"circuit": "semaphore-identity", "version": 3, "artifact": "a" * 64},
        {"circuit": "range-proof", "version": 1, "artifact": "c" * 64},
        {"circuit": "semaphore-identity", "version": 9, "artifact": "a" * 64},
        {"circuit": "nullifier", "version": 5, "artifact": "deadbeef" * 8},
        {"circuit": "witness-guard", "version": 2, "artifact": "e" * 64},
        {"circuit": "future", "version": 1, "artifact": "3" * 64},
    ]}
    man_path = os.path.join(td, "deploy.json")
    with open(man_path, "w", encoding="utf-8") as fh:
        json.dump(manifest, fh)
    import contextlib
    import io
    buf = io.StringIO()
    with contextlib.redirect_stdout(buf):
        rc = main(["check", man_path, "--registry", reg_path,
                   "--revocations", rev_path, "--json"])
    out = json.loads(buf.getvalue())
    assert rc == 1 and out["checked"] == 6, out
    assert out["CERTIFIED"] == 2 and out["CONDITIONAL"] == 1, out
    assert out["REJECTED"] == 3 and out["revoked_subjects"] == 2, out
    verdicts = {e["entry"]: e["verdict"] for e in out["entries"]}
    assert verdicts["semaphore-identity@3"] == "CERTIFIED"
    assert verdicts["future@1"] == "CERTIFIED"
    assert verdicts["witness-guard@2"] == "CONDITIONAL"
    assert verdicts["range-proof@1"] == "REJECTED"
    assert verdicts["semaphore-identity@9"] == "REJECTED"
    assert verdicts["nullifier@5"] == "REJECTED"
    why = {e["entry"]: e["reasons"] for e in out["entries"]}
    assert "circuit version not in registry" in why["semaphore-identity@9"]
    assert "artifact digest mismatch vs registry" in why["nullifier@5"]
    clean = {"deployment": "t", "circuits": manifest["circuits"][:1]}
    clean_path = os.path.join(td, "clean.json")
    with open(clean_path, "w", encoding="utf-8") as fh:
        json.dump(clean, fh)
    buf2 = io.StringIO()
    with contextlib.redirect_stdout(buf2):
        rc = main(["check", clean_path, "--registry", reg_path,
                   "--revocations", rev_path])
    assert rc == 0 and "CERTIFIED 1" in buf2.getvalue(), buf2.getvalue()

    # score subcommand: exit 1 while active circuits sit below 60
    buf3 = io.StringIO()
    with contextlib.redirect_stdout(buf3):
        rc = main(["score", "--registry", reg_path, "--revocations", rev_path])
    txt = buf3.getvalue()
    assert rc == 1, txt
    assert "rotation@2" in txt and "0" in txt
    # malformed revocation row -> usage/IO exit 2
    badrev = dump("badrev.jsonl", [{"subject": "garbage", "ts": "x"}])
    buf4 = io.StringIO()
    with contextlib.redirect_stdout(buf4):
        rc = main(["check", clean_path, "--registry", reg_path,
                   "--revocations", badrev])
    assert rc == 2
    print("OK zk-circuit-audit self-test: lint, revocation effectiveness "
          "(voided-auditor collapse, not-yet-effective), verdicts, scores "
          "100/80/60/20/0, manifest gate, exit codes 0/1/2, --json")


def main(argv=None):
    ap = argparse.ArgumentParser(
        prog="zk-circuit-audit",
        description="ZK circuit audit registry: lint, certification gate, "
                    "compliance scoring")
    sub = ap.add_subparsers(dest="cmd", required=True)
    pl = sub.add_parser("lint", help="registry hygiene check")
    pl.add_argument("registry")
    pc = sub.add_parser("check", help="gate a deployment MANIFEST")
    pc.add_argument("manifest")
    pc.add_argument("--registry", required=True)
    pc.add_argument("--revocations", required=True)
    ps = sub.add_parser("score", help="score every active circuit")
    ps.add_argument("--registry", required=True)
    ps.add_argument("--revocations", required=True)
    for p in (pc, ps):
        p.add_argument("--now", type=parse_ts,
                       default=dt.datetime.now(dt.timezone.utc),
                       help="reference time (default: now, ISO-8601)")
        p.add_argument("--window-days", type=int, default=180,
                       help="audit freshness window (default 180)")
        p.add_argument("--max-gap", type=float, default=1e-4,
                       help="max tolerated soundness gap (default 1e-4)")
        p.add_argument("--min-auditors", type=int, default=2,
                       help="distinct auditors for full certification")
    pc.add_argument("--json", action="store_true")
    args = ap.parse_args(argv)
    try:
        if args.cmd == "lint":
            bad = lint_registry(read_jsonl(args.registry))
            for loc, why in bad:
                print(f"  {loc}: {why}")
            print("LINT OK" if not bad else f"LINT FAIL: {len(bad)} problems")
            return 0 if not bad else 1
        opts = {"now": args.now, "window_days": args.window_days,
                "max_gap": args.max_gap, "min_auditors": args.min_auditors}
        reg_rows = read_jsonl(args.registry)
        rev_rows = read_jsonl(args.revocations)
        if args.cmd == "check":
            summary = check_manifest(read_json(args.manifest), reg_rows,
                                     rev_rows, opts)
            if args.json:
                print(json.dumps(summary, indent=2, default=str))
            else:
                print(f"deployment {summary['deployment']} "
                      f"@ {summary['now']}  revoked-subjects "
                      f"{summary['revoked_subjects']}")
                for e in summary["entries"]:
                    tail = (" [" + "; ".join(e["reasons"]) + "]") if e["reasons"] else ""
                    print(f"  {e['verdict']:11s} {e['entry']} "
                          f"score {e['score']}{tail}")
                print(f"checked {summary['checked']}  "
                      f"CERTIFIED {summary['CERTIFIED']}  "
                      f"CONDITIONAL {summary['CONDITIONAL']}  "
                      f"REJECTED {summary['REJECTED']}")
            return 0 if summary["REJECTED"] == 0 else 1
        bad = lint_registry(reg_rows)
        if bad:
            for loc, why in bad:
                print(f"  {loc}: {why}", file=sys.stderr)
            print("registry fails lint; fix before scoring", file=sys.stderr)
            return 2
        revoked = revocations_of(rev_rows, opts["now"])
        worst = []
        for i, rec in reg_rows:
            if not isinstance(rec, dict) or rec.get("status", "active") != "active":
                continue
            finding = evaluate(rec, revoked, opts["now"], opts["window_days"],
                               opts["max_gap"], opts["min_auditors"])
            verdict, reasons = verdict_of(finding)
            score = score_of(finding)
            worst.append(score)
            tail = (" [" + "; ".join(reasons) + "]") if reasons else ""
            print(f"  {finding['key']:32s} score {score:3d}  {verdict}{tail}")
        print(f"scored {len(worst)} active circuits; revoked subjects "
              f"{len(revoked)}; minimum {min(worst) if worst else 0}")
        return 0 if (not worst or min(worst) >= 60) else 1
    except (OSError, ValueError) as exc:
        print(f"zk-circuit-audit: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    if "--self-test" in sys.argv:
        selftest()
    else:
        raise SystemExit(main())
