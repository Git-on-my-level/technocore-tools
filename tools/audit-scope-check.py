#!/usr/bin/env python3
"""audit-scope-check — label audit claims by scope type and surface what the
audit did NOT review, so "audited" stops being read as a blanket guarantee.

DEMAND: evidence/suggestions/tools-services/2026-10-12.md (3 request lines)
  - request: "Clarification and education on audit scope — users keep
    conflating token audits, protocol audits, and feasibility
    assessments, leading to misinterpretation of what \"audited\"
    actually guarantees" — evidence: "a token audit is not a protocol
    audit, and a feasibility assessment is not a security review.
    whenever a project cites an audit, check what the audit actually
    covered".
  - request: "Verification that a cited audit actually covered the
    relevant surface area (economics, governance, etc.)" — evidence:
    "check what the audit actually covered before you tr[ust it]" /
    "the scope section is where the truth lives".
  - request: "Distinguish token-audit claims used as security
    guarantees in hype contexts" — evidence: "whenever a project
    cites an audit, check what the audit actually covered" plus
    pervasive "leaning bullish" sentiment messaging.
Ground truth for the coverage map comes from the in-room correction itself:
"a token audit is not a protocol audit, and a feasibility assessment is not
a security review ... token audits usually just verify the contract matches
the docs, while a protocol review should cover economics."

Input: JSONL, one room message per line:
  {"room":"lobby","author":"a1","text":"... the token audit passed ..."}
"text" is required; room/author optional. Non-JSON or textless rows are
reported as MALFORMED/NO_TEXT, never trusted, never executed.

Scope labels and what each covers (everything else = NOT REVIEWED):
  TOKEN            contract-logic
  CONTRACT         contract-logic
  PROTOCOL         contract-logic, economics
  SECURITY_REVIEW  contract-logic, operational
  FEASIBILITY      (nothing — it is not a security review)

Finding codes:
  SCOPE_UNKNOWN  audit claim whose scope type is not identifiable
  CLAIM_IN_HYPE  audit assertion inside promotional/sentiment context
  MULTIPLE_SCOPES distinct scope types cited in one message (conflation risk)
  MALFORMED      row that is not a conforming message
  NO_TEXT        JSON row without a text field

Exit: 0 = clean (INFO/WARN allowed), 1 = HIGH finding, 2 = usage.
Usage: audit-scope-check.py FILE [--json] [--self-test]
"""
import argparse
import json
import re
import sys

AREAS = ("contract-logic", "economics", "governance", "operational")

# phrase -> areas that scope of audit actually covers
SCOPE_COVERS = {
    "TOKEN": ("contract-logic",),
    "CONTRACT": ("contract-logic",),
    "PROTOCOL": ("contract-logic", "economics"),
    "SECURITY_REVIEW": ("contract-logic", "operational"),
    "FEASIBILITY": (),
}

SCOPE_PATTERNS = (
    ("TOKEN", re.compile(r"\btoken\s+audit", re.I)),
    ("CONTRACT", re.compile(r"\bcontract\s+audit", re.I)),
    ("PROTOCOL", re.compile(r"\bprotocol\s+(?:audit|review)", re.I)),
    ("FEASIBILITY", re.compile(r"\bfeasibility\s+(?:assessment|study|audit)",
                               re.I)),
    ("SECURITY_REVIEW", re.compile(r"\bsecurity\s+(?:review|audit)", re.I)),
)

# an audit is cited in some form ("whenever a project cites an audit, ...")
CLAIM_PATTERNS = re.compile(
    r"\baudit(?:ed|s)?\b|\baudited\b|\bscope section\b|\bpassed an audit\b",
    re.I)

HYPE_MARKERS = (
    "bullish", "leaning bullish", "moonshot", "100x", "guaranteed",
    "guarantees", "risk-free", "can't lose", "pump", "apes", "no brainer",
    "worth watching", "to the moon", "huge upside", "get in early",
)

SEVERITY = {"SCOPE_UNKNOWN": "HIGH", "CLAIM_IN_HYPE": "HIGH",
            "MULTIPLE_SCOPES": "MEDIUM", "MALFORMED": "WARN",
            "NO_TEXT": "WARN"}


def parse_lines(lines):
    """Yield (index, msg-or-None, err). None + err marks a bad row."""
    out = []
    for i, raw in enumerate(lines, 1):
        s = raw.strip()
        if not s:
            continue
        try:
            obj = json.loads(s)
        except ValueError:
            out.append((i, None, "not JSON"))
            continue
        if not isinstance(obj, dict):
            out.append((i, None, "not an object"))
            continue
        text = obj.get("text")
        if not isinstance(text, str) or not text.strip():
            out.append((i, None, "no text field"))
            continue
        out.append((i, obj, None))
    return out


def label_scopes(text):
    """Scope types cited in this text, in pattern order, deduplicated."""
    seen = []
    for name, pat in SCOPE_PATTERNS:
        if name not in seen and pat.search(text):
            seen.append(name)
    return seen


def is_hype(text):
    low = text.lower()
    return any(m in low for m in HYPE_MARKERS)


def coverage_checklist(scope):
    """(covered, not_reviewed) area tuples for a scope type."""
    covered = tuple(a for a in SCOPE_COVERS[scope] if a in AREAS)
    return covered, tuple(a for a in AREAS if a not in covered)


def _finding(code, line, detail, scope=None, room=None):
    return {"code": code, "severity": SEVERITY[code], "line": line,
            "scope": scope, "room": room, "detail": detail}


def audit(parsed):
    """Parsed rows -> (labels, findings). Deterministic, line order."""
    labels, findings = [], []
    for i, msg, err in parsed:
        if msg is None:
            findings.append(_finding(
                "NO_TEXT" if err == "no text field" else "MALFORMED",
                i, err))
            continue
        text, room = msg["text"], msg.get("room")
        entry = {"line": i, "room": room, "claim": False, "scopes": [],
                 "hype": False, "covered": [], "not_reviewed": []}
        if CLAIM_PATTERNS.search(text):
            entry["claim"] = True
            scopes = label_scopes(text)
            entry["scopes"] = scopes
            if not scopes:
                findings.append(_finding(
                    "SCOPE_UNKNOWN", i,
                    "audit cited without a scope type; check what the "
                    "audit actually covered (scope section)", room=room))
            else:
                covered, missing = coverage_checklist(scopes[0])
                entry["covered"] = list(covered)
                entry["not_reviewed"] = list(missing)
                if len(scopes) > 1:
                    findings.append(_finding(
                        "MULTIPLE_SCOPES", i,
                        "distinct scope types cited together: "
                        + " vs ".join(scopes), scope=scopes[0], room=room))
            if is_hype(text):
                entry["hype"] = True
                findings.append(_finding(
                    "CLAIM_IN_HYPE", i,
                    "'audited' asserted in promotional/sentiment context; "
                    "attach scope breakdown before trusting it",
                    scope=scopes[0] if scopes else None, room=room))
        labels.append(entry)
    return labels, findings


def classify(findings):
    """1 if any HIGH finding, else 0."""
    return 1 if any(f["severity"] == "HIGH" for f in findings) else 0


def render(labels, findings, as_json=False):
    if as_json:
        return json.dumps({"labels": labels, "findings": findings},
                          indent=2, ensure_ascii=False)
    lines = []
    claim_rows = [e for e in labels if e["claim"]]
    if not claim_rows:
        lines.append("no messages with audit claims")
    for e in claim_rows:
        where = f"[{e['room']}] " if e.get("room") else ""
        if e["scopes"]:
            cov = ",".join(e["covered"]) or "-"
            miss = ",".join(e["not_reviewed"]) or "-"
            lines.append(f"line {e['line']} {where}scope={'+'.join(e['scopes'])}"
                         f" hype={'yes' if e['hype'] else 'no'}")
            lines.append(f"  covered     : {cov}")
            lines.append(f"  NOT reviewed: {miss}")
        else:
            lines.append(f"line {e['line']} {where}scope=UNKNOWN "
                         f"hype={'yes' if e['hype'] else 'no'}")
    for f in findings:
        lines.append(f"{f['severity']:6} {f['code']:14} line {f['line']}: "
                     f"{f['detail']}")
    n_scope = sum(1 for e in claim_rows if e["scopes"])
    lines.append(f"summary: {n_scope} labeled, "
                 f"{len(claim_rows) - n_scope} unlabeled, "
                 f"{len(findings)} findings")
    if not findings:
        lines.append("CLEAN")
    return "\n".join(lines)


def self_test():
    import os
    import subprocess
    import tempfile

    msg = lambda t, room="lobby": json.dumps({"room": room, "text": t})

    # 1. scope labeling: each cited type resolves to the right label
    cases = [
        ("the token audit passed last week", ["TOKEN"]),
        ("their contract audit found nothing", ["CONTRACT"]),
        ("a protocol review should cover economics", ["PROTOCOL"]),
        ("the feasibility assessment came back fine", ["FEASIBILITY"]),
        ("after the security review we are safe", ["SECURITY_REVIEW"]),
        ("project cites an audit on the website", []),
    ]
    for text, want in cases:
        got = label_scopes(text)
        assert got == want, f"label_scopes({text!r}) = {got}, want {want}"

    # 2. coverage checklist: what was NOT reviewed per scope
    assert coverage_checklist("TOKEN") == (
        ("contract-logic",),
        ("economics", "governance", "operational"))
    assert coverage_checklist("PROTOCOL") == (
        ("contract-logic", "economics"), ("governance", "operational"))
    assert coverage_checklist("FEASIBILITY") == ((), AREAS)

    # 3. full audit over a mixed stream: labels + findings by code
    rows = [msg("a token audit is not a protocol audit, check the scope"),
            msg("audited and guaranteed 100x, get in early", "hype"),
            msg("the project cites an audit"),
            msg("just chatter, no claims here", "cafe")]
    parsed = parse_lines(rows)
    labels, findings = audit(parsed)
    codes = sorted({f["code"] for f in findings})
    assert codes == ["CLAIM_IN_HYPE", "MULTIPLE_SCOPES", "SCOPE_UNKNOWN"], codes
    assert labels[0]["scopes"] == ["TOKEN", "PROTOCOL"]
    assert labels[0]["not_reviewed"] == ["economics", "governance",
                                         "operational"]
    assert labels[1]["hype"] is True and labels[1]["scopes"] == []
    assert labels[1]["claim"] is True and labels[2]["claim"] is True
    assert labels[3]["claim"] is False and not any(
        f["line"] == 4 for f in findings)  # no claim -> no finding

    # 4. malformed rows are reported, not crashed on
    bad = parse_lines(["not json", '{"room":"x"}', '{"text":""}'])
    assert sum(1 for _, m, e in bad if m is None and e) == 3
    _, bf = audit(bad)
    assert sorted(f["code"] for f in bf) == ["MALFORMED", "NO_TEXT",
                                             "NO_TEXT"]

    # 5. exit policy and renderer
    assert classify([]) == 0
    assert classify([{"severity": "MEDIUM"}]) == 0
    assert classify([{"severity": "HIGH"}]) == 1
    txt = render(labels, findings)
    assert "NOT reviewed: economics,governance,operational" in txt
    assert "CLAIM_IN_HYPE" in txt and "CLEAN" not in txt
    assert "CLEAN" in render([], [])

    # 6. CLI round-trip on a real file: clean exits 0, hype exits 1
    with tempfile.TemporaryDirectory() as d:
        for name, data, want_rc in (
                ("ok.jsonl", [msg("protocol review covered economics")], 0),
                ("bad.jsonl", [msg("audited, bullish, to the moon")], 1)):
            path = os.path.join(d, name)
            with open(path, "w") as fh:
                fh.write("\n".join(data))
            r = subprocess.run([sys.executable, os.path.abspath(__file__),
                                path], capture_output=True, text=True)
            assert r.returncode == want_rc, (name, r.returncode, r.stdout)
            assert ("CLEAN" in r.stdout) == (want_rc == 0)

    print("audit-scope-check self-test: OK (6 checks, 5 finding codes)")


def main(argv=None):
    ap = argparse.ArgumentParser(
        description="Label audit claims by scope type and surface uncovered "
                    "areas (economics/governance/operational)")
    ap.add_argument("file", help="JSONL of room messages with a text field")
    ap.add_argument("--json", action="store_true", help="JSON output")
    ap.add_argument("--self-test", action="store_true",
                    help="run built-in verification")
    args = ap.parse_args(argv)
    try:
        with open(args.file, errors="replace") as fh:
            parsed = parse_lines(fh)
    except OSError as e:
        print(f"audit-scope-check: cannot read {args.file}: {e}",
              file=sys.stderr)
        return 2
    labels, findings = audit(parsed)
    print(render(labels, findings, as_json=args.json))
    return classify(findings)


if __name__ == "__main__":
    if "--self-test" in sys.argv:
        self_test()  # falls through; rc 0 (probe hook runs after this line)
    else:
        raise SystemExit(main())
