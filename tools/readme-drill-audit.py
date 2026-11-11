#!/usr/bin/env python3
"""readme-drill-audit — answers and audits readme-drill provenance queries:
given a README export and a git tag log, it answers "when was vX.Y.Z
tagged?" drills and flags readme version claims no tag can back.

DEMAND: evidence/suggestions/tools-services/2026-11-11.md (05:57 run)
  - request: "Answer readme-drill queries asking for the v0.1.0 tag date
    (audit-probe ACKed but readme queries ignored)" — evidence: "the
    readme-drill queries asking for the v0.1.0 tag date have received
    no reply, suggesting a systematic bias toward verification" —
    proposed service: "Extend ... to handle readme/docs provenance
    queries (e.g., tag dates) alongside verification probes, or route
    unserved readme-drill questions to a docs-audit handler."
Scope: full proposed service over saved README + tag-log exports.

Inputs:
  --readme PATH   markdown/text export of the README (or any doc)
  --tags PATH     lines from
                  git for-each-ref --sort=creatordate --format=
                  '%(refname:short) %(creatordate:iso8601)' refs/tags
                  (bare "vX.Y.Z DATE" lines and "refs/tags/..." lines
                  are accepted; noise lines are skipped)
  --query STR     drill question, repeatable; a version token inside is
                  extracted and answered from the tag table

Findings (rc 1 when any exist, rc 0 clean, rc 2 usage/IO error):
  unanswered-query  drill names a version absent from the tag table
  orphan-claim      README mentions a version no tag backs
  unmentioned-tag   tag never referenced by the README (info-level)
Answers to --query drills print to stdout either way. Data is parsed,
never executed.
"""

import argparse
import json
import re
import sys

# three-part versions (v optional); two-part only with v/ or "version"
_V3 = re.compile(r"\bv?(\d+)\.(\d+)\.(\d+)\b")
_V2_CTX = re.compile(r"\bv(\d+)\.(\d+)\b")
_V2_WORD = re.compile(r"\bversion[ _-]?(\d+)\.(\d+)\b", re.I)
# major.minor or major.minor.patch; longer dotted names are skipped
_TAGREF = re.compile(r"^(?:refs/tags/)?v?(\d+\.\d+(?:\.\d+)?)$")
_DATE = re.compile(r"(\d{4}-\d{2}-\d{2})")


def norm_ver(major, minor, patch=None):
    """Canonical dotted form for a version triple/pair."""
    return "%d.%d.%s" % (major, minor, patch if patch is not None else 0)


def parse_tags(lines):
    """Tag-log lines -> {version: earliest iso date}.

    Accepts `v0.1.0 2026-09-01...`, `refs/tags/1.2.3<TAB>date`, skips
    anything without a recognizable tag name + date. Re-tagged versions
    keep the earliest date (first sighting).
    """
    table = {}
    for line in lines:
        parts = line.split()
        if len(parts) < 2:
            continue
        m = _TAGREF.match(parts[0])
        d = _DATE.search(line)
        if not m or not d:
            continue
        ver = norm_ver(*[int(x) for x in m.group(1).split(".")])
        iso = d.group(1)
        if ver not in table or iso < table[ver]:
            table[ver] = iso
    return table


def extract_claims(text):
    """Version mentions in a doc -> [(version, context_snippet)].

    Three-part tokens always count; two-part only when v-prefixed or
    preceded by the word "version" (so prose like "pi is 3.14" is not a
    release claim). Duplicate (version, snippet) pairs collapse.
    """
    out = []
    seen = set()
    for m in _V3.finditer(text):
        ver = norm_ver(int(m.group(1)), int(m.group(2)), int(m.group(3)))
        out.append((ver, _snip(text, m.start())))
    for m in _V2_CTX.finditer(text):
        ver = norm_ver(int(m.group(1)), int(m.group(2)))
        if _three_at(text, m.end()):
            continue  # already captured by the _V3 scan
        out.append((ver, _snip(text, m.start())))
    for m in _V2_WORD.finditer(text):
        ver = norm_ver(int(m.group(1)), int(m.group(2)))
        if _three_at(text, m.end()):
            continue  # already captured by the _V3 scan
        out.append((ver, _snip(text, m.start())))
    uniq = []
    for pair in out:
        if pair not in seen:
            seen.add(pair)
            uniq.append(pair)
    return uniq


def _three_at(text, end):
    """True when the two-part match ending at end continues as `.N`."""
    return end + 1 < len(text) and text[end] == "." and text[end + 1].isdigit()


def _snip(text, pos, width=48):
    """Compact context snippet around pos, whitespace-collapsed."""
    lo, hi = max(0, pos - 16), min(len(text), pos + width)
    return re.sub(r"\s+", " ", text[lo:hi]).strip()


def answer_query(query, table):
    """Best-effort answer for one drill: (version, date) or (ver, None)."""
    hits = extract_claims(query)
    if not hits:
        return None, None
    ver = hits[0][0]
    return ver, table.get(ver)


def audit(readme_text, tag_lines, queries):
    """Full drill audit -> report dict (also used by --json output)."""
    table = parse_tags(tag_lines)
    claims = extract_claims(readme_text)
    claimed = {v for v, _ in claims}
    findings = []
    for ver, snip in claims:
        if ver not in table:
            findings.append({"kind": "orphan-claim", "version": ver,
                             "context": snip})
    for ver in sorted(set(table) - claimed):
        findings.append({"kind": "unmentioned-tag", "version": ver,
                         "context": "tagged %s, absent from README"
                                    % table[ver]})
    answered, unanswered = [], []
    for q in queries:
        ver, date = answer_query(q, table)
        if ver is None:
            unanswered.append({"query": q, "version": None})
        elif date is None:
            unanswered.append({"query": q, "version": ver})
            findings.append({"kind": "unanswered-query", "version": ver,
                             "context": q})
        else:
            answered.append({"query": q, "version": ver, "date": date})
    return {"tag_table": table, "claims": len(claimed),
            "answered": answered,
            "unanswered": unanswered, "findings": findings}


def fmt_report(rep):
    """Human-readable audit report."""
    lines = ["readme-drill-audit: %d tags, %d version claims in README"
             % (len(rep["tag_table"]), rep["claims"])]
    for a in rep["answered"]:
        lines.append("  answered: %s -> tagged %s (%s)"
                     % (a["version"], a["date"], a["query"]))
    for u in rep["unanswered"]:
        lines.append("  unanswered: %s (%s)"
                     % (u["version"] or "no version found", u["query"]))
    for f in rep["findings"]:
        lines.append("  %s: %s — %s" % (f["kind"], f["version"],
                                        f["context"]))
    if not rep["findings"] and not rep["unanswered"]:
        lines.append("  no findings: every claim backed, every drill "
                     "answered")
    return "\n".join(lines)


def build_parser():
    ap = argparse.ArgumentParser(
        prog="readme-drill-audit",
        description="Answer readme-drill provenance queries (tag dates) "
                    "and audit README version claims against a tag log.")
    ap.add_argument("--readme", required=True,
                    help="README/doc export to audit")
    ap.add_argument("--tags", required=True,
                    help="git tag log (refname + creatordate lines)")
    ap.add_argument("--query", action="append", default=[],
                    metavar="STR", help="drill question (repeatable)")
    ap.add_argument("--json", action="store_true",
                    help="emit the raw report dict as JSON")
    return ap


def main(argv=None):
    opt = build_parser().parse_args(argv)
    try:
        with open(opt.readme, errors="replace") as fh:
            readme_text = fh.read()
        with open(opt.tags, errors="replace") as fh:
            tag_lines = fh.read().splitlines()
    except OSError as exc:
        print("readme-drill-audit: %s" % exc, file=sys.stderr)
        return 2
    rep = audit(readme_text, tag_lines, opt.query)
    if opt.json:
        print(json.dumps(rep, indent=2, sort_keys=True))
    else:
        print(fmt_report(rep))
    return 1 if rep["findings"] else 0


def self_test():
    import os
    import shutil
    import tempfile

    tag_log = [
        "v0.1.0 2026-09-01T12:00:00+00:00",
        "refs/tags/0.2.0\t2026-09-15 08:30:00 +0000",
        "noise line without a date",
        "not-a-tag 2026-09-02",
        "v0.2.0 2026-09-10 00:00:00 +0000",  # re-tag: keep earliest
    ]
    table = parse_tags(tag_log)
    assert parse_tags(tag_log) == table, "parse_tags must be stable"

    readme = ("# tool\n\nStable as of v0.1.0 (first public cut).\n\n"
              "## Changelog\n- 0.2.0: faster probes; version 1.0 due "
              "later\n- mentions 3.14 in a math note\n"
              "## heading for 0.1.0 drills\n")
    claims = extract_claims(readme)
    vers = sorted({v for v, _ in claims})
    assert extract_claims(readme) == claims, "claim extraction stable"
    assert any(v == "0.1.0" and "drills" not in s for v, s in claims)
    # decimal prose is not a claim
    assert "3.14" not in {v for v, _ in claims}
    # "version 1.2.3" is that triple only — not also a phantom 1.2.0
    assert [v for v, _ in extract_claims("version 1.2.3")] == ["1.2.3"]
    assert [v for v, _ in extract_claims("v1.2.3")] == ["1.2.3"]
    # a real 1.2.0 tag stays unmentioned when the README only says 1.2.3
    hid = audit("version 1.2.3\n",
                ["v1.2.0 2026-01-01", "v1.2.3 2026-02-02"], [])
    assert [(f["kind"], f["version"]) for f in hid["findings"]] == [
        ("unmentioned-tag", "1.2.0")], hid
    # two-part claims survive newline, tab, and comma separators
    adj = "v1.0\nv2.0\tv3.0,v4.0"
    assert [v for v, _ in extract_claims(adj)] == [
        "1.0.0", "2.0.0", "3.0.0", "4.0.0"]
    kept = audit(adj + "\n", ["v1.0 2026-01-01", "v2.0 2026-02-01",
                              "v3.0 2026-03-01", "v4.0 2026-04-01"], [])
    assert kept["findings"] == [], kept
    # four-or-more-part tags are skipped; two- and three-part still parse
    assert parse_tags(["v1.2.3.4 2026-01-01T00:00:00+00:00",
                       "refs/tags/v1.2.3.4.5 2026-02-01",
                       "v1.2 2026-03-01",
                       "v0.1.0 2026-09-01"]) == {
        "1.2.0": "2026-03-01", "0.1.0": "2026-09-01"}

    # drill answering: the v0.1.0 tag-date question from the demand
    ver, date = answer_query("when was v0.1.0 tagged?", table)
    assert answer_query("when was v0.1.0 tagged?",
                        parse_tags(tag_log)) == ("0.1.0", "2026-09-01")
    ver, date = answer_query("release date of 9.9.9?", table)
    assert ver == "9.9.9" and date is None, (ver, date)
    ver, date = answer_query("what time is it?", table)
    assert ver is None and date is None, (ver, date)

    rep = audit(readme, tag_log + ["v0.3.0 2026-10-01"],
                ["when was v0.1.0 tagged?", "any word on 9.9.9?"])
    kinds = sorted({f["kind"] for f in rep["findings"]})
    assert audit(readme, tag_log + ["v0.3.0 2026-10-01"],
                 ["when was v0.1.0 tagged?", "any word on 9.9.9?"]) == rep
    assert rep["answered"][0]["date"] == "2026-09-01"
    text = fmt_report(rep)
    assert "no version found" not in fmt_report(rep)
    assert "9.9.9" in text, text

    # end-to-end via main(): clean repo -> rc 0; orphans -> rc 1; IO -> 2
    root = tempfile.mkdtemp(prefix="readme-drill-")
    try:
        rp = os.path.join(root, "README.md")
        tp = os.path.join(root, "tags.log")
        with open(rp, "w") as fh:
            fh.write("tool readme\n\nas of v0.1.0 it works\n")
        with open(tp, "w") as fh:
            fh.write("v0.1.0 2026-09-01\n")
        rc = main(["--readme", rp, "--tags", tp,
                   "--query", "when was v0.1.0 tagged?"])
        assert rc == 0, rc
        clean = audit(open(rp).read(), open(tp).readlines(),
                      ["when was v0.1.0 tagged?"])
        assert not clean["findings"], clean
        # determinism
        again = audit(open(rp).read(), open(tp).readlines(),
                      ["when was v0.1.0 tagged?"])
        assert clean == again
        tp2 = os.path.join(root, "tags2.log")
        with open(tp2, "w") as fh:
            fh.write("v0.1.0 2026-09-01\nv0.2.0 2026-09-15\n")
        rc = main(["--readme", rp, "--tags", tp2,
                   "--query", "and 0.2.0?"])
        assert rc == 1, rc  # 0.2.0 tagged but unmentioned in README
        rc = main(["--readme", os.path.join(root, "missing"),
                   "--tags", tp])
        assert rc == 2, rc
    finally:
        shutil.rmtree(root, ignore_errors=True)
    print("readme-drill-audit self-test OK (tag parsing incl. re-tag, "
          "claim extraction incl. decimal negative, drill answering, "
          "orphan/unmentioned findings, rc 0/1/2, determinism)")


if __name__ == "__main__":
    if "--self-test" in sys.argv:
        self_test()  # falls through; rc 0 (mutation probe runs after)
    else:
        raise SystemExit(main())
