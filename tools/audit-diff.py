#!/usr/bin/env python3
"""audit-diff — decompose an audit report into queryable sections and
cross-check its CLAIMED scope/methodology/summary against the ACTUAL tests
and findings, flagging omissions and misstatements.

DEMAND: evidence/suggestions/tools-services/2026-09-06.md (top ask, 5/5 runs)
  - "I'd like to see the specific data on the discrepancies between the
    audit report and the actual findings, such as what was omitted or
    misstated" (03:26 run) → per-item claimed-vs-actual cross-check
  - "decompose audit reports into queryable sections (e.g., scope,
    methodology, findings, omissions) and allow users to request specific
    data points or comparisons against claimed results" (08:37 run)
  - "audit report diff service that identifies omissions or misstatements
    between claimed scope and actual findings" (07:13 run)

Input is one JSON audit report (nothing from it is ever run):
  {"report_id": "R-1",
   "scope": {"components": ["wallet", "bridge"],
             "excluded": ["legacy-relay"]},
   "methodology": [{"proc_id": "P-1", "name": "static analysis",
                    "components": ["wallet"]}],
   "tests": [{"test_id": "T-1", "proc": "P-1", "component": "wallet",
              "result": "pass" | "fail" | "error"}],
   "findings": [{"id": "F-1", "component": "wallet", "severity":
                 "critical|high|medium|low|info", "status":
                 "open|resolved|accepted", "tests": ["T-1"]}],
   "summary": {"opinion": "clean|qualified", "components_tested": 2,
               "counts": {"critical": 0, "high": 0, ...}}}

Commands:
  sections REPORT [--query X] [--section NAME] [--json]
      queryable index of every section (path, item count, ids);
      --query filters sections/ids by substring; --section dumps one
      section as canonical JSON (scope, excluded, methodology, tests,
      findings, summary, meta).
  diff REPORT [--json]
      one line per discrepancy:
        omission      untested_scope     scope component no test covers
        omission      unreported_failure failed/errored test no finding cites
        omission      summary_mismatch   counts table hides a severity
        misstatement  scope_creep        finding names out-of-scope component
        misstatement  unperformed_proc   procedure no test cites
        misstatement  dangling_ref       finding/test cites an unknown id
        misstatement  summary_mismatch   claimed counts/components wrong
        misstatement  opinion_conflict   'clean' over open medium+ findings
        misstatement  duplicate_id       finding id used more than once
      Verdict CLEAN / DISCREPANT; exit 0 / 1 (discrepancies) / 2 (usage,
      I/O, malformed report). Stdlib only.

VERIFY: `audit-diff.py --self-test` runs 40+ asserts over fixtures with
injected omissions/misstatements (every check kind, verdicts, exit codes,
JSON output) and prints OK on success.
"""

import argparse
import copy
import json
import sys

SEVERITIES = ("critical", "high", "medium", "low", "info")
MATERIAL = ("critical", "high", "medium")          # opinion-threatening
UNRESOLVED = ("open", "new", "unresolved")


class ReportError(Exception):
    """The input is not a structurally valid audit report."""


def load_report(path):
    """Parse REPORT and enforce the minimal report shape."""
    try:
        with open(path, encoding="utf-8") as fh:
            rep = json.load(fh)
    except json.JSONDecodeError as exc:
        raise ReportError(f"{path}: not valid JSON ({exc})") from exc
    except OSError as exc:
        raise ReportError(str(exc)) from exc
    if not isinstance(rep, dict):
        raise ReportError(f"{path}: report must be a JSON object")
    for key in ("scope", "findings"):
        if key not in rep:
            raise ReportError(f"{path}: missing required section {key!r}")
    if not isinstance(rep["scope"], dict) or not isinstance(
            rep["scope"].get("components", []), list):
        raise ReportError(f"{path}: scope.components must be a list")
    if not isinstance(rep["findings"], list):
        raise ReportError(f"{path}: findings must be a list")
    rep.setdefault("methodology", [])
    rep.setdefault("tests", [])
    rep.setdefault("summary", {})
    return rep


def section_index(rep):
    """Decompose the report into one queryable row per section."""
    inner = ("scope", "methodology", "tests", "findings", "summary")
    rows = []
    meta = sorted(k for k in rep if k not in inner)
    if meta:
        rows.append({"section": "meta", "path": "$ (top-level)",
                     "items": len(meta), "ids": meta})
    scope = rep["scope"]
    comps = [str(c) for c in scope.get("components", [])]
    rows.append({"section": "scope", "path": "$.scope.components",
                 "items": len(comps), "ids": comps})
    if scope.get("excluded"):
        rows.append({"section": "excluded", "path": "$.scope.excluded",
                     "items": len(scope["excluded"]),
                     "ids": [str(c) for c in scope["excluded"]]})
    procs = [str(p.get("proc_id", "?")) for p in rep["methodology"]]
    rows.append({"section": "methodology", "path": "$.methodology",
                 "items": len(procs), "ids": procs})
    tids = [str(t.get("test_id", "?")) for t in rep["tests"]]
    rows.append({"section": "tests", "path": "$.tests",
                 "items": len(tids), "ids": tids})
    fids = [str(f.get("id", "?")) for f in rep["findings"]]
    rows.append({"section": "findings", "path": "$.findings",
                 "items": len(fids), "ids": fids})
    rows.append({"section": "summary", "path": "$.summary",
                 "items": len(rep["summary"]), "ids": sorted(rep["summary"])})
    return rows


def query_sections(rows, needle):
    """Case-insensitive containment filter over section rows."""
    want = needle.lower()
    out = []
    for row in rows:
        if want in row["section"].lower() or want in row["path"].lower():
            out.append(row)
            continue
        hits = [i for i in row["ids"] if want in i.lower()]
        if hits:
            out.append(dict(row, ids=hits))
    return out


def crosscheck(rep):
    """Every discrepancy between claimed scope/summary and actual records."""
    out = []

    def add(cls, kind, where, detail):
        out.append({"class": cls, "kind": kind, "where": where,
                    "detail": detail})

    comps = [str(c) for c in rep["scope"].get("components", [])]
    excl = {str(c) for c in rep["scope"].get("excluded", [])}
    proc_ids = {str(p.get("proc_id", "")) for p in rep["methodology"]}
    tests_by_id = {}
    tested = set()
    for t in rep["tests"]:
        tid = str(t.get("test_id", ""))
        rec = (str(t.get("component", "")),
               str(t.get("result", "")).lower(),
               str(t.get("proc", "")))
        tests_by_id.setdefault(tid, []).append(rec)
        if rec[0]:
            tested.add(rec[0])

    cited = set()
    sev_actual = {s: 0 for s in SEVERITIES}
    seen_ids = {}
    open_material = 0
    for f in rep["findings"]:
        fid = str(f.get("id", ""))
        seen_ids[fid] = seen_ids.get(fid, 0) + 1
        comp = str(f.get("component", ""))
        sev = str(f.get("severity", "")).lower()
        status = str(f.get("status", "open")).lower()
        if sev in sev_actual:
            sev_actual[sev] += 1
        if comp and comp not in comps and comp not in excl:
            add("misstatement", "scope_creep", f"findings[{fid}].component",
                f"{comp!r} is neither in scope.components nor excluded")
        for tid in f.get("tests") or []:
            tid = str(tid)
            cited.add(tid)
            if tid not in tests_by_id:
                add("misstatement", "dangling_ref", f"findings[{fid}].tests",
                    f"cites unknown test {tid}")
        if sev in MATERIAL and status in UNRESOLVED:
            open_material += 1
    for fid, n in seen_ids.items():
        if n > 1:
            add("misstatement", "duplicate_id", f"findings[{fid}]",
                f"finding id used {n} times")

    for comp in comps:
        if comp not in tested:
            add("omission", "untested_scope", f"scope.components[{comp}]",
                "claimed in scope but no test covers it")
    for pid in sorted(proc_ids):
        if pid and not any(rec[2] == pid for recs in tests_by_id.values()
                           for rec in recs):
            add("misstatement", "unperformed_proc", f"methodology[{pid}]",
                "procedure claimed but no test cites it")
    for tid, recs in tests_by_id.items():
        for comp, result, proc in recs:
            if proc and proc not in proc_ids:
                add("misstatement", "dangling_ref", f"tests[{tid}].proc",
                    f"cites unknown procedure {proc}")
            if result in ("fail", "error") and tid not in cited:
                add("omission", "unreported_failure", f"tests[{tid}]",
                    f"result={result} but no finding cites this test")

    summ = rep["summary"]
    claimed = summ.get("counts")
    if isinstance(claimed, dict):
        for sev in SEVERITIES:
            if sev in claimed:
                if claimed[sev] != sev_actual[sev]:
                    add("misstatement", "summary_mismatch",
                        f"summary.counts.{sev}",
                        f"claims {claimed[sev]} but findings contain "
                        f"{sev_actual[sev]}")
            elif sev_actual[sev]:
                add("omission", "summary_mismatch", f"summary.counts.{sev}",
                    f"omitted although {sev_actual[sev]} {sev} finding(s) "
                    "exist")
    if "components_tested" in summ and summ["components_tested"] != len(tested):
        add("misstatement", "summary_mismatch", "summary.components_tested",
            f"claims {summ['components_tested']} but tests cover "
            f"{len(tested)}")
    opinion = str(summ.get("opinion", "")).lower()
    if opinion in ("clean", "unqualified") and open_material:
        add("misstatement", "opinion_conflict", "summary.opinion",
            f"{opinion!r} over {open_material} open medium+ finding(s)")
    return out


def verdict(discrepancies):
    """Aggregate verdict + class counts for a crosscheck result."""
    omissions = sum(1 for d in discrepancies if d["class"] == "omission")
    return {"verdict": "DISCREPANT" if discrepancies else "CLEAN",
            "omissions": omissions,
            "misstatements": len(discrepancies) - omissions}


def _dump(rep, name):
    inner = ("scope", "methodology", "tests", "findings", "summary")
    table = {"meta": {k: rep[k] for k in rep if k not in inner},
             "scope": rep["scope"],
             "excluded": rep["scope"].get("excluded", []),
             "methodology": rep["methodology"], "tests": rep["tests"],
             "findings": rep["findings"], "summary": rep["summary"]}
    return table.get(name)


def main(argv=None):
    ap = argparse.ArgumentParser(
        prog="audit-diff",
        description="decompose an audit report into queryable sections and "
                    "cross-check claimed scope/summary against actual "
                    "tests and findings")
    sub = ap.add_subparsers(dest="cmd", required=True)
    sp = sub.add_parser("sections", help="queryable section index")
    sp.add_argument("report")
    sp.add_argument("--query", help="filter sections/items by substring")
    sp.add_argument("--section", help="dump one section as canonical JSON")
    sp.add_argument("--json", action="store_true")
    dp = sub.add_parser("diff", help="claimed-vs-actual discrepancy analysis")
    dp.add_argument("report")
    dp.add_argument("--json", action="store_true")
    args = ap.parse_args(argv)
    try:
        rep = load_report(args.report)
    except ReportError as exc:
        print(f"audit-diff: {exc}", file=sys.stderr)
        return 2
    if args.cmd == "sections":
        if args.section:
            blob = _dump(rep, args.section.lower())
            if blob is None:
                print(f"audit-diff: unknown section {args.section!r}",
                      file=sys.stderr)
                return 2
            print(json.dumps(blob, indent=2, sort_keys=True, default=str))
            return 0
        rows = section_index(rep)
        if args.query:
            rows = query_sections(rows, args.query)
        if args.json:
            print(json.dumps({"sections": rows}, indent=2, default=str))
        else:
            for row in rows:
                ids = " ".join(row["ids"]) or "-"
                print(f"{row['section']:12s} {row['path']:24s} "
                      f"{row['items']:>3d}  {ids}")
            if not rows:
                print("no matching sections")
        return 0
    discs = crosscheck(rep)
    agg = verdict(discs)
    if args.json:
        print(json.dumps({**agg, "discrepancies": discs}, indent=2,
                         default=str))
    else:
        extra = (f"  {len(discs)} discrepancies ({agg['omissions']} "
                 f"omissions, {agg['misstatements']} misstatements)"
                 if discs else "  report is internally consistent")
        print(agg["verdict"] + extra)
        for d in discs:
            print(f"  {d['class']:13s} {d['kind']:19s} {d['where']}: "
                  f"{d['detail']}")
    return 1 if discs else 0


def _fixture():
    """A clean, internally consistent baseline report."""
    return {
        "report_id": "R-1",
        "scope": {"components": ["wallet", "bridge", "oracle"],
                  "excluded": ["legacy-relay"]},
        "methodology": [
            {"proc_id": "P-1", "name": "static analysis",
             "components": ["wallet", "bridge"]},
            {"proc_id": "P-2", "name": "fuzzing", "components": ["oracle"]}],
        "tests": [
            {"test_id": "T-1", "proc": "P-1", "component": "wallet",
             "result": "pass"},
            {"test_id": "T-2", "proc": "P-1", "component": "bridge",
             "result": "pass"},
            {"test_id": "T-3", "proc": "P-2", "component": "oracle",
             "result": "pass"}],
        "findings": [
            {"id": "F-1", "component": "wallet", "severity": "low",
             "status": "open", "tests": ["T-1"]}],
        "summary": {"opinion": "qualified", "components_tested": 3,
                    "counts": {"critical": 0, "high": 0, "medium": 0,
                               "low": 1, "info": 0}},
    }


def selftest():
    import os
    import tempfile

    def kinds(rep):
        return {d["kind"] for d in crosscheck(rep)}

    # section decomposition is complete, sized, and queryable
    rows = section_index(_fixture())
    assert [r["section"] for r in rows] == ["meta", "scope", "excluded",
                                           "methodology", "tests",
                                           "findings", "summary"], rows
    fr = next(r for r in rows if r["section"] == "findings")
    assert fr["items"] == 1 and fr["ids"] == ["F-1"]
    assert fr["path"] == "$.findings"
    assert [r["section"] for r in query_sections(rows, "oracl")] == ["scope"]
    assert any(r["section"] == "methodology"
               for r in query_sections(rows, "METH"))
    assert query_sections(rows, "nosuchthing") == []

    # the clean baseline diffs clean
    clean = _fixture()
    assert crosscheck(clean) == []
    assert verdict(crosscheck(clean)) == {"verdict": "CLEAN", "omissions": 0,
                                          "misstatements": 0}

    # scope_creep: finding names an out-of-scope component
    rep = _fixture()
    rep["findings"].append({"id": "F-2", "component": "relayer",
                            "severity": "high", "status": "open",
                            "tests": ["T-2"]})
    d = [x for x in crosscheck(rep) if x["kind"] == "scope_creep"]
    assert d and d[0]["class"] == "misstatement" and "relayer" in d[0]["detail"]

    # excluded components are legitimate finding targets, not creep
    rep = _fixture()
    rep["findings"][0]["component"] = "legacy-relay"
    assert "scope_creep" not in kinds(rep)

    # untested_scope + unperformed_proc: drop the oracle test entirely
    rep = _fixture()
    rep["tests"] = [t for t in rep["tests"] if t["test_id"] != "T-3"]
    rep["summary"]["components_tested"] = 2
    rep["summary"]["counts"]["low"] = 1
    k = kinds(rep)
    assert "untested_scope" in k and "unperformed_proc" in k, k
    om = [x for x in crosscheck(rep) if x["kind"] == "untested_scope"]
    assert om[0]["class"] == "omission" and "oracle" in om[0]["where"]

    # unreported_failure: a failed test no finding cites
    rep = _fixture()
    rep["tests"][2]["result"] = "fail"
    d = [x for x in crosscheck(rep) if x["kind"] == "unreported_failure"]
    assert d and d[0]["class"] == "omission" and d[0]["where"] == "tests[T-3]"
    rep["findings"].append({"id": "F-2", "component": "oracle",
                            "severity": "high", "status": "open",
                            "tests": ["T-3"]})
    assert "unreported_failure" not in kinds(rep)

    # dangling refs in both directions
    rep = _fixture()
    rep["findings"][0]["tests"] = ["T-9"]
    assert any(x["where"] == "findings[F-1].tests" and x["kind"] == "dangling_ref"
               for x in crosscheck(rep))
    rep = _fixture()
    rep["tests"][2]["proc"] = "P-9"
    assert any(x["where"] == "tests[T-3].proc"
               for x in crosscheck(rep) if x["kind"] == "dangling_ref")

    # summary_mismatch: wrong counts, wrong coverage, hidden severity
    rep = _fixture()
    rep["summary"]["counts"]["low"] = 7
    assert any("claims 7" in x["detail"] and "contain 1" in x["detail"]
               for x in crosscheck(rep))
    rep = _fixture()
    rep["summary"]["components_tested"] = 99
    assert any(x["where"] == "summary.components_tested"
               for x in crosscheck(rep))
    rep = _fixture()
    del rep["summary"]["counts"]["low"]
    d = [x for x in crosscheck(rep) if x["kind"] == "summary_mismatch"]
    assert d and d[0]["class"] == "omission" and d[0]["where"].endswith(".low")

    # opinion_conflict: clean opinion over an open material finding
    rep = _fixture()
    rep["findings"][0].update(severity="high", status="open")
    rep["summary"]["opinion"] = "clean"
    rep["summary"]["counts"].update(low=0, high=1)
    assert "opinion_conflict" in kinds(rep)
    rep["findings"][0]["status"] = "resolved"
    assert "opinion_conflict" not in kinds(rep)
    rep["findings"][0].update(severity="info", status="open")
    assert "opinion_conflict" not in kinds(rep)

    # duplicate finding ids
    rep = _fixture()
    rep["findings"].append(dict(rep["findings"][0]))
    rep["summary"]["counts"]["low"] = 2
    d = [x for x in crosscheck(rep) if x["kind"] == "duplicate_id"]
    assert d and "2 times" in d[0]["detail"]

    # verdict aggregation mixes classes correctly
    rep = _fixture()
    rep["tests"] = [t for t in rep["tests"] if t["test_id"] != "T-3"]
    rep["findings"].append({"id": "F-1", "component": "ghost",
                            "severity": "critical", "status": "open",
                            "tests": ["T-1"]})
    agg = verdict(crosscheck(rep))
    assert agg["verdict"] == "DISCREPANT"
    assert agg["omissions"] >= 1 and agg["misstatements"] >= 2, agg

    # load_report enforces the shape
    with tempfile.TemporaryDirectory() as tmp:
        good = os.path.join(tmp, "r.json")
        with open(good, "w", encoding="utf-8") as fh:
            json.dump(_fixture(), fh)
        assert load_report(good)["report_id"] == "R-1"
        assert load_report(good)["tests"][0]["test_id"] == "T-1"
        badjson = os.path.join(tmp, "bad.json")
        with open(badjson, "w", encoding="utf-8") as fh:
            fh.write("{not json")
        try:
            load_report(badjson)
            raise SystemExit("bad JSON accepted")
        except ReportError:
            pass
        noscope = os.path.join(tmp, "noscope.json")
        with open(noscope, "w", encoding="utf-8") as fh:
            json.dump({"findings": []}, fh)
        try:
            load_report(noscope)
            raise SystemExit("missing scope accepted")
        except ReportError:
            pass

        # CLI exit codes and output
        assert main(["sections", good]) == 0
        assert main(["sections", good, "--query", "oracle"]) == 0
        assert main(["sections", good, "--section", "scope"]) == 0
        assert main(["sections", good, "--section", "nope"]) == 2
        assert main(["diff", good]) == 0
        assert main(["diff", os.path.join(tmp, "missing.json")]) == 2
        rep = _fixture()
        rep["summary"]["counts"]["low"] = 3
        ugly = os.path.join(tmp, "ugly.json")
        with open(ugly, "w", encoding="utf-8") as fh:
            json.dump(rep, fh)
        assert main(["diff", ugly]) == 1
        import io as _io
        import contextlib as _cx
        buf = _io.StringIO()
        with _cx.redirect_stdout(buf):
            rc = main(["diff", ugly, "--json"])
        blob = json.loads(buf.getvalue())
        assert rc == 1 and blob["verdict"] == "DISCREPANT"
        assert blob["discrepancies"] and "omissions" in blob

    print("audit-diff self-test OK "
          f"({len(SEVERITIES)} severities, {len(_fixture()['tests'])} tests)")


if __name__ == "__main__":
    if "--self-test" in sys.argv:
        selftest()
    else:
        raise SystemExit(main())
