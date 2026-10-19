#!/usr/bin/env python3
"""payment-splitter-audit — static audit of payment-splitter / revenue-
share code for the bugs that actually lose money: float division on
monetary amounts, unguarded divisors (ZeroDivisionError), floor-division
that silently drops cents, percent-share tables that do not sum to 100,
negative shares, binary-float money, and per-party rounding without
larger-remainder reconciliation. Audited code is parsed with `ast` and
NEVER executed. Verdict UNSAFE on any BLOCK finding, AT-RISK on WARN,
else CLEAN. rc 0 clean / 1 findings / 2 usage. --harden prints a
hardened largest-remainder reference splitter (integer minor units).

DEMAND: evidence/suggestions/tools-services/2026-10-17.md (11:58 run)
  - request: "payment-splitter code audit (list bugs + hardened
    version)" — evidence: "JOB v1 | k9c9c6513ba | review | Audit this
    snippet: `def div(a,b): return a/b` used in a payment splitter.
    Success: list 2 concrete bugs and a hardened version." — proposed
    service: "code-audit job; not hermes-tools' room-audit scope, but
    repeated (also job IDs k4cf074d765, k8518066ede) and unclaimed —
    could be served by hermes-tools or routed to a code-audit service".
  This tool serves that job offline: input is the snippet file, output
  is named findings (rule id, line, severity) plus a hardened version.
  Every rule is a named deterministic AST check; severity BLOCK means
  money is lost or the splitter crashes on reachable input. Stdlib
  only; nothing from the input is run."""
import argparse
import ast
import hashlib
import inspect
import json
import sys

SEVS = ("BLOCK", "WARN", "INFO")

# rule table: (rule_id, severity, why it loses money)
RULES = (
    ("money-div", "BLOCK",
     "true division `/` on money yields binary floats; split math must "
     "use integer minor units (cents)"),
    ("div-zero-guard", "BLOCK",
     "division with no zero/validity guard in the function -> "
     "ZeroDivisionError on an empty or zero weight/count"),
    ("floor-truncation", "BLOCK",
     "`//` drops the remainder and no redistribution (`%`/`divmod`) is "
     "present: cents vanish from the total"),
    ("share-sum", "BLOCK",
     "percent-share literal collection does not sum to 100: the split "
     "loses (or mints) the difference"),
    ("neg-share", "BLOCK",
     "negative literal in a share collection: one payee pays the other"),
    ("float-money", "WARN",
     "binary-float literal used as money/rate (0.1 is not a cent); use "
     "integer minor units"),
    ("round-drift", "WARN",
     "round() on per-party amounts without larger-remainder "
     "reconciliation: parts drift from the total"),
)
RULE = {r[0]: r for r in RULES}


def parse_source(src):
    """source text -> Module tree (SyntaxError propagates to caller)."""
    return ast.parse(src)


def divisions(fn):
    """function node -> [(op, node)] for `/` and `//` in it."""
    out = []
    for n in ast.walk(fn):
        if isinstance(n, ast.BinOp) and isinstance(n.op, (ast.Div,
                                                          ast.FloorDiv)):
            out.append(("//" if isinstance(n.op, ast.FloorDiv) else "/",
                        n))
    return out


def divisor_terms(node):
    """right operand of a division -> the names it is built from."""
    return {x.id for x in ast.walk(node.right)
            if isinstance(x, ast.Name)}


def guarded(fn):
    """heuristic: does the function defend its divisors? True if it
    compares anything against 0/1, handles ZeroDivisionError, or
    clamps via max(x, 1) / `or 1`."""
    for n in ast.walk(fn):
        if isinstance(n, ast.Compare):
            for c in n.comparators:
                if isinstance(c, ast.Constant) and c.value in (0, 1):
                    return True
        if isinstance(n, ast.ExceptHandler):
            t = n.type
            if isinstance(t, ast.Name) and t.id == "ZeroDivisionError":
                return True
        if (isinstance(n, ast.Call) and isinstance(n.func, ast.Name)
                and n.func.id == "max"
                and any(isinstance(a, ast.Constant) for a in n.args)):
            return True
        if isinstance(n, ast.BoolOp) and isinstance(n.op, ast.Or):
            for v in n.values:
                if isinstance(v, ast.Constant) and v.value == 1:
                    return True
    return False


def has_remainder_work(fn):
    """does the function redistribute the division remainder?"""
    for n in ast.walk(fn):
        if isinstance(n, ast.BinOp) and isinstance(n.op, ast.Mod):
            return True
        if (isinstance(n, ast.Call) and isinstance(n.func, ast.Name)
                and n.func.id == "divmod"):
            return True
    return False


def num_literal(node):
    """expression node -> numeric value for literals (incl. -10)."""
    if (isinstance(node, ast.Constant)
            and isinstance(node.value, (int, float))
            and not isinstance(node.value, bool)):
        return node.value
    if (isinstance(node, ast.UnaryOp)
            and isinstance(node.op, ast.USub)):
        v = num_literal(node.operand)
        return -v if v is not None else None
    return None


def literal_collections(tree):
    """tree -> [(node, [constant values])] for list/tuple/set/dict
    whose elements/values are all numeric literals."""
    out = []
    for n in ast.walk(tree):
        if isinstance(n, (ast.List, ast.Tuple, ast.Set)):
            vals = [num_literal(e) for e in n.elts]
            if len(n.elts) >= 2 and all(v is not None for v in vals):
                out.append((n, vals))
        elif isinstance(n, ast.Dict):
            vals = [num_literal(v) for v in n.values]
            if len(n.values) >= 2 and all(v is not None for v in vals):
                out.append((n, vals))
    return out


def audit(tree, src):
    """AST -> (findings, meta); pure, deterministic, order by line."""
    finds = []
    funcs = [n for n in ast.walk(tree)
             if isinstance(n, ast.FunctionDef)]
    for fn in funcs:
        divs = divisions(fn)
        if divs:
            if not guarded(fn):
                for op, node in divs:
                    finds.append((node.lineno, "div-zero-guard",
                                  f"unguarded `{op}` on line "
                                  f"{node.lineno} in {fn.name}()"))
            for op, node in divs:
                if op == "/":
                    finds.append((node.lineno, "money-div",
                                  f"`/` in {fn.name}() line "
                                  f"{node.lineno} puts money on "
                                  "binary floats"))
                elif not has_remainder_work(fn):
                    finds.append((node.lineno, "floor-truncation",
                                  f"`//` in {fn.name}() line "
                                  f"{node.lineno} with no remainder "
                                  "redistribution"))
        rounds = [n for n in ast.walk(fn)
                  if isinstance(n, ast.Call)
                  and isinstance(n.func, ast.Name)
                  and n.func.id == "round"]
        if rounds and not has_remainder_work(fn):
            finds.append((rounds[0].lineno, "round-drift",
                          f"round() in {fn.name}() line "
                          f"{rounds[0].lineno} without "
                          "larger-remainder reconciliation"))
    for node, vals in literal_collections(tree):
        if any(isinstance(v, (int, float)) and v < 0 for v in vals):
            finds.append((node.lineno, "neg-share",
                          "negative literal in share collection"))
            continue
        ivals = [v for v in vals if isinstance(v, int)]
        if (len(ivals) == len(vals) and max(ivals) <= 100
                and sum(ivals) / len(ivals) >= 10
                and sum(ivals) != 100):
            finds.append((node.lineno, "share-sum",
                          f"percent shares sum to {sum(ivals)}, "
                          "not 100"))
    for n in ast.walk(tree):
        if (isinstance(n, ast.Constant)
                and isinstance(n.value, float)):
            finds.append((getattr(n, "lineno", 0), "float-money",
                          f"binary-float literal {n.value!r} as "
                          "money/rate"))
        elif (isinstance(n, ast.Call) and isinstance(n.func, ast.Name)
                and n.func.id == "float"):
            finds.append((n.lineno, "float-money",
                          "float() casts money onto binary floats"))
    finds.sort(key=lambda f: (f[0], f[1]))
    meta = {"functions": [f.name for f in funcs],
            "lines": len(src.splitlines()),
            "divisions": sum(len(divisions(f)) for f in funcs)}
    return finds, meta


def verdict(findings):
    sevs = {RULE[r][1] for _, r, _ in findings}
    if "BLOCK" in sevs:
        return "UNSAFE"
    if "WARN" in sevs:
        return "AT-RISK"
    return "CLEAN"


def fmt_report(path, meta, findings, digest):
    """human report: named rules first, then summary + verdict."""
    lines = [f"payment-splitter-audit: {path}",
             f"  parsed {meta['lines']} lines, {len(meta['functions'])}"
             f" functions, {meta['divisions']} divisions (code parsed,"
             " never executed)"]
    for ln, rid, why in findings:
        lines.append(f"  line {ln} [{RULE[rid][1]}] {rid}: {why} "
                     f"({RULE[rid][2]})")
    if not findings:
        lines.append("  no splitter anti-patterns matched")
    lines.append(f"  findings: {len(findings)} "
                 f"(digest {digest})")
    lines.append(f"verdict: {verdict(findings)}")
    return "\n".join(lines)


def findings_digest(findings):
    """order/content digest so two auditors agree on the same code."""
    canon = json.dumps([[r[0], r[1], r[2]] for r in findings],
                       sort_keys=True)
    return hashlib.sha256(canon.encode()).hexdigest()[:16]


def split_minor(total_cents, weights):
    """Hardened payment splitter: integer minor units, guarded
    division, largest-remainder reconciliation. It is runnable (the
    self-test executes it) and prints via --harden as the reference."""
    if not isinstance(total_cents, int):
        raise TypeError("total must be integer cents")
    if total_cents < 0:
        raise ValueError("negative total")
    wsum = sum(weights.values())
    if not weights or wsum <= 0:
        raise ValueError("weights must be positive")
    base = {k: (total_cents * w) // wsum for k, w in weights.items()}
    rem = total_cents - sum(base.values())
    order = sorted(weights, key=lambda k: (total_cents * weights[k]) % wsum,
                   reverse=True)
    for k in order:
        if rem <= 0:
            break
        base[k] += 1
        rem -= 1
    assert sum(base.values()) == total_cents
    return base


def main(argv):
    ap = argparse.ArgumentParser(
        description="static payment-splitter code audit (no execution)")
    ap.add_argument("file", help="Python source to audit")
    ap.add_argument("--json", action="store_true",
                    help="machine-readable findings document")
    ap.add_argument("--harden", action="store_true",
                    help="print hardened reference splitter")
    a = ap.parse_args(argv)
    try:
        src = open(a.file, errors="replace").read()
        tree = parse_source(src)
    except OSError:
        print(f"usage: cannot read {a.file}", file=sys.stderr)
        return 2
    except SyntaxError as e:
        print(f"usage: {a.file} does not parse: {e.msg} "
              f"(line {e.lineno})", file=sys.stderr)
        return 2
    findings, meta = audit(tree, src)
    digest = findings_digest(findings)
    v = verdict(findings)
    if a.json:
        print(json.dumps({"file": a.file, "verdict": v,
                          "findings": [{"line": ln, "rule": rid,
                                        "severity": RULE[rid][1],
                                        "detail": why}
                                       for ln, rid, why in findings],
                          "digest": digest, **meta}, ensure_ascii=False))
    else:
        print(fmt_report(a.file, meta, findings, digest))
    if not a.json and (a.harden or v == "UNSAFE"):
        print("\nhardened reference splitter (integer minor units,"
              " guarded, largest remainder):")
        print(inspect.getsource(split_minor))
    return 1 if findings else 0


def self_test():
    import inspect
    import io
    import os
    import tempfile
    from contextlib import redirect_stdout

    def run(src, extra=()):
        with tempfile.TemporaryDirectory() as d:
            p = os.path.join(d, "split.py")
            with open(p, "w") as f:
                f.write(src)
            buf = io.StringIO()
            with redirect_stdout(buf):
                rc = main([p, *extra])
        return rc, buf.getvalue()

    def find(src):
        f, m = audit(parse_source(src), src)
        return {(r, ) for _, r, _ in f}, f, m

    # 1. the filed job snippet: exactly the 2 concrete bugs
    job = "def div(a,b): return a/b\n"
    rset, finds, meta = find(job)
    assert rset == {("money-div",), ("div-zero-guard",)}, rset
    assert all(RULE[r][1] == "BLOCK" for _, r, _ in finds), finds
    assert meta["functions"] == ["div"] and meta["divisions"] == 1, meta

    # 2. floor division: unguarded + dropped remainder
    rset, _, _ = find("def pay(total, n):\n    return total // n\n")
    assert rset == {("div-zero-guard",), ("floor-truncation",)}, rset
    good = ("def pay(total, n):\n"
            "    if n <= 0:\n        raise ValueError('n')\n"
            "    q, r = divmod(total, n)\n    return q, r\n")
    assert find(good)[0] == set(), find(good)[1]

    # 3. float money and drift: named, WARN, verdict AT-RISK
    rset, _, _ = find("FEE = 0.3\n\n\ndef fee(x):\n    return x * FEE\n")
    assert rset == {("float-money",)}, rset
    rset, _, _ = find("def amt(x, w):\n    return round(x * w, 2)\n")
    assert rset == {("round-drift",)}, rset
    assert verdict([("1", "float-money", "w")]) == "AT-RISK"

    # 4. share tables: 99 != 100, dict 110, negatives; 100 passes
    rset, f4, _ = find("SHARES = [33, 33, 33]\n")
    assert rset == {("share-sum",)} and "99" in f4[0][2], f4
    rset, _, _ = find("SHARES = {'a': 70, 'b': 40}\n")
    assert rset == {("share-sum",)}, rset
    rset, _, _ = find("SHARES = [-10, 60, 50]\n")
    assert rset == {("neg-share",)}, rset
    assert find("SHARES = [50, 30, 20]\n")[0] == set()
    assert find("IDS = [1, 2, 3]\n")[0] == set()  # not share-shaped

    # 5. hardened reference: correct largest-remainder math, guarded,
    #    and it audits CLEAN against this tool's own rules
    r = split_minor(100, {"a": 1, "b": 1, "c": 1})
    assert r == {"a": 34, "b": 33, "c": 33} and sum(r.values()) == 100
    r = split_minor(101, {"a": 50, "b": 30, "c": 20})
    assert sum(r.values()) == 101 and max(r.values()) == 51, r
    for bad in [(100.0, {"a": 1}), (-5, {"a": 1}), (100, {}),
                (100, {"a": 0})]:
        try:
            split_minor(*bad)
            raise AssertionError(f"no guard for {bad}")
        except (TypeError, ValueError):
            pass
    rset, _, _ = find(inspect.getsource(split_minor))
    assert rset == set(), rset

    # 6. end-to-end: job file fails with both bugs + hardened output;
    #    clean splitter passes; digests are deterministic
    rc, out = run(job)
    assert rc == 1 and "UNSAFE" in out and "money-div" in out, (rc, out)
    assert "div-zero-guard" in out and "split_minor" in out, out
    rc, out = run(job, ["--json"])
    doc = json.loads(out)
    assert doc["verdict"] == "UNSAFE" and len(doc["findings"]) == 2, doc
    rc2, out2 = run(job, ["--json"])
    assert json.loads(out2)["digest"] == doc["digest"]
    assert doc["digest"] == findings_digest(
        audit(parse_source(job), job)[0])
    rc, out = run(good)
    assert rc == 0 and "CLEAN" in out and "split_minor" not in out
    rc, out = run("X = [33, 33, 33]\n")
    assert rc == 1 and "AT-RISK" not in out and "share-sum" in out

    # 7. usage errors: unreadable file, non-Python file
    buf = io.StringIO()
    with redirect_stdout(buf):
        rc = main(["/nonexistent-split.py"])
    assert rc == 2, rc
    rc, _ = run("def broken(:\n")
    assert rc == 2, rc

    print("payment-splitter-audit self-test OK (7 groups: filed job "
          "snippet yields exactly money-div + div-zero-guard, floor "
          "truncation vs guarded divmod, float-money / round-drift "
          "WARNs, share-table sum/negative checks with non-share "
          "exemption, hardened reference runs correct largest-remainder "
          "math with guards and audits CLEAN, end-to-end verdicts + "
          "JSON + deterministic digest + --harden output, usage "
          "errors)")


if __name__ == "__main__":
    if "--self-test" in sys.argv:
        self_test()  # falls through; rc 0 (probe hook runs after this)
    else:
        raise SystemExit(main(sys.argv[1:]))
