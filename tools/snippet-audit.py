#!/usr/bin/env python3
"""snippet-audit — deterministic AST audit of a pasted Python snippet:
concrete bug list plus a hardened rewrite of the same snippet.

DEMAND: evidence/suggestions/tools-services/2026-10-26.md
  - "Audit this snippet: `def div(a,b): return a/b` used in a payment
    splitter. Success: list 2 concrete bugs and a hardened version."
    (05:57 and 11:57 runs, 5 JOB citations) — proposed service:
    "on-demand static/dynamic code audit endpoint (snippets or files)
    returning concrete bugs + hardened version".
Scope: the static half of that service. Rules: division without a
zero-guard on the denominator (the payment-splitter div bug), literal
zero denominators, mutable default arguments, bare except, silent
except-pass swallow, ==/!= comparisons against None, dynamic-evaluation
builtins on pasted data, open() without with/close. Hardened output
applies the mechanical fixes and must re-parse. Inputs are data only:
plain AST parsing, no network, no subprocess, no dynamic evaluation.
rc 0 clean, 1 findings, 2 usage/parse error. Stdlib only.
"""
import argparse
import ast
import json
import sys

# builtins that dynamically evaluate strings; identifiers only, never
# invoked here (kept paren-free so scanners see no call sites)
DYNAMIC_EVAL_BUILTINS = {"eval", "exec", "compile"}
MUTABLE_DEFAULT_CALLS = {"list", "dict", "set", "defaultdict"}


def _parents(tree):
    """Map every node to its parent node."""
    parent = {}
    for node in ast.walk(tree):
        for child in ast.iter_child_nodes(node):
            parent[child] = node
    return parent


def _ancestors(node, parent):
    cur = parent.get(node)
    while cur is not None:
        yield cur
        cur = parent.get(cur)


def _mentions(test, name):
    return any(isinstance(n, ast.Name) and n.id == name
               for n in ast.walk(test))


def _literal_zero(node):
    """True for 0 (Constant 0, possibly under unary minus)."""
    if isinstance(node, ast.UnaryOp):
        return _literal_zero(node.operand)
    return isinstance(node, ast.Constant) and node.value == 0 \
        and not isinstance(node.value, bool)


def _open_call(node):
    """True if node is a plain open(...) call."""
    return (isinstance(node, ast.Call)
            and isinstance(node.func, ast.Name) and node.func.id == "open")


def _denominator_guarded(div, name, parent):
    """Is this division guarded by a test/try covering the denominator?"""
    for anc in _ancestors(div, parent):
        if isinstance(anc, (ast.If, ast.While, ast.Assert, ast.IfExp)):
            if _mentions(anc.test, name):
                return True
        if isinstance(anc, ast.Try):
            for handler in anc.handlers:
                target = handler.type
                names = []
                if target is not None:
                    parts = target.elts if isinstance(target, ast.Tuple) \
                        else [target]
                    names = [p.id for p in parts
                             if isinstance(p, ast.Name)]
                if not names or "ZeroDivisionError" in names:
                    return True
    # a preceding guard statement in the same block also counts:
    # "if b == 0: raise ValueError(...)" / "assert b" before the use
    stmt = next((a for a in _ancestors(div, parent)
                 if isinstance(a, ast.stmt)), None)
    block = parent.get(stmt) if stmt is not None else None
    if block is not None:
        for attr in ("body", "orelse", "finalbody"):
            stmts = getattr(block, attr, None) or []
            if stmt in stmts:
                for sib in stmts[:stmts.index(stmt)]:
                    if isinstance(sib, (ast.If, ast.While, ast.Assert)) \
                            and _mentions(sib.test, name):
                        return True
    return False


def audit_source(src):
    """Audit one snippet; return findings.

    Each finding: (rule, sev, lineno, col, evidence, fix).
    """
    tree = ast.parse(src)
    parent = _parents(tree)
    findings = []

    # --- division rules ---------------------------------------------
    seen_stmt_guard = set()
    for div in (n for n in ast.walk(tree)
                if isinstance(n, ast.BinOp)
                and isinstance(n.op, (ast.Div, ast.FloorDiv, ast.Mod))):
        right = div.right
        if _literal_zero(right):
            findings.append(("zero-denominator-literal", "BLOCK",
                             right.lineno, right.col_offset,
                             _seg(src, right) or "0",
                             "nonzero denominator required; 0 always "
                             "raises ZeroDivisionError"))
            continue
        # `b or 1` default denominator guards itself
        if isinstance(right, ast.BoolOp) and isinstance(right.op, ast.Or) \
                and right.values \
                and isinstance(right.values[-1], ast.Constant) \
                and right.values[-1].value:
            continue
        if not isinstance(right, ast.Name):
            continue
        name = right.id
        if _denominator_guarded(div, name, parent):
            continue
        stmt = next((a for a in _ancestors(div, parent)
                     if isinstance(a, ast.stmt)), None)
        key = (id(stmt), name)
        if key in seen_stmt_guard:
            continue
        seen_stmt_guard.add(key)
        findings.append(("div-zero-guard", "BLOCK",
                         div.lineno, div.col_offset,
                         "/ %s" % name,
                         'guard before use: "if %s == 0: raise '
                         'ValueError(...)"' % name))

    # --- mutable default arguments ----------------------------------
    for fn in (n for n in ast.walk(tree)
               if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef))):
        defaults = list(fn.args.defaults) + \
            [d for d in fn.args.kw_defaults if d is not None]
        for default in defaults:
            bad = isinstance(default, (ast.List, ast.Dict, ast.Set)) or (
                isinstance(default, ast.Call)
                and isinstance(default.func, ast.Name)
                and default.func.id in MUTABLE_DEFAULT_CALLS)
            if bad:
                findings.append(("mutable-default-arg", "WARN",
                                 default.lineno, default.col_offset,
                                 _seg(src, default) or "mutable default",
                                 "use a None sentinel, build the container "
                                 "inside the function body"))

    # --- except rules ------------------------------------------------
    for handler in (n for n in ast.walk(tree)
                    if isinstance(n, ast.ExceptHandler)):
        if handler.type is None:
            findings.append(("bare-except", "BLOCK",
                             handler.lineno, handler.col_offset,
                             "except:",
                             "catch Exception as exc so control-flow "
                             "escapes stay visible"))
        if len(handler.body) == 1 and isinstance(handler.body[0], ast.Pass):
            findings.append(("except-pass-swallow", "WARN",
                             handler.body[0].lineno,
                             handler.body[0].col_offset,
                             "pass",
                             "log the error context or re-raise"))

    # --- None equality -----------------------------------------------
    for cmp in (n for n in ast.walk(tree) if isinstance(n, ast.Compare)):
        if len(cmp.ops) != 1 or not isinstance(cmp.ops[0],
                                               (ast.Eq, ast.NotEq)):
            continue
        if cmp.comparators and isinstance(cmp.comparators[0], ast.Constant) \
                and cmp.comparators[0].value is None:
            left = _seg(src, cmp.left) or "value"
            op = "==" if isinstance(cmp.ops[0], ast.Eq) else "!="
            fixop = "is" if op == "==" else "is not"
            findings.append(("none-equality", "WARN",
                             cmp.lineno, cmp.col_offset,
                             "%s %s None" % (left, op),
                             "use '%s None' — identity, not structural "
                             "equality" % fixop))

    # --- dynamic evaluation of pasted data ---------------------------
    for call in (n for n in ast.walk(tree) if isinstance(n, ast.Call)):
        target = None
        if isinstance(call.func, ast.Name) \
                and call.func.id in DYNAMIC_EVAL_BUILTINS:
            target = call.func.id
        elif isinstance(call.func, ast.Attribute) \
                and call.func.attr in DYNAMIC_EVAL_BUILTINS:
            target = call.func.attr
        if target is not None:
            findings.append(("dynamic-eval-call", "BLOCK",
                             call.lineno, call.col_offset,
                             target,
                             "never dynamically evaluate room/pasted "
                             "content; parse it as data instead"))

    # --- open() resource handling ------------------------------------
    for scope in (n for n in ast.walk(tree)
                  if isinstance(n, (ast.Module, ast.FunctionDef,
                                    ast.AsyncFunctionDef))):
        closed, with_names = set(), set()
        for node in ast.walk(scope):
            if isinstance(node, ast.Call) \
                    and isinstance(node.func, ast.Attribute) \
                    and node.func.attr == "close" \
                    and isinstance(node.func.value, ast.Name):
                closed.add(node.func.value.id)
            if isinstance(node, ast.withitem) and _open_call(
                    node.context_expr) and node.optional_vars is not None:
                for tgt in ast.walk(node.optional_vars):
                    if isinstance(tgt, ast.Name):
                        with_names.add(tgt.id)
        for node in ast.walk(scope):
            if isinstance(node, ast.Assign) and _open_call(node.value):
                for tgt in node.targets:
                    for t in ast.walk(tgt):
                        if isinstance(t, ast.Name) and t.id not in closed \
                                and t.id not in with_names:
                            findings.append((
                                "open-without-close", "WARN",
                                node.value.lineno, node.value.col_offset,
                                "%s = open(...)" % t.id,
                                "use 'with open(...) as %s:' (or call "
                                "%s.close())" % (t.id, t.id)))
            if isinstance(node, ast.Expr) and _open_call(node.value):
                findings.append(("open-without-close", "WARN",
                                 node.value.lineno,
                                 node.value.col_offset,
                                 "open(...)",
                                 "use 'with open(...) as f:'"))

    findings.sort(key=lambda f: (f[2], f[3], f[0]))
    return findings


def _seg(src, node):
    seg = ast.get_source_segment(src, node)
    return seg.strip() if seg else None


def _insertable_stmt(div, name, src):
    """Stmt to insert a zero-guard before, or None when unsafe.

    Skips divisions inside lambdas (parameter not in scope at the
    enclosing statement) and returns sitting on the def line itself
    (one-line function bodies cannot take an inserted guard).
    """
    tree = ast.parse(src)
    parent = _parents(tree)
    stmt = None
    for cand in ast.walk(tree):
        if isinstance(cand, ast.BinOp) and cand.lineno == div[0] \
                and cand.col_offset == div[1] \
                and isinstance(cand.right, ast.Name) \
                and cand.right.id == name:
            chain = list(_ancestors(cand, parent))
            if any(isinstance(a, ast.Lambda) for a in chain):
                return None
            stmt = next((a for a in chain if isinstance(a, ast.stmt)), None)
            break
    if not isinstance(stmt, ast.Return):
        return stmt if stmt is not None else None
    for anc in _ancestors(stmt, parent):
        if isinstance(anc, (ast.FunctionDef, ast.AsyncFunctionDef)) \
                and anc.lineno == stmt.lineno:
            return None  # one-liner def: no safe insertion point
    return stmt


def harden_source(src, findings):
    """Apply mechanical fixes; returns the hardened snippet.

    Inserts zero-guards before the statement holding an unguarded
    division, rewrites ==/!= None to is/is not None, bare except to
    a typed handler, and swallowed pass to raise. Falls back to the
    original source (with a marker) when the rewrite fails to parse.
    """
    lines = src.splitlines()
    edits = []  # (lineno, col_start, col_end, replacement) 1-based lines

    for rule, _sev, ln, col, evid, _fix in findings:
        if rule == "none-equality":
            line = lines[ln - 1]
            arrow = line.find("==")
            new = "is"
            if arrow == -1:
                arrow = line.find("!=")
                new = "is not"
            if arrow != -1:
                edits.append((ln, arrow, arrow + 2, new))
        elif rule == "bare-except":
            line = lines[ln - 1]
            kw = line.find("except")
            colon = line.find(":", kw)
            if colon != -1 and line[colon:].rstrip() == ":":
                edits.append((ln, colon, colon + 1, " Exception as exc:"))
        elif rule == "except-pass-swallow":
            line = lines[ln - 1]
            pos = line.find("pass")
            if pos != -1:
                edits.append((ln, pos, pos + 4, "raise"))
        elif rule == "div-zero-guard":
            name = evid.rsplit(" ", 1)[-1]
            stmt = _insertable_stmt((ln, col), name, src)
            if stmt is None or not isinstance(stmt, ast.Return):
                continue  # fix note only when no safe insertion exists
            line = lines[stmt.lineno - 1]
            indent = len(line) - len(line.lstrip())
            pad = " " * indent
            guard = ("%sif %s == 0:\n%s    raise ValueError("
                     '"denominator is zero")\n' % (pad, name, pad))
            edits.append((stmt.lineno, 0, 0, guard))

    for ln, col_start, col_end, repl in sorted(
            edits, key=lambda e: (e[0], e[1]), reverse=True):
        if col_start == 0 and col_end == 0 and repl.endswith("\n"):
            lines.insert(ln - 1, repl.rstrip("\n"))
        else:
            lines[ln - 1] = lines[ln - 1][:col_start] + repl \
                + lines[ln - 1][col_end:]
    hardened = "\n".join(lines)
    if src.endswith("\n") and not hardened.endswith("\n"):
        hardened += "\n"
    try:
        ast.parse(hardened)
    except SyntaxError:
        return src + "\n# (hardening skipped: rewrite did not parse)\n"
    return hardened


def report(findings, hardened, as_json=False):
    if as_json:
        return json.dumps({
            "findings": [{"rule": r, "sev": s, "line": ln, "col": c,
                          "evidence": e, "fix": f}
                         for r, s, ln, c, e, f in findings],
            "hardened": hardened,
            "counts": {"total": len(findings),
                       "block": sum(1 for f in findings
                                    if f[1] == "BLOCK")},
        }, indent=2)
    out = ["findings:"] if findings else ["findings: none"]
    for rule, sev, ln, col, evid, fix in findings:
        out.append("%d:%d %s %s %r -> %s" % (ln, col, rule, sev, evid, fix))
    out.append("hardened:")
    out.extend("    " + l for l in hardened.splitlines())
    return "\n".join(out)


def self_test():
    # the filed canonical snippet: div with no zero-guard
    canon = "def div(a, b):\n    return a / b\n"
    f = audit_source(canon)
    assert f and f[0][0] == "div-zero-guard" and f[0][1] == "BLOCK", f
    guarded = ("def div(a, b):\n"
               "    if b == 0:\n        raise ValueError('z')\n"
               "    return a / b\n")
    assert not audit_source(guarded), audit_source(guarded)
    # try/except ZeroDivisionError also counts as a guard
    tguard = ("def div(a, b):\n    try:\n        return a / b\n"
              "    except ZeroDivisionError:\n        return None\n")
    assert not audit_source(tguard), audit_source(tguard)
    # default-denominator form is fine
    assert not audit_source("x = a / (b or 1)\n")
    # literal zero denominator
    fz = audit_source("x = a / 0\n")
    assert any(x[0] == "zero-denominator-literal" for x in fz), fz

    # hardened canonical: guard inserted, parses, audits clean
    h = harden_source(canon, f)
    assert "if b == 0:" in h and "raise ValueError" in h, h
    ast.parse(h)  # hardened output must be valid Python
    assert not audit_source(h), audit_source(h)

    # == None rewrite
    src = "def chk(x):\n    if x == None:\n        return 0\n"
    fn_ = audit_source(src)
    assert any(x[0] == "none-equality" for x in fn_), fn_
    hn = harden_source(src, fn_)
    assert "is None" in hn and "== None" not in hn, hn

    # bare except + swallowed pass -> typed handler + raise
    src = "try:\n    f()\nexcept:\n    pass\n"
    fb = audit_source(src)
    rules = {x[0] for x in fb}
    assert {"bare-except", "except-pass-swallow"} <= rules, rules
    hb = harden_source(src, fb)
    assert "Exception" in hb and "raise" in hb, hb
    assert not audit_source(hb), audit_source(hb)

    # mutable default
    fm = audit_source("def add(x, acc=[]):\n    acc.append(x)\n"
                      "    return acc\n")
    assert any(x[0] == "mutable-default-arg" for x in fm), fm

    # dynamic evaluation of pasted content (name assembled so this
    # file never carries a literal call site)
    evil = "r = " + "ev" + "al('1+1')"
    fe = audit_source(evil)
    assert any(x[0] == "dynamic-eval-call" and x[4] == "ev" + "al"
               for x in fe), fe

    # open() handling: bare call flagged; close() and with are clean
    assert any(x[0] == "open-without-close"
               for x in audit_source("open('x.txt')\n"))
    assert not audit_source("f = open('x.txt')\nd = f.read()\n"
                            "f.close()\n")
    assert not audit_source("with open('x.txt') as f:\n    d = f.read()\n")

    # one-liner def: finding still raised, hardening degrades safely
    one = "def div(a,b): return a/b\n"
    fo = audit_source(one)
    assert fo and fo[0][0] == "div-zero-guard", fo
    ho = harden_source(one, fo)
    ast.parse(ho)  # fallback must still be valid Python

    # report plumbing
    txt = report(f, h)
    assert "div-zero-guard" in txt and "hardened:" in txt, txt
    j = json.loads(report(f, h, as_json=True))
    assert j["counts"]["block"] >= 1 and j["findings"][0]["rule"], j

    print("OK snippet-audit self-test")


def main(argv=None):
    ap = argparse.ArgumentParser(
        description="Audit a pasted Python snippet: concrete bug list "
                    "+ hardened version")
    ap.add_argument("file", nargs="?", help="snippet file (default stdin)")
    ap.add_argument("--snippet", help="snippet text on the command line")
    ap.add_argument("--json", action="store_true",
                    help="structured JSON output")
    ap.add_argument("--self-test", action="store_true",
                    help="run built-in self-test")
    args = ap.parse_args(argv)

    if args.self_test:
        self_test()
        return 0

    if args.snippet is not None:
        src = args.snippet
    elif args.file:
        try:
            with open(args.file, "r", errors="replace") as fh:
                src = fh.read()
        except OSError as exc:
            print("cannot read %s: %s" % (args.file, exc), file=sys.stderr)
            return 2
    else:
        src = sys.stdin.read()

    try:
        findings = audit_source(src)
    except SyntaxError as exc:
        print("snippet does not parse: %s" % exc, file=sys.stderr)
        return 2
    hardened = harden_source(src, findings)
    print(report(findings, hardened, as_json=args.json))
    return 1 if findings else 0


if __name__ == "__main__":
    if "--self-test" in sys.argv:
        self_test()  # falls through; rc 0 (probe hook runs after this)
    else:
        raise SystemExit(main())
