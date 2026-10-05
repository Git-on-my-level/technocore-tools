#!/usr/bin/env python3
"""constant-time-compare-audit — timing-safety audit for secret
comparisons: static scan of captured source plus variance analysis of
comparison-latency captures.

DEMAND: evidence/suggestions/tools-services/2026-09-08.md (09:35 run)
  - "Continuous background data-integrity verification for
    constant-time comparison without locking production tables" —
    evidence: "Auditing data integrity across a constant-time
    comparison without locking production tables" (11:21) — proposed
    service: "Timing-safe comparison audit to detect variance
    side-channel regressions".
Scope: both halves of that service. Static: find secret-bearing
comparisons that early-exit (==, !=, <, >, in, startswith/endswith)
where hmac.compare_digest belongs, guarded against metadata subscripts
(key["kty"]) and call results (len(token_a) != len(token_b)).
Dynamic: per-label Pearson correlation of match length vs latency —
the regression test for variance side-channels. Inputs are data only:
plain parsing, no network, no subprocess. rc 0 clean (INFO-only),
1 BLOCK/WARN findings, 2 usage/IO. Stdlib only.
"""
import argparse
import ast
import json
import math
import re
import sys

# identifier segments that mark a value as secret (exact segment match,
# so "machine" never matches "mac")
SECRET_SEGS = {
    "token", "secret", "password", "passwd", "signature", "sig", "mac",
    "hmac", "digest", "cookie", "otp", "bearer", "credential",
    "credentials", "passphrase", "apikey", "privatekey", "sessionkey",
}
KEY_QUALIFIERS = {"api", "access", "session", "signing", "master", "client"}
# subscript metadata keys: secret["alg"] == "HS256" compares metadata,
# not secret material — stays silent
META_KEYS = {
    "alg", "kty", "kid", "use", "crv", "typ", "version", "ver", "id",
    "name", "type", "status", "exp", "iat", "nbf", "len", "length",
    "count", "size", "format", "curve", "method", "mode", "kind", "key",
}
LEN_KEYS = ("match_len", "prefix_len", "overlap", "len", "n")
NS_KEYS = ("ns", "nanos", "dur_ns")
BLOCK_R, WARN_R = 0.60, 0.35  # Pearson thresholds for timing findings


def secret_name(name):
    """Any _-segment is a secret word or key compound (signing_key)."""
    segs = {s for s in re.split(r"[^a-z0-9]+", name.lower()) if s}
    if segs & SECRET_SEGS:
        return True
    return "key" in segs and bool(segs & KEY_QUALIFIERS)


def _meta_key(sub):
    """True when a subscript indexes metadata (key["kty"]), not material."""
    key = sub.slice
    if not isinstance(key, ast.Constant):
        key = getattr(key, "value", key)  # legacy ast.Index wrapper
    return (isinstance(key, ast.Constant) and isinstance(key.value, str)
            and key.value.lower() in META_KEYS)


def is_secret(node):
    """Secret-named leaf in this expression? Calls are opaque (the
    len(tok) == len(mac) guard); metadata subscripts and containers
    recurse past non-secret parts only."""
    if isinstance(node, ast.Call):
        return False
    if isinstance(node, ast.Name):
        return secret_name(node.id)
    if isinstance(node, ast.Attribute):
        return is_secret(node.value) or secret_name(node.attr)
    if isinstance(node, ast.Subscript):
        return False if _meta_key(node) else is_secret(node.value)
    if isinstance(node, (ast.Tuple, ast.List, ast.Set)):
        return any(is_secret(e) for e in node.elts)
    if isinstance(node, ast.BinOp):
        return is_secret(node.left) or is_secret(node.right)
    return False


def secret_leaves(node, out):
    """Names of the secret leaves an expression carries (for messages)."""
    if isinstance(node, ast.Call):
        return
    if isinstance(node, ast.Name) and secret_name(node.id):
        out.append(node.id)
    elif isinstance(node, ast.Attribute):
        secret_leaves(node.value, out)
        if secret_name(node.attr):
            out.append(node.attr)
    elif isinstance(node, ast.Subscript):
        if not _meta_key(node):
            secret_leaves(node.value, out)
    elif isinstance(node, (ast.Tuple, ast.List, ast.Set)):
        for e in node.elts:
            secret_leaves(e, out)
    elif isinstance(node, ast.BinOp):
        secret_leaves(node.left, out)
        secret_leaves(node.right, out)


def _finding(kind, sev, origin, line, detail):
    return {"kind": kind, "severity": sev, "origin": origin,
            "line": line, "detail": detail}


def scan_python(src, origin):
    """AST scan of one Python source capture -> findings."""
    finds = []
    tree = ast.parse(src)
    for node in ast.walk(tree):
        if isinstance(node, ast.Compare):
            named = []
            for e in [node.left] + list(node.comparators):
                secret_leaves(e, named)
            if not named:
                continue
            line = getattr(node, "lineno", 0)
            who = ", ".join(sorted(set(named)))
            if any(isinstance(o, (ast.In, ast.NotIn)) for o in node.ops):
                right = node.comparators[0]
                lit = isinstance(right, (ast.Tuple, ast.List))
                sev = "BLOCK" if (is_secret(node.left) or lit) else "WARN"
                finds.append(_finding(
                    "membership-scan", sev, origin, line,
                    "'in' scan over secrets [%s] — linear or hash-order "
                    "membership; use compare_digest per entry" % who))
            else:
                opmap = {ast.Eq: "==", ast.NotEq: "!=", ast.Lt: "<",
                         ast.LtE: "<=", ast.Gt: ">", ast.GtE: ">="}
                opname = next(v for k, v in opmap.items()
                              if isinstance(node.ops[0], k))
                finds.append(_finding(
                    "data-dependent-compare", "BLOCK", origin, line,
                    "comparison '%s' involves secret [%s] — early-exit "
                    "byte scan; use hmac.compare_digest"
                    % (opname, who)))
        elif isinstance(node, ast.Call):
            f = node.func
            if (isinstance(f, ast.Attribute)
                    and f.attr in ("startswith", "endswith")
                    and is_secret(f.value)):
                names = []
                secret_leaves(f.value, names)
                finds.append(_finding(
                    "prefix-early-exit", "BLOCK", origin,
                    getattr(node, "lineno", 0),
                    "'%s' on secret [%s] — match length leaks via timing"
                    % (f.attr, ", ".join(sorted(set(names))))))
            elif (isinstance(f, ast.Attribute)
                    and f.attr == "compare_digest"):
                finds.append(_finding(
                    "compare-digest-used", "INFO", origin,
                    getattr(node, "lineno", 0),
                    "hmac.compare_digest call: timing-safe verification"))
    return finds


TEXT_CMP = re.compile(
    r"\b(\w*(?:token|secret|password|signature|sig|digest|hmac|cookie|"
    r"mac|apikey)\w*)\s*(==|!=|<|>)")
TEXT_PREFIX = re.compile(
    r"\b(\w*(?:token|secret|password|signature|sig|digest|hmac)\w*)"
    r"\s*\.\s*(startswith|endswith)\s*\(")


def scan_text(src, origin):
    """Line scan fallback for non-Python captures (heuristic -> WARN)."""
    finds = []
    for i, line in enumerate(src.splitlines(), 1):
        if "compare_digest" in line:
            continue
        m = TEXT_CMP.search(line)
        if m:
            finds.append(_finding(
                "text-compare", "WARN", origin, i,
                "line compares %r with '%s' — verify it is timing-safe"
                % (m.group(1), m.group(2))))
            continue
        m = TEXT_PREFIX.search(line)
        if m:
            finds.append(_finding(
                "text-prefix", "WARN", origin, i,
                "'%s' on %r — prefix match length leaks via timing"
                % (m.group(2), m.group(1))))
    return finds


def pearson(xs, ys):
    """Pearson r; None when either side has zero variance."""
    n = len(xs)
    mx, my = sum(xs) / n, sum(ys) / n
    sxy = sum((x - mx) * (y - my) for x, y in zip(xs, ys))
    sxx = sum((x - mx) ** 2 for x in xs)
    syy = sum((y - my) ** 2 for y in ys)
    if sxx <= 0 or syy <= 0:
        return None
    return sxy / math.sqrt(sxx * syy)


def lin_slope(xs, ys):
    n = len(xs)
    mx, my = sum(xs) / n, sum(ys) / n
    sxx = sum((x - mx) ** 2 for x in xs)
    if sxx <= 0:
        return 0.0
    return sum((x - mx) * (y - my) for x, y in zip(xs, ys)) / sxx


def timing_findings(samples):
    """Raw capture records -> variance side-channel findings."""
    finds = []
    groups = {}
    for s in samples:
        ln, ns = _pick(s, LEN_KEYS), _pick(s, NS_KEYS)
        if not (isinstance(ln, (int, float))
                and isinstance(ns, (int, float))):
            continue
        groups.setdefault(str(s.get("label", "cmp")), []).append(
            (float(ln), float(ns)))
    for label in sorted(groups):
        pts = groups[label]
        xs = [p[0] for p in pts]
        ys = [p[1] for p in pts]
        mean_ns = sum(ys) / len(ys)
        if len(pts) < 4 or len(set(xs)) < 3:
            continue  # nothing decisive to say
        r = pearson(xs, ys)
        if r is None:
            continue
        slope = lin_slope(xs, ys)
        spread = abs(slope) * (max(xs) - min(xs))
        detail = ("label %r: r=%+.2f, %.1f ns/match-unit, spread %.0f ns "
                  "over mean %.0f ns (n=%d)" % (label, r, slope, spread,
                                                mean_ns, len(pts)))
        if abs(r) >= BLOCK_R and spread >= 0.2 * max(mean_ns, 1.0):
            finds.append(_finding("correlated-timing", "BLOCK", label,
                                  len(pts), detail))
        elif abs(r) >= WARN_R and spread >= 0.1 * max(mean_ns, 1.0):
            finds.append(_finding("weak-timing-signal", "WARN", label,
                                  len(pts), detail))
    return finds


def _pick(rec, keys):
    for k in keys:
        if k in rec:
            return rec[k]
    return None


def load_jsonl(text):
    """-> (records, bad_count): per-line dicts plus unparsable count."""
    recs, bad = [], 0
    for line in text.splitlines():
        if not line.strip():
            continue
        try:
            rec = json.loads(line)
        except ValueError:
            bad += 1
            continue
        if isinstance(rec, dict):
            recs.append(rec)
        else:
            bad += 1
    return recs, bad


def audit(path, mode):
    """Dispatch on mode -> findings; JSONL iff every nonblank line is a
    record or a counted straggler (broken lines stay in capture mode)."""
    with open(path, encoding="utf-8", errors="replace") as fh:
        text = fh.read()
    finds = []
    lines = [l for l in text.splitlines() if l.strip()]
    recs, bad = load_jsonl(text)
    jsonl = bool(recs) and len(recs) + bad == len(lines)
    is_timing = mode == "timing" or (
        mode == "auto" and jsonl
        and any(_pick(r, LEN_KEYS) is not None
                and _pick(r, NS_KEYS) is not None for r in recs))
    if is_timing:
        finds += timing_findings(recs)
        if bad:
            finds.append(_finding("unparsable-line", "WARN", path, bad,
                                  "%d unparsable capture lines skipped"
                                  % bad))
        return finds
    if mode == "auto" and jsonl and any("src" in r for r in recs):
        for i, rec in enumerate(recs, 1):
            src, lang = str(rec.get("src", "")), str(
                rec.get("lang", "py")).lower()
            origin = str(rec.get("path", "%s#%d" % (path, i)))
            try:
                finds += (scan_python(src, origin) if lang in
                          ("py", "python") else scan_text(src, origin))
            except SyntaxError:
                finds += scan_text(src, origin)
        if bad:
            finds.append(_finding("unparsable-line", "WARN", path, bad,
                                  "%d unparsable source records skipped"
                                  % bad))
        return finds
    # raw source file
    try:
        return scan_python(text, path)
    except SyntaxError:
        return scan_text(text, path)


def render(findings):
    counts = {s: sum(1 for f in findings if f["severity"] == s)
              for s in ("BLOCK", "WARN", "INFO")}
    for f in sorted(findings, key=lambda x: (x["severity"],
                                             x["origin"], x["line"])):
        print("%s %s: %s (%s:%s)" % (f["severity"], f["kind"],
                                     f["detail"], f["origin"],
                                     f["line"]))
    print("summary: %d BLOCK, %d WARN, %d INFO"
          % (counts["BLOCK"], counts["WARN"], counts["INFO"]))
    return counts


def main(argv=None):
    ap = argparse.ArgumentParser(
        description="Timing-safe comparison audit: static secret-"
                    "comparison scan + latency variance side-channel check")
    ap.add_argument("input", help="source file or JSONL capture")
    ap.add_argument("--mode", choices=("auto", "src", "timing"),
                    default="auto", help="auto-detect by default")
    ap.add_argument("--json", action="store_true",
                    help="emit one JSON doc as the final line")
    args = ap.parse_args(argv)
    try:
        findings = audit(args.input, args.mode)
    except OSError as exc:
        print("error: cannot read %s: %s" % (args.input, exc),
              file=sys.stderr)
        return 2
    counts = render(findings)
    if args.json:
        print(json.dumps({"input": args.input, "findings": findings,
                          "counts": counts}))
    return 1 if any(f["severity"] in ("BLOCK", "WARN")
                    for f in findings) else 0


def _sev_kinds(finds, sev):
    return sorted({f["kind"] for f in finds if f["severity"] == sev})


def _tf(content, suffix):
    """Write content to a temp file; return its path (self-test helper)."""
    import tempfile
    fh = tempfile.NamedTemporaryFile("w", suffix=suffix, delete=False)
    fh.write(content)
    fh.close()
    return fh.name


def self_test():
    import os

    def bk(finds):
        return _sev_kinds(finds, "BLOCK")

    # static: == on a secret is the classic early-exit bug
    leak = ("def check(user_token, stored_token):\n"
            "    return user_token == stored_token\n")
    got = scan_python(leak, "leak.py")
    assert bk(got) == ["data-dependent-compare"] and \
        "user_token" in got[0]["detail"], got

    # compare_digest is clean and positively noted (INFO)
    safe = ("import hmac\n"
            "def check(provided_mac, computed_mac):\n"
            "    return hmac.compare_digest(provided_mac, computed_mac)\n")
    got = scan_python(safe, "safe.py")
    assert bk(got) == [] and \
        _sev_kinds(got, "INFO") == ["compare-digest-used"], got

    # guards: metadata subscript, call results stay silent; real
    # material under a non-metadata key is still flagged
    guarded = ("def meta(key_record, secret_bundle, received_token,"
               " stored_token):\n"
               "    if key_record['kty'] == 'OKP': pass\n"
               "    if secret_bundle['alg'] == 'HS256': pass\n"
               "    return len(received_token) != len(stored_token)\n")
    assert scan_python(guarded, "g.py") == []
    material = ("def m(secret_bundle, got):\n"
                "    return secret_bundle['material'] == got\n")
    assert bk(scan_python(material, "m.py")) == ["data-dependent-compare"]

    # startswith prefix leak; compound key names (signing_key) caught
    prefix = "def p(auth, pfx):\n    return auth.token.startswith(pfx)\n"
    assert bk(scan_python(prefix, "p.py")) == ["prefix-early-exit"]
    compound = "def c(signing_key, given):\n    return signing_key == given\n"
    assert bk(scan_python(compound, "c.py")) == ["data-dependent-compare"]

    # membership: secret in a literal list is BLOCK; secret container
    # of unknown shape is WARN
    member = "def chk(candidate_token):\n    return candidate_token in [1, 2]\n"
    assert bk(scan_python(member, "mem.py")) == ["membership-scan"]
    member2 = "def chk2(plain, token_store):\n    return plain in token_store\n"
    got = scan_python(member2, "mem2.py")
    assert got and got[0]["kind"] == "membership-scan" and \
        got[0]["severity"] == "WARN", got

    # text fallback for non-Python captures; no secrets stays silent
    text = "function chk(token, input) {\n  return token == input;\n}\n"
    got = scan_text(text, "chk.js")
    assert _sev_kinds(got, "WARN") == ["text-compare"] and \
        got[0]["line"] == 2, got
    assert scan_text("if size == limit: pass\n", "x.py") == []

    # timing: strong correlation blocks; flat and noisy-flat stay clean
    leaky = [{"label": "verify", "match_len": i, "ns": 480 + 435 * i}
             for i in range(1, 7)]
    got = timing_findings(leaky)
    assert bk(got) == ["correlated-timing"] and "r=+" in got[0]["detail"]
    flat = [{"label": "lookup", "match_len": i, "ns": 900 + (i % 2)}
            for i in range(1, 9)]
    assert timing_findings(flat) == []
    noisy = [{"label": "v", "match_len": i, "ns": 500 + 37 * (i % 5)}
             for i in range(1, 13)]
    assert timing_findings(noisy) == []
    # too few samples: silent
    few = [{"label": "v", "match_len": 1, "ns": n} for n in (5, 6)]
    assert timing_findings(few) == []
    # weak signal lands in WARN band (validated with module pearson)
    weak = [{"label": "w", "match_len": i,
             "ns": 1000 + 300 * i + (0 if i != 4 else 2600)}
            for i in range(1, 7)]
    r = pearson([s["match_len"] for s in weak], [s["ns"] for s in weak])
    assert 0.35 <= abs(r) < 0.60 and \
        _sev_kinds(timing_findings(weak), "WARN") == \
        ["weak-timing-signal"], (r, timing_findings(weak))
    # labels are audited independently
    assert bk(timing_findings(leaky + flat)) == ["correlated-timing"]

    # end-to-end CLI: rc contract, auto-detection, --json, IO errors
    import io
    from contextlib import redirect_stdout
    src_path = _tf(leak, ".py")
    tim_path = _tf("".join(json.dumps(s) + "\n" for s in leaky), ".jsonl")
    rec_path = _tf('{"path": "a.py", "src": "x = 1\\n", "lang": "py"}\n'
                   '{"path": "b.py", "src": "if api_key == got:\\n'
                   '    pass\\n"}\n'
                   '{"broken\n', ".jsonl")
    js_path = _tf(text, ".js")
    safe_path = _tf(safe, ".py")
    try:
        buf = io.StringIO()
        with redirect_stdout(buf):
            assert main([src_path]) == 1
            assert main([src_path, "--json"]) == 1
        doc = json.loads(buf.getvalue().splitlines()[-1])
        assert doc["counts"]["BLOCK"] == 1 and \
            doc["findings"][0]["kind"] == "data-dependent-compare"
        buf = io.StringIO()
        with redirect_stdout(buf):
            assert main([tim_path]) == 1  # auto-detected as timing
        assert "correlated-timing" in buf.getvalue()
        buf = io.StringIO()
        with redirect_stdout(buf):
            rc = main([rec_path])
        assert rc == 1
        out = buf.getvalue()
        assert "data-dependent-compare" in out and \
            "1 unparsable source records skipped" in out, out
        buf = io.StringIO()
        with redirect_stdout(buf):
            assert main([js_path]) == 1  # text fallback on non-Python
            assert main([tim_path, "--mode", "src"]) == 0  # forced src
            assert main(["/nonexistent.input"]) == 2
        assert "text-compare" in buf.getvalue()
        buf = io.StringIO()
        with redirect_stdout(buf):
            assert main([safe_path]) == 0  # INFO-only is clean
    finally:
        for p in (src_path, tim_path, rec_path, js_path, safe_path):
            os.unlink(p)

    print("constant-time-compare-audit self-test OK (18 assertion "
          "groups: early-exit ==, compare_digest, metadata/call guards, "
          "prefix leak, key compounds, membership, text fallback, timing "
          "correlation/flat/weak, labels, CLI rc + json + auto-detect)")


if __name__ == "__main__":
    if "--self-test" in sys.argv:
        self_test()  # falls through; rc 0 (probe hook runs after this)
    else:
        raise SystemExit(main())
