#!/usr/bin/env python3
"""dep-blindspot — scan dependency manifests for audit blind spots: sources
an audit cannot reach (private repos, closed-source hosts, local paths,
private registries) and print an explicit audit-scope statement.

DEMAND: evidence/suggestions/tools-services/2026-08-29.md
  - "Audit codebases with private/proprietary dependencies (such as private
    submodules). ... scan the dependency tree and flag/report modules in
    audit blind spots (private repos, closed-source libraries)."
    ("a client with its crypto in a private submodule is unauditable in the
    only place auditing matters.")
  - "The audit service needs to solve the blind spot of not being able to
    audit private code (especially private submodules containing
    cryptographic logic) ... analyze publicly available dependency lists or
    build configurations, identify private critical submodules that may
    exist, and clearly annotate the limitations of the audit scope in the
    report." (08-28 06:47 general; filed twice in the 08-29 run)

What it does: parses dependency configs readable without repo access
(.gitmodules, requirements*.txt, pyproject.toml, package.json, go.mod,
Cargo.toml), classifies every dependency SOURCE (public / private-vcs /
private-registry / local-path / unknown-host), flags per-line blind spots,
computes coverage, prints an audit-scope note. Read-only: manifests are
data, never interpreted or run.

Usage:
  python3 dep-blindspot.py /path/to/repo            # human report
  python3 dep-blindspot.py --json go.mod Cargo.toml # machine output
  python3 dep-blindspot.py --strict repo && audit   # exit 2 if blind spots

VERIFY: self-test — python3 dep-blindspot.py --self-test
  Every parser, every verdict class, end-to-end tempdir scan, coverage
  math, scope note, --strict exit. Asserts, prints OK.
"""
import argparse
import json
import os
import re
import sys
import tempfile
import tomllib

PUBLIC_FORGES = {
    "github.com", "gitlab.com", "bitbucket.org", "codeberg.org",
    "gitee.com", "salsa.debian.org", "sr.ht", "git.sr.ht",
    "huggingface.co", "git.kernel.org", "sourceware.org",
}
PUBLIC_REGISTRIES = ("pypi.org", "files.pythonhosted.org",
                     "registry.npmjs.org", "crates.io", "index.crates.io",
                     "proxy.golang.org")
PRIV_HOST_TLD = (".internal", ".local", ".corp", ".lan", ".intranet",
                 ".private")
PRIV_HOST_LABEL = {"internal", "intranet", "corp", "vpn", "ghe", "private",
                   "gitlab"}
SKIP_DIRS = {".git", "node_modules", "vendor", "target", ".venv", "venv",
             "__pycache__"}
IPV4 = re.compile(r"^\d{1,3}(?:\.\d{1,3}){3}$")


def host_of(url):
    """Bare hostname of a git/npm/pip URL spec, lowercased; '' if none."""
    u = url.strip()
    m = re.match(r"^[a-z0-9+.-]+://([^/@]+@)?([^/:?#]+)", u, re.I) \
        or re.match(r"^([^/@:]+)@([^/:?#]+):", u)        # scp: git@host:path
    return m.group(2).lower() if m else ""


def _vcs_name(spec):
    """Human name from a VCS URL path: repo basename minus .git/@ref."""
    base = spec.rstrip("/").rsplit("/", 1)[-1].rsplit(":", 1)[-1]
    base = base.split("@", 1)[0]
    return base[:-4] if base.endswith(".git") else (base or spec[:24])


def _host_verdict(h, kind, path=""):
    """(verdict, reason) for a source host; kind names the private class."""
    if not h:
        return "unknown-host", "cannot parse source host"
    if h == "localhost" or h.endswith(".localhost") or IPV4.match(h):
        return kind, f"host {h} is local"
    if any(h.endswith(t) for t in PRIV_HOST_TLD):
        return kind, f"host {h} resolves to an internal zone"
    if h in PUBLIC_FORGES:
        return "public", f"public forge {h}"
    if path and path.endswith((".tgz", ".tar.gz", ".zip")):
        return "unknown-host", f"tarball from non-forge host {h}"
    if "." not in h:
        return kind, f"single-label host {h} (internal alias)"
    label = sorted(set(h.split(".")) & PRIV_HOST_LABEL)
    if label and h not in PUBLIC_FORGES:
        return kind, f"host {h} has internal-network label '{label[0]}'"
    return "unknown-host", f"host {h} is not a known public forge"


def classify_source(spec):
    """(verdict, reason) for one dependency source spec; public == auditable
    via a public forge or the default public registry, anything else is a
    blind spot: private-vcs / private-registry / local-path / unknown-host."""
    s = (spec or "").strip()
    if not s:
        return "public", "no source pin (default public registry)"
    low = s.lower()
    if low.startswith(("file:", "path:", "workspace:", "link:", "portal:",
                       "../", "./", "/")) or \
            s.startswith(("\\", "~")) or re.match(r"^[A-Za-z]:[\\/]", s):
        return "local-path", "source is a local/workspace path, outside repo"
    if re.match(r"^(git\+)?(ssh|git)://", low) or "@" in s.split(":")[0]:
        return _host_verdict(host_of(s), "private-vcs")
    plain = re.sub(r"^[a-z]+\+", "", low)   # git+https:// -> https://
    if re.match(r"^https?://", plain):
        if re.search(r"https?://[^/@]+:[^/@]+@", plain):
            return "private-vcs", "URL embeds credentials (internal mirror)"
        m = re.match(r"^[a-z0-9+.-]+://[^/]+(/.*)", s, re.I)
        return _host_verdict(host_of(s), "private-vcs",
                             path=m.group(1) if m else "")
    if re.match(r"^[A-Za-z0-9.-]+\.[A-Za-z]{2,}(?:/.*)?$", s) and \
            not re.search(r"[<>=!~\s]", s):
        # bare VCS path (go module path): the host is itself the source
        return _host_verdict(host_of("https://" + s), "private-vcs")
    return "public", "version spec on default public registry"


def classify_registry(url):
    """(verdict, reason) for a package-index/registry URL."""
    h = host_of(url)
    if h in PUBLIC_REGISTRIES:
        return "public", f"public registry {h}"
    return _host_verdict(h, "private-registry")


# ------- manifest parsers: text -> (deps, registries); dep = name/spec/line
# spec "" means a plain version spec on the default public registry.

def parse_requirements(text):
    deps, regs = [], []
    for i, raw in enumerate(text.splitlines(), 1):
        t = raw.split("#", 1)[0].strip()
        m = re.match(r"^--(?:extra-)?index-url\s+(\S+)", t)
        e = re.match(r"^-e\s+(?:--\S+\s+)*(\S+)", t)
        if m:
            regs.append({"url": m.group(1), "line": i})
        elif e:
            deps.append({"name": _vcs_name(e.group(1)), "spec": e.group(1),
                         "line": i})
        elif not t.startswith("-") and " @ " in t:
            nm, _, ref = t.partition(" @ ")  # PEP 508: name @ url
            deps.append({"name": nm.strip(), "spec": ref.strip(), "line": i})
        elif not t.startswith("-") and t:
            nm = re.split(r"[\s\[\]<>=!~;,#]+", t, 1)[0] or t[:24]
            deps.append({"name": nm, "spec": "", "line": i})
    return deps, regs


def parse_gitmodules(text):
    deps, name, line = [], None, 0
    for i, ln in enumerate(text.splitlines(), 1):
        m = re.match(r"\s*path\s*=\s*(\S+)", ln)
        if m:
            name, line = m.group(1), i
        m = re.match(r"\s*url\s*=\s*(\S+)", ln)
        if m and name is not None:
            deps.append({"name": name, "spec": m.group(1), "line": line})
            name = None
    return deps, []


def parse_pyproject(text):
    try:
        data = tomllib.loads(text)
    except tomllib.TOMLDecodeError:
        return [], []
    specs = list(data.get("project", {}).get("dependencies", []))
    for grp in data.get("project", {}).get(
            "optional-dependencies", {}).values():
        specs += grp
    deps = []
    for d in specs:
        nm, _, ref = d.partition("@")
        deps.append({"name": re.split(r"[\s\[\]<>=!~;]+", nm, 1)[0].strip(),
                     "spec": ref.strip(), "line": 0})
    poetry = data.get("tool", {}).get("poetry", {})
    for nm, v in (poetry.get("dependencies") or {}).items():
        spec = str(v.get("git") or v.get("url") or v.get("path") or "") \
            if isinstance(v, dict) else \
            (v if isinstance(v, str) and v.startswith(("git", "http", "/",
                                                       "../")) else "")
        deps.append({"name": nm, "spec": spec, "line": 0})
    src = poetry.get("source") or []
    if isinstance(src, dict):
        src = [src]
    regs = [{"url": s["url"], "line": 0} for s in src
            if isinstance(s, dict) and s.get("url")]
    return deps, regs


def parse_package_json(text):
    try:
        data = json.loads(text)
    except json.JSONDecodeError:
        return [], []
    deps = []
    for sec in ("dependencies", "devDependencies", "optionalDependencies",
                "resolutions", "overrides"):
        for i, (nm, v) in enumerate((data.get(sec) or {}).items(), 1):
            v = str(v)
            spec = v if v.startswith(("git", "http", "file:", "link:",
                                      "workspace:", "../", "./")) else ""
            deps.append({"name": nm, "spec": spec, "line": i})
    return deps, []


def parse_go_mod(text):
    require, replace, mode = [], {}, ""
    for i, raw in enumerate(text.splitlines(), 1):
        t = raw.split("//", 1)[0].strip()
        if t in ("require (", "replace ("):
            mode = t.split()[0]
            continue
        if t == ")":
            mode = ""
            continue
        m = re.match(r"^require\s+(\S+)", t) if not mode else \
            re.match(r"^(\S+)(?:\s+\S+)?$", t)
        r = re.match(r"^replace\s+(\S+)(?:\s+\S+)?\s+=>\s*(.+)$", t) \
            if not mode else re.match(r"^(\S+)(?:\s+\S+)?\s+=>\s*(.+)$", t)
        if r:
            replace[r.group(1)] = (r.group(2).strip(), i)
        elif m:
            require.append((m.group(1), i))
    deps = []
    for mod, i in require:
        spec, ln = replace.get(mod, ("", i))
        deps.append({"name": mod, "spec": spec or mod, "line": ln})
    return deps, []


def parse_cargo(text):
    try:
        data = tomllib.loads(text)
    except tomllib.TOMLDecodeError:
        return [], []
    deps = []
    for sec in ("dependencies", "dev-dependencies", "build-dependencies"):
        for nm, v in (data.get(sec) or {}).items():
            spec = ""
            if isinstance(v, dict) and v.get("git"):
                g = str(v["git"])
                spec = g if g.startswith(("git+", "http", "ssh:", "git@")) \
                    else "git+https://" + g
            elif isinstance(v, dict) and v.get("path"):
                p = str(v["path"])
                spec = p if p.startswith(("./", "../", "/", "~")) else "./" + p
            deps.append({"name": nm, "spec": spec, "line": 0})
    return deps, []


PARSERS = {".gitmodules": parse_gitmodules, "pyproject.toml": parse_pyproject,
           "package.json": parse_package_json, "go.mod": parse_go_mod,
           "Cargo.toml": parse_cargo}
REQ_RE = re.compile(r"^requirements[-\w]*\.txt$")


def scan(paths):
    """Walk files/dirs; return (findings, registries)."""
    files = []
    for p in paths:
        if os.path.isfile(p):
            files.append(p)
        elif os.path.isdir(p):
            for root, dirs, names in os.walk(p):
                dirs[:] = sorted(d for d in dirs if d not in SKIP_DIRS)
                files += [os.path.join(root, n) for n in sorted(names)]
        else:
            print(f"dep-blindspot: {p}: not found", file=sys.stderr)
    base = paths[0] if len(paths) == 1 and os.path.isdir(paths[0]) else "."
    findings, registries = [], []
    for f in files:
        nm = os.path.basename(f)
        parser = PARSERS.get(nm) or (parse_requirements if REQ_RE.match(nm)
                                     else None)
        if not parser:
            continue
        try:
            with open(f, encoding="utf-8", errors="replace") as fh:
                deps, regs = parser(fh.read())
        except OSError as e:
            print(f"dep-blindspot: {f}: {e}", file=sys.stderr)
            continue
        rel = os.path.relpath(f, base).replace(os.sep, "/")
        for d in deps:
            verdict, reason = classify_source(d["spec"])
            findings.append({"manifest": rel, "name": d["name"],
                             "spec": d["spec"], "line": d["line"],
                             "verdict": verdict, "reason": reason,
                             "blind": verdict != "public"})
        for r in regs:
            verdict, reason = classify_registry(r["url"])
            registries.append({"manifest": rel, "url": r["url"],
                               "line": r["line"], "verdict": verdict,
                               "reason": reason, "blind": verdict != "public"})
    return findings, registries


def coverage(findings):
    total = len(findings)
    blind = sum(1 for f in findings if f["blind"])
    return total, blind, (round((total - blind) / total, 4) if total else 1.0)


def scope_note(findings, registries):
    """The audit-scope limitation statement demanded by the filed request."""
    total, blind, cov = coverage(findings)
    if total == 0:
        return ("no dependency manifests found; audit scope cannot be "
                "assessed from build configs")
    names = sorted({f["name"] for f in findings if f["blind"]})
    note = (f"{blind} of {total} dependency sources are NOT publicly "
            f"auditable (coverage {cov:.0%}): "
            + ", ".join(names[:40]) + (" ..." if len(names) > 40 else "")
            + ". Any audit of this repo excludes these sources; findings "
              "must not be read as covering them.")
    bad_reg = sorted({r["url"] for r in registries if r["blind"]})
    if bad_reg:
        note += " private package registries in use: " + ", ".join(bad_reg[:10])
    return note


def decide_exit(findings, strict):
    return 2 if strict and any(f["blind"] for f in findings) else 0


def self_test():
    checks = 0

    # classify_source(): one verdict per source class (incl. bare go paths)
    cases = [
        ("git+ssh://git@gitlab.corp.example.com/acme/crypto.git", "private-vcs"),
        ("git@github.com:acme/pub.git", "public"),
        ("git@gitlab:acme/secret.git", "private-vcs"),
        ("https://10.1.2.3/acme/keys.git", "private-vcs"),
        ("git+https://user:tok@mgit.acme.io/x.git", "private-vcs"),
        ("git+https://bitbucket.org/acme/pub.git", "public"),
        ("https://cdn.somevendor.io/pkg-1.2.3.tgz", "unknown-host"),
        ("../shared/crypto-lib", "local-path"),
        ("file:./local-wasm", "local-path"),
        ("workspace:*", "local-path"),
        ("git.corp.acme.io/acme/keys", "private-vcs"),
        ("github.com/acme/pub", "public"),
        ("requests==2.31.0", "public"),
    ]
    got = [classify_source(s)[0] for s, _w in cases]
    assert got == [w for _s, w in cases], \
        [c for c in zip(cases, got) if c[0][1] != c[1]]
    assert "single-label" in classify_source("git@gitlab:acme/s.git")[1]
    assert "internal" in classify_source(
        "git+ssh://git@gitlab.corp.example.com/a/c.git")[1]
    assert classify_registry("https://pypi.org/simple")[0] == "public"
    assert classify_registry(
        "http://nexus.internal.acme.io:8081/x")[0] == "private-registry"
    checks += len(cases) + 4

    # every manifest parser, end to end through scan()
    fixtures = {
        ".gitmodules": (
            '[submodule "vendor/crypto-engine"]\n'
            "\tpath = vendor/crypto-engine\n"
            "\turl = git@gitlab.acme.io:acme/crypto-engine.git\n"
            '[submodule "vendor/public-dep"]\n\tpath = vendor/public-dep\n'
            "\turl = https://github.com/acme/public-dep.git\n"),
        "requirements.txt": (
            "requests==2.31.0\n"
            "--index-url https://nexus.internal.acme.io/repository/pypi-all\n"
            "-e git+ssh://git@gitlab.acme.io/acme/crypto-engine.git@v2\n"
            "acme-lib @ git+https://github.com/acme/lib.git\n"),
        "pyproject.toml": (
            "[project]\ndependencies = [\n  \"requests>=2\",\n"
            "  \"crypto-engine @ git+ssh://git@gitlab.acme.io/acme/ce.git\",\n"
            "]\n[tool.poetry.dependencies]\npython = \"^3.10\"\n"
            "seccfg = { git = \"https://git.internal.acme.io/acme/s.git\" }\n"
            "localutil = { path = \"../localutil\" }\n"
            "[[tool.poetry.source]]\nname = \"acme\"\n"
            "url = \"https://pypi.acme.internal/simple\"\n"),
        "package.json": json.dumps({
            "dependencies": {"react": "^18.0.0",
                             "acme-wasm": "git+ssh://git@gitlab.acme.io/a/w.git",
                             "shared-ui": "file:../shared-ui",
                             "ws-pkg": "workspace:*"},
            "devDependencies": {"left-pad": "1.3.0"}}),
        "go.mod": (
            "module acme.io/svc\n\ngo 1.22\n\nrequire (\n"
            "\tgithub.com/acme/pub v1.2.0\n"
            "\tgit.corp.acme.io/acme/secrets v0.4.1\n)\n"
            "replace github.com/acme/pub => ../local-pub\n"),
        "Cargo.toml": (
            "[dependencies]\nserde = \"1.0\"\n"
            "acme-crypto = { git = \"https://git.internal.acme.io/acme/c.git\" }\n"
            "inner = { path = \"crates/inner\" }\n"),
    }
    want = {
        (".gitmodules", "vendor/crypto-engine"): "private-vcs",
        (".gitmodules", "vendor/public-dep"): "public",
        ("requirements.txt", "requests"): "public",
        ("requirements.txt", "crypto-engine"): "private-vcs",
        ("requirements.txt", "acme-lib"): "public",
        ("pyproject.toml", "requests"): "public",
        ("pyproject.toml", "crypto-engine"): "private-vcs",
        ("pyproject.toml", "seccfg"): "private-vcs",
        ("pyproject.toml", "localutil"): "local-path",
        ("pyproject.toml", "python"): "public",
        ("package.json", "react"): "public",
        ("package.json", "acme-wasm"): "private-vcs",
        ("package.json", "shared-ui"): "local-path",
        ("package.json", "ws-pkg"): "local-path",
        ("package.json", "left-pad"): "public",
        ("go.mod", "github.com/acme/pub"): "local-path",
        ("go.mod", "git.corp.acme.io/acme/secrets"): "private-vcs",
        ("Cargo.toml", "serde"): "public",
        ("Cargo.toml", "acme-crypto"): "private-vcs",
        ("Cargo.toml", "inner"): "local-path",
    }
    with tempfile.TemporaryDirectory() as td:
        os.makedirs(os.path.join(td, "vendor"))
        for name, text in fixtures.items():
            with open(os.path.join(td, name), "w") as fh:
                fh.write(text)
        findings, registries = scan([td])
        got = {(f["manifest"], f["name"]): f["verdict"] for f in findings}
        assert got == want, {k: (got.get(k), v) for k, v in want.items()
                             if got.get(k) != v}
        lines = {(f["manifest"], f["name"]): f["line"] for f in findings}
        assert lines[(".gitmodules", "vendor/crypto-engine")] == 2
        assert lines[("requirements.txt", "crypto-engine")] == 3
        assert lines[("go.mod", "git.corp.acme.io/acme/secrets")] == 7, lines
        total, blind, cov = coverage(findings)
        assert (total, blind, cov) == (20, 12, 0.4), (total, blind, cov)
        note = scope_note(findings, registries)
        assert ("12 of 20" in note and "vendor/crypto-engine" in note
                and "must not be read as covering" in note
                and "nexus.internal.acme.io" in note), note
        assert decide_exit(findings, strict=True) == 2
        assert decide_exit(findings, strict=False) == 0
        assert decide_exit([f for f in findings if not f["blind"]],
                           strict=True) == 0
    checks += len(want) + 9

    print(f"self-test OK ({checks} assertions)")


def main():
    ap = argparse.ArgumentParser(
        description="Flag dependency sources an audit cannot reach (private "
                    "repos, closed-source hosts, local paths, private "
                    "registries) and print the audit-scope note.")
    ap.add_argument("paths", nargs="*",
                    help="repo dirs or manifest files to scan")
    ap.add_argument("--json", action="store_true",
                    help="machine-readable JSON instead of human report")
    ap.add_argument("--strict", action="store_true",
                    help="exit 2 if any blind spot is found (CI gate)")
    ap.add_argument("--self-test", action="store_true",
                    help="run built-in verification and exit")
    a = ap.parse_args()
    if a.self_test:
        self_test()
        return
    if not a.paths:
        ap.error("provide at least one repo dir or manifest file")
    findings, registries = scan(a.paths)
    total, blind, cov = coverage(findings)
    if a.json:
        print(json.dumps({"total": total, "blind": blind, "coverage": cov,
                          "findings": findings, "registries": registries,
                          "scope_note": scope_note(findings, registries)},
                         ensure_ascii=False, indent=1))
    else:
        print(f"dependency audit blind-spot scan — {total} sources, "
              f"{blind} unauditable (coverage {cov:.0%})")
        for f in sorted(findings, key=lambda x: (not x["blind"],
                                                 x["manifest"], str(x["name"]))):
            print(f"  [{'BLIND ' if f['blind'] else 'public'}] "
                  f"{f['manifest']}:{f['line'] or '?'} {f['name']} — "
                  f"{f['verdict']}: {f['reason']}")
        for r in registries:
            print(f"  [{'BLIND ' if r['blind'] else 'public'}] "
                  f"{r['manifest']} registry {r['url']} — {r['reason']}")
        print("\nAUDIT SCOPE: " + scope_note(findings, registries))
    raise SystemExit(decide_exit(findings, a.strict))


if __name__ == "__main__":
    try:
        main()
    except BrokenPipeError:
        os.dup2(os.open(os.devnull, os.O_WRONLY), sys.stdout.fileno())
        raise SystemExit(0)
