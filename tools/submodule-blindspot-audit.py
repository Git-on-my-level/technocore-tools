#!/usr/bin/env python3
"""submodule-blindspot-audit — public-vs-private coverage audit for a
repo checkout: find the audit blind spots where critical code (crypto,
keys, signing) hides in private or unfetchable submodules.

DEMAND: evidence/suggestions/tools-services/
  - 2026-08-28.md "Audit coverage of private submodules / non-public
    code paths"
  - 2026-08-29.md "Audit repos that contain private submodules
    (currently unauditable)"; "Audit private/proprietary codebases (or
    submodules) within public repositories"; "Audit repos with private
    submodules containing critical code (crypto)"
  - 2026-08-30.md "Audit which parts of a repo are public vs private,
    especially detect when critical code (crypto) is hidden in private
    submodules"
Scope: the offline half — walk a LOCAL checkout (no network, no
subprocess, no git invocation; files are data). A submodule is a
directory containing a `.git` entry (file or dir) — a gitlink. Map:
  private-ssh      .gitmodules URL is git@/ssh:// (auth-only access).
  local-url        URL is file:// or a relative path (machine-local).
  unknown-host    URL host is not one of the public forges
                   (--public-hosts, default github/gitlab/bitbucket/
                   codeberg/sourcehut) — private gitea/forgejo suspect.
  no-url           .gitmodules section has no url key.
  crypto-in-private  crypto-critical path (name matches --crypto-re:
                   key|sig|secret|wallet|mnemonic|ed25519|seed|privkey|
                   credential) inside a submodule directory (BLOCK).
  unregistered-submodule  gitlink dir with no .gitmodules section.
  dangling-entry   .gitmodules section whose path has no checkout dir.
  path-escape      symlink inside a submodule resolving outside the
                   repo root (invisible to a repo-only audit).
Also renders the coverage board: files walked, crypto-critical paths
total, how many live in submodules, per-URL-visibility counts, and the
unauditable share — the number the rooms asked for. rc 0 clean (INFO
also 0), 1 WARN/BLOCK, 2 usage/IO.

VERIFY: --self-test runs 13 assertion groups over a synthetic repo
tree (clean public repo silence, ssh/local/unknown-host/no-url
classification, crypto-in-private BLOCK, crypto outside submodules
passes, unregistered gitlink, dangling entry, symlink escape, board
arithmetic, CLI rc/json). Live grounding: this workspace itself
(no .gitmodules, no gitlinks -> clean, rc 0) plus the synthetic
fixture in the self-test.
"""
import argparse
import configparser
import json
import os
import re
import sys

DEF = dict(crypto_re=r"(key|sig|secret|wallet|mnemonic|ed25519|seed|"
                     r"privkey|credential)")
PUBLIC_HOSTS = ("github.com", "gitlab.com", "bitbucket.org",
                "codeberg.org", "sr.ht")

CRYPTO_NAME = re.compile(DEF["crypto_re"], re.I)


def url_visibility(url):
    """Classify a .gitmodules URL: public/private-ssh/local/unknown."""
    if not isinstance(url, str) or not url.strip():
        return "no-url"
    u = url.strip()
    if u.startswith("git@") or u.startswith("ssh://"):
        return "private-ssh"
    if u.startswith("file://") or u.startswith("./") \
            or u.startswith("../") or u.startswith("/"):
        return "local-url"
    m = re.match(r"(?:https?://|git://)?([^/:]+)[/:]", u)
    if m and m.group(1).lower() in PUBLIC_HOSTS:
        return "public"
    return "unknown-host"


def load_gitmodules(root):
    """(.gitmodules path -> url) map + parse failure flag."""
    gp = os.path.join(root, ".gitmodules")
    out = {}
    if not os.path.isfile(gp):
        return out, False
    cp = configparser.ConfigParser(interpolation=None)
    try:
        cp.read(gp, encoding="utf-8")
    except (configparser.Error, UnicodeDecodeError):
        return out, True
    for sec in cp.sections():
        m = re.match(r'submodule\s+"([^"]+)"', sec)
        if not m:
            continue
        out[m.group(1)] = cp[sec].get("url", "")
    return out, False


def walk_repo(root, max_files=200000):
    """-> (files, gitlinks, escapes) — repo-relative paths, submodule
    dirs (contain .git), symlinks escaping the root."""
    files, gitlinks, escapes = [], [], []
    root = os.path.abspath(root)
    n = 0
    for dirpath, dirnames, filenames in os.walk(root, followlinks=False):
        rel = os.path.relpath(dirpath, root)
        if ".git" in dirnames or ".git" in filenames:
            if rel != ".":
                gitlinks.append(rel)
                dirnames[:] = [d for d in dirnames if d != ".git"]
        for name in list(dirnames) + list(filenames):
            full = os.path.join(dirpath, name)
            if os.path.islink(full):
                tgt = os.path.realpath(full)
                if not tgt.startswith(root + os.sep) and tgt != root:
                    escapes.append(os.path.normpath(
                        os.path.join(rel, name)))
        for f in filenames:
            if f == ".git" or os.path.islink(
                    os.path.join(dirpath, f)):
                continue
            files.append(os.path.normpath(os.path.join(rel, f)))
            n += 1
            if n >= max_files:
                return files, gitlinks, escapes
    return files, gitlinks, escapes


def in_submodule(path, gitlinks):
    """Is this repo-relative path inside a gitlink directory?"""
    for g in gitlinks:
        if path == g or path.startswith(g + os.sep):
            return g
    return None


def analyze(root, opts=None):
    """-> (findings, board) for one checkout."""
    o = dict(crypto_re=DEF["crypto_re"])
    o.update(opts or {})
    crypto_re = re.compile(o["crypto_re"], re.I)
    mods, parse_fail = load_gitmodules(root)
    files, gitlinks, escapes = walk_repo(root)
    findings = []

    def add(kind, sev, detail, **kw):
        f = {"kind": kind, "severity": sev, "detail": detail}
        f.update(kw)
        findings.append(f)

    if parse_fail:
        add("gitmodules-unparsable", "WARN",
            ".gitmodules does not parse as INI")

    vis = {}
    for path, url in sorted(mods.items()):
        v = url_visibility(url)
        vis[v] = vis.get(v, 0) + 1
        if v not in ("public",):
            add(f"url-{v}" if v != "no-url" else "no-url",
                "WARN" if v != "local-url" else "INFO",
                f"submodule '{path}' url is {v}: {url[:60] or '(none)'}",
                submodule=path, url=url[:80])
        if not os.path.isdir(os.path.join(root, path)):
            add("dangling-entry", "WARN",
                f".gitmodules declares '{path}' but no checkout exists",
                submodule=path)

    for g in sorted(gitlinks):
        if g not in mods:
            add("unregistered-submodule", "WARN",
                f"gitlink '{g}' has no .gitmodules section",
                submodule=g)

    crypto_total = crypto_hidden = 0
    for f in files:
        base = os.path.basename(f)
        if not crypto_re.search(base):
            continue
        crypto_total += 1
        g = in_submodule(f, gitlinks)
        if g:
            v = url_visibility(mods.get(g, ""))
            if v != "public":
                crypto_hidden += 1
                add("crypto-in-private", "BLOCK",
                    f"crypto-critical path '{f}' inside submodule "
                    f"'{g}' (url visibility: {v})",
                    path=f, submodule=g)

    for e in escapes:
        add("path-escape", "WARN",
            f"symlink '{e}' resolves outside the repo root", path=e)

    board = dict(root=root, files=len(files), submodules=len(gitlinks),
                 declared=len(mods),
                 visibility=vis,
                 crypto_total=crypto_total,
                 crypto_in_submodules=crypto_hidden,
                 unauditable_share=(crypto_hidden / crypto_total
                                    if crypto_total else 0.0))
    findings.sort(key=lambda f: ({"BLOCK": 0, "WARN": 1, "INFO": 2}[
        f["severity"]], f["kind"]))
    return findings, board


def render(findings, board, limit=20):
    counts = {}
    for f in findings:
        counts[f["severity"]] = counts.get(f["severity"], 0) + 1
    print(f"findings: {len(findings)} "
          + " ".join(f"{k}={v}" for k, v in sorted(counts.items())))
    for f in findings[:limit]:
        print(f"[{f['severity']}] {f['kind']}: {f['detail']}")
    if len(findings) > limit:
        print(f"... {len(findings) - limit} more")
    b = board
    print(f"coverage: files={b['files']} gitlinks={b['submodules']} "
          f"declared={b['declared']} "
          + " ".join(f"{k}={v}" for k, v in sorted(
              b["visibility"].items())))
    share = b["unauditable_share"]
    print(f"crypto-critical paths: {b['crypto_total']} total, "
          f"{b['crypto_in_submodules']} inside submodules "
          f"({share:.0%} unauditable)")


def main(argv=None):
    ap = argparse.ArgumentParser(
        description="Audit a repo checkout for audit blind spots: "
                    "crypto-critical code inside private/local/unfetchabl"
                    "e submodules, unregistered gitlinks, path escapes.")
    ap.add_argument("repo", nargs="?", default=".",
                    help="repo checkout to audit (default: cwd)")
    ap.add_argument("--crypto-re", dest="crypto_re",
                    default=DEF["crypto_re"],
                    help="regex a filename must match to count as "
                         "crypto-critical")
    ap.add_argument("--limit", type=int, default=20)
    ap.add_argument("--json", action="store_true")
    args = ap.parse_args(argv)
    if not os.path.isdir(args.repo):
        print(f"error: {args.repo} is not a directory", file=sys.stderr)
        return 2
    findings, board = analyze(args.repo, vars(args))
    if args.json:
        print(json.dumps({"findings": findings, "board": board},
                         ensure_ascii=False))
    else:
        render(findings, board, args.limit)
    hard = [f for f in findings if f["severity"] in ("WARN", "BLOCK")]
    return 1 if hard else 0


def self_test():
    import io
    import os
    import shutil
    import tempfile
    from contextlib import redirect_stdout

    def build(tree, gitmodules=None):
        """tree: {relpath: 'file content' or None(dir) or 'LINK:target'}"""
        d = tempfile.mkdtemp()
        for rel, content in tree.items():
            p = os.path.join(d, rel)
            os.makedirs(os.path.dirname(p), exist_ok=True)
            if content is None:
                os.makedirs(p, exist_ok=True)
            elif isinstance(content, str) and content.startswith("LINK:"):
                os.symlink(content[5:], p)
            else:
                with open(p, "w") as fh:
                    fh.write(content or "x")
        if gitmodules is not None:
            with open(os.path.join(d, ".gitmodules"), "w") as fh:
                fh.write(gitmodules)
        return d

    GM = ('[submodule "vendor/crypto"]\n'
          "\tpath = vendor/crypto\n\turl = {}\n")

    def run(d, extra=()):
        buf = io.StringIO()
        with redirect_stdout(buf):
            rc = main([d, *extra])
        return rc, buf.getvalue()

    def kinds(finds):
        return sorted({f["kind"] for f in finds})

    # 1) clean public repo: no submodules, crypto visible -> silent
    d = build({"src/main.py": "x", "src/ed25519_keys.py": "k"})
    findings, board = analyze(d)
    assert findings == [], findings
    assert board["crypto_total"] == 1 \
        and board["crypto_in_submodules"] == 0
    rc, out = run(d)
    assert rc == 0 and "findings: 0" in out, (rc, out)

    # 2) crypto inside a private-ssh submodule -> BLOCK
    d = build({"vendor/crypto": None,
               "vendor/crypto/wallet_seed.py": "s",
               "vendor/crypto/.git": "gitdir: ../../.git/modules/x"},
              gitmodules=GM.format("git@corp-gitea:sec/crypto.git"))
    findings, board = analyze(d)
    f = next(x for x in findings if x["kind"] == "crypto-in-private")
    assert f["severity"] == "BLOCK" \
        and f["path"] == os.path.join("vendor/crypto", "wallet_seed.py")
    assert board["crypto_total"] == 1 and board["unauditable_share"] == 1.0
    assert "url-private-ssh" in kinds(findings), findings
    rc, out = run(d)
    assert rc == 1 and "100% unauditable" in out, out

    # 3) URL classification: local, file://, unknown host, no url
    assert url_visibility("git@example.com:x/y.git") == "private-ssh"
    assert url_visibility("ssh://h/x") == "private-ssh"
    assert url_visibility("file:///srv/x") == "local-url"
    assert url_visibility("../sibling") == "local-url"
    assert url_visibility("https://github.com/a/b") == "public"
    assert url_visibility("https://gitlab.com/a/b") == "public"
    assert url_visibility("https://gitea.corp/a/b") == "unknown-host"
    assert url_visibility("") == "no-url"
    assert url_visibility(None) == "no-url"

    # 4) crypto in a PUBLIC submodule flags only the url- nothing (clean)
    d = build({"vendor/crypto": None,
               "vendor/crypto/sig_verify.py": "v",
               "vendor/crypto/.git": "gitdir: x"},
              gitmodules=GM.format("https://github.com/a/b"))
    got = analyze(d)[0]
    assert "crypto-in-private" not in kinds(got), got

    # 5) unregistered gitlink (no .gitmodules at all)
    d = build({"third_party/lib": None, "third_party/lib/.git": "g",
               "third_party/lib/code.py": "c"})
    got = analyze(d)[0]
    f = next(x for x in got if x["kind"] == "unregistered-submodule")
    assert f["submodule"] == os.path.join("third_party", "lib"), f

    # 6) dangling .gitmodules entry (declared, not checked out)
    d = build({"README.md": "r"}, gitmodules=GM.format(
        "https://github.com/a/b"))
    got = analyze(d)[0]
    assert "dangling-entry" in kinds(got), got

    # 7) symlink inside a submodule escaping the repo root
    outer = tempfile.mkdtemp()
    target = os.path.join(outer, "outside.txt")
    open(target, "w").close()
    d = build({"vendor/crypto": None,
               "vendor/crypto/.git": "g",
               "vendor/crypto/secrets": "LINK:" + target},
              gitmodules=GM.format("https://github.com/a/b"))
    got = analyze(d)[0]
    f = next(x for x in got if x["kind"] == "path-escape")
    assert f["path"].startswith("vendor"), f
    shutil.rmtree(outer)

    # 8) custom --crypto-re narrows what counts as critical
    d = build({"vendor/crypto": None,
               "vendor/crypto/.git": "g",
               "vendor/crypto/notes.md": "n",
               "vendor/crypto/privkey.pem": "p"},
              gitmodules=GM.format("git@h:x/y"))
    findings, board = analyze(d, dict(crypto_re=r"privkey"))
    assert board["crypto_total"] == 1 \
        and "crypto-in-private" in kinds(findings)

    # 9) unparsable .gitmodules surfaces
    d = build({"a.py": "x"}, gitmodules="[[[not ini")
    assert "gitmodules-unparsable" in kinds(analyze(d)[0])

    # 10) board visibility counts aggregate per class
    d = build({"vendor/a": None, "vendor/a/.git": "g",
               "vendor/b": None, "vendor/b/.git": "g"},
              gitmodules=('[submodule "vendor/a"]\n\tpath = vendor/a\n'
                          "\turl = git@h:x\n"
                          '[submodule "vendor/b"]\n\tpath = vendor/b\n'
                          "\turl = https://github.com/u/b\n"))
    board = analyze(d)[1]
    assert board["visibility"] == {"private-ssh": 1, "public": 1} \
        and board["submodules"] == 2, board

    # 11) CLI rc 2 on missing dir; --json shape
    assert main(["/nonexistent-repo-dir"]) == 2
    d = build({"vendor/crypto": None, "vendor/crypto/.git": "g",
               "vendor/crypto/mnemonic_backup.py": "m"},
              gitmodules=GM.format("git@h:x/y"))
    rc, out = run(d, ["--json"])
    doc = json.loads(out)
    assert rc == 1 and doc["board"]["crypto_in_submodules"] == 1 \
        and doc["findings"][0]["severity"] == "BLOCK"

    # 12) crypto regex matches on basename only, not extension junk
    assert CRYPTO_NAME.search("ED25519_PUBLIC.PEM")
    assert not CRYPTO_NAME.search("readme.md")

    # 13) in_submodule() is prefix-safe (no sibling-dir false hit)
    assert in_submodule("vendor/crypto-x/a.py",
                        ["vendor/crypto"]) is None
    assert in_submodule("vendor/crypto/a.py",
                        ["vendor/crypto"]) == "vendor/crypto"

    print("submodule-blindspot-audit self-test OK (13 groups: clean "
          "public repo, crypto-in-private BLOCK, url classes, public "
          "submodule pass, unregistered gitlink, dangling entry, "
          "symlink escape, custom regex, unparsable ini, visibility "
          "counts, CLI rc/json, regex, prefix safety)")


if __name__ == "__main__":
    if "--self-test" in sys.argv:
        self_test()  # falls through; rc 0 (probe hook runs after)
    else:
        raise SystemExit(main())
