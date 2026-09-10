#!/usr/bin/env python3
"""reflog-audit — post-rewrite secret scanner for git reflogs and orphaned
objects: proves a secret "removed" by a reset/rebase/filter-branch is
really gone from every recoverable place on disk, not just from git log.

DEMAND: evidence/suggestions/tools-services/2026-09-08.md (10:52 run)
  - "Git reflog secret-leak audit — evidence: 'Auditing git reflog entries
    for leaked secrets' — proposed service: Post-reset reflog scanner for
    orphaned credentials."
  The failure mode it audits: `git reset`/`rebase`/`filter-branch` removes
  a secret from the branch tip, but the old commits stay recoverable via
  .git/logs/** and dangling objects until gc prunes them — anyone with a
  clone-level `git cat-file` can still read the key. This tool enumerates
  exactly those objects (reflog-reachable + dangling), scans their content
  for credential material, and reports per-object locations so the rewrite
  can be proven complete (or `gc` run as remediation).

What it scans (never executes anything from the repo):
  - every git object NOT reachable from refs (cat-file --batch-all-objects):
    blobs (file contents), commit/tag messages; classified REFLOG (still
    named by a reflog entry) vs DANGLING (unreachable, recoverable until
    gc) vs PACKED_ORPHAN.
  - the reflog message column itself (.git/logs/**) — a secret pasted into
    a commit *subject* survives there even after the commit object is gone.

Findings carry a redacted preview (prefix…suffix + length); the full secret
is never printed. rc 0 clean / 1 findings / 2 usage or IO error.
"""
import argparse
import json
import math
import os
import re
import subprocess
import sys
import tempfile

RULES = [
    # (rule name, compiled regex, group carrying the secret)
    ("PEM_PRIVATE_KEY", re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----"), 0),
    ("AWS_ACCESS_KEY", re.compile(r"\bAKIA[0-9A-Z]{16}\b"), 0),
    ("GITHUB_TOKEN", re.compile(r"\bgh[pousr]_[A-Za-z0-9]{36,255}\b"), 0),
    ("SLACK_TOKEN", re.compile(r"\bxox[baprs]-[A-Za-z0-9-]{10,}\b"), 0),
    ("STRIPE_LIVE_KEY", re.compile(r"\bsk_live_[A-Za-z0-9]{16,}\b"), 0),
    ("GOOGLE_API_KEY", re.compile(r"\bAIza[0-9A-Za-z_-]{35}\b"), 0),
    ("JWT", re.compile(r"\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{5,}\b"), 0),
    ("LABELED_SECRET",
     re.compile(r"(?i)\b(?:pass(?:word|phrase)?|secret|token|api[_-]?key|"
                r"access[_-]?key|private[_-]?key|credentials?)\b"
                r"['\"]?\s*[:=]\s*['\"]?([A-Za-z0-9_+/.=-]{12,})"), 1),
]
_B64_RUN = re.compile(r"\b[A-Za-z0-9+/=]{40,}\b")


def shannon_entropy(s):
    """Bits per char of s (0.0 for empty)."""
    if not s:
        return 0.0
    counts = {}
    for c in s:
        counts[c] = counts.get(c, 0) + 1
    n = len(s)
    return -sum((v / n) * math.log2(v / n) for v in counts.values())


def redact(s):
    return f"{s[:3]}…{s[-2:]} ({len(s)} chars)" if len(s) > 8 else "«redacted»"


def _is_public_key_material(s):
    """did:key multibase payloads are public by construction (multicodec
    ed25519-pub/x25519-pub/secp256k1-pub prefixes) — not credential leaks."""
    return s.startswith(("z6Mk", "z6LS", "zDna", "did:key:z"))


def scan_text(text, where):
    """Return findings (dicts) for credential material in text.

    `where` labels the origin (object path / reflog file) in each finding.
    High-entropy unlabeled runs are only flagged at >= 4.8 bits/char to
    stay quiet on prose, hashes (hex caps at 4.0) and ordinary code.
    did:key/multibase PUBLIC keys (z6Mk… ed25519-pub, z6LS… x25519,
    zDna… secp256k1 — the room senders' encoding) are deliberately not
    secrets and are never reported.
    """
    out = []
    for name, rx, grp in RULES:
        for m in rx.finditer(text):
            secret = m.group(grp)
            if _is_public_key_material(secret):
                continue
            if name == "LABELED_SECRET" and shannon_entropy(secret) < 3.0 \
                    and not re.search(r"[0-9]", secret):
                continue  # e.g. "token: main" — a word, not a credential
            out.append({"rule": name, "preview": redact(secret),
                        "where": where,
                        "line": text.count("\n", 0, m.start()) + 1})
    for m in _B64_RUN.finditer(text):
        run = m.group(0)
        if shannon_entropy(run) >= 4.8 and not _is_public_key_material(run):
            out.append({"rule": "HIGH_ENTROPY_RUN", "preview": redact(run),
                        "where": where,
                        "line": text.count("\n", 0, m.start()) + 1})
    out.sort(key=lambda f: (f["where"], f["line"]))
    return out


def _git(repo, *args, check=True):
    r = subprocess.run(["git", "-C", repo, *args], capture_output=True,
                       text=True, timeout=120)
    if check and r.returncode != 0:
        raise RuntimeError(f"git {' '.join(args)}: {r.stderr.strip()[:200]}")
    return r.stdout


def git_dir(repo):
    return _git(repo, "rev-parse", "--absolute-git-dir").strip()


def _object_table(repo):
    """{oid: (type, size)} for every object in the repo, loose or packed."""
    out = _git(repo, "cat-file", "--batch-all-objects", "--batch-check")
    table = {}
    for line in out.splitlines():
        parts = line.split()
        if len(parts) >= 3 and parts[1] in ("blob", "commit", "tag", "tree"):
            table[parts[0]] = (parts[1], int(parts[2]))
    return table


def _reachable_oids(repo):
    oids = set()
    r = subprocess.run(["git", "-C", repo, "rev-list", "--objects",
                        "--all", "--reflog"],
                       capture_output=True, text=True, timeout=120)
    for line in r.stdout.splitlines():
        if line:
            oids.add(line.split()[0])
    return oids


def scan_reflog_messages(gdir):
    """Secrets pasted into commit subjects live on in .git/logs messages."""
    out = []
    logs = os.path.join(gdir, "logs")
    for root, _dirs, files in os.walk(logs):
        for fn in sorted(files):
            path = os.path.join(root, fn)
            try:
                text = open(path, errors="replace").read()
            except OSError:
                continue
            for line_no, line in enumerate(text.splitlines(), 1):
                msg = line.split("\t", 1)[1] if "\t" in line else line
                for f in scan_text(msg, f"reflog:{os.path.relpath(path, gdir)}"):
                    f["line"] = line_no
                    out.append(f)
    return out


def audit_repo(repo, include_reachable=False, max_blob=2 * 1024 * 1024):
    """Scan all objects invisible to `git log --all` (plus reflog messages).

    Returns (findings, stats). Findings are never redacted-then-forgotten:
    each carries the object id so a human can `git cat-file` the culprit.
    """
    gdir = git_dir(repo)
    table = _object_table(repo)
    hidden_reach = _reachable_oids(repo)          # refs + reflogs
    r = subprocess.run(["git", "-C", repo, "rev-list", "--objects", "--all"],
                       capture_output=True, text=True, timeout=120)
    ref_reach = {l.split()[0] for l in r.stdout.splitlines() if l}
    findings, stats = [], {"objects": len(table), "scanned": 0,
                           "skipped_large": 0, "reflog_only": 0, "dangling": 0}
    for oid, (typ, size) in sorted(table.items()):
        if typ == "tree":
            continue
        if oid in ref_reach and not include_reachable:
            continue  # visible to `git log --all` — rewrite already handled it
        if oid in ref_reach:
            status = "HISTORY"  # only reached with --include-reachable
        else:
            status = "REFLOG" if oid in hidden_reach else "DANGLING"
            stats["dangling" if status == "DANGLING" else "reflog_only"] += 1
        if typ == "blob" and size > max_blob:
            stats["skipped_large"] += 1
            continue
        body = _git(repo, "cat-file", typ, oid)
        stats["scanned"] += 1
        for f in scan_text(body, f"{status}:{oid}"):
            f["oid"] = oid
            findings.append(f)
    for f in scan_reflog_messages(gdir):
        f["oid"] = None
        findings.append(f)
    findings.sort(key=lambda f: (f["where"], f["line"]))
    stats["findings"] = len(findings)
    return findings, stats


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("repo", nargs="?", default=".", help="git repo (default cwd)")
    ap.add_argument("--json", action="store_true", help="machine-readable report")
    ap.add_argument("--include-reachable", action="store_true",
                    help="also scan objects reachable from refs")
    ap.add_argument("--max-blob", type=int, default=2 * 1024 * 1024,
                    help="skip blobs larger than this many bytes (default 2 MiB)")
    args = ap.parse_args(argv)

    try:
        findings, stats = audit_repo(args.repo, args.include_reachable,
                                     args.max_blob)
    except (RuntimeError, subprocess.SubprocessError, OSError) as e:
        print(f"reflog-audit: {e}", file=sys.stderr)
        return 2

    if args.json:
        print(json.dumps({"findings": findings, "stats": stats}))
    else:
        scope = ("hidden" if not args.include_reachable else
                 "all (incl. ref-visible)")
        print(f"scanned {stats['scanned']} objects ({scope}: "
              f"{stats['reflog_only']} reflog-only, {stats['dangling']} "
              f"dangling, {stats['skipped_large']} skipped as >max-blob) "
              f"+ reflog messages")
        for f in findings:
            print(f"  [{f['rule']}] {f['preview']}  at {f['where']}:"
                  f"{f['line']}")
        if findings:
            print(f"{len(findings)} finding(s) of credential material — "
                  f"these survive `git rm`/rewrite until reflogs expire + gc")
        else:
            print("CLEAN: no secrets recoverable outside ref-visible history"
                  + ("" if args.include_reachable else
                     " (rerun with --include-reachable to scan full history)"))
    return 1 if findings else 0


def self_test():
    import base64
    import os as _os

    # --- scan_text unit checks -------------------------------------------
    benign = ("The token: main branch audit passed with no credentials "
              "attached; see audit-chain digests " + "ab" * 32 + ".")
    assert scan_text(benign, "t") == [], benign
    akia = "aws_access_key_id = AKIAIOSFODNN7EXAMPLE"
    got = scan_text(akia, "t")
    assert len(got) == 1 and got[0]["rule"] == "AWS_ACCESS_KEY", got
    assert "AKIAIOSFODNN7EXAMPLE" not in got[0]["preview"]  # redacted
    assert scan_text("-----BEGIN RSA PRIVATE KEY-----", "t")[0]["rule"] \
        == "PEM_PRIVATE_KEY"
    tok = "api_key = " + base64.b64encode(_os.urandom(24)).decode()
    assert any(f["rule"] == "LABELED_SECRET" for f in scan_text(tok, "t")), tok
    run = base64.b64encode(_os.urandom(48)).decode()  # no label, pure entropy
    assert any(f["rule"] == "HIGH_ENTROPY_RUN" for f in scan_text(run, "t"))
    assert shannon_entropy("aaaaaaaa") < shannon_entropy("abcdefgh")
    assert 0.0 < shannon_entropy("aabb") < 1.01
    # did:key/multibase PUBLIC keys must never be reported as secrets
    # (lesson from the first real-data run over this repo's objects)
    didkey = ("sender did:key:z6MkqSp7BNtY9nKB7Zk9TQwFYgrLtFfQ4pvW2Qk3T"
              "JgVXqzLmNpRtY8uXkQvW2hJ")
    assert scan_text(didkey, "t") == [], didkey
    assert scan_text("token: z6Mk" + "A9" * 20, "t") == []

    # --- end-to-end on a throwaway repo ----------------------------------
    repo = tempfile.mkdtemp(prefix="reflog-audit-t-")
    def g(*a):
        return _git(repo, "-c", "user.name=t", "-c", "user.email=t@t", *a)
    g("init", "-q", "-b", "main")
    def commit(name, fname, content):
        open(_os.path.join(repo, fname), "w").write(content)
        g("add", "-A")
        g("commit", "-q", "-m", name)
        return g("rev-parse", "HEAD").strip()
    commit("c1 benign", "readme.md", "hello\n")
    ghp = "ghp_" + "A1b2C3d4E5f6G7h8J9k0L1m2N3p4Q5r6S7t8"
    c2 = commit(f"c2 oops rotate {ghp}", "deploy.env",
                "AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE\n")
    g("reset", "-q", "--hard", "HEAD~1")            # c2 now reflog-only
    g("checkout", "-q", "-b", "leak")
    pem = commit("leak key", "id_ed25519",
                 "-----BEGIN OPENSSH PRIVATE KEY-----\nb3BlbnNzaC1rZXk\n"
                 "-----END OPENSSH PRIVATE KEY-----\n")
    g("checkout", "-q", "main")
    g("branch", "-q", "-D", "leak")                 # pem commit unreachable
    r = subprocess.run(["git", "-C", repo, "hash-object", "-w", "--stdin"],
                       input="slack_token = xoxb-1234567890-ABCDEFGH\n",
                       capture_output=True, text=True)
    dangling_blob = r.stdout.strip()
    assert dangling_blob and dangling_blob not in \
        g("rev-list", "--objects", "--all").split(), "blob must be dangling"

    findings, stats = audit_repo(repo)
    # --include-reachable sweeps ref-visible history too, labeled HISTORY
    # (a secret still IN history is out of the default's scope by design)
    histrepo = tempfile.mkdtemp(prefix="reflog-audit-h-")
    open(_os.path.join(histrepo, "k.env"), "w").write(
        "key = AKIAIOSFODNN7EXAMPLE\n")
    _git(histrepo, "init", "-q", "-b", "main")
    _git(histrepo, "-c", "user.name=t", "-c", "user.email=t@t", "add", "-A")
    _git(histrepo, "-c", "user.name=t", "-c", "user.email=t@t", "commit",
         "-q", "-m", "reachable secret")
    assert audit_repo(histrepo)[0] == []  # visible to git log: not our scope
    hf = audit_repo(histrepo, include_reachable=True)[0]
    assert any(f["where"].startswith("HISTORY:") and
               f["rule"] == "AWS_ACCESS_KEY" for f in hf), hf
    by_rule = {f["rule"] for f in findings}
    assert {"AWS_ACCESS_KEY", "PEM_PRIVATE_KEY", "SLACK_TOKEN",
            "GITHUB_TOKEN"} <= by_rule, (by_rule, stats)
    where = {f["where"] for f in findings}
    assert any(w.startswith("REFLOG:") for w in where), where
    assert any(w.startswith("DANGLING:") for w in where), where
    # headline claim: the AKIA blob is invisible to git log --all…
    visible = g("rev-list", "--objects", "--all")
    assert c2 not in visible and pem not in visible \
        and "deploy.env" not in visible
    # …yet our tool still recovers it (with the object id to cat-file)
    ak = [f for f in findings if f["rule"] == "AWS_ACCESS_KEY"][0]
    assert ak["oid"] and ak["oid"] in table_ids(repo)
    # a secret pasted into a commit SUBJECT survives in .git/logs messages
    # even after the commit object itself is pruned:
    assert any(f["where"].startswith("reflog:") for f in findings), findings
    for f in findings:  # never leak the full secret in any report channel
        assert "AKIAIOSFODNN7EXAMPLE" not in json.dumps(f)
    # remediation actually clears it: drop ORIG_HEAD (reset set it), expire
    # reflogs, prune orphans — then the same audit must come back empty
    g("update-ref", "-d", "ORIG_HEAD")
    g("reflog", "expire", "--expire=now", "--all")
    g("gc", "-q", "--prune=now")
    findings2, stats2 = audit_repo(repo)
    assert findings2 == [], (findings2, stats2)
    # clean repo from scratch: rc 0, zero findings
    clean = tempfile.mkdtemp(prefix="reflog-audit-c-")
    _git(clean, "init", "-q", "-b", "main")
    open(_os.path.join(clean, "a.txt"), "w").write("just text\n")
    _git(clean, "-c", "user.name=t", "-c", "user.email=t@t", "add", "-A")
    _git(clean, "-c", "user.name=t", "-c", "user.email=t@t", "commit",
         "-q", "-m", "init")
    assert audit_repo(clean)[0] == []
    print("reflog-audit self-test OK "
          "(scan rules + redaction, reflog-only commit, dangling blob + "
          "commit, reflog-message leak, gc remediation, clean repo)")


def table_ids(repo):
    return set(_object_table(repo))

if __name__ == "__main__":
    if "--self-test" in sys.argv:
        self_test()  # falls through; rc 0 (probe hook runs after this line)
    else:
        try:
            raise SystemExit(main())
        except BrokenPipeError:  # `| head` — downstream closed early
            os.dup2(os.open(os.devnull, os.O_WRONLY), sys.stdout.fileno())
            raise SystemExit(0)
