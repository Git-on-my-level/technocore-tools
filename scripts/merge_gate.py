#!/usr/bin/env python3
"""merge_gate.py — the ONLY sanctioned merge lane for technocore-tools.

Since only our account can merge (sole collaborator), GitHub-side branch
protection can't block US — so this gate is the enforcement. It refuses to
merge any PR whose CI checks are not green (or still pending), and refuses
PRs that touch anything outside tools/, scripts/, docs/, README.md (defense
in depth: the fleet never merges workflow/permission changes via automation).

Usage: python3 scripts/merge_gate.py <PR-number> [--reason "context"]
Exit 0 = merged; nonzero = refused (prints why).
"""
import subprocess
import sys

REPO = "Git-on-my-level/technocore-tools"
ALLOWED_PATH_PREFIXES = ("tools/", "scripts/", "docs/", "")


def sh(*args):
    return subprocess.run(args, capture_output=True, text=True)


def main() -> int:
    if len(sys.argv) < 2 or not sys.argv[1].isdigit():
        print("usage: merge_gate.py <PR-number>", file=sys.stderr)
        return 2
    pr = sys.argv[1]

    # 1. CI checks must ALL be green (fail or pending -> refuse)
    checks = sh("gh", "pr", "checks", pr, "-R", REPO)
    if checks.returncode != 0:
        print(f"REFUSED: PR #{pr} CI not green:\n{checks.stdout or checks.stderr}")
        return 1

    # 2. Diff must stay inside fleet-sanctioned paths
    files = sh("gh", "pr", "view", pr, "-R", REPO, "--json", "files", "-q",
               ".files[].path")
    if files.returncode != 0:
        print(f"REFUSED: could not read PR #{pr} files: {files.stderr}")
        return 1
    bad = [f for f in files.stdout.split() if f and not f.startswith(("tools/", "scripts/", "docs/"))
           and f not in ("README.md", ".gitignore", "ANNOUNCE.md", "LICENSE")]
    if bad:
        print(f"REFUSED: PR #{pr} touches protected paths: {bad} "
              "(automation may not merge workflow/config changes)")
        return 1

    merge = sh("gh", "pr", "merge", pr, "-R", REPO, "--squash", "--delete-branch")
    if merge.returncode != 0:
        print(f"REFUSED: merge failed: {merge.stderr}")
        return 1
    print(f"MERGED PR #{pr} (CI green, paths sanctioned)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
