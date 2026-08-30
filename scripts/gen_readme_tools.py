#!/usr/bin/env python3
"""gen_readme_tools.py — regenerate the README tool table from tools/*.py.

Single source of truth: each tool's module docstring (first paragraph).
The README section between <!-- TOOLS:BEGIN --> and <!-- TOOLS:END --> is
fully generated — never edit it by hand. A tool with no docstring is still
listed (marked TODO) rather than silently dropped: silent-dropping is how
the README went stale in the first place.

Usage:
  python3 scripts/gen_readme_tools.py            # rewrite README.md in place
  python3 scripts/gen_readme_tools.py --check    # exit 1 if stale (CI/hook mode)
"""
import ast
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
TOOLS = ROOT / "tools"
README = ROOT / "README.md"
BEGIN = "<!-- TOOLS:BEGIN -->"
END = "<!-- TOOLS:END -->"

# only third-party dependency in the repo today; extend as needed
THIRD_PARTY = {"cryptography": "cryptography"}


def summarize(path: Path) -> tuple[str, str]:
    """Return (one-line description, deps-label) for a tool file."""
    src = path.read_text(encoding="utf-8")
    desc = ""
    try:
        doc = ast.get_docstring(ast.parse(src))
        if doc:
            first_para = re.split(r"\n\s*\n", doc.strip())[0]
            desc = re.sub(r"\s+", " ", first_para).strip()
    except SyntaxError:
        pass
    if not desc:
        desc = "TODO: add a module docstring"
    # keep the table readable
    if len(desc) > 160:
        desc = desc[:157] + "..."

    deps = set()
    try:
        tree = ast.parse(src)
        for node in ast.walk(tree):
            mods = []
            if isinstance(node, ast.Import):
                mods = [a.name.split(".")[0] for a in node.names]
            elif isinstance(node, ast.ImportFrom) and node.module and node.level == 0:
                mods = [node.module.split(".")[0]]
            deps.update(THIRD_PARTY[m] for m in mods if m in THIRD_PARTY)
    except SyntaxError:
        pass
    return desc, ", ".join(sorted(deps)) if deps else "stdlib"


def build_table() -> str:
    rows = ["| Tool | What it does | Deps |", "|---|---|---|"]
    for path in sorted(TOOLS.glob("*.py")):
        if path.name.startswith("_"):
            continue
        desc, deps = summarize(path)
        rows.append(f"| [`{path.name}`](tools/{path.name}) | {desc} | {deps} |")
    return "\n".join(rows)


def main() -> int:
    readme = README.read_text(encoding="utf-8")
    if BEGIN not in readme or END not in readme:
        print(f"README.md missing {BEGIN}/{END} markers", file=sys.stderr)
        return 2
    head, _, rest = readme.partition(BEGIN)
    _, _, tail = rest.partition(END)
    new = head + BEGIN + "\n" + build_table() + "\n" + END + tail
    if "--check" in sys.argv:
        if new != readme:
            print("README tool table is STALE — run: python3 scripts/gen_readme_tools.py",
                  file=sys.stderr)
            return 1
        print("README tool table up to date")
        return 0
    if new == readme:
        print("README tool table already up to date")
        return 0
    README.write_text(new, encoding="utf-8")
    print(f"README tool table regenerated from {len(list(TOOLS.glob('*.py')))} tools")
    return 0


if __name__ == "__main__":
    sys.exit(main())
