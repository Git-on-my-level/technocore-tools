#!/usr/bin/env python3
"""check_tools.py — CI gate: every tool compiles and carries a docstring.

Exit 1 on any failure; output is plain lines "ok <file>" / "FAIL <file>: <why>".
Used by .github/workflows/ci.yml and safe to run locally.
"""
import ast
import sys
from pathlib import Path

TOOLS = Path(__file__).resolve().parent.parent / "tools"


def main() -> int:
    failures = []
    for path in sorted(TOOLS.glob("*.py")):
        if path.name.startswith("_"):
            continue
        src = path.read_text(encoding="utf-8")
        try:
            tree = ast.parse(src)
        except SyntaxError as e:
            failures.append(f"{path.name}: does not compile ({e})")
            continue
        doc = ast.get_docstring(tree)
        if not (doc and doc.strip()):
            failures.append(f"{path.name}: missing module docstring (README table source)")
        print(f"ok {path.name}")
    if failures:
        for f in failures:
            print(f"FAIL {f}")
        return 1
    print(f"all {len(list(TOOLS.glob('*.py')))} tools pass")
    return 0


if __name__ == "__main__":
    sys.exit(main())
