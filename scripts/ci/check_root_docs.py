#!/usr/bin/env python3
"""Keep the repository root tidy and ban project-management documents.

Usage: check_root_docs.py [FILE ...]

- Only an allowlisted set of Markdown files may live in the repo root.
- No file anywhere may be a status/progress/report document.
"""

from __future__ import annotations

import sys
from pathlib import Path

ROOT_MD_ALLOWLIST = {
    "README.md",
    "README.zh-CN.md",
    "CHANGELOG.md",
    "CONTRIBUTING.md",
    "DEVELOPMENT.md",
    "SECURITY.md",
    "CODE_OF_CONDUCT.md",
    "AGENTS.md",
    "CLAUDE.md",
    "NOTICE.md",
}

FORBIDDEN_STEMS = (
    "STATUS",
    "REPORT",
    "SUMMARY",
    "PROGRESS",
    "ROADMAP",
    "PLAN",
    "TODO",
    "HANDOFF",
    "BACKLOG",
    "MILESTONE",
)


def main(argv: list[str]) -> int:
    errors: list[str] = []
    for arg in argv:
        path = Path(arg)
        parts = path.parts
        name = path.name

        if path.suffix == ".md" and len(parts) == 1 and name not in ROOT_MD_ALLOWLIST:
            errors.append(f"{path}: Markdown files are not allowed in the repo root")

        stem = path.stem.upper()
        if any(token in stem for token in FORBIDDEN_STEMS):
            errors.append(f"{path}: status/progress/report documents are not allowed")

    if errors:
        print("check-root-docs:", file=sys.stderr)
        for e in errors:
            print(f"  {e}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
