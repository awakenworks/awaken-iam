#!/usr/bin/env python3
"""Validate a commit message against the project convention.

Usage: check_commit_shape.py COMMIT_MSG_FILE

Format: ``<emoji> <type>(<scope>): <subject>``
- subject <= 100 chars
- no AI-generation markers or Co-Authored-By trailers
- no project-management vocabulary
"""

from __future__ import annotations

import re
import sys

TYPES = (
    "feat",
    "fix",
    "refactor",
    "docs",
    "test",
    "chore",
    "perf",
    "style",
    "build",
    "ci",
    "revert",
)

HEADER = re.compile(
    r"^\S+ (?:" + "|".join(TYPES) + r")(?:\([a-z0-9.-]+\))?: .+"
)

FORBIDDEN_SUBSTRINGS = (
    "co-authored-by:",
    "generated with",
    "🤖",
)

PM_TERMS = ("sprint", "phase ", "owner:", "assignee", "eta", "estimate")


def main(argv: list[str]) -> int:
    if not argv:
        print("check-commit-shape: missing commit message file", file=sys.stderr)
        return 1

    with open(argv[0], encoding="utf-8") as handle:
        lines = handle.read().splitlines()

    # Ignore comment lines that git includes in the template.
    content = [ln for ln in lines if not ln.startswith("#")]
    if not content:
        print("check-commit-shape: empty commit message", file=sys.stderr)
        return 1

    errors: list[str] = []
    header = content[0]

    if not HEADER.match(header):
        errors.append(
            "header must be `<emoji> <type>(<scope>): <subject>` "
            f"with type in {{{', '.join(TYPES)}}}"
        )
    if len(header) > 100:
        errors.append(f"header is {len(header)} chars (max 100)")
    if len(content) > 1 and content[1].strip():
        errors.append("leave a blank line between subject and body")

    lowered = "\n".join(content).lower()
    for token in FORBIDDEN_SUBSTRINGS:
        if token in lowered:
            errors.append(f"forbidden marker: {token!r}")
    for token in PM_TERMS:
        if token in lowered:
            errors.append(f"project-management term not allowed: {token!r}")

    if errors:
        print("check-commit-shape:", file=sys.stderr)
        for e in errors:
            print(f"  {e}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
