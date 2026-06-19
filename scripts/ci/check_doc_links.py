#!/usr/bin/env python3
"""Validate that relative Markdown links resolve to real files.

Usage: check_doc_links.py [FILE ...]

Only local relative links are checked. URLs, mailto, pure anchors, and template
placeholders (links containing ``XXXX``) are skipped.
"""

from __future__ import annotations

import re
import sys
from pathlib import Path

LINK = re.compile(r"\[[^\]]*\]\(([^)]+)\)")


def is_external(target: str) -> bool:
    return (
        target.startswith(("http://", "https://", "mailto:", "#"))
        or "XXXX" in target
    )


def main(argv: list[str]) -> int:
    errors: list[str] = []
    for arg in argv:
        path = Path(arg)
        if path.suffix != ".md" or not path.is_file():
            continue
        try:
            text = path.read_text(encoding="utf-8")
        except (UnicodeDecodeError, OSError):
            continue
        for match in LINK.finditer(text):
            target = match.group(1).split(" ")[0].strip()
            if not target or is_external(target):
                continue
            target = target.split("#", 1)[0]
            if not target:
                continue
            resolved = (path.parent / target).resolve()
            if not resolved.exists():
                errors.append(f"{path}: broken link -> {target}")

    if errors:
        print("check-doc-links:", file=sys.stderr)
        for e in errors:
            print(f"  {e}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
