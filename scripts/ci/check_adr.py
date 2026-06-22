#!/usr/bin/env python3
"""Validate ADR metadata.

Usage: check_adr.py [FILE ...]

For every ADR under ``docs/adr/`` (the template and README are skipped) this
checks two independent fields:

- **Status** — the decision state. One of: Proposed, Accepted, Superseded,
  Deprecated.
- **Implementation** — an independent review signal, not the decision status.
  One of: planned, in-progress, done, n/a.

Both fields must be present and carry an allowed value. The fields are
deliberately not cross-validated: implementation progress never gates the
decision status.
"""

from __future__ import annotations

import re
import sys
from pathlib import Path

STATUS_VALUES = {"Proposed", "Accepted", "Superseded", "Deprecated"}
IMPLEMENTATION_VALUES = {"planned", "in-progress", "done", "n/a"}

STATUS_RE = re.compile(r"^\s*-\s*\*\*Status:\*\*\s*(.+?)\s*$", re.MULTILINE)
IMPL_RE = re.compile(r"^\s*-\s*\*\*Implementation:\*\*\s*(.+?)\s*$", re.MULTILINE)

# Files that carry placeholder metadata rather than a real decision.
SKIP_NAMES = {"0000-template.md", "README.md"}


def is_adr(path: Path) -> bool:
    return (
        path.suffix == ".md"
        and "adr" in path.parts
        and path.name not in SKIP_NAMES
    )


def first_token(value: str) -> str:
    # Status may be e.g. "Superseded by [ADR-0007](...)"; the state is the first
    # word. Implementation is a single token.
    return value.split()[0] if value.split() else ""


def check_file(path: Path) -> list[str]:
    errors: list[str] = []
    try:
        text = path.read_text(encoding="utf-8")
    except (UnicodeDecodeError, OSError) as exc:
        return [f"{path}: cannot read ({exc})"]

    status_match = STATUS_RE.search(text)
    if not status_match:
        errors.append(f"{path}: missing `- **Status:**` line")
    else:
        state = first_token(status_match.group(1))
        if state not in STATUS_VALUES:
            errors.append(
                f"{path}: Status `{state}` not in {sorted(STATUS_VALUES)}"
            )

    impl_match = IMPL_RE.search(text)
    if not impl_match:
        errors.append(
            f"{path}: missing `- **Implementation:**` line "
            "(use n/a for code-less decisions)"
        )
    else:
        impl = first_token(impl_match.group(1))
        if impl not in IMPLEMENTATION_VALUES:
            errors.append(
                f"{path}: Implementation `{impl}` not in "
                f"{sorted(IMPLEMENTATION_VALUES)}"
            )

    return errors


def main(argv: list[str]) -> int:
    paths = [Path(a) for a in argv] if argv else sorted(Path("docs/adr").glob("*.md"))
    errors: list[str] = []
    for path in paths:
        if is_adr(path) and path.is_file():
            errors.extend(check_file(path))

    if errors:
        print("check-adr:", file=sys.stderr)
        for e in errors:
            print(f"  {e}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
