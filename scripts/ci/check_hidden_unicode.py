#!/usr/bin/env python3
"""Reject hidden / bidirectional Unicode control characters.

Usage: check_hidden_unicode.py [FILE ...]

Defends against Trojan-Source style attacks: bidi overrides, zero-width
characters, and BOMs can make source read differently from how it compiles.
This mirrors the lefthook pre-commit check in CI so such characters cannot
reach the default branch even if local hooks are bypassed.
"""

from __future__ import annotations

import re
import sys
from pathlib import Path

# Inclusive codepoint ranges to reject: the Trojan-Source bidi set, zero-width
# characters, word joiner, BOM, and the Arabic letter mark. Built from numbers
# so this file stays free of the very characters it bans.
_RANGES = [
    (0x200B, 0x200F),  # zero-width space/joiners + LRM/RLM
    (0x202A, 0x202E),  # bidi embeddings and overrides
    (0x2060, 0x2064),  # word joiner + invisible operators
    (0x2066, 0x2069),  # bidi isolates
    (0xFEFF, 0xFEFF),  # BOM / zero-width no-break space
    (0x061C, 0x061C),  # Arabic letter mark
]
_CLASS = "".join(
    f"{chr(lo)}-{chr(hi)}" if lo != hi else chr(lo) for lo, hi in _RANGES
)
FORBIDDEN = re.compile(f"[{_CLASS}]")


def main(argv: list[str]) -> int:
    findings: list[str] = []
    for arg in argv:
        path = Path(arg)
        if not path.is_file():
            continue
        try:
            text = path.read_text(encoding="utf-8")
        except (UnicodeDecodeError, OSError):
            continue  # binary or unreadable
        for lineno, line in enumerate(text.splitlines(), 1):
            match = FORBIDDEN.search(line)
            if match:
                cp = ord(match.group())
                findings.append(f"{path}:{lineno}: hidden unicode U+{cp:04X}")
    if findings:
        print("check-hidden-unicode:", file=sys.stderr)
        for f in findings:
            print(f"  {f}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
