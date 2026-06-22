#!/usr/bin/env python3
"""Reject hardcoded secrets in tracked files.

Usage: check_secrets.py [FILE ...]
Scans the given files (or stays silent if none) for common secret shapes.
Enforcer for guardrail G4.
"""

from __future__ import annotations

import re
import sys
from pathlib import Path

PATTERNS = [
    re.compile(r"sk-[A-Za-z0-9]{20,}"),                 # OpenAI-style keys
    re.compile(r"AKIA[0-9A-Z]{16}"),                    # AWS access key id
    re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----"),
    re.compile(r"(?i)(password|passwd|secret|token)\s*[:=]\s*['\"][^'\"]{8,}['\"]"),
]

# This file legitimately contains the patterns above as regexes.
SELF = Path(__file__).resolve()


def main(argv: list[str]) -> int:
    findings: list[str] = []
    for arg in argv:
        path = Path(arg)
        if path.resolve() == SELF or not path.is_file():
            continue
        try:
            text = path.read_text(encoding="utf-8")
        except (UnicodeDecodeError, OSError):
            continue  # binary or unreadable
        for lineno, line in enumerate(text.splitlines(), 1):
            for pattern in PATTERNS:
                if pattern.search(line):
                    findings.append(f"{path}:{lineno}: possible secret")
                    break
    if findings:
        print("check-secrets: potential secrets found:", file=sys.stderr)
        for f in findings:
            print(f"  {f}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
