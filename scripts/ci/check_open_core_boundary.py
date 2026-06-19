#!/usr/bin/env python3
"""Enforce the open-core boundary (the static half of the mirror leak gate).

Closed directories (`pro/`, proprietary; `incubating/`, not yet published) are
removed from the public mirror by `josh-filter`. For that to produce a
self-contained, leak-free public tree, the open tree must never reach into a
closed one. This gate guarantees the one-way rule:

1. **No open -> closed reference.** A file outside the closed prefixes may not
   point into them via a Cargo `path = "..."` dependency or a resolvable
   Markdown link. closed -> open is fine; open -> closed is forbidden.
2. **No proprietary SPDX leak.** No file outside `pro/` may carry the
   proprietary SPDX header; a leaked header means closed source escaped into the
   public tree.

The dynamic half (run josh-filter, build the filtered tree, push the mirror)
lives in `.github/workflows/mirror.yml` and calls this gate first.

Usage:
    check_open_core_boundary.py            # full working-tree audit
    check_open_core_boundary.py --staged   # only staged files (pre-commit)
    check_open_core_boundary.py --self-test
"""

from __future__ import annotations

import posixpath
import re
import subprocess
import sys

CLOSED_PREFIXES = ("pro/", "incubating/")
PRO_PREFIX = "pro/"
PROPRIETARY_SPDX = "LicenseRef-Awaken-Commercial"

SPDX_HEADER_RE = re.compile(
    r"SPDX-License-Identifier:[^\n]*" + re.escape(PROPRIETARY_SPDX)
)
CARGO_PATH_RE = re.compile(r"""\bpath\s*=\s*["']([^"']+)["']""")
MD_LINK_RE = re.compile(r"\[[^\]]*\]\(([^)]+)\)")
LINK_SCHEMES = ("http://", "https://", "mailto:", "data:", "#")


# --------------------------------------------------------------------------- #
# Pure helpers (operate on relpath + text, so they are self-testable)
# --------------------------------------------------------------------------- #
def is_closed(relpath: str) -> bool:
    return any(relpath.startswith(p) for p in CLOSED_PREFIXES)


def resolve(source_relpath: str, link: str) -> str | None:
    """Normalise a reference to a repo-root-relative POSIX path, or None."""
    link = link.strip().split("#", 1)[0].split("?", 1)[0]
    if not link or link.startswith(LINK_SCHEMES):
        return None
    if link.startswith("/"):
        return posixpath.normpath(link.lstrip("/"))
    base = posixpath.dirname(source_relpath)
    return posixpath.normpath(posixpath.join(base, link))


def closed_references(source_relpath: str, text: str) -> list[str]:
    """References from an open file that resolve into a closed prefix."""
    if is_closed(source_relpath):
        return []  # closed -> anywhere is allowed
    targets: list[str] = []
    if source_relpath.endswith("Cargo.toml"):
        targets += CARGO_PATH_RE.findall(text)
    if source_relpath.endswith(".md"):
        targets += MD_LINK_RE.findall(text)
    hits = []
    for raw in targets:
        resolved = resolve(source_relpath, raw)
        if resolved is not None and is_closed(resolved + "/"):
            hits.append(raw)
    return hits


def spdx_leak(source_relpath: str, text: str) -> bool:
    """A proprietary SPDX header outside pro/ is a leak."""
    if source_relpath.startswith(PRO_PREFIX):
        return False
    return SPDX_HEADER_RE.search(text) is not None


# --------------------------------------------------------------------------- #
# Audit
# --------------------------------------------------------------------------- #
def git_files(staged: bool) -> list[str]:
    if staged:
        args = ["diff", "--cached", "--name-only", "--diff-filter=ACMR"]
    else:
        args = ["ls-files"]
    out = subprocess.run(
        ["git", *args], capture_output=True, text=True, check=False
    ).stdout
    return [p for p in out.splitlines() if p]


def read(relpath: str) -> str | None:
    try:
        with open(relpath, encoding="utf-8") as handle:
            return handle.read()
    except (FileNotFoundError, UnicodeDecodeError, OSError):
        return None


def audit(staged: bool) -> int:
    errors: list[str] = []
    for relpath in git_files(staged):
        text = read(relpath)
        if text is None:
            continue
        for raw in closed_references(relpath, text):
            errors.append(f"{relpath}: open tree references closed path {raw!r}")
        if spdx_leak(relpath, text):
            errors.append(
                f"{relpath}: proprietary SPDX header outside pro/ (leak)"
            )
    if errors:
        print("check-open-core-boundary:", file=sys.stderr)
        for e in errors:
            print(f"  {e}", file=sys.stderr)
        return 1
    return 0


# --------------------------------------------------------------------------- #
# Self-test
# --------------------------------------------------------------------------- #
def self_test() -> int:
    cases = [
        ("crates/x/Cargo.toml", 'path = "../../pro/secret"', True, False),
        ("crates/x/Cargo.toml", 'path = "../runtime"', False, False),
        ("docs/a.md", "see [x](../incubating/plan.md)", True, False),
        ("docs/a.md", "see [x](./b.md) and <https://e.com>", False, False),
        ("pro/x/Cargo.toml", 'path = "../../crates/x"', False, False),
        ("crates/x/src/lib.rs", f"// SPDX-License-Identifier: {PROPRIETARY_SPDX}", False, True),
        ("pro/x/src/lib.rs", f"// SPDX-License-Identifier: {PROPRIETARY_SPDX}", False, False),
    ]
    failures = 0
    for relpath, text, expect_ref, expect_spdx in cases:
        if bool(closed_references(relpath, text)) != expect_ref:
            failures += 1
            print(f"self-test FAILED (ref) [{relpath}]: {text!r}", file=sys.stderr)
        if spdx_leak(relpath, text) != expect_spdx:
            failures += 1
            print(f"self-test FAILED (spdx) [{relpath}]: {text!r}", file=sys.stderr)
    if failures:
        return 1
    print("check-open-core-boundary self-test: ok")
    return 0


def main(argv: list[str]) -> int:
    if argv and argv[0] == "--self-test":
        return self_test()
    staged = bool(argv) and argv[0] == "--staged"
    return audit(staged)


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
