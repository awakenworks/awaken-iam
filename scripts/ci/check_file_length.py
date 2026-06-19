#!/usr/bin/env python3
"""Warn on large source files and reject oversized ones.

Usage:
    check_file_length.py [--staged] [--self-test]

Source files at or above 1000 lines receive a warning. Files at or above 2000 lines
fail the check. The remediation is to split by responsibility and keep tests
with the behavior they verify; do not merely move tests out to hide length.
"""

from __future__ import annotations

import argparse
import subprocess
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent.parent
WARN_LIMIT = 1000
ERROR_LIMIT = 2000
CODE_SUFFIXES = {
    ".c",
    ".cc",
    ".cpp",
    ".cxx",
    ".cjs",
    ".cs",
    ".go",
    ".h",
    ".hpp",
    ".java",
    ".js",
    ".jsx",
    ".mjs",
    ".py",
    ".rs",
    ".sh",
    ".sql",
    ".ts",
    ".tsx",
    ".vue",
}
GENERATED_MARKERS = (
    "/generated/",
    ".generated.",
    "_generated.",
)
IGNORED_PREFIXES = (
    "target/",
    "node_modules/",
    "dist/",
    "build/",
    "coverage/",
    ".next/",
)


def is_source_file(rel: str) -> bool:
    path = Path(rel)
    if path.suffix not in CODE_SUFFIXES:
        return False
    if any(rel.startswith(prefix) for prefix in IGNORED_PREFIXES):
        return False
    if any(marker in f"/{rel}" for marker in GENERATED_MARKERS):
        return False
    return True


def findings(counts: dict[str, int]) -> tuple[list[str], list[str]]:
    warnings: list[str] = []
    errors: list[str] = []
    advice = (
        "split by responsibility; keep tests with the behavior they verify "
        "rather than moving tests out just to reduce line count"
    )
    for rel, count in sorted(counts.items()):
        if count >= ERROR_LIMIT:
            errors.append(f"{rel}: {count} lines >= {ERROR_LIMIT} ({advice})")
        elif count >= WARN_LIMIT:
            warnings.append(f"{rel}: {count} lines >= {WARN_LIMIT} ({advice})")
    return warnings, errors


def git_lines(args: list[str]) -> list[str]:
    out = subprocess.check_output(args, cwd=REPO_ROOT, text=True)
    return [line for line in out.splitlines() if line]


def tracked_files(staged: bool) -> list[str]:
    if staged:
        return git_lines(["git", "diff", "--cached", "--name-only", "--diff-filter=ACMR"])
    return git_lines(["git", "ls-files"])


def line_count(rel: str, staged: bool) -> int | None:
    if staged:
        result = subprocess.run(
            ["git", "show", f":{rel}"],
            cwd=REPO_ROOT,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            check=False,
        )
        if result.returncode != 0:
            return None
        return len(result.stdout.splitlines())

    path = REPO_ROOT / rel
    if not path.is_file():
        return None
    try:
        with path.open("rb") as fh:
            return sum(1 for _ in fh)
    except OSError:
        return None


def run_check(staged: bool) -> int:
    counts: dict[str, int] = {}
    for rel in tracked_files(staged):
        if not is_source_file(rel):
            continue
        count = line_count(rel, staged)
        if count is not None:
            counts[rel] = count

    warnings, errors = findings(counts)
    if warnings:
        print("check-file-length warnings:", file=sys.stderr)
        for warning in warnings:
            print(f"  {warning}", file=sys.stderr)
    if errors:
        print("check-file-length errors:", file=sys.stderr)
        for error in errors:
            print(f"  {error}", file=sys.stderr)
        return 1
    return 0


def self_test() -> int:
    warnings, errors = findings(
        {
            "under.rs": WARN_LIMIT - 1,
            "warn.rs": WARN_LIMIT,
            "limit.rs": ERROR_LIMIT,
            "error.rs": ERROR_LIMIT + 1,
        }
    )
    failures: list[str] = []
    if len(warnings) != 1 or "warn.rs" not in warnings[0]:
        failures.append(f"expected one warning at {WARN_LIMIT}, got {warnings}")
    if len(errors) != 2 or not any("limit.rs" in e for e in errors):
        failures.append(f"expected errors at and above {ERROR_LIMIT}, got {errors}")
    if not is_source_file("crates/example/src/lib.rs"):
        failures.append("expected Rust source to be checked")
    if is_source_file("web/src/types/_generated.d.ts"):
        failures.append("expected generated files to be skipped")
    if failures:
        print("check-file-length self-test failed:", file=sys.stderr)
        for failure in failures:
            print(f"  {failure}", file=sys.stderr)
        return 1
    return 0


def main(argv: list[str]) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--staged", action="store_true", help="check staged content")
    parser.add_argument("--self-test", action="store_true", help="run script self-tests")
    args = parser.parse_args(argv)
    if args.self_test:
        return self_test()
    return run_check(args.staged)


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
