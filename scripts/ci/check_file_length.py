#!/usr/bin/env python3
"""Report large source files as architectural diagnostics.

Usage:
    check_file_length.py [--staged] [--self-test]

Source files at or above 1000 lines receive a warning. Line count does not fail
the check: responsibility, ownership and behavior determine whether a change is
needed. Keep tests with the behavior they verify.
"""

from __future__ import annotations

import argparse
import contextlib
import io
import subprocess
import sys
from pathlib import Path
from unittest import mock

REPO_ROOT = Path(__file__).resolve().parent.parent.parent
WARN_LIMIT = 1000
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


def findings(counts: dict[str, int]) -> list[str]:
    warnings: list[str] = []
    advice = "review responsibility and ownership; line count is diagnostic"
    for rel, count in sorted(counts.items()):
        if count >= WARN_LIMIT:
            warnings.append(f"{rel}: {count} lines >= {WARN_LIMIT} ({advice})")
    return warnings


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

    warnings = findings(counts)
    if warnings:
        print("check-file-length warnings:", file=sys.stderr)
        for warning in warnings:
            print(f"  {warning}", file=sys.stderr)
    return 0


def self_test() -> int:
    # Boundary-value design: below 1000 -> no diagnostic; at/above 1000 ->
    # one warning. Cross the former 2000 hard boundary and a much larger value
    # to prove that size alone cannot become a commit failure again. Staged
    # and working-tree entrypoints must report the same nonblocking outcome;
    # source/generated-file selection remains the original independent rule.
    warnings = findings(
        {
            "under.rs": WARN_LIMIT - 1,
            "warn.rs": WARN_LIMIT,
            "before-old-limit.rs": 1999,
            "old-limit.rs": 2000,
            "after-old-limit.rs": 2001,
            "large.rs": 10_000,
        }
    )
    failures: list[str] = []
    if len(warnings) != 5 or any("under.rs:" in warning for warning in warnings):
        failures.append(f"expected five size diagnostics and no below-limit warning, got {warnings}")
    for staged in (False, True):
        output = io.StringIO()
        with (
            mock.patch(__name__ + ".tracked_files", return_value=["large.rs"]) as files,
            mock.patch(__name__ + ".line_count", return_value=10_000) as count,
            contextlib.redirect_stderr(output),
        ):
            status = run_check(staged)
        files.assert_called_once_with(staged)
        count.assert_called_once_with("large.rs", staged)
        if status != 0 or "large.rs: 10000 lines" not in output.getvalue():
            failures.append(f"expected visible nonblocking size diagnostic for staged={staged}")
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
