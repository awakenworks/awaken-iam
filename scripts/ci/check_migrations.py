#!/usr/bin/env python3
"""Commit-time validation of migration best practices.

A self-contained, dependency-free hook that any repository using
`awaken-scoped-migration` can drop in (copy this one file anywhere, then wire it
into a git hook). It **auto-discovers** the repo's migration files — no
configuration required — and enforces every best practice that is mechanically
checkable, so "best practice" and "what the hook checks" are the same list:

  1. Immutability (append-only)   — never edit/delete a shipped migration line.
  2. Destructive-op guard         — DROP / TRUNCATE / DELETE-without-WHERE needs a marker.
  3. Deterministic statements     — no IF NOT EXISTS / IF EXISTS / CREATE OR REPLACE.
  4. Portable SQL                 — no raw dialect types; use {tokens}.
  5. Readable, unique versions    — version labels are `V0001`-form, no duplicates.

Determinism (3): the ledger already guarantees each migration runs exactly once,
so conditional DDL is redundant *and* masks drift — `CREATE TABLE IF NOT EXISTS`
silently passes when the ledger says "not applied" but the table already exists,
hiding the inconsistency. A bare `CREATE TABLE` fails loudly instead. (The
ledger's own bootstrap DDL legitimately uses IF NOT EXISTS, but that lives in the
crate, which auto-discovery excludes.)

Auto-discovery: a file is a migration file if it *constructs* migrations
(`MigrationBundle::new`, `bundle_from_statements`, `Migration::new(` in a `.rs`,
or a `.sql` under a migration path) — and is **not** the crate's own
implementation (a file defining `MigrationBundle` / `plan` / a `MigrationRunner`
is excluded). A `.migration-paths` file (globs, one per line) at the repo root
*adds* paths but is never required.

Modes:
  --audit        discover every migration file and check its full content (CI / adoption)
  --staged       check the migration files in the index against HEAD (pre-commit)
  --base REF     check the migration files in REF...HEAD (pre-push / CI)
  --self-test    run the checks against synthetic fixtures

`--audit` runs the static checks (2–5) over the whole tree; immutability (1) is
diff-only and applies in `--staged` / `--base`.

In-diff override markers (a comment on an added line), so an intentional
exception is reviewable rather than silent:
  migration-allow-edit            modify/delete an existing migration line
  migration-allow-destructive     an added destructive statement
  migration-allow-raw-sql         an added raw dialect type (escape hatch)
  migration-allow-conditional     an added conditional/non-deterministic statement
"""

from __future__ import annotations

import fnmatch
import re
import subprocess
import sys

ALLOW_EDIT = "migration-allow-edit"
ALLOW_DESTRUCTIVE = "migration-allow-destructive"
ALLOW_RAW_SQL = "migration-allow-raw-sql"
ALLOW_CONDITIONAL = "migration-allow-conditional"

# A file that *constructs* migrations is a migration file.
CONSTRUCTS_RE = r"MigrationBundle::new|bundle_from_statements|Migration::new\("
# A file that *defines* the machinery is the crate itself, never a migration.
DEFINES_RE = r"pub struct MigrationBundle|pub fn plan|MigrationRunner|impl MigrationBundle"

DESTRUCTIVE_RE = re.compile(
    r"\b(DROP\s+TABLE|DROP\s+COLUMN|DROP\s+SCHEMA|TRUNCATE|ALTER\s+TABLE\s+\w+\s+DROP)\b",
    re.IGNORECASE,
)
DELETE_NO_WHERE_RE = re.compile(r"\bDELETE\s+FROM\b(?!.*\bWHERE\b)", re.IGNORECASE)
# Conditional / state-dependent DDL: the ledger guarantees exactly-once, so these
# are redundant and mask drift. Migrations must be deterministic.
NONDETERMINISTIC_RE = re.compile(
    r"\bIF\s+NOT\s+EXISTS\b|\bIF\s+EXISTS\b|\bCREATE\s+OR\s+REPLACE\b",
    re.IGNORECASE,
)
RAW_DIALECT_RE = re.compile(
    r"\b(JSONB|TIMESTAMPTZ|BIGSERIAL|SERIAL|AUTOINCREMENT|CURRENT_TIMESTAMP)\b"
    r"|\bnow\s*\(\s*\)",
    re.IGNORECASE,
)
VERSION_LABEL_RE = re.compile(r"\bV(\d+)(?!\d)")
WELL_FORMED_VERSION_RE = re.compile(r"^V\d{4,}$")


# --------------------------------------------------------------------------- #
# Pure checks (string-only, self-testable without git)
# --------------------------------------------------------------------------- #
def is_editable_removal(line: str) -> bool:
    s = line.strip()
    return s == "" or s.startswith(("//", "--", "#", "/*", "*"))


def immutability_violations(removed: list[str], override: bool) -> list[str]:
    if override:
        return []
    return [ln.strip() for ln in removed if not is_editable_removal(ln)]


def destructive_violations(lines: list[str], override: bool) -> list[str]:
    if override:
        return []
    return [
        ln.strip()
        for ln in lines
        if DESTRUCTIVE_RE.search(ln) or DELETE_NO_WHERE_RE.search(ln)
    ]


def nondeterministic_violations(lines: list[str], override: bool) -> list[str]:
    if override:
        return []
    return [ln.strip() for ln in lines if NONDETERMINISTIC_RE.search(ln)]


def raw_sql_violations(lines: list[str], override: bool) -> list[str]:
    if override:
        return []
    return [ln.strip() for ln in lines if RAW_DIALECT_RE.search(ln)]


def version_violations(lines: list[str], filenames: list[str]) -> list[str]:
    out: list[str] = []
    seen: set[str] = set()
    for source in [*filenames, *lines]:
        for m in VERSION_LABEL_RE.finditer(source):
            label = "V" + m.group(1)
            if not WELL_FORMED_VERSION_RE.match(label):
                out.append(f"version `{label}` is not zero-padded `V0001`-form")
            if label in seen:
                out.append(f"duplicate version `{label}`")
            seen.add(label)
    return out


def static_checks(lines: list[str], path: str, added_for_markers: list[str]) -> list[str]:
    """Practices 2-5 over `lines`; markers are read from `added_for_markers`."""
    out = []
    for bad in destructive_violations(lines, marker(added_for_markers, ALLOW_DESTRUCTIVE)):
        out.append(f"{path}: destructive op without `{ALLOW_DESTRUCTIVE}`: {bad!r}")
    for bad in nondeterministic_violations(lines, marker(added_for_markers, ALLOW_CONDITIONAL)):
        out.append(f"{path}: non-deterministic/conditional DDL (the ledger ensures once): {bad!r}")
    for bad in raw_sql_violations(lines, marker(added_for_markers, ALLOW_RAW_SQL)):
        out.append(f"{path}: raw dialect type (use a portable token): {bad!r}")
    for bad in version_violations(lines, [path]):
        out.append(f"{path}: {bad}")
    return out


def marker(added: list[str], name: str) -> bool:
    return any(name in line for line in added)


# --------------------------------------------------------------------------- #
# git plumbing + auto-discovery
# --------------------------------------------------------------------------- #
def git(args: list[str]) -> tuple[int, str]:
    proc = subprocess.run(["git", *args], capture_output=True, text=True)
    return proc.returncode, proc.stdout


def repo_root() -> str | None:
    code, out = git(["rev-parse", "--show-toplevel"])
    return out.strip() if code == 0 else None


def extra_globs() -> tuple[str, ...]:
    root = repo_root()
    if not root:
        return ()
    try:
        with open(f"{root}/.migration-paths", encoding="utf-8") as fh:
            return tuple(ln.strip() for ln in fh if ln.strip() and not ln.startswith("#"))
    except FileNotFoundError:
        return ()


def discover() -> list[str]:
    """Every tracked migration file, found automatically (no config required)."""
    candidates: set[str] = set()
    # Rust files that construct migrations.
    _, out = git(["grep", "-lE", CONSTRUCTS_RE, "--", "*.rs"])
    candidates.update(out.split())
    # SQL files on a migration path.
    _, out = git(["ls-files", "*.sql"])
    candidates.update(p for p in out.split() if "migrat" in p.lower())
    # Anything an explicit .migration-paths glob names.
    globs = extra_globs()
    if globs:
        _, tracked = git(["ls-files"])
        candidates.update(
            p for p in tracked.split() if any(fnmatch.fnmatch(p, g) for g in globs)
        )
    # Exclude the crate's own implementation (it defines, not constructs).
    _, impl_out = git(["grep", "-lE", DEFINES_RE, "--", "*.rs"])
    impl = set(impl_out.split())
    return sorted(candidates - impl)


def is_migration_file(path: str) -> bool:
    return path in set(discover())


def file_lines(path: str) -> list[str]:
    try:
        with open(path, encoding="utf-8") as fh:
            return fh.read().splitlines()
    except (FileNotFoundError, UnicodeDecodeError):
        return []


def diff_args(mode: str, base: str | None) -> list[str]:
    if mode == "staged":
        return ["diff", "--cached", "--unified=0"]
    return ["diff", "--unified=0", f"{base}...HEAD"]


def changed_migration_files(mode: str, base: str | None) -> list[str]:
    if mode == "staged":
        _, out = git(["diff", "--cached", "--name-only"])
    else:
        _, out = git(["diff", "--name-only", f"{base}...HEAD"])
    found = set(discover())
    return [p for p in out.split() if p in found]


def hunks_for(mode: str, base: str | None, path: str) -> tuple[list[str], list[str]]:
    _, out = git([*diff_args(mode, base), "--", path])
    added, removed = [], []
    for line in out.splitlines():
        if line.startswith("+") and not line.startswith("+++"):
            added.append(line[1:])
        elif line.startswith("-") and not line.startswith("---"):
            removed.append(line[1:])
    return added, removed


# --------------------------------------------------------------------------- #
# Drivers
# --------------------------------------------------------------------------- #
def audit() -> int:
    errors: list[str] = []
    files = discover()
    for path in files:
        lines = file_lines(path)
        errors.extend(static_checks(lines, path, lines))
    return report(errors, f"audited {len(files)} migration file(s)")


def diff_mode(mode: str, base: str | None) -> int:
    errors: list[str] = []
    for path in changed_migration_files(mode, base):
        added, removed = hunks_for(mode, base, path)
        for bad in immutability_violations(removed, marker(added, ALLOW_EDIT)):
            errors.append(f"{path}: edited/removed a shipped migration line: {bad!r}")
        errors.extend(static_checks(added, path, added))
    return report(errors, None)


def report(errors: list[str], ok_note: str | None) -> int:
    if errors:
        print("check-migrations:", file=sys.stderr)
        for e in errors:
            print(f"  {e}", file=sys.stderr)
        print(
            "  (shipped migrations are frozen; to override include the relevant "
            "`migration-allow-*` marker in the diff)",
            file=sys.stderr,
        )
        return 1
    if ok_note:
        print(f"check-migrations: {ok_note}, no violations")
    return 0


def self_test() -> int:
    cases = [
        (immutability_violations(["CREATE TABLE a (id TEXT)"], False), 1, "edit shipped"),
        (immutability_violations(["CREATE TABLE a (id TEXT)"], True), 0, "override edit"),
        (immutability_violations(["", " -- c"], False), 0, "blank/comment ok"),
        (destructive_violations(["DROP TABLE u"], False), 1, "drop"),
        (destructive_violations(["DROP TABLE u"], True), 0, "drop override"),
        (destructive_violations(["DELETE FROM t WHERE id=1"], False), 0, "delete+where ok"),
        (destructive_violations(["DELETE FROM t"], False), 1, "delete no where"),
        (nondeterministic_violations(["CREATE TABLE t (id TEXT)"], False), 0, "bare create ok"),
        (nondeterministic_violations(["CREATE TABLE IF NOT EXISTS t (id TEXT)"], False), 1, "ine forbidden"),
        (nondeterministic_violations(["DROP TABLE IF EXISTS t"], False), 1, "if exists forbidden"),
        (nondeterministic_violations(["CREATE OR REPLACE VIEW v AS SELECT 1"], False), 1, "or replace forbidden"),
        (nondeterministic_violations(["CREATE TABLE IF NOT EXISTS t"], True), 0, "conditional override"),
        (nondeterministic_violations(["INSERT INTO t VALUES (1)"], False), 0, "insert ok"),
        (raw_sql_violations(["col JSONB NOT NULL"], False), 1, "jsonb raw"),
        (raw_sql_violations(["at TIMESTAMPTZ DEFAULT now()"], False), 1, "tstz+now one line"),
        (raw_sql_violations(["data {json} NOT NULL"], False), 0, "token ok"),
        (raw_sql_violations(["col JSONB"], True), 0, "raw override"),
        (version_violations([], ["V0001__init.sql"]), 0, "good version"),
        (version_violations([], ["V1__init.sql"]), 1, "short version"),
        (version_violations(["-- V0002", "-- V0002 again"], []), 1, "dup version"),
    ]
    failures = 0
    for got, want, name in cases:
        if len(got) != want:
            print(f"self-test FAILED: {name}: got {got!r}", file=sys.stderr)
            failures += 1
    if failures:
        return 1
    print("check-migrations: self-test passed")
    return 0


def main(argv: list[str]) -> int:
    if not argv or argv[0] in ("-h", "--help"):
        print(
            "usage: check_migrations.py --audit | --staged | --base REF | --self-test",
            file=sys.stderr,
        )
        return 0 if argv[:1] in ([], ["--help"], ["-h"]) else 2
    if argv[0] == "--self-test":
        return self_test()
    if argv[0] == "--audit":
        return audit()
    if argv[0] == "--staged":
        return diff_mode("staged", None)
    if argv[0] == "--base":
        if len(argv) < 2:
            print("--base requires a ref", file=sys.stderr)
            return 2
        return diff_mode("base", argv[1])
    print(f"unknown mode {argv[0]!r}", file=sys.stderr)
    return 2


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
