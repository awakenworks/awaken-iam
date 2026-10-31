#!/usr/bin/env python3
"""Enforce ADR append-mostly immutability.

Once an ADR is **Accepted** (or terminal: Superseded / Deprecated) its body is
frozen: you may append new content and edit header metadata, but you may not
modify or delete existing body lines. To change the decision, write a new ADR
that supersedes it.

Modes:
  --staged       compare the index against HEAD (pre-commit)
  --base REF     compare REF...HEAD, confirmed per commit (pre-push / CI)
  --self-test    run the enforcer logic against synthetic fixtures

What stays editable on a locked ADR:
  - blank lines
  - header metadata lines: Status, Implementation, Date, Related, Supersedes,
    Superseded by, Amended by, Clarified by, Deprecated
  - link reference definitions
  - anything, if the diff carries an `adr-allow-edit` override marker

Status transitions are also gated: a decision may not slide backwards
(e.g. Accepted -> Proposed).

``--base`` first compares the merge base of REF and HEAD with HEAD. A path
whose net change looks illegal is then replayed commit by commit: an ADR added
as Proposed and accepted by a later commit is a legal lifecycle even when both
commits are new relative to REF, so the path is reported only when some commit
in the range made an illegal change to it. A merge commit's change is legal
when it is legal from at least one parent, so content one side already carried
through its own commits is not re-judged as new, while an ADR edit that only
the merge resolution introduces is still checked.
"""

from __future__ import annotations

import re
import subprocess
import sys

# Decision states.
EDITABLE = {"Proposed"}
LOCKED = {"Accepted", "Superseded", "Deprecated"}
ALL_STATES = EDITABLE | LOCKED

# Once the OLD status is one of these, append-mostly applies.
TRANSITIONS = {
    "Proposed": {"Proposed", "Accepted", "Superseded", "Deprecated"},
    "Accepted": {"Accepted", "Superseded", "Deprecated"},
    "Superseded": {"Superseded"},
    "Deprecated": {"Deprecated"},
}

STATUS_RE = re.compile(r"^\s*-\s*\*\*Status:\*\*\s*(.+?)\s*$", re.MULTILINE)

ALLOWED_REMOVAL_RE = re.compile(
    r"^\s*$"  # blank line
    r"|^- \*\*(?:Status|Implementation|Date|Related|Supersedes|"
    r"Superseded by|Amended by|Clarified by|Deprecated):\*\*"  # header metadata
    r"|^\[[^\]]+\]:\s*\S+"  # link reference definition
)

OVERRIDE_MARKER = "adr-allow-edit"


# --------------------------------------------------------------------------- #
# Pure logic (unit-testable without git)
# --------------------------------------------------------------------------- #
def first_token(value: str) -> str:
    parts = value.split()
    return parts[0] if parts else ""


def offending_removals(removed_lines: list[str], has_override: bool) -> list[str]:
    """Body lines removed from a locked ADR that are not allowed."""
    if has_override:
        return []
    return [ln for ln in removed_lines if not ALLOWED_REMOVAL_RE.match(ln)]


def transition_allowed(old: str, new: str) -> bool:
    return new in TRANSITIONS.get(old, set())


def check_change(
    path: str,
    old_status: str | None,
    new_status: str | None,
    removed_lines: list[str],
    has_override: bool,
) -> list[str]:
    """Evaluate one ADR change. ``old_status`` is None for a new file."""
    errors: list[str] = []

    if old_status is None:
        # New ADR: must start editable, never as a decided record.
        if new_status not in EDITABLE:
            errors.append(
                f"{path}: a new ADR must start as Proposed, not {new_status!r}"
            )
        return errors

    if new_status is not None and new_status not in ALL_STATES:
        errors.append(f"{path}: Status {new_status!r} is not a known state")
    elif new_status is not None and not transition_allowed(old_status, new_status):
        errors.append(
            f"{path}: illegal status transition {old_status} -> {new_status}"
        )

    if old_status in LOCKED:
        bad = offending_removals(removed_lines, has_override)
        for line in bad:
            errors.append(
                f"{path}: ADR is {old_status} (append-mostly); body line may not "
                f"change: {line.strip()!r}"
            )
    return errors


# --------------------------------------------------------------------------- #
# Git plumbing
# --------------------------------------------------------------------------- #
def git(args: list[str]) -> tuple[int, str]:
    proc = subprocess.run(
        ["git", *args], capture_output=True, text=True, check=False
    )
    return proc.returncode, proc.stdout


def changed_adrs(diff_range: list[str]) -> list[str]:
    code, out = git(
        ["diff", "--name-only", "--diff-filter=ACMR", *diff_range, "--", "docs/adr/"]
    )
    if code != 0:
        return []
    return [
        p
        for p in out.splitlines()
        if p.endswith(".md")
        and not p.endswith("0000-template.md")
        and not p.endswith("README.md")
    ]


def removed_lines(diff_range: list[str], path: str) -> tuple[list[str], bool]:
    """Return (removed body lines, override-marker-present)."""
    code, out = git(["diff", "--unified=0", *diff_range, "--", path])
    if code != 0:
        return [], False
    removed: list[str] = []
    override = OVERRIDE_MARKER in out
    for line in out.splitlines():
        if line.startswith("--- ") or line.startswith("+++ "):
            continue
        if line.startswith("-"):
            removed.append(line[1:])
    return removed, override


def status_of(blob: str) -> str | None:
    match = STATUS_RE.search(blob)
    return first_token(match.group(1)) if match else None


def show(ref_path: str) -> str | None:
    code, out = git(["show", ref_path])
    return out if code == 0 else None


def change_errors(
    diff_args: list[str], old_ref: str, new_ref: str | None
) -> list[tuple[str, str]]:
    """``(path, error)`` ADR violations from ``old_ref`` to ``new_ref`` (None = index)."""
    errors: list[tuple[str, str]] = []
    for path in changed_adrs(diff_args):
        old_blob = show(f"{old_ref}:{path}")
        new_blob = show(f":{path}") if new_ref is None else show(f"{new_ref}:{path}")
        old_status = status_of(old_blob) if old_blob is not None else None
        new_status = status_of(new_blob) if new_blob else None
        removed, override = removed_lines(diff_args, path)
        errors.extend(
            (path, error)
            for error in check_change(path, old_status, new_status, removed, override)
        )
    return errors


def commit_errors(per_parent: list[list[tuple[str, str]]]) -> list[tuple[str, str]]:
    """A commit's ADR change is legal when it is legal from at least one parent."""
    if not per_parent or any(not errors for errors in per_parent):
        return []
    return per_parent[0]


def confirmed(
    net: list[tuple[str, str]], per_commit: list[tuple[str, str]]
) -> list[str]:
    """Net violations that some commit in the range really introduced."""
    suspects = {path for path, _ in net}
    return [error for path, error in per_commit if path in suspects]


def range_errors(ref: str) -> list[str]:
    code, out = git(["merge-base", ref, "HEAD"])
    if code != 0:
        return [f"no merge base between {ref} and HEAD"]
    base = out.strip()
    net = change_errors([base, "HEAD"], base, "HEAD")
    if not net:
        return []
    code, out = git(["rev-list", "--reverse", "--parents", f"{ref}..HEAD"])
    if code != 0:
        return [f"cannot list commits in {ref}..HEAD"]
    per_commit: list[tuple[str, str]] = []
    for line in out.splitlines():
        commit, *parents = line.split()
        per_parent = [
            change_errors([parent, commit], parent, commit) for parent in parents
        ]
        per_commit.extend(
            (path, f"{commit[:12]}: {error}")
            for path, error in commit_errors(per_parent)
        )
    return confirmed(net, per_commit)


def report(errors: list[str]) -> int:
    if errors:
        print("check-adr-immutability:", file=sys.stderr)
        for e in errors:
            print(f"  {e}", file=sys.stderr)
        return 1
    return 0


# --------------------------------------------------------------------------- #
# Self-test
# --------------------------------------------------------------------------- #
def self_test() -> int:
    cases = [
        # (desc, old, new, removed, override, expect_errors)
        ("append only", "Accepted", "Accepted", [], False, False),
        ("body edit blocked", "Accepted", "Accepted", ["We will use X."], False, True),
        (
            "header edits allowed",
            "Accepted",
            "Accepted",
            ["- **Status:** Accepted", "- **Implementation:** in-progress"],
            False,
            False,
        ),
        ("override allows edit", "Accepted", "Accepted", ["We will use X."], True, False),
        ("backslide blocked", "Accepted", "Proposed", [], False, True),
        ("supersede allowed", "Accepted", "Superseded", [], False, False),
        ("proposed freely edited", "Proposed", "Proposed", ["anything"], False, False),
        ("new must be proposed", None, "Accepted", [], False, True),
        ("new proposed ok", None, "Proposed", [], False, False),
    ]
    failures = 0
    merge_cases = [
        # (desc, errors per parent, expect_errors)
        ("ordinary commit clean", [[]], False),
        ("ordinary commit violation", [["x"]], True),
        ("merge carries a side's checked ADR", [[], ["new Accepted"]], False),
        ("merge resolution edits locked body", [["edit"], ["edit"]], True),
    ]
    merge_cases = [
        (desc, [[("t.md", e) for e in errors] for errors in per_parent], expect)
        for desc, per_parent, expect in merge_cases
    ]
    for desc, per_parent, expect in merge_cases:
        errs = commit_errors(per_parent)
        if bool(errs) != expect:
            failures += 1
            print(
                f"self-test FAILED [{desc}]: expected errors={expect}, got {errs}",
                file=sys.stderr,
            )
    for desc, old, new, removed, override, expect in cases:
        errs = check_change("t.md", old, new, removed, override)
        if bool(errs) != expect:
            failures += 1
            print(
                f"self-test FAILED [{desc}]: expected errors={expect}, got {errs}",
                file=sys.stderr,
            )
    lifecycle_cases = [
        # (desc, net violations, per-commit violations, expect_errors)
        ("net change legal", [], [("t.md", "c1: edit")], False),
        ("proposed then accepted in range", [("t.md", "new Accepted")], [], False),
        ("commit really added it accepted", [("t.md", "new Accepted")],
         [("t.md", "c1: new Accepted")], True),
        ("other path's commit violation", [("t.md", "new Accepted")],
         [("u.md", "c1: edit")], False),
    ]
    for desc, net, per_commit, expect in lifecycle_cases:
        errs = confirmed(net, per_commit)
        if bool(errs) != expect:
            failures += 1
            print(
                f"self-test FAILED [{desc}]: expected errors={expect}, got {errs}",
                file=sys.stderr,
            )
    if failures:
        return 1
    print("check-adr-immutability self-test: ok")
    return 0


def main(argv: list[str]) -> int:
    if not argv:
        print("usage: check_adr_immutability.py --staged | --base REF | --self-test",
              file=sys.stderr)
        return 2
    if argv[0] == "--self-test":
        return self_test()
    if argv[0] == "--staged":
        return report([error for _, error in change_errors(["--cached"], "HEAD", None)])
    if argv[0] == "--base":
        if len(argv) < 2:
            print("--base requires a ref", file=sys.stderr)
            return 2
        ref = argv[1]
        code, _ = git(["rev-parse", "--verify", "--quiet", ref])
        if code != 0:
            print(f"check-adr-immutability: base ref {ref!r} not found; skipping")
            return 0
        return report(range_errors(ref))
    print(f"unknown mode: {argv[0]}", file=sys.stderr)
    return 2


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
