#!/usr/bin/env bash
# Prune `fix/*` branches whose work has fully landed on the integration branch.
#
# A `fix/*` branch is "superseded" when every commit it carries is already
# present on the base branch -- either as a true ancestor (the branch was
# merged) or as a patch-equivalent re-commit/cherry-pick. `git cherry` settles
# both cases by patch-id: it prints `-` for commits already upstream and `+`
# for commits that are still unique to the branch. A branch with zero `+`
# lines is safe to delete; a branch with any `+` line still holds unmerged
# work and is kept.
#
# Usage:
#   scripts/maintenance/prune-superseded-fix-branches.sh [--apply] [--base REF] [--remote NAME]
#
#   (default)        Dry run: classify every `fix/*` branch, delete nothing.
#   --apply          Push the deletions for every superseded branch.
#   --base REF       Base branch to compare against (default: origin/main).
#   --remote NAME    Remote whose `fix/*` heads are pruned (default: origin).
#
# The dry run is the audit; `--apply` is the only mutating path and it only
# ever deletes branches that carry no unique commits.
set -euo pipefail

apply=0
base="origin/main"
remote="origin"

while [ $# -gt 0 ]; do
  case "$1" in
    --apply) apply=1 ;;
    --base) shift; base="${1:?--base needs a ref}" ;;
    --remote) shift; remote="${1:?--remote needs a name}" ;;
    -h|--help) sed -n '2,24p' "$0"; exit 0 ;;
    *) echo "unknown argument: $1" >&2; exit 2 ;;
  esac
  shift
done

git fetch --prune "$remote" >/dev/null 2>&1 || true

if ! git rev-parse --verify --quiet "$base" >/dev/null; then
  echo "base ref not found: $base" >&2
  exit 1
fi

superseded=()
kept=()

while IFS= read -r ref; do
  [ -n "$ref" ] || continue
  branch="${ref#refs/heads/}"
  remote_ref="refs/remotes/${remote}/${branch}"
  git rev-parse --verify --quiet "$remote_ref" >/dev/null || continue
  if git cherry "$base" "$remote_ref" | grep -q '^+'; then
    kept+=("$branch")
  else
    superseded+=("$branch")
  fi
done < <(git for-each-ref --format='%(refname)' "refs/remotes/${remote}/fix/" \
           | sed "s#refs/remotes/${remote}/#refs/heads/#")

echo "base:   $base"
echo "remote: $remote"
echo "kept (unmerged work present):    ${#kept[@]}"
for b in "${kept[@]:-}"; do [ -n "$b" ] && echo "  keep   $b"; done
echo "superseded (fully upstream):     ${#superseded[@]}"
for b in "${superseded[@]:-}"; do [ -n "$b" ] && echo "  prune  $b"; done

if [ "${#superseded[@]}" -eq 0 ]; then
  echo "nothing to prune."
  exit 0
fi

if [ "$apply" -eq 0 ]; then
  echo "dry run -- re-run with --apply to delete the superseded branches."
  exit 0
fi

for b in "${superseded[@]}"; do
  echo "deleting ${remote}/${b}"
  git push "$remote" --delete "$b"
done
echo "pruned ${#superseded[@]} superseded branch(es)."
