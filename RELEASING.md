# Releasing

`awaken-iam` is consumed by downstream repos as a git dependency pinned to an
**immutable version tag** (see [ADR-0007](docs/adr/0007-release-versioning-contract.md)).
This document is the manual process for cutting one. There is no release
automation yet by design.

## Versioning

- Tags are `vMAJOR.MINOR.PATCH` (annotated). Once pushed, a tag is never moved or
  deleted.
- While pre-1.0 (`0.y.z`): a `0.MINOR` bump may include breaking changes; a
  `0.0.PATCH` bump is fixes only. Call out any breaking seam change in the
  CHANGELOG.
- The workspace `version` in the root `Cargo.toml` is the source of truth and
  carries a `-dev` suffix between releases.

## Cutting a release

1. **Pick the version** per the rules above based on what landed since the last
   tag (`git log v<last>..HEAD`).
2. **Bump the workspace version** in `Cargo.toml` to the release version, dropping
   `-dev` (e.g. `0.1.0-dev` → `0.1.0`). Run `cargo build` so `Cargo.lock`
   updates.
3. **Promote the CHANGELOG.** The working `## X.Y.Z-dev` heading becomes the
   released `## X.Y.Z - <date>`; open a fresh `## <next>-dev` section above it for
   the next cycle.
4. **Verify the gates** the same checks CI/lefthook run:
   `cargo fmt --all --check`, `cargo clippy --workspace --all-targets -- -D
   clippy::correctness`, `cargo test --workspace`, `cargo deny check`.
5. **Commit** the bump (`🔖 chore(release): vX.Y.Z`) on a release branch and
   merge it.
6. **Tag** the merge commit: `git tag -a vX.Y.Z -m "vX.Y.Z"` and push the tag.
7. **Open the next cycle.** Bump the workspace `version` to the next `-dev`
   (e.g. `0.1.0` → `0.2.0-dev`) in a follow-up commit.

## Downstream pinning

Consumers depend on a tag, never a branch:

```toml
awaken-iam = { git = "https://github.com/AwakenWorks/awaken-iam", tag = "v0.1.0" }
```

When a downstream needs a newer seam, it moves its pin to a newer tag and notes
the bump in its own changelog.
