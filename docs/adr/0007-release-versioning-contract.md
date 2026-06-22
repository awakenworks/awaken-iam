# ADR-0007 - The repo is consumed at immutable version tags

- **Status:** Proposed
- **Implementation:** planned
- **Date:** 2026-06-23

## Context

The open IAM crates are consumed as artifacts by downstream repos — most
immediately the closed `awaken-cloud` platform, which composes them rather than
vendoring them. But every crate here is `version = "0.1.0-dev"` with `publish =
false` and the repo carries **no git tags**, so a downstream has nothing stable
to pin to: a `git` dependency can only track a moving branch `rev`, which means a
downstream build is not reproducible and an upstream change can silently break or
alter a consumer.

We do not (yet) publish to crates.io, and for a multi-repo family consumed by git
dependency we do not need to. What we need is an **immutable point to pin** and a
predictable cadence for cutting one, so a downstream can depend on
`tag = "vX.Y.Z"` and know that tag never moves.

## Decision

We will define a lightweight release contract for the repo:

1. **Semver tags are the unit of consumption.** Releases are cut as annotated git
   tags `vMAJOR.MINOR.PATCH`. A tag is immutable: once pushed it is never moved or
   deleted. Downstreams pin `git = "…", tag = "vX.Y.Z"`, never a branch.
2. **Pre-1.0 semver.** While `0.y.z`, a `0.MINOR` bump may carry breaking changes
   and `0.0.PATCH` is reserved for fixes; the workspace `version` is bumped to the
   release version in the release commit (dropping the `-dev` suffix), then moved
   to the next `-dev` after tagging.
3. **The CHANGELOG is the release note.** The working `## X.Y.Z-dev` section is
   promoted to the released version heading in the release commit; every release
   has a CHANGELOG entry.
4. **Process is documented, not yet automated.** The steps live in
   [RELEASING.md](../../RELEASING.md). A CI release workflow is intentionally out
   of scope for this ADR and may follow once the cadence is established.

## Consequences

- Easier: downstreams (notably `awaken-cloud`) pin reproducibly to an immutable
  tag; "what changed between versions" is answerable from the CHANGELOG and tag
  range; the open/closed boundary has a versioned contract, not a moving branch.
- Harder: releases are a deliberate, manual step (bump, changelog, tag) until
  automated; a breaking seam change must wait for a `0.MINOR` bump and a note.
- New guardrail: tags are immutable; consumers pin tags, not branches.

## Alternatives considered

- **Publish to crates.io:** rejected for now — unnecessary for a git-dependency
  family and it adds release surface and name/ownership management we do not yet
  need; revisit if external (non-family) consumers appear.
- **Pin downstreams to branch revs:** rejected — a `rev` is reproducible only
  until someone force-pushes or the consumer re-pins, and it carries no semver
  signal about breakage; a moving target is exactly the problem.
- **A full release CI pipeline now:** deferred — valuable, but it exceeds the
  minimum needed to give downstreams a stable pin; the manual process unblocks
  that today and the pipeline can automate it later.
