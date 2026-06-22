# ADR-0005 - License claim shape and offline verification are open; issuance stays closed

- **Status:** Proposed
- **Implementation:** in-progress
- **Date:** 2026-06-23

## Context

The [entitlement plane](../design/entitlements.md) is an injection seam: a
self-hosted build is fully functional and unlicensed, while paid features and
numeric ceilings are unlocked by a signed license a licensed deployment presents.
The seam draws an open/closed line, but the original wording named "signed
offline-verifiable licenses" wholesale as the proprietary concern and said the
open repo "never carries the licensing mechanism." That is too coarse: it
conflates two separable halves.

- **Minting trust** — the issuer's private signing key, the plan catalog, quota
  leases, and billing. Whoever holds these can fabricate entitlements. This is
  the commercial asset and the real threat surface.
- **Checking a presented claim** — given a claim and a pinned set of *public*
  keys, deciding whether the claim is authentic, in-window, and current-epoch.
  This holds no secret and grants no power; a self-hosted build needs it to honor
  a license without calling home.

A blanket "no licensing in the open repo" forces the public verification path to
live behind the closed seam, which would make every self-hosted build phone home
to validate a license — defeating the offline, no-call-home property the seam
exists to provide.

## Decision

The **open** `awaken-iam-contract` crate carries:

- the `LicenseClaim` wire shape (`features`, `limits`, `issued_at`, `not_after`,
  `epoch`, detached `sig`) and its canonical signing-input serialization, and
- an offline verification primitive that checks a claim against a pinned JWKS of
  Ed25519 public keys, with a caller-supplied `now` and epoch floor, returning a
  closed rejection taxonomy (unknown key, unsupported key, malformed signature,
  bad signature, not-yet-valid, expired, epoch-fenced). It performs no I/O and
  reads no clock.

The **closed** commercial platform (`awaken-cloud`) keeps everything that mints
trust: the private signing store, the plan catalog, quota leases, billing, and
the threat model around issuance. The open repo never gains a signing key or an
issuing pipeline.

This is a deliberate refinement of the `awaken-iam-contract` scope. The crate is
"DTOs and identifiers," and additionally the pure, offline verification of the
self-describing wire shapes it defines — a public-key signature check is not
policy evaluation, persistence, or server logic, and stays consistent with the
contract boundary guardrail (G1): the verifier depends only on external crypto
crates, never on sibling IAM crates.

## Consequences

- A self-hosted build can verify a presented license entirely offline; absence of
  a claim remains the unlicensed default.
- The signing key never appears in the open tree, so possession of the open
  verifier cannot mint a valid license.
- `features` and `limits` are free-form keys, so new entitlements ship without an
  IAM schema break; the entitlement plane's evaluation consumes a verified claim
  without re-deriving trust.
- The entitlement-plane callout is updated in lockstep to describe the open
  shape + verification / closed issuance split rather than a blanket exclusion.
