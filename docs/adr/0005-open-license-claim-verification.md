# ADR-0005 - License claim shape and offline verification are open; issuance stays closed

- **Status:** Proposed
- **Implementation:** done
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

- the versioned `LicenseClaim` wire shape (`license_id`, `customer_id`,
  `deployment_id`, `catalog_release`, `billing_version`, `features`, `limits`,
  `issued_at`, `not_after`, `epoch`, detached `sig`) and its canonical
  signing-input serialization, and
- an offline verification primitive that checks a claim against a pinned JWKS of
  Ed25519 public keys, with a caller-supplied `now` and epoch floor, returning a
  closed rejection taxonomy (unsupported schema, missing/mismatched binding,
  unknown or unsupported key, malformed or bad signature, malformed/inverted
  RFC 3339 validity, not-yet-valid, expired, epoch-fenced). Temporal comparison
  uses parsed instants rather than wire-string ordering, so fractional seconds
  and equivalent offsets remain correct. It performs no I/O and reads no clock.

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

## Amendment: rejected licenses cannot unlock commercial features (2026-08-19)

The original open-core wording was implemented with a blanket `default_allow`
fallback. Once real commercial gates existed, deleting or corrupting a license
would therefore allow more than presenting a valid restrictive claim. Production
construction now installs `EntitlementEngine::unlicensed`: ordinary open
functionality remains outside entitlement checks, while every explicit
commercial entitlement denies. Missing, unreadable, malformed, expired,
signature-invalid, and epoch-fenced claims all resolve to that same restricted
provider. `default_allow` remains available only as an explicit development/test
fixture.

## Amendment: V2 claims bind one customer and deployment (2026-08-19)

Signature validity alone does not authorize a license for the current host: an
otherwise-valid unbound claim could be copied to another customer or
installation. Schema V2 signs `license_id`, `customer_id`, `deployment_id`, the
immutable `catalog_release`, and `billing_version` together with the feature and
lifecycle payload. Production resolution requires exact customer and deployment
matches through `LicenseClaim::verify_for`; V1, missing bindings, and either
mismatch fail closed to the unlicensed provider. There is no legacy acceptance
path to synchronize or accidentally leave enabled.

## Amendment: live verification and durable rollback floor (2026-08-19)

A signature-valid old claim must not regain removed capacity after the host has
already accepted a newer subscription projection. IAM therefore owns one
durable high-water mark per customer/deployment: accepted `epoch` and
`billing_version`. Resolution verifies against that floor and advances it with
an owner-only, atomic, fsynced replacement before enabling the claim. A lower
value, malformed state, cross-deployment state, symlink, insecure permissions,
or persistence failure denies commercial entitlements. Product repositories do
not implement their own rollback files or verifier.

The production provider reloads and re-verifies the configured claim for each
commercial entitlement decision. Expiry and operator rotation therefore take
effect without a restart or a product-specific refresh timer. The pinned JWKS
is loaded once at composition time; changing the license file cannot change the
trusted issuer.

This raises the cost of accidental rollback and non-administrative tampering; it
does not claim DRM-style impossibility. A customer with root access can patch a
binary, replace both binary and state, or remove the policy-enforcement point.
Commercial protection therefore also relies on short claim lifetimes, signed
release artifacts, controlled update/support access, audit evidence, and the
contract. Hardware-backed measured boot or online activation may strengthen a
managed appliance, but is not a hidden requirement for offline self-hosting.
