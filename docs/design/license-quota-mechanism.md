# License and quota mechanism

This document specifies the **mechanism** `awaken-iam` provides for cloud-issued
license and quota enforcement, and draws the line at which the mechanism stops
and **product policy** begins. The rule mirrors authorization: **IAM decides and
supplies the tokens; the product enforces.** It complements the [entitlement
plane](entitlements.md), [local authorization, cloud
license](local-authz-cloud-license.md), [permission
mechanisms](permission-mechanisms.md), and [ADR-0004](../adr/0004-consumers-reuse-iam-authz.md)
(the outbox).

## Scope — mechanism only

`awaken-iam` implements only the **mechanism plane**: the cloud daemon and the
shared client SDK. It does **not** implement where a product gates, what a
product's resources mean, or what happens when a limit is hit — those are product
application logic and stay out of IAM so IAM remains product-agnostic
([ADR-0001](../adr/0001-iam-shared-boundary.md)).

| Layer | Owner | Provides |
|---|---|---|
| **Cloud daemon** | IAM | plan/`limits` source of truth, signed license issuance, concurrency-lease minting + cap, `epoch` revocation, reconciliation count, JWKS |
| **Client SDK** (`awaken-iam-client`) | IAM (shared) | offline license verification, lease acquire/renew/cache, `check_entitlement` against the cached claim, sliding-lease + freshness bookkeeping, fail-closed helpers |
| **Product** (e.g. Oversight) | product | the gating points, the domain inventory + outbox reporting, the over-limit behavior (block / read-only / messaging) |

IAM never learns what a `worker`, `workspace`, or `project` is. It sees opaque
**SKU keys** (`workers`, `workspaces`, `projects`) carrying numbers, and mints
generic tokens; the product maps its concrete create/execute paths onto those
keys.

## The mechanism surface

### 1. License claim — signed limits, verifiable offline

The cloud issues, at login, a JWKS-verifiable claim carrying the entitlement and
its limits. It extends the [entitlement plane](entitlements.md)'s `Plan{ tier,
features, limits, rates }` with an offline envelope:

```
LicenseClaim {
  subject / org,
  features: [ ... ],            // unlocked SKUs (feature gates)
  limits:   { workers: N, workspaces: M, projects: K, ... },   // numeric quota SKUs
  issued_at, not_after,        // sliding offline lease
  epoch,                       // advanced to revoke
  sig                          // EdDSA; verified against cached /.well-known/jwks.json
}
```

The SDK verifies the signature and `not_after` offline (reusing the access-token
JWKS surface). `check_entitlement(sku)` reads the cached claim. The signature
stops forgery of a higher limit; it does not stop a product that gates locally
from being patched — see [threat model](local-authz-cloud-license.md#threat-model--what-this-can-and-cannot-enforce).

### 2. Concurrency leases — for *concurrent* limits (e.g. workers)

For a limit on things that **run** (workers), the mechanism is a finite set of
cloud-minted, short-lived, epoch-fenced **capability tokens** — one lease per
slot — built directly on the attenuated, lease-epoch [capability
mechanism](permission-mechanisms.md) (`MintCapability { …, epoch, … }`):

- the cloud mints at most `limits.workers` concurrent leases and refuses the
  `N+1`th;
- a lease is short-lived and renewed online within the offline window;
- the product requires a live lease to operate a slot; offline it spends from the
  cached pool of `N` it already holds and cannot mint an `N+1`th (no private key);
- advancing `epoch` invalidates every lease at the next renewal.

The SDK acquires, caches, renews, and verifies leases; the product decides *where*
a lease is required (its worker-spawn path).

### 3. Reconciliation count — for *cumulative* limits (e.g. workspaces, projects)

For a limit on things that **accumulate** (containers created and kept), the
durable count is server-side, reconciled through the [outbox](../adr/0004-consumers-reuse-iam-authz.md):

- the product creates locally and reports its resource inventory through the
  outbox (`ResourceProvision`, idempotent on `idempotency_key`);
- the cloud counts the actual inventory against `limits` and is the authoritative
  count;
- a create that the cloud has not acknowledged is **provisional**; the cloud
  blesses it only if it is within the limit, and reports an over-limit verdict
  otherwise;
- the sliding lease bounds how long a provisional, unreconciled resource stays
  usable offline before the product must treat it as over-limit.

The mechanism supplies the signed limit, the count, and the verdict; the product
supplies the inventory and decides what a counted unit is.

### 4. Revocation and freshness

- **Sliding lease**: every successful online contact slides `not_after` forward;
  a genuinely offline deployment runs on the cached claim/leases until it lapses.
- **Epoch**: the cloud advances `epoch` to invalidate cached licenses/leases at
  the next contact.
- **Fail-closed staleness**: past `not_after` (or an unreconciled provisional
  beyond its window), the mechanism reports the SKU as not entitled / the lease as
  unavailable; the product fails closed on that SKU.

## Verdicts the mechanism returns

The mechanism returns stable, machine-readable verdicts; the product maps each to
behavior. It never dictates the behavior.

| Verdict | Meaning | Product maps to (examples, not prescribed) |
|---|---|---|
| `entitled` | SKU/feature is licensed and fresh | enable |
| `quota_exceeded` | count ≥ limit for a quota SKU | block new create / mark excess read-only |
| `lease_unavailable` | no concurrency lease available (cap reached) | refuse to start another slot |
| `license_expired` | past `not_after`, offline lease lapsed | degrade to free tier |
| `license_revoked` | `epoch` advanced / subscription withdrawn | lock cloud-granted features |

## Mechanism / policy boundary

The mechanism stops here; everything below is the product's:

- **Where** the check happens — the worker-spawn path, the workspace/project
  create path — is a product call site.
- **What counts** as a worker/workspace/project is the product's domain
  inventory.
- **What to do** on a non-`entitled` verdict — block, degrade, mark read-only, the
  UX and messaging, and the rule *not to destroy user data* — is product policy.
- **Safety-critical behavior is never gated on the license**; that is
  authorization's job, and it is local and default-deny.

## Maps to existing primitives

- limits / features: `EntitlementCatalog`, `Plan{ tier, features, limits, rates }`,
  `check_entitlement`, subscriptions (`crates/awaken-iam-core`).
- leases: the attenuated, epoch-fenced capability token
  (`crates/awaken-iam-server/src/capability_token.rs`, `MintCapability`).
- reconciliation: the transactional outbox (`ResourceProvision`, the
  `awaken-iam-client` outbox relay).
- offline verification: the access-token JWKS surface (`/.well-known/jwks.json`).
- remote contact: the reqwest `HttpAuthzTransport` and the snapshot
  `version/epoch` fence.

What is new on top of these is small and lives in the mechanism plane only: the
**license claim** envelope (limits + lease + epoch, signed), the **slot-lease
minting cap**, and the **inventory reconciliation count** — plus the SDK
bookkeeping that verifies, caches, renews, and fails closed.

## Invariants

- **Mechanism, not policy.** IAM/SDK supply signed limits, finite minted leases,
  a reconciled count, and verdicts; they never decide a product's gating point or
  over-limit behavior.
- **Product-agnostic.** IAM sees SKU keys and opaque tokens, never domain types.
- **Bounded blast radius.** A bypassed quota costs revenue only; it can never
  grant a permission, widen a scope, or cross a tenant — those are the local
  default-deny authorization engine, which the license never feeds.
- **Forgery hard, removal easy.** Signing stops minting a higher limit; it does
  not stop a locally-gated product from being patched. Hard enforcement requires a
  closed gating module (open-core) or cryptographic binding — a product/deployment
  choice, not part of this mechanism.
