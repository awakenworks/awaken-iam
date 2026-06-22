# Local authorization, cloud license

This document defines the split a locally-running product uses when **its
permissions are local but its feature license is cloud-controlled**: the product
owns its authorization plane in-process, while the cloud owns the entitlement
plane (the license) and gates features through login. It complements the
[entitlement plane](entitlements.md), [consumer integration](consumer-integration.md)
(the *entitlement-only* delegation mode), [seeding and
provisioning](seeding-and-provisioning.md), and the JWKS surface in the
[auth server](auth-server.md).

The worked example is **Oversight** running locally (a single binary on
`localhost`), which already carries its own authorization engine and only needs
the cloud to license features.

## Purpose

Two planes that are routinely fused must be split here because they have
different owners and different offline behavior:

- **Authorization (AuthZ) is local.** *Who may edit which issue, what role they
  hold, the scope tree* — the product owns its grants/roles/scopes, its own
  [seed and provisioning](seeding-and-provisioning.md), and its own engine. The
  cloud never touches it, and it works **fully offline, forever**.
- **License (Entitlement) is cloud.** *Which features are unlocked, the plan
  tier, seats, quotas* — the cloud is the single source of truth, issued at
  **login**. "Controlling local features through login" is exactly this plane.

The two are orthogonal (per the [authorization engine](authorization-engine.md)
and [entitlement plane](entitlements.md)): the authorization engine never
consults the license, and the license never consults grants. A gated action
passes **both** gates — the license says *this feature is bought*, the local
authorizer says *this user may do it*.

## Who controls what

| Concern | Local | Cloud |
|---|---|---|
| Identity resolution (after login) | ✅ | login itself is cloud |
| **Authorization**: grants/roles/scopes, who-may-do-what | ✅ **own engine + own seed** | ❌ |
| **License**: feature flags, tier, seats, quotas | read-only enforcement | ✅ **single source of truth** |
| Seed / provisioning | the authz catalog + bindings, local | plans / subscriptions, cloud |

## The license: a claim signed at login

At login the cloud issues, alongside identity, a **JWKS-verifiable license claim**
the product caches and can verify and read **offline**:

```
LicenseClaim {
  subject / org,
  plan_tier,                 // free | pro | enterprise
  features: [ ... ],         // unlocked SKUs: model.strong_access, run.parallel, ...
  limits:   { seats, quotas, rates },
  issued_at, not_after,      // the offline lease window
  epoch,                     // cloud advances it to revoke (kill-switch primitive)
  sig                        // EdDSA; the product verifies against the cached JWKS
}
```

Verifying the signature against the cached `/.well-known/jwks.json` keys plus
checking `not_after` is enough to decide whether a feature is unlocked **without
reaching the cloud**. The local `check_entitlement(feature)` reads this cached
claim.

## Enforcement — two gates

```
user triggers a gated feature / action
  ├─ permission gate (local engine):  may this user, at this scope, do it?   ← local grants/roles, decided offline
  └─ license gate (cached claim):     is this feature unlocked?              ← cloud-signed license, verified offline
        both pass → allow
        license gate fails → the feature locks / degrades to the free tier
```

The permission gate is the product's existing authorization engine, unchanged.
The license gate is `check_entitlement` against the cached `LicenseClaim`.

## Offline behavior — the kill-switch is on the license only

- **Permissions**: purely local, **no expiry, no cloud dependency** — available
  offline 100% of the time.
- **License**: cached and governed by a **sliding lease**. Every successful login
  (or token refresh) slides `not_after` forward; a genuinely offline device keeps
  full features inside the window. On expiry **or** an advanced `epoch`, the
  premium features **lock and degrade to the free tier — while local permissions
  keep working**. The product does not stop; it loses only the cloud-granted
  features.

So "the cloud controls local features" reduces to the cloud controlling the
license's renewal and epoch:

- stop renewing → the lease expires and premium features lock;
- advance the epoch → the next online contact invalidates the cached license;
- never reconnect → the lease still expires on its own and features lock.

## Default semantics

The base entitlement plane is **default-allow**, but a *license* model inverts the
default for paid SKUs:

- **Premium features fail closed** when the license is missing, expired, or its
  epoch is stale → that SKU is treated as not entitled (feature off / free tier).
- **Base features stay on** regardless of license state.
- **Authorization stays default-deny**, locally, as always — the license never
  loosens a permission, and an expired license never tightens one.

## Tuning

```
license offline lease    = 14–30d   # how long a truly-offline device keeps features; slides forward on every login
high-value freshness     = optional # specific SKUs may require "synced within N days"; the rest are fully offline
permissions (local)      = no expiry # always available offline
```

The only knob is the **license lease window**: short = tight control, short
offline; long = long offline, slower revocation. Permissions are unaffected
because they never depend on the cloud.

## Mapping to existing primitives

- **License engine** = the entitlement plane: `EntitlementEngine` /
  `EntitlementCatalog` / `Plan{ tier, features, limits, rates }` /
  `check_entitlement` / subscriptions (see [entitlements](entitlements.md)).
- **Offline verification** reuses the access-token **JWKS** surface
  (`/.well-known/jwks.json`) to verify the license signature.
- **Revocation timeliness** reuses the capability **lease-epoch** primitive (see
  [permission mechanisms](permission-mechanisms.md)) to invalidate a cached
  license at once.
- **Integration mode** is the *entitlement-only* consumer mode pinned by
  `crates/awaken-iam/tests/consumer_integration.rs`: the product delegates
  feature/SKU gating to IAM and keeps its authorization engine in-repo.

What is new on top of those primitives is small: the cloud issues a **license
claim** (signed, JWKS-verifiable, carrying a lease and an epoch), and the product
wires "premium feature fails closed when the license is stale" into its feature
gate.

## Threat model — what this can and cannot enforce

Be honest about the boundary: **any license check that runs entirely on the
user's machine is ultimately bypassable**, and an **open-source client makes the
bypass trivial** — fork it, delete the gate, recompile. This is not a flaw to fix
with better crypto; it is the nature of client-side trust.

What the crypto does and does not buy:

- **Signing stops forgery, not removal.** The `LicenseClaim` is EdDSA-signed with
  a server-held private key, so an attacker *cannot mint* an `enterprise` license.
  But they do not need to — they patch the client to skip the signature check,
  skip `check_entitlement`, or hardcode `tier = enterprise`. The verifier, not the
  signature, is the soft spot, and on an open client it is right there to delete.
- **`not_after` is defeated by clock rollback** unless time is anchored to the
  server (which needs connectivity, defeating offline) or ratcheted against a
  monotonic last-seen high-water mark (which a patched client ignores anyway).

So client-side gating of a **purely local feature** is *deterrence against casual
piracy*, never a hard boundary. The realistic levers there are: account-binding
(a cracked copy is de-anonymized — you logged in), detection on the next
reconnect (renewal requires contact; anomalies flag the account), and raising
cost (obfuscation, integrity checks, signed binaries) proportional to per-seat
value. None make it uncrackable.

**The only license boundary that actually holds is server-gated value.** Make the
thing you license *require the cloud to function*:

- the premium capability is a **cloud service** (hosted inference, compute, sync)
  the client cannot perform alone; or
- the premium action requires a **short-lived, per-use capability token minted by
  the cloud** (the attenuated, epoch-fenced [capability
  mechanism](permission-mechanisms.md)), scoped to that feature — offline you
  spend a cached budget the server issued, and the server controls minting.

Then an open client changes nothing: there is no flag to patch out, and without
the server you never obtain the artifact. Design the license around features
whose value lives server-side; treat pure-local feature flags as soft deterrence,
and never gate **safety**-critical behavior on the license at all (that is
authorization's job, and it is local and default-deny).

Note the asymmetry with **authorization**: cracking the license costs *you* a paid
feature you did not buy — a revenue problem with a bounded blast radius. It can
never grant a permission, widen a scope, or cross a tenant boundary, because
those decisions are the local default-deny engine, which the license never feeds.

## Invariants

- **Authorization never leaves local.** No cloud call decides a permission; the
  product's engine and seed are authoritative and offline-complete.
- **License is cloud-owned and read-only locally.** The product enforces it but
  never mints or widens it.
- **Two orthogonal gates.** A gated action needs both; neither substitutes for
  the other.
- **Fail-closed asymmetry.** A stale license locks *cloud-granted features*, never
  the product's base function and never the local permission decision.
- **The lease is the single control/offline knob**, and it governs only the
  license — not authorization.
