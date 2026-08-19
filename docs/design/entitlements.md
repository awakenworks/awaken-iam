# Entitlement plane

This document specifies `check_entitlement`, the plane that answers
*does this account/org/plan allow this feature or package access* — kept strictly
separate from authorization. It extends
[IAM model](iam-model.md#authorization-vs-entitlement). Production construction
defaults to an unlicensed provider that denies explicit commercial checks;
`default_allow` remains an explicit development/test mode only.

> **Open seam, closed issuance.** This plane is an injection seam. The open repo
> ships the generic evaluation, an explicit development-only `default_allow`, and — so a self-hosted
> build is fully functional and can honor a presented license without calling
> home — the open `LicenseClaim` wire shape and its *offline verification* against
> a pinned JWKS of public keys. What stays *proprietary* and injected at deploy
> time by a commercial platform is everything that **mints** trust: the issuer's
> private signing store, the plan catalog, quota leases, and billing, together
> with the threat model around issuance. The open repo carries the claim shape and
> the public-key verification check; it never carries a signing key or the issuing
> pipeline. A build with no claim is unlicensed by default. The open/closed split
> is recorded in [ADR-0005](../adr/0005-open-license-claim-verification.md).
> A V2 claim is signed for exactly one `customer_id` and `deployment_id`;
> production resolution verifies both bindings in addition to signature,
> validity window, and epoch. Copying a valid claim to another installation
> therefore resolves to the same unlicensed denial as an invalid claim.
> IAM also persists the highest accepted `epoch` and `billing_version` for that
> installation and re-verifies the live claim on each commercial entitlement
> decision. Old, expired, replaced, malformed, or rebound claims fail closed.

## Why a separate plane

Authorization and entitlement answer different questions and fail for different
reasons:

```text
authorize        -> may this principal do this action at this scope?   (grants)
check_entitlement-> does this principal's plan permit this feature?     (plans)
```

Mixing them rots both: plan limits leak into grant evaluation, and a billing
lapse becomes indistinguishable from a missing role. They are evaluated
independently and a caller that needs both runs both (authorization first, then
entitlement), surfacing distinct reason codes.

## Records

```text
Plan {
  id,                # e.g. plan:free, plan:team, plan:enterprise
  features: Set<FeatureKey>,
  limits:   Map<FeatureKey, Quota>,       # optional numeric ceilings
  rates:    Map<FeatureKey, RateLimit>,   # optional per-window rate ceilings
}

Quota     = Limited(count) | Unlimited      # an inclusive numeric ceiling
RateLimit = { max_per_window, window }      # window in second|minute|hour|day

Subscription {
  subject_scope,     # Org or Account the plan is attached to
  plan_id,
  status,            # active | past_due | canceled
  valid_until?,
}
```

Entitlement is anchored at the **billing** scope (Org or Account), not the
operational scope, because plans are bought once and apply across the org's
namespaces, workspaces, and projects.

## Request and decision

The contract shape already exists:

```rust
EntitlementRequest  { principal, entitlement: String, resource: Option<String> }
EntitlementDecision { Allow | Deny }
```

`entitlement` is a feature/SKU key (`pack.publish`, `model.strong_access`,
`pack.read`). `resource` is an optional coordinate (`acme/pkg`, a workspace id)
used for per-resource limits. The decision carries a reason code
(`entitled | plan_missing | quota_exceeded | subscription_inactive`) for billing
and upsell surfaces.

## Evaluation

```text
check_entitlement(principal, entitlement, resource?):
  1. resolve the billing subject (account -> org subscription, or account plan)
  2. inactive/canceled subscription      -> Deny(subscription_inactive)
  3. entitlement not in plan.features     -> Deny(plan_missing)
  4. limit defined and resource over it   -> Deny(quota_exceeded)
  5. otherwise                            -> Allow(entitled)
```

## Quotas and rate limits

A plan attaches two optional kinds of numeric ceiling to a feature key:

- a **quota** — an inclusive total ceiling (e.g. *5 private namespaces*), and
- a **rate limit** — a maximum number of units per time window (e.g.
  *60 publishes / minute*).

IAM **defines and answers** these ceilings; it holds no counters and performs no
metering. The caller meters its own usage and supplies the observed count when it
asks whether it is still within the limit. A feature with no quota or rate entry
is unlimited. Step 4 of evaluation compares the caller-supplied usage against the
defined ceiling: usage strictly *over* the ceiling resolves
`Deny(quota_exceeded)`; a feature the plan does not entitle never reaches the
quota check and resolves `Deny(plan_missing)` first.

## Modes

```toml
[entitlements]
mode = "unlicensed"   # unlicensed | remote | license
```

`unlicensed` leaves ordinary open functionality outside this plane and denies
every explicit commercial entitlement. `remote` resolves against Cloud Billing;
`license` resolves against a verified offline claim bound to the configured
customer and deployment. `default_allow` may be selected only by tests or local
development fixtures and is never a production fallback. An unreachable billing
service and an unreadable, expired, fenced, misbound, or invalid license both
deny commercial checks.

Production license composition uses these environment inputs:

```text
AWAKEN_IAM_LICENSE or AWAKEN_IAM_LICENSE_FILE
AWAKEN_IAM_LICENSE_JWKS or AWAKEN_IAM_LICENSE_JWKS_FILE
AWAKEN_IAM_LICENSE_CUSTOMER_ID
AWAKEN_IAM_LICENSE_DEPLOYMENT_ID
```

The product supplies only its protected data-directory path for IAM's canonical
rollback-floor file. The floor is an atomic owner-only high-water mark, not a
second entitlement source. If it cannot be trusted or advanced, paid unlocks
deny. The JWKS must be provisioned through an immutable image/configuration or a
protected secret mount; it is public key material, but replacing it changes the
trust root.

### Threat boundary

Offline licensing can prevent claim forgery, casual copying, stale-claim reuse,
and tampering by principals that cannot replace the running program or its
protected state. It cannot make a customer-controlled host mathematically
unbreakable: root can patch the executable or remove a call site. Rust and
symbol stripping increase reverse-engineering cost but are not trust anchors.
Operational controls complete the boundary: Ed25519 private keys remain in
Cloud KMS/HSM, claims are short-lived, release images and manifests are signed,
SBOM/provenance are published, privileged changes are audited, and update/support
eligibility is contractually tied to a valid subscription. Optional online
activation or TPM-backed measured boot is a separate stronger deployment mode,
not part of the offline baseline.

## Where it applies

- Publishing/registry models — `pack.publish` / `pack.read` gating for paid or
  private namespaces, layered after the authorization checks in
  [namespace trust model](namespace-trust-model.md).
- Runtime models — feature gating (e.g. a model-access or capability feature) per
  tenant plan, distinct from runtime capability admission.
- Tenant plans generally — install or feature ceilings and numeric quotas at the
  org/billing scope; see [permission mechanisms](permission-mechanisms.md).

## Out of scope

- Metering, invoicing, and payment capture — a billing service, not IAM. IAM
  reads subscription state; it does not own the money path.
- Runtime quota *enforcement counters* — products meter usage; IAM answers the
  yes/no entitlement question.
