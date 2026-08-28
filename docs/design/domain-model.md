# IAM domain model

This document gives `awaken-iam` a DDD shape: explicit context boundaries,
small aggregates, explicit events, and repository contracts mapped onto the
existing crates. It is the model behind
[ADR-0002](../adr/0002-iam-consolidation.md).

## Bounded context

`awaken-iam` is one deployable component containing the Authorization/Identity
context and the supporting Space Directory context. They share deployment,
authentication, audit, and storage machinery, but not domain state or revision
semantics. Both are **product-agnostic**: a product is represented only by an
open `ProductSpaceRef`; product aggregates and vocabulary do not leak inward.

### Subdomain classification

Where to spend design effort (DDD core/supporting/generic):

| Subdomain | Type | Why |
|---|---|---|
| **Authorization** | **Core** | The differentiating value: one decision plane across all products. Invest here. |
| Identity & Federation | Generic | Standard OAuth/OIDC against Google/GitHub. Adopt proven patterns, do not invent. |
| Organization & Membership | Supporting | Needed structure, not differentiating. |
| Namespace & Trust | Supporting | Publishing-specific; enables publishing/registry models. |
| Entitlement | Generic | A plan/feature seam; the money path lives elsewhere. |
| Audit | Generic | Append-only decision/identity trail. |
| Space Directory | Supporting | User-visible placement of stable product spaces; independent from authorization and product ownership. |

## Ubiquitous language

Account, External Identity, Provider, Login Flow, Session, API Token, Principal,
Organization, Group, Membership, Role, Grant, Scope, Resource Model, Action,
Decision, Namespace, Signer, Plan, Subscription, Entitlement, Directory Node,
Product Space, Product-Space Placement.

Notably: **email is a claim, never an identity key**; **Principal** is the
resolved caller (chainable for delegation); **Scope** is an authorization target
in a hierarchy, distinct from a product's domain object.

## Aggregates

Aggregates are kept small — each is a consistency boundary holding one invariant
cluster; references across aggregates are by id.

| Aggregate (root) | Holds | Invariant |
|---|---|---|
| **Account** | profile, status, linked External Identities | external identity is unique by `(provider, subject)`; a verified email selects an account only on explicit user confirmation, never silently; unlinking the last identity is refused |
| **LoginFlow** | state/nonce/PKCE challenge | started once, consumed at most once, not after expiry |
| **Session** | → AccountId, token hash, expiry | authenticates only while unexpired and unrevoked; revocation is idempotent |
| **ApiToken** | → Principal, scopes, secret hash | active until revoked; secret stored only as hash |
| **Organization** | identity, ownership | one owner principal at all times |
| **DirectoryNode** | display metadata, optional parent, Org partition | arbitrary depth; live parent stays in the same Org; no cycles; placement identity is IAM-generated |
| **Group** | member principals | members resolve to existing accounts |
| **Role** | action patterns, scope kind | patterns are exact or single-glob; no wildcard-all |
| **Grant** | subject, action pattern, scope, effect | anchored at exactly one scope |
| **Membership** | principal, scope, role | the role's scope kind matches the scope |
| **Namespace** | ownership, Signer set | signers hold public key only; revocation idempotent |
| **Plan** | features, limits | — |
| **Subscription** | → billing scope, plan, status | one active plan per billing scope |
| **ResourceModel** | a product's resource types, actions, scope edges | registered, never inferred; the genericity seam |

Organization privacy lifecycle is an application command over these existing
aggregates, not another aggregate or tenant registry. `OrganizationPrivacyScope`
derives the exact transitive closure from the authoritative Workspace→Org and
resource-parent edges. `OrgPrivacyRepository::erase_org_privacy` then removes the Org,
its groups and invitations, owned-scope grants and memberships, resource edges,
and Workspace API tokens in one storage transaction. Exact retries succeed
without a second version advance.

Accounts, external identities, sessions, global roles/profiles, namespaces, and
append-only audit remain global or independently governed records and are not
silently deleted with one organization. A caller that also needs an account
privacy lifecycle must invoke that separate, account-owned process after
checking cross-organization membership and legal-retention policy.

`Membership` is sugar that expands into grants, kept explicit so "who is a member
of X" is a cheap query. `ResourceModel` is how a product teaches IAM its scope
hierarchy and action catalog **as data**, so IAM authorizes deep product scopes
(e.g. issue → project → workspace) without depending on the product.

`DirectoryNode` is presentation, not an authorization Scope or a product
aggregate. A `ProductSpacePlacement` places one stable, product-qualified
opaque id at a node and independently records whether that product space is
active or retired. Retiring a product space never deletes, moves, or archives
the user-managed node. Moving the node never changes product identity, tenant
partition, lifecycle, or permissions; see
[ADR-0013](../adr/0013-directory-placement-independent-product-spaces.md).

## Domain services

Stateless behaviour that does not belong to one aggregate:

- **AuthorizationService** (PDP) — `evaluate(principal_chain, action, scope) ->
  Decision`. Pure over a loaded snapshot. See
  [authorization engine](authorization-engine.md).
- **EntitlementService** — `check(principal, entitlement, resource?) ->
  Decision`. A separate plane; see [entitlement plane](entitlements.md).
- **LoginService** — begins/completes federated login, normalizes claims, links
  or creates the Account. See [auth server](auth-server.md).
- **TokenService** — mints and verifies access tokens, rotates refresh tokens.
- **ScopeGraph** — ancestor resolution over registered scope edges (the PIP).

## Domain events

Every state change emits an event; events feed the audit trail and bump the
snapshot `version` that invalidates consumer caches.

```text
AccountRegistered, ExternalIdentityLinked, ExternalIdentityUnlinked,
SessionEstablished, SessionRevoked, ApiTokenIssued, ApiTokenRevoked,
RoleDefined, GrantIssued, GrantRevoked, MembershipGranted, MembershipRevoked,
SignerRegistered, SignerRevoked, SubscriptionChanged,
AuthorizationDecided (audit only)
```

## Repository contracts and adapters

The domain depends on repository **repository contracts** (traits); adapters live at the edges.
This maps onto the existing crates with no new boundaries:

```text
awaken-iam-contract   Published Language: values, ids, commands, views, decisions
awaken-iam-core       domain model + domain services + repository contracts (pure, no I/O)
awaken-iam-server     application services + adapters: HTTP (OAuth/PDP/admin), storage
awaken-iam-client     Policy Enforcement Point SDK: local | remote, used by products
awaken-iam            facade
```

Repository contracts the core declares (the server provides adapters): `AccountRepository`,
`SessionRepository`, `LoginFlowRepository`, `ApiTokenRepository`, `OrgRepository`, `GroupRepository`,
`RoleRepository`, `GrantRepository`, `MembershipRepository`, `NamespaceRepository`, `PlanRepository`,
`SubscriptionRepository`, `ResourceModelRepository`, `DirectoryRepository`, `OrgPrivacyRepository`,
`AuditSink`. The process-memory adapter is compiled for tests/test-support only;
local production uses migrated SQLite and hosted production uses Postgres. The SQL adapter
owns IAM's schema as scope-partitioned `awaken-scoped-migration` bundles — the
discipline that lets IAM deploy embedded or standalone. See
[deployment](deployment.md).

The guardrails from [AGENTS](../../AGENTS.md) already enforce this: contract
depends on nothing inward, core/client never depend on server, IAM never depends
on product runtime.

## Context map

```text
        Google / GitHub (OIDC)
              │  upstream
        [ACL: provider adapters normalize claims]
              │
        ┌─────▼──────────────── awaken-iam ────────────────┐
        │  Open Host Service (remote protocol)             │
        │  Published Language (awaken-iam-contract)        │
        └───┬───────────────┬───────────────────┬──────────┘
            │ Conformist     │ ACL (migration)    │ ACL (migration)
       conformist        incumbent-engine     thin-runtime
```

- **Upstream Google/GitHub** — IAM is a downstream conformist to their OIDC, but
  isolates them behind provider adapters so the rest of the model never sees a
  provider-specific shape.
- **Conformist consumer** — greenfield, speaks IAM's language directly.
- **Incumbent / thin-runtime consumers** — integrate through an Anticorruption
  Layer during migration, translating between their existing local vocabulary and
  IAM's, until cutover. See [permission mechanisms](permission-mechanisms.md) and
  [migration plan](migration-strategy.md).

## Simple-design commitments

- One policy language in v1: hierarchical RBAC with optional small conditions. No
  ABAC engine, no Zanzibar tuple store, no rule DSL until a second concrete need
  appears (YAGNI). The model is shaped so those are widenings, not rewrites.
- The model is broad but the **v1 build is small**: login, sessions / API keys,
  and RBAC `authorize` over the resource-model registry. Principal chains,
  `RequireApproval`, entitlement, capability tokens, and federated workload
  identity are contract-shaped now but built when the consumer that needs them
  arrives (see [migration plan](migration-strategy.md)).
- Aggregates stay small; no aggregate loads another's internals.
- Providers limited to Google, GitHub, fake. Adding one is enum + config, but we
  ship only what is needed.
