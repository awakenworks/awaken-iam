# Consumer integration

This document reconciles the shared IAM contract with the concrete consumers
that adopt it. It decides what is **shared** (owned by `awaken-iam-contract`)
and what stays **product-local**, for three things the consumers disagree on:
principals, the authorization decision, and action keys. It complements
[IAM model](iam-model.md), the [authorization engine](authorization-engine.md),
[domain model](domain-model.md), and [ADR-0001](../adr/0001-iam-shared-boundary.md).

The three consumption modes named here are pinned by the contract test
`crates/awaken-iam/tests/consumer_integration.rs`, which exercises them through
the public `awaken-iam` facade — the same surface a product service integrates
against.

## Why this exists

Consumers carry richer, product-specific vocabularies than IAM does:

- **Oversight Next** models actors as `User`, `Agent`, `ProcessAgent`, `System`,
  and groups them with `Team`. It wants approval gates, not just allow/deny.
- **Oversight Pack Hub** publishes packages and needs namespace/signer authorization.
- **Awaken Next** runs agents and gates capabilities and credentials in-repo.

If every product vocabulary leaked into the shared contract, `awaken-iam-contract`
would grow product runtime knowledge and break guardrail **G4** (no product
runtime ownership). The reconciliation principle is therefore **resolve down at
the boundary**: a consumer keeps its rich local taxonomy and collapses it to the
small shared contract shapes at the IAM call seam. IAM never learns product
actor types, product action lists, or product workflow state.

## Decision 1 — Principals

`PrincipalRef` stays the three shared variants. The rich consumer taxonomy is
product-local and resolves down to a `PrincipalRef` at the call boundary.

```rust
enum PrincipalRef {
    Account { account_id },   // a human/global account
    Service { service_id },   // a non-human service / agent / system actor
    ApiToken { token_id },    // a token-bearing caller
}
```

Mapping from Oversight Next's actor model:

| Consumer actor | Resolves to | Notes |
|---|---|---|
| `User` | `Account { account_id }` | a human account principal |
| `Agent` | `Service { service_id }` | `service_id` encodes the actor kind, e.g. `agent:<id>` |
| `ProcessAgent` | `Service { service_id }` | a process/automation actor, e.g. `process:<id>` |
| `System` | `Service { service_id }` | platform/system actor, e.g. `system:<name>` |
| token-bearing caller | `ApiToken { token_id }` | API/PAT/CI callers |
| `Team` | **not a principal** | a grant subject / membership target |

Rationale:

- **`Team` is never a principal.** A request is never made "as a Team". A Team is
  composed of a `Group` (its roster) + a `ScopeRef` (its container) + a group role
  binding. The binding does **not** expand into per-member grants; instead the
  engine resolves the requesting principal's group memberships from the **live
  roster** at evaluation and includes any grant or role the group holds at a
  covering scope (see the group subject in the
  [authorization engine](authorization-engine.md)). So a user who joins or leaves
  the Team gains or loses its permissions immediately. Keeping `Team` out of
  `PrincipalRef` keeps the request shape unambiguous — every request resolves to
  exactly one acting identity, and "no principal means deny".
- **The rich actor kinds collapse to `Service`.** IAM does not need to know the
  difference between an `Agent`, a `ProcessAgent`, and a `System` actor to decide
  a grant; it needs a stable, opaque service identity. The product retains the
  distinction for its own domain logic. The `service_id` string carries the
  product's actor kind as a prefix convention, which is human-legible in audit
  traces without becoming a contract-level enum.

### Delegation (reserved)

A `ProcessAgent` acting on behalf of a `User` is a **delegated** request. The
engine already evaluates a principal *chain* (`[Account, Service]`) as a
conjunction — both links must be authorized. v1 carries this as the existing
chain mechanism; an explicit `on_behalf_of` delegation field on the request DTO
is reserved for a future ADR rather than added speculatively (YAGNI; the shape is
a widening, not a rewrite).

## Decision 2 — Authorization decision

The shared wire decision stays **binary** in v1; `RequireApproval` is reserved in
the engine lattice, not added to the wire DTO yet.

```rust
enum AuthorizationDecision { Allow, Deny }   // awaken-iam-contract, v1 wire shape
```

The apparent tension — the [authorization engine](authorization-engine.md)
describes a three-valued lattice `deny > require_approval > allow > default-deny`
— resolves as a layering split:

- The **engine's internal `Decision` lattice** already admits `RequireApproval`
  as a third outcome. This costs nothing: it is a reserved widening the
  precedence rule already orders, so adding it later does not reorder existing
  outcomes.
- The **shipped contract DTO** `AuthorizationDecision` stays `{ Allow, Deny }`.
  No current consumer needs IAM to *return* an approval verdict over the wire.

How approval works today: a consumer that wants an approval gate models it as a
**product workflow**. IAM returns `Deny` (with a reason code), and the product
runs its own approve/pause/resume loop. Approval execution — prompting, pausing,
resuming — is product-local in every design; IAM only ever *decides*, it never
drives the workflow.

When a real consumer needs IAM to natively return "needs approval" rather than
infer it from `Deny` + reason, `AuthorizationDecision` widens to a third variant
and the engine's existing `RequireApproval` outcome is surfaced unchanged. An
**obligations envelope** (carrying the reason code and any approval metadata
alongside the outcome) is reserved for that same future ADR.

## Decision 3 — Action keys

`ActionKey` stays an **open string**. IAM owns structural action domains; products
own their own action vocabularies and fail closed on unknown actions.

```rust
struct ActionKey(String);   // open string, no contract-level enum
```

Naming convention: `<domain>.<resource?>.<verb>`, lower snake segments, no
wildcards in a key (wildcards belong to grant *patterns*, not requests).

| Owner | Domains | Examples |
|---|---|---|
| **IAM (structural)** | `org.*`, `namespace.*`, `workspace.*`, `project.*` | `org.manage`, `namespace.signer.use`, `workspace.configure`, `project.read` |
| **IAM (catalog-seeded, consumer-declared)** | `agent.*`, `session.*`, `tool.*` | `agent.run`, `session.create`, `tool.invoke` |
| **Product (local)** | product-defined | `issue.advance`, `flow.install`, `connector.use` |

Rules:

- **Open string, not an enum.** A contract-level enum would force an IAM release
  for every new product action. The open string lets a product add domain actions
  with no IAM schema change, matching the existing
  [IAM model](iam-model.md#actionkey).
- **Structural domains are IAM's.** Actions over orgs, namespaces, workspaces, and
  projects are part of the shared scope/identity plane and are evaluated by IAM.
- **Catalog-seeded consumer namespaces are IAM-owned by declaration.** A consumer
  declares its action namespaces via [`ConsumerNamespaces`] and seeds a matching
  role preset through `awaken-iam-core`. The awaken-runtime consumer (`awaken_runtime()`)
  declares `agent.*`, `session.*`, and `tool.*` this way; those namespaces are
  **catalog-owned** (G16), not product-local — the catalog carries the grant sets and
  the runtime derives its vocab from preset instead of hand-rolling it.
- **Product domains are the product's.** Action vocabularies specific to a single
  product that are not catalog-seeded remain product-local. When a consumer keeps its
  own authorization engine (see Oversight Next below), IAM never sees those keys.
- **Unknown actions default-deny.** There is no superuser wildcard; a grant must
  list its action patterns explicitly, so an unrecognized action simply matches no
  grant and is denied.

## Shared vs product-local

| Concern | Shared (`awaken-iam-contract`) | Product-local |
|---|---|---|
| Acting identity | `PrincipalRef` (Account / Service / ApiToken) | rich actor taxonomy (`User`/`Agent`/`ProcessAgent`/`System`/`Team`) |
| Scope | `ScopeRef` | product resource hierarchy beyond the scope graph |
| Action | `ActionKey` (open string) + structural domains + catalog-seeded consumer namespaces (`agent.*`, `session.*`, `tool.*`) | non-catalog product action vocabularies |
| Decision | `AuthorizationDecision { Allow, Deny }` | approval workflow execution |
| Entitlement | `EntitlementRequest`/`EntitlementDecision` | runtime capabilities, credentials |
| Roles | grant-bundle roles + catalog-seeded consumer presets (`runtime_admin`, `runtime_user`) | product workflow/stage roles |
| Authorization of product domain actions | `authorize` over a registered `ResourceModel` (ADR-0004) | product action vocabulary, approval workflow execution |

## Consumption modes

Each consumer delegates a different slice of IAM. These are the three modes the
contract test pins.

### Oversight Next — authentication only (historical baseline)

Oversight Next originally delegated **authN only**: it resolved the caller through
the IAM session core (mapping its actor to a `PrincipalRef`), then ran its **own**
authorization engine over its own domain, without consulting the IAM grant plane.
This is the strangler-fig *starting point*, superseded by the reuse below.

### Oversight Next — full authorization reuse (ADR-0004)

ADR-0004 changed the product direction: Oversight Next now reuses IAM's **full**
authorization plane rather than carrying its own engine. Two pieces make that
work, both pinned by the cutover contract test:

- **ResourceModel registration.** Oversight teaches IAM its resource types
  (`issue`, `run`, `thread`, `team`), their action catalogs, and their
  per-instance scope parent edges *as data*. IAM then resolves the product
  hierarchy (`run -> issue -> project -> workspace`) through the same scope-graph
  walk it uses for the well-known scopes; the core never learns the product. The
  rich actor taxonomy resolves down to `Account`/`Service`/`Group` at the call
  boundary, per the mapping table above, and a `Team` is a `Group` (membership
  target), never a principal.
- **Strangler-Fig shadow cutover.** Because Oversight has an incumbent engine, the
  enforcement point runs both engines through a `ShadowAuthorizer`: the incumbent
  stays authoritative while the IAM candidate is compared but never enforced.
  Divergence is burned down to measured parity over a request window, then the
  flag flips and IAM alone decides — at which point the in-repo engine is retired.
  (Managed agents integrate greenfield, with no shadow phase.)

### Oversight Pack Hub — authorize plus namespace/signer checks

Pack Hub delegates **authorization to IAM**. A publish requires the
`pack.publish` grant *and* the `namespace.signer.use` grant at the namespace
scope, *plus* a `pack.publish` entitlement — all against the IAM seam. Missing the
signer grant blocks the publish even when `pack.publish` is held, proving both
`authorize()` checks are independently required and that entitlement is its own
plane.

### Awaken Next — consumer namespaces + entitlement gating

Awaken Next declares its action surface via the **awaken-runtime consumer
namespaces** (`awaken_runtime()`: `agent.*`, `session.*`, `tool.*`) and seeds a
matching role preset (`runtime_admin`, `runtime_user`) during startup provisioning
via `seed_runtime_roles()`. This keeps the runtime's action vocab **catalog-owned
(G16)**: awaken-1.0.0-dev derives its grant vocabulary from the preset rather than
hand-rolling names.

Beyond action/role seeding, Awaken Next delegates **entitlement gating**. A run is
gated by `check_entitlement` against the IAM plan/SKU plane; runtime capability
gating and credentials stay in-repo and never route through IAM. A principal whose
plan lacks the feature fails closed, and an absent in-repo capability also blocks
the run — that second decision is made locally, not by IAM.

Per [ADR-0004](../adr/0004-consumers-reuse-iam-authz.md), managed agents widen
this from entitlement-only to also reusing IAM's **attenuated capability tokens**
(permission mechanism 7) for sub-agent / sandbox delegation. The flow composes
the two planes without reimplementing either: the entitlement plane gates *who*
may run (`agent.run`, the model tier, and the run quota); then a cleared parent
agent mints a scope-narrowed, epoch-fenced capability and **attenuates** it for a
sub-agent, handing the child strictly less authority for a bounded time. The
sandbox verifies the delegated token holder-independently against the published
JWKS, and advancing the sandbox lease epoch fences every outstanding token out at
once. IAM still owns neither the run loop nor the in-sandbox enforcement — it
mints and verifies the delegated authority; the runtime spends it.

## Consequences

- The shared contract stays small and product-agnostic; guardrails **G1** and
  **G4** hold because no product runtime vocabulary enters
  `awaken-iam-contract`.
- Consumers can integrate at three depths (authN-only, full authorize, entitlement
  -only) without IAM growing per-consumer surface.
- Three future widenings are contract-shaped but unbuilt: an `on_behalf_of`
  delegation field, a third `RequireApproval` decision variant with an obligations
  envelope, and any new structural action domain. Each is additive.
