# Permission mechanisms

`awaken-iam` does not model any specific product. It offers a small set of
orthogonal **mechanisms**, and any product's permission model is *composed* from
them. The test of the design is mechanical, not nominal: if a model can be
expressed by combining the mechanisms below, it is supported — no product is
ever named or special-cased in the core.

This document enumerates those mechanisms and the model archetypes each one
covers. It is the coverage argument behind [ADR-0002](../adr/0002-iam-consolidation.md).

## The mechanisms

### 1. Hierarchical RBAC
Roles are bundles of action patterns; a grant binds a subject to an action
pattern at a scope; memberships expand roles onto principals. Covers any
role/permission model. See [authorization engine](authorization-engine.md).

### 2. Open scope model
Scopes are not a closed set. Beyond the well-known ones
(`global / org / namespace / workspace / project`) there is an open
`Resource { resource_type, resource_id }`, and parent edges come from a
registered [`ResourceModel`](domain-model.md#aggregates). This expresses an
**arbitrarily deep** product hierarchy (e.g. a leaf object → … → tenant root)
without changing the core. A grant anchored at any ancestor applies to
descendants.

### 3. Open action catalog
`ActionKey` is an open string; a product registers its own catalog through its
`ResourceModel`. No schema change is needed to add a product action.

### 4. Principals, groups, and delegation chains
Principals are human (account), service (any non-human identity, including
automated agents), or token. Groups give group-based grants. A request carries a
**principal chain** evaluated conjunctively, so on-behalf-of and delegated
dispatch (`[human, agent]`) authorize correctly — every link must pass.

### 5. Three-valued decision
`Allow | Deny | RequireApproval`. The approval *decision* is IAM's; the approval
*execution* (prompting, pausing, resuming) belongs to the caller. Covers
human-in-the-loop gates without IAM running a workflow. A `RequireApproval`
outcome carries an **obligation envelope** (`obligation_id`, `policy_id`,
approval authority); the approval is discharged product-side or as a capability
token bound to `obligation_id`, never by re-querying authorize. See
[authorization engine](authorization-engine.md#approval-obligation) and
[ADR-0004](../adr/0004-consumers-reuse-iam-authz.md) #3.

### 6. Visibility filtering
A batch query returns the subset of candidate scopes a principal may act on, in
one pass — so list endpoints do not issue one decision per row.

### 7. Attenuated capability tokens
A holder can mint a short-lived token that is **scope-narrowed** to a subset and
**fenced** by an epoch; verification checks signature, audience, and epoch, so a
lease change invalidates outstanding tokens at once. Covers sub-process /
sandbox / worker delegation where a parent grants a child strictly less authority
for a bounded time. See [auth server](auth-server.md#sessions-and-tokens).

### 8. Scoped tokens (API keys)
A long-lived principal token carries a set of action scopes and is stored only as
a hash. Covers machine and automation callers whose authority is a fixed scope
set.

### 9. Federated workload identity
Token exchange accepts an upstream OIDC/STS assertion from a trusted external
issuer and mints an IAM token for a service principal. Covers workloads that
already carry a federated identity from another IdP.

### 10. Entitlement and quota plane
A plane separate from authorization: boolean features, numeric quotas (ceilings),
and rate-limit definitions, anchored at a billing scope. IAM **defines and
answers** the limit; the caller meters usage against it. See
[entitlement plane](entitlements.md).

### 11. Namespace and signer trust
Namespace ownership plus a namespace→authorized-signer-key binding, with
publish/read/yank authorized at namespace scope. Covers any publishing or
registry model that binds releases to a trusted identity. See
[namespace trust model](namespace-trust-model.md).

### 12. Versioned snapshot and fence
A monotonic `version` lets a caller run a local decision point over a synced
snapshot for hot paths, and propagates grants and revocations on the next sync.

## Composing a model

A product's model is the subset of mechanisms it needs. Some representative
shapes, described by archetype rather than by name:

| Model archetype | Mechanisms used |
|---|---|
| Publishing / registry | 1, 2, 3, 10, 11 |
| Incumbent deep-RBAC service | 1, 2, 3, 4, 5, 6, 12 |
| Sandboxed multi-agent service | 1, 2, 4, 7, 8, 10 |
| Thin runtime (identity + gating elsewhere) | 4, 9, 10 |

Each cell is a composition, not a new feature. Adding a future consumer means
registering its `ResourceModel` and picking mechanisms — never extending the
core for it.

## What is never a mechanism here

The boundary that keeps IAM coherent (and matches the
[ADR-0001](../adr/0001-iam-shared-boundary.md) guardrails): IAM owns the
*decision* and the *identity*; it does not own *enforcement* or *runtime
mechanism*. Out of scope, always:

- in-process tool / action gating policy and its prompts;
- runtime capability admission and environment reconciliation;
- connector / third-party credentials and secret material;
- approval-workflow execution;
- usage meters and counters (IAM defines the quota; the caller counts);
- product business logic on the resources it scopes.
