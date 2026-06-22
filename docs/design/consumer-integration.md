# Consumer integration boundary

This document defines the **cross-consumer integration boundary** for Awaken
IAM: exactly which planes each product service delegates to IAM and which it
keeps in-repo. It complements [IAM model](iam-model.md),
[Entitlement plane](entitlement-plane.md), and
[ADR-0001](../adr/0001-iam-shared-boundary.md).

IAM exposes three independent seams through the `IamClient` trait and the
identity/session core:

- **AuthN** — resolve a caller to a `PrincipalRef` (login, sessions, external
  identities). Owned by the identity/session core.
- **AuthZ** — `authorize(principal, action, scope) -> Decision`. Grant plane.
- **Entitlement** — `check_entitlement(principal, feature, resource?) -> Decision`.
  Plan/SKU plane.

A consumer is free to adopt any subset of these seams. What a consumer does
**not** delegate stays product-owned. The point of this document is to pin that
subset per consumer so the boundary cannot drift silently, and to back each
choice with a contract test.

## Consumption modes

| Consumer | AuthN | AuthZ (`authorize`) | Entitlement | Stays in-repo |
|---|---|---|---|---|
| Oversight Next | delegated | **not** delegated | optional | its own authz engine + all domain data |
| Oversight Pack Hub | delegated | delegated (`pack.*` + `namespace.signer.*`) | delegated | packages, versions, blob/index metadata |
| Awaken Next | delegated | **not** delegated | delegated (model/SKU gating) | runtime capability/permission gating + credentials |

### Oversight Next — delegates authN only

Oversight Next uses IAM to authenticate the caller (login, sessions, external
identity link) and to resolve a `PrincipalRef`. It then runs **its own
authorization engine** over its own domain objects (Issues, Workflows,
WorkProducts, FlowInstallations, ConnectorBindings, CredentialSources).

It does **not** call `authorize()` for those domain decisions. IAM does not
own Oversight's project/workflow authorization, so a default-deny IAM grant
plane is the expected answer for an Oversight domain action; relying on it would
be a boundary violation. The contract is: IAM resolves *who* the caller is;
Oversight decides *what* they may do.

### Oversight Pack Hub — remote authorize + namespace/signer checks

Pack Hub delegates authorization to IAM. A publish is gated by **two** grant
checks plus an entitlement check, all against the IAM seam:

```text
publish pack:
  authorize(principal, pack.publish, namespace:acme)          // namespace publish grant
  authorize(principal, namespace.signer.use, namespace:acme)  // signer-key use grant
  check_entitlement(principal, pack.publish, acme/pkg)        // plan/SKU gate
```

Both grant checks are required: holding `pack.publish` without
`namespace.signer.use` cannot sign and publish. Pack Hub still owns packages,
package versions, component/flow indexes, and blob metadata — IAM owns only the
namespace ownership and signer-use grants.

### Awaken Next — entitlement gating only

Awaken Next delegates **entitlement** decisions to IAM (model tier / SKU access,
e.g. `model.strong_access` at a workspace), so plan limits are enforced
consistently across products.

Runtime capability and permission gating stays **in-repo**: whether an agent run
may actually use a tool/capability is decided by the Awaken runtime, not by
IAM's `authorize()`. Credentials remain **product-owned** — IAM never stores or
brokers connector/model credentials. The contract is: IAM answers *is this plan
entitled*; the runtime answers *may this run use this capability* and holds the
secrets to do so.

## Why the boundary is enforced by contract tests

Each mode above is proven by a contract test in
`crates/awaken-iam/tests/consumer_integration.rs`, exercised through the public
`awaken-iam` facade (the same surface a consumer integrates against):

- Oversight Next authenticates through the IAM session core, then a local
  product authz engine decides a domain action that the IAM grant plane would
  deny — proving authz is not delegated.
- Pack Hub's publish path requires both the `pack.publish` and
  `namespace.signer.use` grants plus the entitlement, and is blocked when the
  signer grant is missing.
- Awaken Next gates a run on `check_entitlement` while resolving runtime
  capability and credentials locally, and fails closed when the plan lacks the
  feature.

These tests pin the consumption modes so a change that, say, made Oversight Next
depend on IAM `authorize()` or moved credentials into IAM would break the suite.
