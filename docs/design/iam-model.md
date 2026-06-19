# IAM model

This document defines the target IAM model for `awaken-iam`. It complements [IAM overview](iam-overview.md) and [ADR-0001](../adr/0001-iam-shared-boundary.md).

## Purpose

`awaken-iam` is the shared identity, authorization, scope, and entitlement control plane for AwakenWorks services:

- Oversight Cloud;
- Awaken Next Cloud;
- Oversight Pack Hub;
- future cloud services that need the same account/org/workspace/project identity plane.

The core authorization shape is:

```text
Principal + Action + Scope -> Decision
```

IAM owns identity and permission evaluation. Product services own their runtime domain objects and invariants.

## Core boundaries

IAM owns:

- global accounts and sessions;
- organizations / owners and memberships;
- namespace ownership for package publishing;
- workspace and project scope references;
- grants and role bindings;
- authorization decisions;
- entitlement checks;
- API token / session contract shapes;
- audit identity and decision trace metadata.

IAM does not own:

- Oversight Issues, Workflows, WorkProducts, FlowInstallations, ConnectorBindings, CredentialSources, or OutboundEffects;
- Pack Hub package blobs, component indexes, flow indexes, or package versions;
- Awaken runtime execution state, workers, agent runs, or model/provider runtime state.

## PrincipalRef

A principal is the resolved caller identity.

```rust
enum PrincipalRef {
    Account { account_id },
    Service { service_id },
    ApiToken { token_id },
}
```

Future variants may include worker or service-account identities, but every request must resolve to a principal before it can be authorized. No principal means deny.

## ScopeRef

Scopes are product/platform authorization targets.

```rust
enum ScopeRef {
    Global,
    Org { org_id },
    Namespace { namespace_id },
    Workspace { workspace_id },
    Project { workspace_id, project_id },
}
```

Scope graph:

```text
global
  └─ org:acme
       ├─ namespace:acme
       ├─ namespace:acme-labs
       ├─ workspace:ws_acme_main
       │    └─ project:proj_web
       └─ workspace:ws_acme_support
            └─ project:proj_support
```

Meaning:

- `Org` is account/owner/billing/governance scope.
- `Namespace` is Pack publishing and trust scope.
- `Workspace` is collaboration and shared resource scope.
- `Project` is product execution scope where flows/workflows/issues run.

Namespace and Workspace may default to the same slug in product UI, but they are not the same scope.

## ActionKey

Actions are open string keys so products can add domain actions without IAM schema changes.

Examples:

```text
org.manage
namespace.manage
namespace.signer.manage
pack.read
pack.publish
pack.yank
workspace.read
workspace.configure
project.read
project.configure
flow.install
flow.configure
issue.create
issue.advance
agent.run
connector.use
credential.use
```

## Grant and RoleBinding

A grant permits a principal or role to perform an action pattern at a scope.

Target shape:

```text
Grant {
  subject,          # principal or role binding target
  action_pattern,  # e.g. pack.publish or project.*
  scope,
  effect,          # v1: allow; deny requires a future ADR
  condition?       # optional, intentionally small
}
```

Roles are grant bundles, not product workflow roles. Product-level workflow/stage roles remain in the product service.

Common role bundles:

| Scope | Roles |
|---|---|
| Org | `org_owner`, `org_admin`, `billing_admin` |
| Namespace | `namespace_owner`, `publisher`, `maintainer`, `reader`, `signer_admin` |
| Workspace | `owner`, `admin`, `member`, `viewer`, `billing_admin` |
| Project | `owner`, `maintainer`, `contributor`, `reviewer`, `viewer`, `automation` |

## Authorization vs entitlement

Authorization and entitlement are separate.

Authorization answers:

```text
Is this principal allowed to do this action at this scope?
```

Entitlement answers:

```text
Does this account/org/plan/subscription allow this feature or package access?
```

Interfaces:

```rust
authorize(AuthorizationRequest) -> AuthorizationDecision
check_entitlement(EntitlementRequest) -> EntitlementDecision
```

v1 entitlement may be default-allow, but the seam must exist so paid packs, private namespaces, and product-plan limits do not get mixed into grant evaluation.

## Product integration boundaries

### Oversight Pack Hub

Pack Hub asks IAM for namespace/package access:

```text
publish pack:
  authorize(principal, pack.publish, namespace:acme)
  authorize(principal, namespace.signer.use, namespace:acme)
  check_entitlement(principal, pack.publish, acme/pkg)

read private pack:
  authorize(principal, pack.read, namespace:acme)
  check_entitlement(principal, pack.read, acme/pkg)
```

Pack Hub still owns packages, package versions, component indexes, flow indexes, and blob metadata.

### Oversight Cloud

Oversight uses IAM for account/session and workspace/project access:

```text
install flow:
  authorize(principal, flow.install, project:web)
  authorize(principal, connector.use, workspace:acme)
  check_entitlement(principal, pack.install, coordinate)
```

Oversight still owns Issues, Workflows, WorkProducts, ConnectorBindings, CredentialSources, FlowInstallations, OutboundEffects, and domain validation.

### Awaken Next Cloud

Awaken Next uses IAM for account/org/workspace access and product entitlement:

```text
run agent:
  authorize(principal, agent.run, workspace:ws)
  check_entitlement(principal, model.strong_access, workspace:ws)
```

Awaken runtime still owns execution state and runtime-specific capabilities.

## API surface

Recommended service endpoints:

```http
POST /v1/authorize
POST /v1/authorize/batch
POST /v1/entitlements/check
GET  /v1/session
POST /v1/sessions
DELETE /v1/sessions/{id}
POST /v1/api-tokens
DELETE /v1/api-tokens/{id}
GET  /v1/orgs
GET  /v1/orgs/{org_id}/members
GET  /v1/namespaces
GET  /v1/workspaces
```

All responses should include enough explanation for audit/debug UI: decision, reason code, and optionally matched grant/role ids.

## Service configuration

Consumers should integrate through an IAM mode switch:

```toml
[iam]
mode = "remote" # local | remote
base_url = "https://iam.awakenworks.com"
audience = "oversight-pack-hub"
timeout_ms = 3000

[iam.local]
default_principal = "local_user"
default_org = "local"
default_workspace = "local"

[entitlements]
mode = "default_allow" # default_allow | remote
```

Local mode is explicit. It is not a permissive fallback for unresolved identity.

## Crate ownership

```text
awaken-iam-contract
  PrincipalRef, ScopeRef, ActionKey, AuthorizationRequest/Decision,
  EntitlementRequest/Decision, session/API-token claim DTOs

awaken-iam-core
  grant evaluation, scope graph, role expansion, decision trace

awaken-iam-client
  trait and future HTTP client used by product services

awaken-iam-server
  protocol/service assembly, storage adapters, session/token endpoints

awaken-iam
  facade
```

Guardrails:

- contract must not depend on core/client/server;
- core/client must not depend on server;
- IAM must not depend on product runtime crates;
- product services consume IAM by contract/client, not by server internals.
