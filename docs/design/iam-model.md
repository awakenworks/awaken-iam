# IAM model

This document defines the target IAM model for `awaken-iam`. It complements [domain model](domain-model.md) and [ADR-0001](../adr/0001-iam-shared-boundary.md).

## Purpose

`awaken-iam` is the shared, product-agnostic identity, authorization, scope, and entitlement control plane for any service that needs the same account/org/workspace/project identity plane:

- publishing / registry services;
- collaboration / workspace services;
- agent-runtime services;
- any future service that adopts the same identity plane.

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

- product domain objects and their lifecycle (issues, workflows, work products, flow installations, connector bindings, credential sources, outbound effects);
- registry artifacts (package blobs, component/flow indexes, package versions);
- runtime execution state (workers, agent runs, model/provider runtime state).

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

## External identity and sessions

Accounts are internal IAM principals. External login providers only establish or
refresh a link to an account.

Core records:

```text
Account {
  id,
  status,
  display_name?,
  created_at,
  updated_at,
}

IdentityProviderConfig {
  id,
  provider_key,
  kind,          # fake | oauth2 | oidc
  display_name,
  issuer_url?,
  authorization_endpoint?,
  token_endpoint?,
  client_id?,
  enabled,
}

ExternalIdentity {
  id,
  account_id,
  provider_key,
  claims,
  first_seen_at,
  last_seen_at,
}

ExternalIdentityClaims {
  subject,
  email?,
  email_verified?,
  display_name?,
  username?,
  avatar_url?,
  locale?,
}

OAuthLoginState {
  id,
  provider_key,
  state_hash,
  nonce_hash?,
  pkce_verifier_hash?,
  return_to?,
  created_at,
  expires_at,
  consumed_at?,
}

Session {
  id,
  account_id,
  token_hash,
  external_identity_id?,
  created_at,
  last_seen_at,
  expires_at,
  revoked_at?,
}
```

External identity uniqueness is:

```text
provider_key + claims.subject
```

Email is not an identity key. It is a mutable provider claim and can change on a
later login without creating or selecting a different account. Fake-provider
login uses the same model: the fake provider emits a deterministic provider key
and subject, then IAM resolves that provider+subject to the linked account and
creates a session.

`Account` is platform-global and durable. Every hosted IAM replica reads the
same Account and ExternalIdentity repositories; Account plus first identity are
provisioned atomically. Organizations, Workspaces, Projects, products, and
physical Cells reference that AccountId through roles or projections and do not
own a separate user lifecycle.

Hosted AwakenWorks identity uses `https://accounts.awakenworks.com` as the stable
OIDC issuer. Product applications discover and start login through that issuer's
`/v1/oauth/authorize` endpoint; provider-specific routes such as
`/v1/auth/login/{provider}` are IAM-owned subflows after account/provider
selection, not product integration points.

The hosted issuer is the production default. Self-hosted or regional deployments
may configure a different issuer, client registry, redirect-uri allowlist, scopes,
provider set, and signing-key/JWKS policy. Clients must follow discovery output
rather than assuming the default AwakenWorks host.

The login loop carries two invariants. An `OAuthLoginState` challenge is
single-use: it is started once and consumed at most once, and an expired
challenge cannot be consumed. A `Session` authenticates only while it is
unrevoked and unexpired; revocation is idempotent. These rules are enforced
independently of the mutable claims carried by the identity.

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

## Integration patterns

Services integrate by composing IAM calls; the model owns the decision, the
service owns the resource. Representative call shapes, generic to any consumer:

```text
publish to a namespace:
  authorize(principal, pack.publish, namespace:acme)
  authorize(principal, namespace.signer.use, namespace:acme)
  check_entitlement(principal, pack.publish, acme/pkg)

read a private resource:
  authorize(principal, pack.read, namespace:acme)
  check_entitlement(principal, pack.read, acme/pkg)

act within a workspace / project:
  authorize(principal, flow.install, project:web)
  authorize(principal, connector.use, workspace:acme)
  check_entitlement(principal, pack.install, coordinate)

run a tenant-gated capability:
  authorize(principal, agent.run, workspace:ws)
  check_entitlement(principal, model.strong_access, workspace:ws)
```

In every case the service still owns its own domain objects, runtime state, and
business validation; IAM owns only identity, the authorization decision, and the
entitlement check. See [permission mechanisms](permission-mechanisms.md) for how
arbitrary models compose from these calls.

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
base_url = "https://iam.example.com"
audience = "example-service"
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
