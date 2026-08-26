# Remote protocol and client

This document specifies how product services reach IAM authorization and
entitlement decisions over the wire, and how the `IamClient` seam supports both
in-process and remote modes. It makes the
[API surface](iam-model.md#api-surface) in [IAM model](iam-model.md) concrete.

## Problem

Today `IamClient` is an in-process synchronous trait and only the login API is
served over HTTP — `authorize()` is unreachable for a separate service. A
standalone consumer runs as its own process and must obtain decisions remotely,
while an embedded consumer wants the same trait in-process with no network hop.

## One trait, two modes

```rust
trait IamClient {
    fn authorize(&self, req: AuthorizationRequest) -> Decision;
    fn check_entitlement(&self, req: EntitlementRequest) -> EntitlementDecision;
}
```

The remote transport layer is broken out as the `AuthzTransport` trait so that
`RemoteIamClient<T>` can delegate each endpoint call to a swappable implementation
(`HttpAuthzTransport` in production, stubs in tests). Methods on `AuthzTransport`
correspond one-to-one with the HTTP endpoints below:

| Transport method | HTTP endpoint |
|---|---|
| `authorize` | `POST /v1/authorize` |
| `authorize_batch` | `POST /v1/authorize/batch` |
| `check_entitlement` | `POST /v1/entitlements/check` |
| `fetch_signers` | `GET /v1/namespaces/{id}/signers` |
| `fetch_snapshot` / `fetch_snapshot_since` | `GET /v1/authz/snapshot` |
| `introspect_token` | `POST /v1/tokens/introspect` |
| `create_directory_node` | `POST /v1/admin/directory/nodes` |
| `get_directory_node` / `directory_children` | `GET /v1/admin/directory/nodes...` |
| `move_directory_node` / `update_directory_node` / `archive_directory_node` | `PUT` / `PATCH` / `DELETE /v1/admin/directory/nodes/{id}` |
| `product_space_binding` | `POST /v1/admin/directory/product-spaces/query` |

`introspect_token` has a default implementation that returns an unsupported error,
so existing `AuthzTransport` implementations remain valid without change. The
production `HttpAuthzTransport` overrides it to call the endpoint below.

```toml
[iam]
mode = "remote"          # local | remote
base_url = "https://iam.example.com"
audience = "example-service"
timeout_ms = 3000
```

- **local** — the client wraps `IamServer`/`IamCore` directly; decisions are a
  function call over a loaded snapshot. Used by the embedded role and tests.
  Local mode is explicit, never a permissive fallback for unresolved identity.
- **remote** — the client calls the HTTP endpoints below and caches snapshots.

A product depends only on the trait and `awaken-iam-contract`; swapping modes is
configuration, not a code change, and never reaches `awaken-iam-server`
internals.

## Endpoints

```http
POST /v1/authorize
POST /v1/authorize/batch
POST /v1/entitlements/check
GET  /v1/namespaces/{namespace_id}/signers
GET  /v1/authz/snapshot?since={version}
GET  /v1/session
POST /v1/tokens/introspect
POST /v1/capabilities/introspect
POST /v1/admin/capabilities
POST /v1/admin/directory/nodes
GET  /v1/admin/directory/nodes/{id}
GET  /v1/admin/directory/nodes?org_id={org}&parent_id={optional_parent}
PUT  /v1/admin/directory/nodes/{id}
PATCH /v1/admin/directory/nodes/{id}
DELETE /v1/admin/directory/nodes/{id}
POST /v1/admin/directory/product-spaces/query
```

### POST /v1/authorize

```jsonc
// request
{ "principal": {...PrincipalRef}, "action": "pack.publish",
  "scope": { "kind": "namespace", "namespace_id": "acme" } }
// response
{ "outcome": "deny", "reason_code": "no_grant",
  "matched_grant_id": null, "scope_anchor": null }
```

The response is the [decision trace](authorization-engine.md#decision-trace):
outcome, reason code, and matched grant/role/scope ids — enough for an audit/debug
UI without a second round trip. `/v1/authorize/batch` takes an array and returns
decisions positionally, for list filtering.

### GET /v1/authz/snapshot

Returns the versioned [`AuthzSnapshot`](authorization-engine.md#snapshot) for
consumers that prefer to evaluate locally and only sync on the `version` fence. `since` lets the client skip an unchanged snapshot. Decisions
computed from a synced snapshot are byte-identical to remote `authorize` calls —
the evaluation code is shared, the transport differs.

### POST /v1/tokens/introspect

```jsonc
// request
{ "token": "sk-awaken-<prefix>.<secret>" }
// response (200 OK — token is live)
{ "principal": {...PrincipalRef}, "workspace": "<workspace_id>",
  "status": "active" }
// error (401 Unauthorized — invalid, revoked, or expired)
```

Verifies a bearer API token and resolves its `principal` + `workspace` binding.
Token verification (argon2id) stays in IAM; consumers never hold or re-implement
the `secret_hash` check. Invalid, revoked, and expired tokens all return
`401 Unauthorized` — no branch is distinguishable to the caller, per the
no-information-leak rule. The `status` field is always `active` in a 200 response;
it is present for forward-compatibility with any future offline/cached introspection
path. Exposed on `AuthzTransport` as `introspect_token` (see the method table
above).

### Capability issuance and introspection

`POST /v1/admin/capabilities` is the single guarded HTTP adapter over IAM's
existing `mint_capability` mechanism. It accepts issuer, subject, audience,
token id, Unix-second issue/expiry coordinates, and non-empty scopes, and
returns the one-time `cap+jwt`. The daemon uses the same injected asymmetric
authority and JWKS as its access-token surface; it never constructs a second
signer.

`POST /v1/capabilities/introspect` verifies the presented token's signature,
family `typ`, audience, public-link epoch, and expiry and returns its claims.
The token remains only authentication evidence. A consumer must separately call
the ordinary `/v1/authorize` PDP for the returned subject, requested action, and
exact product resource. Revocation and rotation therefore reuse the canonical
Grant: remove it to revoke, or replace its deterministic id with a fresh subject
to invalidate every older link. IAM stores no second share registry.

## Caching and freshness

- Remote `authorize` results may be cached briefly keyed by
  `(principal, action, scope, snapshot_version)`; a `version` bump invalidates
  the cache.
- Signer sets and snapshots carry the same `version` fence, so revocation and
  grant changes propagate on the next sync.
- Caching is opt-in per call site; security-sensitive writes
  (publish, grant changes) should evaluate fresh.

## Failure semantics

### Policy administration: invitations and member queries

The guarded authorization administration API adds the following product-neutral
operations. They use the same admin credential and policy-version fence as
organization and membership writes.

| Method | Path | Result |
|---|---|---|
| `POST` | `/v1/admin/memberships/query-scope` | exact RoleBindings anchored at one scope |
| `PUT` | `/v1/admin/memberships/scoped` | atomically replace one managed role family for a principal at an exact scope |
| `POST` | `/v1/admin/invitations` | pending invitation + one-time clear token |
| `POST` | `/v1/admin/invitations/query` | invitations for one Org |
| `DELETE` | `/v1/admin/invitations/{id}` | revoke pending invitation |
| `POST` | `/v1/admin/invitations/{id}/resend` | rotated one-time token |
| `POST` | `/v1/admin/invitations/{id}/accept` | accepted invitation + visible policy version |
| `DELETE` | `/v1/admin/orgs/{id}` | idempotently erase the IAM-owned organization scope closure |

The clear token is never persisted. Accept requires an IAM account id and a
verified email assertion obtained from IAM UserInfo by the trusted relying
party; the PAP compares that routing claim to the invitation and atomically
materializes every declared RoleBinding.

Organization deletion is the single IAM privacy lifecycle command. The server
derives the owned scope closure from its existing Workspace→Org and resource
graph, atomically removes IAM projections in that closure, and advances the
ordinary policy version exactly once. A retry after success returns the current
version rather than `404`; consumers therefore use the same guarded admin
transport in embedded and remote deployments. Global accounts, sessions, and
append-only audit are outside this Org-scoped command.

```text
transport error / timeout (remote)  -> Deny(reason = iam_unavailable)
unresolved principal                -> Deny(reason = principal_unresolved)
entitlement backend unreachable      -> Deny (not Allow); default_allow is a
                                        configured mode, not a failure mode
```

Authorization fails closed. An IAM that cannot answer denies; it never degrades
to allow. This matches the engine's default-deny posture.

## Auth of the caller

Each product service authenticates to IAM with a service principal
(`PrincipalRef::Service` / `ApiToken`) scoped by `audience`. The caller's
*subject* principal travels inside the request body; the *transport* principal is
the service itself. IAM authorizes the subject, not the carrier.

Long-running workloads may configure that service credential either as one
explicit in-memory value (tests and local composition) or as one projected file
(orchestrated deployments). The two sources are mutually exclusive. The HTTP
transport reads and trims the projected file for every attempt, so an atomic
file replacement rotates subsequent requests without rebuilding the client or
its connection pool. A missing, unreadable, or empty file fails closed before
any request is sent; it never falls back to an ambient user credential.

```text
configured credential source
  -> exactly one of static value / projected file
  -> resolve immediately before an IAM request attempt
  -> non-empty bearer
  -> remote IAM decision
```

| Static value | Projected file | File state | Result |
|---|---|---|---|
| present | absent | n/a | send the static bearer |
| absent | configured | readable and non-empty | send the current file bearer |
| absent | configured | replaced between requests | next request sends the replacement |
| absent | configured | missing, unreadable, or empty | fail closed; send no request |
| present | configured | any | configuration error; send no request |
| absent | absent | n/a | anonymous transport, only where explicitly permitted |

## Out of scope

- Login/OAuth endpoints — already served; see
  [IAM model](iam-model.md#external-identity-and-sessions).
- Wire framing details (gRPC vs JSON/HTTP) — an implementation choice; the shape
  above is transport-agnostic.
