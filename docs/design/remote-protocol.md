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

## Capability-specific clients, two modes

```rust
trait IamClient {
    fn authorize(&self, req: AuthorizationRequest) -> Decision;
    fn check_entitlement(&self, req: EntitlementRequest) -> EntitlementDecision;
}
```

The remote layer separates authorization and Directory capabilities.
`AuthzTransport` owns authorization, entitlement, snapshot, and token methods;
`DirectoryClient` owns the complete Directory surface. `RemoteIamClient<T>` can
delegate either capability to `HttpAuthzTransport` in production or a focused
test implementation without forcing an authorization-only consumer to implement
Directory methods.

| Transport method | HTTP endpoint |
|---|---|
| `authorize` | `POST /v1/authorize` |
| `authorize_resource` | `POST /v1/authorize/resource` |
| `profile_publication_state` | `GET /v1/authz/profiles/{namespace}/publication` |
| `authorize_batch` | `POST /v1/authorize/batch` |
| `check_entitlement` | `POST /v1/entitlements/check` |
| `register_resource_model` with `ProductResourceModelRequest` | `POST /v1/authz/resource-model` |
| `fetch_signers` | `GET /v1/namespaces/{id}/signers` |
| `fetch_snapshot` / `fetch_snapshot_since` | `GET /v1/authz/snapshot` |
| `introspect_token` | `POST /v1/tokens/introspect` |
The independent `DirectoryClient` maps one-to-one to:

| Directory method | HTTP endpoint |
|---|---|
| `create_directory_node` | `POST /v1/admin/directory/nodes` |
| `ensure_product_space_placement` | `POST /v1/admin/directory/product-spaces/ensure` |
| `get_directory_node` / `directory_children` | `GET /v1/admin/directory/nodes...` |
| `directory_revision` | `GET /v1/admin/directory/revision` |
| `move_directory_node` / `update_directory_node` / `archive_directory_node` / `restore_directory_node` | `PUT` / `PATCH` / `DELETE` / `POST /v1/admin/directory/nodes/{id}/restore` |
| `product_space_placement` | `POST /v1/admin/directory/product-spaces/query` |

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
POST /v1/authorize/resource
GET  /v1/authz/profiles/{namespace}/publication
POST /v1/authorize/batch
POST /v1/entitlements/check
GET  /v1/namespaces/{namespace_id}/signers
GET  /v1/authz/snapshot?since={version}
GET  /v1/session
POST /v1/tokens/introspect
POST /v1/capabilities/introspect
POST /v1/admin/capabilities
POST /v1/admin/directory/nodes
POST /v1/admin/directory/product-spaces/ensure
GET  /v1/admin/directory/nodes/{id}
GET  /v1/admin/directory/nodes?org_id={org}&parent_id={optional_parent}
GET  /v1/admin/directory/revision?org_id={org}
PUT  /v1/admin/directory/nodes/{id}
PATCH /v1/admin/directory/nodes/{id}
DELETE /v1/admin/directory/nodes/{id}
POST /v1/admin/directory/nodes/{id}/restore
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

### Product resource vocabulary and instances

The existing `AuthzTransport::register_resource_model` and `RemoteIamClient`
method take the canonical `ProductResourceModelRequest`, containing an explicit
`product_id` and the original `resource_model`. The client sends that complete
request once through its existing authenticated transport. It does not infer the
product from an audience, token or resource-type prefix, or retry a rejected
wrapper as a bare registration.

The guarded daemon route checks the product credential and accepts vocabulary
only. Instance edges and revocable grants use `ResourceProjectionBatch` on
`/v1/authz/resource-provisions`; atomic `ResourceProvision` clients use
`/v1/authz/resource-provision-transactions`. The published route's existing strict
dispatch and both v8 histories remain owned by [ADR-0015](../adr/0015-reconcile-published-and-consumed-provisioning.md).
The local `AuthzApi`/Core model-registration method retains its embedded model
input and does not simulate the daemon's product-admission policy.

### GET /v1/authz/snapshot

Returns the versioned [`AuthzSnapshot`](authorization-engine.md#snapshot) for
consumers that prefer to evaluate locally and only sync on the `version` fence. `since` lets the client skip an unchanged snapshot. Decisions
computed from a synced snapshot are byte-identical to remote `authorize` calls —
the evaluation code is shared, the transport differs.

### Profile publication evidence

The existing profile PAP owns a small read projection for decision consumers:

```json
{ "namespace": "example.business", "has_published_revision": false }
```

`AuthorizationProfileAdmin` reads its existing immutable revision history.
Draft and validated-only history is false; any active or retired revision is
true. Retirement cannot turn a previously configured namespace back into an
unconfigured one. No flag, policy copy, or additional repository is stored.

This is evidence about publication, not permission. A consumer must first
authorize its platform operation; an optional business layer may retain legacy
behavior only after a successful, exact-namespace false response. Published
namespaces still require the ordinary contextual PDP. The caller verifies the
echoed namespace. Missing fields, an unsupported endpoint, malformed replies,
transport errors, and unavailable history are errors, never false. The Boolean
is required on the wire and has no deserialization default.

The read uses the existing decision transport and credential source; it cannot
create, activate, retire, or enumerate policy documents. PAP mutations retain
their separate administrator credential. Embedded hosts call the same native
projection; remote hosts expose it through the existing decision router.

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

The standalone daemon resolves this endpoint through the scoped router's native
API-token repository on each request, including keys issued after a replica
started. Revocation and expiry do not depend on a policy-cache refresh marker.
Storage or worker failure returns `503 credential_unavailable`; it never returns
an identity from an older snapshot. Storage and Argon2 run outside async workers
and without holding the daemon mutex. The request body is limited to 1 KiB.

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

`authorize`, `authorize_batch`, `authorize_resource` and policy snapshots reuse
the daemon's one shared-fence refresh owner before reading its local PDP. A quiet
replica's contextual decision must observe peer revocation on its first request;
an unreadable or repeatedly changing policy returns the same `503 policy_unavailable`
response rather than serving cached policy. The existing refresh retry bound is
unchanged.

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
| `POST` | `/v1/admin/orgs/privacy-erasure` | erase through the same owner and return its exact versioned participant receipt; body is the existing `OrgId` JSON value |

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

## Durable personal consent

The daemon explicitly composes `personal_delegation_router` over its shared
SQL store, OP signer and current PDP. Contract types live in
`awaken-iam-contract::personal_delegation` (re-exported from the crate root).
See [ADR-0019](../adr/0019-durable-personal-consent-and-action-bound-credentials.md)
for the credential-family fence, live checks and original-outcome rule.

| Route | Authority |
|---|---|
| POST `/v1/personal-delegations` | Direct owner consent token, exact original intent |
| GET `/v1/personal-delegations/{id}` | Same direct owner |
| POST `/v1/personal-delegations/{id}/revoke` | Same direct owner; first stamp retained |
| POST `/v1/personal-delegations/token` | Registered confidential recipient; exact finite binding |
| POST `/v1/personal-delegations/inspect` | Same admitted confidential recipient; public descriptor and current revocation |
| POST `/v1/authorize/personal-delegation` | Signed execution binding plus current native owner facts |

The native remote SDK transports the compound decision through the same
authenticated HTTP client and timeout as other PDP requests. Generic legacy
bearer verification remains unchanged; hosts must explicitly opt into this
family and fence a supported owner route. Local hosts without a live durable
consent owner fail closed.

For this personal authorization route, the remote SDK maps authoritative HTTP
401/403 rejections to an explicit Deny outcome with reason
`personal_delegation_rejected` and no matched grants. Revoked or invalid execution
authority is therefore a refusal, not a dependency outage. Connection failures,
malformed responses, unsupported endpoints and other statuses remain errors;
hosts must withhold execution on all of them. The SDK uses the preserved numeric
status, never diagnostic text, and does not cache or re-authorize a rejection.

## Out of scope

- Login/OAuth endpoints — already served; see
  [IAM model](iam-model.md#external-identity-and-sessions).
- Wire framing details (gRPC vs JSON/HTTP) — an implementation choice; the shape
  above is transport-agnostic.

### Exact organization privacy receipt

The strict privacy operation uses the same authenticated PAP and atomic
organization lifecycle as legacy DELETE. It returns the single contract
`OrgPrivacyCommitReceipt`: receipt format version, exact Org, payload-change and
new-admission flags, explicit identity confirmation, stored erasure policy version
and current observed policy version. Missing/unknown format, foreign Org or
reversed coordinates fail closed. `confirmed_organization=false` is a committed
negative admission, not proof that an unknown historical identity was erased.

Legacy `AdminMutationAck` JSON remains unchanged and exposes only the current
policy coordinate. Strict callers never fall back to it: an older server or
transport must refuse the strict request, retain recovery intent and withhold
certificate completion. The static strict path carries the original `OrgId` in
the body, preserving exact identities without raw URL-segment interpolation.
The existing transport timeout, bounded retries and authenticated TLS policy are
unchanged; a lost reply repeats the same terminal owner operation.

### Scoped policy publication

[ADR-0021](../adr/0021-scoped-profile-publication-and-original-intent-recovery.md)
defines the finite service authority. The canonical
[contracts](../../crates/awaken-iam-contract/src/profile_publication.rs) and
[`ScopedProfilePublisher`](../../crates/awaken-iam-client/src/scoped_publication.rs)
are separate from the decision-only `IamClient` interface. The HTTP client
encodes every Workspace, namespace and original key as an individual URL segment.

Under `/v1/scoped-authz/workspaces/{workspace}/profiles/{namespace}`:

| Method and suffix | Result |
| --- | --- |
| `POST /authorize` | Current remote `ResourceAuthorizationRequest` → `AuthorizationOutcome`, requiring this namespace's native Workspace pin and active head |
| `GET` | Exact scoped baseline: current profile and native publication history |
| `POST /source-groups` | Resolve at most 32 exact Flow Group references to current same-Org revision digests without returning membership |
| `POST /publications` | Persist one immutable original request and validated revision |
| `GET /publications/{key}` | Recover its original intent, effect and current head |
| `POST /publications/{key}/activate` | Activate using the original expected head, or read its terminal effect |
| `POST /publications/{key}/retire` | Retire the exact active revision named by the original intent, or read its retired or superseded effect |

`ScopedProfileConsumer` owns the explicit decision call. Product PEPs supply
their verified principal chain and owner-resolved facts; this endpoint returns
a decision, not a credential. A missing pin/head, wrong Workspace or action
namespace denies. Current active Account/exact Org membership and same-Org Group
rosters are resolved natively on each call; native Deny/approval ceilings still
apply. An unavailable source/decision port or changed policy fence returns 503.
There is no fallback to a legacy global Allow. Generic daemon decision calls
and the internal current-resource hook used by personal-delegation compound
authorization also use this admission once the namespace has a scoped pin.
A valid signed consent cannot replace current Org membership or the scoped
decision port. Offline snapshot consumers are not qualified by this contract.

`RemoteIamClient<T>` carries `ScopedProfileConsumer` when its original transport
supports it. The native remote `IamGate` delegates through that same client and
credential configuration. Open and embedded gates return an unsupported error
for scoped decisions; they do not substitute legacy policy or an offline
snapshot. Ordinary legacy decision APIs retain their existing mode behavior.

Publication baseline/receipt reads require `iam.authorization-profile.read:{namespace}` and publication writes require
`iam.authorization-profile.publish:{namespace}` at the exact Workspace, with a
deciding direct grant to the owned service principal. Its live token must also
belong to that Workspace. Broad or separate grants cannot compose this pair.
Global PAP keys are refused by this interface. Missing/invalid credentials yield
401; insufficient capabilities or foreign subjects yield 403; unknown fields or
scope violations yield 422; original-body or native-head conflicts yield 409.
Transport failures retain the same serialized request, key and expected head.
Retirement requires the separate direct `iam.authorization-profile.retire:{namespace}`
grant at the exact Workspace. An authorized service can retire a revision even
after the original publisher loses access. The original request key identifies
the immutable revision, and the native head comparison fences later revisions.
Superseded and retired receipts never reactivate their historical revision.

`POST /source-groups` requires the separate exact
`iam.authorization-profile.observe-groups:{namespace}` grant. It accepts
`{ "group_ids": [...] }` and returns the resolved Org, Workspace, namespace
and a map of Group identifiers to SHA-256 revisions. A missing or foreign
Group refuses the entire observation. A native policy change during the
observation returns unavailable. The digests are evidence for review, while
the scoped decision path continues to read current membership itself.
