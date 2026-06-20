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

## Caching and freshness

- Remote `authorize` results may be cached briefly keyed by
  `(principal, action, scope, snapshot_version)`; a `version` bump invalidates
  the cache.
- Signer sets and snapshots carry the same `version` fence, so revocation and
  grant changes propagate on the next sync.
- Caching is opt-in per call site; security-sensitive writes
  (publish, grant changes) should evaluate fresh.

## Failure semantics

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

## Out of scope

- Login/OAuth endpoints — already served; see
  [IAM model](iam-model.md#external-identity-and-sessions).
- Wire framing details (gRPC vs JSON/HTTP) — an implementation choice; the shape
  above is transport-agnostic.
