# Registered resource authorization test design

## Contract and authority

[ADR 0025](../adr/0025-strict-resource-registration-evaluation.md) defines the
opt-in registration guarantee. The existing authorization route keeps its
pre-profile compatibility. Neither freshness nor a caller-supplied Resource
scope proves registration. The registered endpoint must return Deny or
Unavailable whenever qualification is absent; registration cannot upgrade the
actual PDP decision or discharge approval.

The immutable profile explicitly owns its product resource model. Persisted
product vocabulary must contain the exact action on the exact type. Every
Resource edge to the expected Workspace must be owned by that product in a
current versioned projection, with the canonical Workspace-to-organization
mapping. Manually added edges and merged policy snapshots are insufficient.
Evaluation and observations share the complete native version-and-epoch fence.

## Decision matrix

| Case | Expected result | Evidence |
| --- | --- | --- |
| Legacy exact wildcard grant, no profile or edge | Legacy Allow; strict Deny; zero writes | Native HTTP conformance |
| No active profile, exact action, Resource rule, type, product vocabulary, or owned projection | Strict Deny, no qualification | Native conformance |
| Wrong namespace, product, type, resource, contextual identity, or Workspace | Deny; no policy write | Native conformance and client mutations |
| Manual edge or retired projection | Deny | Real SQL owner records and native HTTP |
| Complete matching registration and actual permission | Allow with matching proof and freshness | Native HTTP and canonical client |
| Workspace-read permission only, revoked grant, Deny or approval | Original Deny or RequireApproval | First current request after policy mutation |
| Profile owner removal or change, including after retirement | Conflict; same immutable history | Both SQL adapters |
| Missing legacy owner field | Byte-identical old serialized document | Profile contract regression |
| First native 503 followed by a healthy qualified PDP | Preserve first 503 with one request; only explicit new call may Allow | Native client/server request-count regression |
| Old server, missing or malformed qualification/freshness | Unavailable; no fallback to legacy route | Native client transport tests |
| Foreign profile repository supplied beside a stable native store | Deny; no foreign authority qualification | Native HTTP source-unity regression |
| Policy version or epoch changes during qualification | Unavailable; no usable proof | Deterministic real-store race |
| Source store unavailable | 503; no cached Allow | Native HTTP fault |

## Qualification levels

Pure client tests establish exact matching and fail-closed interpretation only.
SQLite tests exercise actual native SQL and HTTP. PostgreSQL uses the same
conformance over a separately supplied test database and unique table prefix;
without the explicitly required fixture its result is not a PostgreSQL claim.
A negative control must demonstrate that removing qualification or a fence
comparison makes an authored refusal assertion fail, then restore the source
and rerun the affected cases.

These tests do not establish consumer PEP coverage, human authentication,
Agent-directory visibility, definition governance, conversation privacy, or
personal selection HTTP behavior. Those consumers must separately prove that
they request this strict contract, use a verified identity and trusted resource
coordinates, check current authority on every request, and preserve original
write intents without caching registration evidence as a grant.
