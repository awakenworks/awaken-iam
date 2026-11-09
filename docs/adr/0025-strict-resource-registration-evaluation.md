# ADR 0025: Qualify registered resource operations within the live PDP fence

- **Status:** Proposed
- **Implementation:** done

The implementation boundaries are the [registered resource protocol](../../crates/awaken-iam-contract/src/registered_resource.rs), [native evaluation](../../crates/awaken-iam-server/src/admin_http/registered_resource.rs), and [client enforcement](../../crates/awaken-iam-client/src/registered_resource.rs).

## Context

The legacy evaluator intentionally permits pre-profile deployments. An existing
wildcard grant can therefore allow an action when its namespace has no active
profile. A current authorization freshness observation proves a stable native
policy observation; it does not prove action or resource registration.

Product operations that require explicitly registered actions need a stronger,
opt-in contract. A consumer-side catalog check followed by authorization leaves
a race and makes the consumer a second authority.

## Decision

Add a separate registered-resource evaluation protocol. Preserve the existing
resource authorization request, route, and legacy behavior. A strict request
carries the existing authorization question and its expected namespace, product,
workspace, and resource type. These expectations only restrict a decision; they
are not credentials, grants, or registrations.

The immutable profile document explicitly declares `resource_product`. An absent
field preserves the exact legacy serialized document and checksum. Once any
revision declares a product, all retained namespace history prevents later
removal or reassignment, including after retirement. Adoption requires an
explicit new revision. The native daemon checks all expectations and evaluates the actual request
inside one complete policy-version and revocation-epoch fence. The strict
endpoint reads profiles and builds the current PDP from that same physical
policy store; a separately supplied legacy profile repository or policy cache
cannot establish this guarantee. Qualification
requires an active immutable profile, an exact action declaration and Resource
scope-kind rule, the declared resource type, and an active product-owned resource
projection rooted in the expected workspace. A retired, missing, mismatched, or
unavailable dependency cannot produce a qualified Allow. No role, grant,
profile, resource edge, or projection is created by evaluation.

The response binds registration evidence to the exact action and resource,
profile revision and checksum, product and workspace. The ordinary three-valued
PDP decision remains authoritative: registration never upgrades Deny or
RequireApproval. A strict consumer accepts Allow only with matching complete
registration evidence and a valid current native freshness observation. An old
server, unsupported provider, malformed response, missing evidence, or changed
fence fails closed. Each strict evaluation makes one HTTP attempt; a failure
cannot be hidden by an automatic second decision. A healthy retry requires an
explicit new caller request. Registration evidence is an observation, never a lease.

## Consequences

Strict products explicitly publish their vocabulary and project native
resources before admitting their operations. Legacy callers retain their
existing contract. IAM remains the sole owner of registration and authorization;
product runtime definitions and preferences remain outside IAM. Tests separate
wire qualification, policy evaluation, SQL transaction behavior, native HTTP,
and consumer enforcement.
