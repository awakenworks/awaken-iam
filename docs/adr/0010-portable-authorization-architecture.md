# ADR-0010 - Portable authorization control plane and resource-service integration

- **Status:** Accepted
- **Implementation:** done
- **Date:** 2026-07-20
- **Related:** ADR-0002, ADR-0004, ADR-0008, ADR-0009,
  [consumer integration](../design/consumer-integration.md)

## Context

Awaken runs the same products in three deployment shapes:

1. a local, single-machine installation;
2. a cloud installation with a shared IAM service; and
3. a local product whose human signs in through Awaken Cloud and then uses the
   local runtime ("cloud login, local use").

Consumers currently have useful but inconsistent pieces of this design. Some
embed the IAM engine, some call a remote decision API, and some keep a second
product policy registry. Several resource adapters also use a process-wide
workspace constant. That is unsafe in a multi-tenant host: possession of a
resource id can become sufficient to address data in another workspace, and an
in-memory owner index cannot protect objects created before the process started.

The design must keep resource services simple. Memory, Skill, File, Artifact,
Agent, Worker, Run, and similar services should own resource data and lifecycle,
not identity protocols or policy evaluation. At the same time, authorization
must be reusable across repositories and deployable either in-process or as a
cloud service without changing its meaning.

## Decision

### 1. Use the industry authorization roles, but name code by intent

The architecture uses the XACML/NIST role names in documentation and integration
contracts:

- **PAP (Policy Administration Point)** owns policy, role, membership, resource
  model, and policy-snapshot administration.
- **PDP (Policy Decision Point)** evaluates a normalized authorization request
  and returns `Allow`, `Deny`, or `RequireApproval` plus obligations.
- **PIP (Policy Information Point)** supplies trusted facts needed by a decision,
  such as resource ownership, parent edges, lifecycle state, and entitlements.
- **PEP (Policy Enforcement Point)** authenticates at a trust boundary, resolves
  the target resource and action, asks the PDP, enforces the result, and emits an
  audit record.

These are architectural roles, not four mandatory network services. Code uses
intent-revealing names:

| Architecture role | Shared IAM name | Consumer name |
|---|---|---|
| PAP | `PolicyAdminApi` / `PolicyRepository` | `PolicyPublisher` |
| PDP | `AuthorizationService` / `IamClient` | `AuthorizationPort` |
| PIP | `ResourceFacts` / `ResourceResolver` port | product resource repository |
| PEP | reusable middleware helpers only | `<Plane>AuthorizationGuard` |

`Pep`, `Pip`, `Pap`, or `Pdp` alone are not used as domain type names. They hide
intent and encourage a framework-shaped domain model.

PAP and PDP are inside the **authorization bounded context** owned by
`awaken-iam`. A PIP is a port of that context whose data normally remains owned
by another bounded context. A PEP belongs to the application boundary it
protects. Authentication is adjacent to, but distinct from, authorization.

### 2. Keep policy orthogonal to resource services

The static dependency direction is:

```text
                         authorization bounded context (awaken-iam)
                    +-----------------------------------------------+
                    | PolicyAdminApi (PAP)   AuthorizationService   |
                    | PolicyRepository       (PDP)                  |
                    |        |                  ^                   |
                    |        v                  | ResourceFacts port|
                    | policy/snapshot ----------+ (PIP contract)    |
                    +-------------------^---------------------------+
                                        |
                          shared contract + client/host adapters
                                        |
          +-----------------------------+-----------------------------+
          |                             |                             |
   +------v-------+              +------v-------+              +------v-------+
   | Flow API PEP |              | Runtime PEP  |              | Cloud API PEP|
   +------+-------+              +------+-------+              +------+-------+
          |                             |                             |
   +------v-------+              +------v-------+              +------v-------+
   | Flow domain  |              | resources    |              | org/resource |
   | repositories |              | repositories |              | repositories |
   +--------------+              +--------------+              +--------------+
       PIP facts                      PIP facts                      PIP facts
```

Resource domain crates do not depend on IAM DTOs. They expose product-language
facts through a port or application adapter. Only composition-root and adapter
crates depend on `awaken-iam-contract`, `awaken-iam-client`, or
`awaken-iam-host`. This is the anti-corruption layer.

The PEP order is fixed:

```text
request
  -> authenticate credential
  -> resolve actor and trusted tenant context
  -> load target resource / owner / parent facts
  -> map product operation to an ActionKey
  -> authorize(actor, action, target scope, context)
  -> enforce Allow | Deny | RequireApproval
  -> execute domain operation
  -> append audit/outbox event
```

For a mutation that creates or changes an ownership edge, the domain write and
the authorization projection/outbox record commit atomically. The IAM projection
is idempotent and replayable. A missing, stale, malformed, or unknown owner edge
is a denial, never an implicit global or default-workspace grant.

### 3. One logical decision model, three deployment modes

Consumers select one mode at the composition root. Domain and handler code is
unchanged:

```text
Embedded local
  Product PEP -> in-process AuthorizationService -> local policy store

Remote cloud
  Product PEP -> RemoteIamClient -> awaken-iam service -> durable policy store

Cloud login, local use
  Browser/CLI -> cloud OAuth/OIDC + PKCE -> user access/refresh credential
  Product PEP -> local JWT verification
              -> local PDP using signed cloud policy snapshot
              -> local resource facts owned by the product
```

The hybrid mode is not an independent permission system. Cloud is authoritative
for human identity, org/team/workspace membership, shared roles, revocation
epochs, and signed policy snapshots. The local product remains authoritative for
product resources and their parent/owner facts. Snapshot import is monotonic,
signature-checked, issuer/audience-bound, and fail-closed after its allowed
staleness window. Security-sensitive revocation may require online introspection
or a short credential/snapshot lifetime.

An explicit unauthenticated mode may exist only in tests or a clearly labelled
single-user developer build. It is never the production default and cannot be
selected accidentally by omitting configuration.

### 4. API keys and login credentials are not permissions

An API key, session cookie, OAuth access token, workload token, and service token
are credentials. Authentication proves a `PrincipalRef` and credential context;
authorization separately evaluates the principal's bindings and grants at the
resolved scope.

An API key is workspace-attributed for accounting and revocation but obtains no
authority merely from that attribute. Service tokens used for product-to-IAM
calls authenticate the product service; they must not silently replace the end
user. Acting for a user is represented explicitly by the principal chain or
token exchange, and both service and user authority are evaluated when required.

Credentials are stored in an OS-protected credential store or a `0600` cache,
redacted from logs, audience restricted, short lived where practical, and never
put in resource records or policy snapshots.

### 5. Scope is an opaque coordinate resolved from trusted facts

`Org`, `Workspace`, and product-specific resource ids are coordinates, not
authorization decisions. A product may expose friendly path types, but the
authorization request carries a canonical `ScopeRef` and a namespaced resource
type. Product-specific hierarchy is registered through `ResourceModel` and
instance parent edges.

No Runtime Host, server, repository adapter, or background worker may use a
compiled-in `HOST_*_WORKSPACE`, `"default"`, or similar value for persisted
multi-tenant resources. Scope is obtained from one of these trusted sources:

1. an authenticated, edge-resolved workspace path;
2. a resource owner/parent record read by id;
3. a claimed work item whose durable row contains its scope; or
4. an explicitly configured local workspace id created by the platform during
   single-user bootstrap (configuration, not a library constant).

Client-supplied `workspace_id` is only a selector. The PEP verifies it against
the credential and/or resource owner. An id-addressed read, update, or delete
must resolve ownership before returning the object; cross-tenant and unknown
ownership responses do not disclose existence.

### 6. Resource services publish facts; IAM administers and decides

All persisted resources are platform-managed and follow the same minimum
contract:

```text
ResourceRef {
  resource_type, resource_id, owner_scope, parent_scope,
  lifecycle_state, policy_version
}
```

The record may live in the product database; it need not be copied wholesale to
IAM. IAM stores policy-relevant projections and versions. Products publish their
action vocabulary and resource model; cloud composition must not invent a second
copy of a product action catalog.

Adaptation rules:

| Resource family | Authoritative facts | Typical actions / special rule |
|---|---|---|
| Worker / Work item | Flow/runtime queue row: org, workspace, project, lease owner | `worker.claim`, `work.read`, `work.execute`, `work.ack`; authorize both claim and completion, fence by lease generation |
| Memory store / Memory | durable store definition and content/version rows | `memory.create/read/write/delete/redact`; persist version history and owner scope, never accept an id without owner resolution |
| File | file metadata row; blob store only owns bytes | `file.create/read/delete`; content hash is not tenant identity, so the metadata owner is mandatory even for deduplicated blobs |
| Artifact | producing run/work item plus artifact metadata | `artifact.create/read/delete`; inherit scope from the producing run and record it immutably |
| Agent | agent registry/version row | `agent.create/read/update/publish/run`; a run also requires use of referenced Skills/Files/Memory |
| Skill / Skill version | durable catalog identity and immutable version rows | `skill.create/read/update/delete/use`; persist rich object and version history, not only current `SKILL.md` |
| Run / Session | durable run/session row and actor chain | `run.create/read/cancel`; every child resource inherits the run scope but is still checked at access time |

Composite operations authorize every independently protected resource. For
example, running an Agent does not imply permission to read every referenced
Memory or File. Bulk/list APIs use a visibility query or scope-constrained
repository query; they do not load all tenants and filter after serialization.

#### Scope applicability is one versioned PAP configuration

Whether an action targets an organization, workspace, project, or leaf resource
is policy data, not a convention repeated in handlers. The PAP owns one signed,
versioned authorization profile per consumer namespace:

```text
AuthorizationProfile {
  namespace, version, lifecycle,
  resource_types: [{ type, parent_type, allowed_parent_scope_kinds }],
  actions: [{ action, target_resource_type, allowed_scope_kinds }],
  role_grants, inheritance_rules
}
```

For example, `project.read` targets `Project`, while `file.read` targets a
`Resource(file, id)` whose registered parent may be a Project or Workspace. The
PEP submits the concrete target coordinate; the PDP validates that its kind is
allowed by the active profile before evaluating grants. A resource service does
not decide that a Project operation is "close enough" to Workspace scope.

Profiles are administered through the PAP as immutable revisions with
`draft -> validated -> active -> retired` lifecycle. Activation atomically
replaces the namespace's previous active revision; rollback reactivates a known
revision. Local/embedded mode loads the exact same profile document or a signed
snapshot. Remote mode reads the active revision from awaken-iam. Environment
variables may select a profile or endpoint, but may not redefine individual
action/scope rules. The existing `ResourceModelRegistration` and monotonic
`policy_version` are the transport/evaluation foundation; the PAP must expose
whole-profile validate, activate, fetch, and rollback operations rather than
requiring consumers to perform a series of additive mutations.

The implemented wire surface is:

```text
POST /v1/admin/authz/profiles
POST /v1/admin/authz/profiles/{namespace}/{revision}/validate
POST /v1/admin/authz/profiles/{namespace}/{revision}/activate
POST /v1/admin/authz/profiles/{namespace}/{revision}/rollback
GET  /v1/admin/authz/profiles/{namespace}
GET  /v1/admin/authz/profiles/{namespace}/{revision}
GET  /v1/admin/authz/profiles/{namespace}/active
```

Profile documents include the resource model, exact action/scope rules, grants,
role bindings, group rosters, and group role bindings. Revisions are immutable
and checksummed. The durable store keeps documents separately from one
`authorization_profile_heads` row per namespace. Activation and rollback use a
single compare-and-set of that head, so optimistic concurrency is atomic on
SQLite and Postgres. At startup the daemon hydrates all active namespace heads
before binding its socket. `PolicySnapshot.active_profiles` carries the same
documents to an embedded/local evaluator.

Profile activation and rollback always compose the selected immutable profile
revisions over the current repository-backed PAP snapshot in one live-PDP
replacement. They never replace organization grants, role bindings, resource
ancestry, or other base policy. The same composition applies during restart
hydration, so a profile mutation cannot make a persisted tenant or operator
grant disappear until the next PAP write or process restart.

An active profile's scope-kind rules govern only actions in that profile's
exact `<namespace>::` action namespace. Activating an Awaken Runtime profile,
for example, cannot make Cloud Console or Flow PAP actions invalid merely
because those unrelated actions are intentionally absent from the Runtime
document.

The migration proceeds through four observable phases:

1. **A — shadow:** construct and validate a revision while the prior policy
   continues serving decisions; compare decisions with the shared shadow
   authorizer.
2. **B — review:** retain divergence evidence and refuse activation until the
   resource/action/scope validation report is clean.
3. **C — enforce:** atomically activate the validated revision; the PDP rejects
   `scope_kind_not_allowed` before matching any grant.
4. **D — retire legacy:** consumers remove their public `DEFAULT_SCOPE` and
   additive policy mutation paths after embedded/remote conformance passes.

### 7. Reuse contracts and conformance suites, not a cross-repository framework

Cross-repository reuse is split into small packages:

- `awaken-iam-contract`: stable request, decision, scope, principal, snapshot,
  and resource-model DTOs;
- `awaken-iam-core`: authorization semantics, usable in-process;
- `awaken-iam-client`: remote PAP/PDP transports and credential cache;
- `awaken-iam-host`: deployment assembly, JWT verification, and middleware
  building blocks;
- consumer-owned adapters: action mapping, resource resolution, response
  shaping, and transaction/outbox integration.

Every transport and host mode must pass the same authorization conformance suite.
Every resource adapter must pass an ownership suite covering same-tenant access,
cross-tenant id guessing, unknown/legacy owner, list isolation, parent moves,
archive/delete, and restart/rebuild. Repository pins are immutable tags or commit
ids; a release is upgraded deliberately, never through a machine-local path.

### 8. Security invariants

The following are release gates:

1. default deny on missing authentication, policy, resource model, ownership,
   issuer, audience, or decision-service availability;
2. one authoritative PDP per request and one token-signing trust root per
   deployment mode;
3. no process-local owner map as the sole access-control source;
4. no fixed tenant in reusable runtime or storage components;
5. no resource data or credentials owned by IAM;
6. no product policy engine in cloud or product services beside the shared IAM
   implementation;
7. audit records contain actor, action, canonical scope/resource, decision,
   policy version, request id, and reason, but no secret;
8. caches and offline snapshots have bounded staleness, monotonic versions, key
   rotation, rollback protection, and tested denial behavior.

This architecture reduces duplicated security logic; it does not by itself
"guarantee security". Assurance comes from threat modelling, least-privilege
defaults, conformance and adversarial tests, dependency/key hygiene, audit
review, and operational controls.

## Consequences

- `awaken-iam` is the one authorization control plane for both embedded and
  hosted deployments. Awaken Cloud may operate it, but does not fork its policy
  or decision semantics.
- Consumers keep thin PEP adapters and their own resource repositories/PIP facts.
- Existing fixed-workspace host APIs, in-memory-only owner/version registries,
  duplicate product policy registries, and remote modes with a local signer are
  migration blockers. They must fail closed or remain explicitly non-production
  until replaced.
- Existing flat URLs may remain compatibility aliases only when middleware first
  resolves a trusted scope. New multi-tenant APIs use explicit scoped paths or
  owner-resolving resource ids.
- The simple design is one authorization request algebra, one policy model, and
  three interchangeable adapters. DDD boundaries remain intact because identity
  and policy live in IAM while product data and vocabulary live with each product.
