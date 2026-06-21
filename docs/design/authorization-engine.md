# Authorization engine

This document specifies how `awaken-iam-core` turns an
[`AuthorizationRequest`](iam-model.md#authorization-vs-entitlement) into a
decision. It makes the model in [IAM model](iam-model.md) buildable and replaces
the placeholder `IamCore::authorize() -> Deny` stub.

## Position

```text
Principal + Action + Scope --> [engine] --> Decision (+ trace)
```

The engine is pure evaluation over a loaded snapshot. It performs no I/O: a
store loads roles, grants, and memberships into an in-memory `AuthzSnapshot`;
the engine answers from that snapshot. Persistence and transport live in the
server and client crates.

## Data model

Records the store owns (shapes, not columns):

```text
Role {
  id,                # stable role id, e.g. role:namespace_owner
  scope_kind,        # the ScopeRef kind this role binds at
  grants: [GrantTemplate],  # action patterns this role expands to
}

GrantTemplate {
  action_pattern,    # exact ("pack.publish") or suffix glob ("project.*")
  effect,            # allow | require_approval; deny is a future widening
}

Grant {
  id,
  subject,           # PrincipalRef | RoleBinding { role_id, principal }
  action_pattern,
  scope,             # the ScopeRef the grant is anchored at
  effect,            # allow | require_approval
  condition?,        # optional, intentionally small (see below)
}

Membership {
  principal,         # Account / Service / ApiToken
  scope,             # Org / Namespace / Workspace / Project
  role_id,
}
```

`Membership` is sugar: it expands into `Grant`s by binding `role_id`'s templates
to the member principal at the membership scope. Keeping it explicit lets the
store index "who is a member of X" without scanning all grants (a query any
membership-based model needs).

## Snapshot

```text
AuthzSnapshot {
  version,                 # monotonic fence; bump on any write
  roles:      Map<RoleId, Role>,
  grants:     [Grant],     # indexed by (scope, action head)
  memberships:[Membership],
  scope_index: ScopeGraph, # parent edges for ancestor walk
}
```

Consumers that evaluate locally cache the snapshot and re-load when `version`
changes (the fence). Consumers that call the remote API never see the snapshot;
they receive only the decision. Both paths run the identical evaluation code.

## Evaluation pipeline

`authorize(request) -> Decision`:

1. **Resolve the principal chain.** A request carries a principal *chain* (length
   one for a direct caller, longer for delegated/on-behalf-of dispatch such as
   `[human, agent]`). Every link is resolved and authorized; the result is the
   conjunction — all must pass. An unresolved or empty principal is an immediate
   `Deny` (reason `principal_unresolved`). No principal ever means allow.
2. **Expand the scope chain.** Walk `request.scope` to its root through the
   scope graph, e.g. `issue:42 -> project:web -> workspace:ws -> org:acme ->
   global`. Scopes are open — a well-known scope or an open `Resource {
   resource_type, resource_id }` whose parent edges come from the registered
   `ResourceModel` — so arbitrarily deep product hierarchies resolve through this
   same walk. A grant anchored at any ancestor applies to descendants.
3. **Collect candidate grants.** From the snapshot, take grants whose `scope` is
   on the chain and whose `action_pattern` matches `request.action`
   (exact, then suffix glob). Include grants reached via the principal's
   memberships (role-template expansion).
4. **Evaluate conditions.** Drop grants whose optional `condition` is not
   satisfied by the request context.
5. **Apply precedence and decide.** See below.

### Action matching

Patterns are exact (`pack.publish`) or a single trailing `*` segment glob
(`project.*` matches `project.read`, `project.configure`). No internal globs, no
regex, no `**`. There is no implicit superuser wildcard: a role that should do
everything in its scope lists its action patterns explicitly. This mirrors the
"no `ALL_ACTIONS`" rule that keeps a blanket bypass out of the model.

### Precedence

```text
deny  >  require_approval  >  allow  >  (no matching grant) = default deny
```

The decision is **three-valued** — `Allow | Deny | RequireApproval`. A grant's
effect is `allow` or `require_approval`; an explicit `deny` grant is a future
widening that the lattice already admits. `RequireApproval` is a real decision:
the caller executes the approval (prompt, pause, resume); IAM only decides it. A
more-specific scope does **not** override a less-specific one; effect precedence
is the only tie-breaker, which keeps evaluation order-independent.

## Decision trace

Every decision carries an explanation for audit/debug surfaces:

```text
Decision {
  outcome,           # allow | deny | require_approval
  reason_code,       # granted | needs_approval | no_grant | principal_unresolved | condition_failed
  matched_grant_id?, # the grant that decided it
  matched_role_id?,
  scope_anchor?,     # which scope on the chain the grant was anchored at
  obligation?,       # present iff outcome = require_approval (see below)
}
```

The trace never includes secrets. It is safe to return over the wire and to log.

### Approval obligation

A `require_approval` outcome carries an **obligation envelope** — the single
hand-off seam between IAM's decision and the caller's approval execution
([ADR-0004](../adr/0004-consumers-reuse-iam-authz.md) #3):

```text
Obligation {
  obligation_id,     # content hash of (principal chain, action, scope, policy_id)
  policy_id,         # the require-approval grant that imposed it
  authority { scope }# scope the approval is anchored at (approved at or above)
}
```

`obligation_id` is content-addressed, so re-querying authorize for the same
question yields the same id and an approval discharged against it is idempotent
— identical whether computed by the server or by a consumer over a synced
snapshot. The approval is discharged **product-side** (a recorded approval keyed
by `obligation_id`) or as a **capability token bound to `obligation_id`**; it is
never discharged by re-querying authorize and never by minting a per-instance
grant, so the decision stays a pure function of policy.

## Core API additions

```rust
impl IamCore {
    fn authorize(&self, request: &AuthorizationRequest) -> Decision;
    fn visible(&self, principal: &PrincipalRef, action: &ActionKey,
               candidates: &[ScopeRef]) -> Vec<ScopeRef>; // list filtering
}
```

`visible` answers "which of these scopes can this principal do `action` on" in a
single pass, so list endpoints do not issue one `authorize` call per row.

## Out of scope

- Product workflow/stage roles (a product's own lifecycle roles) — these stay in
  the product service; IAM roles are grant bundles only.
- Entitlement/plan checks — a separate plane, see
  [entitlement plane](entitlements.md).
- Transport and storage — see [remote protocol](remote-protocol.md).
