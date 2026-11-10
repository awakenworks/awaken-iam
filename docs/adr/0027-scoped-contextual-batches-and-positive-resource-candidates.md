# ADR 0027: Scoped contextual batches and positive Resource candidates

- **Status:** Proposed
- **Implementation:** in-progress
- **Date:** 2026-11-10

## Context

A product with sparse Resource permissions cannot discover the next permitted
row by evaluating a fixed prefix of all its data. Returning Resource identifiers
from IAM would require IAM to own a second product inventory. Translating policy
inside the product would create a second authorization implementation.

The existing scalar contextual PDP already owns grant precedence, delegated
principal intersection, live groups, limits and scoped profile prerequisites.
[ADR 0024](0024-authorization-freshness-is-observation-not-authority.md) makes its
freshness an observation, not permission or a time lease. These properties must
also hold when reducing candidate search or evaluating several actual rows.

## Decision

Add separate [bounded contracts](../../crates/awaken-iam-contract/src/resource_candidates.rs)
for an ordered contextual batch and a positive candidate plan. The batch holds
at most 256 complete Resource questions with one principal/delegation chain,
Workspace and namespace. Context, actual physical owner scope and request order
remain intact. All outcomes share one complete native policy-version and
revocation-epoch observation; a changed fence or unavailable dependency returns
Unavailable without a usable partial result.

The [Core planner](../../crates/awaken-iam-core/src/authorization/candidates.rs)
accepts the current native PolicySet. It shares native role eligibility and
binding-limit matching with the PDP. Allow paths are unions; every principal in
a delegation chain contributes an intersection. The closed positive tree has
All, None, OwnerIn, ResponsibleIn, GroupAny, ResourceIdsOrPredecessors, And and Or.
Every actual native Allow must satisfy the candidate tree. A candidate match
never authorizes the row or its fields.

Scope coverage and permission-bundle ownership remain native. A visible Project
does not change a Resource's physical Workspace or Project owner. Resource-id
selectors include trusted same-scope migration predecessors; separate limits
remain conjunctive even when different predecessors satisfy them. IAM does not
enumerate or persist product Resource data.

Deny and approval paths may be omitted only to broaden the positive superset.
Amount, initiator-separation and field checks are additional conjuncts after
native data-scope matching. The candidate defers these checks with an explicit
reason while retaining necessary Owner, Responsible, group and id selectors.
Dropping an extra conjunct can only broaden that Allow path; grant union and
delegation intersection still preserve every actual native Allow. For example,
Owner plus readable fields remains an Owner candidate, and the final PDP still
denies private fields. An unconstrained AuthorizedScope path may legitimately
produce All. Exceeding the finite node/value budget also yields All, never a
truncated or empty plan. Binding expiry is deferred with a reason while
retaining necessary positive owner/group/id conditions: a wall-clock rollback
can reactivate a binding without a policy change. Current native PDP evaluation
continues to enforce expiry, Deny, approval and every contextual constraint.

The [scoped HTTP owner](../../crates/awaken-iam-server/src/admin_http/scoped_decisions/resource_reads.rs)
mounts `authorize-resources` and `resource-candidates` beside the scalar scoped
route. Both require the existing exact namespace/Workspace read capability of
a live owned service credential. Administrator, global wildcard, foreign
Workspace and unowned credentials cannot substitute for it. Personal delegation
is explicitly unsupported by these new capabilities; an ordinary principal
chain is not consent. Existing personal protocols remain responsible for their
sealed credential and live consent checks.

Scalar scoped decisions, batches, candidates, inherited native ceilings and
capability admission read the same physical native policy/profile store, using
the [ADR 0025 evaluator](../../crates/awaken-iam-server/src/admin_http/registered_resource.rs).
A separately supplied legacy profile repository cannot supply scoped permission
or ceilings. Disagreement about a namespace's scoped owner is Unavailable; it
cannot become an empty policy or reopen the legacy wildcard route. Proven
same-source absence retains the existing healthy scoped Deny. Native read
failure is not absence.

Every native prerequisite mutation must publish a freshness change with its
source write. The [SQL source transaction](../../crates/awaken-iam-server/src/store/sql/admission.rs)
advances the native observation epoch in the same commit as raw Account, Group,
grant, role-binding, scope-edge/Workspace ownership and token-qualification
writes. The first durable scoped namespace pin also advances the epoch because
it changes the decision family before activation. Active profile/projection
commands which already publish a policy version retain that atomic owner.
Account-and-identity provisioning and invitation acceptance publish the same
epoch when they create an eligible Account or materialize role bindings.
Read-only probes and original publication replay do not advance an observation.
An epoch failure rolls back the source write. The
[memory adapter](../../crates/awaken-iam-server/src/store/memory/authorization_sources.rs)
holds the source and fence locks through publication and refuses exhausted
epochs before modifying data.

PAP domain-event versions retain their existing application meaning. A raw
source write may therefore change the epoch while the event version is
unchanged. The daemon compares the complete version/epoch pair when hydrating
and serving the PDP. An epoch change invalidates a remembered incremental
composition; an unrelated source write cannot be mistaken for this command's
policy delta. This source-write atomicity does not turn a historically separate
PAP event/audit commit into one transaction.

Embedded consumers use the read-only
[AuthzApi entry point](../../crates/awaken-iam-server/src/authz_api.rs) while
holding their existing current-policy lock. The remote
[SDK](../../crates/awaken-iam-client/src/http/scoped_publication.rs) checks the
common freshness and ordered result cardinality. Unsupported providers return
an explicit capability error; no legacy decision or administrator retry supplies
the missing capability.

A configured HTTP endpoint is a read-only source hint propagated through the
existing client and gate; it contains no bearer credential and is withheld for
URLs containing userinfo, query or fragment. Consumers may qualify an observed
domain with this endpoint and their configured issuer. Neither the hint nor
the native fence identifies a database incarnation. Supported HA requires one
continuous shared native PostgreSQL source. Independent databases behind the
same URL, SQLite multi-node authority, and restore/counter reuse without source
continuity are unsupported; endpoint hashing does not make them safe.

## Consequences

Products can apply native positive plans to their own indexed current Resource
relations, then run the actual current PDP for returned rows and fields. A broad
All plan remains correct and makes no sparse-performance promise. Freshness
does not extend a prior Allow across expiry, revocation or source change.

The [test design](../design/resource-candidate-authorization-testing.md)
separates pure superset proofs, actual native HTTP/SQL, transport qualification
and composing-product acceptance. These tests do not by themselves qualify a
deployment, a production migration, or a particular throughput target.
