# ADR-0018 - Fenced principal team access replacement

- **Status:** Proposed
- **Implementation:** done
- **Date:** 2026-10-31
- **Related:** ADR-0003, ADR-0008, ADR-0017

## Context

A consumer that owns people's access (Awaken Flow's personnel owner) changes
one principal's access as one step: suspend the principal in a Workspace,
replace its membership of the groups the consumer manages, read the rosters
back and lift the suspension unless the person leaves. Embedded hosts do this
in process. A remote consumer running on several hosts could only use the
generic admin routes, which are unsafe for it:

- `PUT /v1/admin/groups/{id}` replaces the whole group with no expected
  revision, so a read-modify-write of the member list loses concurrent edits.
  There is no `GET /v1/admin/groups/{id}` to read a roster back.
- `POST /v1/admin/grants` and `DELETE /v1/admin/grants/{id}` are
  unconditional, and each admin call commits separately, so a multi-call
  replacement exposes intermediate access and a delayed call from a
  superseded plan can re-apply old access.
- Every admin route accepts only a static administrator credential, so a
  consumer would need full administrative power.

## Decision

**P1 - One atomic command.** `POST /v1/admin/principal-access/team-replacements`
takes `TeamAccessReplacement {workspace_id, principal, managed, teams,
suspended, fence: {generation, plan_id}}`. In one policy transaction (the
existing shared policy lock and fence) it creates target groups that do not
exist under the Workspace's Org, sets the principal's membership of every
managed group to exactly `teams` (other members are untouched), keeps one
Workspace-wide deny grant for the principal exactly when `suspended`,
records the fence, appends one audit event and advances the policy version.
It returns `TeamAccessReceipt` with the managed groups that contain the
principal afterwards. Deny grants in stored policy are introduced only for
this suspension and only at a Workspace.

**P2 - Fence.** One row per (Workspace, principal) in authz migration 11.
A command applies when no row exists, when its generation is greater, or
when generation and `plan_id` both equal the row (an idempotent resume).
Otherwise it is `409 stale_access_fence` and nothing changes. The upsert
repeats the rule in SQL so the row cannot move back. The consumer owns the
generation sequence; IAM only enforces its order.

**P3 - Business profile read.** `GET
/v1/admin/principal-access/profiles/{namespace}` returns the active profile
of one namespace (404 when none) so the consumer can apply its own rules to
the bindings.

**P4 - Scoped service-account credential.** Both routes accept the
administrator credential or a service-account API token. The token is
authenticated against the durable token repository
(`authenticate_stored_api_token`, same rules as `ApiTokenDirectory`), must
belong to a `Service` principal and must have an accountable owner recorded
by `mint_service_account` (ADR-0017). Its principal then needs
`iam.principal_access.replace` at the Workspace, or `iam.authz_profile.read`
at the `Namespace` scope, through ordinary IAM grants. A product Directory
credential is refused.

**P5 - Compatibility.** The routes are mounted by a separate
`principal_access_router`, as `projection_router` is; `daemon_router`,
`PolicyStore` and every existing type keep their signatures. New items are
additive: contract types, `PrincipalAccessStore` (implemented for the
in-memory and SQL stores), `PolicyAdminApi::replace_team_access` for stores
that implement it, and the core helper. The standalone daemon mounts the
router.

## Validation

`admin_api::principal_access` tests cover the fence decision table, group
creation under the Workspace Org, validation and the in-memory store.
`tests/principal_access_http_e2e.rs` drives two daemons over one SQLite store
through C1-C5 credential admission, F1-F5 fencing, preservation of other
group members, deny propagation to the other replica, refusal of stale and
competing plans without any change, and the profile read.
