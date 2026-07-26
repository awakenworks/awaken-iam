# Seeding and provisioning

This document defines **what is planted once as static seed** versus **what is
provisioned dynamically at runtime** in an `awaken-iam` deployment, and the rules
that govern the dynamic path. It complements the [IAM model](iam-model.md), the
[authorization engine](authorization-engine.md), [consumer
integration](consumer-integration.md), and [ADR-0004](../adr/0004-consumers-reuse-iam-authz.md)
(the transactional outbox).

The worked example throughout is **Oversight**, mapped onto the shared shapes per
the [consumer-integration](consumer-integration.md) tables.

## Why this exists

The authorization engine is a pure function over a loaded `PolicySnapshot`: with
no grants, every request resolves to `default_deny`. There is **no superuser
wildcard** to break this — that is a security invariant, not a gap. So a fresh
store denies *everyone*, including the operator who must create the first grant.
Creating a grant is itself an action (`authz.grant.manage`) that needs a grant to
authorize it — a cycle only an **out-of-band seed** can break.

But seed must stay *minimal*. Anything tied to a specific user or a specific
resource instance must not be seeded: those subjects do not exist yet at seed
time, seeding them does not scale, and it erases the audit fact of *why* the
binding exists (who invited whom, which resource was created). Those are
**provisioned dynamically** at the moment the user or resource comes into being.

## The boundary: three things, not one

"Permissions" is routinely conflated into one bucket. It is three, with different
lifecycles:

| Concern | Materializes as | Lifecycle |
|---|---|---|
| **Role catalog** — what `role_owner` *means* (its action patterns) | `RoleId` + grant templates | **Static / seed.** Policy constitution; changes are deliberate edits. |
| **Scope skeleton + resource model** — the tree nodes/edges and product resource types | `scope_graph`, `ResourceModelRegistration` | **Static / seed** for the platform + bootstrap tenant; **dynamic** for per-instance edges (below). |
| **Bootstrap root** — the very first authority | one direct `Grant` | **Static / seed.** The trust root; cannot be produced by the system. |
| **Role bindings** — *who* holds *which role* *where* | `RoleBindingSnapshot` | **Dynamic.** Provisioned at first login / invite acceptance. |
| **Resource ownership** — who owns `issue:42` | `Grant` on a `Resource` scope | **Dynamic.** Provisioned at resource creation via the outbox. |
| **Group rosters** — who is in `team_web` | `GroupRosterSnapshot` | **Dynamic.** Membership writes; evaluated live. |

The engine *evaluation* is always dynamic (live roster resolution + the
version/epoch snapshot fence). "Needs seed" applies only to the **role catalog**,
the **bootstrap root**, and the **platform/bootstrap-tenant skeleton** — never to
a real user's binding or a runtime resource's grant.

## What the seed contains

The minimal bootstrap set, in dependency order. Tables show the `awaken-iam` type
each row materializes into; values use the Oversight example tenant
(`Org acme → Workspace ws_eng → Project proj_web`, owner `ada`).

### ① Scope skeleton — nodes + parent edges (`scope_graph`)

| node | `ScopeRef` | parent edge |
|---|---|---|
| org acme | `Org{ org_id: "acme" }` | (root) |
| ws_eng | `Workspace{ workspace_id: "ws_eng" }` | `workspace→org`: ws_eng → acme |
| proj_web | `Project{ workspace_id: "ws_eng", project_id: "proj_web" }` | implied by `workspace_id` |

Only the **bootstrap tenant's** skeleton is seeded. Further orgs/workspaces/
projects are created at runtime through the same provisioning path as their
owning event.

### ② Resource model — teach IAM the product's resources (`ResourceModelRegistration`)

`ResourceTypeRegistration{ resource_type, parent_type, actions }`:

| resource_type | parent_type | actions |
|---|---|---|
| `issue` | `project` | `issue.create` `issue.read` `issue.write` `issue.comment` `issue.assign` `issue.advance` `issue.transition` |
| `run` | `issue` | `run.start` `run.cancel` `run.pause` `run.resume` `run.decide` |
| `thread` | `run` | `thread.read` `thread.post` |
| `team` | `workspace` | `team.read` `team.manage` |

`parent_type` is the *shape* (`run → issue → project → workspace`). A specific
instance edge (`issue:42 → proj_web`) is written **at resource-create time**, not
seeded.

### ③ Role catalog — roles are data (`RoleId` + action patterns)

| role_id | action patterns |
|---|---|
| `role_owner` | `project.*` `issue.*` `run.*` `thread.*` `team.*` `agent.*` `tool.*` `workspace.configure` `authz.grant.manage` `authz.role.write` |
| `role_admin` | `project.*` `issue.*` `run.*` `team.manage` `agent.*` `tool.use` `workspace.configure` |
| `role_member` | `project.read` `issue.create` `issue.read` `issue.write` `issue.comment` `issue.advance` `run.start` `run.cancel` `thread.post` `tool.use` |
| `role_viewer` | `project.read` `issue.read` `run.read` `thread.read` |

No `*` superuser pattern; a role is only effective inside the scope subtree it is
*bound* at.

### ④ Bootstrap root — the one out-of-band grant (`Grant`)

| id | subject | action_pattern | scope | effect |
|---|---|---|---|---|
| `g_boot` | `Principal(Account "ada")` | `authz.grant.manage` | `Org{ acme }` | Allow |

`g_boot` is the trust root: it cannot be produced by the authorization system, so
it is planted out-of-band. It lets `ada` issue every subsequent binding. (A
first-login-becomes-owner default policy is the dynamic equivalent for tenants
stood up after bootstrap — see provisioning rules.)

### ⑤ Platform entitlement — Org-level plan (`EntitlementCatalog`)

| plan_id | tier | features | subscription |
|---|---|---|---|
| `plan_pro` | Pro | `model.strong_access` `run.parallel` `seats:50` | `Org{ acme }` → `plan_pro` |

Default-allow; orthogonal to authorization.

**Not seeded:** per-user role bindings, resource-instance grants/edges, and group
rosters. Those are provisioned dynamically (next section).

## Provisioning rules — the dynamic layer

Each rule maps a runtime **event** to the exact writes it produces. Every write
goes through the single write pipeline, is tagged with a `GrantSource`, and is
auditable; a failed write fails closed (no grant ⇒ deny, never a silent
elevation).

| Event | Writes | Source | Notes |
|---|---|---|---|
| **First login / invite accepted** | `RoleBindingSnapshot{ principal, role_id, scope }` (e.g. `bob → role_member @ Workspace{ws_eng}`) | `Invite` / `Membership` | Materializes a *declared intent*; see below. Mirrors Oversight's `WorkspaceMember` row. |
| **First login into a fresh org (default policy)** | `RoleBindingSnapshot{ first_account → role_owner @ Org{...} }` | `System` | The dynamic equivalent of `g_boot` for non-bootstrap tenants. |
| **Create Project/Issue/Run** | `ResourceProvision{ idempotency_key, epoch, grants:[creator owner @ Resource], scope_edges:[child → parent] }` | (creator) | Via the transactional outbox (ADR-0004 #4); idempotent on `idempotency_key`. |
| **Join / leave a Team** | add/remove a row in `GroupRosterSnapshot` | `Membership` | Evaluated live; permission gained/lost immediately, no re-expansion. |
| **Grant/revoke a role to a team** | `GroupRoleBindingSnapshot{ group_id, role_id, scope }` | `Manual` | The team's roster inherits it at evaluation. |

Two events, two different assignments:

- **First login → tenant membership** (a `RoleBindingSnapshot` at an Org/Workspace
  scope): *you belong to this tenant with role X*.
- **Resource creation → instance ownership** (a `Grant` at a `Resource` scope, via
  the outbox): *you made this, you own this*.

### Dynamic assignment materializes intent — it never invents authority

"First login assigns a role" must not conjure authority from nothing; that would
violate default-deny and the no-silent-elevation rule. The role to assign comes
from a **pre-declared source**:

- **Invite** (explicit): the user was invited with `role_member`; first login
  materializes that intent into a binding.
- **Domain / SSO mapping** (claims): an IdP group claim maps to a role. Per the
  IAM model, external claims may **seed an audited binding** but never replace a
  `Grant` or bypass the engine.
- **Default policy** (cold start): the first principal in a fresh org becomes
  owner — the dynamic form of `g_boot`.

In every case the assignment (1) goes through the single write pipeline, (2)
carries an auditable `GrantSource`, and (3) fails closed if it does not commit.

## Tenant membership decision table

The organization directory, role bindings, policy snapshot, and PDP are one
causal chain.  A successful administration response is not complete until the
same committed rows are visible to the evaluator behind the returned snapshot
version.  A product must never maintain a second organization/member registry.

```text
admin mutation
  -> authoritative IAM repository write + audit + version fence
  -> rebuild/evolve the PDP from that repository state
  -> return the exact visible version
  -> product PEP authorizes the trusted tenant scope
```

| Authenticated | live org binding | requested org | operator list grant | Result |
|---|---|---|---|---|
| no | any | any | any | `401`; read and mutation are not attempted |
| yes | none | any | no | `403`; no product resource is created |
| yes | org A | org A | no | evaluate the requested action at `Org A` |
| yes | org A | org B | no | `403`/not-found without revealing whether B exists |
| yes | any | all orgs | no | `403`; tenant users cannot enumerate organizations |
| yes | any | all orgs | yes | return the operator view and append an audit event |

The corresponding fault cases are fail-closed: a repository, audit, fence, or
PDP refresh failure returns an error and must not report a version that the PDP
cannot evaluate.  Restart hydration reads the same repository; an independent
in-memory PAP store is forbidden because it makes a successful membership write
invisible to authorization and loses it on restart.

## Invariants

- **Default-deny, no superuser.** An empty store denies everyone; seed is the
  only break, and it is the minimal trust root + catalog + skeleton.
- **Seed is policy, not population.** Role catalog, bootstrap root, and the
  bootstrap tenant's skeleton — never real users or runtime resources.
- **Provisioning materializes a declared intent**, audited via `GrantSource`,
  through the single write pipeline; it never elevates silently.
- **Evaluation stays dynamic**: live group rosters and the version/epoch snapshot
  fence; a binding or roster change is visible on the next read.
- **Eventual consistency is safe** because authorization fails closed: until a
  resource-create outbox payload lands, the new resource matches no grant and is
  denied — it never over-permits.

## Load order

```
① scope skeleton → ② resource model → ③ role catalog
   → ④ g_boot (bootstrap root) → ⑤ platform plan
   ── seed ends; everything below is runtime provisioning ──
   → first login / invite       ⇒ role bindings
   → resource creation (outbox) ⇒ resource grants + scope edges
   → membership                 ⇒ group rosters
```

Seed gives `ada` ownership the instant she logs in; the engine then grows every
remaining binding and resource grant by the provisioning rules, while Issue/Run
facts arrive continuously through the outbox.
