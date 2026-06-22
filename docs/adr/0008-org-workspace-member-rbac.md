# ADR-0008 - One permission model for org/workspace members and API keys

- **Status:** Proposed
- **Implementation:** in-progress
- **Date:** 2026-06-23
- **Related:** ADR-0002, ADR-0004, [authorization engine](../design/authorization-engine.md)

## Context

Product direction is to make **API members** (service accounts and API keys)
first-class permission holders, modelled as closely as practical on the
**Anthropic Claude platform**, while keeping a **single permission model** rather
than a second, parallel role system. The shape we want to be compatible with:

- A two-level container hierarchy: **Organization → Workspace** (every org has a
  non-deletable **Default Workspace**). API keys, files, and skills are
  **workspace-scoped**; members are an org-level resource.
- **Named roles** at two levels. Org: `user`, `claude_code_user`, `developer`
  (manage API keys), `billing`, `admin`. Workspace: `workspace_user`,
  `workspace_limited_developer`, `workspace_developer`, `workspace_admin`,
  `workspace_billing`. Composition is by inheritance: an org `admin` is
  automatically `workspace_admin` everywhere, org `billing` is `workspace_billing`
  everywhere, and an ordinary member has authority in a workspace **only when
  explicitly added** to it.
- **API keys have no per-key operation scopes.** A key is bound to one workspace;
  its authority is the **workspace plus the creating member's workspace role**.
- **Service accounts** (`svac_`) are non-human principals, implicitly in the
  default workspace, explicitly addable to others; federated short-lived tokens
  are minted for them via issuer/rule mappings (Workload Identity Federation).
- **Managed-agent tool permission policies** are two-valued per tool —
  `always_allow` / `always_ask`.
- **The Admin API wire surface**: resources under `/v1/organizations/...`
  (`users`, `invites`, `workspaces`, `workspaces/{id}/members`, `api_keys`,
  `service_accounts`, `federation_issuers`, `federation_rules`); auth is an admin
  key in `x-api-key` (`sk-ant-admin...`) or a `Bearer` token with `org:admin`;
  responses are typed objects (`{"type":"api_key", "id":...}`) with cursor
  pagination (`limit`, `before_id`/`after_id`, `has_more`, `first_id`/`last_id`);
  ids are prefixed (`wrkspc_`, `svac_`, `fdis_`, `fdrl_`).

The engine already has every primitive this needs: `ScopeRef::{Org,Workspace}`
with a `Workspace → Org` parent edge, `RoleBinding`/`Grant`/`Group`, the
`ScopeGraph::covers` walk, the three-valued `RequireApproval` decision, RFC 8693
token exchange with trusted issuers, and `PrincipalRef::{Service,ApiToken}`. What
is missing is **product semantics layered on the one model**, not a second engine.
Today API tokens (permission mechanism 8) carry a flat, exact-match
`Vec<ActionKey>` scope on a **separate** path (`ApiTokenDirectory::authorize`)
that never touches `PolicySet`, so a key cannot hold a role, be workspace-scoped,
or get resource-aware or wildcarded authority. And because both **managed agents**
and **Oversight** reuse this one plane (ADR-0004), a key must be able to reach
both **without a second, per-product configuration surface** — which would
reintroduce the parallel model this ADR exists to avoid.

## Decision

1. **Org and workspace roles are the same `RoleBinding` at different scopes.**
   There is no separate org-role/workspace-role engine. An org role is a
   `RoleBinding { principal, role, scope: Org{..} }`; a workspace role is the same
   binding at `scope: Workspace{..}`. Anthropic's inheritance falls out for free:
   `PolicySet::held_roles` gates each binding through `ScopeGraph::covers`, so an
   `Org`-scoped binding is held at every workspace under that org, while a
   `Workspace`-scoped one does not reach sibling workspaces. No new propagation
   logic is written.

2. **A seeded, named role catalog maps the Anthropic role names to grant sets.**
   We ship a product-agnostic catalog of `RoleDef`s whose ids are the Anthropic
   names and whose grants encode each role's authority (e.g. `developer ⇒
   apikey.*`, `billing ⇒ billing.*`, `admin ⇒ *`). The kernel stays neutral
   (ADR-0002 #3): the names are seed data, not engine code. Deployments may extend
   the catalog with custom roles.

3. **An API key is authorized exactly like a human account.** `ApiToken` drops the
   flat `scope: Vec<ActionKey>` and gains a `workspace: WorkspaceId`. The workspace
   is the key's **credential attribution** — usage and rate-limit accounting,
   matching Anthropic's one-workspace key. Its **authority** is whatever its
   principal's `RoleBinding`s cover, evaluated through the same
   `PolicySet::evaluate` as any account — no per-key scope, no side path.
   `ApiTokenDirectory::authorize` is deleted; `authenticate` (credential check,
   liveness, revocation, expiry) stays.

4. **Minting a key binds a workspace role; it does not attach a scope.** The mint
   request names the workspace and the workspace role the key holds (defaulting,
   like Anthropic, to the creating member's role there), and creates the credential
   plus the `RoleBinding` in one step. Keys persist as workspace-scoped credentials
   independent of the creator's continued membership.

5. **Service accounts are `PrincipalRef::Service`, implicitly in the default
   workspace** and addable to others with a workspace role. Federated tokens ride
   the existing RFC 8693 token-exchange + trusted-issuer path; a federation rule's
   OAuth scope (e.g. `workspace:developer`) maps to the workspace role its minted
   token is treated as holding. No new federation engine.

6. **The Admin API is an Anthropic-compatible wire surface over the one model.**
   Member, workspace-member, API-key, service-account, and federation operations
   are expressed as `RoleBinding`/membership edits over the existing
   `grant_membership`/`revoke_membership`/`define_role` on `PolicyAdminApi`, and
   rendered at the wire to match the Context's Anthropic shape: the
   `/v1/organizations/...` paths and verbs, `x-api-key` / `Bearer org:admin` auth
   (itself an `authorize(admin, "org.admin.*", Org{..})` under the one model),
   typed envelopes, cursor pagination, id prefixes, and the decision-2 role enums.
   Two divergences are **owned, not silent**: the API-key credential is
   `oiam_<prefix>.<secret>` today (an `sk-ant-`-style rendering is a contained,
   separately-sequenced change to the minter/parser), and our `ScopeRef` is a
   superset of org/workspace — the compatible endpoints expose only those two
   levels, the deeper scopes stay on our own surface.

7. **Managed-agent tool policies reuse the three-valued decision.** `always_allow`
   ≡ an `Allow` grant; `always_ask` ≡ a `RequireApproval` grant with the
   obligations envelope (ADR-0004 #3). The MCP "default to ask" posture is a
   seed-policy choice over an MCP action namespace, not a new mechanism. Capability
   tokens (mechanism 7) stay the **delegation/attenuation** primitive for sub-agent
   fan-out: they narrow *within* this one model, they are not a parallel system.

8. **No per-product configuration: products are action namespaces.** A consumer
   distinguishes its product by the `ResourceModel` it registers — its resource
   types and an action-key namespace (`agent.*` for managed agents,
   `oversight.*`/`issue.*` for Oversight). Since every request runs the same
   `PolicySet::evaluate(principal, action, scope)`, a key reaches a product's
   action iff its principal holds a covering `Allow` grant for it — nothing binds a
   key to one product. One key therefore spans both products by holding a role
   whose grants cross both namespaces (or one bound at a covering `Org` scope), and
   is confined to one by a workspace-scoped role — a binding choice, never a second
   config. This is how Anthropic gates Claude Code through `claude_code_user`:
   reach is a role property, not a partition. Oversight's approval gates still
   resolve to `RequireApproval` per action, so one cross-product key can be `Allow`
   for `agent.*` and `RequireApproval` for some `oversight.*` actions under the
   same evaluation, with no extra wiring.

## Consequences

- `ApiToken` loses `scope: Vec<ActionKey>` and gains `workspace: WorkspaceId` — a
  **breaking change** to the API-token contract, taken to collapse mechanism 8 onto
  `PolicySet`. Authentication, argon2id hashing, prefix lookup, revocation, and
  expiry are unchanged.
- A seed role catalog (data + loader) is added; the engine is untouched.
- `admin_api` widens additively with the member/workspace/key/service-account
  framings and their Anthropic-compatible wire rendering.
- API-caller authorization becomes resource-aware and wildcarded (it now flows
  through `ActionPattern` + scope-graph), but default-deny is preserved: an unbound
  key authorizes nothing, and one key serving both products needs **no separate
  permission configuration**.
- Tracked as issues: the role-catalog seed; the `ApiToken` workspace migration and
  scope removal; folding `ApiTokenDirectory::authorize` into `PolicySet`; the
  Anthropic-compatible Admin API surface (operations + wire shape); the
  federation-rule → workspace-role mapping; a per-consumer action-namespace
  convention (`agent.*`, `oversight.*`); and — sequenced separately — an
  `sk-ant-`-style API-key credential rendering.
