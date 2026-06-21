# ADR-0004 - Consumers reuse the IAM authorization plane

- **Status:** Proposed
- **Implementation:** planned
- **Date:** 2026-06-22
- **Related:** ADR-0002, [consumer integration](../design/consumer-integration.md), [authorization engine](../design/authorization-engine.md)

## Context

[Consumer integration](../design/consumer-integration.md) pinned three *partial*
consumption modes: Oversight Next delegated **authentication only** (keeping its
own authorization engine), and Awaken Next delegated **entitlement gating only**.
The product direction has since changed: **both Oversight Next and Awaken Next
(managed agents) must reuse IAM's full capability** — identity, authorization,
and entitlement — rather than each carrying its own engine.

Reusing IAM surfaces three concrete decisions the earlier design left as
reserved widenings:

1. **Group/Team membership.** Consumers model **Teams** that hold roles, and a
   user who joins a team must **inherit** the team's permissions immediately
   (the Linear semantic). The current engine knows only `Principal | Role`
   subjects, and [authorization engine](../design/authorization-engine.md)
   describes membership as *static expansion into per-member grants* — which
   cannot deliver automatic, instant inheritance without re-expanding on every
   roster change.
2. **Approval.** Oversight has first-class approval gates. Today IAM returns
   `Deny` and the product infers approval from the reason code; reusing IAM
   natively means surfacing `RequireApproval` over the wire.
3. **Resource creation consistency.** When a consumer reuses the IAM authz plane,
   creating a Workspace/Project/Issue must also write scope edges and grants into
   IAM, atomically with the domain object.

## Decision

1. **Consumers reuse the authorization plane by registering a `ResourceModel`.**
   A consumer registers its resource types, action catalog, and scope parent
   edges; IAM evaluates `authorize` over them. The core stays product-agnostic
   (ADR-0002 #3): product vocabulary (`User`, `Agent`, `Team`, `issue.advance`)
   resolves down to the shared shapes (`Account`, `Service`, `Group`, open
   `ActionKey`) at the boundary, exactly as before.

2. **`Group` is a first-class authorization subject, resolved dynamically.** A
   grant or role binding may target a `Group`; at evaluation the engine resolves
   the requesting principal's group memberships from the **live roster** and
   includes any grant a covering group holds at a covering scope. This supersedes
   the static-expansion model: membership is the single source of truth, so
   joining or leaving a group changes effective permissions immediately, with no
   re-expansion. A product **Team** is composed as `Group` (roster) + a `ScopeRef`
   (container) + a group role binding (members hold a role at the team scope).
   `Group` stays the neutral kernel term; the consumer keeps "Team" at its
   surface. A `Group` is **never a principal** — no request is made "as a group".

3. **`RequireApproval` is a native, three-valued wire decision.** The contract
   `AuthorizationDecision` widens to `{ Allow, Deny, RequireApproval }`, carrying
   an **obligations envelope** (`obligation_id`, `policy_id`, and the approval
   authority required). IAM only *decides*; the product drives the approve / pause
   / resume loop. Approval is **discharged** product-side either as a product
   approval record or as a scope-narrowed, epoch-fenced **capability token** bound
   to the `obligation_id` (never by re-querying `authorize`, never by adding a
   per-instance allow grant).

4. **Resource creation keeps domain and grant consistent by deployment mode.**
   Embedded consumers write the domain row and the IAM grant/edge in **one shared
   database transaction** (IAM's prefixed tables live in the host database).
   Remote consumers use a **transactional outbox**: domain write plus an outbox
   event in one local transaction, then idempotent propagation to IAM. Eventual
   consistency is safe because authorization is fail-closed (a not-yet-synced
   grant denies, never over-permits), grant upserts are idempotent, and
   revocations ride the `version`/`epoch` fence. No 2PC or consensus is added.

5. **Migration is Strangler Fig with shadow comparison.** Oversight, which has an
   incumbent engine, runs both engines in shadow (`ShadowAuthorizer`) and compares
   to parity before cutover; managed agents integrate greenfield.

## Consequences

- The engine gains a `Group` subject and a live membership index; the contract
  gains the third `RequireApproval` variant and the obligations envelope; the
  `PolicySnapshot` carries group rosters and group role bindings under the version
  fence. These are additive; the ADR-0001 guardrails and the fail-closed posture
  are unchanged.
- [consumer integration](../design/consumer-integration.md) and
  [authorization engine](../design/authorization-engine.md) are revised by the
  implementing work: the static-expansion description becomes dynamic group
  resolution, and the binary-decision note becomes the native three-valued
  decision. (Those edits ride with their issues, not this ADR.)
- A new cross-service concern appears — resource-create consistency — addressed by
  the embedded single-transaction path and the remote outbox above.
- Tracked as issues on the roadmap: native approval, ResourceModel registration,
  the outbox, consumer snapshot evaluation, group-as-subject, and the two
  consumer cutovers (Oversight, managed agents).
