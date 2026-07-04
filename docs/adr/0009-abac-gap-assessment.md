# ADR-0009 - ABAC gap assessment for consumer authorization

- **Status:** Accepted
- **Implementation:** done
- **Date:** 2026-07-04
- **Related:** ADR-0004, [authorization engine](../design/authorization-engine.md), [consumer integration](../design/consumer-integration.md)

## Context

ADR-0004 decision 1 states that "the core stays product-agnostic" and that
consumers register a `ResourceModel` to teach IAM their resource hierarchy and
action vocabulary. The authorization engine design mentions a `condition?` field
on `Grant` (described as "optional, intentionally small") and an evaluation step
that drops grants whose condition is not satisfied by the request context.

This ADR records the formal assessment of whether consumers reusing the
authorization plane — specifically Oversight, whose actor and resource model is
the richest of the current adopters — need conditions beyond the existing
primitives for their authorization decision points.

## Decision points

Oversight's authorization surface resolves to seven distinct decision types, each
mapped to the current engine primitives below.

### 1. Role-based access to resources (read, write, transition)

**Scenario:** A workspace member with the `viewer` role may `issue.read`; one
with `editor` may also `issue.advance`; neither may `issue.delete`.

**Coverage:** `RoleBinding` at `ScopeRef::Workspace` (or `ScopeRef::Project`) +
`Grant` on the role for the matching `ActionPattern`. `ScopeGraph::covers` walks
the `issue -> project -> workspace` chain, so a workspace-level grant covers
every issue in that workspace without a per-issue grant.

**Condition needed:** no.

### 2. Team-scoped access (Group/Team membership)

**Scenario:** Only members of the "backend" team may `issue.close` issues in
`project:backend-api`. Non-members are denied.

**Coverage:** `GroupRoleBinding { group: "backend", role: "closer",
scope: Project{..} }` + a grant for `issue.close` on that role. The live roster
is resolved at evaluation, so joining or leaving the team changes effective
permissions immediately with no re-expansion.

**Condition needed:** no.

### 3. Approval-gated sensitive actions

**Scenario:** `issue.delete` requires explicit approval from a project lead before
it takes effect.

**Coverage:** `Grant { effect: RequireApproval, action_pattern: "issue.delete",
scope: Project{..} }`. The engine returns `RequireApproval` with a content-
addressed `obligation_id`; the product drives the approve / pause / resume loop
product-side (ADR-0004 #3). The approval is discharged against the
`obligation_id`, never by re-querying `authorize`.

**Condition needed:** no.

### 4. Delegated authorization (agent acting on behalf of a human)

**Scenario:** An AI agent may `issue.close` only when both the agent itself and
the human it acts for each hold that permission. If either is denied, the
conjunctive evaluation denies the whole chain.

**Coverage:** The principal chain (`[agent, human]`) is evaluated conjunctively.
The agent's `Service` principal and the human's `Account` principal each need a
covering grant. This encodes "the agent inherits no more authority than the human
it acts for" without any condition.

**Condition needed:** no.

### 5. Per-instance ownership (creator can manage their own resource)

**Scenario:** The issue creator may `issue.delete` their own issue; other
workspace members may not (unless they hold a broader role).

**Coverage:** When the issue is created, the transactional write (ADR-0004 #4)
also writes a `Grant { subject: creator, action_pattern: "issue.delete",
scope: Resource(issue, <id>), effect: Allow }`. The per-instance resource scope
makes the grant exact to that one issue. No glob, no attribute comparison, no
condition — just a correctly-scoped grant written atomically with the domain
object and revoked when ownership changes.

**Condition needed:** no. The scope hierarchy (`ScopeRef::Resource`) plus the
transactional outbox express ownership as a normal (narrow) grant, not as a
condition on a broad one.

### 6. Cross-product key authorization

**Scenario:** A single API key should allow `agent.*` actions but require
approval for `oversight.*` actions.

**Coverage:** The key's principal holds an `Allow` grant for `agent.*` and a
`RequireApproval` grant for `oversight.*` (or both via role bindings at the
appropriate scope). Action-namespace separation (ADR-0008 #8) ensures the two
namespaces do not bleed into each other; no per-product configuration surface is
needed — it is a grant / role binding choice.

**Condition needed:** no.

### 7. Visibility filtering for list endpoints

**Scenario:** A list endpoint must return only the issues the calling principal
may `issue.read`, without one `authorize` call per row.

**Coverage:** `PolicySet::visible(principal, "issue.read", candidate_scopes)`
evaluates the whole candidate set in a single pass. The scope graph walk resolves
every candidate against the registered resource model in O(n × depth) time.

**Condition needed:** no.

## Conclusion: no gap

The seven decision points enumerated above cover Oversight's full authorization
surface. Every one is expressible with the existing engine primitives:

- **action + scope + group** (including the scope hierarchy and live group roster)
- **three-valued effect** (`Allow | RequireApproval | Deny`)
- **conjunctive principal chain** (agent on behalf of human)
- **resource-scoped grants** via the transactional outbox (ownership)

The `condition?` placeholder in the authorization-engine design is explicitly
**deferred**: no current consumer requires it for correctness. It would offer a
convenience (expressing ownership as a single broad grant rather than N narrow
resource-scoped grants) but would not unlock any semantics that cannot be modelled
today. The fail-closed posture and the "registered, never inferred" invariant are
both preserved without it.

The design remains open to a future bounded condition (e.g. `PrincipalIs`) if a
consumer demonstrates a scale or ergonomics need that outweighs the added
evaluation complexity. That decision requires a new ADR at the time.

## Consequences

- The `Grant` struct carries no `condition` field in v1. The evaluation pipeline
  step described in the authorization-engine design as "evaluate conditions" is
  a no-op until a future ADR acts on it; until then, every grant that matches on
  `(action_pattern, scope)` is unconditionally included.
- The decision is recorded as `crates/awaken-iam-core/tests/abac_gap.rs`: each
  scenario above is an executable integration test, so the conclusion is kept
  honest by the test suite.
- No new `condition` variants are added, keeping the engine surface minimal.
