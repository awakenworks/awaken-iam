# ADR-0014 - Permission bundles and trusted resource constraints

- **Status:** Proposed
- **Implementation:** in-progress
- **Date:** 2026-10-12
- **Related:** ADR-0009, ADR-0010, ADR-0011

## Context

Consumers distribute named combinations of actions and bind them to people or
Teams in an independently selected Workspace or Project. A product Team is the
existing live Group roster. Bundle customization must retain one policy owner,
and installation must not grant permissions automatically.

The existing action/scope model remains sufficient for ordinary grants. Business
consumers additionally need to express ownership or responsible-Team limits
inside one Project, read/write field limits, expiry and amount-based approval.
Materializing a new grant for every ownership change would add a synchronization
authority and cannot represent field limits. This extends the assessment in
ADR-0009 for these additional scenarios; it does not introduce a general ABAC
language or product runtime ownership.

## Decision

1. A permission bundle is an existing Role plus inert metadata and ordinary
   grants. Its metadata, finite grant constraints and binding limits are stored
   in the existing immutable authorization-profile document. Profile validation,
   optimistic activation, persistence and audit remain the single lifecycle.
2. Constraints are closed value objects. A consumer supplies server-resolved
   owner, responsible principal, Group relationships, exact target, requested
   fields and optional monetary facts. Missing required facts deny. IAM owns no
   business object, Pack blob, Workflow or external credential.
3. The existing evaluator applies constraints before its existing effect and
   principal-chain composition. Different actions never share field or row
   authority. A request for a field is authorized on that exact target; consumers
   apply the resulting checks before query pagination, aggregation or egress.
4. A profile may reference a live Group owned by another namespace, just as it
   references a global Account. It cannot define a foreign Group roster or
   foreign Role/action grants. The consumer validates business tenant and Team
   ownership before binding; namespace boundaries still constrain action policy.
5. Time limits use the server's evaluation time. Consumer-supplied time is not
   accepted as an authorization clock at the remote boundary. Direct pure-core
   callers supply a trusted time explicitly. Expiring bindings without a clock
   do not match.
6. Pack upgrade and enterprise changes produce explicit new policy revisions.
   Neither source metadata nor Team membership alone grants an action. Services
   and Agents continue to require every link in the delegation chain.

## Enforcement and validation

The contract carries optional constraints without changing legacy JSON when
absent. Profile administration validates references, scope ownership and finite
conditions. The core evaluator is the sole effect composer. Core and server
tests cover ownership, live Groups, fields, delegation, approval, expiry,
cross-scope refusal, invalid profiles and persisted restart parity.

## Rejected alternatives

- A second writable bundle registry in each consumer: competing policy truth.
- Copies of a Role's grants on a Group: role changes leave stale permissions.
- An arbitrary expression engine: unnecessary for the closed business cases.
- Per-Role publication state machines: duplicate the existing profile lifecycle.
