# ADR-0011 - Isolate authorization profile action namespaces

- **Status:** Proposed
- **Implementation:** done
- **Date:** 2026-07-20
- **Related:** ADR-0010

## Context

Several bounded contexts legitimately use the same local vocabulary, such as
`workspace.read` and `admin`. Authorization profiles are evaluated together in
one platform PDP. Merging unqualified action patterns and role identifiers would
let a grant or scope rule from one profile affect another profile. Dynamic
actions such as `tool.invoke:<id>` also cannot be represented as exact keys.

## Decision

Profile scope rules use the IAM action-pattern grammar. The PAP rejects the
unbounded `*` pattern. Every action is qualified as
`<profile-namespace>::<local-action>`; profile-owned grant, role, and group ids
begin with `<profile-namespace>:`. Validation rejects identifiers outside that
partition.

The product PEP qualifies its local action at the anti-corruption boundary. A
resource service continues to use its local domain vocabulary and does not know
about IAM profile namespaces.

## Consequences

- Multiple consumer profiles can share one evaluator without grants, roles, or
  scope applicability leaking across bounded contexts.
- A bounded dynamic family such as `awaken.flow::tool.*` remains configurable.
- Consumers must publish and evaluate the qualified form consistently; an
  unqualified action fails closed once a profile is active.
