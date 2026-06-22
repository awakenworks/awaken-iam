# Authorization evaluation engine

This document describes the authorization evaluation engine in `awaken-iam-core`.
It refines the authorization sections of [IAM model](iam-model.md) into the
concrete evaluation behaviour the engine implements.

## Shape

```text
Principal + Action + Scope -> Decision (+ trace)
```

Evaluation is **default-deny**. A request is allowed only when at least one
matching grant permits it, and a matching deny grant overrides any allow.

## Inputs

The engine evaluates an `AuthorizationRequest` against a `PolicySet`:

- **Grants** — each grant has a subject (a principal or a role), an action
  pattern, a scope, and an effect (`Allow` or `Deny`). v1 stored policy is
  expected to use only `Allow`; the deny effect exists so the precedence seam is
  present from the start (introducing deny grants in stored policy requires a
  future ADR).
- **Role bindings** — bind a principal to a role at a scope. A binding lets the
  principal use every grant carried by that role for requests at the binding
  scope and anything beneath it.
- **Scope graph** — records the `org -> namespace` and `org -> workspace` parent
  links that are not derivable from a `ScopeRef` alone. The
  `workspace -> project` link is intrinsic to `ScopeRef::Project`.

## Scope-graph resolution

A grant issued at a broader scope covers requests at narrower scopes beneath it.
The inclusive ancestor chain is:

```text
global
  └─ org
       ├─ namespace
       └─ workspace
            └─ project
```

`covers(grant_scope, request_scope)` holds when `grant_scope` equals
`request_scope` or is one of its ancestors. `Global` covers everything. Org
coverage of namespaces and workspaces requires the membership edge to be
registered in the scope graph; an unregistered namespace/workspace is only
covered by `Global` and its own exact scope.

## Action-pattern matching

- `*` matches every action.
- A dotted prefix wildcard such as `project.*` matches `project` and any action
  beneath it (`project.read`, `project.configure`), but not a sibling prefix
  (`projectile.read`).
- Any other value matches a single action key exactly.

## Decision precedence

1. Expand the roles the principal holds for the request scope.
2. Collect grants whose subject matches (directly or via a held role), whose
   action pattern matches, and whose scope covers the request scope.
3. If any matched grant denies → `Deny` (`denied_by_grant`).
4. Else if any matched grant allows → `Allow` (`allowed_by_grant`).
5. Else → `Deny` (`default_deny`).

## Decision trace

Every evaluation returns an `AuthorizationTrace` carrying the decision, a stable
reason code (`allowed_by_grant`, `denied_by_grant`, `default_deny`), and the ids
of the grants and roles that produced the deciding effect, so audit and debug
surfaces can explain each outcome.
