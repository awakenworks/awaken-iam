# ADR-0002 - Unified, product-agnostic IAM control plane

- **Status:** Proposed
- **Implementation:** planned
- **Date:** 2026-06-23
- **Related:** ADR-0001

## Context

[ADR-0001](0001-iam-shared-boundary.md) drew the boundary: `awaken-iam` is the
shared control plane. In practice the IAM capability is still scattered. One
consuming service owns a full authorization engine (roles, grants, scopes,
delegation, approval) and its own sessions and API tokens; another has only an
authorization stub; a greenfield service is designed against IAM but cannot
proceed because IAM's `authorize()` returns `Deny` unconditionally. Login,
session minting, and token lifecycle would otherwise be re-implemented per
service.

The goal is now stronger than "shared types": **all IAM capability — identity,
authorization, and entitlement — is consolidated into `awaken-iam` as the single
system of record and decision point**, and the result must be **product-agnostic**
(reusable by any service, with login limited to Google and GitHub) rather than
wired to one product's domain.

The proven shape for this exists. A reference federation-broker implementation
runs IAM as the broker: services authenticate against IAM with PKCE, IAM
federates to Google/GitHub upstream and issues its own sessions, and callers
consume a unified client. Two lessons are adopted directly: normalize all auth
endpoints under one canonical path tree, and unify token lifecycle behind one
client with rotation and revocation.

## Decision

1. **One control plane, three planes of capability.** `awaken-iam` owns
   Identity & Federation, Authorization, and Entitlement. It is the system of
   record for accounts, external-identity links, sessions, API tokens,
   organizations, groups, memberships, roles, grants, namespaces/signers, plans,
   and subscriptions. See [domain model](../design/domain-model.md).

2. **Externalized authorization (PEP/PDP/PAP).** IAM is the Policy Decision Point
   and Administration Point; products keep only a thin Policy Enforcement Point
   (the client SDK). Decisions are computed by one engine, locally or remotely,
   over a versioned snapshot. See
   [authorization engine](../design/authorization-engine.md) and
   [remote protocol](../design/remote-protocol.md).

3. **Product-agnostic kernel; products register their domain as data.** The core
   contains no product names. A product onboards by registering a
   `ResourceModel` (its resource types, action catalog, and scope-parent edges)
   and receiving an OAuth client id — never by IAM depending on the product. This
   is what lets a consumer's deep scope tree be authorized without coupling.

4. **IAM is the identity broker; login is Google and GitHub only.** IAM is an
   OpenID Provider to product clients and an OAuth client to Google/GitHub
   upstream. Products never integrate Google/GitHub directly. The provider set is
   config-driven and deliberately limited to Google, GitHub (and a fake provider
   for tests). See [auth server](../design/auth-server.md).

5. **Migrate by Strangler Fig, never big-bang.** Each capability moves behind a
   flag, runs in shadow against the incumbent until parity, then cuts over and the
   local implementation is removed. See [migration plan](../design/migration-strategy.md).

6. **The boundary holds.** IAM owns the *decision* and *identity*; products own
   *enforcement* and *runtime mechanism*. Tool-permission gating, capability
   admission, connector credentials/secrets, approval-workflow execution, and
   product workflow/stage roles do **not** migrate (consistent with ADR-0001 and
   the no-credentials guardrail).

## Consequences

- Authorization becomes the core domain and must ship real evaluation; the
  `Deny` stub is removed. The decision lattice widens to `Allow | Deny |
  RequireApproval` and requests carry a principal chain, to absorb an incumbent
  engine's semantics without forcing a rewrite later.
- Products gain a single login, session, and token story and lose their bespoke
  copies; the migration is staged and reversible per the plan.
- IAM gains OAuth-server surface (JWKS, token, userinfo, revoke) and a
  `ResourceModel` registry. These are additive to the existing crate layout
  (contract / core / client / server); the guardrails in ADR-0001 are unchanged.
- Design follows DDD and simple-design discipline: small aggregates, explicit
  domain events, ports-and-adapters, and no speculative policy language beyond
  hierarchical RBAC until a second need appears.
