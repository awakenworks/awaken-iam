# IAM consolidation — migration plan

This document is the staged plan to move all IAM capability into `awaken-iam` as
the single system of record, per [ADR-0002](../adr/0002-iam-consolidation.md).
It follows the Strangler Fig pattern: never a big-bang cutover — each capability
is wrapped, shadowed against the incumbent until parity, then cut over, then the
old path is deleted. It is written by capability and by consumer **archetype**,
not by product, so it applies to any service that adopts IAM.

> This is *capability* migration. For *schema* migration and the
> embedded-or-standalone deployment mechanism, see [deployment](deployment.md) —
> a separate concern.

## Principles

- **Flagged.** Every move is behind a per-consumer, per-capability flag.
- **Shadowed.** Before cutover, the enforcement point calls IAM *and* the
  incumbent, compares, and logs divergences. Cutover happens only at measured
  parity.
- **Reversible.** The incumbent stays callable until the old code is deleted; the
  flag flips back instantly.
- **Boundary-respecting.** Only true IAM moves; see
  [permission mechanisms](permission-mechanisms.md#what-is-never-a-mechanism-here).

## What migrates / what does not

| Migrates to awaken-iam | Stays with the consumer |
|---|---|
| accounts, external-identity links | product workflow/stage roles |
| sessions, API tokens, refresh lifecycle | in-process tool/action gating |
| federated login (Google/GitHub) | runtime capability admission |
| orgs, groups, memberships | connector credentials / secrets / vaults |
| roles, grants, authorization decisions | approval-workflow execution |
| namespace ownership + signer trust | product sub-resource business logic |
| plans, subscriptions, entitlement, quota | the enforcement point and usage meters |

IAM owns the **decision and the identity**; the consumer owns **enforcement and
runtime mechanism**. `RequireApproval` is a decision IAM may return; executing
the approval is the consumer's.

## Consumer archetypes

The cutover path depends on where a consumer starts, not on which product it is:

- **Conformist (greenfield).** No prior authorization; speaks IAM's language from
  day one. Integrates by calling the remote decision point. Lowest risk — used to
  prove the engine end to end.
- **Incumbent engine.** Already owns a rich local authorization model. Registers
  its `ResourceModel` (scope hierarchy, action catalog, roles) as data, imports
  its grants/memberships, and runs in shadow until parity before deleting the
  local engine.
- **Thin runtime.** Has only a stub. Adopts identity, workspace-level
  authorization, and entitlement; keeps its runtime gating local.
- **Scoped-token / sandbox.** Authenticates by scoped key or federated workload
  identity and delegates to short-lived sandboxed children. Adopts scoped tokens,
  capability tokens, and quota.

## Phases

Ordered to de-risk the engine on the simplest archetype first.

### Phase 0 — Foundation (engine + registry + auth hardening)
- Authorization evaluation engine, replacing the `Deny` stub (#29).
- Grant / role / membership model + store + versioned snapshot (#30).
- `ResourceModel` registry: open scopes, open action catalog, scope edges as data.
- Widen the contract: `Decision = Allow | Deny | RequireApproval`; requests carry
  a principal chain (#34) — both widenings of today's shapes.
- Harden the auth server: JWKS, refresh-token rotation, revoke, scoped API
  tokens, capability tokens, federated token exchange
  ([auth server](auth-server.md)), on top of the existing Google/GitHub login.
Exit: IAM answers a real `authorize` and a real federated login end to end.

### Phase 1 — Identity as system of record
- Consumers delegate login to the IAM broker (OIDC redirect).
- Sessions and API tokens become IAM-issued; local session tables become caches
  keyed by IAM session id (anticorruption layer).
- Dual-write during cutover; shadow-validate tokens against both.
Exit: one login, one session, one token story.

### Phase 2 — Conformist consumer (lowest risk)
- Namespace ownership + signer-key binding (#31),
  [namespace trust model](namespace-trust-model.md).
- Remote `authorize` + client, local/remote mode (#33),
  [remote protocol](remote-protocol.md).
Exit: a real consumer runs with **zero** local authorization.

### Phase 3 — Incumbent engine (the large one)
- Register the incumbent's `ResourceModel` (its full scope tree, action catalog,
  builtin roles) as data; import roles, grants, memberships.
- **Shadow mode**: every decision calls IAM and the local engine; divergence is
  logged and burned down to zero.
- Use `RequireApproval` + principal chains so HITL and delegation survive; the
  approval *execution* stays with the consumer.
- Cut over reads (visibility filtering) via synced snapshot for latency, then
  writes; delete the local engine.
Exit: the incumbent authorizes through IAM; its local engine is removed.

### Phase 4 — Entitlement and quota plane
- Plan/subscription model + `check_entitlement` + numeric quota / rate-limit
  definitions, replacing default-allow (#32),
  [entitlement plane](entitlements.md).
Exit: private/paid resources and feature/usage gates switch on with no change to
grant evaluation.

### Phase 5 — Thin runtime / scoped-token consumers (narrow, last)
- Tenant principal + workspace authorization at the gateway, replacing stubs.
- Scoped API tokens, capability tokens, and federated workload identity for
  sandboxed delegation; quota checks.
- Explicitly unchanged: runtime capability admission, tool gating, credential
  broker/pool, usage meters. These are not IAM.
Exit: thin/scoped consumers use IAM for identity, scoped authz, and entitlement
only.

### Phase 6 — Decommission
Remove dual-writes, retire shadow harnesses, delete superseded local code, freeze
the canonical contract version.

## Per-consumer cutover checklist

```text
[ ] ResourceModel registered (or Conformist: speaks IAM language natively)
[ ] data imported (roles/grants/memberships/identities) and reconciled
[ ] shadow divergence == 0 over a sustained window
[ ] latency budget met (snapshot-synced local decision point where needed)
[ ] rollback flag verified in staging
[ ] incumbent code deleted; audit retained
```

## Rollback and safety

- Authorization fails closed everywhere (an unreachable IAM denies, never allows).
- Shadow precedes every cutover; a divergence spike auto-holds the flag.
- The append-only audit trail is the reconciliation source of truth during dual
  running.

## Issue map

`#29` engine · `#30` grant/role/membership store · `#31` namespace+signer ·
`#32` entitlement · `#33` remote API+client · `#34` contract reconciliation ·
`#35` integration boundary + contract tests. Phases 0–2 are reachable with the
issues already filed; Phases 3–6 expand into per-consumer epics as they begin.
