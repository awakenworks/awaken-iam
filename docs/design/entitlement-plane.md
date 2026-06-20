# Entitlement plane

Entitlement is a **separate plane** from authorization. The two questions are
answered by different evaluators that never share state:

- **Authorization** — _is this principal allowed to do this action at this
  scope?_ Answered by grant evaluation in `awaken-iam-core` (`IamCore`).
- **Entitlement** — _does this account's plan / subscription include this
  feature or SKU?_ Answered by the entitlement engine in `awaken-iam-core`
  (`EntitlementEngine`).

Keeping them apart means paid packs, private namespaces, and product-plan limits
never get mixed into grant evaluation. A product service calls both planes
independently per request, e.g.

```text
authorize(principal, pack.publish, namespace:acme)   // grant plane
check_entitlement(principal, pack.publish, acme/pkg) // entitlement plane
```

## Model

- **Feature / SKU key** — `EntitlementRequest.entitlement`, an opaque string such
  as `pack.publish` or `model.strong_access`. This is the unit an entitlement
  check resolves.
- **Resource coordinate** — `EntitlementRequest.resource`, an optional string
  (e.g. `acme/pkg`, `workspace:ws`) that scopes the check to a specific resource.
  v1 evaluates feature membership; the coordinate is carried for remote policies
  and audit.
- **Plan** — a `PlanId`, a `PlanTier` (`Free < Pro < Team < Enterprise`), and the
  set of feature/SKU keys it entitles.
- **Assignment** — a principal is assigned to at most one plan in the local
  catalog.

## Modes

`EntitlementEngine` evaluates in one of three modes:

| Mode | Behaviour |
|---|---|
| `DefaultAllow` | v1 default. Allows every check without consulting policy. The seam still runs so call sites are stable. |
| `Local(EntitlementCatalog)` | Resolves the principal's plan and checks feature membership. A principal with no assigned plan fails **closed** (`Deny`) — local mode is an explicit policy, not a permissive fallback. |
| `Remote(Box<dyn EntitlementResolver>)` | Delegates the decision to an external billing/subscription service through the `EntitlementResolver` seam. |

The contract decision (`EntitlementDecision`) is `Allow` / `Deny`. The engine also
exposes `evaluate()` returning an `EntitlementOutcome` that pairs the decision
with an `EntitlementReason` code (`DefaultAllow`, `PlanEntitles`,
`PlanLacksFeature`, `NoPlanAssigned`, `Remote`) for audit/debug surfaces.

## Crate placement

- `awaken-iam-contract` owns the DTOs (`EntitlementRequest`,
  `EntitlementDecision`).
- `awaken-iam-core` owns evaluation (`EntitlementEngine` and the plan model),
  held separately from `IamCore` grant evaluation.
- `awaken-iam-server` wires an engine into `IamServer` and exposes it through the
  `IamClient::check_entitlement` trait method; it defaults to `DefaultAllow` and
  can be constructed `with_entitlements(...)` for local or remote modes.

This keeps the contract boundary (G1) and the core/server boundary (G2) intact:
the engine depends only on contract DTOs, and the server depends on the engine.
