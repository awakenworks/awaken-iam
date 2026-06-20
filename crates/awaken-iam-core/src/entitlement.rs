//! Entitlement evaluation engine.
//!
//! Entitlement is a **separate plane** from authorization. Authorization asks
//! "is this principal allowed to do this action at this scope?"; entitlement
//! asks "does this account's plan / subscription include this feature or SKU?".
//! The two are never mixed: this engine does not consult grants, roles, or the
//! scope graph, and grant evaluation never consults plans. Product services call
//! both planes independently.
//!
//! v1 keeps the policy open (default-allow) while still exercising the real
//! seam, so paid packs, private namespaces, and product-plan limits can be added
//! later without threading billing state through grant evaluation. Two further
//! modes exist today: a local plan catalog and a remote delegation seam.

use std::collections::{BTreeSet, HashMap};
use std::fmt;

use awaken_iam_contract::{EntitlementDecision, EntitlementRequest, PrincipalRef};

/// Identifier of a billing plan / product tier definition.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct PlanId(pub String);

/// Coarse product tier a plan belongs to.
///
/// Tiers are ordered (`Free < Pro < Team < Enterprise`) so future policy can
/// express "at least this tier"; v1 evaluates explicit feature membership and
/// treats the tier as descriptive metadata.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum PlanTier {
    /// Entry-level / unpaid tier.
    Free,
    /// Individual paid tier.
    Pro,
    /// Shared workspace tier.
    Team,
    /// Negotiated enterprise tier.
    Enterprise,
}

/// A plan definition: the set of feature/SKU keys a subscriber is entitled to.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Plan {
    /// Stable plan identifier.
    pub id: PlanId,
    /// Coarse tier this plan belongs to.
    pub tier: PlanTier,
    /// Feature / SKU keys this plan entitles.
    pub features: BTreeSet<String>,
}

impl Plan {
    /// Build a plan from an id, tier, and an iterator of feature/SKU keys.
    pub fn new<I, S>(id: PlanId, tier: PlanTier, features: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        Self {
            id,
            tier,
            features: features.into_iter().map(Into::into).collect(),
        }
    }

    /// Whether this plan entitles the given feature/SKU key.
    pub fn entitles(&self, feature: &str) -> bool {
        self.features.contains(feature)
    }
}

/// Why an entitlement check resolved the way it did, for audit/debug surfaces.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EntitlementReason {
    /// The engine runs in default-allow mode; no plan policy was consulted.
    DefaultAllow,
    /// The principal's plan includes the requested feature/SKU key.
    PlanEntitles {
        /// Plan that granted the feature.
        plan: PlanId,
        /// Feature/SKU key that was matched.
        feature: String,
    },
    /// The principal's plan does not include the requested feature/SKU key.
    PlanLacksFeature {
        /// Plan that was consulted.
        plan: PlanId,
        /// Feature/SKU key that was missing.
        feature: String,
    },
    /// No plan is assigned to the principal, so no feature can be entitled.
    NoPlanAssigned,
    /// A remote entitlement resolver produced the decision.
    Remote,
}

/// Outcome of an entitlement check: the decision plus an explanation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EntitlementOutcome {
    /// Allow/Deny decision returned to the caller.
    pub decision: EntitlementDecision,
    /// Reason code for audit/debug surfaces.
    pub reason: EntitlementReason,
}

impl EntitlementOutcome {
    fn allow(reason: EntitlementReason) -> Self {
        Self {
            decision: EntitlementDecision::Allow,
            reason,
        }
    }

    fn deny(reason: EntitlementReason) -> Self {
        Self {
            decision: EntitlementDecision::Deny,
            reason,
        }
    }
}

/// Catalog mapping principals to plans and resolving feature membership.
///
/// This is the local-mode policy store. A principal with no assigned plan fails
/// closed: local mode is an explicit policy, not a permissive fallback.
#[derive(Debug, Default, Clone)]
pub struct EntitlementCatalog {
    plans: HashMap<PlanId, Plan>,
    assignments: HashMap<PrincipalRef, PlanId>,
}

impl EntitlementCatalog {
    /// Create an empty catalog.
    pub fn new() -> Self {
        Self::default()
    }

    /// Register or replace a plan definition.
    pub fn upsert_plan(&mut self, plan: Plan) {
        self.plans.insert(plan.id.clone(), plan);
    }

    /// Assign a plan to a principal. The plan need not exist yet; an assignment
    /// to an unknown plan resolves as if no plan were assigned.
    pub fn assign(&mut self, principal: PrincipalRef, plan: PlanId) {
        self.assignments.insert(principal, plan);
    }

    /// Resolve the plan currently assigned to a principal, if any.
    pub fn plan_for(&self, principal: &PrincipalRef) -> Option<&Plan> {
        let plan_id = self.assignments.get(principal)?;
        self.plans.get(plan_id)
    }

    fn evaluate(&self, request: &EntitlementRequest) -> EntitlementOutcome {
        let Some(plan) = self.plan_for(&request.principal) else {
            return EntitlementOutcome::deny(EntitlementReason::NoPlanAssigned);
        };
        if plan.entitles(&request.entitlement) {
            EntitlementOutcome::allow(EntitlementReason::PlanEntitles {
                plan: plan.id.clone(),
                feature: request.entitlement.clone(),
            })
        } else {
            EntitlementOutcome::deny(EntitlementReason::PlanLacksFeature {
                plan: plan.id.clone(),
                feature: request.entitlement.clone(),
            })
        }
    }
}

/// Remote entitlement seam: delegate the decision to an external service.
///
/// The control plane keeps entitlement evaluation behind this trait so a
/// product deployment can point at a hosted billing/subscription service
/// without changing call sites. Implementations must be `Send + Sync` so the
/// engine can be shared across requests.
pub trait EntitlementResolver: fmt::Debug + Send + Sync {
    /// Resolve an entitlement request into an outcome.
    fn resolve(&self, request: &EntitlementRequest) -> EntitlementOutcome;
}

/// Evaluation mode for the entitlement plane.
#[derive(Debug, Default)]
pub enum EntitlementMode {
    /// v1 default: allow every entitlement check without consulting policy.
    #[default]
    DefaultAllow,
    /// Evaluate against a local plan catalog.
    Local(EntitlementCatalog),
    /// Delegate to a remote entitlement service.
    Remote(Box<dyn EntitlementResolver>),
}

/// Entitlement evaluation engine — the real `check_entitlement` path.
///
/// Held separately from the authorization core so the two planes never share
/// state. Construct it in the mode a deployment needs and call
/// [`EntitlementEngine::check_entitlement`] (or [`EntitlementEngine::evaluate`]
/// for the reasoned outcome).
#[derive(Debug, Default)]
pub struct EntitlementEngine {
    mode: EntitlementMode,
}

impl EntitlementEngine {
    /// Construct an engine in v1 default-allow mode.
    pub fn default_allow() -> Self {
        Self {
            mode: EntitlementMode::DefaultAllow,
        }
    }

    /// Construct an engine backed by a local plan catalog.
    pub fn local(catalog: EntitlementCatalog) -> Self {
        Self {
            mode: EntitlementMode::Local(catalog),
        }
    }

    /// Construct an engine that delegates to a remote resolver.
    pub fn remote(resolver: Box<dyn EntitlementResolver>) -> Self {
        Self {
            mode: EntitlementMode::Remote(resolver),
        }
    }

    /// The mode this engine evaluates in.
    pub fn mode(&self) -> &EntitlementMode {
        &self.mode
    }

    /// Evaluate a request into a reasoned outcome.
    pub fn evaluate(&self, request: &EntitlementRequest) -> EntitlementOutcome {
        match &self.mode {
            EntitlementMode::DefaultAllow => {
                EntitlementOutcome::allow(EntitlementReason::DefaultAllow)
            }
            EntitlementMode::Local(catalog) => catalog.evaluate(request),
            EntitlementMode::Remote(resolver) => resolver.resolve(request),
        }
    }

    /// Evaluate a request into the contract Allow/Deny decision.
    pub fn check_entitlement(&self, request: &EntitlementRequest) -> EntitlementDecision {
        self.evaluate(request).decision
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use awaken_iam_contract::{AccountId, PrincipalRef};

    fn account(id: &str) -> PrincipalRef {
        PrincipalRef::Account {
            account_id: AccountId(id.into()),
        }
    }

    fn request(
        principal: PrincipalRef,
        entitlement: &str,
        resource: Option<&str>,
    ) -> EntitlementRequest {
        EntitlementRequest {
            principal,
            entitlement: entitlement.into(),
            resource: resource.map(str::to_owned),
        }
    }

    #[test]
    fn default_allow_mode_permits_any_feature() {
        let engine = EntitlementEngine::default_allow();
        let outcome = engine.evaluate(&request(account("acct_1"), "model.strong_access", None));
        assert_eq!(outcome.decision, EntitlementDecision::Allow);
        assert_eq!(outcome.reason, EntitlementReason::DefaultAllow);
        assert_eq!(
            engine.check_entitlement(&request(account("acct_1"), "anything", Some("acme/pkg"))),
            EntitlementDecision::Allow
        );
    }

    #[test]
    fn local_plan_allows_entitled_feature_and_denies_others() {
        let mut catalog = EntitlementCatalog::new();
        catalog.upsert_plan(Plan::new(
            PlanId("pro".into()),
            PlanTier::Pro,
            ["pack.read", "pack.publish"],
        ));
        catalog.assign(account("acct_1"), PlanId("pro".into()));
        let engine = EntitlementEngine::local(catalog);

        let allowed = engine.evaluate(&request(
            account("acct_1"),
            "pack.publish",
            Some("acme/pkg"),
        ));
        assert_eq!(allowed.decision, EntitlementDecision::Allow);
        assert_eq!(
            allowed.reason,
            EntitlementReason::PlanEntitles {
                plan: PlanId("pro".into()),
                feature: "pack.publish".into(),
            }
        );

        let denied = engine.evaluate(&request(account("acct_1"), "model.strong_access", None));
        assert_eq!(denied.decision, EntitlementDecision::Deny);
        assert_eq!(
            denied.reason,
            EntitlementReason::PlanLacksFeature {
                plan: PlanId("pro".into()),
                feature: "model.strong_access".into(),
            }
        );
    }

    #[test]
    fn local_mode_fails_closed_for_unassigned_principal() {
        let mut catalog = EntitlementCatalog::new();
        catalog.upsert_plan(Plan::new(
            PlanId("pro".into()),
            PlanTier::Pro,
            ["pack.read"],
        ));
        catalog.assign(account("acct_1"), PlanId("pro".into()));
        let engine = EntitlementEngine::local(catalog);

        let outcome = engine.evaluate(&request(account("acct_2"), "pack.read", None));
        assert_eq!(outcome.decision, EntitlementDecision::Deny);
        assert_eq!(outcome.reason, EntitlementReason::NoPlanAssigned);
    }

    #[test]
    fn plan_tiers_are_ordered() {
        assert!(PlanTier::Free < PlanTier::Pro);
        assert!(PlanTier::Pro < PlanTier::Team);
        assert!(PlanTier::Team < PlanTier::Enterprise);
    }

    #[derive(Debug)]
    struct DenyAllResolver;

    impl EntitlementResolver for DenyAllResolver {
        fn resolve(&self, _request: &EntitlementRequest) -> EntitlementOutcome {
            EntitlementOutcome {
                decision: EntitlementDecision::Deny,
                reason: EntitlementReason::Remote,
            }
        }
    }

    #[test]
    fn remote_mode_delegates_to_resolver() {
        let engine = EntitlementEngine::remote(Box::new(DenyAllResolver));
        let outcome = engine.evaluate(&request(account("acct_1"), "pack.read", None));
        assert_eq!(outcome.decision, EntitlementDecision::Deny);
        assert_eq!(outcome.reason, EntitlementReason::Remote);
        assert!(matches!(engine.mode(), EntitlementMode::Remote(_)));
    }
}
