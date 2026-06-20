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

use std::collections::{BTreeMap, BTreeSet, HashMap};
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

/// A numeric ceiling IAM defines for a metered feature/SKU key.
///
/// IAM only *defines and answers* the ceiling — it holds no counters. The caller
/// meters its own usage and supplies the observed count; [`Quota::permits`]
/// answers whether that usage stays within the ceiling. A feature with no quota
/// entry is unlimited.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Quota {
    /// An inclusive finite ceiling: usage at or below this count stays within.
    Limited(u64),
    /// No ceiling — the feature is entitled without a numeric cap.
    Unlimited,
}

impl Quota {
    /// Whether the caller-metered `usage` stays within this ceiling.
    ///
    /// The ceiling is inclusive: `Limited(n)` permits usage up to and including
    /// `n` and is exceeded only by usage strictly greater than `n`. `Unlimited`
    /// always permits.
    pub fn permits(&self, usage: u64) -> bool {
        match self {
            Quota::Unlimited => true,
            Quota::Limited(ceiling) => usage <= *ceiling,
        }
    }

    /// The inclusive finite ceiling, if this quota is bounded.
    pub fn ceiling(&self) -> Option<u64> {
        match self {
            Quota::Unlimited => None,
            Quota::Limited(ceiling) => Some(*ceiling),
        }
    }
}

/// The time window a [`RateLimit`] is measured over.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RateWindow {
    /// Per one-second window.
    Second,
    /// Per one-minute window.
    Minute,
    /// Per one-hour window.
    Hour,
    /// Per one-day window.
    Day,
}

/// A rate-limit *definition*: the maximum units a feature permits per window.
///
/// Like [`Quota`], this is a definition only. IAM answers the shape of the limit;
/// the caller tracks request counts over the window and enforces. A feature with
/// no rate entry has no per-window cap.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RateLimit {
    /// Maximum units permitted within a single window (inclusive).
    pub max_per_window: u64,
    /// The window the maximum is measured over.
    pub window: RateWindow,
}

impl RateLimit {
    /// Define a rate limit of `max_per_window` units per `window`.
    pub fn new(max_per_window: u64, window: RateWindow) -> Self {
        Self {
            max_per_window,
            window,
        }
    }

    /// Whether `observed` units measured by the caller within one window stay
    /// within this limit. The maximum is inclusive.
    pub fn permits(&self, observed: u64) -> bool {
        observed <= self.max_per_window
    }
}

/// A plan definition: the feature/SKU keys a subscriber is entitled to, plus the
/// optional numeric quota and rate-limit ceilings IAM defines for them.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Plan {
    /// Stable plan identifier.
    pub id: PlanId,
    /// Coarse tier this plan belongs to.
    pub tier: PlanTier,
    /// Feature / SKU keys this plan entitles.
    pub features: BTreeSet<String>,
    /// Optional numeric ceilings keyed by feature/SKU key.
    pub limits: BTreeMap<String, Quota>,
    /// Optional per-window rate-limit definitions keyed by feature/SKU key.
    pub rates: BTreeMap<String, RateLimit>,
}

impl Plan {
    /// Build a plan from an id, tier, and an iterator of feature/SKU keys. The
    /// plan starts with no quota or rate-limit ceilings; attach them with
    /// [`Plan::with_quota`] and [`Plan::with_rate_limit`].
    pub fn new<I, S>(id: PlanId, tier: PlanTier, features: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        Self {
            id,
            tier,
            features: features.into_iter().map(Into::into).collect(),
            limits: BTreeMap::new(),
            rates: BTreeMap::new(),
        }
    }

    /// Attach a numeric quota ceiling to a feature/SKU key (builder style).
    pub fn with_quota(mut self, feature: impl Into<String>, quota: Quota) -> Self {
        self.limits.insert(feature.into(), quota);
        self
    }

    /// Attach a per-window rate-limit definition to a feature/SKU key (builder
    /// style).
    pub fn with_rate_limit(mut self, feature: impl Into<String>, rate: RateLimit) -> Self {
        self.rates.insert(feature.into(), rate);
        self
    }

    /// Whether this plan entitles the given feature/SKU key.
    pub fn entitles(&self, feature: &str) -> bool {
        self.features.contains(feature)
    }

    /// The numeric quota ceiling defined for a feature/SKU key, if any.
    pub fn quota(&self, feature: &str) -> Option<Quota> {
        self.limits.get(feature).copied()
    }

    /// The rate-limit definition for a feature/SKU key, if any.
    pub fn rate_limit(&self, feature: &str) -> Option<RateLimit> {
        self.rates.get(feature).copied()
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
    /// The plan entitles the feature, but the caller-metered usage is over the
    /// quota ceiling IAM defines for it.
    QuotaExceeded {
        /// Plan that defined the ceiling.
        plan: PlanId,
        /// Feature/SKU key the ceiling applies to.
        feature: String,
        /// Inclusive ceiling defined for the feature.
        ceiling: u64,
        /// Usage the caller metered and supplied.
        observed: u64,
    },
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

    /// Answer the quota ceiling a principal's plan defines for a feature/SKU key.
    /// Returns `None` when no plan is assigned or the feature has no ceiling.
    pub fn quota_for(&self, principal: &PrincipalRef, feature: &str) -> Option<Quota> {
        self.plan_for(principal)?.quota(feature)
    }

    /// Answer the rate-limit definition a principal's plan defines for a
    /// feature/SKU key. Returns `None` when no plan is assigned or the feature
    /// has no rate limit.
    pub fn rate_limit_for(&self, principal: &PrincipalRef, feature: &str) -> Option<RateLimit> {
        self.plan_for(principal)?.rate_limit(feature)
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

    fn evaluate_quota(&self, request: &EntitlementRequest, observed: u64) -> EntitlementOutcome {
        let Some(plan) = self.plan_for(&request.principal) else {
            return EntitlementOutcome::deny(EntitlementReason::NoPlanAssigned);
        };
        if !plan.entitles(&request.entitlement) {
            return EntitlementOutcome::deny(EntitlementReason::PlanLacksFeature {
                plan: plan.id.clone(),
                feature: request.entitlement.clone(),
            });
        }
        if let Some(Quota::Limited(ceiling)) = plan.quota(&request.entitlement)
            && observed > ceiling
        {
            return EntitlementOutcome::deny(EntitlementReason::QuotaExceeded {
                plan: plan.id.clone(),
                feature: request.entitlement.clone(),
                ceiling,
                observed,
            });
        }
        EntitlementOutcome::allow(EntitlementReason::PlanEntitles {
            plan: plan.id.clone(),
            feature: request.entitlement.clone(),
        })
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

    /// Answer the quota ceiling the remote defines for a feature/SKU key.
    /// Defaults to "no ceiling defined" so existing resolvers stay valid.
    fn quota(&self, _principal: &PrincipalRef, _feature: &str) -> Option<Quota> {
        None
    }

    /// Answer the rate-limit definition the remote defines for a feature/SKU
    /// key. Defaults to "no rate limit defined".
    fn rate_limit(&self, _principal: &PrincipalRef, _feature: &str) -> Option<RateLimit> {
        None
    }

    /// Resolve an entitlement request together with the caller-metered usage.
    /// Defaults to the usage-agnostic [`EntitlementResolver::resolve`] so a
    /// remote that does not model quotas keeps its existing behaviour.
    fn resolve_quota(&self, request: &EntitlementRequest, _observed: u64) -> EntitlementOutcome {
        self.resolve(request)
    }
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

    /// Answer the quota ceiling defined for a principal's feature/SKU key.
    ///
    /// IAM defines and answers the limit; the caller meters usage against it.
    /// Default-allow mode imposes no ceilings (`None`); local mode reads the
    /// plan catalog; remote mode delegates to the resolver.
    pub fn quota(&self, principal: &PrincipalRef, feature: &str) -> Option<Quota> {
        match &self.mode {
            EntitlementMode::DefaultAllow => None,
            EntitlementMode::Local(catalog) => catalog.quota_for(principal, feature),
            EntitlementMode::Remote(resolver) => resolver.quota(principal, feature),
        }
    }

    /// Answer the rate-limit definition for a principal's feature/SKU key.
    ///
    /// IAM defines and answers the limit; the caller meters request counts over
    /// the window and enforces. Default-allow mode imposes no rate limits.
    pub fn rate_limit(&self, principal: &PrincipalRef, feature: &str) -> Option<RateLimit> {
        match &self.mode {
            EntitlementMode::DefaultAllow => None,
            EntitlementMode::Local(catalog) => catalog.rate_limit_for(principal, feature),
            EntitlementMode::Remote(resolver) => resolver.rate_limit(principal, feature),
        }
    }

    /// Evaluate a request against the quota ceiling using the caller-metered
    /// `observed_usage`, returning a reasoned outcome.
    ///
    /// This realises step 4 of the evaluation flow: a plan that entitles the
    /// feature but whose ceiling the supplied usage exceeds resolves
    /// `Deny(QuotaExceeded)`. A feature with no ceiling, or usage within it,
    /// resolves the same as [`EntitlementEngine::evaluate`].
    pub fn check_quota(
        &self,
        request: &EntitlementRequest,
        observed_usage: u64,
    ) -> EntitlementOutcome {
        match &self.mode {
            EntitlementMode::DefaultAllow => {
                EntitlementOutcome::allow(EntitlementReason::DefaultAllow)
            }
            EntitlementMode::Local(catalog) => catalog.evaluate_quota(request, observed_usage),
            EntitlementMode::Remote(resolver) => resolver.resolve_quota(request, observed_usage),
        }
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
    fn quota_ceiling_is_inclusive() {
        let quota = Quota::Limited(5);
        assert!(quota.permits(0));
        assert!(quota.permits(5));
        assert!(!quota.permits(6));
        assert_eq!(quota.ceiling(), Some(5));

        assert!(Quota::Unlimited.permits(u64::MAX));
        assert_eq!(Quota::Unlimited.ceiling(), None);
    }

    #[test]
    fn rate_limit_max_is_inclusive() {
        let rate = RateLimit::new(60, RateWindow::Minute);
        assert!(rate.permits(60));
        assert!(!rate.permits(61));
        assert_eq!(rate.window, RateWindow::Minute);
    }

    #[test]
    fn local_mode_answers_quota_and_rate_definitions() {
        let mut catalog = EntitlementCatalog::new();
        catalog.upsert_plan(
            Plan::new(PlanId("team".into()), PlanTier::Team, ["namespace.private"])
                .with_quota("namespace.private", Quota::Limited(5))
                .with_rate_limit("pack.publish", RateLimit::new(60, RateWindow::Minute)),
        );
        catalog.assign(account("acct_1"), PlanId("team".into()));
        let engine = EntitlementEngine::local(catalog);
        let who = account("acct_1");

        assert_eq!(
            engine.quota(&who, "namespace.private"),
            Some(Quota::Limited(5))
        );
        assert_eq!(
            engine.rate_limit(&who, "pack.publish"),
            Some(RateLimit::new(60, RateWindow::Minute))
        );
        // Features without a defined ceiling are unlimited (None).
        assert_eq!(engine.quota(&who, "pack.publish"), None);
        assert_eq!(engine.rate_limit(&who, "namespace.private"), None);
        // An unassigned principal has no plan, hence no ceilings.
        assert_eq!(engine.quota(&account("acct_2"), "namespace.private"), None);
    }

    #[test]
    fn default_allow_imposes_no_ceilings() {
        let engine = EntitlementEngine::default_allow();
        let who = account("acct_1");
        assert_eq!(engine.quota(&who, "namespace.private"), None);
        assert_eq!(engine.rate_limit(&who, "pack.publish"), None);
        let outcome = engine.check_quota(&request(who, "namespace.private", None), u64::MAX);
        assert_eq!(outcome.decision, EntitlementDecision::Allow);
        assert_eq!(outcome.reason, EntitlementReason::DefaultAllow);
    }

    #[test]
    fn check_quota_denies_when_usage_over_ceiling() {
        let mut catalog = EntitlementCatalog::new();
        catalog.upsert_plan(
            Plan::new(PlanId("team".into()), PlanTier::Team, ["namespace.private"])
                .with_quota("namespace.private", Quota::Limited(2)),
        );
        catalog.assign(account("acct_1"), PlanId("team".into()));
        let engine = EntitlementEngine::local(catalog);
        let req = request(account("acct_1"), "namespace.private", None);

        // At the inclusive ceiling -> still allowed.
        let at = engine.check_quota(&req, 2);
        assert_eq!(at.decision, EntitlementDecision::Allow);
        assert_eq!(
            at.reason,
            EntitlementReason::PlanEntitles {
                plan: PlanId("team".into()),
                feature: "namespace.private".into(),
            }
        );

        // Over the ceiling -> quota exceeded.
        let over = engine.check_quota(&req, 3);
        assert_eq!(over.decision, EntitlementDecision::Deny);
        assert_eq!(
            over.reason,
            EntitlementReason::QuotaExceeded {
                plan: PlanId("team".into()),
                feature: "namespace.private".into(),
                ceiling: 2,
                observed: 3,
            }
        );
    }

    #[test]
    fn check_quota_fails_closed_before_reaching_ceiling() {
        let mut catalog = EntitlementCatalog::new();
        catalog.upsert_plan(
            Plan::new(PlanId("free".into()), PlanTier::Free, ["pack.read"])
                .with_quota("namespace.private", Quota::Limited(0)),
        );
        catalog.assign(account("acct_1"), PlanId("free".into()));
        let engine = EntitlementEngine::local(catalog);

        // Feature the plan does not entitle never reaches the quota check.
        let lacks = engine.check_quota(&request(account("acct_1"), "namespace.private", None), 0);
        assert_eq!(lacks.decision, EntitlementDecision::Deny);
        assert_eq!(
            lacks.reason,
            EntitlementReason::PlanLacksFeature {
                plan: PlanId("free".into()),
                feature: "namespace.private".into(),
            }
        );

        // Unassigned principal fails closed regardless of usage.
        let unassigned = engine.check_quota(&request(account("acct_2"), "pack.read", None), 0);
        assert_eq!(unassigned.decision, EntitlementDecision::Deny);
        assert_eq!(unassigned.reason, EntitlementReason::NoPlanAssigned);
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
