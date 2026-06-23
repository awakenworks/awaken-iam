//! Remote authorization HTTP API surface.
//!
//! This is the framework-agnostic seam that exposes the authorization and
//! entitlement planes over the wire — the server half of the protocol described
//! in `docs/design/remote-protocol.md`. Like [`AuthApi`](crate::AuthApi) it
//! speaks in logical request/response values (the DTOs in
//! [`awaken_iam_contract`]) rather than binding to a concrete HTTP framework; a
//! deployment maps these methods onto its router of choice:
//!
//! | Route | Method on [`AuthzApi`] |
//! |---|---|
//! | `POST /v1/authorize` | [`AuthzApi::authorize`] |
//! | `POST /v1/authorize/batch` | [`AuthzApi::authorize_batch`] |
//! | `POST /v1/entitlements/check` | [`AuthzApi::check_entitlement`] |
//! | `GET /v1/authz/snapshot` | [`AuthzApi::snapshot`] |
//!
//! Authorization and entitlement are held as independent planes: grant
//! evaluation lives in [`IamCore`] and never consults the
//! [`EntitlementEngine`], and the engine never consults grants. The policy
//! snapshot is authorization-only; entitlement is always evaluated live so a
//! plan or billing change takes effect without a re-sync.

use awaken_iam_contract::{
    AuthorizationOutcome, AuthorizationRequest, BatchAuthorizationRequest,
    BatchAuthorizationResponse, EntitlementCheckResponse, EntitlementRequest, PolicySnapshot,
};
use awaken_iam_core::{EntitlementEngine, IamCore, PolicySet};

/// Authorization/entitlement protocol surface over an in-process [`IamCore`] and
/// [`EntitlementEngine`].
#[derive(Debug, Default)]
pub struct AuthzApi {
    core: IamCore,
    entitlements: EntitlementEngine,
    policy_version: u64,
}

impl AuthzApi {
    /// Build an API with an empty default-deny policy and v1 default-allow
    /// entitlements at policy version 1.
    pub fn new() -> Self {
        Self {
            core: IamCore::new(),
            entitlements: EntitlementEngine::default_allow(),
            policy_version: 1,
        }
    }

    /// Build an API with a specific entitlement engine and an empty default-deny
    /// policy.
    pub fn with_entitlements(entitlements: EntitlementEngine) -> Self {
        Self {
            core: IamCore::new(),
            entitlements,
            policy_version: 1,
        }
    }

    /// Build an API over an explicit core and entitlement engine.
    pub fn from_parts(core: IamCore, entitlements: EntitlementEngine) -> Self {
        Self {
            core,
            entitlements,
            policy_version: 1,
        }
    }

    /// Read-only access to the authorization core.
    pub fn core(&self) -> &IamCore {
        &self.core
    }

    /// Mutable access to the policy. Mutating the policy bumps the snapshot
    /// version so local-mode consumers re-sync on their next poll.
    pub fn policy_mut(&mut self) -> &mut PolicySet {
        self.policy_version += 1;
        self.core.policy_mut()
    }

    /// The current monotonic policy version reported in snapshots.
    pub fn policy_version(&self) -> u64 {
        self.policy_version
    }

    /// `POST /v1/authorize`: evaluate one authorization request into a reasoned
    /// outcome (decision, reason code, matched grant/role ids).
    pub fn authorize(&self, request: &AuthorizationRequest) -> AuthorizationOutcome {
        self.core.evaluate(request).to_outcome()
    }

    /// `POST /v1/authorize/batch`: evaluate several requests in one round trip,
    /// preserving order one-to-one.
    pub fn authorize_batch(
        &self,
        request: &BatchAuthorizationRequest,
    ) -> BatchAuthorizationResponse {
        BatchAuthorizationResponse {
            outcomes: request
                .requests
                .iter()
                .map(|item| self.authorize(item))
                .collect(),
        }
    }

    /// `POST /v1/entitlements/check`: evaluate an entitlement request live
    /// against the entitlement plane.
    pub fn check_entitlement(&self, request: &EntitlementRequest) -> EntitlementCheckResponse {
        self.entitlements.evaluate(request).to_response()
    }

    /// `GET /v1/authz/snapshot`: capture the authorization policy as a versioned
    /// snapshot for local-mode synchronisation. A consumer can rebuild the
    /// policy with [`PolicySet::from_snapshot`] and evaluate in-process for
    /// decisions byte-identical to remote `authorize` calls.
    pub fn snapshot(&self) -> PolicySnapshot {
        self.core.policy().snapshot(self.policy_version)
    }

    /// `GET /v1/authz/snapshot?since=`: return the snapshot only when the policy
    /// has advanced past `since`, letting a synced consumer skip an unchanged
    /// payload. Returns `None` when `since` already matches the current version.
    pub fn snapshot_since(&self, since: u64) -> Option<PolicySnapshot> {
        (self.policy_version > since).then(|| self.snapshot())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use awaken_iam_contract::{
        AccountId, ActionKey, AuthorizationDecision, EntitlementDecision, PrincipalRef, ScopeRef,
    };
    use awaken_iam_core::{
        ActionPattern, Effect, EntitlementCatalog, EntitlementEngine, Grant, GrantId, GrantSubject,
        Plan, PlanId, PlanTier,
    };

    fn service(id: &str) -> PrincipalRef {
        PrincipalRef::Service {
            service_id: id.into(),
        }
    }

    fn request(principal: PrincipalRef, action: &str, scope: ScopeRef) -> AuthorizationRequest {
        AuthorizationRequest::direct(principal, ActionKey(action.into()), scope)
    }

    #[test]
    fn authorize_reports_default_deny_with_reason() {
        let api = AuthzApi::new();
        let outcome = api.authorize(&request(service("svc"), "pack.publish", ScopeRef::Global));
        assert_eq!(outcome.decision, AuthorizationDecision::Deny);
        assert_eq!(outcome.reason, "default_deny");
        assert!(outcome.matched_grants.is_empty());
    }

    #[test]
    fn authorize_reports_matched_grant_when_allowed() {
        let mut api = AuthzApi::new();
        api.policy_mut().add_grant(Grant {
            id: GrantId("g1".into()),
            subject: GrantSubject::Principal(service("svc")),
            action_pattern: ActionPattern("pack.publish".into()),
            scope: ScopeRef::Global,
            effect: Effect::Allow,
        });
        let outcome = api.authorize(&request(service("svc"), "pack.publish", ScopeRef::Global));
        assert_eq!(outcome.decision, AuthorizationDecision::Allow);
        assert_eq!(outcome.reason, "allowed_by_grant");
        assert_eq!(outcome.matched_grants, vec!["g1".to_owned()]);
    }

    #[test]
    fn batch_preserves_request_order() {
        let mut api = AuthzApi::new();
        api.policy_mut().add_grant(Grant {
            id: GrantId("g1".into()),
            subject: GrantSubject::Principal(service("svc")),
            action_pattern: ActionPattern("pack.read".into()),
            scope: ScopeRef::Global,
            effect: Effect::Allow,
        });
        let response = api.authorize_batch(&BatchAuthorizationRequest {
            requests: vec![
                request(service("svc"), "pack.read", ScopeRef::Global),
                request(service("svc"), "pack.delete", ScopeRef::Global),
            ],
        });
        assert_eq!(response.outcomes.len(), 2);
        assert_eq!(response.outcomes[0].decision, AuthorizationDecision::Allow);
        assert_eq!(response.outcomes[1].decision, AuthorizationDecision::Deny);
    }

    #[test]
    fn entitlement_check_reports_reason() {
        let mut catalog = EntitlementCatalog::new();
        catalog.upsert_plan(Plan::new(
            PlanId("pro".into()),
            PlanTier::Pro,
            ["pack.read"],
        ));
        let principal = PrincipalRef::Account {
            account_id: AccountId("acct_1".into()),
        };
        catalog.assign(principal.clone(), PlanId("pro".into()));
        let api = AuthzApi::with_entitlements(EntitlementEngine::local(catalog));

        let allowed = api.check_entitlement(&EntitlementRequest {
            principal: principal.clone(),
            entitlement: "pack.read".into(),
            resource: None,
        });
        assert_eq!(allowed.decision, EntitlementDecision::Allow);
        assert_eq!(allowed.reason, "plan_entitles");

        let denied = api.check_entitlement(&EntitlementRequest {
            principal,
            entitlement: "model.strong_access".into(),
            resource: None,
        });
        assert_eq!(denied.decision, EntitlementDecision::Deny);
        assert_eq!(denied.reason, "plan_lacks_feature");
    }

    #[test]
    fn snapshot_version_advances_when_policy_changes() {
        let mut api = AuthzApi::new();
        assert_eq!(api.snapshot().version, 1);
        assert!(api.snapshot_since(1).is_none());
        api.policy_mut().add_grant(Grant {
            id: GrantId("g1".into()),
            subject: GrantSubject::Principal(service("svc")),
            action_pattern: ActionPattern("pack.read".into()),
            scope: ScopeRef::Global,
            effect: Effect::Allow,
        });
        let snapshot = api.snapshot();
        assert_eq!(snapshot.version, 2);
        assert_eq!(snapshot.grants.len(), 1);
        // A consumer still on version 1 is handed the fresh snapshot.
        assert_eq!(api.snapshot_since(1).map(|s| s.version), Some(2));
        assert!(api.snapshot_since(2).is_none());
    }

    #[test]
    fn synced_snapshot_evaluates_identically_to_remote_authorize() {
        let mut api = AuthzApi::new();
        api.policy_mut().add_grant(Grant {
            id: GrantId("g1".into()),
            subject: GrantSubject::Principal(service("svc")),
            action_pattern: ActionPattern("pack.*".into()),
            scope: ScopeRef::Global,
            effect: Effect::Allow,
        });
        let snapshot = api.snapshot();
        let local = PolicySet::from_snapshot(&snapshot);

        for action in ["pack.publish", "image.push"] {
            let req = request(service("svc"), action, ScopeRef::Global);
            // Local evaluation from the synced snapshot mirrors the remote answer.
            assert_eq!(local.evaluate(&req).to_outcome(), api.authorize(&req));
        }
    }
}
