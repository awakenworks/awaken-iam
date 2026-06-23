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

use awaken_iam_client::IamClient;
use awaken_iam_contract::{
    AuthorizationDecision, AuthorizationOutcome, AuthorizationRequest, BatchAuthorizationRequest,
    BatchAuthorizationResponse, EntitlementCheckResponse, EntitlementDecision, EntitlementRequest,
    NamespaceId, PolicySnapshot, SignerSetSnapshot,
};
use awaken_iam_core::{EntitlementEngine, IamCore, NamespaceTrustDirectory, PolicySet};

/// Authorization/entitlement protocol surface over an in-process [`IamCore`],
/// [`EntitlementEngine`], and namespace [`NamespaceTrustDirectory`].
#[derive(Debug, Default)]
pub struct AuthzApi {
    core: IamCore,
    entitlements: EntitlementEngine,
    trust: NamespaceTrustDirectory,
    policy_version: u64,
}

impl AuthzApi {
    /// Build an API with an empty default-deny policy and v1 default-allow
    /// entitlements at policy version 1.
    pub fn new() -> Self {
        Self {
            core: IamCore::new(),
            entitlements: EntitlementEngine::default_allow(),
            trust: NamespaceTrustDirectory::new(),
            policy_version: 1,
        }
    }

    /// Build an API with a specific entitlement engine and an empty default-deny
    /// policy.
    pub fn with_entitlements(entitlements: EntitlementEngine) -> Self {
        Self {
            core: IamCore::new(),
            entitlements,
            trust: NamespaceTrustDirectory::new(),
            policy_version: 1,
        }
    }

    /// Build an API over an explicit core and entitlement engine.
    pub fn from_parts(core: IamCore, entitlements: EntitlementEngine) -> Self {
        Self {
            core,
            entitlements,
            trust: NamespaceTrustDirectory::new(),
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

    /// Read-only access to the namespace trust directory.
    pub fn trust(&self) -> &NamespaceTrustDirectory {
        &self.trust
    }

    /// Mutable access to the namespace trust directory, e.g. to record ownership
    /// or register/revoke signer keys. Mutating it bumps the version fence — the
    /// same fence [`snapshot`](Self::snapshot) reports — so a registry consumer
    /// re-fetches the signer set after a registration or revocation.
    pub fn trust_mut(&mut self) -> &mut NamespaceTrustDirectory {
        self.policy_version += 1;
        &mut self.trust
    }

    /// `GET /v1/namespaces/{namespace_id}/signers`: capture a namespace's active
    /// signer set under the current version fence for trust-root distribution.
    ///
    /// A registry consumer (Pack Hub) caches this and re-fetches only when
    /// `version` advances, so revocation propagates on the next sync while
    /// offline/edge verification stays possible against the cached set. An
    /// unknown or unowned namespace yields an empty set at the current version.
    pub fn signers(&self, namespace_id: &NamespaceId) -> SignerSetSnapshot {
        SignerSetSnapshot {
            namespace_id: namespace_id.clone(),
            version: self.policy_version,
            signers: self
                .trust
                .active_signers(namespace_id)
                .into_iter()
                .cloned()
                .collect(),
        }
    }
}

/// In-process [`IamClient`] over the same engines that serve `/v1`.
///
/// This is the **local** client an embedded deployment hands to in-process
/// callers (see [deployment](../../../../docs/design/deployment.md)): it resolves
/// decisions by calling the very `AuthzApi` that backs the mounted routes, so a
/// local-mode decision is byte-identical to a remote `POST /v1/authorize` against
/// the same policy — no network hop, no second policy copy. Standalone callers
/// instead reach this API through the remote `IamClient`.
impl IamClient for AuthzApi {
    fn authorize(&self, request: AuthorizationRequest) -> AuthorizationDecision {
        self.authorize(&request).decision
    }

    fn check_entitlement(&self, request: EntitlementRequest) -> EntitlementDecision {
        self.check_entitlement(&request).decision
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
    fn authorize_surfaces_the_obligation_on_require_approval() {
        let mut api = AuthzApi::new();
        api.policy_mut().add_grant(Grant {
            id: GrantId("g_gate".into()),
            subject: GrantSubject::Principal(service("svc")),
            action_pattern: ActionPattern("pack.publish".into()),
            scope: ScopeRef::Global,
            effect: Effect::RequireApproval,
        });
        let outcome = api.authorize(&request(service("svc"), "pack.publish", ScopeRef::Global));
        assert_eq!(outcome.decision, AuthorizationDecision::RequireApproval);
        assert_eq!(outcome.reason, "needs_approval");
        let obligation = outcome.obligation.expect("require_approval carries one");
        assert_eq!(obligation.policy_id, "g_gate");
        assert_eq!(obligation.authority.scope, ScopeRef::Global);
        assert!(obligation.obligation_id.starts_with("obl_"));

        // The discharge seam is the obligation, not a re-query: asking authorize
        // again yields the very same obligation id rather than a fresh one.
        let again = api.authorize(&request(service("svc"), "pack.publish", ScopeRef::Global));
        assert_eq!(
            again.obligation.map(|o| o.obligation_id),
            Some(obligation.obligation_id)
        );
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
        // A require-approval grant so the obligation envelope is exercised too.
        api.policy_mut().add_grant(Grant {
            id: GrantId("g_gate".into()),
            subject: GrantSubject::Principal(service("svc")),
            action_pattern: ActionPattern("pack.publish".into()),
            scope: ScopeRef::Global,
            effect: Effect::RequireApproval,
        });
        let snapshot = api.snapshot();
        let local = PolicySet::from_snapshot(&snapshot);

        for action in ["pack.publish", "pack.read", "image.push"] {
            let req = request(service("svc"), action, ScopeRef::Global);
            // Local evaluation from the synced snapshot mirrors the remote answer,
            // obligation id and all — the id is content-addressed, not minted.
            assert_eq!(local.evaluate(&req).to_outcome(), api.authorize(&req));
        }
        // The publish question really does resolve to an obligation-bearing
        // require-approval, so the equality above is meaningful, not vacuous.
        let publish = api.authorize(&request(service("svc"), "pack.publish", ScopeRef::Global));
        assert_eq!(publish.decision, AuthorizationDecision::RequireApproval);
        assert!(publish.obligation.is_some());
    }

    #[test]
    fn signers_are_served_under_the_version_fence() {
        use awaken_iam_contract::{
            NamespaceId, NamespaceOwner, OrgId, SignerKey, SignerKeyAlgorithm,
            SignerKeyFingerprint, SignerKeyId, SignerKeyStatus, Timestamp,
        };

        let namespace = NamespaceId("acme".into());
        let ts = |value: &str| Timestamp(value.into());
        let key = |id: &str, fingerprint: &str| SignerKey {
            id: SignerKeyId(id.into()),
            namespace_id: namespace.clone(),
            fingerprint: SignerKeyFingerprint(fingerprint.into()),
            algorithm: SignerKeyAlgorithm::Ed25519,
            public_key: "base64-public-key".into(),
            status: SignerKeyStatus::Active,
            label: None,
            registered_at: ts("2026-06-20T00:00:00Z"),
            revoked_at: None,
        };

        let mut api = AuthzApi::new();
        // An unowned namespace yields an empty set at the current fence.
        assert_eq!(api.signers(&namespace).signers, vec![]);
        assert_eq!(api.signers(&namespace).version, 1);

        // Establishing ownership and registering keys advances the fence each time.
        api.trust_mut().set_namespace_owner(NamespaceOwner {
            namespace_id: namespace.clone(),
            owner_org_id: OrgId("org_acme".into()),
            created_at: ts("2026-06-20T00:00:00Z"),
        });
        api.trust_mut()
            .register_signer_key(key("key_b", "fp_b"))
            .unwrap();
        api.trust_mut()
            .register_signer_key(key("key_a", "fp_a"))
            .unwrap();

        let set = api.signers(&namespace);
        assert_eq!(set.namespace_id, namespace);
        // Fence advanced from 1 across the three trust mutations.
        assert_eq!(set.version, 4);
        // Active signers come back ordered by id, only public material carried.
        let ids: Vec<&str> = set.signers.iter().map(|k| k.id.0.as_str()).collect();
        assert_eq!(ids, vec!["key_a", "key_b"]);

        // Revoking a key advances the fence and drops it from the served set.
        api.trust_mut()
            .revoke_signer_key(
                &namespace,
                &SignerKeyId("key_a".into()),
                ts("2026-06-21T00:00:00Z"),
            )
            .unwrap();
        let after = api.signers(&namespace);
        assert_eq!(after.version, 5);
        let ids: Vec<&str> = after.signers.iter().map(|k| k.id.0.as_str()).collect();
        assert_eq!(ids, vec!["key_b"]);
    }
}
