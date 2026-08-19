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
//! | `POST /v1/authz/resource-model` | [`AuthzApi::register_resource_model`] |
//! | `GET /v1/authz/snapshot` | [`AuthzApi::snapshot`] |
//! | `POST /v1/tokens/introspect` | [`AuthzApi::introspect_token`] |
//!
//! Authorization and entitlement are held as independent planes: grant
//! evaluation lives in [`IamCore`] and never consults the
//! [`EntitlementEngine`], and the engine never consults grants. The policy
//! snapshot is authorization-only; entitlement is always evaluated live so a
//! plan or billing change takes effect without a re-sync.

use awaken_iam_client::IamClient;
use awaken_iam_contract::{
    ApiToken, ApiTokenStatus, AuthorizationDecision, AuthorizationOutcome, AuthorizationRequest,
    BatchAuthorizationRequest, BatchAuthorizationResponse, EntitlementCheckResponse,
    EntitlementDecision, EntitlementRequest, NamespaceId, PolicySnapshot, ResourceModelRegistered,
    ResourceModelRegistration, SignerSetSnapshot, Timestamp, TokenIntrospectionRequest,
    TokenIntrospectionResponse,
};
use awaken_iam_core::{
    ApiTokenDirectory, EntitlementEngine, EntitlementProvider, IamCore, IamError,
    NamespaceTrustDirectory, PolicySet, ResourceModel,
};

/// Failure returned by [`AuthzApi::introspect_token`].
///
/// Any of these outcomes yields `401 Unauthorized` over HTTP — the caller learns
/// only that the credential does not authenticate, never which branch failed, so
/// a probing attacker cannot distinguish an unknown prefix from a wrong secret.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum IntrospectionError {
    /// Token is syntactically invalid, refers to an unknown prefix, or the
    /// secret does not match the stored hash.
    #[error("token is invalid")]
    Invalid,
    /// Token has been explicitly revoked and can no longer authenticate.
    #[error("token has been revoked")]
    Revoked,
    /// Token has passed its expiration timestamp.
    #[error("token has expired")]
    Expired,
}

impl From<IamError> for IntrospectionError {
    fn from(err: IamError) -> Self {
        match err {
            IamError::ApiTokenRevoked { .. } => IntrospectionError::Revoked,
            IamError::ApiTokenExpired { .. } => IntrospectionError::Expired,
            _ => IntrospectionError::Invalid,
        }
    }
}

/// Authorization/entitlement protocol surface over an in-process [`IamCore`], an
/// injectable [`EntitlementProvider`], and namespace [`NamespaceTrustDirectory`].
///
/// Also holds an in-memory [`ApiTokenDirectory`] for the token-introspection
/// plane: API tokens registered via [`register_api_token`](AuthzApi::register_api_token)
/// are verified by `POST /v1/tokens/introspect` so the consumer never holds the
/// `secret_hash` and never re-implements the argon2id check.
#[derive(Debug)]
pub struct AuthzApi {
    core: IamCore,
    entitlements: Box<dyn EntitlementProvider>,
    trust: NamespaceTrustDirectory,
    policy_version: u64,
    api_tokens: ApiTokenDirectory,
}

impl Default for AuthzApi {
    fn default() -> Self {
        Self::new()
    }
}

impl AuthzApi {
    /// Build an API with an empty default-deny policy and an unlicensed,
    /// fail-closed commercial entitlement plane at policy version 1.
    pub fn new() -> Self {
        Self {
            core: IamCore::new(),
            entitlements: Box::new(EntitlementEngine::unlicensed()),
            trust: NamespaceTrustDirectory::new(),
            policy_version: 1,
            api_tokens: ApiTokenDirectory::new(),
        }
    }

    /// Build an API with a specific entitlement provider and an empty
    /// default-deny policy. This is the deploy-time seam: an open
    /// [`EntitlementEngine`] or a closed, licensed provider plugs in here.
    pub fn with_entitlements(entitlements: impl EntitlementProvider + 'static) -> Self {
        Self {
            core: IamCore::new(),
            entitlements: Box::new(entitlements),
            trust: NamespaceTrustDirectory::new(),
            policy_version: 1,
            api_tokens: ApiTokenDirectory::new(),
        }
    }

    /// Build an API over an explicit core and entitlement provider.
    pub fn from_parts(core: IamCore, entitlements: impl EntitlementProvider + 'static) -> Self {
        Self {
            core,
            entitlements: Box::new(entitlements),
            trust: NamespaceTrustDirectory::new(),
            policy_version: 1,
            api_tokens: ApiTokenDirectory::new(),
        }
    }

    /// Replace the installed entitlement provider in place.
    ///
    /// The deploy-time re-install seam: a host that re-verifies a license on a
    /// cadence (claims expire at their `not_after`) swaps the resolved provider
    /// here without rebuilding the API or disturbing the authorization policy.
    pub fn set_entitlements(&mut self, entitlements: impl EntitlementProvider + 'static) {
        self.entitlements = Box::new(entitlements);
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

    /// Advance the snapshot version without touching the grant policy.
    ///
    /// The seam an administrative mutation applied out-of-band (through the
    /// [`PolicyAdminApi`](crate::PolicyAdminApi) over the same shared state) uses
    /// to signal freshness: a policy-administration change — creating an org,
    /// issuing a grant — must move the fence a synced consumer polls
    /// [`snapshot`](Self::snapshot) against, even when it does not edit the
    /// in-memory grant set this engine evaluates. Returns the new version.
    pub fn bump_policy_version(&mut self) -> u64 {
        self.policy_version += 1;
        self.policy_version
    }

    /// Replace the live evaluator with repository-backed policy at `version`.
    ///
    /// Administrative handlers call this only after their durable mutation and
    /// fence commit succeed. The exact returned fence therefore identifies the
    /// policy the PDP is already able to evaluate; merely bumping a counter
    /// while leaving the old policy installed is forbidden.
    pub fn replace_policy_at_version(&mut self, policy: PolicySet, version: u64) {
        self.core.replace_policy(policy);
        self.policy_version = version;
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

    /// `POST /v1/authz/resource-model`: register a consumer's
    /// [`ResourceModel`](awaken_iam_core::ResourceModel) — its resource types,
    /// action catalog, and per-instance scope parent edges — so the evaluator
    /// resolves the product's open [`ScopeRef::Resource`](awaken_iam_contract::ScopeRef::Resource)
    /// scopes through the same ancestor walk used for the well-known scopes.
    ///
    /// Registration folds the model's parent edges into the policy's scope graph
    /// and bumps the snapshot version, so a local-mode consumer re-syncs and
    /// resolves the same ancestry in-process on its next poll. Re-registering is
    /// additive and idempotent (a repeated instance edge replaces that instance's
    /// parent). Returns the policy version the registration advanced to.
    pub fn register_resource_model(
        &mut self,
        registration: &ResourceModelRegistration,
    ) -> ResourceModelRegistered {
        let model = ResourceModel::from_registration(registration);
        self.policy_mut().register_resource_model(&model);
        ResourceModelRegistered {
            version: self.policy_version,
        }
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

    /// Register an API token row in the in-memory directory so it can be
    /// verified by [`introspect_token`](Self::introspect_token).
    ///
    /// Called at daemon startup (loading from the SQL store) and on every
    /// successful token mint. A duplicate id or prefix is silently ignored:
    /// idempotency here matches the store's upsert semantics and lets a restart
    /// replay the load without failing.
    pub fn register_api_token(&mut self, token: ApiToken) {
        let _ = self.api_tokens.create(token);
    }

    /// `POST /v1/tokens/introspect`: verify a bearer API token and resolve its
    /// `principal` + `workspace` binding at `now`.
    ///
    /// Performs the full argon2id secret verification and liveness check
    /// (revocation and expiry) in IAM so the consumer never holds `secret_hash`
    /// and never re-implements the verification logic. An unknown prefix, a
    /// wrong secret, a revoked token, or an expired token all map to
    /// [`IntrospectionError`]; the HTTP layer translates every variant to
    /// `401 Unauthorized` so a caller cannot distinguish which branch failed.
    pub fn introspect_token(
        &self,
        request: &TokenIntrospectionRequest,
        now: &Timestamp,
    ) -> Result<TokenIntrospectionResponse, IntrospectionError> {
        let token = self
            .api_tokens
            .authenticate(&request.token, now)
            .map_err(IntrospectionError::from)?;
        Ok(TokenIntrospectionResponse {
            principal: token.principal.clone(),
            workspace: token.workspace.clone(),
            status: ApiTokenStatus::Active,
        })
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
    fn registering_a_resource_model_lets_authorize_resolve_open_scopes() {
        use awaken_iam_contract::{
            ProjectId, ResourceId, ResourceModelRegistration, ResourceParentEdge, ResourceType,
            ResourceTypeRegistration, WorkspaceId,
        };

        let mut api = AuthzApi::new();
        let before = api.policy_version();

        // A consumer teaches IAM its hierarchy as data: issue:42 nests under a
        // project. The registration advances the snapshot version.
        let registered = api.register_resource_model(&ResourceModelRegistration {
            resource_types: vec![ResourceTypeRegistration {
                resource_type: ResourceType("issue".into()),
                parent_type: None,
                actions: vec![ActionKey("issue.close".into())],
            }],
            actions: Vec::new(),
            edges: vec![ResourceParentEdge {
                resource_type: ResourceType("issue".into()),
                resource_id: ResourceId("42".into()),
                parent: ScopeRef::Project {
                    workspace_id: WorkspaceId("ws_main".into()),
                    project_id: ProjectId("proj_web".into()),
                },
            }],
        });
        assert_eq!(registered.version, before + 1);
        assert_eq!(api.policy_version(), before + 1);

        // A grant anchored at the project now covers the issue resource through
        // the registered edge — the open scope resolves up to its ancestor.
        api.policy_mut().add_grant(Grant {
            id: GrantId("g_proj".into()),
            subject: GrantSubject::Principal(service("svc")),
            action_pattern: ActionPattern("issue.*".into()),
            scope: ScopeRef::Project {
                workspace_id: WorkspaceId("ws_main".into()),
                project_id: ProjectId("proj_web".into()),
            },
            effect: Effect::Allow,
        });
        let outcome = api.authorize(&request(
            service("svc"),
            "issue.close",
            ScopeRef::Resource {
                resource_type: ResourceType("issue".into()),
                resource_id: ResourceId("42".into()),
            },
        ));
        assert_eq!(outcome.decision, AuthorizationDecision::Allow);

        // The registered edge rides the snapshot so a synced consumer resolves
        // the same ancestry in-process.
        let snapshot = api.snapshot();
        assert_eq!(
            snapshot.scope_graph.resource_parents,
            vec![ResourceParentEdge {
                resource_type: ResourceType("issue".into()),
                resource_id: ResourceId("42".into()),
                parent: ScopeRef::Project {
                    workspace_id: WorkspaceId("ws_main".into()),
                    project_id: ProjectId("proj_web".into()),
                },
            }]
        );
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

    #[test]
    fn introspect_token_resolves_principal_and_workspace_for_a_live_token() {
        use awaken_iam_contract::{
            ApiTokenId, ApiTokenStatus, Timestamp, TokenIntrospectionRequest, WorkspaceId,
        };
        use awaken_iam_core::{
            ApiTokenDirectory, ApiTokenMinter, EntropySource, MintApiToken, PolicySet, RoleId,
        };

        struct SequentialEntropy {
            next: u8,
        }
        impl EntropySource for SequentialEntropy {
            fn fill_bytes(&mut self, buf: &mut [u8]) {
                for byte in buf.iter_mut() {
                    *byte = self.next;
                    self.next = self.next.wrapping_add(1);
                }
            }
        }

        let mut minter = ApiTokenMinter::new(SequentialEntropy { next: 0 });
        let mut directory = ApiTokenDirectory::new();
        let mut policy = PolicySet::new();
        let workspace = WorkspaceId("wrkspc_test".into());
        let issued = minter
            .mint(
                &mut directory,
                &mut policy,
                MintApiToken {
                    id: ApiTokenId("tok_introspect".into()),
                    principal: PrincipalRef::Service {
                        service_id: "ci".into(),
                    },
                    workspace: workspace.clone(),
                    role: RoleId("workspace_developer".into()),
                    created_at: Timestamp("2026-06-19T00:00:00Z".into()),
                    expires_at: None,
                },
            )
            .unwrap();

        // Load the token into the AuthzApi's directory.
        let mut api = AuthzApi::new();
        api.register_api_token(issued.token.clone());

        let request = TokenIntrospectionRequest {
            token: issued.secret.clone(),
        };
        let now = Timestamp("2026-06-19T12:00:00Z".into());
        let response = api.introspect_token(&request, &now).unwrap();

        assert_eq!(
            response.principal,
            PrincipalRef::Service {
                service_id: "ci".into()
            }
        );
        assert_eq!(response.workspace, workspace);
        assert_eq!(response.status, ApiTokenStatus::Active);
    }

    #[test]
    fn introspect_token_returns_invalid_for_unknown_or_wrong_secret() {
        use awaken_iam_contract::{Timestamp, TokenIntrospectionRequest};

        let api = AuthzApi::new();
        let now = Timestamp("2026-06-19T12:00:00Z".into());
        let err = api
            .introspect_token(
                &TokenIntrospectionRequest {
                    token: String::from("sk-awaken-ZZZZZZZZ.deadbeef"),
                },
                &now,
            )
            .unwrap_err();
        assert_eq!(err, IntrospectionError::Invalid);
    }

    #[test]
    fn register_api_token_is_idempotent() {
        use awaken_iam_contract::{ApiToken, ApiTokenId, ApiTokenPrefix, Timestamp, WorkspaceId};

        let token = ApiToken {
            id: ApiTokenId("tok_idem".into()),
            prefix: ApiTokenPrefix("pfx_idem".into()),
            principal: PrincipalRef::Service {
                service_id: "svc".into(),
            },
            secret_hash: "$argon2id$v=19$m=19456,t=2,p=1$AAAAAAAAAAAAAAAAAAAAAA$AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA".into(),
            workspace: WorkspaceId("ws".into()),
            created_at: Timestamp("2026-06-19T00:00:00Z".into()),
            expires_at: None,
            revoked_at: None,
        };
        let mut api = AuthzApi::new();
        api.register_api_token(token.clone());
        // Registering the same token a second time is a no-op, not a panic.
        api.register_api_token(token);
    }
}
