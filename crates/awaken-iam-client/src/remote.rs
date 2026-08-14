//! Remote IAM client and the local/remote mode switch.
//!
//! Product services delegate IAM decisions through [`IamClient`]. A deployment
//! chooses, per the `[iam] mode = "local" | "remote"` configuration described in
//! `docs/design/remote-protocol.md`, whether those calls resolve in-process
//! (local mode) or over the wire (remote mode). [`IamClientMode`] is the switch:
//! it wraps either an in-process [`IamClient`] or a [`RemoteIamClient`] and
//! implements [`IamClient`] itself, so call sites are identical in both modes.
//!
//! Byte transport for remote mode lives behind the [`AuthzTransport`] seam — a
//! deployment supplies the HTTP client, while this crate owns request shaping,
//! response mapping, and the fail-closed contract. Authorization fails closed:
//! when the remote transport errors or times out, the client denies (it never
//! silently widens access to an allow).

use awaken_iam_contract::{
    AcceptInvitation, AcceptedInvitation, ActivateAuthorizationProfile, AdminMutationAck,
    AuthorizationDecision, AuthorizationOutcome, AuthorizationProfile,
    AuthorizationProfileActivated, AuthorizationProfileRetired, AuthorizationProfileValidation,
    AuthorizationRequest, BatchAuthorizationRequest, BatchAuthorizationResponse,
    CreateAuthorizationProfile, CreateInvitation, EntitlementCheckResponse, EntitlementDecision,
    EntitlementRequest, GrantSnapshot, InvitationDto, InvitationId, InvitationQuery,
    IssuedInvitation, MembershipQuery, NamespaceId, OrgDto, PolicySnapshot, ResendInvitation,
    ResourceModelRegistered, ResourceModelRegistration, RetireAuthorizationProfile,
    RoleBindingSnapshot, RoleDto, ScopeMembershipQuery, SignerSetSnapshot,
    TokenIntrospectionRequest, TokenIntrospectionResponse, UserInfo, WorkspaceOrgEdge,
};

use crate::IamClient;

/// Failure reported by an [`AuthzTransport`] implementation.
///
/// Covers transport-level problems (connection, status, decode) uniformly; the
/// authorization/entitlement *decisions* themselves are carried in the response
/// DTOs, not in this error.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("iam remote transport failed: {0}")]
pub struct RemoteError(pub String);

/// Byte-transport seam for the remote authorization protocol.
///
/// Implementors own the HTTP client and the deployment's `base_url`, audience,
/// and timeout. Keeping transport behind a trait lets the client logic (request
/// shaping, decision mapping, fail-closed policy) be unit tested without network
/// access. Implementations should be `Send + Sync` so the client can be shared.
pub trait AuthzTransport {
    /// `POST /v1/authorize`.
    fn authorize(
        &self,
        request: &AuthorizationRequest,
    ) -> Result<AuthorizationOutcome, RemoteError>;

    /// `POST /v1/authorize/batch`.
    fn authorize_batch(
        &self,
        request: &BatchAuthorizationRequest,
    ) -> Result<BatchAuthorizationResponse, RemoteError>;

    /// `POST /v1/entitlements/check`.
    fn check_entitlement(
        &self,
        request: &EntitlementRequest,
    ) -> Result<EntitlementCheckResponse, RemoteError>;

    /// `POST /v1/authz/resource-model`.
    fn register_resource_model(
        &self,
        registration: &ResourceModelRegistration,
    ) -> Result<ResourceModelRegistered, RemoteError>;

    /// `GET /v1/authz/snapshot`.
    fn fetch_snapshot(&self) -> Result<PolicySnapshot, RemoteError>;

    /// `GET /v1/namespaces/{namespace_id}/signers`.
    fn fetch_signers(&self, namespace_id: &NamespaceId) -> Result<SignerSetSnapshot, RemoteError>;
    /// `GET /v1/authz/snapshot?since={since}`: fetch the snapshot only when the
    /// policy has advanced past `since`, so a synced consumer can skip an
    /// unchanged payload on the version fence.
    ///
    /// The default implementation fetches the full snapshot and filters by
    /// version locally; a transport whose backend honours `since` should
    /// override this to skip the payload on the wire.
    fn fetch_snapshot_since(&self, since: u64) -> Result<Option<PolicySnapshot>, RemoteError> {
        let snapshot = self.fetch_snapshot()?;
        Ok((snapshot.version > since).then_some(snapshot))
    }

    /// `POST /v1/tokens/introspect`: verify a bearer API token and resolve its
    /// `principal` + `workspace` binding at the server's current wall clock.
    ///
    /// Returns `Err` when the token is invalid, revoked, or expired — the caller
    /// never learns which branch; from its side the credential simply does not
    /// authenticate. Token verification (argon2id) stays in IAM; this transport
    /// method is the seam that keeps consumers from re-implementing it.
    ///
    /// The default implementation returns an unsupported error so existing
    /// transports remain valid without providing the new method until they opt in.
    fn introspect_token(
        &self,
        request: &TokenIntrospectionRequest,
    ) -> Result<TokenIntrospectionResponse, RemoteError> {
        let _ = request;
        Err(RemoteError(
            "introspect_token is not supported by this transport".into(),
        ))
    }

    fn create_org(&self, _org: &OrgDto) -> Result<AdminMutationAck, RemoteError> {
        Err(RemoteError("organization PAP is not supported".into()))
    }

    fn list_orgs(&self) -> Result<Vec<OrgDto>, RemoteError> {
        Err(RemoteError("organization PAP is not supported".into()))
    }

    fn get_org(&self, _org_id: &str) -> Result<Option<OrgDto>, RemoteError> {
        Err(RemoteError("organization PAP is not supported".into()))
    }

    fn create_role(&self, _role: &RoleDto) -> Result<AdminMutationAck, RemoteError> {
        Err(RemoteError("role PAP is not supported".into()))
    }

    fn get_role(&self, _role_id: &str) -> Result<Option<RoleDto>, RemoteError> {
        Err(RemoteError("role PAP is not supported".into()))
    }

    fn issue_grant(&self, _grant: &GrantSnapshot) -> Result<AdminMutationAck, RemoteError> {
        Err(RemoteError("grant PAP is not supported".into()))
    }

    fn get_grant(&self, _grant_id: &str) -> Result<Option<GrantSnapshot>, RemoteError> {
        Err(RemoteError("grant PAP is not supported".into()))
    }

    fn grant_membership(
        &self,
        _binding: &RoleBindingSnapshot,
    ) -> Result<AdminMutationAck, RemoteError> {
        Err(RemoteError("membership PAP is not supported".into()))
    }

    fn revoke_membership(
        &self,
        _binding: &RoleBindingSnapshot,
    ) -> Result<AdminMutationAck, RemoteError> {
        Err(RemoteError("membership PAP is not supported".into()))
    }

    fn memberships_for_principal(
        &self,
        _query: &MembershipQuery,
    ) -> Result<Vec<RoleBindingSnapshot>, RemoteError> {
        Err(RemoteError("membership PAP is not supported".into()))
    }

    fn memberships_for_scope(
        &self,
        _query: &ScopeMembershipQuery,
    ) -> Result<Vec<RoleBindingSnapshot>, RemoteError> {
        Err(RemoteError("membership PAP is not supported".into()))
    }

    fn create_invitation(
        &self,
        _request: &CreateInvitation,
    ) -> Result<IssuedInvitation, RemoteError> {
        Err(RemoteError("invitation PAP is not supported".into()))
    }

    fn list_invitations(
        &self,
        _query: &InvitationQuery,
    ) -> Result<Vec<InvitationDto>, RemoteError> {
        Err(RemoteError("invitation PAP is not supported".into()))
    }

    fn revoke_invitation(&self, _id: &InvitationId) -> Result<AdminMutationAck, RemoteError> {
        Err(RemoteError("invitation PAP is not supported".into()))
    }

    fn resend_invitation(
        &self,
        _id: &InvitationId,
        _request: &ResendInvitation,
    ) -> Result<IssuedInvitation, RemoteError> {
        Err(RemoteError("invitation PAP is not supported".into()))
    }

    fn accept_invitation(
        &self,
        _id: &InvitationId,
        _request: &AcceptInvitation,
    ) -> Result<AcceptedInvitation, RemoteError> {
        Err(RemoteError("invitation PAP is not supported".into()))
    }

    /// Resolve verified OIDC claims from an end-user access token.
    fn userinfo(&self, _access_token: &str) -> Result<UserInfo, RemoteError> {
        Err(RemoteError("userinfo is not supported".into()))
    }

    fn assign_workspace_org(
        &self,
        _edge: &WorkspaceOrgEdge,
    ) -> Result<AdminMutationAck, RemoteError> {
        Err(RemoteError("scope projection PAP is not supported".into()))
    }

    fn create_profile(
        &self,
        _request: &CreateAuthorizationProfile,
    ) -> Result<AuthorizationProfile, RemoteError> {
        Err(RemoteError(
            "authorization profile PAP is not supported".into(),
        ))
    }

    fn validate_profile(
        &self,
        _namespace: &NamespaceId,
        _revision: u64,
    ) -> Result<AuthorizationProfileValidation, RemoteError> {
        Err(RemoteError(
            "authorization profile PAP is not supported".into(),
        ))
    }

    fn activate_profile(
        &self,
        _namespace: &NamespaceId,
        _revision: u64,
        _request: &ActivateAuthorizationProfile,
    ) -> Result<AuthorizationProfileActivated, RemoteError> {
        Err(RemoteError(
            "authorization profile PAP is not supported".into(),
        ))
    }

    fn rollback_profile(
        &self,
        _namespace: &NamespaceId,
        _revision: u64,
        _request: &ActivateAuthorizationProfile,
    ) -> Result<AuthorizationProfileActivated, RemoteError> {
        Err(RemoteError(
            "authorization profile PAP is not supported".into(),
        ))
    }

    fn retire_profile(
        &self,
        _namespace: &NamespaceId,
        _request: &RetireAuthorizationProfile,
    ) -> Result<AuthorizationProfileRetired, RemoteError> {
        Err(RemoteError(
            "authorization profile PAP is not supported".into(),
        ))
    }

    fn active_profile(
        &self,
        _namespace: &NamespaceId,
    ) -> Result<AuthorizationProfile, RemoteError> {
        Err(RemoteError(
            "authorization profile PAP is not supported".into(),
        ))
    }
}

/// IAM client that resolves decisions over the remote protocol.
///
/// Generic over the [`AuthzTransport`] seam so a deployment injects its HTTP
/// client while tests inject a deterministic fake. The reasoned `*_outcome`
/// accessors surface transport errors to callers that want to handle them; the
/// [`IamClient`] trait methods instead fail closed to a deny so a transport
/// outage can never widen access.
#[derive(Debug, Clone)]
pub struct RemoteIamClient<T> {
    transport: T,
}

impl<T> RemoteIamClient<T> {
    /// Build a remote client over the given transport.
    pub fn new(transport: T) -> Self {
        Self { transport }
    }

    /// Borrow the underlying transport.
    pub fn transport(&self) -> &T {
        &self.transport
    }
}

impl<T: AuthzTransport> RemoteIamClient<T> {
    /// Resolve one authorization request into its reasoned outcome, surfacing
    /// transport errors.
    pub fn authorize_outcome(
        &self,
        request: &AuthorizationRequest,
    ) -> Result<AuthorizationOutcome, RemoteError> {
        self.transport.authorize(request)
    }

    /// Resolve a batch of authorization requests, surfacing transport errors.
    pub fn authorize_batch(
        &self,
        request: &BatchAuthorizationRequest,
    ) -> Result<BatchAuthorizationResponse, RemoteError> {
        self.transport.authorize_batch(request)
    }

    /// Resolve an entitlement request into its reasoned response, surfacing
    /// transport errors.
    pub fn check_entitlement_response(
        &self,
        request: &EntitlementRequest,
    ) -> Result<EntitlementCheckResponse, RemoteError> {
        self.transport.check_entitlement(request)
    }

    /// Register a consumer's resource model so the server resolves its open
    /// resource scopes, surfacing transport errors. Returns the policy version
    /// the registration advanced to.
    pub fn register_resource_model(
        &self,
        registration: &ResourceModelRegistration,
    ) -> Result<ResourceModelRegistered, RemoteError> {
        self.transport.register_resource_model(registration)
    }

    /// Fetch the current authorization policy snapshot for local-mode caching.
    pub fn fetch_snapshot(&self) -> Result<PolicySnapshot, RemoteError> {
        self.transport.fetch_snapshot()
    }

    /// Fetch a namespace's active signer set for trust-root distribution,
    /// surfacing transport errors. The set carries the same version fence as the
    /// policy snapshot, so a consumer caches it and re-syncs when the fence moves.
    pub fn fetch_signers(
        &self,
        namespace_id: &NamespaceId,
    ) -> Result<SignerSetSnapshot, RemoteError> {
        self.transport.fetch_signers(namespace_id)
    }

    /// Verify a bearer API token against the remote IAM server and resolve its
    /// `principal` + `workspace`.
    ///
    /// Delegates to `POST /v1/tokens/introspect` via the transport. Returns `Err`
    /// on an invalid/expired/revoked token or a transport failure. Token
    /// verification (argon2id) stays in IAM — the consumer never holds the
    /// `secret_hash` and never re-implements the check.
    pub fn introspect_token(
        &self,
        request: &TokenIntrospectionRequest,
    ) -> Result<TokenIntrospectionResponse, RemoteError> {
        self.transport.introspect_token(request)
    }

    pub fn create_org(&self, org: &OrgDto) -> Result<AdminMutationAck, RemoteError> {
        self.transport.create_org(org)
    }

    pub fn list_orgs(&self) -> Result<Vec<OrgDto>, RemoteError> {
        self.transport.list_orgs()
    }

    pub fn get_org(&self, org_id: &str) -> Result<Option<OrgDto>, RemoteError> {
        self.transport.get_org(org_id)
    }

    pub fn create_role(&self, role: &RoleDto) -> Result<AdminMutationAck, RemoteError> {
        self.transport.create_role(role)
    }

    pub fn get_role(&self, role_id: &str) -> Result<Option<RoleDto>, RemoteError> {
        self.transport.get_role(role_id)
    }

    pub fn issue_grant(&self, grant: &GrantSnapshot) -> Result<AdminMutationAck, RemoteError> {
        self.transport.issue_grant(grant)
    }

    pub fn get_grant(&self, grant_id: &str) -> Result<Option<GrantSnapshot>, RemoteError> {
        self.transport.get_grant(grant_id)
    }

    pub fn grant_membership(
        &self,
        binding: &RoleBindingSnapshot,
    ) -> Result<AdminMutationAck, RemoteError> {
        self.transport.grant_membership(binding)
    }

    pub fn revoke_membership(
        &self,
        binding: &RoleBindingSnapshot,
    ) -> Result<AdminMutationAck, RemoteError> {
        self.transport.revoke_membership(binding)
    }

    pub fn memberships_for_principal(
        &self,
        query: &MembershipQuery,
    ) -> Result<Vec<RoleBindingSnapshot>, RemoteError> {
        self.transport.memberships_for_principal(query)
    }

    pub fn memberships_for_scope(
        &self,
        query: &ScopeMembershipQuery,
    ) -> Result<Vec<RoleBindingSnapshot>, RemoteError> {
        self.transport.memberships_for_scope(query)
    }

    pub fn create_invitation(
        &self,
        request: &CreateInvitation,
    ) -> Result<IssuedInvitation, RemoteError> {
        self.transport.create_invitation(request)
    }

    pub fn list_invitations(
        &self,
        query: &InvitationQuery,
    ) -> Result<Vec<InvitationDto>, RemoteError> {
        self.transport.list_invitations(query)
    }

    pub fn revoke_invitation(&self, id: &InvitationId) -> Result<AdminMutationAck, RemoteError> {
        self.transport.revoke_invitation(id)
    }

    pub fn resend_invitation(
        &self,
        id: &InvitationId,
        request: &ResendInvitation,
    ) -> Result<IssuedInvitation, RemoteError> {
        self.transport.resend_invitation(id, request)
    }

    pub fn accept_invitation(
        &self,
        id: &InvitationId,
        request: &AcceptInvitation,
    ) -> Result<AcceptedInvitation, RemoteError> {
        self.transport.accept_invitation(id, request)
    }

    pub fn userinfo(&self, access_token: &str) -> Result<UserInfo, RemoteError> {
        self.transport.userinfo(access_token)
    }

    pub fn assign_workspace_org(
        &self,
        edge: &WorkspaceOrgEdge,
    ) -> Result<AdminMutationAck, RemoteError> {
        self.transport.assign_workspace_org(edge)
    }

    pub fn create_profile(
        &self,
        request: &CreateAuthorizationProfile,
    ) -> Result<AuthorizationProfile, RemoteError> {
        self.transport.create_profile(request)
    }

    pub fn validate_profile(
        &self,
        namespace: &NamespaceId,
        revision: u64,
    ) -> Result<AuthorizationProfileValidation, RemoteError> {
        self.transport.validate_profile(namespace, revision)
    }

    pub fn activate_profile(
        &self,
        namespace: &NamespaceId,
        revision: u64,
        request: &ActivateAuthorizationProfile,
    ) -> Result<AuthorizationProfileActivated, RemoteError> {
        self.transport
            .activate_profile(namespace, revision, request)
    }

    pub fn rollback_profile(
        &self,
        namespace: &NamespaceId,
        revision: u64,
        request: &ActivateAuthorizationProfile,
    ) -> Result<AuthorizationProfileActivated, RemoteError> {
        self.transport
            .rollback_profile(namespace, revision, request)
    }

    pub fn retire_profile(
        &self,
        namespace: &NamespaceId,
        request: &RetireAuthorizationProfile,
    ) -> Result<AuthorizationProfileRetired, RemoteError> {
        self.transport.retire_profile(namespace, request)
    }

    pub fn active_profile(
        &self,
        namespace: &NamespaceId,
    ) -> Result<AuthorizationProfile, RemoteError> {
        self.transport.active_profile(namespace)
    }
}

impl<T: AuthzTransport> IamClient for RemoteIamClient<T> {
    fn authorize(&self, request: AuthorizationRequest) -> AuthorizationDecision {
        self.transport
            .authorize(&request)
            .map(|outcome| outcome.decision)
            .unwrap_or(AuthorizationDecision::Deny)
    }

    fn check_entitlement(&self, request: EntitlementRequest) -> EntitlementDecision {
        self.transport
            .check_entitlement(&request)
            .map(|response| response.decision)
            .unwrap_or(EntitlementDecision::Deny)
    }
}

/// The `local | remote` IAM mode switch.
///
/// Wraps either an in-process [`IamClient`] (`L`) or a remote one (`R`) and
/// implements [`IamClient`] by dispatching to whichever is selected, so a
/// product service binds to one type regardless of deployment mode. Local mode
/// is an explicit policy, not a permissive fallback: it never substitutes for an
/// unreachable remote.
#[derive(Debug, Clone)]
pub enum IamClientMode<L, R> {
    /// Resolve decisions in-process.
    Local(L),
    /// Resolve decisions over the remote protocol.
    Remote(R),
}

impl<L, R> IamClientMode<L, R> {
    /// Whether this switch is in local mode.
    pub fn is_local(&self) -> bool {
        matches!(self, IamClientMode::Local(_))
    }

    /// Whether this switch is in remote mode.
    pub fn is_remote(&self) -> bool {
        matches!(self, IamClientMode::Remote(_))
    }
}

impl<L: IamClient, R: IamClient> IamClient for IamClientMode<L, R> {
    fn authorize(&self, request: AuthorizationRequest) -> AuthorizationDecision {
        match self {
            IamClientMode::Local(client) => client.authorize(request),
            IamClientMode::Remote(client) => client.authorize(request),
        }
    }

    fn check_entitlement(&self, request: EntitlementRequest) -> EntitlementDecision {
        match self {
            IamClientMode::Local(client) => client.check_entitlement(request),
            IamClientMode::Remote(client) => client.check_entitlement(request),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use awaken_iam_contract::{AccountId, ActionKey, PrincipalRef, ScopeRef};
    use std::cell::Cell;

    fn auth_request(action: &str) -> AuthorizationRequest {
        AuthorizationRequest::direct(
            PrincipalRef::Account {
                account_id: AccountId("acct_1".into()),
            },
            ActionKey(action.into()),
            ScopeRef::Global,
        )
    }

    fn ent_request() -> EntitlementRequest {
        EntitlementRequest {
            principal: PrincipalRef::Account {
                account_id: AccountId("acct_1".into()),
            },
            entitlement: "pack.read".into(),
            resource: None,
        }
    }

    /// Transport that allows `pack.read` and otherwise denies, unless `fail` is
    /// set, in which case every call reports a transport error.
    struct StubTransport {
        fail: bool,
    }

    impl AuthzTransport for StubTransport {
        fn authorize(
            &self,
            request: &AuthorizationRequest,
        ) -> Result<AuthorizationOutcome, RemoteError> {
            if self.fail {
                return Err(RemoteError("boom".into()));
            }
            let allow = request.action == ActionKey("pack.read".into());
            Ok(AuthorizationOutcome {
                decision: if allow {
                    AuthorizationDecision::Allow
                } else {
                    AuthorizationDecision::Deny
                },
                reason: if allow {
                    "allowed_by_grant"
                } else {
                    "default_deny"
                }
                .into(),
                matched_grants: if allow { vec!["g1".into()] } else { vec![] },
                matched_roles: vec![],
                obligation: None,
            })
        }

        fn authorize_batch(
            &self,
            request: &BatchAuthorizationRequest,
        ) -> Result<BatchAuthorizationResponse, RemoteError> {
            if self.fail {
                return Err(RemoteError("boom".into()));
            }
            let mut outcomes = Vec::new();
            for item in &request.requests {
                outcomes.push(self.authorize(item)?);
            }
            Ok(BatchAuthorizationResponse { outcomes })
        }

        fn check_entitlement(
            &self,
            _request: &EntitlementRequest,
        ) -> Result<EntitlementCheckResponse, RemoteError> {
            if self.fail {
                return Err(RemoteError("boom".into()));
            }
            Ok(EntitlementCheckResponse {
                decision: EntitlementDecision::Allow,
                reason: "default_allow".into(),
            })
        }

        fn register_resource_model(
            &self,
            _registration: &ResourceModelRegistration,
        ) -> Result<ResourceModelRegistered, RemoteError> {
            if self.fail {
                return Err(RemoteError("boom".into()));
            }
            Ok(ResourceModelRegistered { version: 5 })
        }

        fn fetch_snapshot(&self) -> Result<PolicySnapshot, RemoteError> {
            if self.fail {
                return Err(RemoteError("boom".into()));
            }
            Ok(PolicySnapshot {
                version: 4,
                ..PolicySnapshot::default()
            })
        }

        fn fetch_signers(
            &self,
            namespace_id: &NamespaceId,
        ) -> Result<SignerSetSnapshot, RemoteError> {
            if self.fail {
                return Err(RemoteError("boom".into()));
            }
            Ok(SignerSetSnapshot {
                namespace_id: namespace_id.clone(),
                version: 4,
                signers: Vec::new(),
            })
        }
    }

    #[test]
    fn remote_client_maps_transport_decisions() {
        let client = RemoteIamClient::new(StubTransport { fail: false });
        assert_eq!(
            client.authorize(auth_request("pack.read")),
            AuthorizationDecision::Allow
        );
        assert_eq!(
            client.authorize(auth_request("pack.delete")),
            AuthorizationDecision::Deny
        );
        assert_eq!(
            client.check_entitlement(ent_request()),
            EntitlementDecision::Allow
        );
        assert_eq!(client.fetch_snapshot().unwrap().version, 4);
        // The signer set is fetched for the requested namespace under the fence.
        let signers = client.fetch_signers(&NamespaceId("acme".into())).unwrap();
        assert_eq!(signers.namespace_id, NamespaceId("acme".into()));
        assert_eq!(signers.version, 4);
    }

    #[test]
    fn remote_client_registers_resource_model_and_surfaces_errors() {
        use awaken_iam_contract::ResourceModelRegistration;

        let client = RemoteIamClient::new(StubTransport { fail: false });
        let registered = client
            .register_resource_model(&ResourceModelRegistration::default())
            .unwrap();
        assert_eq!(registered.version, 5);

        // Registration is not a decision: a transport outage surfaces the error
        // to the caller rather than failing closed to a deny.
        let down = RemoteIamClient::new(StubTransport { fail: true });
        assert_eq!(
            down.register_resource_model(&ResourceModelRegistration::default()),
            Err(RemoteError("boom".into()))
        );
    }

    #[test]
    fn remote_batch_preserves_order() {
        let client = RemoteIamClient::new(StubTransport { fail: false });
        let response = client
            .authorize_batch(&BatchAuthorizationRequest {
                requests: vec![auth_request("pack.read"), auth_request("pack.delete")],
            })
            .unwrap();
        assert_eq!(response.outcomes.len(), 2);
        assert_eq!(response.outcomes[0].decision, AuthorizationDecision::Allow);
        assert_eq!(response.outcomes[1].decision, AuthorizationDecision::Deny);
    }

    #[test]
    fn remote_client_fails_closed_on_transport_error() {
        let client = RemoteIamClient::new(StubTransport { fail: true });
        // A transport outage must never widen access: both planes deny.
        assert_eq!(
            client.authorize(auth_request("pack.read")),
            AuthorizationDecision::Deny
        );
        assert_eq!(
            client.check_entitlement(ent_request()),
            EntitlementDecision::Deny
        );
        // The reasoned accessor still surfaces the error for callers that care.
        assert_eq!(
            client.authorize_outcome(&auth_request("pack.read")),
            Err(RemoteError("boom".into()))
        );
        // The signer fetch surfaces the transport error rather than a stale set.
        assert_eq!(
            client.fetch_signers(&NamespaceId("acme".into())),
            Err(RemoteError("boom".into()))
        );
    }

    /// In-process client used to exercise the local arm of the mode switch.
    struct LocalStub {
        calls: Cell<u32>,
    }

    impl IamClient for LocalStub {
        fn authorize(&self, _request: AuthorizationRequest) -> AuthorizationDecision {
            self.calls.set(self.calls.get() + 1);
            AuthorizationDecision::Allow
        }

        fn check_entitlement(&self, _request: EntitlementRequest) -> EntitlementDecision {
            EntitlementDecision::Allow
        }
    }

    #[test]
    fn mode_switch_dispatches_to_selected_client() {
        let local: IamClientMode<LocalStub, RemoteIamClient<StubTransport>> =
            IamClientMode::Local(LocalStub {
                calls: Cell::new(0),
            });
        assert!(local.is_local());
        assert_eq!(
            local.authorize(auth_request("pack.delete")),
            AuthorizationDecision::Allow
        );

        let remote: IamClientMode<LocalStub, RemoteIamClient<StubTransport>> =
            IamClientMode::Remote(RemoteIamClient::new(StubTransport { fail: false }));
        assert!(remote.is_remote());
        // Remote arm honours the transport's deny for an unknown action.
        assert_eq!(
            remote.authorize(auth_request("pack.delete")),
            AuthorizationDecision::Deny
        );
    }

    #[test]
    fn mode_switch_routes_entitlement_checks_through_both_arms() {
        let local: IamClientMode<LocalStub, RemoteIamClient<StubTransport>> =
            IamClientMode::Local(LocalStub {
                calls: Cell::new(0),
            });
        assert_eq!(
            local.check_entitlement(ent_request()),
            EntitlementDecision::Allow
        );

        let remote: IamClientMode<LocalStub, RemoteIamClient<StubTransport>> =
            IamClientMode::Remote(RemoteIamClient::new(StubTransport { fail: false }));
        assert_eq!(
            remote.check_entitlement(ent_request()),
            EntitlementDecision::Allow
        );
    }

    #[test]
    fn reasoned_accessors_surface_responses_and_borrow_the_transport() {
        let client = RemoteIamClient::new(StubTransport { fail: false });
        // The transport accessor returns the injected seam.
        assert!(!client.transport().fail);
        // The reasoned entitlement accessor surfaces the full response.
        let response = client.check_entitlement_response(&ent_request()).unwrap();
        assert_eq!(response.decision, EntitlementDecision::Allow);
        assert_eq!(response.reason, "default_allow");
    }

    #[test]
    fn batch_and_snapshot_propagate_transport_errors_to_reasoned_callers() {
        let client = RemoteIamClient::new(StubTransport { fail: true });
        assert_eq!(
            client.authorize_batch(&BatchAuthorizationRequest {
                requests: vec![auth_request("pack.read")],
            }),
            Err(RemoteError("boom".into()))
        );
        assert_eq!(client.fetch_snapshot(), Err(RemoteError("boom".into())));
        assert_eq!(
            client.check_entitlement_response(&ent_request()),
            Err(RemoteError("boom".into()))
        );
    }

    #[test]
    fn default_introspect_token_returns_unsupported_error() {
        use awaken_iam_contract::TokenIntrospectionRequest;
        // StubTransport does not override introspect_token; the default impl
        // returns a "not supported" error so existing transports stay valid.
        let client = RemoteIamClient::new(StubTransport { fail: false });
        let err = client
            .introspect_token(&TokenIntrospectionRequest {
                token: String::from("sk-awaken-test.token"),
            })
            .unwrap_err();
        assert!(
            err.0.contains("not supported"),
            "unexpected error: {}",
            err.0
        );
    }

    #[test]
    fn introspect_token_surfaces_transport_response() {
        use awaken_iam_contract::{
            ApiTokenStatus, TokenIntrospectionRequest, TokenIntrospectionResponse, WorkspaceId,
        };

        struct IntrospectStub;
        impl AuthzTransport for IntrospectStub {
            fn authorize(
                &self,
                _: &AuthorizationRequest,
            ) -> Result<AuthorizationOutcome, RemoteError> {
                unreachable!()
            }
            fn authorize_batch(
                &self,
                _: &BatchAuthorizationRequest,
            ) -> Result<BatchAuthorizationResponse, RemoteError> {
                unreachable!()
            }
            fn check_entitlement(
                &self,
                _: &EntitlementRequest,
            ) -> Result<EntitlementCheckResponse, RemoteError> {
                unreachable!()
            }
            fn register_resource_model(
                &self,
                _: &ResourceModelRegistration,
            ) -> Result<ResourceModelRegistered, RemoteError> {
                unreachable!()
            }
            fn fetch_snapshot(&self) -> Result<PolicySnapshot, RemoteError> {
                unreachable!()
            }
            fn fetch_signers(&self, _: &NamespaceId) -> Result<SignerSetSnapshot, RemoteError> {
                unreachable!()
            }
            fn introspect_token(
                &self,
                _request: &TokenIntrospectionRequest,
            ) -> Result<TokenIntrospectionResponse, RemoteError> {
                Ok(TokenIntrospectionResponse {
                    principal: PrincipalRef::Service {
                        service_id: "ci".into(),
                    },
                    workspace: WorkspaceId("ws_1".into()),
                    status: ApiTokenStatus::Active,
                })
            }
        }

        let client = RemoteIamClient::new(IntrospectStub);
        let response = client
            .introspect_token(&TokenIntrospectionRequest {
                token: String::from("sk-awaken-prefix.secret"),
            })
            .unwrap();
        assert_eq!(
            response.principal,
            PrincipalRef::Service {
                service_id: "ci".into()
            }
        );
        assert_eq!(response.workspace, WorkspaceId("ws_1".into()));
        assert_eq!(response.status, ApiTokenStatus::Active);
    }
}
