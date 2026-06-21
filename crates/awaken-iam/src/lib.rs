//! Convenience facade for Awaken IAM library users.

pub use awaken_iam_client::{
    AuthzTransport, IamClient, IamClientMode, RemoteError, RemoteIamClient,
};
pub use awaken_iam_contract::{
    Account, AccountId, AccountStatus, ActionKey, AuthorizationDecision, AuthorizationOutcome,
    AuthorizationRequest, BatchAuthorizationRequest, BatchAuthorizationResponse,
    EntitlementCheckResponse, EntitlementDecision, EntitlementRequest, ExternalIdentity,
    ExternalIdentityClaims, ExternalIdentityId, ExternalIdentityKey, ExternalSubject, GrantEffect,
    GrantSnapshot, GrantSubjectRef, IdentityProviderConfig, IdentityProviderConfigId,
    IdentityProviderKey, IdentityProviderKind, NamespaceId, NamespaceOwner, OAuthLoginState,
    OAuthLoginStateId, OrgId, PolicySnapshot, PrincipalRef, ProjectId, ResourceId, ResourceType,
    RoleBindingSnapshot, ScopeGraphSnapshot, ScopeRef, Session, SessionId, SessionView, SignerKey,
    SignerKeyAlgorithm, SignerKeyFingerprint, SignerKeyId, SignerKeyStatus, Timestamp, WorkspaceId,
};
pub use awaken_iam_core::{
    BeginLogin, EntitlementCatalog, EntitlementEngine, EntitlementMode, EntitlementOutcome,
    EntitlementReason, EntitlementResolver, EntropySource, EstablishSession, IamCore, IamError,
    IdentityDirectory, IssuedLogin, IssuedSession, LoginAttempt, LoginBinding, LoginSecrets,
    NamespaceGrant, NamespaceTrustDirectory, OAuthChallengeService, OsEntropy, PkceChallenge,
    PkceMethod, Plan, PlanId, PlanTier, Quota, RateLimit, RateWindow, ResourceEdge, ResourceModel,
    ResourceTypeDef, SessionDirectory, SessionMinter, TrustError, hash_session_token,
};
pub use awaken_iam_server::{
    AuthApi, AuthApiError, AuthAuditEvent, AuthFailureReason, AuthzApi, CallbackOutcome,
    CallbackRequest, DEFAULT_LOGIN_COOKIE_NAME, DEFAULT_SESSION_COOKIE_NAME, Deployment,
    EstablishedSession, HttpMethod, IAM_TABLE_PREFIX, IamAssembly, IamDaemon, IamServer,
    LinkIdentity, LogoutOutcome, ProviderRegistration, ProviderSummary, ReturnToDecision,
    ReturnToPolicy, RouteSpec, SameSite, SessionCookieConfig, SessionGateway, StartLogin,
    StartLoginOutcome, UnlinkIdentity,
};

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn facade_reexports_server_and_contract() {
        let server = IamServer::new();
        let decision = server.authorize(AuthorizationRequest {
            principal: PrincipalRef::Service {
                service_id: "svc".into(),
            },
            on_behalf_of: Vec::new(),
            action: ActionKey("pack.publish".into()),
            scope: ScopeRef::Global,
        });
        assert_eq!(decision, AuthorizationDecision::Deny);
    }
}
