//! Convenience facade for Awaken IAM library users.

pub use awaken_iam_client::{
    AuthzTransport, DrainReport, IamClient, IamClientMode, InMemoryOutbox, OutboxError,
    OutboxRecord, OutboxRelay, OutboxStatus, OutboxStore, ProvisionTransport, RemoteError,
    RemoteIamClient,
};
#[cfg(feature = "http")]
pub use awaken_iam_client::{
    DEFAULT_MAX_RETRIES, DEFAULT_TIMEOUT, HttpAuthzTransport, HttpTransportConfig,
};
pub use awaken_iam_contract::{
    Account, AccountId, AccountStatus, ActionKey, AuthorizationDecision, AuthorizationOutcome,
    AuthorizationRequest, BatchAuthorizationRequest, BatchAuthorizationResponse,
    EntitlementCheckResponse, EntitlementDecision, EntitlementRequest, ExternalIdentity,
    ExternalIdentityClaims, ExternalIdentityId, ExternalIdentityKey, ExternalSubject, GrantEffect,
    GrantSnapshot, GrantSubjectRef, IdentityProviderConfig, IdentityProviderConfigId,
    IdentityProviderKey, IdentityProviderKind, NamespaceId, NamespaceOwner, OAuthLoginState,
    OAuthLoginStateId, OrgId, PolicySnapshot, PrincipalRef, ProjectId, RefreshToken,
    RefreshTokenChainId, RefreshTokenId, RefreshTokenView, ResourceId, ResourceProvision,
    ResourceType, RoleBindingSnapshot, ScopeGraphSnapshot, ScopeRef, Session, SessionId,
    SessionView, SignerKey, SignerKeyAlgorithm, SignerKeyFingerprint, SignerKeyId, SignerKeyStatus,
    Timestamp, WorkspaceId,
};
pub use awaken_iam_core::{
    ActionPattern, AuditEvent, AuditLedger, AuditSink, AuthorizedGrant, BeginLogin, DecisionTrace,
    DomainEvent, Effect, EntitlementCatalog, EntitlementEngine, EntitlementMode,
    EntitlementOutcome, EntitlementReason, EntitlementResolver, EntropySource, EstablishSession,
    GenericOAuthProvider, GenericOAuthSecrets, Grant, GrantId, GrantSubject, IamCore, IamError,
    IdentityDirectory, IssuedAuthorizationCode, IssuedLogin, IssuedSession, LoginAttempt,
    LoginBinding, LoginSecrets, NamespaceGrant, NamespaceTrustDirectory, OAuthAuthorizationRequest,
    OAuthAuthorizationServer, OAuthChallengeService, OAuthClientRegistry, OAuthProviderError,
    OsEntropy, PkceChallenge, PkceMethod, Plan, PlanId, PlanTier, PolicySet, Quota, RateLimit,
    RateWindow, RegisteredClient, ResourceEdge, ResourceModel, ResourceTypeDef, SessionDirectory,
    SessionMinter, TokenRedemption, TrustError, hash_session_token,
    ActionPattern, AuthorizedGrant, BeginLogin, Effect, EntitlementCatalog, EntitlementEngine,
    EntitlementMode, EntitlementOutcome, EntitlementReason, EntitlementResolver, EntropySource,
    EstablishSession, GenericOAuthProvider, GenericOAuthSecrets, Grant, GrantId, GrantSubject,
    IamCore, IamError, IdentityDirectory, IssuedAuthorizationCode, IssuedLogin, IssuedSession,
    LoginAttempt, LoginBinding, LoginSecrets, NamespaceGrant, NamespaceTrustDirectory,
    OAuthAuthorizationRequest, OAuthAuthorizationServer, OAuthChallengeService,
    OAuthClientRegistry, OAuthProviderError, OsEntropy, PkceChallenge, PkceMethod, Plan, PlanId,
    PlanTier, PolicySet, Quota, RateLimit, RateWindow, RegisteredClient, ResourceEdge,
    ResourceModel, ResourceTypeDef, SessionDirectory, SessionMinter, TokenRedemption, TrustError,
    apply_resource_provision, hash_session_token,
    RateWindow, RegisteredClient, ResourceEdge, ResourceModel, ResourceTypeDef, RoleBinding,
    RoleId, SessionDirectory, SessionMinter, ShadowAuthorizer, ShadowOutcome, ShadowReport,
    TokenRedemption, TrustError, hash_session_token,
};
pub use awaken_iam_server::{
    AuthApi, AuthApiError, AuthAuditEvent, AuthFailureReason, AuthzApi, CallbackOutcome,
    CallbackRequest, DEFAULT_LOGIN_COOKIE_NAME, DEFAULT_SESSION_COOKIE_NAME, Deployment, Dialect,
    EstablishedSession, HttpMethod, IAM_TABLE_PREFIX, IamAssembly, IamDaemon, IamServer,
    IssueTokenGrant, LinkIdentity, LogoutOutcome, PrincipalResolutionFailure, ProviderRegistration,
    ProviderSummary, RefreshGrant, ReturnToDecision, ReturnToPolicy, RevokeOutcome, RevokeToken,
    RevokeTokenHint, RouteSpec, SameSite, SessionCookieConfig, SessionGateway, StartLogin,
    StartLoginOutcome, TOKEN_EXCHANGE_GRANT_TYPE, TokenExchangeError, TokenExchangeRequest,
    TokenExchangeResponse, TokenGrant, TrustedIssuer, TrustedIssuerRegistry, UnlinkIdentity,
    WorkloadBinding,
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
