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
    IdentityProviderKey, IdentityProviderKind, JsonWebKey, Jwks, LicenseClaim, NamespaceId,
    NamespaceOwner, OAuthLoginState, OAuthLoginStateId, OrgId, PolicySnapshot, PrincipalRef,
    ProjectId, RefreshToken, RefreshTokenChainId, RefreshTokenId, RefreshTokenView, ResourceId,
    ResourceProvision, ResourceType, RoleBindingSnapshot, ScopeGraphSnapshot, ScopeRef, Session,
    SessionId, SessionView, SignerKey, SignerKeyAlgorithm, SignerKeyFingerprint, SignerKeyId,
    SignerKeyStatus, Timestamp, WorkspaceId,
};
pub use awaken_iam_core::{
    ActionPattern, AuditEvent, AuditLedger, AuditSink, AuthorizedGrant, BeginLogin,
    ConsumerNamespaces, DecisionTrace, DomainEvent, Effect, EntitlementCatalog, EntitlementEngine,
    EntitlementMode, EntitlementOutcome, EntitlementProvider, EntitlementReason,
    EntitlementResolver, EntropySource, EstablishSession, GenericOAuthProvider,
    GenericOAuthSecrets, Grant, GrantId, GrantSubject, IamCore, IamError, IdentityDirectory,
    IssuedAuthorizationCode, IssuedLogin, IssuedSession, LicenseEntitlements, LoginAttempt,
    LoginBinding, LoginSecrets, NamespaceGrant, NamespaceTrustDirectory, OAuthAuthorizationRequest,
    OAuthAuthorizationServer, OAuthChallengeService, OAuthClientRegistry, OAuthProviderError,
    OsEntropy, PkceChallenge, PkceMethod, Plan, PlanId, PlanTier, PolicySet, Quota, RateLimit,
    RateWindow, RegisteredClient, ResourceEdge, ResourceModel, ResourceTypeDef, RoleBinding,
    RoleId, SessionDirectory, SessionMinter, ShadowAuthorizer, ShadowOutcome, ShadowReport,
    TokenRedemption, TrustError, action_namespace, apply_resource_provision, hash_session_token,
    seed_roles,
};
pub use awaken_iam_preset::{
    ANTHROPIC_ROLE_IDS, MANAGED_AGENTS_NAMESPACES, OVERSIGHT_NAMESPACES, ROLE_NAMESPACES,
    managed_agents, named_role_catalog, oversight, seed_named_roles,
};
pub use awaken_iam_server::{
    AccessTokenAuthority, AccessTokenClaims, AccessTokenError, AttenuateCapability, AuthApi,
    AuthApiError, AuthAuditEvent, AuthFailureReason, AuthzApi, CallbackOutcome, CallbackRequest,
    CapabilityCheck, CapabilityClaims, CapabilityError, DEFAULT_LOGIN_COOKIE_NAME,
    DEFAULT_SESSION_COOKIE_NAME, Deployment, Dialect, EstablishedSession, HttpMethod,
    IAM_TABLE_PREFIX, IamAssembly, IamDaemon, IamServer, IssueTokenGrant, LeaseEpoch, LinkIdentity,
    LocalSeedSigner, LogoutOutcome, MintCapability, PrincipalResolutionFailure,
    ProviderRegistration, ProviderSummary, RefreshGrant, ReturnToDecision, ReturnToPolicy,
    RevokeOutcome, RevokeToken, RevokeTokenHint, RouteSpec, SameSite, SessionCookieConfig,
    SessionGateway, Signer, SignerError, StartLogin, StartLoginOutcome, TOKEN_EXCHANGE_GRANT_TYPE,
    TokenExchangeError, TokenExchangeRequest, TokenExchangeResponse, TokenGrant, TrustedIssuer,
    TrustedIssuerRegistry, UnlinkIdentity, WorkloadBinding, attenuate, ed25519_public_jwk,
    mint_capability, verify_access_token, verify_capability,
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

    #[test]
    fn facade_reexports_access_token_value_types() {
        // Publishing a JWKS and offline-verifying an access token must be
        // possible through the facade alone — Gap E was that downstream had to
        // reach past it into `-server`/`-contract` for these value types.
        let jwk: JsonWebKey = ed25519_public_jwk("kid-1", [0u8; 32]);
        assert_eq!(jwk.kid, "kid-1");
        let jwks = Jwks { keys: vec![jwk] };
        let outcome: Result<AccessTokenClaims, AccessTokenError> =
            verify_access_token("not-a-jwt", &jwks);
        assert!(matches!(outcome, Err(AccessTokenError::Malformed)));

        // The offline license envelope is reachable through the facade too.
        let _license = core::marker::PhantomData::<LicenseClaim>;
    }
}
