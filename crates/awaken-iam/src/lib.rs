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
    CreateDirectoryNode, DirectoryChildrenQuery, DirectoryMutationAck, DirectoryNodeId,
    DirectoryNodeView, EntitlementCheckResponse, EntitlementDecision, EntitlementRequest,
    ExternalIdentity, ExternalIdentityClaims, ExternalIdentityId, ExternalIdentityKey,
    ExternalSubject, GrantEffect, GrantSnapshot, GrantSubjectRef, IdentityProviderConfig,
    IdentityProviderConfigId, IdentityProviderKey, IdentityProviderKind, MoveDirectoryNode,
    NamespaceId, NamespaceOwner, OAuthLoginState, OAuthLoginStateId, OrgId, PolicySnapshot,
    PrincipalRef, ProductSpacePlacement, ProductSpaceRef, ProjectId, RefreshToken,
    RefreshTokenChainId, RefreshTokenId, RefreshTokenView, ResourceId, ResourceModelRegistered,
    ResourceModelRegistration, ResourceParentEdge, ResourceProvision, ResourceType,
    ResourceTypeRegistration, RoleBindingSnapshot, ScopeGraphSnapshot, ScopeRef, Session,
    SessionId, SessionView, SignerKey, SignerKeyAlgorithm, SignerKeyFingerprint, SignerKeyId,
    SignerKeyStatus, Timestamp, UpdateDirectoryNode, WorkspaceId,
};
pub use awaken_iam_core::{
    ActionPattern, AuditEvent, AuditLedger, AuditSink, AuthorizedGrant, BeginLogin,
    ConsumerNamespaces, DecisionTrace, DirectoryInvariant, DirectoryNode, DirectoryRepository,
    DomainEvent, Effect, EntitlementCatalog, EntitlementEngine, EntitlementMode,
    EntitlementOutcome, EntitlementProvider, EntitlementReason, EntitlementResolver, EntropySource,
    EstablishSession, GenericOAuthProvider, GenericOAuthSecrets, Grant, GrantId, GrantSubject,
    IamCore, IamError, IdentityDirectory, IssuedAuthorizationCode, IssuedLogin, IssuedSession,
    LicenseEntitlements, LoginAttempt, LoginBinding, LoginSecrets, NamespaceGrant,
    NamespaceTrustDirectory, OAuthAuthorizationRequest, OAuthAuthorizationServer,
    OAuthChallengeService, OAuthClientRegistry, OAuthProviderError, OsEntropy, PkceChallenge,
    PkceMethod, Plan, PlanId, PlanTier, PolicySet, Quota, RateLimit, RateWindow, RegisteredClient,
    RepositoryError, RepositoryResult, ResourceEdge, ResourceModel, ResourceTypeDef, RoleBinding,
    RoleDef, RoleId, SessionDirectory, SessionMinter, ShadowAuthorizer, ShadowOutcome,
    ShadowReport, TokenRedemption, TrustError, action_namespace, apply_resource_provision,
    hash_session_token, seed_roles,
};
pub use awaken_iam_preset::{
    ANTHROPIC_ROLE_IDS, AWAKEN_RUNTIME_NAMESPACES, AWAKEN_RUNTIME_ROLE_IDS,
    MANAGED_AGENTS_NAMESPACES, OVERSIGHT_NAMESPACES, ROLE_NAMESPACES, awaken_runtime,
    managed_agents, named_role_catalog, oversight, runtime_role_catalog, seed_named_roles,
    seed_runtime_roles,
};
pub use awaken_iam_server::{
    AccessTokenAuthority, AccessTokenError, ApprovalDischargeService, AttenuateCapability, AuthApi,
    AuthApiError, AuthAuditEvent, AuthFailureReason, AuthzApi, BeginLocalSetup, BundleScope,
    CallbackOutcome, CallbackRequest, CapabilityCheck, CapabilityClaims, CapabilityError,
    DEFAULT_LOGIN_COOKIE_NAME, DEFAULT_LOGIN_PROOF_COOKIE_NAME, DEFAULT_SESSION_COOKIE_NAME,
    Deployment, Dialect, DirectoryApi, DischargeError, DischargeOutcome, DischargeRequest,
    EstablishedSession, ExchangeLocalSetup, HttpMethod, IAM_TABLE_PREFIX, IamAssembly, IamDaemon,
    IamServer, IamStore, IssueTokenGrant, IssuedLocalSetup, LeaseEpoch, LinkIdentity,
    LocalSeedSigner, LocalSetupError, LocalSetupGateway, LocalSetupId, LogoutOutcome,
    MigrateReport, Migration, MigrationBundle, MigrationExecutor, MintCapability, PlannedMigration,
    PolicyAdminApi, PolicyStore, PostgresBackend, PrincipalResolutionFailure, ProviderRegistration,
    ProviderSummary, RefreshGrant, ReturnToDecision, ReturnToPolicy, RevokeOutcome, RevokeToken,
    RevokeTokenHint, RouteSpec, SameSite, SessionCookieConfig, SessionGateway, Signer, SignerError,
    SqliteBackend, StartLogin, StartLoginOutcome, TOKEN_EXCHANGE_GRANT_TYPE, TokenExchangeError,
    TokenExchangeRequest, TokenExchangeResponse, TokenGrant, TrustedIssuer, TrustedIssuerRegistry,
    UnlinkIdentity, WorkloadBinding, attenuate, bundles, mint_capability, postgres_migrated_store,
    sqlite_in_memory_store, sqlite_migrated_store, verify_capability,
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
