//! Server assembly seam for Awaken IAM.

mod access_token;
mod admin_api;
mod admin_http;
mod anthropic_admin;
mod approval_discharge;
mod assembly;
mod auth_api;
mod auth_redirect;
mod authz_api;
mod capability_token;
mod clock;
mod directory_api;
pub mod http;
mod license;
mod local_setup;
mod oauth_client_admin;
mod op_http;
mod op_id_token;
mod profile_admin;
mod session;
mod store;
mod token_exchange;
mod upstream_http;

pub use access_token::{
    ACCESS_TOKEN_ALG, AccessTokenAuthority, AccessTokenClaims, AccessTokenError,
    AccessTokenRevocations, AccessTokenSubjectKind, LocalSeedSigner, Signer, SignerError,
    decode_unverified_claims, ed25519_public_jwk, verify_access_token, verify_active_access_token,
    verify_signed_claims,
};
pub use admin_api::{AdminError, AdminResult, DomainEvent, PolicyAdminApi, PolicyStore};
pub use admin_http::{AdminAuthPolicy, DaemonState, SharedDaemonState, daemon_router};
pub use anthropic_admin::{
    ADMIN_API_KEY_PREFIX, AdminApiError, AdminCredential, AnthropicAdminApi, ApiKey, ApiResult,
    DEFAULT_PAGE_LIMIT, FEDERATION_ISSUER_ID_PREFIX, FEDERATION_RULE_ID_PREFIX, FederationIssuer,
    FederationRule, ListParams, MAX_PAGE_LIMIT, Member, ORG_ADMIN_ACTION, ObjectKind, OrgRole,
    Page, SERVICE_ACCOUNT_ID_PREFIX, ServiceAccount, WORKSPACE_ID_PREFIX, WorkspaceMember,
    WorkspaceRole, admin_authorization_request, project_federation_issuers,
    project_federation_rules,
};
pub use approval_discharge::{
    ApprovalDischargeService, DischargeError, DischargeOutcome, DischargeRequest,
};
pub use assembly::{Deployment, HttpMethod, IAM_TABLE_PREFIX, IamAssembly, IamDaemon, RouteSpec};
pub use auth_api::{
    AuthApi, AuthApiError, AuthAuditEvent, AuthFailureReason, CallbackOutcome, CallbackRequest,
    DEFAULT_LOGIN_COOKIE_NAME, DEFAULT_LOGIN_PROOF_COOKIE_NAME, DownstreamAuthorizeOutcome,
    DownstreamAuthorizeRequest, IssueTokenGrant, LinkIdentity, LogoutOutcome, MintAccessToken,
    OpCodeRedemption, OpTokenGrant, PrincipalResolutionFailure, ProviderRegistration,
    ProviderSummary, RedeemAuthorizationCode, RefreshGrant, ReturnToDecision, ReturnToPolicy,
    RevokeOutcome, RevokeToken, RevokeTokenHint, StartLogin, StartLoginOutcome, TokenGrant,
    UnlinkIdentity,
};
pub use authz_api::{AuthzApi, IntrospectionError};
pub use capability_token::{
    AttenuateCapability, CapabilityCheck, CapabilityClaims, CapabilityError, LeaseEpoch,
    MintCapability, attenuate, mint_capability, verify_capability,
};
pub use directory_api::DirectoryApi;
pub use license::{
    ENV_LICENSE_CUSTOMER_ID, ENV_LICENSE_DEPLOYMENT_ID, ENV_LICENSE_FILE, ENV_LICENSE_INLINE,
    ENV_LICENSE_JWKS, ENV_LICENSE_JWKS_FILE, LicenseConfig, LicenseFloorStore, LicenseLoadError,
    LicenseRejection, LicenseResolution, LicenseSource, LicenseStateError, LicenseStatus,
};
pub use local_setup::{
    BeginLocalSetup, ExchangeLocalSetup, IssuedLocalSetup, LocalSetupError, LocalSetupGateway,
    LocalSetupId,
};
pub use oauth_client_admin::{IssuedClientSecret, OAuthClientAdminApi, OAuthClientEvent};
pub use op_http::{SharedAuthApi, op_router};
pub use op_id_token::{
    ID_TOKEN_TYP, IdTokenError, MintIdToken, OidcIdTokenClaims, mint_id_token, verify_id_token,
};
pub use profile_admin::{AuthorizationProfileAdmin, ProfileAdminError};
pub use session::{
    DEFAULT_SESSION_COOKIE_NAME, EstablishedSession, SameSite, SessionCookieConfig, SessionGateway,
};
pub use store::{
    BundleScope, Dialect, Fence, FenceStore, IamStore, InMemoryStore, Liveness, MigrateReport,
    Migration, MigrationBundle, MigrationExecutor, PlannedMigration, PostgresBackend, Readiness,
    RecordingExecutor, SqlConn, SqlParam, SqlRow, SqlStore, SqliteBackend, bundles,
    postgres_migrated_store, sqlite_in_memory_store, sqlite_migrated_store,
};
pub use token_exchange::{
    BEARER_TOKEN_TYPE, ISSUED_TOKEN_TYPE_ACCESS_TOKEN, SUBJECT_TOKEN_TYPE_ACCESS_TOKEN,
    SUBJECT_TOKEN_TYPE_ID_TOKEN, SUBJECT_TOKEN_TYPE_JWT, TOKEN_EXCHANGE_GRANT_TYPE,
    TokenExchangeError, TokenExchangeRequest, TokenExchangeResponse, TrustedIssuer,
    TrustedIssuerRegistry, WORKSPACE_ROLE_SCOPE_PREFIX, WorkloadBinding, workspace_role_for_scope,
};
pub use upstream_http::{
    DEFAULT_GITHUB_API_BASE, DEFAULT_GITHUB_USER_AGENT, DEFAULT_TIMEOUT, ReqwestGithubTransport,
    ReqwestHttpTransport,
};

use awaken_iam_client::IamClient;
use awaken_iam_contract::{
    AuthorizationDecision, AuthorizationRequest, EntitlementDecision, EntitlementRequest,
};
use awaken_iam_core::{EntitlementEngine, EntitlementProvider, IamCore};

/// Minimal in-process server facade used by tests and future adapters.
///
/// Authorization and entitlement are held as separate planes: grant evaluation
/// lives in [`IamCore`] and never consults the entitlement plane, and the
/// injectable [`EntitlementProvider`] never consults grants. Both are evaluated
/// independently per request.
#[derive(Debug)]
pub struct IamServer {
    core: IamCore,
    entitlements: Box<dyn EntitlementProvider>,
}

impl Default for IamServer {
    fn default() -> Self {
        Self::new()
    }
}

impl IamServer {
    /// Create an IAM server facade with unlicensed commercial entitlements.
    pub fn new() -> Self {
        Self {
            core: IamCore::new(),
            entitlements: Box::new(EntitlementEngine::unlicensed()),
        }
    }

    /// Create an IAM server facade backed by a specific entitlement provider.
    /// The deploy-time seam: an open [`EntitlementEngine`] or a closed, licensed
    /// provider plugs in here.
    pub fn with_entitlements(entitlements: impl EntitlementProvider + 'static) -> Self {
        Self {
            core: IamCore::new(),
            entitlements: Box::new(entitlements),
        }
    }
}

impl IamClient for IamServer {
    fn authorize(&self, request: AuthorizationRequest) -> AuthorizationDecision {
        self.core.authorize(&request)
    }

    fn check_entitlement(&self, request: EntitlementRequest) -> EntitlementDecision {
        self.entitlements.check_entitlement(&request)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use awaken_iam_contract::{AccountId, ActionKey, EntitlementRequest, PrincipalRef, ScopeRef};
    use awaken_iam_core::{EntitlementCatalog, Plan, PlanId, PlanTier};

    #[test]
    fn server_implements_client_trait() {
        // Cause/effect rule: the default facade has neither authorization grants
        // nor a commercial license/provider, so both independent planes deny.
        let server = IamServer::new();
        let principal = PrincipalRef::Service {
            service_id: "svc".into(),
        };
        let auth = server.authorize(AuthorizationRequest {
            principal: principal.clone(),
            on_behalf_of: Vec::new(),
            action: ActionKey("pack.publish".into()),
            scope: ScopeRef::Global,
        });
        assert_eq!(auth, AuthorizationDecision::Deny);

        let ent = server.check_entitlement(EntitlementRequest {
            principal,
            entitlement: "pack.read".into(),
            resource: None,
        });
        assert_eq!(ent, EntitlementDecision::Deny);
    }

    #[test]
    fn server_evaluates_local_entitlement_plan() {
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
        let server = IamServer::with_entitlements(EntitlementEngine::local(catalog));

        // Authorization still denies by default; the planes are independent.
        assert_eq!(
            server.authorize(AuthorizationRequest {
                principal: principal.clone(),
                on_behalf_of: Vec::new(),
                action: ActionKey("pack.read".into()),
                scope: ScopeRef::Global,
            }),
            AuthorizationDecision::Deny
        );

        assert_eq!(
            server.check_entitlement(EntitlementRequest {
                principal: principal.clone(),
                entitlement: "pack.read".into(),
                resource: Some("acme/pkg".into()),
            }),
            EntitlementDecision::Allow
        );
        assert_eq!(
            server.check_entitlement(EntitlementRequest {
                principal,
                entitlement: "model.strong_access".into(),
                resource: None,
            }),
            EntitlementDecision::Deny
        );
    }
}
