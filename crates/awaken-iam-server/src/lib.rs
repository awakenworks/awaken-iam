//! Server assembly seam for Awaken IAM.

mod access_token;
mod admin_api;
mod assembly;
mod auth_api;
mod authz_api;
mod capability_token;
pub mod http;
mod oauth_client_admin;
mod op_id_token;
mod session;
mod store;
mod token_exchange;
mod upstream_http;

pub use access_token::{
    ACCESS_TOKEN_ALG, AccessTokenAuthority, AccessTokenClaims, AccessTokenError,
    AccessTokenRevocations, LocalSeedSigner, Signer, SignerError, decode_unverified_claims,
    ed25519_public_jwk, verify_access_token, verify_active_access_token, verify_signed_claims,
};
pub use admin_api::{AdminError, AdminResult, DomainEvent, PolicyAdminApi};
pub use assembly::{Deployment, HttpMethod, IAM_TABLE_PREFIX, IamAssembly, IamDaemon, RouteSpec};
pub use auth_api::{
    AuthApi, AuthApiError, AuthAuditEvent, AuthFailureReason, CallbackOutcome, CallbackRequest,
    DEFAULT_LOGIN_COOKIE_NAME, IssueTokenGrant, LinkIdentity, LogoutOutcome, MintAccessToken,
    OpCodeRedemption, OpTokenGrant, PrincipalResolutionFailure, ProviderRegistration,
    ProviderSummary, RefreshGrant, ReturnToDecision, ReturnToPolicy, RevokeOutcome, RevokeToken,
    RevokeTokenHint, StartLogin, StartLoginOutcome, TokenGrant, UnlinkIdentity,
};
pub use authz_api::AuthzApi;
pub use capability_token::{
    AttenuateCapability, CapabilityCheck, CapabilityClaims, CapabilityError, LeaseEpoch,
    MintCapability, attenuate, mint_capability, verify_capability,
};
pub use oauth_client_admin::{IssuedClientSecret, OAuthClientAdminApi, OAuthClientEvent};
pub use op_id_token::{
    ID_TOKEN_TYP, IdTokenError, MintIdToken, OidcIdTokenClaims, mint_id_token, verify_id_token,
};
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
    TrustedIssuerRegistry, WorkloadBinding,
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
    /// Create an IAM server facade with v1 default-allow entitlements.
    pub fn new() -> Self {
        Self {
            core: IamCore::new(),
            entitlements: Box::new(EntitlementEngine::default_allow()),
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
        assert_eq!(ent, EntitlementDecision::Allow);
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
