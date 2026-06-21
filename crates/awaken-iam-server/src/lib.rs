//! Server assembly seam for Awaken IAM.

mod admin_api;
mod auth_api;
mod authz_api;
mod session;
mod store;

pub use admin_api::{AdminError, AdminResult, DomainEvent, PolicyAdminApi};
pub use auth_api::{
    AuthApi, AuthApiError, AuthAuditEvent, AuthFailureReason, CallbackOutcome, CallbackRequest,
    DEFAULT_LOGIN_COOKIE_NAME, LinkIdentity, LogoutOutcome, ProviderRegistration, ProviderSummary,
    ReturnToDecision, ReturnToPolicy, StartLogin, StartLoginOutcome, UnlinkIdentity,
};
pub use authz_api::AuthzApi;
pub use session::{
    DEFAULT_SESSION_COOKIE_NAME, EstablishedSession, SameSite, SessionCookieConfig, SessionGateway,
};
pub use store::{
    BundleScope, IamStore, InMemoryStore, MigrateReport, Migration, MigrationBundle,
    MigrationExecutor, PlannedMigration, RecordingExecutor, bundles,
};

use awaken_iam_client::IamClient;
use awaken_iam_contract::{
    AuthorizationDecision, AuthorizationRequest, EntitlementDecision, EntitlementRequest,
};
use awaken_iam_core::{EntitlementEngine, IamCore};

/// Minimal in-process server facade used by tests and future adapters.
///
/// Authorization and entitlement are held as separate planes: grant evaluation
/// lives in [`IamCore`] and never consults the [`EntitlementEngine`], and the
/// engine never consults grants. Both are evaluated independently per request.
#[derive(Debug, Default)]
pub struct IamServer {
    core: IamCore,
    entitlements: EntitlementEngine,
}

impl IamServer {
    /// Create an IAM server facade with v1 default-allow entitlements.
    pub fn new() -> Self {
        Self {
            core: IamCore::new(),
            entitlements: EntitlementEngine::default_allow(),
        }
    }

    /// Create an IAM server facade backed by a specific entitlement engine.
    pub fn with_entitlements(entitlements: EntitlementEngine) -> Self {
        Self {
            core: IamCore::new(),
            entitlements,
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
