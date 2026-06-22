//! Server assembly seam for Awaken IAM.

mod session;

pub use session::{
    DEFAULT_SESSION_COOKIE_NAME, EstablishedSession, SameSite, SessionCookieConfig, SessionGateway,
};

use awaken_iam_client::IamClient;
use awaken_iam_contract::{
    AuthorizationDecision, AuthorizationRequest, EntitlementDecision, EntitlementRequest,
};
use awaken_iam_core::IamCore;

/// Minimal in-process server facade used by tests and future adapters.
#[derive(Debug, Default)]
pub struct IamServer {
    core: IamCore,
}

impl IamServer {
    /// Create an IAM server facade.
    pub fn new() -> Self {
        Self {
            core: IamCore::new(),
        }
    }
}

impl IamClient for IamServer {
    fn authorize(&self, request: AuthorizationRequest) -> AuthorizationDecision {
        self.core.authorize(&request)
    }

    fn check_entitlement(&self, _request: EntitlementRequest) -> EntitlementDecision {
        self.core.entitlement_default_allow()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use awaken_iam_contract::{ActionKey, EntitlementRequest, PrincipalRef, ScopeRef};

    #[test]
    fn server_implements_client_trait() {
        let server = IamServer::new();
        let principal = PrincipalRef::Service {
            service_id: "svc".into(),
        };
        let auth = server.authorize(AuthorizationRequest {
            principal: principal.clone(),
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
}
