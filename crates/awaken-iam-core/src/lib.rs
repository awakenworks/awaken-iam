//! Core IAM evaluation primitives.

use awaken_iam_contract::{AuthorizationDecision, AuthorizationRequest, EntitlementDecision};

/// Errors returned by IAM evaluation.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum IamError {
    /// The request could not be evaluated because required identity data is missing.
    #[error("missing principal")]
    MissingPrincipal,
}

/// Minimal authorizer seam.
#[derive(Debug, Default)]
pub struct IamCore;

impl IamCore {
    /// Create an IAM core evaluator.
    pub fn new() -> Self {
        Self
    }

    /// Evaluate authorization. The initial skeleton denies by default; concrete
    /// grant stores will extend this through explicit policy inputs.
    pub fn authorize(&self, _request: &AuthorizationRequest) -> AuthorizationDecision {
        AuthorizationDecision::Deny
    }

    /// Evaluate entitlement. v1 starts as default-allow seam until billing / SKU
    /// policy is implemented by a product deployment.
    pub fn entitlement_default_allow(&self) -> EntitlementDecision {
        EntitlementDecision::Allow
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use awaken_iam_contract::{ActionKey, PrincipalRef, ScopeRef};

    #[test]
    fn authorization_denies_by_default() {
        let core = IamCore::new();
        let request = AuthorizationRequest {
            principal: PrincipalRef::Service {
                service_id: "svc".into(),
            },
            action: ActionKey("pack.publish".into()),
            scope: ScopeRef::Global,
        };
        assert_eq!(core.authorize(&request), AuthorizationDecision::Deny);
    }

    #[test]
    fn entitlement_seam_defaults_allow() {
        assert_eq!(
            IamCore::new().entitlement_default_allow(),
            EntitlementDecision::Allow
        );
    }
}
