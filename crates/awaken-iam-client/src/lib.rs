//! Client-facing IAM traits.

mod remote;

pub use remote::{AuthzTransport, IamClientMode, RemoteError, RemoteIamClient};

use awaken_iam_contract::{
    AuthorizationDecision, AuthorizationRequest, EntitlementDecision, EntitlementRequest,
};

/// Shared client interface for services that delegate IAM decisions.
pub trait IamClient {
    /// Check authorization for an action and scope.
    fn authorize(&self, request: AuthorizationRequest) -> AuthorizationDecision;

    /// Check account/product entitlement.
    fn check_entitlement(&self, request: EntitlementRequest) -> EntitlementDecision;
}
