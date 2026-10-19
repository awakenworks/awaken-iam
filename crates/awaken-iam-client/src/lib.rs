//! Client-facing IAM traits.

#[cfg(feature = "credential-cache")]
mod cache;
#[cfg(feature = "desktop-oauth")]
mod desktop_oauth;
#[cfg(feature = "http")]
mod http;
mod remote;
mod snapshot;

#[cfg(feature = "credential-cache")]
pub use cache::{
    CacheError, CachedCredential, CachedOAuthGrant, Credential, CredentialCache, RedactedString,
};
#[cfg(feature = "desktop-oauth")]
pub use desktop_oauth::{DesktopOAuthClient, DesktopOAuthConfig, DesktopOAuthError};
#[cfg(feature = "http")]
pub use http::{DEFAULT_MAX_RETRIES, DEFAULT_TIMEOUT, HttpAuthzTransport, HttpTransportConfig};
mod outbox;

pub use outbox::{
    DrainReport, InMemoryOutbox, OutboxError, OutboxRecord, OutboxRelay, OutboxStatus, OutboxStore,
    ProvisionTransport,
};
pub use remote::{AuthzTransport, DirectoryClient, IamClientMode, RemoteError, RemoteIamClient};
pub use snapshot::{REASON_UNSYNCED, SnapshotCache, SyncStatus};

use awaken_iam_contract::{
    AuthorizationDecision, AuthorizationOutcome, AuthorizationProfilePublicationState,
    AuthorizationRequest, EntitlementDecision, EntitlementRequest, NamespaceId,
    ResourceAuthorizationRequest,
};

/// Availability failure at the IAM decision boundary.
///
/// Policy denials remain ordinary decision values. This error exists so an
/// online PEP can distinguish a reachable PDP denial from an unreachable PDP
/// without ever treating the latter as an allow.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum IamDecisionError {
    #[error("IAM decision service is unavailable")]
    Unavailable,
}

/// Shared client interface for services that delegate IAM decisions.
pub trait IamClient {
    /// Publication evidence is an explicit capability, never a permissive default.
    fn profile_publication_state(
        &self,
        _namespace: &NamespaceId,
    ) -> Result<AuthorizationProfilePublicationState, IamDecisionError> {
        Err(IamDecisionError::Unavailable)
    }
    /// Contextual authorization is an explicit capability; legacy providers fail closed.
    fn authorize_resource_result(
        &self,
        _request: ResourceAuthorizationRequest,
    ) -> Result<AuthorizationOutcome, IamDecisionError> {
        Err(IamDecisionError::Unavailable)
    }
    /// Check authorization for an action and scope.
    fn authorize(&self, request: AuthorizationRequest) -> AuthorizationDecision;

    /// Check authorization while preserving decision-service availability.
    /// Existing in-process clients inherit the infallible adapter; transports
    /// override it so an outage remains distinct from an explicit deny.
    fn authorize_result(
        &self,
        request: AuthorizationRequest,
    ) -> Result<AuthorizationDecision, IamDecisionError> {
        Ok(self.authorize(request))
    }

    /// Check account/product entitlement.
    fn check_entitlement(&self, request: EntitlementRequest) -> EntitlementDecision;

    /// Check entitlement while preserving decision-service availability.
    fn check_entitlement_result(
        &self,
        request: EntitlementRequest,
    ) -> Result<EntitlementDecision, IamDecisionError> {
        Ok(self.check_entitlement(request))
    }
}

/// A shared reference to a client is itself a client.
///
/// This lets an embedded deployment hand its in-process engine to the local arm
/// of [`IamClientMode`] by borrow, without surrendering ownership or cloning the
/// policy — the local client and the mounted routes then share one engine.
impl<C: IamClient + ?Sized> IamClient for &C {
    fn profile_publication_state(
        &self,
        namespace: &NamespaceId,
    ) -> Result<AuthorizationProfilePublicationState, IamDecisionError> {
        (**self).profile_publication_state(namespace)
    }
    fn authorize_resource_result(
        &self,
        request: ResourceAuthorizationRequest,
    ) -> Result<AuthorizationOutcome, IamDecisionError> {
        (**self).authorize_resource_result(request)
    }
    fn authorize(&self, request: AuthorizationRequest) -> AuthorizationDecision {
        (**self).authorize(request)
    }

    fn authorize_result(
        &self,
        request: AuthorizationRequest,
    ) -> Result<AuthorizationDecision, IamDecisionError> {
        (**self).authorize_result(request)
    }

    fn check_entitlement(&self, request: EntitlementRequest) -> EntitlementDecision {
        (**self).check_entitlement(request)
    }

    fn check_entitlement_result(
        &self,
        request: EntitlementRequest,
    ) -> Result<EntitlementDecision, IamDecisionError> {
        (**self).check_entitlement_result(request)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use awaken_iam_contract::{AccountId, ActionKey, PrincipalRef, ScopeRef};

    struct AllowAll;

    impl IamClient for AllowAll {
        fn authorize(&self, _request: AuthorizationRequest) -> AuthorizationDecision {
            AuthorizationDecision::Allow
        }

        fn check_entitlement(&self, _request: EntitlementRequest) -> EntitlementDecision {
            EntitlementDecision::Allow
        }
    }

    #[test]
    fn a_borrowed_client_delegates_to_the_owner() {
        let engine = AllowAll;
        // A shared reference forwards both planes to the owned engine, so an
        // embedded deployment can lend its engine without surrendering ownership.
        let borrowed: &dyn IamClient = &engine;
        let request = AuthorizationRequest::direct(
            PrincipalRef::Account {
                account_id: AccountId("acct_1".into()),
            },
            ActionKey("pack.read".into()),
            ScopeRef::Global,
        );
        assert_eq!(borrowed.authorize(request), AuthorizationDecision::Allow);
        // C1 an older client implements no publication capability. Its borrowed
        // adapter must preserve unavailable, never manufacture unconfigured.
        assert_eq!(
            borrowed.profile_publication_state(&NamespaceId("example.business".into())),
            Err(IamDecisionError::Unavailable)
        );
        assert_eq!(
            borrowed.check_entitlement(EntitlementRequest {
                principal: PrincipalRef::Account {
                    account_id: AccountId("acct_1".into()),
                },
                entitlement: "pack.read".into(),
                resource: None,
            }),
            EntitlementDecision::Allow
        );
    }
}
