//! Client-facing IAM traits.

#[cfg(feature = "http")]
mod http;
mod remote;
mod snapshot;

#[cfg(feature = "http")]
pub use http::{DEFAULT_MAX_RETRIES, DEFAULT_TIMEOUT, HttpAuthzTransport, HttpTransportConfig};
mod outbox;
mod remote;

pub use outbox::{
    DrainReport, InMemoryOutbox, OutboxError, OutboxRecord, OutboxRelay, OutboxStatus, OutboxStore,
    ProvisionTransport,
};
pub use remote::{AuthzTransport, IamClientMode, RemoteError, RemoteIamClient};
pub use snapshot::{REASON_UNSYNCED, SnapshotCache, SyncStatus};

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

/// A shared reference to a client is itself a client.
///
/// This lets an embedded deployment hand its in-process engine to the local arm
/// of [`IamClientMode`] by borrow, without surrendering ownership or cloning the
/// policy — the local client and the mounted routes then share one engine.
impl<C: IamClient + ?Sized> IamClient for &C {
    fn authorize(&self, request: AuthorizationRequest) -> AuthorizationDecision {
        (**self).authorize(request)
    }

    fn check_entitlement(&self, request: EntitlementRequest) -> EntitlementDecision {
        (**self).check_entitlement(request)
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
