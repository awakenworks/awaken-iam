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
