//! Finite publication client, separate from the decision-only `IamClient` seam.
use crate::RemoteError;
use awaken_iam_contract::{
    AuthorizationOutcome, NamespaceId, PrepareScopedAuthorizationProfile,
    ResourceAuthorizationRequest, ScopedAuthorizationProfileBaseline,
    ScopedAuthorizationProfileReceipt, WorkspaceId,
};

/// Current remote scoped decisions. An unavailable/unknown endpoint is an
/// error, never permission to retry through legacy global authorization.
pub trait ScopedProfileConsumer: Send + Sync {
    fn authorize_scoped_resource(
        &self,
        workspace: &WorkspaceId,
        namespace: &NamespaceId,
        request: &ResourceAuthorizationRequest,
    ) -> Result<AuthorizationOutcome, RemoteError>;
}

/// Each call is authenticated with the current scoped service credential.
/// Retrying an uncertain effect must retain its exact original key and body.
pub trait ScopedProfilePublisher: Send + Sync {
    fn scoped_profile_baseline(
        &self,
        workspace: &WorkspaceId,
        namespace: &NamespaceId,
    ) -> Result<ScopedAuthorizationProfileBaseline, RemoteError>;
    fn prepare_scoped_profile(
        &self,
        request: &PrepareScopedAuthorizationProfile,
    ) -> Result<ScopedAuthorizationProfileReceipt, RemoteError>;
    fn scoped_profile_receipt(
        &self,
        workspace: &WorkspaceId,
        namespace: &NamespaceId,
        key: &str,
    ) -> Result<ScopedAuthorizationProfileReceipt, RemoteError>;
    fn activate_scoped_profile(
        &self,
        workspace: &WorkspaceId,
        namespace: &NamespaceId,
        key: &str,
    ) -> Result<ScopedAuthorizationProfileReceipt, RemoteError>;
}
