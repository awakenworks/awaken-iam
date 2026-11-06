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

impl<T: ScopedProfileConsumer> ScopedProfileConsumer for crate::RemoteIamClient<T> {
    fn authorize_scoped_resource(
        &self,
        workspace: &WorkspaceId,
        namespace: &NamespaceId,
        request: &ResourceAuthorizationRequest,
    ) -> Result<AuthorizationOutcome, RemoteError> {
        self.transport()
            .authorize_scoped_resource(workspace, namespace, request)
    }
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
    fn retire_scoped_profile(
        &self,
        _workspace: &WorkspaceId,
        _namespace: &NamespaceId,
        _key: &str,
    ) -> Result<ScopedAuthorizationProfileReceipt, RemoteError> {
        Err(RemoteError::new(
            "scoped profile retirement is unsupported by this transport".into(),
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use awaken_iam_contract::{
        ActionKey, AuthorizationDecision, AuthorizationRequest, PrincipalRef, ScopeRef,
    };
    use std::sync::{Arc, Mutex};
    type Calls = Arc<Mutex<Vec<(WorkspaceId, NamespaceId, ResourceAuthorizationRequest)>>>;
    struct ScopedOnly {
        calls: Calls,
        outcome: Result<AuthorizationOutcome, RemoteError>,
    }
    // No legacy AuthzTransport implementation: this adapter has only the
    // explicit scoped protocol and cannot provide a permissive fallback.
    impl ScopedProfileConsumer for ScopedOnly {
        fn authorize_scoped_resource(
            &self,
            workspace: &WorkspaceId,
            namespace: &NamespaceId,
            request: &ResourceAuthorizationRequest,
        ) -> Result<AuthorizationOutcome, RemoteError> {
            self.calls.lock().unwrap().push((
                workspace.clone(),
                namespace.clone(),
                request.clone(),
            ));
            self.outcome.clone()
        }
    }
    #[test]
    fn remote_scoped_calls_preserve_context_decisions_and_unavailability() {
        let workspace = WorkspaceId("workspace-a".into());
        let namespace = NamespaceId("tenant.a".into());
        let mut request = ResourceAuthorizationRequest {
            request: AuthorizationRequest::direct(
                PrincipalRef::Account {
                    account_id: awaken_iam_contract::AccountId("alice".into()),
                },
                ActionKey("tenant.a::read".into()),
                ScopeRef::Workspace {
                    workspace_id: workspace.clone(),
                },
            ),
            context: Default::default(),
        };
        request.request.on_behalf_of.push(PrincipalRef::Service {
            service_id: "desk".into(),
        });
        request.context.fields = Some(vec!["title".into()]);
        request.context.resource_id = Some("resource-a".into());
        for outcome in [
            Ok(AuthorizationOutcome {
                decision: AuthorizationDecision::Allow,
                reason: "scoped".into(),
                matched_grants: vec!["tenant.a:read".into()],
                matched_roles: vec![],
                obligation: None,
            }),
            Ok(AuthorizationOutcome {
                decision: AuthorizationDecision::Deny,
                reason: "scoped".into(),
                matched_grants: vec![],
                matched_roles: vec![],
                obligation: None,
            }),
            Err(RemoteError::response(503, "unavailable".into())),
        ] {
            let calls = Arc::new(Mutex::new(vec![]));
            let client = crate::RemoteIamClient::new(ScopedOnly {
                calls: calls.clone(),
                outcome: outcome.clone(),
            });
            assert_eq!(
                client.authorize_scoped_resource(&workspace, &namespace, &request),
                outcome
            );
            assert_eq!(
                *calls.lock().unwrap(),
                [(workspace.clone(), namespace.clone(), request.clone())]
            );
        }
    }
}
