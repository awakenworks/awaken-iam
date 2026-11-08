//! Current scoped decisions reuse the gate's original remote client/credentials.
use super::*;
use awaken_iam_client::ScopedProfileConsumer;
use awaken_iam_contract::NamespaceId;

impl ScopedProfileConsumer for IamGate {
    fn authorize_scoped_resource_evaluation(
        &self,
        workspace: &WorkspaceId,
        namespace: &NamespaceId,
        request: &ResourceAuthorizationRequest,
    ) -> Result<awaken_iam_contract::AuthorizationEvaluation, RemoteError> {
        match self.inner.as_ref() {
            GateInner::Remote { client, .. } => {
                client.authorize_scoped_resource_evaluation(workspace, namespace, request)
            }
            GateInner::Open | GateInner::Local { .. } => Err(RemoteError::new(
                "current scoped freshness requires the remote native authority".into(),
            )),
        }
    }
    fn authorize_scoped_resource(
        &self,
        workspace: &WorkspaceId,
        namespace: &NamespaceId,
        request: &ResourceAuthorizationRequest,
    ) -> Result<AuthorizationOutcome, RemoteError> {
        match self.inner.as_ref() {
            GateInner::Remote { client, .. } => {
                client.authorize_scoped_resource(workspace, namespace, request)
            }
            GateInner::Open | GateInner::Local { .. } => Err(RemoteError::new(
                "current scoped decisions require the remote native authority".into(),
            )),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn open_and_embedded_gates_cannot_substitute_legacy_permission_for_scoped_decisions() {
        let request = ResourceAuthorizationRequest {
            request: AuthorizationRequest::direct(
                PrincipalRef::Service {
                    service_id: "caller".into(),
                },
                ActionKey("tenant::read".into()),
                ScopeRef::Workspace {
                    workspace_id: WorkspaceId("w".into()),
                },
            ),
            context: Default::default(),
        };
        let local = crate::embed_local(&crate::HostConfig::local_in_memory()).unwrap();
        for gate in [IamGate::open(), local.gate] {
            assert!(
                gate.authorize_scoped_resource(
                    &WorkspaceId("w".into()),
                    &NamespaceId("tenant".into()),
                    &request
                )
                .is_err()
            );
        }
    }
}
