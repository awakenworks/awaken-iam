//! Current scoped decisions reuse the gate's original remote client/credentials.
use super::*;
use awaken_iam_client::ScopedProfileConsumer;
use awaken_iam_contract::NamespaceId;

impl ScopedProfileConsumer for IamGate {
    fn configured_endpoint(&self) -> Option<&str> {
        match self.inner.as_ref() {
            GateInner::Remote { client, .. } => client.configured_endpoint(),
            GateInner::Open | GateInner::Local { .. } => None,
        }
    }
    fn authorize_scoped_resources_evaluation(
        &self,
        workspace: &WorkspaceId,
        namespace: &NamespaceId,
        request: &awaken_iam_contract::ResourceAuthorizationBatchRequest,
    ) -> Result<awaken_iam_contract::ResourceAuthorizationBatchEvaluation, RemoteError> {
        match self.inner.as_ref() {
            GateInner::Remote { client, .. } => {
                client.authorize_scoped_resources_evaluation(workspace, namespace, request)
            }
            GateInner::Open | GateInner::Local { .. } => Err(RemoteError::response(
                501,
                "scoped contextual batch requires the remote native authority".into(),
            )),
        }
    }
    fn scoped_resource_candidates(
        &self,
        workspace: &WorkspaceId,
        namespace: &NamespaceId,
        request: &awaken_iam_contract::ResourceCandidateRequest,
    ) -> Result<awaken_iam_contract::ResourceCandidateEvaluation, RemoteError> {
        match self.inner.as_ref() {
            GateInner::Remote { client, .. } => {
                client.scoped_resource_candidates(workspace, namespace, request)
            }
            GateInner::Open | GateInner::Local { .. } => Err(RemoteError::response(
                501,
                "scoped candidate capability requires the remote native authority".into(),
            )),
        }
    }
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
    fn remote_gate_retains_the_actual_configured_transport_source_hint() {
        let transport = HttpAuthzTransport::new(awaken_iam_client::HttpTransportConfig::new(
            "https://iam.example.test/tenant/",
        ))
        .unwrap();
        let gate = IamGate::remote(RemoteIamClient::new(transport), None);
        assert_eq!(
            gate.configured_endpoint(),
            Some("https://iam.example.test/tenant")
        );
    }

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
            assert_eq!(gate.configured_endpoint(), None);
            let workspace = WorkspaceId("w".into());
            let namespace = NamespaceId("tenant".into());
            let batch = awaken_iam_contract::ResourceAuthorizationBatchRequest {
                mode: awaken_iam_contract::ResourceAuthorizationMode::Scoped,
                requests: vec![request.clone()],
            };
            let candidate = awaken_iam_contract::ResourceCandidateRequest {
                mode: awaken_iam_contract::ResourceAuthorizationMode::Scoped,
                request: request.request.clone(),
                resource_type: None,
                access: awaken_iam_contract::AuthorizationAccess::Read,
            };
            assert_eq!(
                gate.authorize_scoped_resources_evaluation(&workspace, &namespace, &batch)
                    .unwrap_err()
                    .status(),
                Some(501)
            );
            assert_eq!(
                gate.scoped_resource_candidates(&workspace, &namespace, &candidate)
                    .unwrap_err()
                    .status(),
                Some(501)
            );
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
