use super::tests::{Reply, StubServer, transport};
use super::*;
use crate::ScopedProfileConsumer;
use awaken_iam_contract::*;

fn request() -> ResourceCandidateRequest {
    ResourceCandidateRequest {
        mode: ResourceAuthorizationMode::Scoped,
        request: AuthorizationRequest::direct(
            PrincipalRef::Account {
                account_id: AccountId("alice".into()),
            },
            ActionKey("tenant::read".into()),
            ScopeRef::Workspace {
                workspace_id: WorkspaceId("w".into()),
            },
        ),
        resource_type: Some("document".into()),
        access: AuthorizationAccess::Read,
    }
}
fn freshness(character: char) -> String {
    format!("iam-fence-v1:{}", character.to_string().repeat(64))
}
fn header(value: &str) -> Vec<(String, String)> {
    vec![(AUTHORIZATION_FRESHNESS_HEADER.into(), value.into())]
}
fn candidate(value: &str) -> String {
    serde_json::to_string(&ResourceCandidateEvaluation {
        freshness: value.into(),
        plan: ResourceCandidatePlan {
            predicate: ResourceCandidatePredicate::OwnerIn {
                principals: vec![request().request.principal],
            },
            broadening_reasons: vec![],
        },
    })
    .unwrap()
}

#[test]
fn source_hint_tracks_the_transport_endpoint_without_exposing_credential_sources() {
    for endpoint in [
        "https://iam.example.test/",
        "https://iam.example.test/tenant",
    ] {
        let transport = HttpAuthzTransport::new(
            HttpTransportConfig::new(endpoint).with_service_token("fixture-service-credential"),
        )
        .unwrap();
        assert_eq!(
            transport.configured_endpoint(),
            Some(endpoint.trim_end_matches('/'))
        );
        let client = crate::RemoteIamClient::new(transport);
        assert_eq!(
            client.configured_endpoint(),
            Some(endpoint.trim_end_matches('/'))
        );
    }
    for endpoint in [
        "https://fixture-user:fixture-password@iam.example.test",
        "https://iam.example.test?fixture_key=value",
        "https://iam.example.test#fixture-fragment",
        "not a URL",
    ] {
        let transport = HttpAuthzTransport::new(HttpTransportConfig::new(endpoint)).unwrap();
        assert_eq!(transport.configured_endpoint(), None);
    }
}

#[test]
fn candidate_freshness_is_required_consistent_and_not_a_legacy_endpoint_fallback() {
    let observed = freshness('a');
    for headers in [
        vec![],
        header("malformed"),
        header(&freshness('b')),
        vec![
            (AUTHORIZATION_FRESHNESS_HEADER.into(), observed.clone()),
            (AUTHORIZATION_FRESHNESS_HEADER.into(), observed.clone()),
        ],
    ] {
        let server = StubServer::start(vec![Reply::Headers(candidate(&observed), headers)]);
        assert!(
            transport(&server)
                .scoped_resource_candidates(
                    &WorkspaceId("w".into()),
                    &NamespaceId("tenant".into()),
                    &request()
                )
                .is_err()
        );
        assert_eq!(server.requests().len(), 1);
        assert!(server.requests()[0].starts_with(
            "POST /v1/scoped-authz/workspaces/w/profiles/tenant/resource-candidates "
        ));
    }
    let server = StubServer::start(vec![Reply::Headers(
        candidate(&observed),
        header(&observed),
    )]);
    assert_eq!(
        transport(&server)
            .scoped_resource_candidates(
                &WorkspaceId("w".into()),
                &NamespaceId("tenant".into()),
                &request()
            )
            .unwrap()
            .freshness,
        observed
    );
}

#[test]
fn batch_transport_preserves_every_context_field_and_rejects_truncated_results() {
    let observed = freshness('c');
    let mut contextual = ResourceAuthorizationRequest {
        request: request().request,
        context: Default::default(),
    };
    contextual.request.on_behalf_of.push(PrincipalRef::Service {
        service_id: "agent".into(),
    });
    contextual.context = AuthorizationContext {
        resource_id: Some("current".into()),
        resource_type: Some("document".into()),
        owner: Some(PrincipalRef::Account {
            account_id: AccountId("alice".into()),
        }),
        access: AuthorizationAccess::Read,
        fields: Some(vec!["label".into()]),
        predecessors: vec![AuthorizationPredecessor {
            resource_id: "old".into(),
            scope: contextual.request.scope.clone(),
        }],
        ..Default::default()
    };
    let batch = ResourceAuthorizationBatchRequest {
        mode: ResourceAuthorizationMode::Scoped,
        requests: vec![contextual],
    };
    let outcome = AuthorizationOutcome {
        decision: AuthorizationDecision::Deny,
        reason: "native".into(),
        matched_grants: vec![],
        matched_roles: vec![],
        obligation: None,
    };
    for outcomes in [vec![outcome.clone()], vec![]] {
        let valid = outcomes.len() == 1;
        let server = StubServer::start(vec![Reply::Headers(
            serde_json::to_string(&ResourceAuthorizationBatchEvaluation {
                outcomes,
                freshness: observed.clone(),
            })
            .unwrap(),
            header(&observed),
        )]);
        let result = transport(&server).authorize_scoped_resources_evaluation(
            &WorkspaceId("w".into()),
            &NamespaceId("tenant".into()),
            &batch,
        );
        assert_eq!(result.is_ok(), valid);
        let requests = server.requests();
        assert_eq!(requests.len(), 1);
        let body = requests[0].split_once("\r\n\r\n").unwrap().1;
        assert_eq!(
            serde_json::from_str::<ResourceAuthorizationBatchRequest>(body).unwrap(),
            batch
        );
    }
}

#[test]
fn unsupported_personal_or_write_requests_fail_before_any_network_or_legacy_fallback() {
    let client = HttpAuthzTransport::new(HttpTransportConfig::new("http://127.0.0.1:1")).unwrap();
    let workspace = WorkspaceId("w".into());
    let namespace = NamespaceId("tenant".into());
    let mut request = request();
    request.mode = ResourceAuthorizationMode::PersonalDelegation;
    assert_eq!(
        client
            .scoped_resource_candidates(&workspace, &namespace, &request)
            .unwrap_err()
            .status(),
        Some(501)
    );
    request.mode = ResourceAuthorizationMode::Scoped;
    request.access = AuthorizationAccess::Write;
    assert_eq!(
        client
            .scoped_resource_candidates(&workspace, &namespace, &request)
            .unwrap_err()
            .status(),
        Some(501)
    );
    let batch = ResourceAuthorizationBatchRequest {
        mode: ResourceAuthorizationMode::PersonalDelegation,
        requests: vec![],
    };
    assert_eq!(
        client
            .authorize_scoped_resources_evaluation(&workspace, &namespace, &batch)
            .unwrap_err()
            .status(),
        Some(501)
    );
}
