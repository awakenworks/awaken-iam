//! Transport observations are explicit and never synthesize a cached Allow.
use super::tests::{Reply, StubServer, transport};
use super::*;
use crate::ScopedProfileConsumer;
use awaken_iam_contract::{
    AccountId, ActionKey, AuthorizationDecision, PrincipalRef, ScopeRef, WorkspaceId,
};

fn evaluation_request() -> ResourceAuthorizationRequest {
    ResourceAuthorizationRequest {
        request: AuthorizationRequest::direct(
            PrincipalRef::Account {
                account_id: AccountId("ada".into()),
            },
            ActionKey("documents::resource.read".into()),
            ScopeRef::Global,
        ),
        context: Default::default(),
    }
}
fn evaluation_body(decision: AuthorizationDecision) -> String {
    serde_json::to_string(&AuthorizationOutcome {
        decision,
        reason: "current".into(),
        matched_grants: vec![],
        matched_roles: vec![],
        obligation: None,
    })
    .unwrap()
}
#[test]
fn evaluation_never_qualifies_a_legacy_or_malformed_allow() {
    let valid = format!("iam-fence-v1:{}", "a".repeat(64));
    for headers in [
        vec![],
        vec![(
            awaken_iam_contract::AUTHORIZATION_FRESHNESS_HEADER.into(),
            "old-cache".into(),
        )],
        vec![
            (
                awaken_iam_contract::AUTHORIZATION_FRESHNESS_HEADER.into(),
                valid.clone(),
            ),
            (
                awaken_iam_contract::AUTHORIZATION_FRESHNESS_HEADER.into(),
                valid.clone(),
            ),
        ],
    ] {
        let server = StubServer::start(vec![Reply::Headers(
            evaluation_body(AuthorizationDecision::Allow),
            headers,
        )]);
        assert!(
            transport(&server)
                .authorize_resource_evaluation(&evaluation_request())
                .is_err()
        );
        assert_eq!(server.requests().len(), 1);
    }
}
#[test]
fn evaluation_observes_each_fresh_response_without_caching_an_allow() {
    let first = format!("iam-fence-v1:{}", "a".repeat(64));
    let second = format!("iam-fence-v1:{}", "b".repeat(64));
    let header = |value: &str| {
        vec![(
            awaken_iam_contract::AUTHORIZATION_FRESHNESS_HEADER.into(),
            value.into(),
        )]
    };
    let server = StubServer::start(vec![
        Reply::Headers(
            evaluation_body(AuthorizationDecision::Allow),
            header(&first),
        ),
        Reply::Headers(
            evaluation_body(AuthorizationDecision::Deny),
            header(&second),
        ),
        Reply::Status(503),
    ]);
    let transport = transport(&server);
    let a = transport
        .authorize_resource_evaluation(&evaluation_request())
        .unwrap();
    let b = transport
        .authorize_resource_evaluation(&evaluation_request())
        .unwrap();
    assert_eq!(a.outcome.decision, AuthorizationDecision::Allow);
    assert_eq!(a.freshness.as_deref(), Some(first.as_str()));
    assert_eq!(b.outcome.decision, AuthorizationDecision::Deny);
    assert_eq!(b.freshness.as_deref(), Some(second.as_str()));
    assert!(
        transport
            .authorize_resource_evaluation(&evaluation_request())
            .is_err()
    );
    assert_eq!(server.requests().len(), 3);
}
#[test]
fn an_explicit_deny_without_a_freshness_observation_stays_a_deny() {
    let server = StubServer::start(vec![Reply::Ok(evaluation_body(
        AuthorizationDecision::Deny,
    ))]);
    let result = transport(&server)
        .authorize_resource_evaluation(&evaluation_request())
        .unwrap();
    assert_eq!(result.outcome.decision, AuthorizationDecision::Deny);
    assert!(result.freshness.is_none());
}
#[test]
fn scoped_evaluation_keeps_exact_workspace_and_never_retries_legacy_authorization() {
    let freshness = format!("iam-fence-v1:{}", "c".repeat(64));
    let server = StubServer::start(vec![Reply::Headers(
        evaluation_body(AuthorizationDecision::Allow),
        vec![(
            awaken_iam_contract::AUTHORIZATION_FRESHNESS_HEADER.into(),
            freshness.clone(),
        )],
    )]);
    let result = transport(&server)
        .authorize_scoped_resource_evaluation(
            &WorkspaceId("w".into()),
            &NamespaceId("tenant".into()),
            &evaluation_request(),
        )
        .unwrap();
    assert_eq!(result.freshness.as_deref(), Some(freshness.as_str()));
    assert!(
        server.requests()[0]
            .starts_with("POST /v1/scoped-authz/workspaces/w/profiles/tenant/authorize ")
    );
    let legacy = StubServer::start(vec![Reply::Ok(evaluation_body(
        AuthorizationDecision::Allow,
    ))]);
    assert!(
        transport(&legacy)
            .authorize_scoped_resource_evaluation(
                &WorkspaceId("w".into()),
                &NamespaceId("tenant".into()),
                &evaluation_request()
            )
            .is_err()
    );
    assert_eq!(
        legacy.requests().len(),
        1,
        "missing scoped metadata cannot fall back to a global endpoint"
    );
}
