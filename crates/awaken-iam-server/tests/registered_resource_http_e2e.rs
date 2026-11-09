//! Exact opt-in registration through native HTTP and the two real SQL stores.
use awaken_iam_contract::*;
use awaken_iam_core::{
    ActionPattern, AuthorizationProfileRepository, Effect, Grant, GrantId, GrantRepository,
    GrantSubject, OrgRepository, Organization, ResourceEdge, ResourceModelRepository,
};
use awaken_iam_server::{
    AdminAuthPolicy, AuthApi, AuthorizationProfileAdmin, AuthzApi, DaemonState, FenceStore,
    SqlConn, SqlStore, daemon_router, http, projection_router, sqlite_in_memory_store,
};
use std::sync::{Arc, Mutex};

const NS: &str = "awaken.workspace";
const ACTION: &str = "awaken.workspace::agent.use";
fn account() -> PrincipalRef {
    PrincipalRef::Account {
        account_id: AccountId("owner".into()),
    }
}
fn target() -> ScopeRef {
    ScopeRef::Resource {
        resource_type: ResourceType("awaken.agent".into()),
        resource_id: ResourceId("issuer/workspace/agent".into()),
    }
}
fn workspace() -> ScopeRef {
    ScopeRef::Workspace {
        workspace_id: WorkspaceId("w1".into()),
    }
}
fn at() -> Timestamp {
    Timestamp("2026-11-09T00:00:00Z".into())
}
fn question() -> RegisteredResourceAuthorizationRequest {
    RegisteredResourceAuthorizationRequest {
        authorization: ResourceAuthorizationRequest {
            request: AuthorizationRequest::direct(account(), ActionKey(ACTION.into()), target()),
            context: Default::default(),
        },
        namespace: NamespaceId(NS.into()),
        product_id: ProductId::new("awaken").unwrap(),
        workspace_id: WorkspaceId("w1".into()),
        resource_type: ResourceType("awaken.agent".into()),
    }
}
fn document() -> AuthorizationProfileDocument {
    AuthorizationProfileDocument {
        resource_product: Some(ProductId::new("awaken").unwrap()),
        resource_model: ResourceModelRegistration {
            resource_types: vec![ResourceTypeRegistration {
                resource_type: ResourceType("awaken.agent".into()),
                parent_type: None,
                actions: vec![ActionKey(ACTION.into())],
            }],
            ..Default::default()
        },
        action_scope_rules: vec![ActionScopeRule {
            action_pattern: ACTION.into(),
            allowed_scope_kinds: vec![ScopeKind::Resource {
                resource_type: ResourceType("awaken.agent".into()),
            }],
        }],
        ..Default::default()
    }
}
fn projection() -> ResourceProjectionBatch {
    ResourceProjectionBatch {
        product_id: ProductId::new("awaken").unwrap(),
        org_id: OrgId("o1".into()),
        projection_id: "agent:original".into(),
        idempotency_key: "agent:1".into(),
        epoch: 1,
        grants: vec![],
        scope_edges: vec![ResourceParentEdge {
            resource_type: ResourceType("awaken.agent".into()),
            resource_id: ResourceId("issuer/workspace/agent".into()),
            parent: workspace(),
        }],
        retirements: vec![],
    }
}
fn seed<B: SqlConn>(store: &SqlStore<B>) {
    for (org, ws) in [("o1", "w1"), ("o2", "w2"), ("o1", "w3")] {
        OrgRepository::upsert(
            store,
            Organization {
                id: OrgId(org.into()),
                display_name: None,
                owner: account(),
                created_at: at(),
                updated_at: at(),
            },
        )
        .unwrap();
        ResourceModelRepository::put_workspace_org(
            store,
            WorkspaceOrgEdge {
                workspace_id: WorkspaceId(ws.into()),
                org_id: OrgId(org.into()),
            },
        )
        .unwrap();
    }
    grant(store, "*", Effect::Allow, target());
}
fn grant<B: SqlConn>(store: &SqlStore<B>, action: &str, effect: Effect, scope: ScopeRef) {
    GrantRepository::put(
        store,
        Grant {
            id: GrantId("current".into()),
            subject: GrantSubject::Principal(account()),
            action_pattern: ActionPattern(action.into()),
            scope,
            effect,
        },
    )
    .unwrap();
}
fn publish<B: SqlConn + Clone + 'static>(
    store: &SqlStore<B>,
    document: AuthorizationProfileDocument,
) -> u64 {
    let pap = AuthorizationProfileAdmin::new(Arc::new(store.clone()));
    let p = pap
        .create_draft(CreateAuthorizationProfile {
            namespace: NamespaceId(NS.into()),
            document,
            created_at: at(),
        })
        .unwrap();
    assert!(pap.validate(&p.namespace, p.revision).unwrap().valid);
    let active = AuthorizationProfileRepository::active_profile(store, &p.namespace)
        .unwrap()
        .map(|p| p.revision);
    pap.activate(
        &mut AuthzApi::new(),
        &PolicySnapshot::default(),
        &p.namespace,
        p.revision,
        ActivateAuthorizationProfile {
            expected_active_revision: active,
        },
    )
    .unwrap();
    p.revision
}
async fn serve<B: SqlConn + Clone + 'static>(
    store: SqlStore<B>,
) -> (String, tokio::task::JoinHandle<()>) {
    let state = Arc::new(Mutex::new(
        DaemonState::with_policy_store(
            AuthzApi::new(),
            AdminAuthPolicy::deny_all(),
            Arc::new(store.clone()),
            store,
            AuthApi::new().token_authority(),
        )
        .unwrap(),
    ));
    let router = daemon_router(state.clone()).merge(projection_router(state));
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let handle = tokio::spawn(async move {
        http::serve(listener, router).await.unwrap();
    });
    (format!("http://{address}"), handle)
}
async fn strict(
    client: &reqwest::Client,
    base: &str,
    request: &RegisteredResourceAuthorizationRequest,
) -> RegisteredResourceAuthorizationEvaluation {
    client
        .post(format!("{base}/v1/authorize/resource/registered"))
        .json(request)
        .send()
        .await
        .unwrap()
        .error_for_status()
        .unwrap()
        .json()
        .await
        .unwrap()
}
async fn legacy(client: &reqwest::Client, base: &str) -> AuthorizationOutcome {
    client
        .post(format!("{base}/v1/authorize/resource"))
        .json(&question().authorization)
        .send()
        .await
        .unwrap()
        .error_for_status()
        .unwrap()
        .json()
        .await
        .unwrap()
}
async fn exercise<B: SqlConn + Clone + 'static>(store: SqlStore<B>, prefix: &str) {
    seed(&store);
    let (base, handle) = serve(store.clone()).await;
    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(5))
        .build()
        .unwrap();
    // R1 negative control: exact legacy '*' grants need no profile or parent.
    assert_eq!(
        legacy(&client, &base).await.decision,
        AuthorizationDecision::Allow
    );
    let before = store.fence().unwrap();
    let result = strict(&client, &base, &question()).await;
    assert_eq!(
        result.evaluation.outcome.decision,
        AuthorizationDecision::Deny
    );
    assert!(result.registration.is_none());
    assert_eq!(store.fence().unwrap(), before, "evaluation writes nothing");
    let mut legacy_profile = document();
    legacy_profile.resource_product = None;
    publish(&store, legacy_profile);
    assert_eq!(
        strict(&client, &base, &question())
            .await
            .evaluation
            .outcome
            .decision,
        AuthorizationDecision::Deny,
        "a legacy profile is not silently assigned a product"
    );
    publish(&store, document());
    assert_eq!(
        strict(&client, &base, &question())
            .await
            .evaluation
            .outcome
            .decision,
        AuthorizationDecision::Deny,
        "R2 vocabulary is missing"
    );
    store
        .register_product_resource_model(&ProductResourceModelRequest {
            product_id: ProductId::new("awaken").unwrap(),
            resource_model: document().resource_model,
        })
        .unwrap();
    assert_eq!(
        strict(&client, &base, &question())
            .await
            .evaluation
            .outcome
            .decision,
        AuthorizationDecision::Deny,
        "R3 projection is missing"
    );
    ResourceModelRepository::put_edge(
        &store,
        ResourceEdge {
            resource_type: question().resource_type,
            resource_id: ResourceId("issuer/workspace/agent".into()),
            parent: workspace(),
        },
    )
    .unwrap();
    assert_eq!(
        strict(&client, &base, &question())
            .await
            .evaluation
            .outcome
            .decision,
        AuthorizationDecision::Deny,
        "R4 manual edge is not versioned ownership"
    );
    ResourceModelRepository::remove_edge(
        &store,
        &ResourceType("awaken.agent".into()),
        &ResourceId("issuer/workspace/agent".into()),
    )
    .unwrap();
    store.apply_resource_projection(&projection()).unwrap();
    let native_base = base.clone();
    let native = tokio::task::spawn_blocking(move || {
        use awaken_iam_client::{HttpAuthzTransport, HttpTransportConfig, RemoteIamClient};
        RemoteIamClient::new(
            HttpAuthzTransport::new(HttpTransportConfig::new(native_base).with_max_retries(0))
                .unwrap(),
        )
        .authorize_registered_resource(&question())
    })
    .await
    .unwrap()
    .unwrap();
    assert_eq!(
        native.evaluation.outcome.decision,
        AuthorizationDecision::Allow,
        "canonical native client/server pair"
    );
    let allowed = strict(&client, &base, &question()).await;
    assert_eq!(
        allowed.evaluation.outcome.decision,
        AuthorizationDecision::Allow
    );
    let proof = allowed.registration.unwrap();
    assert_eq!(proof.product_id, question().product_id);
    assert_eq!(proof.workspace_id, question().workspace_id);
    assert_eq!(proof.projection_epoch, 1);
    assert_eq!(proof.action.0, ACTION);
    assert!(allowed.evaluation.freshness.is_some());
    // Exact type/action association and Resource scope are independent inputs.
    for case in 0..3 {
        let mut altered = document();
        match case {
            0 => {
                altered.resource_model.resource_types[0].actions.clear();
                altered
                    .resource_model
                    .actions
                    .push(ActionKey(ACTION.into()));
            }
            1 => altered.action_scope_rules[0].allowed_scope_kinds = vec![ScopeKind::Workspace],
            2 => {
                altered.resource_model.resource_types[0].resource_type =
                    ResourceType("awaken.other".into());
                altered.action_scope_rules[0].allowed_scope_kinds = vec![ScopeKind::Resource {
                    resource_type: ResourceType("awaken.other".into()),
                }];
            }
            _ => unreachable!(),
        }
        publish(&store, altered);
        let result = strict(&client, &base, &question()).await;
        assert_eq!(
            result.evaluation.outcome.decision,
            AuthorizationDecision::Deny,
            "profile mismatch {case}"
        );
        assert!(result.registration.is_none());
    }
    publish(&store, document());
    let mut unregistered = document().resource_model;
    unregistered.resource_types[0].actions.clear();
    store
        .register_product_resource_model(&ProductResourceModelRequest {
            product_id: question().product_id,
            resource_model: unregistered,
        })
        .unwrap();
    assert_eq!(
        strict(&client, &base, &question())
            .await
            .evaluation
            .outcome
            .decision,
        AuthorizationDecision::Deny,
        "product type must actually declare the action"
    );
    store
        .register_product_resource_model(&ProductResourceModelRequest {
            product_id: question().product_id,
            resource_model: document().resource_model,
        })
        .unwrap();
    for case in 0..7 {
        let mut changed = question();
        match case {
            0 => changed.namespace = NamespaceId("other".into()),
            1 => changed.product_id = ProductId::new("other").unwrap(),
            2 => changed.workspace_id = WorkspaceId("w2".into()),
            3 => changed.resource_type = ResourceType("other".into()),
            4 => changed.authorization.context.resource_id = Some("other".into()),
            5 => changed.authorization.context.resource_type = Some("other".into()),
            6 => changed.workspace_id = WorkspaceId("w3".into()),
            _ => unreachable!(),
        }
        let before = store.fence().unwrap();
        let result = strict(&client, &base, &changed).await;
        assert_eq!(
            result.evaluation.outcome.decision,
            AuthorizationDecision::Deny,
            "R5 mismatch {case}"
        );
        assert!(result.registration.is_none());
        assert_eq!(store.fence().unwrap(), before);
    }
    // R6 registration cannot provide a permission or discharge approval.
    grant(
        &store,
        "awaken.workspace::workspace.read",
        Effect::Allow,
        workspace(),
    );
    assert_eq!(
        strict(&client, &base, &question())
            .await
            .evaluation
            .outcome
            .decision,
        AuthorizationDecision::Deny
    );
    for (effect, decision) in [
        (Effect::Deny, AuthorizationDecision::Deny),
        (
            Effect::RequireApproval,
            AuthorizationDecision::RequireApproval,
        ),
        (Effect::Allow, AuthorizationDecision::Allow),
    ] {
        grant(&store, ACTION, effect, target());
        assert_eq!(
            strict(&client, &base, &question())
                .await
                .evaluation
                .outcome
                .decision,
            decision
        );
    }
    // R7 peer grant revocation is visible on the first new strict request.
    let (peer, peer_handle) = serve(store.clone()).await;
    assert_eq!(
        strict(&client, &peer, &question())
            .await
            .evaluation
            .outcome
            .decision,
        AuthorizationDecision::Allow
    );
    GrantRepository::remove(&store, &GrantId("current".into())).unwrap();
    assert_eq!(
        strict(&client, &peer, &question())
            .await
            .evaluation
            .outcome
            .decision,
        AuthorizationDecision::Deny
    );
    grant(&store, "*", Effect::Allow, target());
    // R8 owner history is retained across retirement and cannot be cleared.
    let revision = AuthorizationProfileRepository::active_profile(&store, &NamespaceId(NS.into()))
        .unwrap()
        .unwrap()
        .revision;
    AuthorizationProfileRepository::retire_active_profile(
        &store,
        &NamespaceId(NS.into()),
        revision,
    )
    .unwrap();
    assert_eq!(
        legacy(&client, &peer).await.decision,
        AuthorizationDecision::Allow,
        "legacy compatibility remains explicit"
    );
    assert_eq!(
        strict(&client, &peer, &question())
            .await
            .evaluation
            .outcome
            .decision,
        AuthorizationDecision::Deny
    );
    let history =
        AuthorizationProfileRepository::list_profiles(&store, &NamespaceId(NS.into())).unwrap();
    for product in [None, Some(ProductId::new("other").unwrap())] {
        let mut invalid = history[0].clone();
        invalid.revision = revision + 1;
        invalid.document.resource_product = product;
        assert!(AuthorizationProfileRepository::create_profile(&store, invalid).is_err());
    }
    assert_eq!(
        AuthorizationProfileRepository::list_profiles(&store, &NamespaceId(NS.into())).unwrap(),
        history
    );
    publish(&store, document());
    let mut retired = projection();
    retired.epoch = 2;
    retired.idempotency_key = "agent:2".into();
    retired.scope_edges.clear();
    retired.retirements.push(ResourceRetirement {
        resource_type: ResourceType("awaken.agent".into()),
        resource_id: ResourceId("issuer/workspace/agent".into()),
        grant_ids: vec![],
    });
    store.apply_resource_projection(&retired).unwrap();
    assert_eq!(
        strict(&client, &peer, &question())
            .await
            .evaluation
            .outcome
            .decision,
        AuthorizationDecision::Deny,
        "R9 retired projection"
    );
    // R10 missing source fence never falls back to a cached, qualified Allow.
    store
        .backend()
        .execute(&format!("DROP TABLE {prefix}_fence"), &[])
        .unwrap();
    assert_eq!(
        client
            .post(format!("{peer}/v1/authorize/resource/registered"))
            .json(&question())
            .send()
            .await
            .unwrap()
            .status(),
        503
    );
    handle.abort();
    peer_handle.abort();
    let _ = handle.await;
    let _ = peer_handle.await;
}
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn sqlite_registered_resource_requires_native_profile_vocabulary_and_owned_projection() {
    exercise(
        sqlite_in_memory_store("strict_registration_sqlite").unwrap(),
        "strict_registration_sqlite",
    )
    .await;
}
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn postgres_registered_resource_requires_native_profile_vocabulary_and_owned_projection() {
    let Ok(url) = std::env::var("IAM_TEST_POSTGRES_URL") else {
        assert!(
            std::env::var_os("AWAKEN_TEST_REQUIRE_POSTGRES").is_none(),
            "required PostgreSQL fixture missing"
        );
        eprintln!("SKIPPED native PostgreSQL registration: no fixture supplied");
        return;
    };
    let prefix = format!(
        "strict_reg_{:x}",
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    );
    let store = awaken_iam_server::postgres_migrated_store(&url, &prefix).unwrap();
    exercise(store, &prefix).await;
}

#[path = "registered_resource_http_e2e/races.rs"]
mod races;

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_foreign_profile_repository_cannot_qualify_a_different_physical_store() {
    let store = sqlite_in_memory_store("strict_canonical_owner").unwrap();
    seed(&store);
    store
        .register_product_resource_model(&ProductResourceModelRequest {
            product_id: question().product_id,
            resource_model: document().resource_model,
        })
        .unwrap();
    store.apply_resource_projection(&projection()).unwrap();
    let foreign = sqlite_in_memory_store("strict_foreign_profiles").unwrap();
    publish(&foreign, document());
    let state = Arc::new(Mutex::new(
        DaemonState::with_policy_store(
            AuthzApi::new(),
            AdminAuthPolicy::deny_all(),
            Arc::new(foreign),
            store.clone(),
            AuthApi::new().token_authority(),
        )
        .unwrap(),
    ));
    let router = daemon_router(state.clone()).merge(projection_router(state));
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let handle = tokio::spawn(async move {
        http::serve(listener, router).await.unwrap();
    });
    let base = format!("http://{address}");
    let client = reqwest::Client::new();
    assert_eq!(
        legacy(&client, &base).await.decision,
        AuthorizationDecision::Allow,
        "legacy composition supplied a foreign profile"
    );
    let before = store.fence().unwrap();
    let strict_result = strict(&client, &base, &question()).await;
    assert_eq!(
        strict_result.evaluation.outcome.decision,
        AuthorizationDecision::Deny
    );
    assert!(strict_result.registration.is_none());
    assert_eq!(store.fence().unwrap(), before);
    assert!(
        AuthorizationProfileRepository::active_profile(&store, &NamespaceId(NS.into()))
            .unwrap()
            .is_none()
    );
    handle.abort();
    let _ = handle.await;
}

#[path = "registered_resource_http_e2e/single_attempt.rs"]
mod single_attempt;

#[path = "registered_resource_http_e2e/parent_path.rs"]
mod parent_path;
