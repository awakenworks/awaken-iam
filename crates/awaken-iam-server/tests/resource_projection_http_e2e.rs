//! Real HTTP proof for the guarded product resource-projection route.

use std::sync::{Arc, Mutex};
use std::time::Duration;

use awaken_iam_contract::{
    AccountId, ActionKey, AuthorizationDecision, AuthorizationOutcome, AuthorizationRequest,
    GrantEffect, GrantSnapshot, GrantSubjectRef, OrgId, PrincipalRef, ProductId,
    ProductResourceModelRequest, ResourceId, ResourceModelRegistration, ResourceParentEdge,
    ResourceProjectionBatch, ResourceProjectionDisposition, ResourceProjectionReceipt,
    ResourceRetirement, ResourceType, ResourceTypeRegistration, ScopeRef, Timestamp, WorkspaceId,
    WorkspaceOrgEdge,
};
use awaken_iam_core::{
    ActionPattern, AuditSink, AuthorizationProfileRepository, Effect, Grant, GrantId,
    GrantRepository, GrantSubject, OrgRepository, Organization, ResourceModelRepository,
};
use awaken_iam_server::{
    AdminAuthPolicy, AuthApi, AuthzApi, DaemonState, SqlStore, SqliteBackend, daemon_router, http,
    projection_router, sqlite_in_memory_store, sqlite_migrated_store,
};

fn account() -> PrincipalRef {
    PrincipalRef::Account {
        account_id: AccountId("owner".into()),
    }
}

fn campus_scope() -> ScopeRef {
    ScopeRef::Resource {
        resource_type: ResourceType("tutor.campus".into()),
        resource_id: ResourceId("campus-1".into()),
    }
}

fn model() -> ProductResourceModelRequest {
    ProductResourceModelRequest {
        product_id: ProductId::new("tutor").unwrap(),
        resource_model: ResourceModelRegistration {
            resource_types: vec![ResourceTypeRegistration {
                resource_type: ResourceType("tutor.campus".into()),
                parent_type: None,
                actions: vec![ActionKey("tutor.campus.manage".into())],
            }],
            actions: vec![],
            edges: vec![],
        },
    }
}

fn create() -> ResourceProjectionBatch {
    ResourceProjectionBatch {
        product_id: ProductId::new("tutor").unwrap(),
        org_id: OrgId("org-a".into()),
        projection_id: "campus:campus-1".into(),
        idempotency_key: "campus:campus-1:1".into(),
        epoch: 1,
        grants: vec![GrantSnapshot {
            id: "campus-creator-manage".into(),
            subject: GrantSubjectRef::Principal {
                principal: account(),
            },
            action_pattern: "tutor.campus.manage".into(),
            scope: campus_scope(),
            effect: GrantEffect::Allow,
        }],
        scope_edges: vec![ResourceParentEdge {
            resource_type: ResourceType("tutor.campus".into()),
            resource_id: ResourceId("campus-1".into()),
            parent: ScopeRef::Workspace {
                workspace_id: WorkspaceId("workspace-a".into()),
            },
        }],
        retirements: vec![],
    }
}

fn seed(store: &SqlStore<SqliteBackend>) {
    for id in ["org-a", "org-b"] {
        OrgRepository::upsert(
            store,
            Organization {
                id: OrgId(id.into()),
                display_name: Some(id.into()),
                owner: account(),
                created_at: Timestamp("2026-01-01T00:00:00Z".into()),
                updated_at: Timestamp("2026-01-01T00:00:00Z".into()),
            },
        )
        .unwrap();
    }
    ResourceModelRepository::put_workspace_org(
        store,
        WorkspaceOrgEdge {
            workspace_id: WorkspaceId("workspace-a".into()),
            org_id: OrgId("org-a".into()),
        },
    )
    .unwrap();
}

async fn serve(store: SqlStore<SqliteBackend>) -> (String, tokio::task::JoinHandle<()>) {
    let profiles: Arc<dyn AuthorizationProfileRepository> = Arc::new(store.clone());
    let auth = AdminAuthPolicy::deny_all()
        .with_product_token(ProductId::new("tutor").unwrap(), "tutor-product-token");
    let state = Arc::new(Mutex::new(
        DaemonState::with_policy_store(
            AuthzApi::new(),
            auth,
            profiles,
            store,
            AuthApi::new().token_authority(),
        )
        .unwrap(),
    ));
    let router = daemon_router(state.clone()).merge(projection_router(state));
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let handle = tokio::spawn(async move {
        http::serve(listener, router).await.unwrap();
    });
    (format!("http://{addr}"), handle)
}

async fn authorize(client: &reqwest::Client, base: &str) -> AuthorizationDecision {
    authorize_account(client, base, "owner").await
}

async fn authorize_account(
    client: &reqwest::Client,
    base: &str,
    account_id: &str,
) -> AuthorizationDecision {
    client
        .post(format!("{base}/v1/authorize"))
        .json(&AuthorizationRequest::direct(
            PrincipalRef::Account {
                account_id: AccountId(account_id.into()),
            },
            ActionKey("tutor.campus.manage".into()),
            campus_scope(),
        ))
        .send()
        .await
        .unwrap()
        .error_for_status()
        .unwrap()
        .json::<AuthorizationOutcome>()
        .await
        .unwrap()
        .decision
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn second_daemon_observes_product_grant_and_revocation_from_shared_store() {
    let store = sqlite_in_memory_store("iam_projection_replicas").unwrap();
    seed(&store);
    let (writer, writer_handle) = serve(store.clone()).await;
    let (reader, reader_handle) = serve(store).await;
    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(5))
        .build()
        .unwrap();
    assert_eq!(
        authorize(&client, &reader).await,
        AuthorizationDecision::Deny
    );
    client
        .post(format!("{writer}/v1/authz/resource-model"))
        .bearer_auth("tutor-product-token")
        .json(&model())
        .send()
        .await
        .unwrap()
        .error_for_status()
        .unwrap();
    let grant = create();
    client
        .post(format!("{writer}/v1/authz/resource-provisions"))
        .bearer_auth("tutor-product-token")
        .json(&grant)
        .send()
        .await
        .unwrap()
        .error_for_status()
        .unwrap();
    assert_eq!(
        authorize(&client, &reader).await,
        AuthorizationDecision::Allow
    );

    let mut revoked = grant;
    revoked.epoch = 2;
    revoked.idempotency_key = "campus:campus-1:2".into();
    revoked.grants.clear();
    revoked.scope_edges.clear();
    revoked.retirements.push(ResourceRetirement {
        resource_type: ResourceType("tutor.campus".into()),
        resource_id: ResourceId("campus-1".into()),
        grant_ids: vec!["campus-creator-manage".into()],
    });
    client
        .post(format!("{writer}/v1/authz/resource-provisions"))
        .bearer_auth("tutor-product-token")
        .json(&revoked)
        .send()
        .await
        .unwrap()
        .error_for_status()
        .unwrap();
    assert_eq!(
        authorize(&client, &reader).await,
        AuthorizationDecision::Deny
    );
    writer_handle.abort();
    reader_handle.abort();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn product_route_authenticates_and_retires_under_a_restartable_policy_fence() {
    let store = sqlite_in_memory_store("iam_projection_http").unwrap();
    seed(&store);
    let (base, handle) = serve(store.clone()).await;
    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(5))
        .build()
        .unwrap();
    let route = format!("{base}/v1/authz/resource-provisions");
    let model_route = format!("{base}/v1/authz/resource-model");
    let create = create();

    assert_eq!(
        client
            .post(&route)
            .json(&create)
            .send()
            .await
            .unwrap()
            .status(),
        401
    );
    let mut wrong_product = create.clone();
    wrong_product.product_id = ProductId::new("other").unwrap();
    assert_eq!(
        client
            .post(&route)
            .bearer_auth("tutor-product-token")
            .json(&wrong_product)
            .send()
            .await
            .unwrap()
            .status(),
        403
    );
    assert_eq!(authorize(&client, &base).await, AuthorizationDecision::Deny);
    assert_eq!(
        client
            .post(&model_route)
            .bearer_auth("tutor-product-token")
            .json(&model())
            .send()
            .await
            .unwrap()
            .status(),
        200
    );

    let first: ResourceProjectionReceipt = client
        .post(&route)
        .bearer_auth("tutor-product-token")
        .json(&create)
        .send()
        .await
        .unwrap()
        .error_for_status()
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(first.disposition, ResourceProjectionDisposition::Applied);
    assert_eq!(
        authorize(&client, &base).await,
        AuthorizationDecision::Allow
    );
    let replay: ResourceProjectionReceipt = client
        .post(&route)
        .bearer_auth("tutor-product-token")
        .json(&create)
        .send()
        .await
        .unwrap()
        .error_for_status()
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(replay.disposition, ResourceProjectionDisposition::Replayed);
    assert_eq!(replay.version, first.version);

    // The Tutor staff outbox sends the same product wire shape: a distinct
    // projection stream owns a complete grant snapshot at a campus resource.
    let staff = ResourceProjectionBatch {
        product_id: ProductId::new("tutor").unwrap(),
        org_id: OrgId("org-a".into()),
        projection_id: "staff:staff-1".into(),
        idempotency_key: "staff:staff-1:1".into(),
        epoch: 1,
        grants: vec![GrantSnapshot {
            id: "tutor:staff:staff-1:tutor.campus.manage:resource:campus-1".into(),
            subject: GrantSubjectRef::Principal {
                principal: PrincipalRef::Account {
                    account_id: AccountId("staff-1".into()),
                },
            },
            action_pattern: "tutor.campus.manage".into(),
            scope: campus_scope(),
            effect: GrantEffect::Allow,
        }],
        scope_edges: vec![],
        retirements: vec![],
    };
    assert_eq!(
        authorize_account(&client, &base, "staff-1").await,
        AuthorizationDecision::Deny
    );
    assert_eq!(
        client
            .post(&route)
            .bearer_auth("tutor-product-token")
            .json(&staff)
            .send()
            .await
            .unwrap()
            .error_for_status()
            .unwrap()
            .json::<ResourceProjectionReceipt>()
            .await
            .unwrap()
            .disposition,
        ResourceProjectionDisposition::Applied
    );
    assert_eq!(
        authorize_account(&client, &base, "staff-1").await,
        AuthorizationDecision::Allow
    );
    let mut revoked_staff = staff.clone();
    revoked_staff.epoch = 2;
    revoked_staff.idempotency_key = "staff:staff-1:2".into();
    revoked_staff.grants.clear();
    assert_eq!(
        client
            .post(&route)
            .bearer_auth("tutor-product-token")
            .json(&revoked_staff)
            .send()
            .await
            .unwrap()
            .error_for_status()
            .unwrap()
            .json::<ResourceProjectionReceipt>()
            .await
            .unwrap()
            .disposition,
        ResourceProjectionDisposition::Applied
    );
    assert_eq!(
        authorize_account(&client, &base, "staff-1").await,
        AuthorizationDecision::Deny
    );
    assert_eq!(
        client
            .post(&route)
            .bearer_auth("tutor-product-token")
            .json(&staff)
            .send()
            .await
            .unwrap()
            .error_for_status()
            .unwrap()
            .json::<ResourceProjectionReceipt>()
            .await
            .unwrap()
            .disposition,
        ResourceProjectionDisposition::Stale
    );

    let mut cross_org = create.clone();
    cross_org.org_id = OrgId("org-b".into());
    cross_org.projection_id = "campus:other".into();
    cross_org.idempotency_key = "campus:other:1".into();
    assert_eq!(
        client
            .post(&route)
            .bearer_auth("tutor-product-token")
            .json(&cross_org)
            .send()
            .await
            .unwrap()
            .status(),
        409
    );
    assert!(
        AuditSink::events(&store)
            .unwrap()
            .iter()
            .any(|event| event.action == "resource_projection.reject"
                && event.detail.contains("campus:other"))
    );
    let mut retirement = create.clone();
    retirement.epoch = 2;
    retirement.idempotency_key = "campus:campus-1:2".into();
    retirement.grants.clear();
    retirement.scope_edges.clear();
    retirement.retirements = vec![ResourceRetirement {
        resource_type: ResourceType("tutor.campus".into()),
        resource_id: ResourceId("campus-1".into()),
        grant_ids: vec!["campus-creator-manage".into()],
    }];
    let retired: ResourceProjectionReceipt = client
        .post(&route)
        .bearer_auth("tutor-product-token")
        .json(&retirement)
        .send()
        .await
        .unwrap()
        .error_for_status()
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(retired.disposition, ResourceProjectionDisposition::Applied);
    assert!(retired.version > first.version);
    assert_eq!(authorize(&client, &base).await, AuthorizationDecision::Deny);
    let stale: ResourceProjectionReceipt = client
        .post(&route)
        .bearer_auth("tutor-product-token")
        .json(&create)
        .send()
        .await
        .unwrap()
        .error_for_status()
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(stale.disposition, ResourceProjectionDisposition::Stale);

    handle.abort();
    // A manual grant left behind by an operator still cannot reopen a tombstoned resource.
    GrantRepository::put(
        &store,
        Grant {
            id: GrantId("manual-late-grant".into()),
            subject: GrantSubject::Principal(account()),
            action_pattern: ActionPattern("tutor.campus.manage".into()),
            scope: campus_scope(),
            effect: Effect::Allow,
        },
    )
    .unwrap();
    let (restarted_base, restarted_handle) = serve(store).await;
    assert_eq!(
        authorize(&client, &restarted_base).await,
        AuthorizationDecision::Deny
    );
    let snapshot: awaken_iam_contract::PolicySnapshot = client
        .get(format!("{restarted_base}/v1/authz/snapshot"))
        .send()
        .await
        .unwrap()
        .error_for_status()
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(snapshot.version, retired.version);
    assert_eq!(snapshot.scope_graph.retired_resources.len(), 1);
    restarted_handle.abort();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn projection_survives_a_disk_sqlite_daemon_restart() {
    let path = std::env::temp_dir().join(format!(
        "iam-projection-restart-{}-{}.sqlite",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    let store = sqlite_migrated_store(SqliteBackend::open_path(&path).unwrap(), "iam").unwrap();
    seed(&store);
    let (base, handle) = serve(store.clone()).await;
    let client = reqwest::Client::new();
    let model_reply = client
        .post(format!("{base}/v1/authz/resource-model"))
        .bearer_auth("tutor-product-token")
        .json(&model())
        .send()
        .await
        .unwrap();
    assert_eq!(model_reply.status(), 200);
    let create_reply = client
        .post(format!("{base}/v1/authz/resource-provisions"))
        .bearer_auth("tutor-product-token")
        .json(&create())
        .send()
        .await
        .unwrap();
    assert_eq!(create_reply.status(), 200);
    assert_eq!(
        authorize(&client, &base).await,
        AuthorizationDecision::Allow
    );
    handle.abort();
    let _ = handle.await;
    drop(store);

    let reopened = sqlite_migrated_store(SqliteBackend::open_path(&path).unwrap(), "iam").unwrap();
    let (second_base, second_handle) = serve(reopened).await;
    assert_eq!(
        authorize(&client, &second_base).await,
        AuthorizationDecision::Allow
    );
    let mut retirement = create();
    retirement.epoch = 2;
    retirement.idempotency_key = "campus:campus-1:2".into();
    retirement.grants.clear();
    retirement.scope_edges.clear();
    retirement.retirements = vec![ResourceRetirement {
        resource_type: ResourceType("tutor.campus".into()),
        resource_id: ResourceId("campus-1".into()),
        grant_ids: vec!["campus-creator-manage".into()],
    }];
    let retire_reply = client
        .post(format!("{second_base}/v1/authz/resource-provisions"))
        .bearer_auth("tutor-product-token")
        .json(&retirement)
        .send()
        .await
        .unwrap();
    assert_eq!(retire_reply.status(), 200);
    second_handle.abort();
    let _ = second_handle.await;

    let reopened = sqlite_migrated_store(SqliteBackend::open_path(&path).unwrap(), "iam").unwrap();
    let (third_base, third_handle) = serve(reopened).await;
    assert_eq!(
        authorize(&client, &third_base).await,
        AuthorizationDecision::Deny
    );
    third_handle.abort();
    let _ = third_handle.await;
    let _ = std::fs::remove_file(&path);
}
