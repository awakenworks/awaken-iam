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

fn authorization_request(account_id: &str) -> AuthorizationRequest {
    AuthorizationRequest::direct(
        PrincipalRef::Account {
            account_id: AccountId(account_id.into()),
        },
        ActionKey("tutor.campus.manage".into()),
        campus_scope(),
    )
}

fn resource_authorization_request() -> awaken_iam_contract::ResourceAuthorizationRequest {
    awaken_iam_contract::ResourceAuthorizationRequest {
        request: authorization_request("owner"),
        context: awaken_iam_contract::AuthorizationContext::default(),
    }
}

async fn authorize_resource(client: &reqwest::Client, base: &str) -> AuthorizationDecision {
    client
        .post(format!("{base}/v1/authorize/resource"))
        .json(&resource_authorization_request())
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

async fn authorize_account(
    client: &reqwest::Client,
    base: &str,
    account_id: &str,
) -> AuthorizationDecision {
    client
        .post(format!("{base}/v1/authorize"))
        .json(&authorization_request(account_id))
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
    // HAF cause/effect table: HAF1 current empty store => deny; HAF2 another
    // daemon publishes a grant => allow on this reader's FIRST contextual
    // request; HAF3 peer revocation => deny on its FIRST contextual request;
    // HAF4 shared fence unreadable => unchanged 503 across all policy routes.
    // Probe resource BEFORE the original legacy authorize assertions, otherwise
    // that endpoint would refresh the cache and conceal stale contextual allow.
    let store = sqlite_in_memory_store("iam_projection_replicas").unwrap();
    seed(&store);
    let (writer, writer_handle) = serve(store.clone()).await;
    let (reader, reader_handle) = serve(store.clone()).await;
    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(5))
        .build()
        .unwrap();
    assert_eq!(
        authorize_resource(&client, &reader).await,
        AuthorizationDecision::Deny,
        "HAF1 first contextual read"
    );
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
        authorize_resource(&client, &reader).await,
        AuthorizationDecision::Allow,
        "HAF2 first contextual read"
    );
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
        authorize_resource(&client, &reader).await,
        AuthorizationDecision::Deny,
        "HAF3 first contextual read"
    );
    assert_eq!(
        authorize(&client, &reader).await,
        AuthorizationDecision::Deny
    );
    // Same owned native fixture, no mock freshness predicate: remove its
    // singleton fence so an old cached decision cannot become a 200 response.
    // No production database or migration history is touched by this test cut.
    awaken_iam_server::SqlConn::execute(
        store.backend(),
        "DROP TABLE iam_projection_replicas_fence",
        &[],
    )
    .unwrap();
    for (path, body) in [
        (
            "/v1/authorize/resource",
            Some(serde_json::to_value(resource_authorization_request()).unwrap()),
        ),
        (
            "/v1/authorize",
            Some(serde_json::to_value(authorization_request("owner")).unwrap()),
        ),
        (
            "/v1/authorize/batch",
            Some(serde_json::json!({"requests":[authorization_request("owner")]})),
        ),
        ("/v1/authz/snapshot", None),
    ] {
        let request = match body {
            Some(body) => client.post(format!("{reader}{path}")).json(&body),
            None => client.get(format!("{reader}{path}")),
        };
        let response = request.send().await.unwrap();
        assert_eq!(response.status(), 503, "HAF4 {path}");
        let error: serde_json::Value = response.json().await.unwrap();
        assert_eq!(error["error"], "policy_unavailable", "HAF4 {path}");
        assert_eq!(
            error["message"], "Policy store is unavailable",
            "HAF4 original text"
        );
    }
    writer_handle.abort();
    reader_handle.abort();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn typed_model_client_uses_the_guarded_product_contract_and_rejection_stutters() {
    use awaken_iam_client::{HttpAuthzTransport, HttpTransportConfig, RemoteIamClient};
    // Cause/effect graph: canonical explicit product/vocabulary + matching
    // service credential -> existing registration owner -> committed version.
    // RM4 foreign product OR missing credential -> original 403/401, same policy;
    // RM5 valid credential + bare/missing/extra-field body -> closed-codec 422,
    // same policy. The REAL client/server pair tests the port's input shape;
    // the old JSON-loopback ancestry test remains an embedded-kernel law only.
    let store = sqlite_in_memory_store("iam_typed_model_client").unwrap();
    seed(&store);
    let (base, handle) = serve(store.clone()).await;
    let request = model();
    let client_base = base.clone();
    let accepted = request.clone();
    let registered = tokio::task::spawn_blocking(move || {
        let transport = HttpAuthzTransport::new(
            HttpTransportConfig::new(client_base)
                .with_service_token("tutor-product-token")
                .with_max_retries(0),
        )
        .unwrap();
        RemoteIamClient::new(transport).register_resource_model(&accepted)
    })
    .await
    .unwrap()
    .unwrap();
    assert_eq!(
        registered.version,
        awaken_iam_server::FenceStore::fence(&store)
            .unwrap()
            .version,
        "RM4 exact committed registration version"
    );
    let http = reqwest::Client::builder()
        .timeout(Duration::from_secs(5))
        .build()
        .unwrap();
    let before: serde_json::Value = http
        .get(format!("{base}/v1/authz/snapshot"))
        .send()
        .await
        .unwrap()
        .error_for_status()
        .unwrap()
        .json()
        .await
        .unwrap();
    for (foreign_product, token, status) in [
        (true, Some("tutor-product-token"), "403"),
        (false, None, "401"),
    ] {
        let mut rejected = request.clone();
        if foreign_product {
            rejected.product_id = ProductId::new("other").unwrap();
        }
        let client_base = base.clone();
        let error = tokio::task::spawn_blocking(move || {
            let mut config = HttpTransportConfig::new(client_base).with_max_retries(0);
            if let Some(token) = token {
                config = config.with_service_token(token);
            }
            RemoteIamClient::new(HttpAuthzTransport::new(config).unwrap())
                .register_resource_model(&rejected)
                .unwrap_err()
        })
        .await
        .unwrap();
        assert!(
            error.message().contains(status),
            "RM4 original product/auth refusal: {}",
            error.message()
        );
        let after: serde_json::Value = http
            .get(format!("{base}/v1/authz/snapshot"))
            .send()
            .await
            .unwrap()
            .error_for_status()
            .unwrap()
            .json()
            .await
            .unwrap();
        assert_eq!(
            after, before,
            "RM4 no vocabulary/grant/version effect; rejection audit is separate"
        );
    }
    let canonical = serde_json::to_value(&request).unwrap();
    let mut missing_product = canonical.clone();
    missing_product
        .as_object_mut()
        .unwrap()
        .remove("product_id");
    let mut missing_model = canonical.clone();
    missing_model
        .as_object_mut()
        .unwrap()
        .remove("resource_model");
    let mut unknown = canonical;
    unknown["untrusted_owner"] = serde_json::json!("other");
    for body in [
        serde_json::to_value(&request.resource_model).unwrap(),
        missing_product,
        missing_model,
        unknown,
    ] {
        let response = http
            .post(format!("{base}/v1/authz/resource-model"))
            .bearer_auth("tutor-product-token")
            .json(&body)
            .send()
            .await
            .unwrap();
        assert_eq!(
            response.status(),
            422,
            "RM5 strict existing product wrapper"
        );
        let after: serde_json::Value = http
            .get(format!("{base}/v1/authz/snapshot"))
            .send()
            .await
            .unwrap()
            .error_for_status()
            .unwrap()
            .json()
            .await
            .unwrap();
        assert_eq!(after, before, "RM5 no policy effect");
    }
    handle.abort();
    let _ = handle.await;
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

    // RP-L1 a legacy manual grant can predate the projection's ownership of
    // this identity. Seed it through the original repository while unowned;
    // retirement must still deny it after restart even though its row remains.
    // RP-L2 the CURRENT repository cannot add/update that grant after canonical
    // retirement: refuse before any audit/version/payload mutation. This
    // replaces only the obsolete post-retirement fixture write, preserving the
    // original restart/deny/tombstone/version assertions below.
    let manual = Grant {
        id: GrantId("manual-late-grant".into()),
        subject: GrantSubject::Principal(account()),
        action_pattern: ActionPattern("tutor.campus.manage".into()),
        scope: campus_scope(),
        effect: Effect::Allow,
    };
    GrantRepository::put(&store, manual.clone()).unwrap();

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
    // RP-L1 the actual old payload is still present, so the restart denial is
    // not vacuous. RP-L2 protects both fresh writes and exact legacy updates.
    assert_eq!(
        GrantRepository::get(&store, &manual.id).unwrap(),
        Some(manual.clone())
    );
    let before_audit = AuditSink::events(&store).unwrap();
    let before_fence = awaken_iam_server::FenceStore::fence(&store).unwrap();
    assert!(
        matches!(
            GrantRepository::put(&store, manual.clone()),
            Err(awaken_iam_core::RepositoryError::Conflict(_))
        ),
        "RP-L2 current writer must refuse retirement bypass"
    );
    assert_eq!(
        GrantRepository::get(&store, &manual.id).unwrap(),
        Some(manual)
    );
    assert_eq!(
        AuditSink::events(&store).unwrap(),
        before_audit,
        "RP-L2 no audit"
    );
    assert_eq!(
        awaken_iam_server::FenceStore::fence(&store).unwrap(),
        before_fence,
        "RP-L2 no policy publication"
    );
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

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn native_projection_sdk_composes_with_the_guarded_owner_and_keeps_stale_distinct() {
    // SDK1 native product-scoped credential/model registration; SDK2 exact
    // apply/replay; SDK3 changed same epoch/body or foreign product rejected;
    // SDK4 retirement then old delivery stays Stale and cannot restore access.
    let store = sqlite_in_memory_store("iam_projection_sdk").unwrap();
    seed(&store);
    let (base, handle) = serve(store.clone()).await;
    let native = base.clone();
    let persisted = store.clone();
    tokio::task::spawn_blocking(move || {
        use awaken_iam_client::{HttpAuthzTransport, HttpTransportConfig, RemoteIamClient};
        let transport = HttpAuthzTransport::new(
            HttpTransportConfig::new(&native).with_service_token("tutor-product-token"),
        )
        .unwrap();
        let sdk = RemoteIamClient::new(transport);
        sdk.register_resource_model(&model()).unwrap();
        let original = create();
        let applied = sdk.apply_resource_projection(&original).unwrap();
        assert_eq!(applied.disposition, ResourceProjectionDisposition::Applied);
        assert!(
            GrantRepository::get(&persisted, &GrantId("campus-creator-manage".into()))
                .unwrap()
                .is_some()
        );
        let replayed = sdk.apply_resource_projection(&original).unwrap();
        assert_eq!(
            replayed.disposition,
            ResourceProjectionDisposition::Replayed
        );
        assert_eq!(replayed.version, applied.version);
        let mut changed = original.clone();
        changed.grants.clear();
        assert!(
            sdk.apply_resource_projection(&changed)
                .unwrap_err()
                .to_string()
                .contains("409")
        );
        let mut foreign = original.clone();
        foreign.product_id = ProductId::new("other").unwrap();
        assert!(
            sdk.apply_resource_projection(&foreign)
                .unwrap_err()
                .to_string()
                .contains("403")
        );
        let mut retirement = original.clone();
        retirement.epoch = 2;
        retirement.idempotency_key = "campus:campus-1:2".into();
        retirement.grants.clear();
        retirement.scope_edges.clear();
        retirement.retirements = vec![ResourceRetirement {
            resource_type: ResourceType("tutor.campus".into()),
            resource_id: ResourceId("campus-1".into()),
            grant_ids: vec!["campus-creator-manage".into()],
        }];
        assert_eq!(
            sdk.apply_resource_projection(&retirement)
                .unwrap()
                .disposition,
            ResourceProjectionDisposition::Applied
        );
        let stale = sdk.apply_resource_projection(&original).unwrap();
        assert_eq!(stale.disposition, ResourceProjectionDisposition::Stale);
        assert_eq!(stale.idempotency_key, original.idempotency_key);
        assert_eq!(stale.epoch, original.epoch);
        // This is not a historical outcome query. In particular, Stale cannot
        // establish whether an earlier lost-ack request originally committed.
    })
    .await
    .unwrap();
    assert_eq!(
        authorize(&reqwest::Client::new(), &base).await,
        AuthorizationDecision::Deny
    );
    handle.abort();
    let _ = handle.await;
}
