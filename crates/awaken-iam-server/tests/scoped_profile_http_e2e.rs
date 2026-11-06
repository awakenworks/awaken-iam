//! Exact capability and durable replay through two native HTTP replicas.
use awaken_iam_contract::*;
use awaken_iam_core::{
    ActionPattern, ApiTokenDirectory, ApiTokenMinter, ApiTokenOwnerRepository, ApiTokenRepository,
    AuthorizationProfileRepository, Effect, Grant, GrantId, GrantRepository, GrantSubject, Group,
    GroupId, GroupRepository, MintApiToken, OrgRepository, Organization, OsEntropy, PolicySet,
    ResourceModelRepository, RoleId,
};
use awaken_iam_server::{
    AdminAuthPolicy, AuthApi, AuthzApi, DaemonState, SqlStore, SqliteBackend, daemon_router, http,
    scoped_profile_router, sqlite_in_memory_store,
};
use std::sync::{Arc, Mutex};

const NS: &str = "tenant.a";
#[path = "scoped_profile_http_e2e/current_decisions.rs"]
mod current_decisions;
#[path = "scoped_profile_http_e2e/live_subjects.rs"]
mod live_subjects;
#[path = "scoped_profile_http_e2e/service_references.rs"]
mod service_references;
#[path = "scoped_profile_http_e2e/token_introspection.rs"]
mod token_introspection;
type Store = SqlStore<SqliteBackend>;
fn at() -> Timestamp {
    Timestamp("2026-11-05T00:00:00Z".into())
}
fn service(id: &str) -> PrincipalRef {
    PrincipalRef::Service {
        service_id: id.into(),
    }
}
fn workspace(id: &str) -> ScopeRef {
    ScopeRef::Workspace {
        workspace_id: WorkspaceId(id.into()),
    }
}
fn mint(store: &Store, id: &str, ws: &str, owned: bool) -> String {
    let mut directory = ApiTokenDirectory::new();
    let mut policy = PolicySet::default();
    let mut minter = ApiTokenMinter::new(OsEntropy);
    let request = MintApiToken {
        id: ApiTokenId(id.into()),
        principal: service(id),
        workspace: WorkspaceId(ws.into()),
        role: RoleId("viewer".into()),
        created_at: at(),
        expires_at: Some(Timestamp("2099-01-01T00:00:00Z".into())),
    };
    let issued = if owned {
        minter
            .mint_service_account(
                &mut directory,
                &mut policy,
                request,
                AccountId("owner".into()),
            )
            .unwrap()
            .issued
    } else {
        minter.mint(&mut directory, &mut policy, request).unwrap()
    };
    ApiTokenRepository::create(store, issued.token.clone()).unwrap();
    if owned {
        store
            .record_api_token_owner(&issued.token.id, &AccountId("owner".into()))
            .unwrap();
    }
    issued.secret
}
fn grant(store: &Store, id: &str, action: &str, scope: ScopeRef) {
    GrantRepository::put(
        store,
        Grant {
            id: GrantId(format!("{id}:{action}")),
            subject: GrantSubject::Principal(service(id)),
            action_pattern: ActionPattern(action.into()),
            scope,
            effect: Effect::Allow,
        },
    )
    .unwrap();
}
fn seed(store: &Store) {
    for (org, ws) in [("o1", "w1"), ("o2", "w2")] {
        OrgRepository::upsert(
            store,
            Organization {
                id: OrgId(org.into()),
                display_name: None,
                owner: service("publisher"),
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
    GroupRepository::upsert(
        store,
        Group {
            id: GroupId("foreign".into()),
            org: OrgId("o2".into()),
            display_name: None,
            members: vec![],
            created_at: at(),
            updated_at: at(),
        },
    )
    .unwrap();
}
async fn serve(store: Store) -> String {
    serve_with_scoped_admission(store, true).await
}
async fn serve_with_scoped_admission(store: Store, scoped: bool) -> String {
    let profiles: Arc<dyn AuthorizationProfileRepository> = Arc::new(store.clone());
    let state = Arc::new(Mutex::new(
        DaemonState::with_policy_store(
            AuthzApi::new(),
            AdminAuthPolicy::new(["admin-key".to_owned()]),
            profiles,
            store,
            AuthApi::new().token_authority(),
        )
        .unwrap(),
    ));
    let router = if scoped {
        daemon_router(state.clone()).merge(scoped_profile_router(state))
    } else {
        daemon_router(state)
    };
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move { http::serve(listener, router).await.unwrap() });
    format!("http://{addr}")
}
fn command(key: &str, head: Option<u64>) -> PrepareScopedAuthorizationProfile {
    let action = format!("{NS}::read");
    let mut document = AuthorizationProfileDocument::default();
    document
        .resource_model
        .actions
        .push(ActionKey(action.clone()));
    document.action_scope_rules.push(ActionScopeRule {
        action_pattern: action.clone(),
        allowed_scope_kinds: vec![ScopeKind::Workspace],
    });
    document.grants.push(GrantSnapshot {
        id: format!("{NS}:read"),
        subject: GrantSubjectRef::Principal {
            principal: service("publisher"),
        },
        action_pattern: action,
        scope: workspace("w1"),
        effect: GrantEffect::Allow,
    });
    PrepareScopedAuthorizationProfile {
        request_key: key.into(),
        workspace_id: WorkspaceId("w1".into()),
        profile: CreateAuthorizationProfile {
            namespace: NamespaceId(NS.into()),
            document,
            created_at: at(),
        },
        expected_active_revision: head,
    }
}
fn path(base: &str, suffix: &str) -> String {
    format!("{base}/v1/scoped-authz/workspaces/w1/profiles/{NS}/publications{suffix}")
}
async fn post(
    client: &reqwest::Client,
    url: &str,
    token: &str,
    body: serde_json::Value,
) -> (u16, serde_json::Value) {
    let response = client
        .post(url)
        .bearer_auth(token)
        .json(&body)
        .send()
        .await
        .unwrap();
    let status = response.status().as_u16();
    (status, response.json().await.unwrap_or_default())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn exact_owned_workspace_namespace_capability_and_strict_document() {
    let store = sqlite_in_memory_store("scoped_http_admission").unwrap();
    seed(&store);
    let mut tokens = vec![];
    for (id, ws, owned, action, scope) in [
        (
            "publisher",
            "w1",
            true,
            format!("iam.authorization-profile.publish:{NS}"),
            workspace("w1"),
        ),
        (
            "unowned",
            "w1",
            false,
            format!("iam.authorization-profile.publish:{NS}"),
            workspace("w1"),
        ),
        ("wildcard", "w1", true, "*".into(), workspace("w1")),
        (
            "global",
            "w1",
            true,
            format!("iam.authorization-profile.publish:{NS}"),
            ScopeRef::Global,
        ),
        (
            "foreign-token",
            "w2",
            true,
            format!("iam.authorization-profile.publish:{NS}"),
            workspace("w1"),
        ),
        (
            "foreign-namespace",
            "w1",
            true,
            "iam.authorization-profile.publish:tenant.b".into(),
            workspace("w1"),
        ),
    ] {
        grant(&store, id, &action, scope);
        tokens.push((id, mint(&store, id, ws, owned)));
    }
    let base = serve(store.clone()).await;
    let client = reqwest::Client::new();
    let body = serde_json::to_value(command("original", None)).unwrap();
    for (id, token) in tokens
        .iter()
        .skip(1)
        .map(|(id, token)| (*id, token.as_str()))
        .chain([("admin", "admin-key"), ("unknown", "awk_unknown")])
    {
        let (status, details) = post(&client, &path(&base, ""), token, body.clone()).await;
        assert!(status == 401 || status == 403, "{id}: {status} {details}");
        assert!(
            store
                .list_profiles(&NamespaceId(NS.into()))
                .unwrap()
                .is_empty()
        );
    }
    let publisher = &tokens[0].1;
    let mut unknown = body.clone();
    unknown["profile"]["document"]["grants"][0]["constraints"] =
        serde_json::json!({"future_allow":true});
    assert_eq!(
        post(&client, &path(&base, ""), publisher, unknown).await.0,
        422
    );
    let mut foreign = body.clone();
    foreign["profile"]["document"]["grants"][0]["subject"] =
        serde_json::json!({"kind":"group","group_id":"foreign"});
    assert_eq!(
        post(&client, &path(&base, ""), publisher, foreign).await.0,
        403
    );
    let mut service = body.clone();
    service["profile"]["document"]["grants"][0]["subject"]["principal"] =
        serde_json::json!({"kind":"service","service_id":"foreign-service"});
    assert_eq!(
        post(&client, &path(&base, ""), publisher, service).await.0,
        403
    );
    assert!(
        store
            .list_profiles(&NamespaceId(NS.into()))
            .unwrap()
            .is_empty()
    );
    let (status, receipt) = post(&client, &path(&base, ""), publisher, body).await;
    assert_eq!(status, 200, "{receipt}");
    assert_eq!(receipt["status"], "prepared");
    // A scoped service cannot use the generic global PAP route.
    assert_eq!(
        post(
            &client,
            &format!("{base}/v1/admin/authz/profiles"),
            publisher,
            serde_json::to_value(command("other", None).profile).unwrap()
        )
        .await
        .0,
        403
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn lost_response_replay_across_replicas_never_reactivates_old_policy_and_revocation_is_live()
{
    let store = sqlite_in_memory_store("scoped_http_recovery").unwrap();
    seed(&store);
    for operation in ["publish", "read"] {
        grant(
            &store,
            "publisher",
            &format!("iam.authorization-profile.{operation}:{NS}"),
            workspace("w1"),
        );
    }
    let token = mint(&store, "publisher", "w1", true);
    let first = serve(store.clone()).await;
    let second = serve(store.clone()).await;
    let client = reqwest::Client::new();
    let native_base = first.clone();
    let native_token = token.clone();
    tokio::task::spawn_blocking(move || {
        use awaken_iam_client::{HttpAuthzTransport, HttpTransportConfig, ScopedProfilePublisher};
        let client = HttpAuthzTransport::new(
            HttpTransportConfig::new(native_base).with_service_token(native_token),
        )
        .unwrap();
        let baseline = client
            .scoped_profile_baseline(&WorkspaceId("w1".into()), &NamespaceId(NS.into()))
            .unwrap();
        assert!(baseline.active.is_none());
        assert!(!baseline.has_published_revision);
    })
    .await
    .unwrap();
    let original = serde_json::to_value(command("original", None)).unwrap();
    let (status, prepared) = post(&client, &path(&first, ""), &token, original.clone()).await;
    assert_eq!(status, 200, "{prepared}");
    let (status, recovered) = post(&client, &path(&second, ""), &token, original.clone()).await;
    assert_eq!(status, 200, "{recovered}");
    assert_eq!(prepared, recovered);
    let (status, active) = post(
        &client,
        &path(&second, "/original/activate"),
        &token,
        serde_json::json!({}),
    )
    .await;
    assert_eq!(status, 200, "{active}");
    assert_eq!(active["status"], "active");
    let mut replacement = command("replacement", Some(1));
    replacement.profile.document.grants[0].effect = GrantEffect::Deny;
    let (status, receipt) = post(
        &client,
        &path(&first, ""),
        &token,
        serde_json::to_value(replacement).unwrap(),
    )
    .await;
    assert_eq!(status, 200, "{receipt}");
    let (status, receipt) = post(
        &client,
        &path(&first, "/replacement/activate"),
        &token,
        serde_json::json!({}),
    )
    .await;
    assert_eq!(status, 200, "{receipt}");
    let (status, old) = post(
        &client,
        &path(&second, "/original/activate"),
        &token,
        serde_json::json!({}),
    )
    .await;
    assert_eq!(status, 200, "{old}");
    assert_eq!(old["status"], "superseded");
    assert_eq!(old["current_active_revision"], 2);
    assert_eq!(
        post(&client, &path(&second, ""), &token, original).await.0,
        200
    );
    assert_eq!(
        store.list_profiles(&NamespaceId(NS.into())).unwrap().len(),
        2
    );
    let revoked = client
        .delete(format!(
            "{first}/v1/admin/grants/publisher:iam.authorization-profile.publish:{NS}"
        ))
        .bearer_auth("admin-key")
        .send()
        .await
        .unwrap();
    assert!(revoked.status().is_success(), "native grant revocation");
    let (status, body) = post(
        &client,
        &path(&second, "/original/activate"),
        &token,
        serde_json::json!({}),
    )
    .await;
    assert_eq!(status, 403, "{body}");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn retire_requires_exact_authority_and_never_withdraws_a_later_revision() {
    let store = sqlite_in_memory_store("scoped_http_retirement").unwrap();
    seed(&store);
    let publish = format!("iam.authorization-profile.publish:{NS}");
    let retire = format!("iam.authorization-profile.retire:{NS}");
    grant(&store, "publisher", &publish, workspace("w1"));
    grant(&store, "retirer", &retire, workspace("w1"));
    grant(&store, "foreign", &retire, workspace("w1"));
    let publisher = mint(&store, "publisher", "w1", true);
    let retirer = mint(&store, "retirer", "w1", true);
    let foreign = mint(&store, "foreign", "w2", true);
    let first = serve(store.clone()).await;
    let second = serve(store.clone()).await;
    let client = reqwest::Client::new();
    let empty = || serde_json::json!({});

    for (key, head) in [("original", None), ("replacement", Some(1))] {
        let (status, body) = post(
            &client,
            &path(&first, ""),
            &publisher,
            serde_json::to_value(command(key, head)).unwrap(),
        )
        .await;
        assert_eq!(status, 200, "{body}");
        let (status, body) = post(
            &client,
            &path(&second, &format!("/{key}/activate")),
            &publisher,
            empty(),
        )
        .await;
        assert_eq!(status, 200, "{body}");
        assert_eq!(body["status"], "active");
    }

    for token in [&publisher, &foreign] {
        let (status, body) = post(
            &client,
            &path(&first, "/replacement/retire"),
            token,
            empty(),
        )
        .await;
        assert_eq!(status, 403, "{body}");
    }
    let (status, body) = post(
        &client,
        &path(&second, "/original/retire"),
        &retirer,
        empty(),
    )
    .await;
    assert_eq!(status, 200, "{body}");
    assert_eq!(body["status"], "superseded");
    assert_eq!(body["current_active_revision"], 2);

    let revoked = client
        .delete(format!("{first}/v1/admin/grants/publisher:{publish}"))
        .bearer_auth("admin-key")
        .send()
        .await
        .unwrap();
    assert!(revoked.status().is_success());

    let first_retire = path(&first, "/replacement/retire");
    let second_retire = path(&second, "/replacement/retire");
    let (retired, replayed) = tokio::join!(
        post(&client, &first_retire, &retirer, empty()),
        post(&client, &second_retire, &retirer, empty()),
    );
    assert_eq!(retired.0, 200, "{}", retired.1);
    assert_eq!(retired, replayed);
    assert_eq!(retired.1["status"], "retired");
    assert!(retired.1["current_active_revision"].is_null());
    assert!(
        store
            .active_profile(&NamespaceId(NS.into()))
            .unwrap()
            .is_none()
    );
    assert_eq!(
        store.list_profiles(&NamespaceId(NS.into())).unwrap().len(),
        2
    );

    grant(&store, "publisher", &publish, workspace("w1"));
    let reactivated = post(
        &client,
        &path(&second, "/replacement/activate"),
        &publisher,
        empty(),
    )
    .await;
    assert_eq!(retired, reactivated);
}
