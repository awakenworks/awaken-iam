//! Batch grant issuance and the incremental PDP refresh after local admin
//! commits, over the real daemon router on SQLite and, when
//! `IAM_TEST_POSTGRES_URL` is set, PostgreSQL.
//!
//! Batch table (`POST /v1/admin/grants/batch`):
//! B1 empty -> 422; B2 repeated id -> 422; B3 one grant owned by a product
//! projection -> 409; B1-B3 leave grants, audit and version unchanged. B4 an
//! admitted batch -> every grant stored, one `grant.issue` audit per grant,
//! one version advance, and the PDP serves it at once.
//!
//! Refresh table: every local delta (org, role, group, grant, membership,
//! revoke) must serve exactly what a freshly hydrated daemon serves, and a
//! commit made through another daemon over the same store (R3) must still
//! become visible after this daemon's next local commit.

use std::sync::{Arc, Mutex};

use awaken_iam_contract::{AuthorizationOutcome, PolicySnapshot};
use awaken_iam_core::{AuditSink, AuthorizationProfileRepository};
use awaken_iam_server::{
    AdminAuthPolicy, AuthApi, AuthzApi, DaemonState, SqlConn, SqlStore, daemon_router,
    postgres_migrated_store, sqlite_in_memory_store,
};
use axum::Router;
use axum::body::Body;
use axum::http::{Request, StatusCode};
use tower::ServiceExt;

const ADMIN: &str = "admin-secret";

fn router<B: SqlConn + Clone + 'static>(store: &SqlStore<B>) -> Router {
    let profiles: Arc<dyn AuthorizationProfileRepository> = Arc::new(store.clone());
    let state = DaemonState::with_policy_store(
        AuthzApi::new(),
        AdminAuthPolicy::new([ADMIN.to_owned()]),
        profiles,
        store.clone(),
        AuthApi::new().token_authority(),
    )
    .expect("hydrate daemon");
    daemon_router(Arc::new(Mutex::new(state)))
}

async fn send(
    app: &Router,
    method: &str,
    path: &str,
    body: Option<serde_json::Value>,
) -> (StatusCode, serde_json::Value) {
    let mut request = Request::builder()
        .method(method)
        .uri(path)
        .header("authorization", format!("Bearer {ADMIN}"));
    let body = match body {
        Some(json) => {
            request = request.header("content-type", "application/json");
            Body::from(json.to_string())
        }
        None => Body::empty(),
    };
    let response = app
        .clone()
        .oneshot(request.body(body).unwrap())
        .await
        .unwrap();
    let status = response.status();
    let bytes = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .unwrap();
    let json = serde_json::from_slice(&bytes).unwrap_or(serde_json::Value::Null);
    (status, json)
}

fn service(id: &str) -> serde_json::Value {
    serde_json::json!({ "kind": "service", "service_id": id })
}

fn grant(id: &str, subject: serde_json::Value, action: &str) -> serde_json::Value {
    serde_json::json!({
        "id": id,
        "subject": subject,
        "action_pattern": action,
        "scope": { "kind": "global" },
        "effect": "allow"
    })
}

fn direct(id: &str, principal: &str, action: &str) -> serde_json::Value {
    grant(
        id,
        serde_json::json!({ "kind": "principal", "principal": service(principal) }),
        action,
    )
}

async fn decision(app: &Router, principal: &str, action: &str) -> String {
    let (status, body) = send(
        app,
        "POST",
        "/v1/authorize",
        Some(serde_json::json!({
            "principal": service(principal),
            "action": action,
            "scope": { "kind": "global" }
        })),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    let outcome: AuthorizationOutcome = serde_json::from_value(body).unwrap();
    serde_json::to_value(outcome.decision)
        .unwrap()
        .as_str()
        .unwrap()
        .to_owned()
}

async fn snapshot(app: &Router) -> PolicySnapshot {
    let (status, body) = send(app, "GET", "/v1/authz/snapshot", None).await;
    assert_eq!(status, StatusCode::OK);
    serde_json::from_value(body).unwrap()
}

fn issued_audits<B: SqlConn>(store: &SqlStore<B>) -> usize {
    AuditSink::events(store)
        .unwrap()
        .iter()
        .filter(|event| event.action == "grant.issue")
        .count()
}

async fn batch_is_atomic_audited_and_served<B: SqlConn + Clone + 'static>(store: SqlStore<B>) {
    let app = router(&store);
    let before = snapshot(&app).await.version;

    let (status, _) = send(
        &app,
        "POST",
        "/v1/admin/grants/batch",
        Some(serde_json::json!({ "grants": [] })),
    )
    .await;
    assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY, "B1");
    let (status, _) = send(
        &app,
        "POST",
        "/v1/admin/grants/batch",
        Some(serde_json::json!({ "grants": [
            direct("twice", "alpha", "pack.read"),
            direct("twice", "beta", "pack.read")
        ] })),
    )
    .await;
    assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY, "B2");
    store
        .backend()
        .execute(
            "INSERT INTO iam_resource_projection_grant_owners \
             (grant_id, product_id, org_id, projection_id) VALUES (?, ?, ?, ?)",
            &[
                Some("owned".into()),
                Some("tutor".into()),
                Some("org-a".into()),
                Some("projection-1".into()),
            ],
        )
        .unwrap();
    let (status, _) = send(
        &app,
        "POST",
        "/v1/admin/grants/batch",
        Some(serde_json::json!({ "grants": [
            direct("b-0", "delta", "pack.read"),
            direct("owned", "delta", "pack.read")
        ] })),
    )
    .await;
    assert_eq!(status, StatusCode::CONFLICT, "B3");
    for id in ["twice", "b-0", "owned"] {
        let (status, _) = send(&app, "GET", &format!("/v1/admin/grants/{id}"), None).await;
        assert_eq!(status, StatusCode::NOT_FOUND, "rejected batch wrote {id}");
    }
    assert_eq!(snapshot(&app).await.version, before, "B1-B3 version");
    assert_eq!(issued_audits(&store), 0, "B1-B3 audit");
    assert_eq!(decision(&app, "delta", "pack.read").await, "deny");

    let (status, ack) = send(
        &app,
        "POST",
        "/v1/admin/grants/batch",
        Some(serde_json::json!({ "grants": [
            direct("b-1", "alpha", "pack.read"),
            direct("b-2", "beta", "pack.read"),
            direct("b-3", "gamma", "pack.write")
        ] })),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "B4 {ack}");
    assert_eq!(ack["version"].as_u64(), Some(before + 1), "B4 one advance");
    assert_eq!(snapshot(&app).await.version, before + 1);
    for id in ["b-1", "b-2", "b-3"] {
        let (status, _) = send(&app, "GET", &format!("/v1/admin/grants/{id}"), None).await;
        assert_eq!(status, StatusCode::OK, "B4 stored {id}");
    }
    assert_eq!(issued_audits(&store), 3, "B4 one audit per grant");
    assert_eq!(decision(&app, "alpha", "pack.read").await, "allow");
    assert_eq!(decision(&app, "beta", "pack.read").await, "allow");
    assert_eq!(decision(&app, "gamma", "pack.read").await, "deny");
    assert_eq!(snapshot(&app).await, snapshot(&router(&store)).await);
}

async fn incremental_refresh_matches_full_hydration<B: SqlConn + Clone + 'static>(
    store: SqlStore<B>,
) {
    let app = router(&store);
    let other = router(&store);
    let at = "2026-11-01T00:00:00Z";

    let (status, _) = send(
        &app,
        "POST",
        "/v1/admin/orgs",
        Some(serde_json::json!({
            "id": "acme",
            "owner": { "kind": "account", "account_id": "ada" },
            "created_at": at,
            "updated_at": at
        })),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "org");
    let (status, _) = send(
        &app,
        "POST",
        "/v1/admin/roles",
        Some(serde_json::json!({
            "id": "reader",
            "action_patterns": ["doc.read"],
            "created_at": at,
            "updated_at": at
        })),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "role");

    let (status, _) = send(
        &app,
        "POST",
        "/v1/admin/grants",
        Some(direct("a-1", "alpha", "pack.read")),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(decision(&app, "alpha", "pack.read").await, "allow");

    // R3: another daemon commits; the next local commit must not skip it.
    let (status, _) = send(
        &other,
        "POST",
        "/v1/admin/grants",
        Some(direct("o-1", "beta", "pack.read")),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    let (status, _) = send(
        &app,
        "POST",
        "/v1/admin/grants",
        Some(direct("a-2", "gamma", "pack.read")),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(decision(&app, "beta", "pack.read").await, "allow", "R3");
    assert_eq!(decision(&app, "gamma", "pack.read").await, "allow");

    let binding = serde_json::json!({
        "principal": service("alpha"),
        "role_id": "reader",
        "scope": { "kind": "global" }
    });
    let (status, _) = send(
        &app,
        "POST",
        "/v1/admin/grants",
        Some(grant(
            "r-1",
            serde_json::json!({ "kind": "role", "role_id": "reader" }),
            "doc.read",
        )),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    let (status, _) = send(&app, "POST", "/v1/admin/memberships", Some(binding.clone())).await;
    assert_eq!(status, StatusCode::OK, "bind");
    assert_eq!(decision(&app, "alpha", "doc.read").await, "allow");
    let (status, _) = send(&app, "POST", "/v1/admin/memberships", Some(binding.clone())).await;
    assert_eq!(status, StatusCode::OK, "idempotent bind");
    let (status, _) = send(&app, "DELETE", "/v1/admin/memberships", Some(binding)).await;
    assert_eq!(status, StatusCode::OK, "unbind");
    assert_eq!(
        decision(&app, "alpha", "doc.read").await,
        "deny",
        "one unbind"
    );

    let team = |members: serde_json::Value| {
        serde_json::json!({
            "id": "team",
            "org": "acme",
            "members": members,
            "created_at": at,
            "updated_at": at
        })
    };
    let (status, _) = send(
        &app,
        "POST",
        "/v1/admin/groups",
        Some(team(serde_json::json!([service("delta")]))),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "group");
    let (status, _) = send(
        &app,
        "POST",
        "/v1/admin/grants",
        Some(grant(
            "t-1",
            serde_json::json!({ "kind": "group", "group_id": "team" }),
            "team.read",
        )),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(decision(&app, "delta", "team.read").await, "allow");
    let (status, _) = send(
        &app,
        "PUT",
        "/v1/admin/groups/team",
        Some(team(serde_json::json!([]))),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "group update");
    assert_eq!(decision(&app, "delta", "team.read").await, "deny");

    let (status, _) = send(&app, "DELETE", "/v1/admin/grants/a-1", None).await;
    assert_eq!(status, StatusCode::OK, "revoke");
    assert_eq!(decision(&app, "alpha", "pack.read").await, "deny");

    // A failed mutation forgets the composed base (R1); the next commit still
    // serves exactly the stored policy.
    let (status, _) = send(&app, "DELETE", "/v1/admin/grants/a-1", None).await;
    assert_eq!(status, StatusCode::NOT_FOUND, "absent revoke fails");

    // R4: a profile activation replaces the PDP outside the cache; the next
    // grant commit must keep both the profile and the new grant.
    let (status, _) = send(
        &app,
        "POST",
        "/v1/admin/authz/profiles",
        Some(serde_json::json!({
            "namespace": "awaken.runtime",
            "document": {
                "resource_model": {
                    "resource_types": [],
                    "actions": ["awaken.runtime::memory.*"],
                    "edges": []
                },
                "action_scope_rules": [{
                    "action_pattern": "awaken.runtime::memory.*",
                    "allowed_scope_kinds": [{"kind": "global"}]
                }],
                "grants": [direct("awaken.runtime:g_memory", "runtime", "awaken.runtime::memory.*")]
            },
            "created_at": at
        })),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "profile draft");
    for step in ["validate", "activate"] {
        let (status, body) = send(
            &app,
            "POST",
            &format!("/v1/admin/authz/profiles/awaken.runtime/1/{step}"),
            Some(serde_json::json!({})),
        )
        .await;
        assert_eq!(status, StatusCode::OK, "profile {step}: {body}");
    }
    let (status, _) = send(
        &app,
        "POST",
        "/v1/admin/grants",
        Some(direct("a-3", "epsilon", "pack.read")),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(
        decision(&app, "runtime", "awaken.runtime::memory.read").await,
        "allow",
        "R4 profile kept"
    );
    assert_eq!(decision(&app, "epsilon", "pack.read").await, "allow", "R4");

    let served = snapshot(&app).await;
    assert_eq!(served.version, snapshot(&other).await.version);
    assert_eq!(
        served,
        snapshot(&router(&store)).await,
        "delta == hydration"
    );
}

#[tokio::test]
async fn sqlite_grant_batch_is_atomic_audited_and_served() {
    batch_is_atomic_audited_and_served(sqlite_in_memory_store("iam").unwrap()).await;
}

#[tokio::test]
async fn sqlite_incremental_refresh_matches_full_hydration() {
    incremental_refresh_matches_full_hydration(sqlite_in_memory_store("iam").unwrap()).await;
}

#[tokio::test(flavor = "multi_thread")]
async fn postgres_grant_batch_and_incremental_refresh_when_configured() {
    let Ok(url) = std::env::var("IAM_TEST_POSTGRES_URL") else {
        return;
    };
    for (name, batch) in [("iam_grant_batch", true), ("iam_delta_refresh", false)] {
        let schema = IsolatedPostgresSchema::create(&url, name);
        let schema_url = schema.url.clone();
        let store =
            tokio::task::spawn_blocking(move || postgres_migrated_store(&schema_url, "iam"))
                .await
                .unwrap()
                .expect("migrate isolated schema");
        if batch {
            batch_is_atomic_audited_and_served(store).await;
        } else {
            incremental_refresh_matches_full_hydration(store).await;
        }
    }
}

struct IsolatedPostgresSchema {
    base_url: String,
    schema: String,
    url: String,
}

impl IsolatedPostgresSchema {
    fn create(base_url: &str, prefix: &str) -> Self {
        let schema = format!(
            "{}_{}_{}",
            prefix,
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .expect("wall clock")
                .as_nanos()
        );
        let create_url = base_url.to_owned();
        let create_schema = schema.clone();
        std::thread::spawn(move || {
            let mut client = postgres::Client::connect(&create_url, postgres::NoTls)
                .expect("connect PostgreSQL");
            client
                .batch_execute(&format!("CREATE SCHEMA {create_schema}"))
                .expect("create isolated IAM schema");
        })
        .join()
        .expect("isolated IAM schema thread");
        let separator = if base_url.contains('?') { '&' } else { '?' };
        let url = format!("{base_url}{separator}options=-csearch_path%3D{schema}");
        Self {
            base_url: base_url.into(),
            schema,
            url,
        }
    }
}

impl Drop for IsolatedPostgresSchema {
    fn drop(&mut self) {
        let base_url = self.base_url.clone();
        let schema = self.schema.clone();
        let _ = std::thread::spawn(move || {
            if let Ok(mut client) = postgres::Client::connect(&base_url, postgres::NoTls) {
                let _ = client.batch_execute(&format!("DROP SCHEMA {schema} CASCADE"));
            }
        })
        .join();
    }
}
