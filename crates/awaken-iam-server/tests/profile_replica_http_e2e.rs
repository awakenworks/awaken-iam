//! Authorization-profile HTTP lifecycle and shared-store refresh coverage.

use std::sync::{Arc, Mutex};

use awaken_iam_server::{
    AdminAuthPolicy, AuthApi, AuthzApi, DaemonState, daemon_router, sqlite_in_memory_store,
};
use axum::Router;
use axum::body::Body;
use axum::http::{Request, Response, StatusCode};
use tower::ServiceExt;

const ADMIN_TOKEN: &str = "admin-secret";

fn authed_post(path: &str, body: serde_json::Value) -> Request<Body> {
    Request::builder()
        .method("POST")
        .uri(path)
        .header("content-type", "application/json")
        .header("authorization", format!("Bearer {ADMIN_TOKEN}"))
        .body(Body::from(body.to_string()))
        .expect("build request")
}

fn authed_get(path: &str) -> Request<Body> {
    Request::builder()
        .method("GET")
        .uri(path)
        .header("authorization", format!("Bearer {ADMIN_TOKEN}"))
        .body(Body::empty())
        .expect("build request")
}

async fn body_json(response: Response<Body>) -> serde_json::Value {
    let bytes = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .expect("read body");
    serde_json::from_slice(&bytes).expect("decode json")
}

fn daemon() -> Router {
    let store = sqlite_in_memory_store("iam_profile_http").expect("migrate profile store");
    daemon_router(Arc::new(Mutex::new(
        DaemonState::with_policy_store(
            AuthzApi::new(),
            AdminAuthPolicy::new([ADMIN_TOKEN.to_owned()]),
            Arc::new(store.clone()),
            store,
            AuthApi::new().token_authority(),
        )
        .expect("hydrate daemon"),
    )))
}

fn profile_body(scope_kind: &str) -> serde_json::Value {
    let scope = if scope_kind == "resource" {
        serde_json::json!({"kind":"resource","resource_type":"memory"})
    } else {
        serde_json::json!({"kind":scope_kind})
    };
    serde_json::json!({
        "namespace": "awaken.runtime",
        "document": {
            "resource_model": {
                "resource_types": [],
                "actions": ["awaken.runtime::memory.*"],
                "edges": []
            },
            "action_scope_rules": [{
                "action_pattern": "awaken.runtime::memory.*",
                "allowed_scope_kinds": [scope]
            }],
            "grants": [{
                "id": "awaken.runtime:g_memory",
                "subject": {"kind":"principal","principal":{"kind":"service","service_id":"runtime"}},
                "action_pattern": "awaken.runtime::memory.*",
                "scope": {"kind":"global"},
                "effect": "allow"
            }]
        },
        "created_at": "2026-07-20T00:00:00Z"
    })
}

async fn profile_scope_decision(router: &Router, scope: serde_json::Value) -> serde_json::Value {
    let response = router
        .clone()
        .oneshot(authed_post(
            "/v1/authorize",
            serde_json::json!({
                "principal":{"kind":"service","service_id":"runtime"},
                "action":"awaken.runtime::memory.read",
                "scope":scope
            }),
        ))
        .await
        .expect("authorize profile scope");
    assert_eq!(response.status(), StatusCode::OK);
    body_json(response).await
}

#[tokio::test]
async fn profile_activation_and_retirement_refresh_another_daemon_on_its_next_decision() {
    let store = sqlite_in_memory_store("iam_profile_shared").expect("migrate shared store");
    let make_daemon = || {
        daemon_router(Arc::new(Mutex::new(
            DaemonState::with_policy_store(
                AuthzApi::new(),
                AdminAuthPolicy::new([ADMIN_TOKEN.to_owned()]),
                Arc::new(store.clone()),
                store.clone(),
                AuthApi::new().token_authority(),
            )
            .expect("hydrate daemon"),
        )))
    };
    let first = make_daemon();
    let second = make_daemon();
    let workspace = serde_json::json!({"kind":"workspace","workspace_id":"ws"});
    let project = serde_json::json!({"kind":"project","workspace_id":"ws","project_id":"p"});

    for (revision, scope, expected) in [(1, "workspace", None), (2, "project", Some(1_u64))] {
        let created = first
            .clone()
            .oneshot(authed_post("/v1/admin/authz/profiles", profile_body(scope)))
            .await
            .expect("create profile");
        assert_eq!(created.status(), StatusCode::OK);
        assert_eq!(body_json(created).await["revision"], revision);
        let validated = first
            .clone()
            .oneshot(authed_post(
                &format!("/v1/admin/authz/profiles/awaken.runtime/{revision}/validate"),
                serde_json::json!({}),
            ))
            .await
            .expect("validate profile");
        assert_eq!(body_json(validated).await["valid"], true);
        let activated = first
            .clone()
            .oneshot(authed_post(
                &format!("/v1/admin/authz/profiles/awaken.runtime/{revision}/activate"),
                serde_json::json!({"expected_active_revision":expected}),
            ))
            .await
            .expect("activate profile");
        assert_eq!(activated.status(), StatusCode::OK);
        let receipt = body_json(activated).await;
        let snapshot = second
            .clone()
            .oneshot(authed_get("/v1/authz/snapshot"))
            .await
            .expect("read second node snapshot");
        assert_eq!(
            body_json(snapshot).await["version"],
            receipt["policy_version"]
        );
        assert_eq!(
            profile_scope_decision(&second, workspace.clone()).await["decision"],
            if revision == 1 { "allow" } else { "deny" }
        );
        assert_eq!(
            profile_scope_decision(&second, project.clone()).await["decision"],
            if revision == 2 { "allow" } else { "deny" }
        );
    }

    let rolled_back = first
        .clone()
        .oneshot(authed_post(
            "/v1/admin/authz/profiles/awaken.runtime/1/rollback",
            serde_json::json!({"expected_active_revision":2}),
        ))
        .await
        .expect("roll back profile");
    assert_eq!(rolled_back.status(), StatusCode::OK);
    let rollback_receipt = body_json(rolled_back).await;
    let snapshot = second
        .clone()
        .oneshot(authed_get("/v1/authz/snapshot"))
        .await
        .expect("read rollback version");
    assert_eq!(
        body_json(snapshot).await["version"],
        rollback_receipt["policy_version"]
    );
    assert_eq!(
        profile_scope_decision(&second, workspace.clone()).await["decision"],
        "allow"
    );
    assert_eq!(
        profile_scope_decision(&second, project.clone()).await["decision"],
        "deny"
    );

    let reactivated = first
        .clone()
        .oneshot(authed_post(
            "/v1/admin/authz/profiles/awaken.runtime/2/activate",
            serde_json::json!({"expected_active_revision":1}),
        ))
        .await
        .expect("reactivate profile before retirement");
    assert_eq!(reactivated.status(), StatusCode::OK);
    assert_eq!(
        profile_scope_decision(&second, project.clone()).await["decision"],
        "allow"
    );

    let retired = first
        .clone()
        .oneshot(authed_post(
            "/v1/admin/authz/profiles/awaken.runtime/retire",
            serde_json::json!({"expected_active_revision":2}),
        ))
        .await
        .expect("retire profile");
    assert_eq!(retired.status(), StatusCode::OK);
    let receipt = body_json(retired).await;
    let snapshot = second
        .clone()
        .oneshot(authed_get("/v1/authz/snapshot"))
        .await
        .expect("read second node snapshot");
    assert_eq!(
        body_json(snapshot).await["version"],
        receipt["policy_version"]
    );
    assert_eq!(
        profile_scope_decision(&second, project).await["decision"],
        "deny"
    );
}

#[tokio::test]
async fn profile_pap_replaces_scope_rules_and_rolls_back_over_http() {
    let router = daemon();
    let created = router
        .clone()
        .oneshot(authed_post(
            "/v1/admin/authz/profiles",
            profile_body("workspace"),
        ))
        .await
        .unwrap();
    assert_eq!(created.status(), StatusCode::OK);
    assert_eq!(body_json(created).await["revision"], 1);

    let validated = router
        .clone()
        .oneshot(authed_post(
            "/v1/admin/authz/profiles/awaken.runtime/1/validate",
            serde_json::json!({}),
        ))
        .await
        .unwrap();
    assert_eq!(validated.status(), StatusCode::OK);
    assert_eq!(body_json(validated).await["valid"], true);

    let activated = router
        .clone()
        .oneshot(authed_post(
            "/v1/admin/authz/profiles/awaken.runtime/1/activate",
            serde_json::json!({}),
        ))
        .await
        .unwrap();
    assert_eq!(activated.status(), StatusCode::OK);

    let allowed = router
        .clone()
        .oneshot(authed_post(
            "/v1/authorize",
            serde_json::json!({
                "principal":{"kind":"service","service_id":"runtime"},
                "action":"awaken.runtime::memory.read",
                "scope":{"kind":"workspace","workspace_id":"ws"}
            }),
        ))
        .await
        .unwrap();
    assert_eq!(body_json(allowed).await["decision"], "allow");

    let denied = router
        .clone()
        .oneshot(authed_post(
            "/v1/authorize",
            serde_json::json!({
                "principal":{"kind":"service","service_id":"runtime"},
                "action":"awaken.runtime::memory.read",
                "scope":{"kind":"project","workspace_id":"ws","project_id":"p"}
            }),
        ))
        .await
        .unwrap();
    let denied = body_json(denied).await;
    assert_eq!(denied["decision"], "deny");
    assert_eq!(denied["reason"], "scope_kind_not_allowed");

    let second = router
        .clone()
        .oneshot(authed_post(
            "/v1/admin/authz/profiles",
            profile_body("project"),
        ))
        .await
        .unwrap();
    assert_eq!(body_json(second).await["revision"], 2);
    router
        .clone()
        .oneshot(authed_post(
            "/v1/admin/authz/profiles/awaken.runtime/2/validate",
            serde_json::json!({}),
        ))
        .await
        .unwrap();
    let replaced = router
        .clone()
        .oneshot(authed_post(
            "/v1/admin/authz/profiles/awaken.runtime/2/activate",
            serde_json::json!({"expected_active_revision":1}),
        ))
        .await
        .unwrap();
    assert_eq!(replaced.status(), StatusCode::OK);

    let rolled_back = router
        .clone()
        .oneshot(authed_post(
            "/v1/admin/authz/profiles/awaken.runtime/1/rollback",
            serde_json::json!({"expected_active_revision":2}),
        ))
        .await
        .unwrap();
    assert_eq!(rolled_back.status(), StatusCode::OK);
    assert_eq!(body_json(rolled_back).await["active_revision"], 1);
}
