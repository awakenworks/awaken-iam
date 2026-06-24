//! End-to-end check that the standalone daemon actually serves `/v1/admin/*`.
//!
//! Issue #77 only added the admin routes to the framework-agnostic manifest; the
//! running daemon never bound them, so a real `POST /v1/admin/orgs` answered 404.
//! This test drives the daemon's [`daemon_router`] with real HTTP requests and
//! proves the promised capability: the admin seam answers the full CRUD over the
//! wire with auth enforced, an admin mutation advances the same snapshot version
//! `GET /v1/authz/snapshot` reports, and the embedded surface exposes no
//! `/v1/admin/*` over HTTP.

use std::sync::{Arc, Mutex};

use awaken_iam_contract::{AdminMutationAck, OrgDto, PolicySnapshot};
use awaken_iam_server::{AdminAuthPolicy, AuthzApi, DaemonState, daemon_router, http};
use axum::Router;
use axum::body::Body;
use axum::http::{Request, Response, StatusCode};
use tower::ServiceExt;

const ADMIN_TOKEN: &str = "admin-secret";

fn daemon() -> Router {
    let state = Arc::new(Mutex::new(DaemonState::new(
        AuthzApi::new(),
        AdminAuthPolicy::new([ADMIN_TOKEN.to_owned()]),
    )));
    daemon_router(state)
}

fn org_body(id: &str) -> serde_json::Value {
    serde_json::json!({
        "id": id,
        "owner": { "kind": "account", "account_id": "ada" },
        "created_at": "2026-06-21T00:00:00Z",
        "updated_at": "2026-06-21T00:00:00Z"
    })
}

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

#[tokio::test]
async fn admin_crud_is_served_over_http_and_advances_the_snapshot_version() {
    let router = daemon();

    // The authorization snapshot starts at version 1.
    let before = router
        .clone()
        .oneshot(authed_get("/v1/authz/snapshot"))
        .await
        .expect("dispatch");
    assert_eq!(before.status(), StatusCode::OK);
    let before: PolicySnapshot = serde_json::from_value(body_json(before).await).expect("snapshot");
    assert_eq!(before.version, 1);

    // POST /v1/admin/orgs creates the org over the wire and bumps the version.
    let created = router
        .clone()
        .oneshot(authed_post("/v1/admin/orgs", org_body("acme")))
        .await
        .expect("dispatch");
    assert_eq!(created.status(), StatusCode::OK);
    let ack: AdminMutationAck = serde_json::from_value(body_json(created).await).expect("ack");
    assert_eq!(ack.version, 2, "the mutation advances the snapshot version");

    // GET /v1/authz/snapshot reflects the bump the admin mutation made.
    let after = router
        .clone()
        .oneshot(authed_get("/v1/authz/snapshot"))
        .await
        .expect("dispatch");
    let after: PolicySnapshot = serde_json::from_value(body_json(after).await).expect("snapshot");
    assert_eq!(after.version, 2);

    // GET /v1/admin/orgs lists the org the POST persisted.
    let listed = router
        .clone()
        .oneshot(authed_get("/v1/admin/orgs"))
        .await
        .expect("dispatch");
    assert_eq!(listed.status(), StatusCode::OK);
    let orgs: Vec<OrgDto> = serde_json::from_value(body_json(listed).await).expect("orgs");
    assert_eq!(orgs.len(), 1);
    assert_eq!(orgs[0].id.0, "acme");

    // A duplicate create fails closed as a conflict — the engine is live, not a
    // vacuous accept-everything stub.
    let conflict = router
        .clone()
        .oneshot(authed_post("/v1/admin/orgs", org_body("acme")))
        .await
        .expect("dispatch");
    assert_eq!(conflict.status(), StatusCode::CONFLICT);

    // DELETE /v1/admin/orgs/{id} removes it and advances the version again.
    let deleted = router
        .clone()
        .oneshot(
            Request::builder()
                .method("DELETE")
                .uri("/v1/admin/orgs/acme")
                .header("authorization", format!("Bearer {ADMIN_TOKEN}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .expect("dispatch");
    assert_eq!(deleted.status(), StatusCode::OK);
    let ack: AdminMutationAck = serde_json::from_value(body_json(deleted).await).expect("ack");
    assert_eq!(ack.version, 3);

    let empty = router
        .oneshot(authed_get("/v1/admin/orgs"))
        .await
        .expect("dispatch");
    let orgs: Vec<OrgDto> = serde_json::from_value(body_json(empty).await).expect("orgs");
    assert!(orgs.is_empty());
}

#[tokio::test]
async fn admin_routes_enforce_the_auth_guard() {
    let router = daemon();

    // No credential is rejected 401 before any state is touched.
    let anon = router
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/v1/admin/orgs")
                .header("content-type", "application/json")
                .body(Body::from(org_body("acme").to_string()))
                .unwrap(),
        )
        .await
        .expect("dispatch");
    assert_eq!(anon.status(), StatusCode::UNAUTHORIZED);

    // A credential the policy does not accept is rejected 403.
    let wrong = router
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/v1/admin/orgs")
                .header("content-type", "application/json")
                .header("authorization", "Bearer not-the-admin-token")
                .body(Body::from(org_body("acme").to_string()))
                .unwrap(),
        )
        .await
        .expect("dispatch");
    assert_eq!(wrong.status(), StatusCode::FORBIDDEN);

    // A rejected admin call never advanced the snapshot version.
    let snapshot = router
        .oneshot(authed_get("/v1/authz/snapshot"))
        .await
        .expect("dispatch");
    let snapshot: PolicySnapshot =
        serde_json::from_value(body_json(snapshot).await).expect("snapshot");
    assert_eq!(snapshot.version, 1);
}

#[tokio::test]
async fn embedded_surface_serves_no_admin_routes_over_http() {
    // The embedded host mounts only the read-only authorization router; the admin
    // seam is standalone-only, so a real request 404s rather than being served.
    let embedded = http::authz_router(Arc::new(AuthzApi::new()));
    let response = embedded
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/v1/admin/orgs")
                .header("content-type", "application/json")
                .body(Body::from(org_body("acme").to_string()))
                .unwrap(),
        )
        .await
        .expect("dispatch");
    assert_eq!(response.status(), StatusCode::NOT_FOUND);
}
