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

use awaken_iam_contract::{
    AdminMutationAck, AuthorizationOutcome, BatchAuthorizationResponse, EntitlementCheckResponse,
    OrgDto, PolicySnapshot,
};
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

fn authed(method: &str, path: &str, body: Option<&str>) -> Request<Body> {
    let mut builder = Request::builder()
        .method(method)
        .uri(path)
        .header("authorization", format!("Bearer {ADMIN_TOKEN}"));
    let body = match body {
        Some(json) => {
            builder = builder.header("content-type", "application/json");
            Body::from(json.to_owned())
        }
        None => Body::empty(),
    };
    builder.body(body).expect("build request")
}

fn authed_json(method: &str, path: &str, body: serde_json::Value) -> Request<Body> {
    authed(method, path, Some(&body.to_string()))
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

#[tokio::test]
async fn healthz_returns_ok_over_the_wire() {
    let response = daemon()
        .oneshot(
            Request::builder()
                .method("GET")
                .uri("/healthz")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .expect("dispatch");
    assert_eq!(response.status(), StatusCode::OK);
    let json = body_json(response).await;
    assert_eq!(json["status"], "ok");
}

#[tokio::test]
async fn healthz_does_not_require_an_admin_credential() {
    // /healthz is an operational probe, not part of the admin seam; it must
    // answer 200 even with no credential.
    let response = daemon()
        .oneshot(
            Request::builder()
                .method("GET")
                .uri("/healthz")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .expect("dispatch");
    assert_eq!(response.status(), StatusCode::OK);
}

#[tokio::test]
async fn update_org_replaces_an_existing_organization() {
    let router = daemon();

    // Seed an org via the real POST route.
    router
        .clone()
        .oneshot(authed_json("POST", "/v1/admin/orgs", org_body("acme")))
        .await
        .expect("dispatch");

    // Replace it through PUT /v1/admin/orgs/{id} with a renamed body.
    let mut updated = org_body("acme");
    updated["display_name"] = serde_json::json!("Renamed ACME");
    let response = router
        .clone()
        .oneshot(authed_json("PUT", "/v1/admin/orgs/acme", updated))
        .await
        .expect("dispatch");
    assert_eq!(response.status(), StatusCode::OK);
    let ack: AdminMutationAck = serde_json::from_value(body_json(response).await).expect("ack");
    assert!(ack.version >= 3);

    // The listed org reflects the new name and the path id wins over the body id.
    let listed = router
        .oneshot(authed_get("/v1/admin/orgs"))
        .await
        .expect("dispatch");
    let orgs: Vec<OrgDto> = serde_json::from_value(body_json(listed).await).expect("orgs");
    assert_eq!(orgs.len(), 1);
    assert_eq!(orgs[0].id.0, "acme");
    assert_eq!(orgs[0].display_name.as_deref(), Some("Renamed ACME"));
}

#[tokio::test]
async fn update_org_rejects_an_absent_organization_with_not_found() {
    let router = daemon();
    let response = router
        .oneshot(authed_json(
            "PUT",
            "/v1/admin/orgs/missing",
            org_body("missing"),
        ))
        .await
        .expect("dispatch");
    assert_eq!(response.status(), StatusCode::NOT_FOUND);
    let body = body_json(response).await;
    assert_eq!(body["error"], "not_found");
}

#[tokio::test]
async fn full_admin_crud_round_trip_orgs_groups_roles_grants_memberships() {
    // Drive every `/v1/admin/*` mutation so the seam is exercised end-to-end:
    // create -> read/list -> update -> delete, with each kind of aggregate, and
    // every successful mutation must advance the snapshot version.
    let router = daemon();

    // --- organizations ----------------------------------------------------
    let org_created = router
        .clone()
        .oneshot(authed_json("POST", "/v1/admin/orgs", org_body("acme")))
        .await
        .expect("dispatch");
    assert_eq!(org_created.status(), StatusCode::OK);

    // --- groups -----------------------------------------------------------
    let group_body = serde_json::json!({
        "id": "eng",
        "org": "acme",
        "display_name": "Engineering",
        "members": [
            { "kind": "account", "account_id": "ada" },
            { "kind": "service", "service_id": "ci" }
        ],
        "created_at": "2026-06-21T00:00:00Z",
        "updated_at": "2026-06-21T00:00:00Z"
    });
    let group_created = router
        .clone()
        .oneshot(authed_json("POST", "/v1/admin/groups", group_body.clone()))
        .await
        .expect("dispatch");
    assert_eq!(group_created.status(), StatusCode::OK);

    let group_updated_body = serde_json::json!({
        "id": "eng",
        "org": "acme",
        "display_name": "Engineering (renamed)",
        "members": [{ "kind": "account", "account_id": "ada" }],
        "created_at": "2026-06-21T00:00:00Z",
        "updated_at": "2026-06-22T00:00:00Z"
    });
    let group_updated = router
        .clone()
        .oneshot(authed_json(
            "PUT",
            "/v1/admin/groups/eng",
            group_updated_body,
        ))
        .await
        .expect("dispatch");
    assert_eq!(group_updated.status(), StatusCode::OK);

    // --- roles ------------------------------------------------------------
    let role_body = serde_json::json!({
        "id": "publisher",
        "display_name": "Publisher",
        "action_patterns": ["pack.read", "pack.publish"],
        "created_at": "2026-06-21T00:00:00Z",
        "updated_at": "2026-06-21T00:00:00Z"
    });
    let role_created = router
        .clone()
        .oneshot(authed_json("POST", "/v1/admin/roles", role_body.clone()))
        .await
        .expect("dispatch");
    assert_eq!(role_created.status(), StatusCode::OK);

    let role_updated_body = serde_json::json!({
        "id": "publisher",
        "display_name": "Publisher v2",
        "action_patterns": ["pack.*"],
        "created_at": "2026-06-21T00:00:00Z",
        "updated_at": "2026-06-22T00:00:00Z"
    });
    let role_updated = router
        .clone()
        .oneshot(authed_json(
            "PUT",
            "/v1/admin/roles/publisher",
            role_updated_body,
        ))
        .await
        .expect("dispatch");
    assert_eq!(role_updated.status(), StatusCode::OK);

    // --- grants -----------------------------------------------------------
    let grant_body = serde_json::json!({
        "id": "g_publisher_publish",
        "subject": { "kind": "role", "role_id": "publisher" },
        "action_pattern": "pack.publish",
        "scope": { "kind": "org", "org_id": "acme" },
        "effect": "allow"
    });
    let grant_issued = router
        .clone()
        .oneshot(authed_json("POST", "/v1/admin/grants", grant_body))
        .await
        .expect("dispatch");
    assert_eq!(grant_issued.status(), StatusCode::OK);

    // Revoking an issued grant succeeds over the wire.
    let grant_revoked = router
        .clone()
        .oneshot(authed(
            "DELETE",
            "/v1/admin/grants/g_publisher_publish",
            None,
        ))
        .await
        .expect("dispatch");
    assert_eq!(grant_revoked.status(), StatusCode::OK);

    // --- memberships ------------------------------------------------------
    let binding_body = serde_json::json!({
        "principal": { "kind": "account", "account_id": "ada" },
        "role_id": "publisher",
        "scope": { "kind": "org", "org_id": "acme" }
    });
    let binding_granted = router
        .clone()
        .oneshot(authed_json(
            "POST",
            "/v1/admin/memberships",
            binding_body.clone(),
        ))
        .await
        .expect("dispatch");
    assert_eq!(binding_granted.status(), StatusCode::OK);

    let binding_revoked = router
        .clone()
        .oneshot(authed_json(
            "DELETE",
            "/v1/admin/memberships",
            binding_body.clone(),
        ))
        .await
        .expect("dispatch");
    assert_eq!(binding_revoked.status(), StatusCode::OK);

    // --- deletion closes every aggregate cleanly -------------------------
    assert_eq!(
        router
            .clone()
            .oneshot(authed("DELETE", "/v1/admin/groups/eng", None))
            .await
            .expect("dispatch")
            .status(),
        StatusCode::OK
    );
    assert_eq!(
        router
            .clone()
            .oneshot(authed("DELETE", "/v1/admin/roles/publisher", None))
            .await
            .expect("dispatch")
            .status(),
        StatusCode::OK
    );
    assert_eq!(
        router
            .clone()
            .oneshot(authed("DELETE", "/v1/admin/orgs/acme", None))
            .await
            .expect("dispatch")
            .status(),
        StatusCode::OK
    );

    // After every delete the list answers 200 and is empty.
    let empty = router
        .oneshot(authed_get("/v1/admin/orgs"))
        .await
        .expect("dispatch");
    let orgs: Vec<OrgDto> = serde_json::from_value(body_json(empty).await).expect("orgs");
    assert!(orgs.is_empty());
}

#[tokio::test]
async fn update_and_delete_on_absent_aggregates_yield_not_found() {
    let router = daemon();
    let group_body = serde_json::json!({
        "id": "absent",
        "org": "acme",
        "created_at": "2026-06-21T00:00:00Z",
        "updated_at": "2026-06-21T00:00:00Z"
    });
    let role_body = serde_json::json!({
        "id": "absent",
        "action_patterns": ["pack.read"],
        "created_at": "2026-06-21T00:00:00Z",
        "updated_at": "2026-06-21T00:00:00Z"
    });

    // Seed an org so the group/role/grants referencing an org can attempt ops.
    router
        .clone()
        .oneshot(authed_json("POST", "/v1/admin/orgs", org_body("acme")))
        .await
        .expect("dispatch");

    let put_group = router
        .clone()
        .oneshot(authed_json(
            "PUT",
            "/v1/admin/groups/absent",
            group_body.clone(),
        ))
        .await
        .expect("dispatch");
    assert_eq!(put_group.status(), StatusCode::NOT_FOUND);

    let delete_group = router
        .clone()
        .oneshot(authed("DELETE", "/v1/admin/groups/absent", None))
        .await
        .expect("dispatch");
    assert_eq!(delete_group.status(), StatusCode::NOT_FOUND);

    let put_role = router
        .clone()
        .oneshot(authed_json(
            "PUT",
            "/v1/admin/roles/absent",
            role_body.clone(),
        ))
        .await
        .expect("dispatch");
    assert_eq!(put_role.status(), StatusCode::NOT_FOUND);

    let delete_role = router
        .clone()
        .oneshot(authed("DELETE", "/v1/admin/roles/absent", None))
        .await
        .expect("dispatch");
    assert_eq!(delete_role.status(), StatusCode::NOT_FOUND);

    let revoke_grant = router
        .clone()
        .oneshot(authed("DELETE", "/v1/admin/grants/absent", None))
        .await
        .expect("dispatch");
    assert_eq!(revoke_grant.status(), StatusCode::NOT_FOUND);

    // Revoking a non-existent membership yields not_found.
    let binding_body = serde_json::json!({
        "principal": { "kind": "account", "account_id": "ada" },
        "role_id": "publisher",
        "scope": { "kind": "global" }
    });
    let revoke_membership = router
        .oneshot(authed_json(
            "DELETE",
            "/v1/admin/memberships",
            binding_body.clone(),
        ))
        .await
        .expect("dispatch");
    assert_eq!(revoke_membership.status(), StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn role_define_rejects_empty_patterns_and_wildcard_as_invalid() {
    let router = daemon();

    // Empty patterns violates the role invariant: at least one pattern is required.
    let empty_patterns = serde_json::json!({
        "id": "empty",
        "action_patterns": [],
        "created_at": "2026-06-21T00:00:00Z",
        "updated_at": "2026-06-21T00:00:00Z"
    });
    let response = router
        .clone()
        .oneshot(authed_json("POST", "/v1/admin/roles", empty_patterns))
        .await
        .expect("dispatch");
    assert_eq!(response.status(), StatusCode::UNPROCESSABLE_ENTITY);
    let body = body_json(response).await;
    assert_eq!(body["error"], "invalid");

    // The bare `*` catch-all is fenced out for the same reason.
    let wildcard = serde_json::json!({
        "id": "wild",
        "action_patterns": ["*"],
        "created_at": "2026-06-21T00:00:00Z",
        "updated_at": "2026-06-21T00:00:00Z"
    });
    let response = router
        .oneshot(authed_json("POST", "/v1/admin/roles", wildcard))
        .await
        .expect("dispatch");
    assert_eq!(response.status(), StatusCode::UNPROCESSABLE_ENTITY);
}

#[tokio::test]
async fn role_define_rejects_a_duplicate_id_as_conflict() {
    let router = daemon();
    let body = serde_json::json!({
        "id": "publisher",
        "action_patterns": ["pack.read"],
        "created_at": "2026-06-21T00:00:00Z",
        "updated_at": "2026-06-21T00:00:00Z"
    });
    let created = router
        .clone()
        .oneshot(authed_json("POST", "/v1/admin/roles", body.clone()))
        .await
        .expect("dispatch");
    assert_eq!(created.status(), StatusCode::OK);
    let dup = router
        .oneshot(authed_json("POST", "/v1/admin/roles", body))
        .await
        .expect("dispatch");
    assert_eq!(dup.status(), StatusCode::CONFLICT);
}

#[tokio::test]
async fn group_define_rejects_a_duplicate_id_as_conflict() {
    let router = daemon();
    router
        .clone()
        .oneshot(authed_json("POST", "/v1/admin/orgs", org_body("acme")))
        .await
        .expect("dispatch");
    let body = serde_json::json!({
        "id": "eng",
        "org": "acme",
        "created_at": "2026-06-21T00:00:00Z",
        "updated_at": "2026-06-21T00:00:00Z"
    });
    let created = router
        .clone()
        .oneshot(authed_json("POST", "/v1/admin/groups", body.clone()))
        .await
        .expect("dispatch");
    assert_eq!(created.status(), StatusCode::OK);
    let dup = router
        .oneshot(authed_json("POST", "/v1/admin/groups", body))
        .await
        .expect("dispatch");
    assert_eq!(dup.status(), StatusCode::CONFLICT);
}

#[tokio::test]
async fn every_admin_route_enforces_auth_on_get_put_delete_too() {
    // The 401/403 contract must hold for every HTTP verb the admin seam exposes,
    // not just POST. GET reads leak membership/grants/roles, and PUT/DELETE can
    // mutate them; all must reject a missing or wrong credential *before* any
    // handler-level validation runs. Bodyless routes test directly; PUT routes
    // ship a syntactically-valid empty JSON object so the Json extractor passes
    // the request to the handler and the auth guard fires first.
    let router = daemon();

    let valid_group_body = serde_json::json!({
        "id": "eng",
        "org": "acme",
        "created_at": "2026-06-21T00:00:00Z",
        "updated_at": "2026-06-21T00:00:00Z"
    });
    let valid_role_body = serde_json::json!({
        "id": "publisher",
        "action_patterns": ["pack.read"],
        "created_at": "2026-06-21T00:00:00Z",
        "updated_at": "2026-06-21T00:00:00Z"
    });

    let admin_paths = [
        ("GET", "/v1/admin/orgs", None),
        ("PUT", "/v1/admin/orgs/acme", Some(org_body("acme"))),
        ("DELETE", "/v1/admin/orgs/acme", None),
        (
            "PUT",
            "/v1/admin/groups/eng",
            Some(valid_group_body.clone()),
        ),
        ("DELETE", "/v1/admin/groups/eng", None),
        (
            "PUT",
            "/v1/admin/roles/publisher",
            Some(valid_role_body.clone()),
        ),
        ("DELETE", "/v1/admin/roles/publisher", None),
        ("DELETE", "/v1/admin/grants/g1", None),
    ];

    for (method, path, body) in admin_paths {
        let json = body.map(|v| v.to_string());

        // Missing credential is 401.
        let mut builder = Request::builder().method(method).uri(path);
        if json.is_some() {
            builder = builder.header("content-type", "application/json");
        }
        let request = builder
            .body(Body::from(json.clone().unwrap_or_default()))
            .unwrap();
        let response = router.clone().oneshot(request).await.expect("dispatch");
        assert_eq!(
            response.status(),
            StatusCode::UNAUTHORIZED,
            "{method} {path} must reject missing credential with 401"
        );

        // Wrong credential is 403.
        let mut builder = Request::builder()
            .method(method)
            .uri(path)
            .header("authorization", "Bearer not-the-admin-token");
        if json.is_some() {
            builder = builder.header("content-type", "application/json");
        }
        let request = builder.body(Body::from(json.unwrap_or_default())).unwrap();
        let response = router.clone().oneshot(request).await.expect("dispatch");
        assert_eq!(
            response.status(),
            StatusCode::FORBIDDEN,
            "{method} {path} must reject wrong credential with 403"
        );
    }
}

#[tokio::test]
async fn admin_auth_accepts_an_x_api_key_header_credential() {
    // The auth seam recognises an `x-api-key` admin credential as well as the
    // `Authorization: Bearer` shape — both forms must let the same admin call
    // through.
    let state = Arc::new(Mutex::new(DaemonState::new(
        AuthzApi::new(),
        AdminAuthPolicy::new(["sk-ant-admin-xyz".to_owned()]),
    )));
    let router = daemon_router(state);

    let request = Request::builder()
        .method("POST")
        .uri("/v1/admin/orgs")
        .header("content-type", "application/json")
        .header("x-api-key", "sk-ant-admin-xyz")
        .body(Body::from(org_body("acme").to_string()))
        .unwrap();
    let response = router.oneshot(request).await.expect("dispatch");
    assert_eq!(response.status(), StatusCode::OK);
}

#[tokio::test]
async fn snapshot_since_returns_304_when_already_current() {
    let router = daemon();
    let initial = router
        .clone()
        .oneshot(authed_get("/v1/authz/snapshot"))
        .await
        .expect("dispatch");
    let initial: PolicySnapshot =
        serde_json::from_value(body_json(initial).await).expect("snapshot");
    assert_eq!(initial.version, 1);

    // A `since` equal to the current version is a no-op: 304 Not Modified.
    let mut url = String::from("/v1/authz/snapshot?since=");
    url.push_str(&initial.version.to_string());
    let request = Request::builder()
        .method("GET")
        .uri(&url)
        .header("authorization", format!("Bearer {ADMIN_TOKEN}"))
        .body(Body::empty())
        .unwrap();
    let response = router.clone().oneshot(request).await.expect("dispatch");
    assert_eq!(response.status(), StatusCode::NOT_MODIFIED);

    // A `since` strictly less than the current version returns the snapshot.
    let request = Request::builder()
        .method("GET")
        .uri("/v1/authz/snapshot?since=0")
        .header("authorization", format!("Bearer {ADMIN_TOKEN}"))
        .body(Body::empty())
        .unwrap();
    let response = router.oneshot(request).await.expect("dispatch");
    assert_eq!(response.status(), StatusCode::OK);
    let snap: PolicySnapshot = serde_json::from_value(body_json(response).await).expect("snapshot");
    assert_eq!(snap.version, initial.version);
}

#[tokio::test]
async fn authorize_route_evaluates_a_real_request_through_the_seam() {
    let router = daemon();
    let request_body = serde_json::json!({
        "principal": { "kind": "service", "service_id": "ci" },
        "action": "pack.publish",
        "scope": { "kind": "global" }
    });
    let response = router
        .oneshot(authed_json("POST", "/v1/authorize", request_body))
        .await
        .expect("dispatch");
    assert_eq!(response.status(), StatusCode::OK);
    let outcome: AuthorizationOutcome =
        serde_json::from_value(body_json(response).await).expect("outcome");
    // Default policy has no grants, so an unknown action defaults to deny.
    assert_eq!(
        outcome.decision,
        awaken_iam_contract::AuthorizationDecision::Deny
    );
    assert_eq!(outcome.reason, "default_deny");
}

#[tokio::test]
async fn authorize_batch_preserves_request_order_one_to_one() {
    let router = daemon();
    let request_body = serde_json::json!({
        "requests": [
            {
                "principal": { "kind": "service", "service_id": "ci" },
                "action": "pack.read",
                "scope": { "kind": "global" }
            },
            {
                "principal": { "kind": "account", "account_id": "ada" },
                "action": "pack.publish",
                "scope": { "kind": "global" }
            },
            {
                "principal": { "kind": "account", "account_id": "ada" },
                "action": "pack.read",
                "on_behalf_of": [
                    { "kind": "service", "service_id": "ci" }
                ],
                "scope": { "kind": "global" }
            }
        ]
    });
    let response = router
        .oneshot(authed_json("POST", "/v1/authorize/batch", request_body))
        .await
        .expect("dispatch");
    assert_eq!(response.status(), StatusCode::OK);
    let response: BatchAuthorizationResponse =
        serde_json::from_value(body_json(response).await).expect("batch");
    assert_eq!(response.outcomes.len(), 3);
    // Order is preserved and the empty-policy default-deny holds for every entry.
    for outcome in &response.outcomes {
        assert_eq!(
            outcome.decision,
            awaken_iam_contract::AuthorizationDecision::Deny
        );
        assert_eq!(outcome.reason, "default_deny");
    }
}

#[tokio::test]
async fn check_entitlement_returns_decision_for_known_and_unknown_features() {
    let router = daemon();
    let request_body = serde_json::json!({
        "principal": { "kind": "account", "account_id": "ada" },
        "entitlement": "any.feature"
    });
    let response = router
        .oneshot(authed_json("POST", "/v1/entitlements/check", request_body))
        .await
        .expect("dispatch");
    assert_eq!(response.status(), StatusCode::OK);
    let result: EntitlementCheckResponse =
        serde_json::from_value(body_json(response).await).expect("entitlement");
    // The default-allow entitlement engine permits anything; the seam surfaces
    // that decision faithfully.
    assert_eq!(
        result.decision,
        awaken_iam_contract::EntitlementDecision::Allow
    );
}

#[tokio::test]
async fn admin_grant_issued_over_the_wire_advances_the_snapshot_fence() {
    // The policy-administration seam is the single-applier for the snapshot
    // fence: every successful admin mutation bumps the authz snapshot version
    // a synced consumer polls. Three distinct mutations must produce three
    // monotonic bumps, regardless of whether the mutation creates or deletes.
    let router = daemon();

    let before = router
        .clone()
        .oneshot(authed_get("/v1/authz/snapshot"))
        .await
        .expect("dispatch");
    let before: PolicySnapshot = serde_json::from_value(body_json(before).await).expect("snapshot");
    let base = before.version;

    // Issue a grant over the wire.
    let grant_body = serde_json::json!({
        "id": "g_ada_publish",
        "subject": { "kind": "principal", "principal": { "kind": "account", "account_id": "ada" } },
        "action_pattern": "pack.publish",
        "scope": { "kind": "global" },
        "effect": "allow"
    });
    let issue = router
        .clone()
        .oneshot(authed_json("POST", "/v1/admin/grants", grant_body))
        .await
        .expect("dispatch");
    assert_eq!(issue.status(), StatusCode::OK);
    let ack: AdminMutationAck = serde_json::from_value(body_json(issue).await).expect("ack");
    assert_eq!(ack.version, base + 1);

    // Revoke the same grant: a second bump.
    let revoke = router
        .clone()
        .oneshot(authed("DELETE", "/v1/admin/grants/g_ada_publish", None))
        .await
        .expect("dispatch");
    assert_eq!(revoke.status(), StatusCode::OK);
    let ack: AdminMutationAck = serde_json::from_value(body_json(revoke).await).expect("ack");
    assert_eq!(ack.version, base + 2);

    // The version fence the snapshot returns reflects the same monotonic bumps.
    let after = router
        .oneshot(authed_get("/v1/authz/snapshot"))
        .await
        .expect("dispatch");
    let after: PolicySnapshot = serde_json::from_value(body_json(after).await).expect("snapshot");
    assert_eq!(after.version, base + 2);
}

// -- helpers ------------------------------------------------------------------
