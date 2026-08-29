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
    OrgView, PolicySnapshot, ProductId, RoleView,
};
use awaken_iam_core::AuthorizationProfileRepository;
use awaken_iam_server::{
    AdminAuthPolicy, AuthApi, AuthzApi, DaemonState, SqlStore, SqliteBackend, daemon_router, http,
    sqlite_in_memory_store,
};
use axum::Router;
use axum::body::Body;
use axum::http::{Request, Response, StatusCode};
use tower::ServiceExt;

const ADMIN_TOKEN: &str = "admin-secret";
const AGENTS_TOKEN: &str = "agents-directory-secret";

fn test_daemon_state(
    authz: AuthzApi,
    auth: AdminAuthPolicy,
) -> DaemonState<SqlStore<SqliteBackend>> {
    let store = sqlite_in_memory_store("iam_http_test").expect("migrated sqlite IAM store");
    let profiles: Arc<dyn AuthorizationProfileRepository> = Arc::new(store.clone());
    DaemonState::with_policy_store(
        authz,
        auth,
        profiles,
        store,
        AuthApi::new().token_authority(),
    )
    .expect("hydrate test daemon")
}

fn daemon() -> Router {
    daemon_with_auth(AdminAuthPolicy::new([ADMIN_TOKEN.to_owned()]))
}

fn daemon_with_auth(auth: AdminAuthPolicy) -> Router {
    let state = Arc::new(Mutex::new(test_daemon_state(AuthzApi::new(), auth)));
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

fn product_json(method: &str, path: &str, body: serde_json::Value) -> Request<Body> {
    Request::builder()
        .method(method)
        .uri(path)
        .header("content-type", "application/json")
        .header("authorization", format!("Bearer {AGENTS_TOKEN}"))
        .body(Body::from(body.to_string()))
        .expect("build product request")
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
async fn directory_http_preserves_stable_space_identity_across_move() {
    // Cause/effect graph over the public remote seam: C1 authenticated valid Org
    // and root/child nodes -> E1 both creates succeed with increasing Directory
    // revisions; C2 product space bound to child -> E2 query resolves that exact
    // stable space; C3 metadata update -> E3 display fields change without
    // changing identity; C4 child moved to root -> E4 placement changes while
    // the binding identity is unchanged; C5 unauthenticated read -> E5 deny.
    // Rules H1-H5 cover transport auth, create, update, list, move, and binding
    // lookup.
    let app = daemon();
    assert_eq!(
        app.clone()
            .oneshot(authed_json("POST", "/v1/admin/orgs", org_body("acme")))
            .await
            .unwrap()
            .status(),
        StatusCode::OK
    );
    let root = app
        .clone()
        .oneshot(authed_json(
            "POST",
            "/v1/admin/directory/nodes",
            serde_json::json!({
                "org_id":"acme",
                "name":"Root",
                "preferred_slug":"root"
            }),
        ))
        .await
        .unwrap();
    assert_eq!(root.status(), StatusCode::OK, "H1");
    let root = body_json(root).await;
    let root_revision = root["revision"].as_u64().unwrap();
    let root_id = root["node"]["id"].as_str().unwrap().to_owned();
    let child = app
        .clone()
        .oneshot(authed_json(
            "POST",
            "/v1/admin/directory/product-spaces/ensure",
            serde_json::json!({
                "product_space":{"product_id":"agents", "space_id":"space-a"},
                "org_id":"acme",
                "parent_product_space":null,
                "name":"Team",
                "preferred_slug":"team"
            }),
        ))
        .await
        .unwrap();
    assert_eq!(child.status(), StatusCode::OK, "H1");
    let child = body_json(child).await;
    let child_revision = child["revision"].as_u64().unwrap();
    let child_id = child["node"]["id"].as_str().unwrap().to_owned();
    assert!(child_revision > root_revision, "E1");

    let moved_under_root = app
        .clone()
        .oneshot(authed_json(
            "PUT",
            &format!("/v1/admin/directory/nodes/{child_id}"),
            serde_json::json!({"parent_id":root_id}),
        ))
        .await
        .unwrap();
    assert_eq!(moved_under_root.status(), StatusCode::OK, "H4");

    let updated = app
        .clone()
        .oneshot(authed_json(
            "PATCH",
            &format!("/v1/admin/directory/nodes/{child_id}"),
            serde_json::json!({
                "name":"Platform Team",
                "slug":"platform",
                "description":"Shared platform"
            }),
        ))
        .await
        .unwrap();
    assert_eq!(updated.status(), StatusCode::OK, "H3");
    let updated_revision = body_json(updated).await["revision"].as_u64().unwrap();
    assert!(updated_revision > child_revision, "E3");
    let current = app
        .clone()
        .oneshot(authed_get(&format!("/v1/admin/directory/nodes/{child_id}")))
        .await
        .unwrap();
    let current = body_json(current).await;
    assert_eq!(current["name"], "Platform Team", "E3");
    assert_eq!(current["slug"], "platform", "E3");

    let moved = app
        .clone()
        .oneshot(authed_json(
            "PUT",
            &format!("/v1/admin/directory/nodes/{child_id}"),
            serde_json::json!({}),
        ))
        .await
        .unwrap();
    assert_eq!(moved.status(), StatusCode::OK, "H4");
    assert!(body_json(moved).await["revision"].as_u64().unwrap() > updated_revision);
    let roots = app
        .clone()
        .oneshot(authed_get("/v1/admin/directory/nodes?org_id=acme"))
        .await
        .unwrap();
    assert_eq!(roots.status(), StatusCode::OK);
    let roots = body_json(roots).await;
    assert_eq!(roots["org_id"], "acme", "E4");
    assert_eq!(roots["nodes"].as_array().unwrap().len(), 2, "E4");
    assert!(roots["revision"].as_u64().unwrap() > updated_revision, "E4");

    let binding = app
        .clone()
        .oneshot(authed_json(
            "POST",
            "/v1/admin/directory/product-spaces/query",
            serde_json::json!({
                "org_id":"acme",
                "product_space":{"product_id":"agents", "space_id":"space-a"}
            }),
        ))
        .await
        .unwrap();
    assert_eq!(binding.status(), StatusCode::OK, "H2");
    assert_eq!(body_json(binding).await["node_id"], child_id, "E2/E4");

    let denied = app
        .oneshot(
            Request::builder()
                .uri("/v1/admin/directory/nodes?org_id=acme")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(denied.status(), StatusCode::UNAUTHORIZED, "H5");
}

#[tokio::test]
async fn product_credential_is_scoped_and_directory_route_matrix_is_complete() {
    // Cause-effect decision table over the remote security/read surface:
    // R1 product credential + matching ProductId ensure/query/retire -> 200; R2 same
    // credential + another ProductId -> 403 and no effect; R3 product credential
    // + administrator-only node command -> 403; R4 admin archive/restore/revision
    // -> each route succeeds and the Org revision advances exactly once.
    let app = daemon_with_auth(
        AdminAuthPolicy::new([ADMIN_TOKEN.to_owned()])
            .with_product_token(ProductId::new("agents").unwrap(), AGENTS_TOKEN),
    );
    assert_eq!(
        app.clone()
            .oneshot(authed_json("POST", "/v1/admin/orgs", org_body("acme")))
            .await
            .unwrap()
            .status(),
        StatusCode::OK
    );
    let matching = serde_json::json!({
        "product_space":{"product_id":"agents", "space_id":"workspace/a"},
        "org_id":"acme",
        "name":"Agents workspace",
        "preferred_slug":"agents-workspace"
    });
    let created = app
        .clone()
        .oneshot(product_json(
            "POST",
            "/v1/admin/directory/product-spaces/ensure",
            matching,
        ))
        .await
        .unwrap();
    assert_eq!(created.status(), StatusCode::OK, "R1");
    let created = body_json(created).await;
    let node_id = created["node"]["id"].as_str().unwrap().to_owned();
    assert_eq!(created["revision"], 2, "R1");

    let foreign = app
        .clone()
        .oneshot(product_json(
            "POST",
            "/v1/admin/directory/product-spaces/ensure",
            serde_json::json!({
                "product_space":{"product_id":"objects", "space_id":"space/a"},
                "org_id":"acme",
                "name":"Objects space",
                "preferred_slug":"objects-space"
            }),
        ))
        .await
        .unwrap();
    assert_eq!(foreign.status(), StatusCode::FORBIDDEN, "R2");

    let generic = app
        .clone()
        .oneshot(product_json(
            "POST",
            "/v1/admin/directory/nodes",
            serde_json::json!({
                "org_id":"acme", "name":"Folder", "preferred_slug":"folder"
            }),
        ))
        .await
        .unwrap();
    assert_eq!(generic.status(), StatusCode::FORBIDDEN, "R3");

    let own_query = app
        .clone()
        .oneshot(product_json(
            "POST",
            "/v1/admin/directory/product-spaces/query",
            serde_json::json!({
                "org_id":"acme",
                "product_space":{"product_id":"agents", "space_id":"workspace/a"}
            }),
        ))
        .await
        .unwrap();
    assert_eq!(own_query.status(), StatusCode::OK, "R1");

    let retired = app
        .clone()
        .oneshot(product_json(
            "POST",
            "/v1/admin/directory/product-spaces/retire",
            serde_json::json!({
                "org_id":"acme",
                "product_space":{"product_id":"agents", "space_id":"workspace/a"}
            }),
        ))
        .await
        .unwrap();
    assert_eq!(retired.status(), StatusCode::OK, "R1");
    let retired = body_json(retired).await;
    assert_eq!(retired["placement"]["status"], "retired", "R1");
    assert_eq!(retired["revision"], 3, "R1");

    let foreign_retire = app
        .clone()
        .oneshot(product_json(
            "POST",
            "/v1/admin/directory/product-spaces/retire",
            serde_json::json!({
                "org_id":"acme",
                "product_space":{"product_id":"objects", "space_id":"space/a"}
            }),
        ))
        .await
        .unwrap();
    assert_eq!(foreign_retire.status(), StatusCode::FORBIDDEN, "R2");

    let archived = app
        .clone()
        .oneshot(authed(
            "DELETE",
            &format!("/v1/admin/directory/nodes/{node_id}"),
            None,
        ))
        .await
        .unwrap();
    assert_eq!(archived.status(), StatusCode::OK, "R4");
    assert_eq!(body_json(archived).await["revision"], 4, "R4");
    let restored = app
        .clone()
        .oneshot(authed(
            "POST",
            &format!("/v1/admin/directory/nodes/{node_id}/restore"),
            None,
        ))
        .await
        .unwrap();
    assert_eq!(restored.status(), StatusCode::OK, "R4");
    assert_eq!(body_json(restored).await["revision"], 5, "R4");
    let revision = app
        .oneshot(authed_get("/v1/admin/directory/revision?org_id=acme"))
        .await
        .unwrap();
    assert_eq!(revision.status(), StatusCode::OK, "R4");
    assert_eq!(body_json(revision).await, 5, "R4");
}

#[tokio::test]
async fn capability_http_uses_one_admin_issuer_and_public_fail_closed_verifier() {
    // Capability HTTP cause/effect decision table:
    // C1=admin credential, C2=forward window + non-empty coordinates/scopes,
    // C3=matching audience, C4=unexpired token. Effects: E1=mint exactly one
    // cap+jwt from the daemon authority, E2=return its verified claims, E3=deny
    // without claims. Rules R1 C1+C2 -> E1; R2 !C1|!C2 -> E3;
    // R3 E1+C3+C4 -> E2; R4 E1+(!C3|!C4) -> E3.
    let app = daemon();
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs() as i64;
    let body = serde_json::json!({
        "issuer":"https://iam.example",
        "subject":"public-link-1",
        "audience":"awaken-pilot-public",
        "token_id":"cap-public-1",
        "issued_at":now,
        "expires_at":now + 600,
        "scopes":["pilot.mission.read"]
    });

    let unauthenticated = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/v1/admin/capabilities")
                .header("content-type", "application/json")
                .body(Body::from(body.to_string()))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(unauthenticated.status(), StatusCode::UNAUTHORIZED, "R2");

    let issued = app
        .clone()
        .oneshot(authed_json("POST", "/v1/admin/capabilities", body))
        .await
        .unwrap();
    assert_eq!(issued.status(), StatusCode::CREATED, "R1");
    let token = body_json(issued).await["token"]
        .as_str()
        .unwrap()
        .to_owned();

    let introspect = |audience: &str| {
        Request::builder()
            .method("POST")
            .uri("/v1/capabilities/introspect")
            .header("content-type", "application/json")
            .body(Body::from(
                serde_json::json!({"token":token,"audience":audience}).to_string(),
            ))
            .unwrap()
    };
    let verified = app
        .clone()
        .oneshot(introspect("awaken-pilot-public"))
        .await
        .unwrap();
    assert_eq!(verified.status(), StatusCode::OK, "R3");
    let claims = body_json(verified).await;
    assert_eq!(claims["sub"], "public-link-1", "E2");
    assert_eq!(
        claims["scope"],
        serde_json::json!(["pilot.mission.read"]),
        "E2"
    );

    let wrong_audience = app.oneshot(introspect("other-product")).await.unwrap();
    assert_eq!(wrong_audience.status(), StatusCode::UNAUTHORIZED, "R4");
}

#[tokio::test]
async fn invitation_http_flow_closes_into_queryable_membership() {
    // Causes/effects over the real router: R1 authenticated create with valid
    // Org/role intent -> Pending plus one-time token; R2 matching account email
    // and token -> Accepted plus version fence; R3 scope query after R2 -> exact
    // materialized membership. This proves transport DTOs do not form a path
    // parallel to the PAP/store behavior covered by unit tests.
    let app = daemon();
    assert_eq!(
        app.clone()
            .oneshot(authed_json("POST", "/v1/admin/orgs", org_body("acme")))
            .await
            .unwrap()
            .status(),
        StatusCode::OK,
    );
    let role = serde_json::json!({
        "id": "member",
        "action_patterns": ["workspace.read"],
        "created_at": "2026-08-02T00:00:00Z",
        "updated_at": "2026-08-02T00:00:00Z"
    });
    assert_eq!(
        app.clone()
            .oneshot(authed_json("POST", "/v1/admin/roles", role))
            .await
            .unwrap()
            .status(),
        StatusCode::OK,
    );
    let created = app
        .clone()
        .oneshot(authed_json(
            "POST",
            "/v1/admin/invitations",
            serde_json::json!({
                "idempotency_key":"http-flow",
                "org_id":"acme",
                "email":"member@example.com",
                "bindings":[{"role_id":"member","scope":{"kind":"org","org_id":"acme"}}],
                "invited_by":{"kind":"account","account_id":"ada"},
                "expires_at":"2099-01-01T00:00:00Z"
            }),
        ))
        .await
        .unwrap();
    assert_eq!(created.status(), StatusCode::OK);
    let issued = body_json(created).await;
    let invitation_id = issued["invitation"]["id"].as_str().unwrap();
    let accepted = app
        .clone()
        .oneshot(authed_json(
            "POST",
            &format!("/v1/admin/invitations/{invitation_id}/accept"),
            serde_json::json!({
                "account_id":"member",
                "verified_email":"member@example.com",
                "token":issued["token"]
            }),
        ))
        .await
        .unwrap();
    assert_eq!(accepted.status(), StatusCode::OK);
    assert_eq!(
        body_json(accepted).await["invitation"]["status"],
        "accepted"
    );

    let memberships = app
        .oneshot(authed_json(
            "POST",
            "/v1/admin/memberships/query-scope",
            serde_json::json!({"scope":{"kind":"org","org_id":"acme"}}),
        ))
        .await
        .unwrap();
    assert_eq!(memberships.status(), StatusCode::OK);
    let memberships = body_json(memberships).await;
    assert_eq!(memberships.as_array().unwrap().len(), 1);
    assert_eq!(memberships[0]["principal"]["account_id"], "member");
}

#[tokio::test]
async fn scoped_role_change_reaches_the_live_pdp_as_one_http_command() {
    // Cause/effect decision table over the real transport: R1 authenticated
    // subset replacement -> 200 + one version fence + exact new binding;
    // R2 replacement outside the managed family -> 400 and old binding stays;
    // R3 unrelated role at the same scope -> preserved. The query proves the
    // mutation reached the authoritative PAP rather than a response-only shape.
    let app = daemon();
    let principal = serde_json::json!({"kind":"account","account_id":"member"});
    let scope = serde_json::json!({"kind":"workspace","workspace_id":"workspace-a"});
    for role in ["product:member", "custom:auditor"] {
        let response = app
            .clone()
            .oneshot(authed_json(
                "POST",
                "/v1/admin/memberships",
                serde_json::json!({
                    "principal":principal.clone(),
                    "role_id":role,
                    "scope":scope.clone(),
                }),
            ))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
    }
    let replaced = app
        .clone()
        .oneshot(authed_json(
            "PUT",
            "/v1/admin/memberships/scoped",
            serde_json::json!({
                "principal":principal.clone(),
                "scope":scope.clone(),
                "managed_role_ids":["product:member","product:admin"],
                "replacement_role_ids":["product:admin"],
            }),
        ))
        .await
        .unwrap();
    assert_eq!(replaced.status(), StatusCode::OK, "R1");

    let invalid = app
        .clone()
        .oneshot(authed_json(
            "PUT",
            "/v1/admin/memberships/scoped",
            serde_json::json!({
                "principal":principal.clone(),
                "scope":scope,
                "managed_role_ids":["product:member"],
                "replacement_role_ids":["product:admin"],
            }),
        ))
        .await
        .unwrap();
    assert_eq!(invalid.status(), StatusCode::UNPROCESSABLE_ENTITY, "R2");

    let queried = app
        .oneshot(authed_json(
            "POST",
            "/v1/admin/memberships/query",
            serde_json::json!({"principal":principal}),
        ))
        .await
        .unwrap();
    let bindings = body_json(queried).await;
    let roles = bindings
        .as_array()
        .unwrap()
        .iter()
        .map(|binding| binding["role_id"].as_str().unwrap())
        .collect::<std::collections::BTreeSet<_>>();
    assert_eq!(roles, ["custom:auditor", "product:admin"].into(), "R2/R3");
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
    let orgs: Vec<OrgView> = serde_json::from_value(body_json(listed).await).expect("orgs");
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
    let orgs: Vec<OrgView> = serde_json::from_value(body_json(empty).await).expect("orgs");
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
async fn get_org_matches_the_remote_client_contract_and_fails_closed() {
    // Cause/effect table for the exact resource read used by remote Cloud:
    // C1=valid admin credential + existing Org -> E1=200 and the exact Org;
    // C2=valid credential + absent Org -> E2=404 (the client maps this to
    // None); C3=missing credential -> E3=401 before repository access. This
    // route must not be approximated by an O(number-of-orgs) list scan.
    let router = daemon();
    assert_eq!(
        router
            .clone()
            .oneshot(authed_json("POST", "/v1/admin/orgs", org_body("acme")))
            .await
            .expect("dispatch")
            .status(),
        StatusCode::OK
    );

    let found = router
        .clone()
        .oneshot(authed_get("/v1/admin/orgs/acme"))
        .await
        .expect("dispatch");
    assert_eq!(found.status(), StatusCode::OK);
    let found: OrgView = serde_json::from_value(body_json(found).await).expect("Org");
    assert_eq!(found.id.0, "acme");

    assert_eq!(
        router
            .clone()
            .oneshot(authed_get("/v1/admin/orgs/missing"))
            .await
            .expect("dispatch")
            .status(),
        StatusCode::NOT_FOUND
    );
    assert_eq!(
        router
            .oneshot(
                Request::builder()
                    .method("GET")
                    .uri("/v1/admin/orgs/acme")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .expect("dispatch")
            .status(),
        StatusCode::UNAUTHORIZED
    );
}

#[tokio::test]
async fn get_role_matches_the_remote_client_contract_and_fails_closed() {
    // Cause/effect table for the exact role read used by remote Cloud:
    // C1=valid admin credential + existing Role -> E1=200 and the exact Role;
    // C2=valid credential + absent Role -> E2=404 (the client maps this to
    // None); C3=missing credential -> E3=401 before repository access. This
    // route is the read half of ensure-role and must not be inferred from a
    // cached policy snapshot or approximated by a full collection scan.
    let router = daemon();
    let role = serde_json::json!({
        "id": "publisher",
        "display_name": "Publisher",
        "action_patterns": ["pack.read", "pack.publish"],
        "created_at": "2026-06-21T00:00:00Z",
        "updated_at": "2026-06-21T00:00:00Z"
    });
    assert_eq!(
        router
            .clone()
            .oneshot(authed_json("POST", "/v1/admin/roles", role))
            .await
            .expect("dispatch")
            .status(),
        StatusCode::OK
    );

    let found = router
        .clone()
        .oneshot(authed_get("/v1/admin/roles/publisher"))
        .await
        .expect("dispatch");
    assert_eq!(found.status(), StatusCode::OK);
    let found: RoleView = serde_json::from_value(body_json(found).await).expect("Role");
    assert_eq!(found.id, "publisher");
    assert_eq!(found.action_patterns, ["pack.read", "pack.publish"]);

    assert_eq!(
        router
            .clone()
            .oneshot(authed_get("/v1/admin/roles/missing"))
            .await
            .expect("dispatch")
            .status(),
        StatusCode::NOT_FOUND
    );
    assert_eq!(
        router
            .oneshot(
                Request::builder()
                    .method("GET")
                    .uri("/v1/admin/roles/publisher")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .expect("dispatch")
            .status(),
        StatusCode::UNAUTHORIZED
    );
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
    let orgs: Vec<OrgView> = serde_json::from_value(body_json(listed).await).expect("orgs");
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
    let orgs: Vec<OrgView> = serde_json::from_value(body_json(empty).await).expect("orgs");
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
    let state = Arc::new(Mutex::new(test_daemon_state(
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
    // Cause/effect rule: the production daemon has no configured commercial
    // provider in this fixture, so the HTTP seam faithfully returns the
    // unlicensed fail-closed decision for any feature.
    assert_eq!(
        result.decision,
        awaken_iam_contract::EntitlementDecision::Deny
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

    // The fence is meaningful only if the PDP already evaluates the committed
    // repository row. This assertion catches the former parallel-track bug
    // where the PAP wrote one store and authorize kept an unrelated empty
    // in-memory policy.
    let authorize_request = serde_json::json!({
        "principal": { "kind": "account", "account_id": "ada" },
        "action": "pack.publish",
        "scope": { "kind": "global" }
    });
    let authorized = router
        .clone()
        .oneshot(authed_json(
            "POST",
            "/v1/authorize",
            authorize_request.clone(),
        ))
        .await
        .expect("dispatch");
    let authorized: AuthorizationOutcome =
        serde_json::from_value(body_json(authorized).await).expect("outcome");
    assert_eq!(
        authorized.decision,
        awaken_iam_contract::AuthorizationDecision::Allow
    );

    // Revoke the same grant: a second bump.
    let revoke = router
        .clone()
        .oneshot(authed("DELETE", "/v1/admin/grants/g_ada_publish", None))
        .await
        .expect("dispatch");
    assert_eq!(revoke.status(), StatusCode::OK);
    let ack: AdminMutationAck = serde_json::from_value(body_json(revoke).await).expect("ack");
    assert_eq!(ack.version, base + 2);

    let denied = router
        .clone()
        .oneshot(authed_json("POST", "/v1/authorize", authorize_request))
        .await
        .expect("dispatch");
    let denied: AuthorizationOutcome =
        serde_json::from_value(body_json(denied).await).expect("outcome");
    assert_eq!(
        denied.decision,
        awaken_iam_contract::AuthorizationDecision::Deny
    );

    // The version fence the snapshot returns reflects the same monotonic bumps.
    let after = router
        .oneshot(authed_get("/v1/authz/snapshot"))
        .await
        .expect("dispatch");
    let after: PolicySnapshot = serde_json::from_value(body_json(after).await).expect("snapshot");
    assert_eq!(after.version, base + 2);
}

#[tokio::test]
async fn daemon_restart_hydrates_authorization_from_the_shared_sql_store() {
    let store = sqlite_in_memory_store("iam").expect("migrate sqlite");
    let profiles = Arc::new(store.clone());
    let first = daemon_router(Arc::new(Mutex::new(
        DaemonState::with_policy_store(
            AuthzApi::new(),
            AdminAuthPolicy::new([ADMIN_TOKEN.to_owned()]),
            profiles.clone(),
            store.clone(),
            awaken_iam_server::AuthApi::new().token_authority(),
        )
        .expect("hydrate first daemon"),
    )));
    let grant = serde_json::json!({
        "id": "g_persisted",
        "subject": { "kind": "principal", "principal": { "kind": "account", "account_id": "ada" } },
        "action_pattern": "pack.publish",
        "scope": { "kind": "global" },
        "effect": "allow"
    });
    let issued = first
        .oneshot(authed_json("POST", "/v1/admin/grants", grant))
        .await
        .expect("issue grant");
    let issued_status = issued.status();
    let issued_body = body_json(issued).await;
    assert_eq!(issued_status, StatusCode::OK, "{issued_body}");

    // A new daemon state represents a process restart. It receives no policy
    // object from the first state and must hydrate from the durable repository.
    let restarted = daemon_router(Arc::new(Mutex::new(
        DaemonState::with_policy_store(
            AuthzApi::new(),
            AdminAuthPolicy::new([ADMIN_TOKEN.to_owned()]),
            profiles,
            store,
            awaken_iam_server::AuthApi::new().token_authority(),
        )
        .expect("hydrate restarted daemon"),
    )));
    let request = serde_json::json!({
        "principal": { "kind": "account", "account_id": "ada" },
        "action": "pack.publish",
        "scope": { "kind": "global" }
    });
    let response = restarted
        .oneshot(authed_json("POST", "/v1/authorize", request))
        .await
        .expect("authorize after restart");
    let outcome: AuthorizationOutcome =
        serde_json::from_value(body_json(response).await).expect("outcome");
    assert_eq!(
        outcome.decision,
        awaken_iam_contract::AuthorizationDecision::Allow
    );
}

#[tokio::test]
async fn principal_membership_and_workspace_projection_drive_one_live_policy() {
    let router = daemon();
    assert_eq!(
        router
            .clone()
            .oneshot(authed_json("POST", "/v1/admin/orgs", org_body("acme")))
            .await
            .unwrap()
            .status(),
        StatusCode::OK
    );
    let binding = serde_json::json!({
        "principal": { "kind": "account", "account_id": "ada" },
        "role_id": "tenant-admin",
        "scope": { "kind": "org", "org_id": "acme" }
    });
    assert_eq!(
        router
            .clone()
            .oneshot(authed_json(
                "POST",
                "/v1/admin/memberships",
                binding.clone(),
            ))
            .await
            .unwrap()
            .status(),
        StatusCode::OK
    );
    let queried = router
        .clone()
        .oneshot(authed_json(
            "POST",
            "/v1/admin/memberships/query",
            serde_json::json!({
                "principal": { "kind": "account", "account_id": "ada" }
            }),
        ))
        .await
        .unwrap();
    let bindings: Vec<awaken_iam_contract::RoleBindingSnapshot> =
        serde_json::from_value(body_json(queried).await).expect("bindings");
    assert_eq!(bindings.len(), 1);
    assert_eq!(bindings[0].role_id, "tenant-admin");

    let grant = serde_json::json!({
        "id": "g_workspace_read",
        "subject": { "kind": "principal", "principal": { "kind": "account", "account_id": "ada" } },
        "action_pattern": "workspace.read",
        "scope": { "kind": "org", "org_id": "acme" },
        "effect": "allow"
    });
    assert_eq!(
        router
            .clone()
            .oneshot(authed_json("POST", "/v1/admin/grants", grant))
            .await
            .unwrap()
            .status(),
        StatusCode::OK
    );
    let edge = serde_json::json!({"workspace_id":"ws_flow","org_id":"acme"});
    assert_eq!(
        router
            .clone()
            .oneshot(authed_json(
                "POST",
                "/v1/admin/scope/workspace-orgs",
                edge.clone(),
            ))
            .await
            .unwrap()
            .status(),
        StatusCode::OK
    );
    // Exact redelivery is idempotent and never creates a second edge.
    assert_eq!(
        router
            .clone()
            .oneshot(authed_json("POST", "/v1/admin/scope/workspace-orgs", edge,))
            .await
            .unwrap()
            .status(),
        StatusCode::OK
    );
    let authorized = router
        .oneshot(authed_json(
            "POST",
            "/v1/authorize",
            serde_json::json!({
                "principal": { "kind": "account", "account_id": "ada" },
                "action": "workspace.read",
                "scope": { "kind": "workspace", "workspace_id": "ws_flow" }
            }),
        ))
        .await
        .unwrap();
    let outcome: AuthorizationOutcome =
        serde_json::from_value(body_json(authorized).await).expect("outcome");
    assert_eq!(
        outcome.decision,
        awaken_iam_contract::AuthorizationDecision::Allow
    );
}

// -- helpers ------------------------------------------------------------------
