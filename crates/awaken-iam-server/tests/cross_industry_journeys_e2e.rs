//! Cross-industry user journeys over the real HTTP/PAP/SQLite execution path.

use std::sync::{Arc, Mutex};

use awaken_iam_contract::ProductId;
use awaken_iam_core::AuthorizationProfileRepository;
use awaken_iam_server::{
    AdminAuthPolicy, AuthApi, AuthzApi, DaemonState, SqlStore, SqliteBackend, daemon_router,
    sqlite_in_memory_store,
};
use axum::body::Body;
use axum::http::{Request, StatusCode};
use serde_json::{Value, json};
use tower::ServiceExt;

const ADMIN: &str = "cross-industry-admin";

fn app() -> axum::Router {
    let store = sqlite_in_memory_store("cross_industry").expect("migrate IAM store");
    let profiles: Arc<dyn AuthorizationProfileRepository> = Arc::new(store.clone());
    let state: DaemonState<SqlStore<SqliteBackend>> = DaemonState::with_policy_store(
        AuthzApi::new(),
        AdminAuthPolicy::new([ADMIN.to_owned()]).with_product_token(
            ProductId::new("cross-industry").unwrap(),
            "cross-industry-product",
        ),
        profiles,
        store,
        AuthApi::new().token_authority(),
    )
    .expect("hydrate daemon");
    daemon_router(Arc::new(Mutex::new(state)))
}

fn request(method: &str, path: &str, body: Value, authenticated: bool) -> Request<Body> {
    let mut builder = Request::builder()
        .method(method)
        .uri(path)
        .header("content-type", "application/json");
    if authenticated {
        builder = builder.header("authorization", format!("Bearer {ADMIN}"));
    }
    builder.body(Body::from(body.to_string())).unwrap()
}

fn product_request(body: Value) -> Request<Body> {
    Request::builder()
        .method("POST")
        .uri("/v1/authz/resource-provisions")
        .header("content-type", "application/json")
        .header("authorization", "Bearer cross-industry-product")
        .body(Body::from(body.to_string()))
        .unwrap()
}

async fn json_body(response: axum::response::Response) -> Value {
    let bytes = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .unwrap();
    serde_json::from_slice(&bytes).unwrap()
}

fn org(id: &str) -> Value {
    json!({
        "organization": {
            "id": id,
            "display_name": format!("{id} organization"),
            "owner": {"kind":"account","account_id":"owner"},
            "created_at":"2026-09-17T00:00:00Z",
            "updated_at":"2026-09-17T00:00:00Z"
        },
        "owner_role_id":"organization-admin"
    })
}

fn provision(resource_type: &str, id: &str, key: &str, epoch: u64) -> Value {
    json!({
        "product_id":"cross-industry",
        "org_id":"acme",
        "idempotency_key":key,
        "epoch":epoch,
        "grants":[
            {
                "id":format!("g_{id}_user"),
                "subject":{"kind":"principal","principal":{"kind":"account","account_id":"user"}},
                "action_pattern":format!("{resource_type}.*"),
                "scope":{"kind":"resource","resource_type":resource_type,"resource_id":id},
                "effect":"allow"
            },
            {
                "id":format!("g_{id}_agent"),
                "subject":{"kind":"principal","principal":{"kind":"service","service_id":"managed-agent"}},
                "action_pattern":format!("{resource_type}.*"),
                "scope":{"kind":"resource","resource_type":resource_type,"resource_id":id},
                "effect":"require_approval"
            }
        ],
        "scope_edges":[{
            "resource_type":resource_type,
            "resource_id":id,
            "parent":{"kind":"workspace","workspace_id":"workspace-main"}
        }]
    })
}

#[tokio::test]
async fn organization_business_resource_agent_and_revocation_journeys_are_one_model() {
    // Cause/effect decision table:
    // R1 valid owner role + named Org -> atomic tenant plus owner authority.
    // R2 Workspace anchored to Org + education/manufacturing/retail resources
    // -> the same generic provision endpoint returns durable Applied receipts.
    // R3 exact at-least-once replay -> Replayed at the original version.
    // R4 same resource/epoch under a new key or an edge outside Org -> reject
    // without changing the live policy.
    // R5 user Allow + delegated agent RequireApproval -> RequireApproval.
    // R6 retire the resource at a higher epoch -> edge and exact grants vanish;
    // exact retirement replay is stable and the delegated request becomes Deny.
    let app = app();
    let role = json!({
        "id":"organization-admin",
        "action_patterns":["org.*","workspace.*"],
        "created_at":"2026-09-17T00:00:00Z",
        "updated_at":"2026-09-17T00:00:00Z"
    });
    assert_eq!(
        app.clone()
            .oneshot(request("POST", "/v1/admin/roles", role, true))
            .await
            .unwrap()
            .status(),
        StatusCode::OK
    );
    assert_eq!(
        app.clone()
            .oneshot(request(
                "POST",
                "/v1/admin/orgs/provision",
                org("acme"),
                true
            ))
            .await
            .unwrap()
            .status(),
        StatusCode::OK
    );
    assert_eq!(
        app.clone()
            .oneshot(request(
                "POST",
                "/v1/admin/scope/workspace-orgs",
                json!({"workspace_id":"workspace-main","org_id":"acme"}),
                true,
            ))
            .await
            .unwrap()
            .status(),
        StatusCode::OK
    );

    for (resource_type, id) in [
        ("tutor.campus", "nanshan"),
        ("manufacturing.factory", "shenzhen"),
        ("retail.store", "futian"),
    ] {
        let command = provision(resource_type, id, &format!("{resource_type}:{id}"), 1);
        let applied = app
            .clone()
            .oneshot(product_request(command.clone()))
            .await
            .unwrap();
        assert_eq!(applied.status(), StatusCode::OK, "R2 {resource_type}");
        let applied = json_body(applied).await;
        assert_eq!(applied["disposition"], "applied");
        let replay = json_body(app.clone().oneshot(product_request(command)).await.unwrap()).await;
        assert_eq!(replay["disposition"], "replayed", "R3");
        assert_eq!(replay["version"], applied["version"], "R3 fence");
    }

    let stale = provision("tutor.campus", "nanshan", "different-key", 1);
    assert_eq!(
        app.clone()
            .oneshot(product_request(stale))
            .await
            .unwrap()
            .status(),
        StatusCode::CONFLICT,
        "R4 stale epoch"
    );
    let mut escaped = provision("tutor.campus", "escape", "escape", 1);
    escaped["scope_edges"][0]["parent"] = json!({"kind":"global"});
    assert_eq!(
        app.clone()
            .oneshot(product_request(escaped))
            .await
            .unwrap()
            .status(),
        StatusCode::UNPROCESSABLE_ENTITY,
        "R4 tenant escape"
    );
    let mut wrong_product = provision("tutor.campus", "wrong", "wrong-product", 2);
    wrong_product["product_id"] = json!("other-product");
    assert_eq!(
        app.clone()
            .oneshot(product_request(wrong_product))
            .await
            .unwrap()
            .status(),
        StatusCode::FORBIDDEN,
        "R4 product isolation"
    );

    let authorization = || {
        json!({
            "principal":{"kind":"service","service_id":"managed-agent"},
            "on_behalf_of":[{"kind":"account","account_id":"user"}],
            "action":"tutor.campus.manage",
            "scope":{"kind":"resource","resource_type":"tutor.campus","resource_id":"nanshan"}
        })
    };
    let outcome = json_body(
        app.clone()
            .oneshot(request("POST", "/v1/authorize", authorization(), false))
            .await
            .unwrap(),
    )
    .await;
    assert_eq!(outcome["decision"], "require_approval", "R5");

    let retirement = json!({
        "product_id":"cross-industry",
        "org_id":"acme",
        "idempotency_key":"tutor.campus:nanshan:retire",
        "epoch":2,
        "grants":[],
        "scope_edges":[],
        "retirements":[{
            "resource_type":"tutor.campus",
            "resource_id":"nanshan",
            "grant_ids":["g_nanshan_user","g_nanshan_agent"]
        }]
    });
    let retired = app
        .clone()
        .oneshot(product_request(retirement.clone()))
        .await
        .unwrap();
    assert_eq!(retired.status(), StatusCode::OK);
    assert_eq!(json_body(retired).await["disposition"], "applied");
    assert_eq!(
        json_body(
            app.clone()
                .oneshot(product_request(retirement))
                .await
                .unwrap()
        )
        .await["disposition"],
        "replayed"
    );
    let denied = json_body(
        app.oneshot(request("POST", "/v1/authorize", authorization(), false))
            .await
            .unwrap(),
    )
    .await;
    assert_eq!(denied["decision"], "deny", "R6");
}
