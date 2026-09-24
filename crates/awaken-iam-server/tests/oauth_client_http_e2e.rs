//! The standalone IAM daemon's authenticated OAuth client administration seam.

use std::sync::{Arc, Mutex};

use awaken_iam_contract::ProductId;
use awaken_iam_core::{
    AuditSink, AuthorizationProfileRepository, OAuthClientRepository, hash_session_token,
};
use awaken_iam_server::{
    AdminAuthPolicy, AuthApi, AuthzApi, DaemonState, SqliteBackend, daemon_router,
    sqlite_in_memory_store,
};
use axum::{
    Router,
    body::Body,
    http::{Request, StatusCode},
};
use tower::ServiceExt;

const ADMIN: &str = "oauth-admin-test";
const PRODUCT: &str = "product-directory-only";

fn fixture() -> (Router, awaken_iam_server::SqlStore<SqliteBackend>) {
    let store = sqlite_in_memory_store("oauth_client_http").expect("migrated store");
    let profiles: Arc<dyn AuthorizationProfileRepository> = Arc::new(store.clone());
    let state = DaemonState::with_policy_store(
        AuthzApi::new(),
        AdminAuthPolicy::new([ADMIN.to_owned()])
            .with_product_token(ProductId::new("design").unwrap(), PRODUCT),
        profiles,
        store.clone(),
        AuthApi::new().token_authority(),
    )
    .expect("daemon state");
    (daemon_router(Arc::new(Mutex::new(state))), store)
}

fn request(
    method: &str,
    path: &str,
    body: Option<serde_json::Value>,
    token: Option<&str>,
) -> Request<Body> {
    let mut builder = Request::builder().method(method).uri(path);
    if let Some(token) = token {
        builder = builder.header("authorization", format!("Bearer {token}"));
    }
    let body = if let Some(body) = body {
        builder = builder.header("content-type", "application/json");
        Body::from(body.to_string())
    } else {
        Body::empty()
    };
    builder.body(body).expect("request")
}

async fn json(response: axum::http::Response<Body>) -> serde_json::Value {
    let bytes = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .expect("body");
    serde_json::from_slice(&bytes).expect("json")
}

#[tokio::test]
async fn daemon_administers_one_confidential_product_client_without_exposing_its_hash() {
    // Cause/effect decision table: C1 absent admin credential => E1 401;
    // C2 product-only credential => E2 403; C3 unsafe redirect => E3 422;
    // C4 exact HTTPS redirect + admin => E4 one secret issued, hash persisted,
    // list/get redacted and audit recorded; C5 same id => E5 409 with old hash;
    // C6 rotate => E6 new secret/hash, same callback; C7 delete => E7 404 read.
    // Rules H1 C1=>E1, H2 C2=>E2, H3 C3=>E3, H4 C4=>E4,
    // H5 C4+C5=>E5, H6 C4+C6=>E6, H7 C4+C7=>E7.
    let (app, store) = fixture();
    let path = "/v1/admin/oauth-clients";
    let valid = serde_json::json!({
        "kind": "confidential", "client_id": "awaken-design",
        "redirect_uris": ["https://design.example/auth/callback"],
        "allowed_scopes": ["openid", "email", "profile"],
    });
    assert_eq!(
        app.clone()
            .oneshot(request("POST", path, Some(valid.clone()), None))
            .await
            .unwrap()
            .status(),
        StatusCode::UNAUTHORIZED,
        "H1"
    );
    assert_eq!(
        app.clone()
            .oneshot(request("POST", path, Some(valid.clone()), Some(PRODUCT)))
            .await
            .unwrap()
            .status(),
        StatusCode::FORBIDDEN,
        "H2"
    );
    let unsafe_body = serde_json::json!({
        "kind": "confidential", "client_id": "unsafe",
        "redirect_uris": ["http://foreign.example/callback"],
        "allowed_scopes": ["openid"],
    });
    assert_eq!(
        app.clone()
            .oneshot(request("POST", path, Some(unsafe_body), Some(ADMIN)))
            .await
            .unwrap()
            .status(),
        StatusCode::UNPROCESSABLE_ENTITY,
        "H3"
    );
    let response = app
        .clone()
        .oneshot(request("POST", path, Some(valid.clone()), Some(ADMIN)))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::CREATED, "H4");
    let created = json(response).await;
    let secret = created["client_secret"].as_str().expect("issued secret");
    assert!(secret.len() >= 40, "H4 entropy");
    let stored = OAuthClientRepository::get(&store, "awaken-design")
        .unwrap()
        .unwrap();
    assert_eq!(
        stored.secret_hash,
        Some(hash_session_token(secret)),
        "H4 hash only"
    );
    let get_path = format!("{path}/awaken-design");
    let view = json(
        app.clone()
            .oneshot(request("GET", &get_path, None, Some(ADMIN)))
            .await
            .unwrap(),
    )
    .await;
    assert_eq!(view["kind"], "confidential");
    assert!(
        view.get("client_secret").is_none() && view.get("secret_hash").is_none(),
        "H4 redaction"
    );
    let listed = json(
        app.clone()
            .oneshot(request("GET", path, None, Some(ADMIN)))
            .await
            .unwrap(),
    )
    .await;
    assert_eq!(listed["clients"].as_array().unwrap().len(), 1, "H4 list");
    assert_eq!(
        app.clone()
            .oneshot(request("POST", path, Some(valid), Some(ADMIN)))
            .await
            .unwrap()
            .status(),
        StatusCode::CONFLICT,
        "H5"
    );
    let rotated = json(
        app.clone()
            .oneshot(request(
                "POST",
                &format!("{get_path}/rotate-secret"),
                None,
                Some(ADMIN),
            ))
            .await
            .unwrap(),
    )
    .await;
    let new_secret = rotated["client_secret"].as_str().unwrap();
    assert_ne!(new_secret, secret, "H6");
    let stored = OAuthClientRepository::get(&store, "awaken-design")
        .unwrap()
        .unwrap();
    assert_eq!(
        stored.secret_hash,
        Some(hash_session_token(new_secret)),
        "H6"
    );
    assert_eq!(
        stored.redirect_uris,
        vec!["https://design.example/auth/callback"],
        "H6"
    );
    assert_eq!(
        app.clone()
            .oneshot(request("DELETE", &get_path, None, Some(ADMIN)))
            .await
            .unwrap()
            .status(),
        StatusCode::OK,
        "H7"
    );
    assert_eq!(
        app.clone()
            .oneshot(request("GET", &get_path, None, Some(ADMIN)))
            .await
            .unwrap()
            .status(),
        StatusCode::NOT_FOUND,
        "H7"
    );
    let audit = AuditSink::events(&store).unwrap();
    assert_eq!(
        audit
            .iter()
            .map(|event| event.action.as_str())
            .collect::<Vec<_>>(),
        [
            "oauth_client.register",
            "oauth_client.rotate_secret",
            "oauth_client.deregister"
        ]
    );
}

#[tokio::test]
async fn public_loopback_client_has_no_secret_to_issue_or_rotate() {
    // Decision rule P1: C1 admin registers a public loopback client => E1 one
    // PKCE-only registry row with no secret in the response; C2 rotation is
    // requested for that row => E2 reject without changing the client.
    let (app, store) = fixture();
    let path = "/v1/admin/oauth-clients";
    let body = serde_json::json!({
        "kind": "public", "client_id": "design-local",
        "redirect_uris": ["http://127.0.0.1:9234/callback"],
        "allowed_scopes": ["openid", "email"],
    });
    let created = app
        .clone()
        .oneshot(request("POST", path, Some(body), Some(ADMIN)))
        .await
        .unwrap();
    assert_eq!(created.status(), StatusCode::CREATED, "P1/E1");
    let view = json(created).await;
    assert_eq!(view["client"]["kind"], "public");
    assert!(view.get("client_secret").is_none(), "P1/E1");
    assert!(
        OAuthClientRepository::get(&store, "design-local")
            .unwrap()
            .unwrap()
            .secret_hash
            .is_none()
    );
    assert_eq!(
        app.clone()
            .oneshot(request(
                "POST",
                "/v1/admin/oauth-clients/design-local/rotate-secret",
                None,
                Some(ADMIN)
            ))
            .await
            .unwrap()
            .status(),
        StatusCode::UNPROCESSABLE_ENTITY,
        "P1/E2"
    );
}
