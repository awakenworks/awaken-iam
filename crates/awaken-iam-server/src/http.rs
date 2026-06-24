//! Axum/hyper binding of the canonical `/v1` route manifest.
//!
//! [`assembly`](crate::assembly) emits a framework-agnostic [`RouteSpec`]
//! manifest; this module is the deployment that maps the authorization/
//! entitlement half of that manifest onto a real [`axum::Router`] and dispatches
//! each route to the matching [`AuthzApi`] method (see
//! [remote-protocol](../../../../docs/design/remote-protocol.md)). It is what the
//! standalone [`iam-daemon`](../bin/iam-daemon.rs) serves and what a remote
//! [`RemoteIamClient`](awaken_iam_client::RemoteIamClient) reaches over the wire.
//!
//! | Route | Method on [`AuthzApi`] |
//! |---|---|
//! | `POST /v1/authorize` | [`AuthzApi::authorize`] |
//! | `POST /v1/authorize/batch` | [`AuthzApi::authorize_batch`] |
//! | `POST /v1/entitlements/check` | [`AuthzApi::check_entitlement`] |
//! | `GET /v1/authz/snapshot` | [`AuthzApi::snapshot`] / [`AuthzApi::snapshot_since`] |
//!
//! Every served route reads the engines through a shared [`AuthzState`]; the
//! authorization plane never mutates per request, so the engines are shared
//! read-only across connections behind an [`Arc`]. The browser-facing
//! authentication half of the manifest ([`AuthApi`](crate::AuthApi)) is bound
//! separately and is not mounted here.
//!
//! [`RouteSpec`]: crate::RouteSpec

use std::sync::Arc;

use awaken_iam_contract::{
    AuthorizationOutcome, AuthorizationRequest, BatchAuthorizationRequest,
    BatchAuthorizationResponse, EntitlementCheckResponse, EntitlementRequest, PolicySnapshot,
};
use axum::{
    Json, Router,
    extract::{Query, State},
    http::StatusCode,
    response::{IntoResponse, Response},
    routing::{get, post},
};
use serde::Deserialize;

use crate::AuthzApi;

/// Shared, read-only handle to the authorization/entitlement engines every
/// `/v1` request is dispatched to.
///
/// The served routes are all reads, so one engine is shared across connections
/// behind an [`Arc`] rather than copied or locked per request.
pub type AuthzState = Arc<AuthzApi>;

/// Build the [`axum::Router`] that serves the authorization half of the `/v1`
/// manifest, plus an operational `GET /healthz` liveness probe.
///
/// The returned router is framework-complete: hand it to [`serve`] (or any
/// `axum::serve`) to answer `/v1` over hyper. Bodies are the
/// [`awaken_iam_contract`] DTOs as JSON; a malformed body is rejected by the
/// `Json` extractor as `400 Bad Request` before reaching the engine.
pub fn authz_router(state: AuthzState) -> Router {
    Router::new()
        .route("/healthz", get(healthz))
        .route("/v1/authorize", post(authorize))
        .route("/v1/authorize/batch", post(authorize_batch))
        .route("/v1/entitlements/check", post(check_entitlement))
        .route("/v1/authz/snapshot", get(snapshot))
        .with_state(state)
}

/// Serve `router` on an already-bound listener until the process is signalled
/// (SIGINT / Ctrl-C), then drain in-flight requests gracefully.
pub async fn serve(listener: tokio::net::TcpListener, router: Router) -> std::io::Result<()> {
    axum::serve(listener, router)
        .with_graceful_shutdown(shutdown_signal())
        .await
}

async fn shutdown_signal() {
    // A failure to install the handler should not keep the process alive forever;
    // treat it as an immediate shutdown request rather than panicking.
    let _ = tokio::signal::ctrl_c().await;
}

async fn healthz() -> Json<serde_json::Value> {
    Json(serde_json::json!({ "status": "ok" }))
}

/// `POST /v1/authorize`.
async fn authorize(
    State(api): State<AuthzState>,
    Json(request): Json<AuthorizationRequest>,
) -> Json<AuthorizationOutcome> {
    Json(api.authorize(&request))
}

/// `POST /v1/authorize/batch`.
async fn authorize_batch(
    State(api): State<AuthzState>,
    Json(request): Json<BatchAuthorizationRequest>,
) -> Json<BatchAuthorizationResponse> {
    Json(api.authorize_batch(&request))
}

/// `POST /v1/entitlements/check`.
async fn check_entitlement(
    State(api): State<AuthzState>,
    Json(request): Json<EntitlementRequest>,
) -> Json<EntitlementCheckResponse> {
    Json(api.check_entitlement(&request))
}

/// Query string for `GET /v1/authz/snapshot?since={version}`.
#[derive(Debug, Default, Deserialize)]
struct SnapshotQuery {
    /// Last policy version the caller already holds; the snapshot is skipped when
    /// the policy has not advanced past it.
    since: Option<u64>,
}

/// `GET /v1/authz/snapshot` — full snapshot, or a conditional fetch when `since`
/// is supplied (`304 Not Modified` while the policy is unchanged).
async fn snapshot(State(api): State<AuthzState>, Query(query): Query<SnapshotQuery>) -> Response {
    match query.since {
        Some(since) => match api.snapshot_since(since) {
            Some(snapshot) => Json(snapshot).into_response(),
            None => StatusCode::NOT_MODIFIED.into_response(),
        },
        None => Json::<PolicySnapshot>(api.snapshot()).into_response(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{HttpMethod, RouteSpec};
    use awaken_iam_contract::{AuthorizationDecision, EntitlementDecision, PrincipalRef, ScopeRef};
    use awaken_iam_core::{ActionPattern, Effect, Grant, GrantId, GrantSubject};
    use axum::body::Body;
    use axum::http::{Request, StatusCode};
    use tower::ServiceExt;

    fn service(id: &str) -> PrincipalRef {
        PrincipalRef::Service {
            service_id: id.into(),
        }
    }

    fn allow_grant(action: &str) -> Grant {
        Grant {
            id: GrantId("g1".into()),
            subject: GrantSubject::Principal(service("svc")),
            action_pattern: ActionPattern(action.into()),
            scope: ScopeRef::Global,
            effect: Effect::Allow,
        }
    }

    async fn body_json(response: Response) -> serde_json::Value {
        let bytes = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .expect("read body");
        serde_json::from_slice(&bytes).expect("decode json")
    }

    fn post(path: &str, body: serde_json::Value) -> Request<Body> {
        Request::builder()
            .method("POST")
            .uri(path)
            .header("content-type", "application/json")
            .body(Body::from(body.to_string()))
            .expect("build request")
    }

    #[tokio::test]
    async fn authorize_route_reports_the_engine_decision() {
        let mut api = AuthzApi::new();
        api.policy_mut().add_grant(allow_grant("pack.publish"));
        let router = authz_router(Arc::new(api));

        let request = serde_json::json!({
            "principal": { "kind": "service", "service_id": "svc" },
            "on_behalf_of": [],
            "action": "pack.publish",
            "scope": { "kind": "global" }
        });
        let response = router
            .oneshot(post("/v1/authorize", request))
            .await
            .expect("dispatch");
        assert_eq!(response.status(), StatusCode::OK);
        let outcome: AuthorizationOutcome =
            serde_json::from_value(body_json(response).await).expect("outcome");
        assert_eq!(outcome.decision, AuthorizationDecision::Allow);
        assert_eq!(outcome.matched_grants, vec!["g1".to_owned()]);
    }

    #[tokio::test]
    async fn authorize_route_fails_closed_to_default_deny() {
        let router = authz_router(Arc::new(AuthzApi::new()));
        let request = serde_json::json!({
            "principal": { "kind": "service", "service_id": "svc" },
            "on_behalf_of": [],
            "action": "pack.publish",
            "scope": { "kind": "global" }
        });
        let response = router
            .oneshot(post("/v1/authorize", request))
            .await
            .expect("dispatch");
        let outcome: AuthorizationOutcome =
            serde_json::from_value(body_json(response).await).expect("outcome");
        assert_eq!(outcome.decision, AuthorizationDecision::Deny);
        assert_eq!(outcome.reason, "default_deny");
    }

    #[tokio::test]
    async fn batch_route_preserves_request_order() {
        let mut api = AuthzApi::new();
        api.policy_mut().add_grant(allow_grant("pack.read"));
        let router = authz_router(Arc::new(api));

        let req = |action: &str| {
            serde_json::json!({
                "principal": { "kind": "service", "service_id": "svc" },
                "on_behalf_of": [],
                "action": action,
                "scope": { "kind": "global" }
            })
        };
        let body = serde_json::json!({ "requests": [req("pack.read"), req("pack.delete")] });
        let response = router
            .oneshot(post("/v1/authorize/batch", body))
            .await
            .expect("dispatch");
        let decoded: BatchAuthorizationResponse =
            serde_json::from_value(body_json(response).await).expect("batch");
        assert_eq!(decoded.outcomes.len(), 2);
        assert_eq!(decoded.outcomes[0].decision, AuthorizationDecision::Allow);
        assert_eq!(decoded.outcomes[1].decision, AuthorizationDecision::Deny);
    }

    #[tokio::test]
    async fn entitlement_route_evaluates_live() {
        let router = authz_router(Arc::new(AuthzApi::new()));
        let body = serde_json::json!({
            "principal": { "kind": "service", "service_id": "svc" },
            "entitlement": "pack.read",
            "resource": null
        });
        let response = router
            .oneshot(post("/v1/entitlements/check", body))
            .await
            .expect("dispatch");
        let decoded: EntitlementCheckResponse =
            serde_json::from_value(body_json(response).await).expect("entitlement");
        // The v1 engine is default-allow.
        assert_eq!(decoded.decision, EntitlementDecision::Allow);
    }

    #[tokio::test]
    async fn snapshot_route_serves_and_conditionally_skips() {
        let mut api = AuthzApi::new();
        api.policy_mut().add_grant(allow_grant("pack.*"));
        let version = api.policy_version();
        let router = authz_router(Arc::new(api));

        // Full fetch returns the current snapshot.
        let full = router
            .clone()
            .oneshot(
                Request::builder()
                    .uri("/v1/authz/snapshot")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .expect("dispatch");
        assert_eq!(full.status(), StatusCode::OK);
        let snapshot: PolicySnapshot =
            serde_json::from_value(body_json(full).await).expect("snapshot");
        assert_eq!(snapshot.version, version);
        assert_eq!(snapshot.grants.len(), 1);

        // A caller already at the current version is told nothing changed.
        let unchanged = router
            .oneshot(
                Request::builder()
                    .uri(format!("/v1/authz/snapshot?since={version}"))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .expect("dispatch");
        assert_eq!(unchanged.status(), StatusCode::NOT_MODIFIED);
    }

    #[tokio::test]
    async fn malformed_body_is_rejected_before_the_engine() {
        let router = authz_router(Arc::new(AuthzApi::new()));
        let response = router
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/v1/authorize")
                    .header("content-type", "application/json")
                    .body(Body::from("not json"))
                    .unwrap(),
            )
            .await
            .expect("dispatch");
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn healthz_reports_ok() {
        let router = authz_router(Arc::new(AuthzApi::new()));
        let response = router
            .oneshot(
                Request::builder()
                    .uri("/healthz")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .expect("dispatch");
        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(body_json(response).await["status"], "ok");
    }

    /// The router binds every authorization route the assembly's manifest
    /// declares: the manifest and the served surface stay in lockstep.
    #[tokio::test]
    async fn router_binds_every_authz_manifest_route() {
        let router = authz_router(Arc::new(AuthzApi::new()));
        let authz_routes = [
            RouteSpec {
                method: HttpMethod::Post,
                path: "/v1/authorize",
            },
            RouteSpec {
                method: HttpMethod::Post,
                path: "/v1/authorize/batch",
            },
            RouteSpec {
                method: HttpMethod::Post,
                path: "/v1/entitlements/check",
            },
            RouteSpec {
                method: HttpMethod::Get,
                path: "/v1/authz/snapshot",
            },
        ];
        for spec in authz_routes {
            let builder = Request::builder().uri(spec.path);
            let request = match spec.method {
                HttpMethod::Get => builder.method("GET").body(Body::empty()),
                HttpMethod::Post => builder
                    .method("POST")
                    .header("content-type", "application/json")
                    .body(Body::from("{}")),
                HttpMethod::Put => builder
                    .method("PUT")
                    .header("content-type", "application/json")
                    .body(Body::from("{}")),
                HttpMethod::Delete => builder.method("DELETE").body(Body::empty()),
            }
            .unwrap();
            let status = router
                .clone()
                .oneshot(request)
                .await
                .expect("dispatch")
                .status();
            // A bound route never answers 404/405; it reaches a handler (which may
            // still reject a deliberately empty body as 400/422).
            assert_ne!(status, StatusCode::NOT_FOUND, "unbound route {}", spec.path);
            assert_ne!(
                status,
                StatusCode::METHOD_NOT_ALLOWED,
                "wrong method for {}",
                spec.path
            );
        }
    }
}
