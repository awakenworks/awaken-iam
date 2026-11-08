//! Constructor-owned transport contract. The native authorization router
//! supplies its real Deny after a selected transient fault; no Allow, person or
//! authority receipt is fabricated. This is transport evidence, not product PEP.
use super::*;
use awaken_iam_client::IamClient;
use awaken_iam_contract::{
    AccountId, ActionKey, AuthorizationDecision, AuthorizationRequest, PrincipalRef, ScopeRef,
};
use awaken_iam_server::{AuthApi, AuthzApi, http::authz_router, jwks_router};
use axum::{
    extract::Request,
    http::StatusCode,
    middleware::Next,
    response::{IntoResponse, Response},
};
use std::sync::{
    Arc,
    atomic::{AtomicBool, AtomicUsize, Ordering},
};

#[derive(Default)]
struct Fault {
    armed: AtomicBool,
    calls: AtomicUsize,
}
async fn intercept(request: Request, next: Next, fault: Arc<Fault>) -> Response {
    if request.uri().path() == "/v1/authorize" {
        fault.calls.fetch_add(1, Ordering::SeqCst);
        if fault.armed.swap(false, Ordering::SeqCst) {
            return StatusCode::SERVICE_UNAVAILABLE.into_response();
        }
    }
    next.run(request).await
}
fn request() -> AuthorizationRequest {
    AuthorizationRequest::direct(
        PrincipalRef::Account {
            account_id: AccountId("ungranted-person".into()),
        },
        ActionKey("qualification.read".into()),
        ScopeRef::Global,
    )
}
#[test]
fn current_remote_constructor_preserves_one_failed_observation_and_old_retry_behavior() {
    // R1 single attempt: one actual HTTP503 -> Unavailable, not a later decision.
    // R2 explicit new request after recovery -> real native Deny.
    // R3 legacy constructor: same transient -> second HTTP request/native Deny.
    let runtime = tokio::runtime::Runtime::new().unwrap();
    let fault = Arc::new(Fault::default());
    let (url, task) = runtime.block_on(async {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let url = format!("http://{}", listener.local_addr().unwrap());
        let app = authz_router(Arc::new(AuthzApi::new()))
            .merge(jwks_router(Arc::new(tokio::sync::Mutex::new(
                AuthApi::new(),
            ))))
            .layer(axum::middleware::from_fn({
                let fault = fault.clone();
                move |request, next| intercept(request, next, fault.clone())
            }));
        (
            url,
            tokio::spawn(async move {
                axum::serve(listener, app).await.unwrap();
            }),
        )
    });
    let config = HostConfig::remote(url);
    let current = connect_remote_single_attempt(&config).unwrap();
    fault.armed.store(true, Ordering::SeqCst);
    assert!(IamClient::authorize_result(&current.gate, request()).is_err());
    assert_eq!(fault.calls.load(Ordering::SeqCst), 1);
    assert_eq!(
        IamClient::authorize_result(&current.gate, request()).unwrap(),
        AuthorizationDecision::Deny
    );
    assert_eq!(fault.calls.load(Ordering::SeqCst), 2);
    let legacy = connect_remote(&config).unwrap();
    fault.armed.store(true, Ordering::SeqCst);
    assert_eq!(
        IamClient::authorize_result(&legacy.gate, request()).unwrap(),
        AuthorizationDecision::Deny
    );
    assert_eq!(fault.calls.load(Ordering::SeqCst), 4);
    task.abort();
}
