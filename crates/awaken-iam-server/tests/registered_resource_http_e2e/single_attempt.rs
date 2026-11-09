use super::*;
use std::sync::atomic::{AtomicUsize, Ordering};
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn strict_current_evaluation_preserves_first_native_fault_even_with_default_retries() {
    let store = sqlite_in_memory_store("strict_one_attempt").unwrap();
    seed(&store);
    store
        .register_product_resource_model(&ProductResourceModelRequest {
            product_id: question().product_id,
            resource_model: document().resource_model,
        })
        .unwrap();
    publish(&store, document());
    store.apply_resource_projection(&projection()).unwrap();
    let state = Arc::new(Mutex::new(
        DaemonState::with_policy_store(
            AuthzApi::new(),
            AdminAuthPolicy::deny_all(),
            Arc::new(store.clone()),
            store,
            AuthApi::new().token_authority(),
        )
        .unwrap(),
    ));
    let requests = Arc::new(AtomicUsize::new(0));
    let observed = requests.clone();
    let router = daemon_router(state.clone())
        .merge(projection_router(state))
        .layer(axum::middleware::from_fn(
            move |request: axum::extract::Request, next: axum::middleware::Next| {
                let observed = observed.clone();
                async move {
                    if observed.fetch_add(1, Ordering::SeqCst) == 0 {
                        use axum::response::IntoResponse;
                        axum::http::StatusCode::SERVICE_UNAVAILABLE.into_response()
                    } else {
                        next.run(request).await
                    }
                }
            },
        ));
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let handle = tokio::spawn(async move {
        http::serve(listener, router).await.unwrap();
    });
    let requests_in_client = requests.clone();
    let (first, healthy, count_after_fault) = tokio::task::spawn_blocking(move || {
        use awaken_iam_client::{HttpAuthzTransport, HttpTransportConfig, RemoteIamClient};
        // Intentionally retain the constructor's default two extra retries.
        let client = RemoteIamClient::new(
            HttpAuthzTransport::new(HttpTransportConfig::new(format!("http://{address}"))).unwrap(),
        );
        let first = client.authorize_registered_resource(&question());
        let count = requests_in_client.load(Ordering::SeqCst);
        let healthy = client.authorize_registered_resource(&question());
        (first, healthy, count)
    })
    .await
    .unwrap();
    handle.abort();
    let _ = handle.await;
    assert_eq!(
        first.unwrap_err().status(),
        Some(503),
        "the first fault is not replaced by a subsequent Allow"
    );
    assert_eq!(count_after_fault, 1, "no automatic second evaluation");
    assert_eq!(
        healthy.unwrap().evaluation.outcome.decision,
        AuthorizationDecision::Allow,
        "explicit new request uses the real healthy native PDP"
    );
    assert_eq!(requests.load(Ordering::SeqCst), 2);
}
