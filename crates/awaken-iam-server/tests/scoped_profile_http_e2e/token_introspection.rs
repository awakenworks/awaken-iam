//! Current credential rows, independent of a replica's startup token directory.
use super::*;

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn api_token_introspection_uses_current_native_rows_across_replicas() {
    let store = sqlite_in_memory_store("current_token_introspection").unwrap();
    seed(&store);
    let first = serve(store.clone()).await;
    let second = serve(store.clone()).await;
    // The key is issued after both replicas started. Neither may rely on a
    // startup-only token directory or an authentication snapshot.
    let secret = mint(&store, "late-key", "w1", true);
    let client = reqwest::Client::new();
    let wrong_secret = format!("{}.wrong", secret.split_once('.').unwrap().0);
    for base in [&first, &second] {
        let response = client
            .post(format!("{base}/v1/tokens/introspect"))
            .json(&TokenIntrospectionRequest {
                token: secret.clone(),
            })
            .send()
            .await
            .unwrap();
        assert_eq!(response.status(), 200);
        let identity = response.json::<TokenIntrospectionResponse>().await.unwrap();
        assert_eq!(identity.principal, service("late-key"));
        assert_eq!(identity.workspace, WorkspaceId("w1".into()));
        assert_eq!(identity.status, ApiTokenStatus::Active);
        for token in ["malformed", wrong_secret.as_str()] {
            let response = client
                .post(format!("{base}/v1/tokens/introspect"))
                .json(&TokenIntrospectionRequest {
                    token: token.into(),
                })
                .send()
                .await
                .unwrap();
            assert_eq!(response.status(), 401);
        }
    }
    let mut row = ApiTokenRepository::get(&store, &ApiTokenId("late-key".into()))
        .unwrap()
        .unwrap();
    row.revoked_at = Some(at());
    ApiTokenRepository::update(&store, row).unwrap();
    for base in [&first, &second] {
        let response = client
            .post(format!("{base}/v1/tokens/introspect"))
            .json(&TokenIntrospectionRequest {
                token: secret.clone(),
            })
            .send()
            .await
            .unwrap();
        assert_eq!(
            response.status(),
            401,
            "revocation must be current without a policy-cache marker"
        );
    }
    let expired = mint(&store, "expired-key", "w2", false);
    let mut row = ApiTokenRepository::get(&store, &ApiTokenId("expired-key".into()))
        .unwrap()
        .unwrap();
    row.expires_at = Some(Timestamp("2000-01-01T00:00:00Z".into()));
    ApiTokenRepository::update(&store, row).unwrap();
    for base in [&first, &second] {
        let response = client
            .post(format!("{base}/v1/tokens/introspect"))
            .json(&TokenIntrospectionRequest {
                token: expired.clone(),
            })
            .send()
            .await
            .unwrap();
        assert_eq!(response.status(), 401);
        let response = client
            .post(format!("{base}/v1/tokens/introspect"))
            .json(&TokenIntrospectionRequest {
                token: "x".repeat(1024),
            })
            .send()
            .await
            .unwrap();
        assert_eq!(response.status(), 413);
    }
}
