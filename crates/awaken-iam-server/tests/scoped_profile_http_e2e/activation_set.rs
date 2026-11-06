use super::*;

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn activation_set_rolls_back_all_heads_and_recovers_the_same_effect_across_replicas() {
    let store = sqlite_in_memory_store("scoped_http_activation_set").unwrap();
    seed(&store);
    let second_namespace = "tenant.z";
    for namespace in [NS, second_namespace] {
        for action in ["publish", "activate-set"] {
            grant(
                &store,
                "publisher",
                &format!("iam.authorization-profile.{action}:{namespace}"),
                workspace("w1"),
            );
        }
        grant(
            &store,
            "wrong-owner",
            &format!("iam.authorization-profile.activate-set:{namespace}"),
            workspace("w1"),
        );
    }
    let token = mint(&store, "publisher", "w1", true);
    let wrong_owner = mint(&store, "wrong-owner", "w1", true);
    let first = serve(store.clone()).await;
    let second = serve(store.clone()).await;
    let client = reqwest::Client::new();
    let publications = |namespace: &str| {
        format!("{first}/v1/scoped-authz/workspaces/w1/profiles/{namespace}/publications")
    };
    let activate =
        |base: &str| format!("{base}/v1/scoped-authz/workspaces/w1/activate-publication-set");
    let prepare = |namespace, key, head| {
        let endpoint = publications(namespace);
        let input = serde_json::to_value(command_for(namespace, key, head)).unwrap();
        let client = client.clone();
        let token = token.clone();
        async move {
            let (status, body) = post(&client, &endpoint, &token, input).await;
            assert_eq!(status, 200, "{body}");
            let receipt: ScopedAuthorizationProfileReceipt = serde_json::from_value(body).unwrap();
            assert_eq!(receipt.status, ScopedAuthorizationProfileStatus::Prepared);
            receipt.intent
        }
    };
    let a = prepare(NS, "original-a", None).await;
    let b = prepare(second_namespace, "original-b", None).await;
    let original = serde_json::json!({"intents":[a,b]});
    assert_eq!(
        post(&client, &activate(&first), &wrong_owner, original.clone())
            .await
            .0,
        403
    );
    let mut altered = original.clone();
    altered["intents"][1]["checksum"] = serde_json::json!("foreign");
    assert_eq!(
        post(&client, &activate(&first), &token, altered).await.0,
        409
    );
    let rival = prepare(second_namespace, "rival-b", None).await;
    let (status, body) = post(
        &client,
        &format!("{}/rival-b/activate", publications(second_namespace)),
        &token,
        serde_json::json!({}),
    )
    .await;
    assert_eq!(status, 200, "{body}");
    assert_eq!(
        post(&client, &activate(&second), &token, original).await.0,
        409
    );
    let head = |ns: &str| {
        store
            .active_profile(&NamespaceId(ns.into()))
            .unwrap()
            .map(|profile| profile.revision)
    };
    assert_eq!(
        head(NS),
        None,
        "the first native write must roll back with the second"
    );
    assert_eq!(head(second_namespace), Some(rival.revision));

    let b = prepare(second_namespace, "reviewed-b", Some(rival.revision)).await;
    let request = ActivateScopedAuthorizationProfiles {
        intents: vec![a.clone(), b.clone()],
    };
    let workspace = WorkspaceId("w1".into());
    let first_response = tokio::task::spawn_blocking({
        use awaken_iam_client::{HttpAuthzTransport, HttpTransportConfig, ScopedProfilePublisher};
        let (first, token, workspace, request) = (
            first.clone(),
            token.clone(),
            workspace.clone(),
            request.clone(),
        );
        move || {
            HttpAuthzTransport::new(HttpTransportConfig::new(first).with_service_token(token))
                .unwrap()
                .activate_scoped_profile_set(&workspace, &request)
                .unwrap()
        }
    })
    .await
    .unwrap();
    assert!(
        first_response
            .iter()
            .all(|receipt| receipt.status == ScopedAuthorizationProfileStatus::Active)
    );
    assert_eq!(head(NS), Some(a.revision));
    assert_eq!(head(second_namespace), Some(b.revision));
    let (status, replay) = post(
        &client,
        &activate(&second),
        &token,
        serde_json::to_value(request).unwrap(),
    )
    .await;
    assert_eq!(status, 200, "{replay}");
    assert_eq!(replay, serde_json::to_value(first_response).unwrap());
}
