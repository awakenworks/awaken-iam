use super::*;
async fn every_parent<B: SqlConn + Clone + 'static>(store: SqlStore<B>, prefix: &str) {
    seed(&store);
    let mut model = document().resource_model;
    model.resource_types.push(ResourceTypeRegistration {
        resource_type: ResourceType("awaken.folder".into()),
        parent_type: None,
        actions: vec![],
    });
    store
        .register_product_resource_model(&ProductResourceModelRequest {
            product_id: question().product_id,
            resource_model: model,
        })
        .unwrap();
    publish(&store, document());
    let mut parent = projection();
    parent.projection_id = "folder:original".into();
    parent.idempotency_key = "folder:1".into();
    parent.scope_edges[0].resource_type = ResourceType("awaken.folder".into());
    parent.scope_edges[0].resource_id = ResourceId("parent".into());
    store.apply_resource_projection(&parent).unwrap();
    let mut child = projection();
    child.scope_edges[0].parent = ScopeRef::Resource {
        resource_type: ResourceType("awaken.folder".into()),
        resource_id: ResourceId("parent".into()),
    };
    store.apply_resource_projection(&child).unwrap();
    let (base, handle) = serve(store.clone()).await;
    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(5))
        .build()
        .unwrap();
    assert_eq!(
        strict(&client, &base, &question())
            .await
            .evaluation
            .outcome
            .decision,
        AuthorizationDecision::Allow
    );
    // A real fixture fault removes only the ancestor's ownership record. Its
    // ordinary graph edge and this leaf's owned stream still exist. Neither
    // legacy ancestry nor the leaf's valid receipt may stand in for the parent.
    let before = store.fence().unwrap();
    assert_eq!(store.backend().execute(&format!("DELETE FROM {prefix}_resource_projection_edge_owners WHERE resource_type=? AND resource_id=?"),&[Some("awaken.folder".into()),Some("parent".into())]).unwrap(),1);
    assert_eq!(
        legacy(&client, &base).await.decision,
        AuthorizationDecision::Allow,
        "ordinary edges and exact legacy grant remain; they are not strict registration"
    );
    let result = strict(&client, &base, &question()).await;
    assert_eq!(
        result.evaluation.outcome.decision,
        AuthorizationDecision::Deny
    );
    assert!(result.registration.is_none());
    assert_eq!(
        store.fence().unwrap(),
        before,
        "no cached registration lease and no evaluation write"
    );
    handle.abort();
    let _ = handle.await;
}
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn sqlite_every_resource_ancestor_needs_current_versioned_product_ownership() {
    every_parent(
        sqlite_in_memory_store("strict_parent_sqlite").unwrap(),
        "strict_parent_sqlite",
    )
    .await;
}
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn postgres_every_resource_ancestor_needs_current_versioned_product_ownership() {
    let Ok(url) = std::env::var("IAM_TEST_POSTGRES_URL") else {
        assert!(
            std::env::var_os("AWAKEN_TEST_REQUIRE_POSTGRES").is_none(),
            "required PostgreSQL fixture missing"
        );
        return;
    };
    let prefix = format!(
        "strict_parent_{:x}",
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    );
    every_parent(
        awaken_iam_server::postgres_migrated_store(&url, &prefix).unwrap(),
        &prefix,
    )
    .await;
}
