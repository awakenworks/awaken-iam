use super::*;

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn group_sources_reobserve_exact_same_org_groups_without_disclosing_rosters() {
    let store = sqlite_in_memory_store("scoped_http_group_sources").unwrap();
    seed(&store);
    let action = format!("iam.authorization-profile.observe-groups:{NS}");
    grant(&store, "reader", &action, workspace("w1"));
    grant(&store, "other", &action, workspace("w1"));
    let reader = mint(&store, "reader", "w1", true);
    let other = mint(&store, "other", "w2", true);
    let mut a = Group {
        id: GroupId("awaken.flow:team-a".into()),
        org: OrgId("o1".into()),
        display_name: None,
        members: Vec::new(),
        created_at: at(),
        updated_at: at(),
    };
    let b = Group {
        id: GroupId("awaken.flow:team-b".into()),
        org: OrgId("o2".into()),
        ..a.clone()
    };
    GroupRepository::upsert(&store, a.clone()).unwrap();
    GroupRepository::upsert(&store, b).unwrap();
    let base = serve(store.clone()).await;
    let client = reqwest::Client::new();
    let url = format!("{base}/v1/scoped-authz/workspaces/w1/profiles/{NS}/source-groups");
    let requested = serde_json::json!({"group_ids":[a.id.0]});
    let (status, first) = post(&client, &url, &reader, requested.clone()).await;
    assert_eq!(status, 200, "{first}");
    let first: ScopedProfileGroupSources = serde_json::from_value(first).unwrap();
    assert_eq!(first.org_id, OrgId("o1".into()));
    assert_eq!(first.workspace_id, WorkspaceId("w1".into()));
    assert_eq!(first.namespace, NamespaceId(NS.into()));
    assert_eq!(first.revisions.len(), 1);
    assert_eq!(post(&client, &url, &other, requested.clone()).await.0, 403);
    let (status, body) = post(
        &client,
        &url,
        &reader,
        serde_json::json!({"group_ids":[a.id.0,"awaken.flow:team-b"]}),
    )
    .await;
    assert_eq!(status, 403, "{body}");
    assert!(body.get("revisions").is_none());
    a.members.push(PrincipalRef::Account {
        account_id: AccountId("tenant-private-account".into()),
    });
    GroupRepository::upsert(&store, a.clone()).unwrap();
    let (status, current) = post(&client, &url, &reader, requested).await;
    assert_eq!(status, 200, "{current}");
    assert!(!current.to_string().contains("tenant-private-account"));
    let current: ScopedProfileGroupSources = serde_json::from_value(current).unwrap();
    assert_ne!(
        first.revisions.get(&a.id.0).unwrap(),
        current.revisions.get(&a.id.0).unwrap()
    );
}
