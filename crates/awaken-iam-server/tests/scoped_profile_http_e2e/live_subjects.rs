use super::*;

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn account_membership_and_group_ownership_are_live_activation_gates() {
    use awaken_iam_core::{AccountRepository, RoleBinding, RoleBindingRepository};
    let store = sqlite_in_memory_store("scoped_http_subjects").unwrap();
    seed(&store);
    grant(
        &store,
        "publisher",
        &format!("iam.authorization-profile.publish:{NS}"),
        workspace("w1"),
    );
    let token = mint(&store, "publisher", "w1", true);
    let account = PrincipalRef::Account {
        account_id: AccountId("alice".into()),
    };
    AccountRepository::upsert(
        &store,
        Account {
            id: AccountId("alice".into()),
            status: AccountStatus::Active,
            display_name: None,
            created_at: at(),
            updated_at: at(),
        },
    )
    .unwrap();
    let member = RoleBinding {
        principal: account.clone(),
        role: RoleId("member".into()),
        scope: ScopeRef::Org {
            org_id: OrgId("o1".into()),
        },
    };
    let base = serve(store.clone()).await;
    let client = reqwest::Client::new();
    let mut request = command("member", None);
    request.profile.document.grants[0].subject = GrantSubjectRef::Principal { principal: account };
    assert_eq!(
        post(
            &client,
            &path(&base, ""),
            &token,
            serde_json::to_value(&request).unwrap()
        )
        .await
        .0,
        403,
        "existing Account alone grants no Org membership"
    );
    RoleBindingRepository::add(&store, member.clone()).unwrap();
    // Restart after fixture seed writes. Production PAP writes advance the
    // shared policy fence, as the two-replica recovery test proves.
    let base = serve(store.clone()).await;
    let (status, body) = post(
        &client,
        &path(&base, ""),
        &token,
        serde_json::to_value(&request).unwrap(),
    )
    .await;
    assert_eq!(status, 200, "{body}");
    RoleBindingRepository::remove(&store, &member).unwrap();
    let (status, body) = post(
        &client,
        &path(&base, "/member/activate"),
        &token,
        serde_json::json!({}),
    )
    .await;
    assert_eq!(status, 403, "membership removed after prepare: {body}");
    // Recovery finds the original draft and never recreates membership.
    assert_eq!(
        post(
            &client,
            &path(&base, ""),
            &token,
            serde_json::to_value(request).unwrap()
        )
        .await
        .0,
        200
    );
    assert!(
        store
            .active_profile(&NamespaceId(NS.into()))
            .unwrap()
            .is_none()
    );
    let group = Group {
        id: GroupId("local".into()),
        org: OrgId("o1".into()),
        display_name: None,
        members: vec![],
        created_at: at(),
        updated_at: at(),
    };
    GroupRepository::upsert(&store, group.clone()).unwrap();
    let mut request = command("group", None);
    request.profile.document.grants[0].subject = GrantSubjectRef::Group {
        group_id: "local".into(),
    };
    let (status, body) = post(
        &client,
        &path(&base, ""),
        &token,
        serde_json::to_value(request).unwrap(),
    )
    .await;
    assert_eq!(status, 200, "{body}");
    GroupRepository::upsert(
        &store,
        Group {
            org: OrgId("o2".into()),
            ..group
        },
    )
    .unwrap();
    let (status, body) = post(
        &client,
        &path(&base, "/group/activate"),
        &token,
        serde_json::json!({}),
    )
    .await;
    assert_eq!(status, 403, "Group moved after prepare: {body}");
    assert!(
        store
            .active_profile(&NamespaceId(NS.into()))
            .unwrap()
            .is_none()
    );
}
