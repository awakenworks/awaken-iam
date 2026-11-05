use super::*;

async fn plain_and_batch(
    client: &reqwest::Client,
    base: &str,
    request: &AuthorizationRequest,
) -> [AuthorizationDecision; 2] {
    let direct: AuthorizationOutcome = client
        .post(format!("{base}/v1/authorize"))
        .json(request)
        .send()
        .await
        .unwrap()
        .error_for_status()
        .unwrap()
        .json()
        .await
        .unwrap();
    let batch: BatchAuthorizationResponse = client
        .post(format!("{base}/v1/authorize/batch"))
        .json(&BatchAuthorizationRequest {
            requests: vec![request.clone()],
        })
        .send()
        .await
        .unwrap()
        .error_for_status()
        .unwrap()
        .json()
        .await
        .unwrap();
    [direct.decision, batch.outcomes[0].decision]
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn active_scoped_account_grant_loses_permission_on_current_membership_revocation() {
    use awaken_iam_core::{AccountRepository, RoleBinding, RoleBindingRepository};
    let store = sqlite_in_memory_store("scoped_current_membership").unwrap();
    seed(&store);
    grant(
        &store,
        "publisher",
        &format!("iam.authorization-profile.publish:{NS}"),
        workspace("w1"),
    );
    let token = mint(&store, "publisher", "w1", true);
    let alice = PrincipalRef::Account {
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
    let membership = RoleBinding {
        principal: alice.clone(),
        role: RoleId("member".into()),
        scope: ScopeRef::Org {
            org_id: OrgId("o1".into()),
        },
    };
    RoleBindingRepository::add(&store, membership.clone()).unwrap();
    let first = serve(store.clone()).await;
    let second = serve(store.clone()).await;
    let client = reqwest::Client::new();
    let mut publication = command("current", None);
    publication.profile.document.grants[0].subject = GrantSubjectRef::Principal {
        principal: alice.clone(),
    };
    assert_eq!(
        post(
            &client,
            &path(&first, ""),
            &token,
            serde_json::to_value(publication).unwrap()
        )
        .await
        .0,
        200
    );
    assert_eq!(
        post(
            &client,
            &path(&first, "/current/activate"),
            &token,
            serde_json::json!({})
        )
        .await
        .0,
        200
    );
    let request = ResourceAuthorizationRequest {
        request: AuthorizationRequest::direct(
            alice,
            ActionKey(format!("{NS}::read")),
            workspace("w1"),
        ),
        context: AuthorizationContext::default(),
    };
    for base in [&first, &second] {
        let result: AuthorizationOutcome = client
            .post(format!("{base}/v1/authorize/resource"))
            .json(&request)
            .send()
            .await
            .unwrap()
            .error_for_status()
            .unwrap()
            .json()
            .await
            .unwrap();
        assert_eq!(result.decision, AuthorizationDecision::Allow);
        assert_eq!(
            plain_and_batch(&client, base, &request.request).await,
            [AuthorizationDecision::Allow; 2]
        );
    }
    assert_eq!(
        client
            .delete(format!("{first}/v1/admin/memberships"))
            .bearer_auth("admin-key")
            .json(&RoleBindingSnapshot {
                principal: membership.principal.clone(),
                role_id: membership.role.0.clone(),
                scope: membership.scope.clone()
            })
            .send()
            .await
            .unwrap()
            .status(),
        200
    );
    for base in [&first, &second] {
        let result: AuthorizationOutcome = client
            .post(format!("{base}/v1/authorize/resource"))
            .json(&request)
            .send()
            .await
            .unwrap()
            .error_for_status()
            .unwrap()
            .json()
            .await
            .unwrap();
        assert_eq!(
            result.decision,
            AuthorizationDecision::Deny,
            "an immutable profile grant must not manufacture current Org membership on {base}"
        );
        assert_eq!(
            plain_and_batch(&client, base, &request.request).await,
            [AuthorizationDecision::Deny; 2]
        );
    }
}

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
    let child_only = RoleBinding {
        principal: member.principal.clone(),
        role: RoleId("workspace-owner".into()),
        scope: workspace("w1"),
    };
    RoleBindingRepository::add(&store, child_only.clone()).unwrap();
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
        "a Workspace role is not native Org membership"
    );
    RoleBindingRepository::remove(&store, &child_only).unwrap();
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
