//! Runtime service references remain bounded by the original native role owner.
use super::*;
use awaken_iam_core::{RoleBinding, RoleBindingRepository};

fn controller_binding() -> RoleBinding {
    RoleBinding {
        principal: service("awaken-flow-resource-controller"),
        role: RoleId(format!("{NS}:bundle:controller")),
        scope: workspace("w1"),
    }
}

fn controller_command(key: &str, head: Option<u64>) -> PrepareScopedAuthorizationProfile {
    let binding = controller_binding();
    let mut command = command(key, head);
    let document = &mut command.profile.document;
    document.grants[0].subject = GrantSubjectRef::Role {
        role_id: binding.role.0.clone(),
    };
    document.permission_bundles.push(PermissionBundleMetadata {
        role_id: binding.role.0.clone(),
        key: "controller".into(),
        name: "Native settlement".into(),
        owner_scope: workspace("w1"),
        source_id: "flow-controller".into(),
        source_revision: "1".into(),
        source_digest: format!("sha256:{}", "7".repeat(64)),
    });
    document.role_bindings.push(RoleBindingSnapshot {
        principal: binding.principal.clone(),
        role_id: binding.role.0.clone(),
        scope: binding.scope.clone(),
    });
    document.binding_limits.push(RoleBindingLimit {
        subject: GrantSubjectRef::Principal {
            principal: binding.principal,
        },
        role_id: binding.role.0,
        scope: binding.scope,
        expires_at: None,
        resource_ids: None,
    });
    command
}

async fn decision(client: &reqwest::Client, base: &str) -> AuthorizationDecision {
    decision_for(
        client,
        base,
        service("awaken-flow-resource-controller"),
        "read",
    )
    .await
}

fn request_for(principal: PrincipalRef, action: &str) -> ResourceAuthorizationRequest {
    ResourceAuthorizationRequest {
        request: AuthorizationRequest::direct(
            principal,
            ActionKey(format!("{NS}::{action}")),
            workspace("w1"),
        ),
        context: Default::default(),
    }
}

async fn decision_for(
    client: &reqwest::Client,
    base: &str,
    principal: PrincipalRef,
    action: &str,
) -> AuthorizationDecision {
    client
        .post(format!("{base}/v1/authorize/resource"))
        .json(&request_for(principal, action))
        .send()
        .await
        .unwrap()
        .error_for_status()
        .unwrap()
        .json::<AuthorizationOutcome>()
        .await
        .unwrap()
        .decision
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn runtime_role_reference_uses_current_native_binding_and_loses_it_on_both_replicas() {
    // C1 a distinct publisher cannot impersonate the runtime; C2 the original
    // native role owner has approved this exact service/role/scope; C3 removal
    // follows activation without a policy-version bump. E1 publish works only
    // under C2; E2 both replicas deny after C3 despite the immutable profile.
    let store = sqlite_in_memory_store("scoped_controller_reference").unwrap();
    seed(&store);
    grant(
        &store,
        "publisher",
        &format!("iam.authorization-profile.publish:{NS}"),
        workspace("w1"),
    );
    let token = mint(&store, "publisher", "w1", true);
    let binding = controller_binding();
    RoleBindingRepository::add(&store, binding.clone()).unwrap();
    let first = serve(store.clone()).await;
    let second = serve(store.clone()).await;
    let client = reqwest::Client::new();
    let original = controller_command("controller", None);
    let (status, body) = post(
        &client,
        &path(&first, ""),
        &token,
        serde_json::to_value(&original).unwrap(),
    )
    .await;
    assert_eq!(
        status, 200,
        "an exact independently provisioned runtime binding: {body}"
    );
    let (status, body) = post(
        &client,
        &path(&first, "/controller/activate"),
        &token,
        serde_json::json!({}),
    )
    .await;
    assert_eq!(status, 200, "{body}");
    for base in [&first, &second] {
        assert_eq!(decision(&client, base).await, AuthorizationDecision::Allow);
    }
    RoleBindingRepository::remove(&store, &binding).unwrap();
    for base in [&first, &second] {
        assert_eq!(decision(&client, base).await, AuthorizationDecision::Deny);
    }
    let (status, _) = post(
        &client,
        &path(&first, ""),
        &token,
        serde_json::to_value(controller_command("changed", Some(1))).unwrap(),
    )
    .await;
    assert_eq!(
        status, 403,
        "publication cannot restore a removed runtime reference"
    );
    assert!(
        RoleBindingRepository::list_for_principal(&store, &binding.principal)
            .unwrap()
            .is_empty()
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn unrelated_runtime_role_or_scope_never_supplies_a_publication_reference() {
    for variant in 0..5 {
        let store = sqlite_in_memory_store(&format!("scoped_reference_wrong_{variant}")).unwrap();
        seed(&store);
        grant(
            &store,
            "publisher",
            &format!("iam.authorization-profile.publish:{NS}"),
            workspace("w1"),
        );
        let token = mint(&store, "publisher", "w1", true);
        let mut binding = controller_binding();
        match variant {
            0 => binding.role = RoleId("another-role".into()),
            1 => binding.scope = workspace("w2"),
            2 => binding.principal = service("another-controller"),
            3 => binding.scope = ScopeRef::Global,
            _ => {
                binding.scope = ScopeRef::Org {
                    org_id: OrgId("o1".into()),
                }
            }
        }
        RoleBindingRepository::add(&store, binding).unwrap();
        let base = serve(store.clone()).await;
        let client = reqwest::Client::new();
        let (status, _) = post(
            &client,
            &path(&base, ""),
            &token,
            serde_json::to_value(controller_command("wrong", None)).unwrap(),
        )
        .await;
        assert_eq!(status, 403);
        assert!(
            store
                .list_profiles(&NamespaceId(NS.into()))
                .unwrap()
                .is_empty()
        );
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn revoked_runtime_reference_blocks_activation_but_preserves_original_draft() {
    let store = sqlite_in_memory_store("scoped_reference_activation").unwrap();
    seed(&store);
    grant(
        &store,
        "publisher",
        &format!("iam.authorization-profile.publish:{NS}"),
        workspace("w1"),
    );
    let token = mint(&store, "publisher", "w1", true);
    let binding = controller_binding();
    RoleBindingRepository::add(&store, binding.clone()).unwrap();
    let base = serve(store.clone()).await;
    let client = reqwest::Client::new();
    let original = controller_command("before-revoke", None);
    assert_eq!(
        post(
            &client,
            &path(&base, ""),
            &token,
            serde_json::to_value(&original).unwrap()
        )
        .await
        .0,
        200
    );
    RoleBindingRepository::remove(&store, &binding).unwrap();
    assert_eq!(
        post(
            &client,
            &path(&base, "/before-revoke/activate"),
            &token,
            serde_json::json!({})
        )
        .await
        .0,
        403
    );
    assert!(
        store
            .active_profile(&NamespaceId(NS.into()))
            .unwrap()
            .is_none()
    );
    assert_eq!(
        post(
            &client,
            &path(&base, ""),
            &token,
            serde_json::to_value(&original).unwrap()
        )
        .await
        .0,
        200
    );
    assert_eq!(
        store.list_profiles(&NamespaceId(NS.into())).unwrap().len(),
        1
    );
    assert!(
        RoleBindingRepository::list_for_principal(&store, &binding.principal)
            .unwrap()
            .is_empty()
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn company_group_cannot_supply_another_runtime_role_while_accounts_keep_their_group() {
    use awaken_iam_core::AccountRepository;
    let store = sqlite_in_memory_store("scoped_reference_groups").unwrap();
    seed(&store);
    grant(
        &store,
        "publisher",
        &format!("iam.authorization-profile.publish:{NS}"),
        workspace("w1"),
    );
    let token = mint(&store, "publisher", "w1", true);
    let binding = controller_binding();
    RoleBindingRepository::add(&store, binding.clone()).unwrap();
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
    RoleBindingRepository::add(
        &store,
        RoleBinding {
            principal: alice.clone(),
            role: RoleId("member".into()),
            scope: ScopeRef::Org {
                org_id: OrgId("o1".into()),
            },
        },
    )
    .unwrap();
    GroupRepository::upsert(
        &store,
        Group {
            id: GroupId("company".into()),
            org: OrgId("o1".into()),
            display_name: None,
            members: vec![alice.clone(), binding.principal.clone()],
            created_at: at(),
            updated_at: at(),
        },
    )
    .unwrap();
    let mut original = controller_command("group", None);
    let document = &mut original.profile.document;
    let role = format!("{NS}:bundle:employee");
    let action = format!("{NS}::employee-read");
    document
        .resource_model
        .actions
        .push(ActionKey(action.clone()));
    document.action_scope_rules.push(ActionScopeRule {
        action_pattern: action.clone(),
        allowed_scope_kinds: vec![ScopeKind::Workspace],
    });
    document.grants.push(GrantSnapshot {
        id: format!("{NS}:employee-read"),
        subject: GrantSubjectRef::Role {
            role_id: role.clone(),
        },
        action_pattern: action,
        scope: workspace("w1"),
        effect: GrantEffect::Allow,
    });
    let mut bundle = document.permission_bundles[0].clone();
    bundle.role_id = role.clone();
    bundle.key = "employee".into();
    document.permission_bundles.push(bundle);
    document.group_role_bindings.push(GroupRoleBindingSnapshot {
        group_id: "company".into(),
        role_id: role,
        scope: workspace("w1"),
    });
    let base = serve(store.clone()).await;
    let client = reqwest::Client::new();
    let (status, body) = post(
        &client,
        &path(&base, ""),
        &token,
        serde_json::to_value(&original).unwrap(),
    )
    .await;
    assert_eq!(status, 200, "{body}");
    assert_eq!(
        post(
            &client,
            &path(&base, "/group/activate"),
            &token,
            serde_json::json!({})
        )
        .await
        .0,
        200
    );
    assert_eq!(decision(&client, &base).await, AuthorizationDecision::Allow);
    assert_eq!(
        decision_for(&client, &base, binding.principal.clone(), "employee-read").await,
        AuthorizationDecision::Deny
    );
    assert_eq!(
        decision_for(&client, &base, alice, "employee-read").await,
        AuthorizationDecision::Allow
    );
    RoleBindingRepository::remove(&store, &binding).unwrap();
    assert_eq!(decision(&client, &base).await, AuthorizationDecision::Deny);
    assert_eq!(
        store
            .active_profile(&NamespaceId(NS.into()))
            .unwrap()
            .unwrap()
            .document,
        original.profile.document
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn unavailable_original_runtime_role_source_returns_no_cached_allow() {
    use awaken_iam_server::SqlConn;
    let backend = SqliteBackend::open_in_memory().unwrap();
    let store =
        awaken_iam_server::sqlite_migrated_store(backend.clone(), "reference_unavailable").unwrap();
    seed(&store);
    grant(
        &store,
        "publisher",
        &format!("iam.authorization-profile.publish:{NS}"),
        workspace("w1"),
    );
    let token = mint(&store, "publisher", "w1", true);
    let binding = controller_binding();
    RoleBindingRepository::add(&store, binding.clone()).unwrap();
    let base = serve(store).await;
    let client = reqwest::Client::new();
    assert_eq!(
        post(
            &client,
            &path(&base, ""),
            &token,
            serde_json::to_value(controller_command("unavailable", None)).unwrap()
        )
        .await
        .0,
        200
    );
    assert_eq!(
        post(
            &client,
            &path(&base, "/unavailable/activate"),
            &token,
            serde_json::json!({})
        )
        .await
        .0,
        200
    );
    assert_eq!(decision(&client, &base).await, AuthorizationDecision::Allow);
    backend
        .execute(
            "ALTER TABLE reference_unavailable_role_bindings RENAME TO unavailable_role_source",
            &[],
        )
        .unwrap();
    let response = client
        .post(format!("{base}/v1/authorize/resource"))
        .json(&request_for(binding.principal, "read"))
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), 503);
    assert_eq!(
        response.json::<serde_json::Value>().await.unwrap()["error"],
        "policy_unavailable"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn revoking_one_runtime_role_removes_only_that_role_from_the_native_evaluator() {
    let store = sqlite_in_memory_store("scoped_reference_partial_revoke").unwrap();
    seed(&store);
    grant(
        &store,
        "publisher",
        &format!("iam.authorization-profile.publish:{NS}"),
        workspace("w1"),
    );
    let token = mint(&store, "publisher", "w1", true);
    let first = controller_binding();
    let mut second = first.clone();
    second.role = RoleId(format!("{NS}:bundle:secondary"));
    RoleBindingRepository::add(&store, first.clone()).unwrap();
    RoleBindingRepository::add(&store, second.clone()).unwrap();
    let mut original = controller_command("two-roles", None);
    let document = &mut original.profile.document;
    let action = format!("{NS}::secondary-read");
    document
        .resource_model
        .actions
        .push(ActionKey(action.clone()));
    document.action_scope_rules.push(ActionScopeRule {
        action_pattern: action.clone(),
        allowed_scope_kinds: vec![ScopeKind::Workspace],
    });
    document.grants.push(GrantSnapshot {
        id: format!("{NS}:secondary-read"),
        subject: GrantSubjectRef::Role {
            role_id: second.role.0.clone(),
        },
        action_pattern: action,
        scope: workspace("w1"),
        effect: GrantEffect::Allow,
    });
    let mut bundle = document.permission_bundles[0].clone();
    bundle.role_id = second.role.0.clone();
    bundle.key = "secondary".into();
    document.permission_bundles.push(bundle);
    document.role_bindings.push(RoleBindingSnapshot {
        principal: second.principal.clone(),
        role_id: second.role.0.clone(),
        scope: second.scope.clone(),
    });
    let base = serve(store.clone()).await;
    let client = reqwest::Client::new();
    let (status, body) = post(
        &client,
        &path(&base, ""),
        &token,
        serde_json::to_value(&original).unwrap(),
    )
    .await;
    assert_eq!(status, 200, "{body}");
    assert_eq!(
        post(
            &client,
            &path(&base, "/two-roles/activate"),
            &token,
            serde_json::json!({})
        )
        .await
        .0,
        200
    );
    assert_eq!(decision(&client, &base).await, AuthorizationDecision::Allow);
    assert_eq!(
        decision_for(&client, &base, second.principal.clone(), "secondary-read").await,
        AuthorizationDecision::Allow
    );
    RoleBindingRepository::remove(&store, &second).unwrap();
    assert_eq!(decision(&client, &base).await, AuthorizationDecision::Allow);
    assert_eq!(
        decision_for(&client, &base, second.principal, "secondary-read").await,
        AuthorizationDecision::Deny
    );
    assert_eq!(
        store
            .active_profile(&NamespaceId(NS.into()))
            .unwrap()
            .unwrap()
            .document,
        original.profile.document
    );
}
