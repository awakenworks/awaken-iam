use super::*;
use awaken_iam_core::{AccountRepository, RoleBinding, RoleBindingRepository};

fn account(store: &Store, id: &str, org: &str) -> PrincipalRef {
    let principal = PrincipalRef::Account {
        account_id: AccountId(id.into()),
    };
    AccountRepository::upsert(
        store,
        Account {
            id: AccountId(id.into()),
            status: AccountStatus::Active,
            display_name: None,
            created_at: at(),
            updated_at: at(),
        },
    )
    .unwrap();
    RoleBindingRepository::add(
        store,
        RoleBinding {
            principal: principal.clone(),
            role: RoleId("member".into()),
            scope: ScopeRef::Org {
                org_id: OrgId(org.into()),
            },
        },
    )
    .unwrap();
    principal
}
fn request(principal: PrincipalRef, namespace: &str) -> ResourceAuthorizationRequest {
    ResourceAuthorizationRequest {
        request: AuthorizationRequest::direct(
            principal,
            ActionKey(format!("{namespace}::read")),
            workspace("w1"),
        ),
        context: AuthorizationContext::default(),
    }
}
async fn decision(
    client: &reqwest::Client,
    base: &str,
    request: &ResourceAuthorizationRequest,
) -> AuthorizationDecision {
    client
        .post(format!("{base}/v1/authorize/resource"))
        .json(request)
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
async fn scoped_decisions_keep_current_groups_accounts_scope_and_native_effect_ceilings() {
    let store = sqlite_in_memory_store("scoped_current_groups").unwrap();
    seed(&store);
    let alice = account(&store, "alice", "o1");
    let carol = account(&store, "carol", "o1");
    let bob = account(&store, "bob", "o2");
    let group = Group {
        id: GroupId("current".into()),
        org: OrgId("o1".into()),
        display_name: None,
        members: vec![
            alice.clone(),
            carol.clone(),
            bob.clone(),
            service("unrelated"),
        ],
        created_at: at(),
        updated_at: at(),
    };
    GroupRepository::upsert(&store, group.clone()).unwrap();
    for principal in [&alice, &bob] {
        GrantRepository::put(
            &store,
            Grant {
                id: GrantId(format!("root:{principal:?}")),
                subject: GrantSubject::Principal(principal.clone()),
                action_pattern: ActionPattern("*".into()),
                scope: ScopeRef::Global,
                effect: Effect::Allow,
            },
        )
        .unwrap();
    }
    // A Workspace role alone cannot establish current Org membership.
    RoleBindingRepository::add(
        &store,
        RoleBinding {
            principal: bob.clone(),
            role: RoleId("owner".into()),
            scope: workspace("w1"),
        },
    )
    .unwrap();
    grant(
        &store,
        "publisher",
        &format!("iam.authorization-profile.publish:{NS}"),
        workspace("w1"),
    );
    let token = mint(&store, "publisher", "w1", true);
    let base = serve(store.clone()).await;
    let client = reqwest::Client::new();
    let mut publication = command("current-group", None);
    publication.profile.document.grants[0].subject = GrantSubjectRef::Group {
        group_id: "current".into(),
    };
    assert_eq!(
        post(
            &client,
            &path(&base, ""),
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
            &path(&base, "/current-group/activate"),
            &token,
            serde_json::json!({})
        )
        .await
        .0,
        200
    );
    let a = request(alice.clone(), NS);
    let c = request(carol.clone(), NS);
    assert_eq!(
        decision(&client, &base, &a).await,
        AuthorizationDecision::Allow
    );
    assert_eq!(
        decision(&client, &base, &request(bob, NS)).await,
        AuthorizationDecision::Deny
    );
    assert_eq!(
        decision(&client, &base, &request(service("unrelated"), NS)).await,
        AuthorizationDecision::Deny
    );
    let mut foreign = a.clone();
    foreign.request.scope = workspace("w2");
    assert_eq!(
        decision(&client, &base, &foreign).await,
        AuthorizationDecision::Deny
    );
    GroupRepository::upsert(
        &store,
        Group {
            members: vec![carol],
            ..group.clone()
        },
    )
    .unwrap();
    assert_eq!(
        decision(&client, &base, &a).await,
        AuthorizationDecision::Deny
    );
    assert_eq!(
        decision(&client, &base, &c).await,
        AuthorizationDecision::Allow
    );
    GroupRepository::upsert(&store, group.clone()).unwrap();
    AccountRepository::upsert(
        &store,
        Account {
            id: AccountId("alice".into()),
            status: AccountStatus::Disabled,
            display_name: None,
            created_at: at(),
            updated_at: at(),
        },
    )
    .unwrap();
    assert_eq!(
        decision(&client, &base, &a).await,
        AuthorizationDecision::Deny
    );
    assert_eq!(
        decision(&client, &base, &c).await,
        AuthorizationDecision::Allow
    );
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
    GroupRepository::upsert(
        &store,
        Group {
            org: OrgId("o2".into()),
            ..group.clone()
        },
    )
    .unwrap();
    assert_eq!(
        decision(&client, &base, &a).await,
        AuthorizationDecision::Deny
    );
    GroupRepository::upsert(&store, group).unwrap();
    for effect in [GrantEffect::RequireApproval, GrantEffect::Deny] {
        let ceiling = GrantSnapshot {
            id: "operator-ceiling".into(),
            subject: GrantSubjectRef::Principal {
                principal: alice.clone(),
            },
            action_pattern: "*".into(),
            scope: ScopeRef::Global,
            effect,
        };
        assert_eq!(
            post(
                &client,
                &format!("{base}/v1/admin/grants"),
                "admin-key",
                serde_json::to_value(ceiling).unwrap()
            )
            .await
            .0,
            200
        );
        assert_eq!(
            decision(&client, &base, &a).await,
            match effect {
                GrantEffect::Deny => AuthorizationDecision::Deny,
                _ => AuthorizationDecision::RequireApproval,
            }
        );
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn explicit_scoped_native_client_never_falls_back_before_publication_or_after_retirement() {
    let store = sqlite_in_memory_store("scoped_no_fallback").unwrap();
    seed(&store);
    let alice = account(&store, "alice", "o1");
    GrantRepository::put(
        &store,
        Grant {
            id: GrantId("root".into()),
            subject: GrantSubject::Principal(alice.clone()),
            action_pattern: ActionPattern("*".into()),
            scope: ScopeRef::Global,
            effect: Effect::Allow,
        },
    )
    .unwrap();
    grant(
        &store,
        "publisher",
        &format!("iam.authorization-profile.publish:{NS}"),
        workspace("w1"),
    );
    let token = mint(&store, "publisher", "w1", true);
    let base = serve(store.clone()).await;
    let client = reqwest::Client::new();
    let native_base = base.clone();
    let original = request(alice.clone(), NS);
    let native_request = original.clone();
    tokio::task::spawn_blocking(move || {
        use awaken_iam_client::{HttpAuthzTransport, HttpTransportConfig, ScopedProfileConsumer};
        let client = HttpAuthzTransport::new(HttpTransportConfig::new(native_base)).unwrap();
        assert_eq!(
            client
                .authorize_scoped_resource(
                    &WorkspaceId("w1".into()),
                    &NamespaceId(NS.into()),
                    &native_request
                )
                .unwrap()
                .decision,
            AuthorizationDecision::Deny
        );
    })
    .await
    .unwrap();
    let mut publication = command("retire", None);
    publication.profile.document.grants[0].subject =
        GrantSubjectRef::Principal { principal: alice };
    assert_eq!(
        post(
            &client,
            &path(&base, ""),
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
            &path(&base, "/retire/activate"),
            &token,
            serde_json::json!({})
        )
        .await
        .0,
        200
    );
    assert_eq!(
        decision(&client, &base, &original).await,
        AuthorizationDecision::Allow
    );
    let native_base = base.clone();
    let native_request = original.clone();
    tokio::task::spawn_blocking(move || {
        use awaken_iam_client::{HttpAuthzTransport, HttpTransportConfig, ScopedProfileConsumer};
        let client = HttpAuthzTransport::new(HttpTransportConfig::new(native_base)).unwrap();
        for (workspace, namespace, expected) in [
            ("w1", NS, AuthorizationDecision::Allow),
            ("w2", NS, AuthorizationDecision::Deny),
            ("w1", "tenant.other", AuthorizationDecision::Deny),
        ] {
            assert_eq!(
                client
                    .authorize_scoped_resource(
                        &WorkspaceId(workspace.into()),
                        &NamespaceId(namespace.into()),
                        &native_request
                    )
                    .unwrap()
                    .decision,
                expected
            );
        }
    })
    .await
    .unwrap();
    let unsupported = serve_with_scoped_admission(store, false).await;
    assert_eq!(
        client
            .post(format!("{unsupported}/v1/authorize/resource"))
            .json(&original)
            .send()
            .await
            .unwrap()
            .status(),
        503
    );
    assert_eq!(
        post(
            &client,
            &format!("{base}/v1/admin/authz/profiles/{NS}/retire"),
            "admin-key",
            serde_json::json!({"expected_active_revision":1})
        )
        .await
        .0,
        200
    );
    assert_eq!(
        decision(&client, &base, &original).await,
        AuthorizationDecision::Deny
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn scoped_decisions_preserve_native_relationship_and_field_constraints() {
    let store = sqlite_in_memory_store("scoped_current_constraints").unwrap();
    seed(&store);
    let alice = account(&store, "alice", "o1");
    grant(
        &store,
        "publisher",
        &format!("iam.authorization-profile.publish:{NS}"),
        workspace("w1"),
    );
    let token = mint(&store, "publisher", "w1", true);
    let base = serve(store).await;
    let client = reqwest::Client::new();
    let mut publication = command("constraints", None);
    publication.profile.document.grants[0].subject = GrantSubjectRef::Principal {
        principal: alice.clone(),
    };
    publication
        .profile
        .document
        .grant_constraints
        .push(GrantConstraint {
            grant_id: format!("{NS}:read"),
            data_scope: AuthorizationDataScope::Owner,
            readable_fields: Some(vec!["title".into()]),
            writable_fields: None,
            amount_range: None,
            prohibit_initiator: false,
        });
    assert_eq!(
        post(
            &client,
            &path(&base, ""),
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
            &path(&base, "/constraints/activate"),
            &token,
            serde_json::json!({})
        )
        .await
        .0,
        200
    );
    let mut read = request(alice.clone(), NS);
    read.context.access = AuthorizationAccess::Read;
    read.context.fields = Some(vec!["title".into()]);
    assert_eq!(
        decision(&client, &base, &read).await,
        AuthorizationDecision::Deny,
        "missing owner cannot become Allow"
    );
    read.context.owner = Some(alice);
    assert_eq!(
        decision(&client, &base, &read).await,
        AuthorizationDecision::Allow
    );
    read.context.fields = Some(vec!["secret".into()]);
    assert_eq!(
        decision(&client, &base, &read).await,
        AuthorizationDecision::Deny
    );
    read.context.fields = Some(vec!["title".into()]);
    read.context.owner = Some(service("publisher"));
    assert_eq!(
        decision(&client, &base, &read).await,
        AuthorizationDecision::Deny
    );
}
