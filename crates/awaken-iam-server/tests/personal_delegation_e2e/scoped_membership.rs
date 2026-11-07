//! Compound consent must use the same current scoped admission as ordinary PDP.
use super::*;
use awaken_iam_core::{
    OrgRepository, Organization, ResourceModelRepository, RoleBinding, RoleBindingRepository,
    RoleId,
};

#[tokio::test]
async fn scoped_consent_cannot_restore_revoked_membership_or_skip_its_admission_port() {
    let store = Arc::new(sqlite_in_memory_store("scoped_personal_membership").unwrap());
    let at = Timestamp("2026-11-05T00:00:00Z".into());
    let human = PrincipalRef::Account {
        account_id: AccountId("ada".into()),
    };
    let service = PrincipalRef::Service {
        service_id: "business-service".into(),
    };
    AccountRepository::upsert(
        &*store,
        Account {
            id: AccountId("ada".into()),
            status: AccountStatus::Active,
            display_name: None,
            created_at: at.clone(),
            updated_at: at.clone(),
        },
    )
    .unwrap();
    OrgRepository::upsert(
        &*store,
        Organization {
            id: OrgId("org".into()),
            display_name: None,
            owner: human.clone(),
            created_at: at.clone(),
            updated_at: at.clone(),
        },
    )
    .unwrap();
    ResourceModelRepository::put_workspace_org(
        &*store,
        WorkspaceOrgEdge {
            workspace_id: WorkspaceId("w".into()),
            org_id: OrgId("org".into()),
        },
    )
    .unwrap();
    let member = RoleBinding {
        principal: human.clone(),
        role: RoleId("member".into()),
        scope: ScopeRef::Org {
            org_id: OrgId("org".into()),
        },
    };
    RoleBindingRepository::add(&*store, member.clone()).unwrap();
    let mut policy = PolicyAdminApi::new((*store).clone());
    let namespace = NamespaceId("operations.business".into());
    let mut document = AuthorizationProfileDocument::default();
    document
        .resource_model
        .actions
        .push(ActionKey(ACTION.into()));
    document.action_scope_rules.push(ActionScopeRule {
        action_pattern: ACTION.into(),
        allowed_scope_kinds: vec![ScopeKind::Project],
    });
    for (id, principal) in [("human", human), ("service", service)] {
        policy
            .issue_grant(
                Grant {
                    id: GrantId(id.into()),
                    subject: GrantSubject::Principal(principal.clone()),
                    action_pattern: ActionPattern("*".into()),
                    scope: ScopeRef::Global,
                    effect: Effect::Allow,
                },
                at.clone(),
            )
            .unwrap();
        document.grants.push(GrantSnapshot {
            id: format!("operations.business:{id}"),
            subject: GrantSubjectRef::Principal { principal },
            action_pattern: ACTION.into(),
            scope: scope(),
            effect: GrantEffect::Allow,
        });
    }
    let profiles = AuthorizationProfileAdmin::new(store.clone());
    profiles
        .prepare_scoped_publication(
            PrepareScopedAuthorizationProfile {
                request_key: "scoped-consent".into(),
                workspace_id: WorkspaceId("w".into()),
                profile: CreateAuthorizationProfile {
                    namespace: namespace.clone(),
                    document,
                    created_at: at.clone(),
                },
                expected_active_revision: None,
            },
            PrincipalRef::Service {
                service_id: "publisher".into(),
            },
        )
        .unwrap();
    let base = policy
        .policy()
        .unwrap()
        .snapshot(policy.store_version().unwrap());
    profiles
        .activate_scoped_publication(&mut AuthzApi::new(), &base, &namespace, "scoped-consent")
        .unwrap();
    let client = RegisteredClient::confidential(
        "business",
        "test-recipient-secret",
        vec!["https://business.example/cb".into()],
        [PERSONAL_DELEGATION_CLIENT_SCOPE],
    )
    .with_token_exchange(ClientTokenExchangePolicy {
        audiences: Default::default(),
        delegation: Some(ClientDelegation {
            service_id: "business-service".into(),
            audiences: ["flow".into()].into(),
            subject_audiences: Default::default(),
        }),
    });
    OAuthClientRepository::upsert(&*store, client).unwrap();
    store.create_personal_delegation(record()).unwrap();
    let auth = Arc::new(tokio::sync::Mutex::new(
        AuthApi::new()
            .with_issuer(ISSUER)
            .with_identity_repositories(store.clone(), store.clone(), store.clone())
            .with_oauth_repositories(store.clone(), store.clone()),
    ));
    let signer = auth.lock().await.token_authority();
    let app = |scoped| {
        let daemon = Arc::new(Mutex::new(
            DaemonState::with_policy_store(
                AuthzApi::new(),
                AdminAuthPolicy::deny_all(),
                store.clone(),
                (*store).clone(),
                signer.clone(),
            )
            .unwrap(),
        ));
        let app =
            personal_delegation_router(auth.clone(), daemon.clone(), store.clone(), ISSUER.into());
        if scoped {
            app.merge(scoped_profile_router(daemon))
        } else {
            app
        }
    };
    let first = app(true);
    let second = app(true);
    let no_port = app(false);
    let binding = MintPersonalDelegationToken {
        grant_id: "consent-1".into(),
        action: ActionKey(ACTION.into()),
        scope: scope(),
        target: Some(PersonalDelegationTarget {
            id: "native-task".into(),
            revision: 4,
        }),
        purpose: PersonalDelegationPurpose::Execute,
        original_key: None,
    };
    let (status, token) = call(
        &first,
        None,
        "POST",
        "/v1/personal-delegations/token",
        json!({"client_id":"business","client_secret":"test-recipient-secret","binding":binding}),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    let request = json!({"token":token["access_token"],"audience":"flow","target":binding.target,
        "request":{"request":{"principal":{"kind":"service","service_id":"business-service"},"on_behalf_of":[{"kind":"account","account_id":"ada"}],"action":ACTION,"scope":scope()},"context":{}}});
    for replica in [&first, &second] {
        let (status, outcome) = call(
            replica,
            None,
            "POST",
            "/v1/authorize/personal-delegation",
            request.clone(),
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(outcome["decision"], "allow");
    }
    RoleBindingRepository::remove(&*store, &member).unwrap();
    for replica in [&first, &second] {
        let (status, outcome) = call(
            replica,
            None,
            "POST",
            "/v1/authorize/personal-delegation",
            request.clone(),
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(
            outcome["decision"], "deny",
            "immutable profile and current consent cannot recreate Org membership"
        );
    }
    // A valid signed consent cannot substitute for the native scoped port.
    assert_eq!(
        call(
            &no_port,
            None,
            "POST",
            "/v1/authorize/personal-delegation",
            request.clone()
        )
        .await
        .0,
        StatusCode::SERVICE_UNAVAILABLE
    );
}
