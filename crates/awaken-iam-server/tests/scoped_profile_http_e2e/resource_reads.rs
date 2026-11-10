//! Real native SQLite/HTTP, exact service capability and shared PDP oracle.
use super::*;
use awaken_iam_core::{AccountRepository, RoleBinding, RoleBindingRepository};

fn alice(store: &Store) -> PrincipalRef {
    let principal = PrincipalRef::Account {
        account_id: AccountId("reader-alice".into()),
    };
    AccountRepository::upsert(
        store,
        Account {
            id: AccountId("reader-alice".into()),
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
                org_id: OrgId("o1".into()),
            },
        },
    )
    .unwrap();
    principal
}
fn read_path(base: &str, suffix: &str) -> String {
    format!("{base}/v1/scoped-authz/workspaces/w1/profiles/{NS}/{suffix}")
}
fn resource(principal: PrincipalRef, owner: PrincipalRef) -> ResourceAuthorizationRequest {
    ResourceAuthorizationRequest {
        request: AuthorizationRequest::direct(
            principal,
            ActionKey(format!("{NS}::read")),
            workspace("w1"),
        ),
        context: AuthorizationContext {
            owner: Some(owner),
            resource_id: Some("retained-resource".into()),
            resource_type: Some("document".into()),
            access: AuthorizationAccess::Read,
            fields: Some(vec!["label".into()]),
            ..Default::default()
        },
    }
}
async fn setup(name: &str) -> (Store, String, String, PrincipalRef) {
    let store = sqlite_in_memory_store(name).unwrap();
    seed(&store);
    let alice = alice(&store);
    GroupRepository::upsert(
        &store,
        Group {
            id: GroupId("candidate-team".into()),
            org: OrgId("o1".into()),
            display_name: None,
            members: vec![alice.clone()],
            created_at: at(),
            updated_at: at(),
        },
    )
    .unwrap();
    for operation in ["publish", "read"] {
        grant(
            &store,
            "publisher",
            &format!("iam.authorization-profile.{operation}:{NS}"),
            workspace("w1"),
        );
    }
    let token = mint(&store, "publisher", "w1", true);
    let base = serve(store.clone()).await;
    let client = reqwest::Client::new();
    let mut publication = command("resource-read-slice", None);
    let document = &mut publication.profile.document;
    document.action_scope_rules[0]
        .allowed_scope_kinds
        .push(ScopeKind::Project);
    document.grants[0].subject = GrantSubjectRef::Group {
        group_id: "candidate-team".into(),
    };
    document.grant_constraints.push(GrantConstraint {
        grant_id: document.grants[0].id.clone(),
        data_scope: AuthorizationDataScope::Owner,
        readable_fields: None,
        writable_fields: None,
        amount_range: None,
        prohibit_initiator: false,
    });
    document.grants.push(GrantSnapshot {
        id: format!("{NS}:service-read"),
        subject: GrantSubjectRef::Principal {
            principal: service("publisher"),
        },
        action_pattern: format!("{NS}::read"),
        scope: workspace("w1"),
        effect: GrantEffect::Allow,
    });
    let result = post(
        &client,
        &path(&base, ""),
        &token,
        serde_json::to_value(publication).unwrap(),
    )
    .await;
    assert_eq!(result.0, 200, "{}", result.1);
    let result = post(
        &client,
        &path(&base, "/resource-read-slice/activate"),
        &token,
        serde_json::json!({}),
    )
    .await;
    assert_eq!(result.0, 200, "{}", result.1);
    (store, base, token, alice)
}
fn candidate(request: &ResourceAuthorizationRequest) -> ResourceCandidateRequest {
    ResourceCandidateRequest {
        mode: ResourceAuthorizationMode::Scoped,
        request: request.request.clone(),
        resource_type: request.context.resource_type.clone(),
        access: AuthorizationAccess::Read,
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn contextual_batch_preserves_exact_single_pdp_order_freshness_and_real_sparse_plan() {
    let (_store, base, token, alice) = setup("candidate_batch_oracle").await;
    let client = reqwest::Client::new();
    let owned = resource(alice.clone(), alice.clone());
    let foreign = resource(alice.clone(), service("another-owner"));
    let mut project_owned = owned.clone();
    project_owned.request.scope = ScopeRef::Project {
        workspace_id: WorkspaceId("w1".into()),
        project_id: ProjectId("p".into()),
    };
    let batch = ResourceAuthorizationBatchRequest {
        mode: ResourceAuthorizationMode::Scoped,
        requests: vec![owned.clone(), foreign, project_owned],
    };
    let response = client
        .post(read_path(&base, "authorize-resources"))
        .bearer_auth(&token)
        .json(&batch)
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), 200);
    let header = response
        .headers()
        .get(AUTHORIZATION_FRESHNESS_HEADER)
        .unwrap()
        .to_str()
        .unwrap()
        .to_owned();
    let result = response
        .json::<ResourceAuthorizationBatchEvaluation>()
        .await
        .unwrap();
    assert_eq!(header, result.freshness);
    assert_eq!(
        result
            .outcomes
            .iter()
            .map(|outcome| outcome.decision)
            .collect::<Vec<_>>(),
        [
            AuthorizationDecision::Allow,
            AuthorizationDecision::Deny,
            AuthorizationDecision::Allow
        ]
    );
    for (request, outcome) in batch.requests.iter().zip(&result.outcomes) {
        let response = client
            .post(read_path(&base, "authorize"))
            .json(request)
            .send()
            .await
            .unwrap();
        assert_eq!(
            response
                .headers()
                .get(AUTHORIZATION_FRESHNESS_HEADER)
                .unwrap(),
            header.as_str()
        );
        assert_eq!(
            &response.json::<AuthorizationOutcome>().await.unwrap(),
            outcome
        );
    }
    let response = client
        .post(read_path(&base, "resource-candidates"))
        .bearer_auth(&token)
        .json(&candidate(&owned))
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), 200);
    let plan = response
        .json::<ResourceCandidateEvaluation>()
        .await
        .unwrap();
    assert_eq!(
        plan.plan.predicate,
        ResourceCandidatePredicate::OwnerIn {
            principals: vec![alice]
        }
    );
    assert_eq!(plan.freshness, result.freshness);
    // Exercise the production blocking SDK, not an in-test transport replica.
    tokio::task::spawn_blocking(move || {
        use awaken_iam_client::{HttpAuthzTransport, HttpTransportConfig, ScopedProfileConsumer};
        let sdk = HttpAuthzTransport::new(HttpTransportConfig::new(base).with_service_token(token))
            .unwrap();
        let batch_result = sdk
            .authorize_scoped_resources_evaluation(
                &WorkspaceId("w1".into()),
                &NamespaceId(NS.into()),
                &batch,
            )
            .unwrap();
        assert_eq!(batch_result, result);
        let candidate_result = sdk
            .scoped_resource_candidates(
                &WorkspaceId("w1".into()),
                &NamespaceId(NS.into()),
                &candidate(&owned),
            )
            .unwrap();
        assert_eq!(candidate_result, plan);
    })
    .await
    .unwrap();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn owner_candidates_stay_sparse_with_field_amount_and_initiator_limits_while_native_pdp_refuses_them()
 {
    let (_store, base, token, alice) = setup("candidate_conjunctive_limits").await;
    let client = reqwest::Client::new();
    let mut publication = command("conjunctive-limits", Some(1));
    let grant = &mut publication.profile.document.grants[0];
    grant.subject = GrantSubjectRef::Group {
        group_id: "candidate-team".into(),
    };
    publication
        .profile
        .document
        .grant_constraints
        .push(GrantConstraint {
            grant_id: grant.id.clone(),
            data_scope: AuthorizationDataScope::Owner,
            readable_fields: Some(vec!["name".into(), "amount".into()]),
            writable_fields: None,
            amount_range: Some(AuthorizationAmountRange {
                currency: "CNY".into(),
                minimum: Some(1),
                maximum: Some(1000),
            }),
            prohibit_initiator: true,
        });
    let prepared = post(
        &client,
        &path(&base, ""),
        &token,
        serde_json::to_value(publication).unwrap(),
    )
    .await;
    assert_eq!(prepared.0, 200, "{}", prepared.1);
    let activated = post(
        &client,
        &path(&base, "/conjunctive-limits/activate"),
        &token,
        serde_json::json!({}),
    )
    .await;
    assert_eq!(activated.0, 200, "{}", activated.1);
    let mut owned = resource(alice.clone(), alice.clone());
    owned.context.fields = Some(vec!["name".into(), "amount".into()]);
    owned.context.amount = Some(AuthorizationAmount {
        currency: "CNY".into(),
        minor_units: 100,
    });
    owned.context.initiator = Some(service("another-initiator"));
    let mut private_field = owned.clone();
    private_field.context.fields = Some(vec!["private".into()]);
    let mut excess_amount = owned.clone();
    excess_amount.context.amount.as_mut().unwrap().minor_units = 2000;
    let mut initiated_by_caller = owned.clone();
    initiated_by_caller.context.initiator = Some(alice.clone());
    let mut foreign_owner = owned.clone();
    foreign_owner.context.owner = Some(service("another-owner"));
    let batch = ResourceAuthorizationBatchRequest {
        mode: ResourceAuthorizationMode::Scoped,
        requests: vec![
            owned.clone(),
            private_field,
            excess_amount,
            initiated_by_caller,
            foreign_owner,
        ],
    };
    let response = client
        .post(read_path(&base, "authorize-resources"))
        .bearer_auth(&token)
        .json(&batch)
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), 200);
    let evaluation = response
        .json::<ResourceAuthorizationBatchEvaluation>()
        .await
        .unwrap();
    assert_eq!(
        evaluation
            .outcomes
            .iter()
            .map(|outcome| outcome.decision)
            .collect::<Vec<_>>(),
        [
            AuthorizationDecision::Allow,
            AuthorizationDecision::Deny,
            AuthorizationDecision::Deny,
            AuthorizationDecision::Deny,
            AuthorizationDecision::Deny
        ]
    );
    for (request, expected) in batch.requests.iter().zip(&evaluation.outcomes) {
        let response = client
            .post(read_path(&base, "authorize"))
            .json(request)
            .send()
            .await
            .unwrap();
        assert_eq!(response.status(), 200);
        assert_eq!(
            response.json::<AuthorizationOutcome>().await.unwrap(),
            *expected
        );
    }
    let response = client
        .post(read_path(&base, "resource-candidates"))
        .bearer_auth(&token)
        .json(&candidate(&owned))
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), 200);
    let candidates = response
        .json::<ResourceCandidateEvaluation>()
        .await
        .unwrap();
    assert_eq!(
        candidates.plan.predicate,
        ResourceCandidatePredicate::OwnerIn {
            principals: vec![alice]
        }
    );
    assert!(
        candidates
            .plan
            .broadening_reasons
            .contains(&ResourceCandidateReason::ComplexGrantConstraint)
    );
    assert_eq!(candidates.freshness, evaluation.freshness);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn new_read_capabilities_refuse_ambient_admin_global_foreign_and_missing_service_authority() {
    let (store, base, token, alice) = setup("candidate_exact_capability").await;
    let client = reqwest::Client::new();
    for (id, workspace_id, owned, action, scope) in [
        (
            "unowned-reader",
            "w1",
            false,
            format!("iam.authorization-profile.read:{NS}"),
            workspace("w1"),
        ),
        ("wildcard-reader", "w1", true, "*".into(), workspace("w1")),
        (
            "global-reader",
            "w1",
            true,
            format!("iam.authorization-profile.read:{NS}"),
            ScopeRef::Global,
        ),
        (
            "foreign-reader",
            "w2",
            true,
            format!("iam.authorization-profile.read:{NS}"),
            workspace("w1"),
        ),
    ] {
        grant(&store, id, &action, scope);
        let rejected = mint(&store, id, workspace_id, owned);
        let result = post(
            &client,
            &read_path(&base, "resource-candidates"),
            &rejected,
            serde_json::to_value(candidate(&resource(alice.clone(), alice.clone()))).unwrap(),
        )
        .await;
        assert!(result.0 == 401 || result.0 == 403, "{id}: {result:?}");
    }
    for (id, revoke) in [("expired-reader", false), ("revoked-reader", true)] {
        grant(
            &store,
            id,
            &format!("iam.authorization-profile.read:{NS}"),
            workspace("w1"),
        );
        let rejected = mint(&store, id, "w1", true);
        let mut stored = ApiTokenRepository::get(&store, &ApiTokenId(id.into()))
            .unwrap()
            .unwrap();
        if revoke {
            stored.revoked_at = Some(at());
        } else {
            stored.expires_at = Some(at());
        }
        ApiTokenRepository::update(&store, stored).unwrap();
        let response = client
            .post(read_path(&base, "resource-candidates"))
            .bearer_auth(&rejected)
            .json(&candidate(&resource(alice.clone(), alice.clone())))
            .send()
            .await
            .unwrap();
        assert_eq!(response.status(), 401);
        assert!(
            response
                .headers()
                .get(AUTHORIZATION_FRESHNESS_HEADER)
                .is_none()
        );
    }
    let question = candidate(&resource(alice.clone(), alice));
    assert_eq!(
        client
            .post(read_path(&base, "resource-candidates"))
            .json(&question)
            .send()
            .await
            .unwrap()
            .status(),
        401
    );
    assert_eq!(
        post(
            &client,
            &read_path(&base, "resource-candidates"),
            "admin-key",
            serde_json::to_value(&question).unwrap()
        )
        .await
        .0,
        403
    );
    // Revoking the exact read capability is visible immediately on this replica.
    let response = client
        .delete(format!(
            "{base}/v1/admin/grants/publisher:iam.authorization-profile.read:{NS}"
        ))
        .bearer_auth("admin-key")
        .send()
        .await
        .unwrap();
    assert!(response.status().is_success());
    assert_eq!(
        post(
            &client,
            &read_path(&base, "resource-candidates"),
            &token,
            serde_json::to_value(question).unwrap()
        )
        .await
        .0,
        403
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn batch_bounds_cross_namespace_caller_chain_and_personal_mode_fail_as_one_capability() {
    let (_store, base, token, alice) = setup("candidate_batch_shape").await;
    let client = reqwest::Client::new();
    let question = resource(alice.clone(), alice);
    let batch = ResourceAuthorizationBatchRequest {
        mode: ResourceAuthorizationMode::Scoped,
        requests: vec![question.clone()],
    };
    let mut cases = Vec::new();
    let mut over = batch.clone();
    over.requests = vec![question.clone(); RESOURCE_AUTHORIZATION_BATCH_MAX + 1];
    cases.push(over);
    let mut foreign = batch.clone();
    foreign.requests[0].request.action = ActionKey("tenant.b::read".into());
    cases.push(foreign);
    let mut workspace_mismatch = batch.clone();
    workspace_mismatch.requests[0].request.scope = workspace("w2");
    cases.push(workspace_mismatch);
    let mut chain_mismatch = batch.clone();
    let mut second = question.clone();
    second.request.on_behalf_of.push(service("publisher"));
    chain_mismatch.requests.push(second);
    cases.push(chain_mismatch);
    for invalid in cases {
        let response = client
            .post(read_path(&base, "authorize-resources"))
            .bearer_auth(&token)
            .json(&invalid)
            .send()
            .await
            .unwrap();
        assert_eq!(response.status(), 400);
        assert!(
            response
                .headers()
                .get(AUTHORIZATION_FRESHNESS_HEADER)
                .is_none()
        );
    }
    let mut personal = batch;
    personal.mode = ResourceAuthorizationMode::PersonalDelegation;
    assert_eq!(
        post(
            &client,
            &read_path(&base, "authorize-resources"),
            &token,
            serde_json::to_value(personal).unwrap()
        )
        .await
        .0,
        501
    );
    let mut personal = candidate(&question);
    personal.mode = ResourceAuthorizationMode::PersonalDelegation;
    assert_eq!(
        post(
            &client,
            &read_path(&base, "resource-candidates"),
            &token,
            serde_json::to_value(personal).unwrap()
        )
        .await
        .0,
        501
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn current_roster_account_and_dependency_failure_cannot_reuse_an_old_candidate_plan() {
    let (store, base, token, alice) = setup("candidate_current_native").await;
    let client = reqwest::Client::new();
    let question = candidate(&resource(alice.clone(), alice.clone()));
    let initial = post(
        &client,
        &read_path(&base, "resource-candidates"),
        &token,
        serde_json::to_value(&question).unwrap(),
    )
    .await;
    assert_eq!(initial.0, 200);
    GroupRepository::upsert(
        &store,
        Group {
            id: GroupId("candidate-team".into()),
            org: OrgId("o1".into()),
            display_name: None,
            members: vec![],
            created_at: at(),
            updated_at: at(),
        },
    )
    .unwrap();
    let current = post(
        &client,
        &read_path(&base, "resource-candidates"),
        &token,
        serde_json::to_value(&question).unwrap(),
    )
    .await;
    assert_eq!(current.0, 200);
    assert_eq!(current.1["plan"]["predicate"]["kind"], "none");
    assert_ne!(initial.1["freshness"], current.1["freshness"]);
    GroupRepository::upsert(
        &store,
        Group {
            id: GroupId("candidate-team".into()),
            org: OrgId("o1".into()),
            display_name: None,
            members: vec![alice],
            created_at: at(),
            updated_at: at(),
        },
    )
    .unwrap();
    let restored = post(
        &client,
        &read_path(&base, "resource-candidates"),
        &token,
        serde_json::to_value(&question).unwrap(),
    )
    .await;
    assert_eq!(restored.0, 200);
    assert_eq!(restored.1["plan"]["predicate"]["kind"], "owner_in");
    // Native account suspension is an unconditional eligibility failure, not a
    // request-body fact that a candidate caller can override.
    AccountRepository::upsert(
        &store,
        Account {
            id: AccountId("reader-alice".into()),
            status: AccountStatus::Disabled,
            display_name: None,
            created_at: at(),
            updated_at: at(),
        },
    )
    .unwrap();
    let suspended = post(
        &client,
        &read_path(&base, "resource-candidates"),
        &token,
        serde_json::to_value(&question).unwrap(),
    )
    .await;
    assert_eq!(suspended.0, 200);
    assert_eq!(suspended.1["plan"]["predicate"]["kind"], "none");
    assert_ne!(restored.1["freshness"], suspended.1["freshness"]);
    use awaken_iam_server::SqlConn;
    store
        .backend()
        .execute("DELETE FROM candidate_current_native_fence WHERE id=1", &[])
        .unwrap();
    let response = client
        .post(read_path(&base, "resource-candidates"))
        .bearer_auth(&token)
        .json(&question)
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), 503);
    assert!(
        response
            .headers()
            .get(AUTHORIZATION_FRESHNESS_HEADER)
            .is_none()
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn expired_native_binding_cannot_be_revived_by_a_batch_clients_timestamp() {
    let (_store, base, token, alice) = setup("candidate_expired_binding").await;
    let client = reqwest::Client::new();
    let mut replacement = command("expired-binding", Some(1));
    let role = format!("{NS}:reader");
    replacement.profile.document.grants[0].subject = GrantSubjectRef::Role {
        role_id: role.clone(),
    };
    replacement
        .profile
        .document
        .role_bindings
        .push(RoleBindingSnapshot {
            principal: alice.clone(),
            role_id: role.clone(),
            scope: workspace("w1"),
        });
    replacement
        .profile
        .document
        .binding_limits
        .push(RoleBindingLimit {
            subject: GrantSubjectRef::Principal {
                principal: alice.clone(),
            },
            role_id: role,
            scope: workspace("w1"),
            expires_at: Some(1),
            resource_ids: Some(vec!["retained-resource".into()]),
        });
    let response = post(
        &client,
        &path(&base, ""),
        &token,
        serde_json::to_value(replacement).unwrap(),
    )
    .await;
    assert_eq!(response.0, 200, "{}", response.1);
    assert_eq!(
        post(
            &client,
            &path(&base, "/expired-binding/activate"),
            &token,
            serde_json::json!({})
        )
        .await
        .0,
        200
    );
    let mut request = resource(alice.clone(), alice);
    request.context.evaluated_at = Some(0);
    let batch = ResourceAuthorizationBatchRequest {
        mode: ResourceAuthorizationMode::Scoped,
        requests: vec![request.clone()],
    };
    let response = post(
        &client,
        &read_path(&base, "authorize-resources"),
        &token,
        serde_json::to_value(batch).unwrap(),
    )
    .await;
    assert_eq!(response.0, 200);
    assert_eq!(response.1["outcomes"][0]["decision"], "deny");
    let plan = post(
        &client,
        &read_path(&base, "resource-candidates"),
        &token,
        serde_json::to_value(candidate(&request)).unwrap(),
    )
    .await;
    assert_eq!(plan.0, 200);
    assert_eq!(
        plan.1["plan"]["predicate"]["kind"],
        "resource_ids_or_predecessors"
    );
    assert!(
        plan.1["plan"]["broadening_reasons"]
            .as_array()
            .unwrap()
            .iter()
            .any(|reason| reason == "expiry_deferred")
    );
}

async fn serve_with_profiles(native: Store, profiles: Store) -> String {
    let state = Arc::new(Mutex::new(
        DaemonState::with_policy_store(
            AuthzApi::new(),
            AdminAuthPolicy::new(["admin-key".into()]),
            Arc::new(profiles),
            native,
            AuthApi::new().token_authority(),
        )
        .unwrap(),
    ));
    let router = daemon_router(state.clone()).merge(scoped_profile_router(state));
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    tokio::spawn(async move { http::serve(listener, router).await.unwrap() });
    format!("http://{address}")
}

async fn source_observation(
    client: &reqwest::Client,
    base: &str,
    token: &str,
    alice: &PrincipalRef,
) -> ResourceCandidateEvaluation {
    let requests = vec![
        resource(alice.clone(), alice.clone()),
        resource(alice.clone(), service("another-owner")),
    ];
    let mut expected = Vec::new();
    for request in &requests {
        let response = client
            .post(read_path(base, "authorize"))
            .json(request)
            .send()
            .await
            .unwrap();
        assert_eq!(response.status(), 200);
        expected.push(response.json::<AuthorizationOutcome>().await.unwrap());
    }
    assert_eq!(
        expected
            .iter()
            .map(|outcome| outcome.decision)
            .collect::<Vec<_>>(),
        [AuthorizationDecision::Allow, AuthorizationDecision::Deny]
    );
    let batch = ResourceAuthorizationBatchRequest {
        mode: ResourceAuthorizationMode::Scoped,
        requests: requests.clone(),
    };
    let response = client
        .post(read_path(base, "authorize-resources"))
        .bearer_auth(token)
        .json(&batch)
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), 200);
    let batch = response
        .json::<ResourceAuthorizationBatchEvaluation>()
        .await
        .unwrap();
    assert_eq!(batch.outcomes, expected);
    let response = client
        .post(read_path(base, "resource-candidates"))
        .bearer_auth(token)
        .json(&candidate(&requests[0]))
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), 200);
    let plan = response
        .json::<ResourceCandidateEvaluation>()
        .await
        .unwrap();
    assert_eq!(
        plan.plan.predicate,
        ResourceCandidatePredicate::OwnerIn {
            principals: vec![alice.clone()]
        }
    );
    assert_eq!(plan.freshness, batch.freshness);
    plan
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn foreign_profile_changes_cannot_supply_scoped_authority_or_inherited_ceilings_under_a_native_fence()
 {
    use awaken_iam_server::FenceStore;
    let (native, control, token, alice) = setup("candidate_native_source").await;
    let (foreign, foreign_base, foreign_token, _) = setup("candidate_foreign_source").await;
    // A platform-wide Allow is a ceiling input, never the scoped profile's
    // permission. It makes an accidental foreign broadening observably unsafe.
    GrantRepository::put(
        &native,
        Grant {
            id: GrantId("platform-root".into()),
            subject: GrantSubject::Principal(alice.clone()),
            action_pattern: ActionPattern("*".into()),
            scope: ScopeRef::Global,
            effect: Effect::Allow,
        },
    )
    .unwrap();
    let mixed = serve_with_profiles(native.clone(), foreign.clone()).await;
    let client = reqwest::Client::new();
    let baseline = source_observation(&client, &control, &token, &alice).await;
    assert_eq!(
        source_observation(&client, &mixed, &token, &alice).await,
        baseline
    );
    let native_fence = native.fence().unwrap();
    let mut head = 1;
    for (key, effect) in [
        ("foreign-broad", GrantEffect::Allow),
        ("foreign-deny", GrantEffect::Deny),
    ] {
        let mut publication = command(key, Some(head));
        publication.profile.document.grants[0].subject = GrantSubjectRef::Principal {
            principal: alice.clone(),
        };
        publication.profile.document.grants[0].effect = effect;
        let response = post(
            &client,
            &path(&foreign_base, ""),
            &foreign_token,
            serde_json::to_value(publication).unwrap(),
        )
        .await;
        assert_eq!(response.0, 200, "{}", response.1);
        let response = post(
            &client,
            &path(&foreign_base, &format!("/{key}/activate")),
            &foreign_token,
            serde_json::json!({}),
        )
        .await;
        assert_eq!(response.0, 200, "{}", response.1);
        head += 1;
        assert_eq!(
            native.fence().unwrap(),
            native_fence,
            "only the foreign native store changed"
        );
        assert_eq!(
            source_observation(&client, &control, &token, &alice).await,
            baseline
        );
        assert_eq!(
            source_observation(&client, &mixed, &token, &alice).await,
            baseline,
            "neither foreign Allow nor foreign Deny may change the actual native scoped family"
        );
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn foreign_scoped_declaration_without_native_ownership_is_unavailable_not_legacy_allow_or_empty_plan()
 {
    let native = sqlite_in_memory_store("candidate_absent_native_source").unwrap();
    seed(&native);
    let alice = alice(&native);
    grant(
        &native,
        "publisher",
        &format!("iam.authorization-profile.read:{NS}"),
        workspace("w1"),
    );
    let token = mint(&native, "publisher", "w1", true);
    GrantRepository::put(
        &native,
        Grant {
            id: GrantId("legacy-star".into()),
            subject: GrantSubject::Principal(alice.clone()),
            action_pattern: ActionPattern("*".into()),
            scope: ScopeRef::Global,
            effect: Effect::Allow,
        },
    )
    .unwrap();
    let (foreign, _, _, _) = setup("candidate_absent_foreign_source").await;
    let mixed = serve_with_profiles(native.clone(), foreign).await;
    let control = serve(native).await;
    let client = reqwest::Client::new();
    let request = resource(alice.clone(), alice);
    let batch = ResourceAuthorizationBatchRequest {
        mode: ResourceAuthorizationMode::Scoped,
        requests: vec![request.clone()],
    };
    for (suffix, body) in [
        ("authorize", serde_json::to_value(&request).unwrap()),
        ("authorize-resources", serde_json::to_value(batch).unwrap()),
        (
            "resource-candidates",
            serde_json::to_value(candidate(&request)).unwrap(),
        ),
    ] {
        let response = client
            .post(read_path(&mixed, suffix))
            .bearer_auth(&token)
            .json(&body)
            .send()
            .await
            .unwrap();
        assert_eq!(response.status(), 503);
        assert!(
            response
                .headers()
                .get(AUTHORIZATION_FRESHNESS_HEADER)
                .is_none()
        );
    }
    let mixed_legacy = client
        .post(format!("{mixed}/v1/authorize/resource"))
        .json(&request)
        .send()
        .await
        .unwrap();
    assert_eq!(
        mixed_legacy.status(),
        503,
        "a foreign scoped declaration cannot enter the legacy wildcard fallback"
    );
    // Proved same-store absence remains an ordinary scoped Deny, while the
    // legacy global family intentionally keeps its historical wildcard law.
    let scoped = client
        .post(read_path(&control, "authorize"))
        .json(&request)
        .send()
        .await
        .unwrap();
    assert_eq!(scoped.status(), 200);
    assert_eq!(
        scoped
            .json::<AuthorizationOutcome>()
            .await
            .unwrap()
            .decision,
        AuthorizationDecision::Deny
    );
    let plan = post(
        &client,
        &read_path(&control, "resource-candidates"),
        &token,
        serde_json::to_value(candidate(&request)).unwrap(),
    )
    .await;
    assert_eq!(plan.0, 200);
    assert_eq!(plan.1["plan"]["predicate"]["kind"], "none");
    let legacy = client
        .post(format!("{control}/v1/authorize/resource"))
        .json(&request)
        .send()
        .await
        .unwrap();
    assert_eq!(legacy.status(), 200);
    assert_eq!(
        legacy
            .json::<AuthorizationOutcome>()
            .await
            .unwrap()
            .decision,
        AuthorizationDecision::Allow
    );
}
