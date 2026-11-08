//! Real SQL and native HTTP consent, credential family, revocation and policy.
use awaken_iam_contract::*;
use awaken_iam_core::{
    AccountRepository, ActionPattern, ClientDelegation, ClientTokenExchangePolicy, Effect, Grant,
    GrantId, GrantSubject, OAuthClientRepository, PersonalDelegationRepository, RegisteredClient,
    validate_personal_consent,
};
use awaken_iam_server::*;
use axum::{
    Router,
    body::{Body, to_bytes},
    http::{Request, StatusCode},
};
use serde_json::{Value, json};
use std::sync::{Arc, Barrier, Mutex};
use tower::ServiceExt;
const ISSUER: &str = "https://consent-iam.example";
const ACTION: &str = "operations.business::models.quote.approve";
#[path = "personal_delegation_e2e/scoped_membership.rs"]
mod scoped_membership;
fn now() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs() as i64
}
fn scope() -> ScopeRef {
    ScopeRef::Project {
        workspace_id: WorkspaceId("w".into()),
        project_id: ProjectId("p".into()),
    }
}
fn consent() -> CreatePersonalDelegation {
    CreatePersonalDelegation {
        request_key: "owner-intent".into(),
        recipient_client_id: "business".into(),
        audience: "flow".into(),
        actions: vec![ActionKey(ACTION.into())],
        scopes: vec![scope()],
        valid_from: now() - 10,
        valid_until: now() + 3600,
    }
}
fn record() -> PersonalDelegation {
    PersonalDelegation {
        id: "consent-1".into(),
        owner: AccountId("ada".into()),
        service_id: "business-service".into(),
        consent: consent(),
        created_at: now(),
        revoked_at: None,
        version: 1,
    }
}
fn exercise_repository<S: PersonalDelegationRepository + Clone + Send + 'static>(store: S) {
    let first = record();
    assert!(store.personal_delegation(&first.id).unwrap().is_none());
    let barrier = Arc::new(Barrier::new(8));
    let threads: Vec<_> = (0..8)
        .map(|_| {
            let s = store.clone();
            let b = barrier.clone();
            let v = first.clone();
            std::thread::spawn(move || {
                b.wait();
                s.create_personal_delegation(v).unwrap()
            })
        })
        .collect();
    for t in threads {
        assert_eq!(t.join().unwrap(), first)
    }
    let mut changed = first.clone();
    changed.consent.valid_until += 1;
    assert!(store.create_personal_delegation(changed).is_err());
    assert!(
        store
            .revoke_personal_delegation(&first.id, &AccountId("foreign".into()), now())
            .is_err()
    );
    let revoked = store
        .revoke_personal_delegation(&first.id, &first.owner, now())
        .unwrap();
    assert_eq!(revoked.version, 2);
    assert_eq!(
        store
            .revoke_personal_delegation(&first.id, &first.owner, now() + 100)
            .unwrap(),
        revoked
    );
    assert_eq!(
        store.create_personal_delegation(first).unwrap(),
        revoked,
        "replaying creation never resurrects consent"
    );
}
#[test]
fn consent_sql_concurrency_and_monotonic_lifecycle() {
    exercise_repository(sqlite_in_memory_store("iam").unwrap())
}
#[test]
fn postgres_consent_repository_conformance() {
    let Ok(url) = std::env::var("IAM_TEST_POSTGRES_URL") else {
        return;
    };
    let prefix = format!(
        "ic_{:x}",
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    );
    exercise_repository(postgres_migrated_store(&url, &prefix).unwrap());
}
#[test]
fn consent_requires_finite_exact_actions_scopes_and_window() {
    let c = consent();
    validate_personal_consent(&c, now()).unwrap();
    for change in [
        json!({"actions":["*"]}),
        json!({"actions":[]}),
        json!({"scopes":[{"kind":"global"}]}),
        json!({"valid_until":0}),
        json!({"valid_from":-1}),
        json!({"request_key":""}),
    ] {
        let mut value = serde_json::to_value(&c).unwrap();
        for (k, v) in change.as_object().unwrap() {
            value[k] = v.clone()
        }
        assert!(validate_personal_consent(&serde_json::from_value(value).unwrap(), now()).is_err());
    }
}
async fn call(
    app: &Router,
    token: Option<&str>,
    method: &str,
    path: &str,
    body: Value,
) -> (StatusCode, Value) {
    let mut request = Request::builder()
        .method(method)
        .uri(path)
        .header("content-type", "application/json");
    if let Some(token) = token {
        request = request.header("authorization", format!("Bearer {token}"))
    }
    let response = app
        .clone()
        .oneshot(request.body(Body::from(body.to_string())).unwrap())
        .await
        .unwrap();
    let status = response.status();
    let bytes = to_bytes(response.into_body(), 1024 * 1024).await.unwrap();
    (
        status,
        serde_json::from_slice(&bytes).unwrap_or(Value::Null),
    )
}
#[tokio::test]
async fn explicit_personal_consent_uses_live_policy_and_revocation_even_for_issued_credentials() {
    let store = Arc::new(sqlite_in_memory_store("iam").unwrap());
    let account = Account {
        id: AccountId("ada".into()),
        status: AccountStatus::Active,
        display_name: None,
        created_at: Timestamp("2026-11-04T00:00:00Z".into()),
        updated_at: Timestamp("2026-11-04T00:00:00Z".into()),
    };
    AccountRepository::upsert(&*store, account.clone()).unwrap();
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
    let mut policy = PolicyAdminApi::new((*store).clone());
    for (id, principal) in [
        (
            "human",
            PrincipalRef::Account {
                account_id: account.id.clone(),
            },
        ),
        (
            "service",
            PrincipalRef::Service {
                service_id: "business-service".into(),
            },
        ),
    ] {
        policy
            .issue_grant(
                Grant {
                    id: GrantId(id.into()),
                    subject: GrantSubject::Principal(principal),
                    action_pattern: ActionPattern(ACTION.into()),
                    scope: scope(),
                    effect: Effect::Allow,
                },
                Timestamp("2026-11-04T00:00:00Z".into()),
            )
            .unwrap();
    }
    let mut auth = AuthApi::new()
        .with_issuer(ISSUER)
        .with_identity_repositories(store.clone(), store.clone(), store.clone())
        .with_oauth_repositories(store.clone(), store.clone());
    let owner = auth
        .mint_access_token(MintAccessToken {
            issuer: ISSUER.into(),
            subject: "ada".into(),
            audience: PERSONAL_DELEGATION_CONSENT_AUDIENCE.into(),
            issued_at: now() - 1,
            expires_at: now() + 3600,
            scopes: vec![PERSONAL_DELEGATION_CONSENT_SCOPE.into()],
        })
        .await
        .unwrap();
    let wrong_audience = auth
        .mint_access_token(MintAccessToken {
            issuer: ISSUER.into(),
            subject: "ada".into(),
            audience: "business".into(),
            issued_at: now() - 1,
            expires_at: now() + 3600,
            scopes: vec![PERSONAL_DELEGATION_CONSENT_SCOPE.into()],
        })
        .await
        .unwrap();
    let signer = auth.token_authority();
    let jwks = auth.jwks();
    let daemon = Arc::new(Mutex::new(
        DaemonState::with_policy_store(
            AuthzApi::new(),
            AdminAuthPolicy::deny_all(),
            store.clone(),
            (*store).clone(),
            signer,
        )
        .unwrap(),
    ));
    let auth = Arc::new(tokio::sync::Mutex::new(auth));
    let app = personal_delegation_router(auth.clone(), daemon, store.clone(), ISSUER.into());
    let body = serde_json::to_value(consent()).unwrap();
    assert_eq!(
        call(
            &app,
            Some(&wrong_audience),
            "POST",
            "/v1/personal-delegations",
            body.clone()
        )
        .await
        .0,
        StatusCode::FORBIDDEN
    );
    let (status, grant) = call(
        &app,
        Some(&owner),
        "POST",
        "/v1/personal-delegations",
        body.clone(),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{grant}");
    let grant_id = grant["id"].as_str().unwrap();
    let inspected = call(
        &app,
        None,
        "POST",
        "/v1/personal-delegations/inspect",
        json!({"client_id":"business","client_secret":"test-recipient-secret","grant_id":grant_id}),
    )
    .await;
    assert_eq!(inspected.0, StatusCode::OK);
    assert_eq!(inspected.1, grant);
    assert_eq!(
        call(
            &app,
            None,
            "POST",
            "/v1/personal-delegations/inspect",
            json!({"client_id":"business","client_secret":"wrong","grant_id":grant_id})
        )
        .await
        .0,
        StatusCode::FORBIDDEN
    );
    let binding = json!({"grant_id":grant_id,"action":ACTION,"scope":scope(),"target":{"id":"native-task","revision":4},"purpose":"execute","original_key":null});
    let token_body = |binding: Value| json!({"client_id":"business","client_secret":"test-recipient-secret","binding":binding});
    let (status, issued) = call(
        &app,
        None,
        "POST",
        "/v1/personal-delegations/token",
        token_body(binding.clone()),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{issued}");
    let token = issued["access_token"].as_str().unwrap();
    assert!(
        verify_delegated_access_token(token, &jwks).is_err(),
        "legacy verifiers must reject the new family"
    );
    verify_personal_delegation_token(token, &jwks, ISSUER, "flow", now()).unwrap();
    assert!(verify_personal_delegation_token(token, &jwks, ISSUER, "other", now()).is_err());
    assert!(verify_personal_delegation_token(token, &jwks, ISSUER, "flow", now() + 301).is_err());
    let request = json!({"token":token,"audience":"flow","target":{"id":"native-task","revision":4},"request":{"request":{"principal":{"kind":"service","service_id":"business-service"},"on_behalf_of":[{"kind":"account","account_id":"ada"}],"action":ACTION,"scope":scope()},"context":{}}});
    let (status, result) = call(
        &app,
        None,
        "POST",
        "/v1/authorize/personal-delegation",
        request.clone(),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{result}");
    assert_eq!(result["decision"], "allow");
    let mut different = request.clone();
    different["target"]["revision"] = json!(5);
    assert_eq!(
        call(
            &app,
            None,
            "POST",
            "/v1/authorize/personal-delegation",
            different
        )
        .await
        .0,
        StatusCode::FORBIDDEN
    );
    policy
        .revoke_grant(
            &GrantId("service".into()),
            Timestamp("2026-11-04T00:00:01Z".into()),
        )
        .unwrap();
    assert_eq!(
        call(
            &app,
            None,
            "POST",
            "/v1/authorize/personal-delegation",
            request.clone()
        )
        .await
        .1["decision"],
        "deny",
        "live service policy remains conjunctive"
    );
    let revoke = format!("/v1/personal-delegations/{grant_id}/revoke");
    let (status, revoked) = call(&app, Some(&owner), "POST", &revoke, json!({})).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(revoked["version"], 2);
    assert_eq!(
        call(
            &app,
            None,
            "POST",
            "/v1/authorize/personal-delegation",
            request.clone()
        )
        .await
        .0,
        StatusCode::FORBIDDEN,
        "issued token immediately loses execution consent"
    );
    assert_eq!(
        call(
            &app,
            None,
            "POST",
            "/v1/personal-delegations/token",
            token_body(binding.clone())
        )
        .await
        .0,
        StatusCode::FORBIDDEN
    );
    assert_eq!(
        call(&app, Some(&owner), "POST", "/v1/personal-delegations", body)
            .await
            .1,
        revoked,
        "original consent lookup precedes changed gates"
    );
    let mut recovery = binding;
    recovery["purpose"] = json!("original_outcome");
    recovery["original_key"] = json!("the-original-key");
    let (status, read_only) = call(
        &app,
        None,
        "POST",
        "/v1/personal-delegations/token",
        token_body(recovery),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    let claims = verify_personal_delegation_token(
        read_only["access_token"].as_str().unwrap(),
        &jwks,
        ISSUER,
        "flow",
        now(),
    )
    .unwrap();
    assert_eq!(
        claims.binding.purpose,
        PersonalDelegationPurpose::OriginalOutcome
    );
    let mut readonly_request = request;
    readonly_request["token"] = read_only["access_token"].clone();
    assert_eq!(
        call(
            &app,
            None,
            "POST",
            "/v1/authorize/personal-delegation",
            readonly_request
        )
        .await
        .0,
        StatusCode::FORBIDDEN,
        "outcome credentials never authorize execution"
    );
}

#[tokio::test]
async fn scope_level_read_credentials_are_read_only_untargeted_and_follow_consent() {
    const READ: &str = "resource.read";
    let store = Arc::new(sqlite_in_memory_store("iam").unwrap());
    AccountRepository::upsert(
        &*store,
        Account {
            id: AccountId("ada".into()),
            status: AccountStatus::Active,
            display_name: None,
            created_at: Timestamp("2026-11-04T00:00:00Z".into()),
            updated_at: Timestamp("2026-11-04T00:00:00Z".into()),
        },
    )
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
    OAuthClientRepository::upsert(&*store, client.clone()).unwrap();
    let mut policy = PolicyAdminApi::new((*store).clone());
    for (id, principal) in [
        (
            "read-human",
            PrincipalRef::Account {
                account_id: AccountId("ada".into()),
            },
        ),
        (
            "read-service",
            PrincipalRef::Service {
                service_id: "business-service".into(),
            },
        ),
    ] {
        policy
            .issue_grant(
                Grant {
                    id: GrantId(id.into()),
                    subject: GrantSubject::Principal(principal),
                    action_pattern: ActionPattern(READ.into()),
                    scope: scope(),
                    effect: Effect::Allow,
                },
                Timestamp("2026-11-09T00:00:00Z".into()),
            )
            .unwrap();
    }
    let mut auth = AuthApi::new()
        .with_issuer(ISSUER)
        .with_identity_repositories(store.clone(), store.clone(), store.clone())
        .with_oauth_repositories(store.clone(), store.clone());
    let owner = auth
        .mint_access_token(MintAccessToken {
            issuer: ISSUER.into(),
            subject: "ada".into(),
            audience: PERSONAL_DELEGATION_CONSENT_AUDIENCE.into(),
            issued_at: now() - 1,
            expires_at: now() + 3600,
            scopes: vec![PERSONAL_DELEGATION_CONSENT_SCOPE.into()],
        })
        .await
        .unwrap();
    let signer = auth.token_authority();
    let jwks = auth.jwks();
    let daemon = Arc::new(Mutex::new(
        DaemonState::with_policy_store(
            AuthzApi::new(),
            AdminAuthPolicy::deny_all(),
            store.clone(),
            (*store).clone(),
            signer,
        )
        .unwrap(),
    ));
    let app = personal_delegation_router(
        Arc::new(tokio::sync::Mutex::new(auth)),
        daemon,
        store.clone(),
        ISSUER.into(),
    );
    let mut wanted = consent();
    wanted.request_key = "offline-reads".into();
    wanted.actions = vec![ActionKey(READ.into()), ActionKey(ACTION.into())];
    let (status, grant) = call(
        &app,
        Some(&owner),
        "POST",
        "/v1/personal-delegations",
        serde_json::to_value(wanted).unwrap(),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{grant}");
    let grant_id = grant["id"].as_str().unwrap().to_owned();
    let mint = |binding: Value| {
        let app = app.clone();
        async move {
            call(
                &app,
                None,
                "POST",
                "/v1/personal-delegations/token",
                json!({"client_id":"business","client_secret":"test-recipient-secret","binding":binding}),
            )
            .await
        }
    };
    let read = json!({"grant_id":grant_id,"action":READ,"scope":scope(),"purpose":"read","original_key":null});
    let (status, issued) = mint(read.clone()).await;
    assert_eq!(status, StatusCode::OK, "{issued}");
    let token = issued["access_token"].as_str().unwrap();
    let claims = verify_personal_delegation_token(token, &jwks, ISSUER, "flow", now()).unwrap();
    assert_eq!(claims.binding.purpose, PersonalDelegationPurpose::Read);
    assert_eq!(claims.binding.target, None);
    assert!(claims.exp - claims.iat <= 300);
    for (patch, why) in [
        (
            json!({"target":{"id":"native-task","revision":4}}),
            "a read names no target",
        ),
        (json!({"action":ACTION}), "a read uses a .read action only"),
        (
            json!({"action":"issue.read"}),
            "a read stays within consented actions",
        ),
        (
            json!({"original_key":"k"}),
            "a read carries no original key",
        ),
        (
            json!({"scope":{"kind":"project","workspace_id":"w","project_id":"other"}}),
            "a read stays within consented scopes",
        ),
    ] {
        let mut binding = read.clone();
        for (key, value) in patch.as_object().unwrap() {
            binding[key] = value.clone();
        }
        assert_eq!(mint(binding).await.0, StatusCode::FORBIDDEN, "{why}");
    }
    // Live-read decision table: the same signed credential must be accepted
    // with current consent/policy, then refused after current authority changes.
    // Shape, action, scope, human, service and audience remain exact.
    let live = json!({"token":token,"audience":"flow","request":{"request":{"principal":{"kind":"service","service_id":"business-service"},"on_behalf_of":[{"kind":"account","account_id":"ada"}],"action":READ,"scope":scope()},"context":{}}});
    let check = |request: Value| {
        let app = app.clone();
        async move {
            call(
                &app,
                None,
                "POST",
                "/v1/authorize/personal-delegation",
                request,
            )
            .await
        }
    };
    let (status, allowed) = check(live.clone()).await;
    assert_eq!(status, StatusCode::OK, "{allowed}");
    assert_eq!(allowed["decision"], "allow");
    for (pointer, changed) in [
        ("/audience", json!("other")),
        ("/request/request/action", json!("issue.read")),
        ("/request/request/scope/project_id", json!("other")),
        (
            "/request/request/principal/service_id",
            json!("other-service"),
        ),
        (
            "/request/request/on_behalf_of/0/account_id",
            json!("other-owner"),
        ),
    ] {
        let mut wrong = live.clone();
        *wrong.pointer_mut(pointer).unwrap() = changed;
        assert_eq!(check(wrong).await.0, StatusCode::FORBIDDEN, "{pointer}");
    }
    let mut disabled = AccountRepository::get(&*store, &AccountId("ada".into()))
        .unwrap()
        .unwrap();
    disabled.status = AccountStatus::Disabled;
    AccountRepository::upsert(&*store, disabled.clone()).unwrap();
    assert_eq!(
        check(live.clone()).await.0,
        StatusCode::FORBIDDEN,
        "same token after owner disabled"
    );
    disabled.status = AccountStatus::Active;
    AccountRepository::upsert(&*store, disabled).unwrap();
    let mut withdrawn = client.clone();
    withdrawn.token_exchange.delegation = None;
    OAuthClientRepository::upsert(&*store, withdrawn).unwrap();
    assert_eq!(
        check(live.clone()).await.0,
        StatusCode::FORBIDDEN,
        "same token after recipient admission withdrawn"
    );
    OAuthClientRepository::upsert(&*store, client).unwrap();
    for id in ["read-human", "read-service"] {
        policy
            .revoke_grant(
                &GrantId(id.into()),
                Timestamp("2026-11-09T00:00:01Z".into()),
            )
            .unwrap();
        assert_eq!(
            check(live.clone()).await.1["decision"],
            "deny",
            "same token after {id} policy withdrawn"
        );
        let principal = if id == "read-human" {
            PrincipalRef::Account {
                account_id: AccountId("ada".into()),
            }
        } else {
            PrincipalRef::Service {
                service_id: "business-service".into(),
            }
        };
        policy
            .issue_grant(
                Grant {
                    id: GrantId(format!("{id}-restored")),
                    subject: GrantSubject::Principal(principal),
                    action_pattern: ActionPattern(READ.into()),
                    scope: scope(),
                    effect: Effect::Allow,
                },
                Timestamp("2026-11-09T00:00:02Z".into()),
            )
            .unwrap();
    }
    assert_eq!(check(live.clone()).await.1["decision"], "allow");
    assert!(
        verify_personal_delegation_token(token, &jwks, ISSUER, "flow", claims.exp).is_err(),
        "same signed token expires"
    );
    let execute = json!({"token":token,"audience":"flow","target":{"id":"native-task","revision":4},"request":{"request":{"principal":{"kind":"service","service_id":"business-service"},"on_behalf_of":[{"kind":"account","account_id":"ada"}],"action":READ,"scope":scope()},"context":{}}});
    assert_eq!(
        call(
            &app,
            None,
            "POST",
            "/v1/authorize/personal-delegation",
            execute
        )
        .await
        .0,
        StatusCode::FORBIDDEN,
        "read credentials never authorize execution"
    );
    let revoke = format!("/v1/personal-delegations/{grant_id}/revoke");
    assert_eq!(
        call(&app, Some(&owner), "POST", &revoke, json!({})).await.0,
        StatusCode::OK
    );
    assert_eq!(
        check(live).await.0,
        StatusCode::FORBIDDEN,
        "same issued read token after consent revoked"
    );
    assert_eq!(
        mint(read).await.0,
        StatusCode::FORBIDDEN,
        "revoked consent mints no further reads"
    );
}
