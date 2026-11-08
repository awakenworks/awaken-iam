//! One owner inventory on the native SQL seam and genuine public PKCE routes.
use super::*;
use awaken_iam_core::{SessionRepository, hash_session_token};
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use sha2::{Digest, Sha256};

pub(super) fn exercise_listing<S: PersonalDelegationRepository>(store: &S) {
    for id in ["z-pending", "a-active", "m-expired", "foreign-0"] {
        let mut value = record();
        value.id = id.into();
        value.consent.request_key = id.into();
        if id == "foreign-0" {
            value.owner = AccountId("grace".into());
        }
        if id == "m-expired" {
            value.consent.valid_until = now() - 1;
        }
        if id == "z-pending" {
            value.consent.valid_from = now() + 100;
        }
        store.create_personal_delegation(value).unwrap();
    }
    let owner = AccountId("ada".into());
    let page = store
        .list_personal_delegations(
            &owner,
            &ListPersonalDelegations {
                limit: 2,
                after: None,
            },
        )
        .unwrap();
    assert_eq!(
        page.items
            .iter()
            .map(|item| item.id.as_str())
            .collect::<Vec<_>>(),
        ["a-active", "consent-1"]
    );
    assert!(page.items[1].revoked_at.is_some());
    assert_eq!(page.items[1].version, 2);
    let second = store
        .list_personal_delegations(
            &owner,
            &ListPersonalDelegations {
                limit: 2,
                after: page.next_cursor,
            },
        )
        .unwrap();
    assert_eq!(
        second
            .items
            .iter()
            .map(|item| item.id.as_str())
            .collect::<Vec<_>>(),
        ["m-expired", "z-pending"]
    );
    assert!(second.items[0].consent.valid_until < now());
    assert!(second.items[1].consent.valid_from > now());
    assert!(second.next_cursor.is_none());
    let all = store
        .list_personal_delegations(&owner, &Default::default())
        .unwrap();
    assert_eq!(all.items.len(), 4);
    assert!(all.items.iter().all(|item| item.owner == owner));
    assert_eq!(
        store
            .list_personal_delegations(&AccountId("missing".into()), &Default::default())
            .unwrap()
            .items,
        []
    );
    assert_eq!(
        store
            .list_personal_delegations(&AccountId("grace".into()), &Default::default())
            .unwrap()
            .items
            .len(),
        1
    );
    for query in [
        ListPersonalDelegations {
            limit: 0,
            after: None,
        },
        ListPersonalDelegations {
            limit: 101,
            after: None,
        },
        ListPersonalDelegations {
            limit: 1,
            after: Some(String::new()),
        },
        ListPersonalDelegations {
            limit: 1,
            after: Some("x".repeat(301)),
        },
    ] {
        assert!(store.list_personal_delegations(&owner, &query).is_err());
    }
}

async fn form(app: &Router, fields: &[(&str, &str)]) -> (StatusCode, Value) {
    let mut body = url::form_urlencoded::Serializer::new(String::new());
    for (key, value) in fields {
        body.append_pair(key, value);
    }
    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/v1/oauth/token")
                .header("content-type", "application/x-www-form-urlencoded")
                .body(Body::from(body.finish()))
                .unwrap(),
        )
        .await
        .unwrap();
    let status = response.status();
    let bytes = to_bytes(response.into_body(), 1024 * 1024).await.unwrap();
    (status, serde_json::from_slice(&bytes).unwrap())
}
const VERIFIER: &str = "public-consent-verifier-with-enough-entropy-for-pkce";
const REDIRECT: &str = "https://desk.example/callback";
const CLIENT: &str = "desk";
async fn code(app: &Router, cookie: &str, scope: &str) -> String {
    let challenge = URL_SAFE_NO_PAD.encode(Sha256::digest(VERIFIER.as_bytes()));
    let query = url::form_urlencoded::Serializer::new(String::new())
        .append_pair("client_id", CLIENT)
        .append_pair("redirect_uri", REDIRECT)
        .append_pair("response_type", "code")
        .append_pair("scope", scope)
        .append_pair("state", "owner-consent-state")
        .append_pair("code_challenge", &challenge)
        .append_pair("code_challenge_method", "S256")
        .finish();
    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .uri(format!("/v1/oauth/authorize?{query}"))
                .header("cookie", cookie)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::SEE_OTHER);
    let location = url::Url::parse(response.headers()["location"].to_str().unwrap()).unwrap();
    assert_eq!(
        location
            .query_pairs()
            .find(|(key, _)| key == "state")
            .unwrap()
            .1,
        "owner-consent-state"
    );
    location
        .query_pairs()
        .find(|(key, _)| key == "code")
        .unwrap()
        .1
        .into_owned()
}
async fn redeem(app: &Router, code: &str, verifier: &str) -> (StatusCode, Value) {
    form(
        app,
        &[
            ("grant_type", "authorization_code"),
            ("client_id", CLIENT),
            ("redirect_uri", REDIRECT),
            ("code", code),
            ("code_verifier", verifier),
        ],
    )
    .await
}
async fn public_token(app: &Router, cookie: &str, scope: &str) -> String {
    let code = code(app, cookie, scope).await;
    let (status, body) = redeem(app, &code, VERIFIER).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(
        redeem(app, &code, VERIFIER).await.0,
        StatusCode::BAD_REQUEST,
        "code is single-use"
    );
    body["access_token"].as_str().unwrap().to_owned()
}
async fn exchange(
    app: &Router,
    subject: &str,
    scope: Option<&str>,
    delegated: bool,
) -> (StatusCode, Value) {
    let mut fields = vec![
        ("grant_type", TOKEN_EXCHANGE_GRANT_TYPE),
        ("client_id", if delegated { "delegate" } else { CLIENT }),
        ("subject_token", subject),
        ("subject_token_type", SUBJECT_TOKEN_TYPE_ACCESS_TOKEN),
        ("audience", PERSONAL_DELEGATION_CONSENT_AUDIENCE),
    ];
    if delegated {
        fields.push(("client_secret", "test-delegate-secret"));
    }
    if let Some(scope) = scope {
        fields.push(("scope", scope));
    }
    form(app, &fields).await
}

#[tokio::test]
async fn owner_inventory_is_native_bounded_and_fenced_after_public_pkce_exchange() {
    let store = Arc::new(sqlite_in_memory_store("iam").unwrap());
    for id in ["ada", "grace"] {
        AccountRepository::upsert(
            &*store,
            Account {
                id: AccountId(id.into()),
                status: AccountStatus::Active,
                display_name: None,
                created_at: Timestamp("2026-01-01T00:00:00Z".into()),
                updated_at: Timestamp("2026-01-01T00:00:00Z".into()),
            },
        )
        .unwrap();
        SessionRepository::create(
            &*store,
            Session {
                id: SessionId(format!("session-{id}")),
                account_id: AccountId(id.into()),
                token_hash: hash_session_token(&format!("native-session-{id}")),
                external_identity_id: None,
                created_at: Timestamp("2026-01-01T00:00:00Z".into()),
                last_seen_at: Timestamp("2026-01-01T00:00:00Z".into()),
                expires_at: Timestamp("2099-01-01T00:00:00Z".into()),
                revoked_at: None,
            },
        )
        .unwrap();
    }
    let mut first = record();
    first.id = "a-revoked".into();
    first.consent.request_key = first.id.clone();
    store.create_personal_delegation(first).unwrap();
    store
        .revoke_personal_delegation("a-revoked", &AccountId("ada".into()), now())
        .unwrap();
    for id in ["b-expired", "c-future", "foreign"] {
        let mut value = record();
        value.id = id.into();
        value.consent.request_key = id.into();
        if id == "b-expired" {
            value.consent.valid_until = now() - 1;
        }
        if id == "c-future" {
            value.consent.valid_from = now() + 600;
        }
        if id == "foreign" {
            value.owner = AccountId("grace".into());
        }
        store.create_personal_delegation(value).unwrap();
    }
    OAuthClientRepository::upsert(
        &*store,
        RegisteredClient::public(
            CLIENT,
            vec![REDIRECT.into()],
            ["openid", PERSONAL_DELEGATION_CONSENT_SCOPE],
        )
        .with_token_exchange(ClientTokenExchangePolicy {
            audiences: [PERSONAL_DELEGATION_CONSENT_AUDIENCE.into()].into(),
            delegation: None,
        }),
    )
    .unwrap();
    OAuthClientRepository::upsert(
        &*store,
        RegisteredClient::confidential(
            "delegate",
            "test-delegate-secret",
            vec!["https://delegate.example/cb".into()],
            [PERSONAL_DELEGATION_CONSENT_SCOPE],
        )
        .with_token_exchange(ClientTokenExchangePolicy {
            audiences: Default::default(),
            delegation: Some(ClientDelegation {
                service_id: "svc-delegate".into(),
                audiences: [PERSONAL_DELEGATION_CONSENT_AUDIENCE.into()].into(),
                subject_audiences: [CLIENT.into()].into(),
            }),
        }),
    )
    .unwrap();
    let auth = Arc::new(tokio::sync::Mutex::new(
        AuthApi::new()
            .with_issuer(ISSUER)
            .with_identity_repositories(store.clone(), store.clone(), store.clone())
            .with_session_repository(store.clone())
            .with_oauth_repositories(store.clone(), store.clone()),
    ));
    let signer = auth.lock().await.token_authority();
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
    let app = personal_delegation_router(auth.clone(), daemon, store.clone(), ISSUER.into()).merge(
        op_router(auth.clone(), ISSUER, ProviderLoginRouteOwner::Iam),
    );
    let cookie = format!("{DEFAULT_SESSION_COOKIE_NAME}=native-session-ada");
    let pending = code(&app, &cookie, "openid iam.personal-delegation.manage").await;
    assert_eq!(
        redeem(&app, &pending, "wrong-verifier").await.0,
        StatusCode::BAD_REQUEST
    );
    let subject = public_token(&app, &cookie, "openid iam.personal-delegation.manage").await;
    assert_eq!(
        call(
            &app,
            Some(&subject),
            "GET",
            "/v1/personal-delegations",
            Value::Null
        )
        .await
        .0,
        StatusCode::FORBIDDEN
    );
    let (status, issued) = exchange(
        &app,
        &subject,
        Some(PERSONAL_DELEGATION_CONSENT_SCOPE),
        false,
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    let token = issued["access_token"].as_str().unwrap();
    let verified = auth
        .lock()
        .await
        .verify_delegated_access_token(token)
        .unwrap();
    assert_eq!(verified.act, None);
    assert_eq!(verified.claims.sub, "ada");
    assert_eq!(verified.claims.aud, PERSONAL_DELEGATION_CONSENT_AUDIENCE);
    assert_eq!(verified.claims.scope, [PERSONAL_DELEGATION_CONSENT_SCOPE]);
    let (status, page) = call(
        &app,
        Some(token),
        "GET",
        "/v1/personal-delegations?limit=1",
        Value::Null,
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    let page: PersonalDelegationPage = serde_json::from_value(page).unwrap();
    assert_eq!(page.items[0].id, "a-revoked");
    assert!(page.items[0].revoked_at.is_some());
    let mut ids = vec![page.items[0].id.clone()];
    let mut after = page.next_cursor;
    while let Some(cursor) = after {
        let query = url::form_urlencoded::Serializer::new(String::new())
            .append_pair("limit", "1")
            .append_pair("after", &cursor)
            .finish();
        let (status, page) = call(
            &app,
            Some(token),
            "GET",
            &format!("/v1/personal-delegations?{query}"),
            Value::Null,
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        let page: PersonalDelegationPage = serde_json::from_value(page).unwrap();
        assert_eq!(page.items.len(), 1);
        assert_eq!(page.items[0].owner, AccountId("ada".into()));
        ids.push(page.items[0].id.clone());
        after = page.next_cursor;
        assert!(ids.len() <= 3, "continuation terminates");
    }
    assert_eq!(ids, ["a-revoked", "b-expired", "c-future"]);
    let (_, all) = call(
        &app,
        Some(token),
        "GET",
        "/v1/personal-delegations",
        Value::Null,
    )
    .await;
    assert_eq!(all["items"].as_array().unwrap().len(), 3);
    assert!(all["next_cursor"].is_null());
    for query in [
        "limit=0",
        "limit=101",
        "limit=-1",
        "after=",
        "owner=grace",
        "limit=1&limit=2",
    ] {
        assert_eq!(
            call(
                &app,
                Some(token),
                "GET",
                &format!("/v1/personal-delegations?{query}"),
                Value::Null
            )
            .await
            .0,
            StatusCode::BAD_REQUEST,
            "query {query}"
        );
    }
    let long_cursor = "x".repeat(301);
    assert_eq!(
        call(
            &app,
            Some(token),
            "GET",
            &format!("/v1/personal-delegations?after={long_cursor}"),
            Value::Null
        )
        .await
        .0,
        StatusCode::BAD_REQUEST
    );
    assert_eq!(
        call(&app, None, "GET", "/v1/personal-delegations", Value::Null)
            .await
            .0,
        StatusCode::FORBIDDEN
    );
    let (status, delegated) = exchange(
        &app,
        &subject,
        Some(PERSONAL_DELEGATION_CONSENT_SCOPE),
        true,
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(
        call(
            &app,
            delegated["access_token"].as_str(),
            "GET",
            "/v1/personal-delegations",
            Value::Null
        )
        .await
        .0,
        StatusCode::FORBIDDEN
    );
    let ordinary = public_token(&app, &cookie, "openid").await;
    let (status, denied) = exchange(
        &app,
        &ordinary,
        Some(PERSONAL_DELEGATION_CONSENT_SCOPE),
        false,
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(denied["error"], "invalid_scope");
    let (status, narrowed) = exchange(&app, &ordinary, None, false).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(
        call(
            &app,
            narrowed["access_token"].as_str(),
            "GET",
            "/v1/personal-delegations",
            Value::Null
        )
        .await
        .0,
        StatusCode::FORBIDDEN
    );
    let other = public_token(
        &app,
        &format!("{DEFAULT_SESSION_COOKIE_NAME}=native-session-grace"),
        "openid iam.personal-delegation.manage",
    )
    .await;
    let (status, other) =
        exchange(&app, &other, Some(PERSONAL_DELEGATION_CONSENT_SCOPE), false).await;
    assert_eq!(status, StatusCode::OK);
    let (_, page) = call(
        &app,
        other["access_token"].as_str(),
        "GET",
        "/v1/personal-delegations",
        Value::Null,
    )
    .await;
    assert_eq!(page["items"].as_array().unwrap().len(), 1);
    assert_eq!(page["items"][0]["id"], "foreign");
    // Deliberately native-signed wrong-purpose/principal credentials isolate
    // the list fence; successful owner admission above came through real PKCE.
    let wrong_principal = auth
        .lock()
        .await
        .token_authority()
        .mint(&AccessTokenClaims {
            iss: ISSUER.into(),
            sub: "service-owner".into(),
            subject_kind: AccessTokenSubjectKind::Service,
            aud: PERSONAL_DELEGATION_CONSENT_AUDIENCE.into(),
            exp: now() + 600,
            iat: now() - 1,
            jti: "list-service-jti".into(),
            scope: vec![PERSONAL_DELEGATION_CONSENT_SCOPE.into()],
        })
        .await
        .unwrap();
    assert_eq!(
        call(
            &app,
            Some(&wrong_principal),
            "GET",
            "/v1/personal-delegations",
            Value::Null
        )
        .await
        .0,
        StatusCode::FORBIDDEN
    );
    let expired = auth
        .lock()
        .await
        .mint_access_token(MintAccessToken {
            issuer: ISSUER.into(),
            subject: "ada".into(),
            audience: PERSONAL_DELEGATION_CONSENT_AUDIENCE.into(),
            issued_at: now() - 600,
            expires_at: now() - 1,
            scopes: vec![PERSONAL_DELEGATION_CONSENT_SCOPE.into()],
        })
        .await
        .unwrap();
    assert_eq!(
        call(
            &app,
            Some(&expired),
            "GET",
            "/v1/personal-delegations",
            Value::Null
        )
        .await
        .0,
        StatusCode::FORBIDDEN
    );
    let mut account = AccountRepository::get(&*store, &AccountId("ada".into()))
        .unwrap()
        .unwrap();
    account.status = AccountStatus::Disabled;
    AccountRepository::upsert(&*store, account).unwrap();
    assert_eq!(
        call(
            &app,
            Some(token),
            "GET",
            "/v1/personal-delegations",
            Value::Null
        )
        .await
        .0,
        StatusCode::FORBIDDEN
    );
}
