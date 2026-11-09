//! Real native storage, protocol and credential-family composition.
use super::tests::fixture;
use super::*;
use crate::{AdminAuthPolicy, AuthzApi, DaemonState, SqlConn, SqlStore};
use awaken_iam_contract::{ActionKey, CreatePersonalDelegation, ScopeRef, WorkspaceId};
use awaken_iam_core::{
    AccountRepository, ClientDelegation, ClientTokenExchangePolicy, ExternalIdentityRepository,
    GroupRepository, PersonalDelegationRepository, RegisteredClient, SessionRepository,
    hash_session_token,
};
use axum::{
    Router,
    body::{Body, to_bytes},
    http::{Request, StatusCode},
};
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use serde_json::Value;
use sha2::{Digest, Sha256};
use tower::ServiceExt as _;

const ISSUER: &str = "https://iam.example";
const VERIFIER: &str = "a-real-public-pkce-verifier-with-sufficient-entropy";
const REDIRECT: &str = "https://desk.example/callback";

fn configured<B: SqlConn + Clone + 'static>(
    store: &Arc<SqlStore<B>>,
) -> (AuthApi, AccessTokenAuthority, ChannelAssertionClaims) {
    let (seed, source, signer, claims) = fixture();
    AccountRepository::upsert(
        &**store,
        AccountRepository::get(&source, &AccountId("alice".into()))
            .unwrap()
            .unwrap(),
    )
    .unwrap();
    ExternalIdentityRepository::link(
        &**store,
        ExternalIdentityRepository::get_by_key(
            &source,
            &awaken_iam_contract::ExternalIdentityKey {
                provider_key: IdentityProviderKey("feishu:tenant:app".into()),
                subject: ExternalSubject("ou_alice".into()),
            },
        )
        .unwrap()
        .unwrap(),
    )
    .unwrap();
    GroupRepository::upsert(
        &**store,
        GroupRepository::get(&source, &GroupId("members".into()))
            .unwrap()
            .unwrap(),
    )
    .unwrap();
    let mut api = AuthApi::new()
        .with_issuer(ISSUER)
        .with_identity_repositories(store.clone(), store.clone(), store.clone())
        .with_channel_groups(store.clone())
        .with_session_repository(store.clone())
        .with_oauth_repositories(store.clone(), store.clone());
    api.register_oauth_client(RegisteredClient::confidential(
        "flow-channel",
        "mock-client-secret",
        vec!["https://flow.example/cb".into()],
        ["openid"],
    ))
    .unwrap();
    api.register_channel_verifier(
        seed.channel_authentication
            .verifiers
            .values()
            .next()
            .unwrap()
            .clone(),
    )
    .unwrap();
    api.register_oauth_client(
        RegisteredClient::confidential(
            "proof-consumer",
            "mock-proof-consumer-secret",
            vec!["https://consumer.example/cb".into()],
            [format!("channel.message:{}", claims.body_sha256)],
        )
        .with_token_exchange(ClientTokenExchangePolicy {
            audiences: Default::default(),
            delegation: Some(ClientDelegation {
                service_id: "proof-consumer-service".into(),
                audiences: ["product".into()].into(),
                subject_audiences: ["urn:awaken:iam:channel-principal".into()].into(),
            }),
        }),
    )
    .unwrap();
    api.register_oauth_client(
        RegisteredClient::public(
            "desk",
            vec![REDIRECT.into()],
            ["openid", crate::PERSONAL_DELEGATION_CONSENT_SCOPE],
        )
        .with_token_exchange(ClientTokenExchangePolicy {
            audiences: [crate::PERSONAL_DELEGATION_CONSENT_AUDIENCE.into()].into(),
            delegation: None,
        }),
    )
    .unwrap();
    (api, signer, claims)
}

async fn form(app: &Router, fields: &[(&str, &str)]) -> (StatusCode, Value) {
    let mut encoded = url::form_urlencoded::Serializer::new(String::new());
    for (key, value) in fields {
        encoded.append_pair(key, value);
    }
    let response = app
        .clone()
        .oneshot(
            Request::post("/v1/oauth/token")
                .header("content-type", "application/x-www-form-urlencoded")
                .body(Body::from(encoded.finish()))
                .unwrap(),
        )
        .await
        .unwrap();
    let status = response.status();
    let body = to_bytes(response.into_body(), 65536).await.unwrap();
    (status, serde_json::from_slice(&body).unwrap())
}
async fn call(
    app: &Router,
    token: &str,
    method: &str,
    path: &str,
    value: Value,
) -> (StatusCode, Value) {
    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .method(method)
                .uri(path)
                .header("authorization", format!("Bearer {token}"))
                .header("content-type", "application/json")
                .body(Body::from(value.to_string()))
                .unwrap(),
        )
        .await
        .unwrap();
    let status = response.status();
    (
        status,
        serde_json::from_slice(&to_bytes(response.into_body(), 65536).await.unwrap())
            .unwrap_or(Value::Null),
    )
}
async fn channel(
    app: &Router,
    signer: &AccessTokenAuthority,
    claims: &ChannelAssertionClaims,
) -> (StatusCode, Value) {
    let assertion = signer.sign_claims(claims).await.unwrap();
    form(
        app,
        &[
            (
                "grant_type",
                awaken_iam_contract::CHANNEL_ASSERTION_GRANT_TYPE,
            ),
            ("client_id", "flow-channel"),
            ("client_secret", "mock-client-secret"),
            ("assertion", &assertion),
        ],
    )
    .await
}

async fn public_pkce(app: &Router) -> String {
    let challenge = URL_SAFE_NO_PAD.encode(Sha256::digest(VERIFIER.as_bytes()));
    let query = url::form_urlencoded::Serializer::new(String::new())
        .append_pair("client_id", "desk")
        .append_pair("redirect_uri", REDIRECT)
        .append_pair("response_type", "code")
        .append_pair("scope", "openid iam.personal-delegation.manage")
        .append_pair("state", "channel-proof-pkce-state")
        .append_pair("code_challenge", &challenge)
        .append_pair("code_challenge_method", "S256")
        .finish();
    let response = app
        .clone()
        .oneshot(
            Request::get(format!("/v1/oauth/authorize?{query}"))
                .header(
                    "cookie",
                    format!(
                        "{}=native-alice-session",
                        crate::DEFAULT_SESSION_COOKIE_NAME
                    ),
                )
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
            .find(|(k, _)| k == "state")
            .unwrap()
            .1,
        "channel-proof-pkce-state"
    );
    let code = location
        .query_pairs()
        .find(|(k, _)| k == "code")
        .unwrap()
        .1
        .into_owned();
    let fields = [
        ("grant_type", "authorization_code"),
        ("client_id", "desk"),
        ("redirect_uri", REDIRECT),
        ("code", code.as_str()),
        ("code_verifier", VERIFIER),
    ];
    let (status, grant) = form(app, &fields).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(
        form(app, &fields).await.0,
        StatusCode::BAD_REQUEST,
        "PKCE code remains single use"
    );
    grant["access_token"].as_str().unwrap().to_owned()
}

async fn exercise<B: SqlConn + Clone + 'static>(store: SqlStore<B>, prefix: &str) {
    let store = Arc::new(store);
    let (api, signer, mut claims) = configured(&store);
    let now = crate::clock::unix_seconds() as i64;
    claims.iat = now;
    claims.exp = now + 120;
    SessionRepository::create(
        &*store,
        awaken_iam_contract::Session {
            id: awaken_iam_contract::SessionId("channel-proof-session".into()),
            account_id: AccountId("alice".into()),
            token_hash: hash_session_token("native-alice-session"),
            external_identity_id: None,
            created_at: Timestamp("2026-01-01T00:00:00Z".into()),
            last_seen_at: Timestamp("2026-01-01T00:00:00Z".into()),
            expires_at: Timestamp("2099-01-01T00:00:00Z".into()),
            revoked_at: None,
        },
    )
    .unwrap();
    let daemon = Arc::new(std::sync::Mutex::new(
        DaemonState::with_policy_store(
            AuthzApi::new(),
            AdminAuthPolicy::deny_all(),
            store.clone(),
            (*store).clone(),
            api.token_authority(),
        )
        .unwrap(),
    ));
    let shared = Arc::new(tokio::sync::Mutex::new(api));
    let app =
        crate::personal_delegation_router(shared.clone(), daemon, store.clone(), ISSUER.into())
            .merge(crate::op_router(
                shared.clone(),
                ISSUER,
                crate::ProviderLoginRouteOwner::Iam,
            ));
    let (status, grant) = channel(&app, &signer, &claims).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(
        grant["principal"],
        serde_json::to_value(PrincipalRef::Account {
            account_id: AccountId("alice".into())
        })
        .unwrap()
    );
    assert_eq!(
        grant["token_type"],
        awaken_iam_contract::CHANNEL_MESSAGE_PROOF_TOKEN_TYPE
    );
    let proof = grant["access_token"].as_str().unwrap();
    let jwks = shared.lock().await.jwks();
    let payload: awaken_iam_contract::ChannelMessageProofClaims = crate::access_token::verify_jwt(
        proof,
        &jwks,
        awaken_iam_contract::CHANNEL_MESSAGE_PROOF_TYP,
    )
    .unwrap();
    assert_eq!(payload.message_id, claims.message_id);
    assert_eq!(payload.body_sha256, claims.body_sha256);
    assert_eq!(
        payload.principal,
        PrincipalRef::Account {
            account_id: AccountId("alice".into())
        }
    );
    assert!(crate::verify_access_token(proof, &jwks).is_err());
    assert!(crate::verify_delegated_access_token(proof, &jwks).is_err());
    assert!(shared.lock().await.verify_access_token(proof).is_err());
    assert!(
        shared
            .lock()
            .await
            .verify_delegated_access_token(proof)
            .is_err()
    );
    assert!(
        serde_json::from_value::<AccessTokenClaims>(serde_json::to_value(&payload).unwrap())
            .is_err()
    );
    // Even changing only the header back to the legacy access family cannot
    // make the different proof payload an Account credential.
    let retyped = shared
        .lock()
        .await
        .token_authority()
        .sign_jwt(crate::access_token::ACCESS_TOKEN_TYP, &payload)
        .await
        .unwrap();
    assert!(crate::verify_access_token(&retyped, &jwks).is_err());
    assert_eq!(
        call(&app, proof, "GET", "/v1/oauth/userinfo", Value::Null)
            .await
            .0,
        StatusCode::UNAUTHORIZED
    );
    let exchanged = form(
        &app,
        &[
            (
                "grant_type",
                "urn:ietf:params:oauth:grant-type:token-exchange",
            ),
            ("client_id", "proof-consumer"),
            ("client_secret", "mock-proof-consumer-secret"),
            ("subject_token", proof),
            ("subject_token_type", crate::SUBJECT_TOKEN_TYPE_ACCESS_TOKEN),
            ("audience", "product"),
        ],
    )
    .await;
    assert_eq!(exchanged.0, StatusCode::BAD_REQUEST);
    assert_eq!(exchanged.1["error"], "invalid_grant");
    let consent = CreatePersonalDelegation {
        request_key: "proof-is-not-consent".into(),
        recipient_client_id: "unregistered-recipient".into(),
        audience: "product".into(),
        actions: vec![ActionKey("example.read".into())],
        scopes: vec![ScopeRef::Workspace {
            workspace_id: WorkspaceId("workspace".into()),
        }],
        valid_from: now,
        valid_until: now + 100,
    };
    for (method, path, body) in [
        ("GET", "/v1/personal-delegations", Value::Null),
        (
            "POST",
            "/v1/personal-delegations",
            serde_json::to_value(consent).unwrap(),
        ),
        ("GET", "/v1/personal-delegations/not-a-grant", Value::Null),
        (
            "POST",
            "/v1/personal-delegations/not-a-grant/revoke",
            Value::Null,
        ),
    ] {
        assert_eq!(
            call(&app, proof, method, path, body).await.0,
            StatusCode::FORBIDDEN,
            "{method} {path}"
        );
    }
    assert!(
        store
            .list_personal_delegations(&AccountId("alice".into()), &Default::default())
            .unwrap()
            .items
            .is_empty()
    );
    let ordinary = public_pkce(&app).await;
    assert_eq!(
        call(&app, &ordinary, "GET", "/v1/oauth/userinfo", Value::Null)
            .await
            .0,
        StatusCode::OK
    );
    let (status, management) = form(
        &app,
        &[
            (
                "grant_type",
                "urn:ietf:params:oauth:grant-type:token-exchange",
            ),
            ("client_id", "desk"),
            ("subject_token", &ordinary),
            ("subject_token_type", crate::SUBJECT_TOKEN_TYPE_ACCESS_TOKEN),
            ("audience", crate::PERSONAL_DELEGATION_CONSENT_AUDIENCE),
            ("scope", crate::PERSONAL_DELEGATION_CONSENT_SCOPE),
        ],
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(
        call(
            &app,
            management["access_token"].as_str().unwrap(),
            "GET",
            "/v1/personal-delegations",
            Value::Null
        )
        .await
        .0,
        StatusCode::OK
    );
    for field in ["installation", "connector", "audience", "digest", "sender"] {
        let mut bad = claims.clone();
        match field {
            "installation" => bad.installation_id = "foreign".into(),
            "connector" => bad.connector_id = "foreign".into(),
            "audience" => bad.aud = "foreign".into(),
            "digest" => bad.body_sha256 = "invalid".into(),
            "sender" => bad.sub = "unknown".into(),
            _ => unreachable!(),
        }
        assert_eq!(
            channel(&app, &signer, &bad).await.0,
            StatusCode::BAD_REQUEST,
            "{field}"
        );
    }
    let rogue = AccessTokenAuthority::new(crate::LocalSeedSigner::new("mock-verifier", [18; 32]));
    assert_eq!(
        channel(&app, &rogue, &claims).await.0,
        StatusCode::BAD_REQUEST
    );
    let mut account = AccountRepository::get(&*store, &AccountId("alice".into()))
        .unwrap()
        .unwrap();
    account.status = AccountStatus::Disabled;
    AccountRepository::upsert(&*store, account.clone()).unwrap();
    assert_eq!(
        channel(&app, &signer, &claims).await.0,
        StatusCode::BAD_REQUEST
    );
    account.status = AccountStatus::Active;
    AccountRepository::upsert(&*store, account).unwrap();
    let mut group = GroupRepository::get(&*store, &GroupId("members".into()))
        .unwrap()
        .unwrap();
    let members = group.members.clone();
    group.members.clear();
    GroupRepository::upsert(&*store, group.clone()).unwrap();
    assert_eq!(
        channel(&app, &signer, &claims).await.0,
        StatusCode::BAD_REQUEST
    );
    group.members = members;
    GroupRepository::upsert(&*store, group).unwrap();
    assert_eq!(channel(&app, &signer, &claims).await.0, StatusCode::OK);
    // Drop only this fixture's native table. The real SQL read must become
    // unavailable and may not reuse the previously accepted identity/Groups.
    store
        .backend()
        .execute(&format!("DROP TABLE {prefix}_groups"), &[])
        .unwrap();
    let (status, body) = channel(&app, &signer, &claims).await;
    assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE);
    assert_eq!(body["error"], "temporarily_unavailable");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn sqlite_channel_proofs_stay_outside_account_routes_and_use_native_current_owners() {
    exercise(
        crate::sqlite_in_memory_store("channel_proof_sqlite").unwrap(),
        "channel_proof_sqlite",
    )
    .await;
}
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn postgres_channel_proofs_stay_outside_account_routes_and_use_native_current_owners() {
    let Ok(url) = std::env::var("IAM_TEST_POSTGRES_URL") else {
        assert!(
            std::env::var_os("AWAKEN_TEST_REQUIRE_POSTGRES").is_none(),
            "required PostgreSQL fixture missing"
        );
        return;
    };
    let prefix = format!(
        "channel_proof_{:x}",
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    );
    exercise(
        crate::postgres_migrated_store(&url, &prefix).unwrap(),
        &prefix,
    )
    .await;
}
