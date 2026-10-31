//! RFC 8693 exchange between IAM access tokens over `POST /v1/oauth/token`
//! (ADR-0017): browser audience exchange and business-service delegation.
//!
//! Every admitted and refused path is driven through the real Axum OP router;
//! issued tokens are verified with only the published JWKS, exactly as a
//! relying party (Flow, Awaken via `IamGate`) does.

use std::collections::BTreeSet;
use std::sync::Arc;

use awaken_iam_contract::{Account, AccountId, AccountStatus, Timestamp};
use awaken_iam_core::{ClientDelegation, ClientTokenExchangePolicy, RegisteredClient};
use awaken_iam_server::{
    AccessTokenActor, AccessTokenClaims, AccessTokenExchangeError, AccessTokenSubjectKind, AuthApi,
    AuthAuditEvent, DELEGATED_TOKEN_MAX_LIFETIME_SECS, DelegatedAccessTokenClaims, MintAccessToken,
    ProviderLoginRouteOwner, RevokeToken, RevokeTokenHint, SharedAuthApi, op_router,
    verify_delegated_access_token,
};
use axum::{
    Router,
    body::Body,
    http::{Request, StatusCode, header},
};
use tokio::sync::Mutex;
use tower::ServiceExt;

const ISSUER: &str = "https://iam.example";
const ACCESS_TOKEN: &str = "urn:ietf:params:oauth:token-type:access_token";
const EXCHANGE: &str = "urn:ietf:params:oauth:grant-type:token-exchange";
const BUSINESS_SECRET: &str = "business-secret";

/// One refused request: field overrides, expected status and OAuth error code.
type Refusal<'a> = (Vec<(&'a str, &'a str)>, StatusCode, &'static str);

fn now() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs() as i64
}

fn set(values: &[&str]) -> BTreeSet<String> {
    values.iter().map(|value| (*value).to_owned()).collect()
}

fn account(id: &str, status: AccountStatus) -> Account {
    Account {
        id: AccountId(id.into()),
        status,
        display_name: None,
        created_at: Timestamp("2026-01-01T00:00:00Z".into()),
        updated_at: Timestamp("2026-01-01T00:00:00Z".into()),
    }
}

/// The enterprise topology from the architecture: a public SPA allowed to
/// re-target its users' tokens at Flow and the business service, a
/// confidential business service allowed to act for users toward Flow, and a
/// plain client admitted to nothing.
fn configured() -> AuthApi {
    let mut api = AuthApi::new().with_issuer(ISSUER);
    api.register_oauth_client(
        RegisteredClient::public(
            "enterprise-web",
            vec!["https://app.example/callback".into()],
            ["openid", "flow.read", "business.command"],
        )
        .with_token_exchange(ClientTokenExchangePolicy {
            audiences: set(&["flow", "business"]),
            delegation: None,
        }),
    )
    .unwrap();
    api.register_oauth_client(
        RegisteredClient::confidential(
            "business",
            BUSINESS_SECRET,
            vec!["https://business.example/callback".into()],
            ["flow.read", "flow.write", "business.command"],
        )
        .with_token_exchange(ClientTokenExchangePolicy {
            audiences: BTreeSet::new(),
            delegation: Some(ClientDelegation {
                service_id: "svc-business".into(),
                audiences: set(&["flow"]),
                subject_audiences: BTreeSet::new(),
            }),
        }),
    )
    .unwrap();
    api.register_oauth_client(RegisteredClient::public(
        "plain",
        vec!["https://plain.example/callback".into()],
        ["openid"],
    ))
    .unwrap();
    api.upsert_account(account("acct_ada", AccountStatus::Active))
        .unwrap();
    api.upsert_account(account("acct_off", AccountStatus::Disabled))
        .unwrap();
    api
}

async fn user_token(
    api: &mut AuthApi,
    subject: &str,
    audience: &str,
    scopes: &[&str],
    lifetime: i64,
) -> String {
    let issued_at = now() - 5;
    api.mint_access_token(MintAccessToken {
        issuer: ISSUER.into(),
        subject: subject.into(),
        audience: audience.into(),
        issued_at,
        expires_at: issued_at + lifetime,
        scopes: scopes.iter().map(|scope| (*scope).to_owned()).collect(),
    })
    .await
    .unwrap()
}

async fn raw_token(api: &AuthApi, claims: AccessTokenClaims) -> String {
    api.token_authority().mint(&claims).await.unwrap()
}

fn claims(sub: &str, kind: AccessTokenSubjectKind, aud: &str) -> AccessTokenClaims {
    AccessTokenClaims {
        iss: ISSUER.into(),
        sub: sub.into(),
        subject_kind: kind,
        aud: aud.into(),
        exp: now() + 600,
        iat: now() - 5,
        jti: format!("jti-raw-{sub}-{aud}"),
        scope: vec!["flow.read".into()],
    }
}

fn router(api: AuthApi) -> (Router, SharedAuthApi) {
    let shared = Arc::new(Mutex::new(api));
    (
        op_router(shared.clone(), ISSUER, ProviderLoginRouteOwner::Iam),
        shared,
    )
}

async fn exchange(app: &Router, fields: &[(&str, &str)]) -> (StatusCode, serde_json::Value) {
    let mut form = url::form_urlencoded::Serializer::new(String::new());
    form.append_pair("grant_type", EXCHANGE);
    for (key, value) in fields {
        form.append_pair(key, value);
    }
    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/v1/oauth/token")
                .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
                .body(Body::from(form.finish()))
                .unwrap(),
        )
        .await
        .unwrap();
    let status = response.status();
    let bytes = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .unwrap();
    (status, serde_json::from_slice(&bytes).unwrap())
}

/// Verify like a relying party: claims plus the RFC 8693 actor.
async fn verified(shared: &SharedAuthApi, token: &str) -> DelegatedAccessTokenClaims {
    verify_delegated_access_token(token, &shared.lock().await.jwks()).unwrap()
}

/// Audience exchange decision table (browser SPA, public client + PKCE):
///
/// | subject token | params | result |
/// |---|---|---|
/// | issued to the SPA, live | audience in allowlist, narrower scope | 200: sub unchanged, aud = target, scope narrowed, no act, exp ≤ subject |
/// | same | scope omitted | 200: subject scope ∩ client registration |
/// | same | scope widened | 400 invalid_scope |
/// | same | audience outside allowlist | 400 invalid_target |
/// | issued to another client | allowed audience | 400 invalid_grant |
/// | expired / revoked / disabled account | allowed audience | 400 invalid_grant |
/// | client admitted to nothing | any audience | 400 unauthorized_client |
/// | unknown client | any | 401 invalid_client |
/// | missing audience/subject, foreign token types, resource | any | 400 invalid_request / invalid_target |
#[tokio::test]
async fn audience_exchange_narrows_and_refuses_every_other_shape() {
    let mut api = configured();
    let subject_lifetime = 1_800;
    let spa_token = user_token(
        &mut api,
        "acct_ada",
        "enterprise-web",
        &["openid", "flow.read", "business.command"],
        subject_lifetime,
    )
    .await;
    let foreign = user_token(&mut api, "acct_ada", "business", &["flow.read"], 600).await;
    let expired = user_token(&mut api, "acct_ada", "enterprise-web", &["flow.read"], 1).await;
    let revoked = user_token(&mut api, "acct_ada", "enterprise-web", &["flow.read"], 600).await;
    api.revoke_token(RevokeToken {
        token: revoked.clone(),
        token_type_hint: Some(RevokeTokenHint::AccessToken),
        now: Timestamp("2026-10-31T00:00:00Z".into()),
    });
    let disabled = user_token(&mut api, "acct_off", "enterprise-web", &["flow.read"], 600).await;
    let plain = user_token(&mut api, "acct_ada", "plain", &["openid"], 600).await;
    let spa_jti = verify_jti(&spa_token);
    let (app, shared) = router(api);

    let (status, body) = exchange(
        &app,
        &[
            ("client_id", "enterprise-web"),
            ("subject_token", &spa_token),
            ("subject_token_type", ACCESS_TOKEN),
            ("audience", "flow"),
            ("scope", "flow.read"),
        ],
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(body["issued_token_type"], ACCESS_TOKEN);
    assert_eq!(body["token_type"], "Bearer");
    assert_eq!(body["scope"], "flow.read");
    assert!(body.get("refresh_token").is_none());
    let issued = verified(&shared, body["access_token"].as_str().unwrap()).await;
    let subject = verified(&shared, &spa_token).await;
    assert_eq!(issued.claims.sub, "acct_ada");
    assert_eq!(issued.claims.subject_kind, AccessTokenSubjectKind::Account);
    assert_eq!(issued.claims.aud, "flow");
    assert_eq!(issued.claims.scope, vec!["flow.read".to_owned()]);
    assert_eq!(issued.act, None);
    assert!(issued.claims.exp <= subject.claims.exp);
    assert_ne!(issued.claims.jti, subject.claims.jti);

    let (status, body) = exchange(
        &app,
        &[
            ("client_id", "enterprise-web"),
            ("subject_token", &spa_token),
            ("subject_token_type", ACCESS_TOKEN),
            ("audience", "business"),
        ],
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(body["scope"], "openid flow.read business.command");

    let refusals: Vec<Refusal> = vec![
        (
            vec![("scope", "flow.read flow.write")],
            StatusCode::BAD_REQUEST,
            "invalid_scope",
        ),
        (
            vec![("audience", "billing")],
            StatusCode::BAD_REQUEST,
            "invalid_target",
        ),
        (
            vec![("subject_token", &foreign)],
            StatusCode::BAD_REQUEST,
            "invalid_grant",
        ),
        (
            vec![("subject_token", &expired)],
            StatusCode::BAD_REQUEST,
            "invalid_grant",
        ),
        (
            vec![("subject_token", &revoked)],
            StatusCode::BAD_REQUEST,
            "invalid_grant",
        ),
        (
            vec![("subject_token", &disabled)],
            StatusCode::BAD_REQUEST,
            "invalid_grant",
        ),
        (
            vec![("subject_token", "not-a-jwt")],
            StatusCode::BAD_REQUEST,
            "invalid_grant",
        ),
        (
            vec![("client_id", "plain"), ("subject_token", &plain)],
            StatusCode::BAD_REQUEST,
            "unauthorized_client",
        ),
        (
            vec![("client_id", "ghost")],
            StatusCode::UNAUTHORIZED,
            "invalid_client",
        ),
        (
            vec![("audience", "")],
            StatusCode::BAD_REQUEST,
            "invalid_request",
        ),
        (
            vec![("subject_token_type", "urn:ietf:params:oauth:token-type:jwt")],
            StatusCode::BAD_REQUEST,
            "invalid_request",
        ),
        (
            vec![(
                "requested_token_type",
                "urn:ietf:params:oauth:token-type:refresh_token",
            )],
            StatusCode::BAD_REQUEST,
            "invalid_request",
        ),
        (
            vec![("resource", "https://flow.example/api")],
            StatusCode::BAD_REQUEST,
            "invalid_target",
        ),
    ];
    for (overrides, expected_status, expected_code) in refusals {
        let mut fields = vec![
            ("client_id", "enterprise-web"),
            ("subject_token", spa_token.as_str()),
            ("subject_token_type", ACCESS_TOKEN),
            ("audience", "flow"),
        ];
        for (key, value) in &overrides {
            match fields.iter_mut().find(|(existing, _)| existing == key) {
                Some(field) => field.1 = value,
                None => fields.push((key, value)),
            }
        }
        let (status, body) = exchange(&app, &fields).await;
        assert_eq!(status, expected_status, "{overrides:?}: {body}");
        assert_eq!(body["error"], expected_code, "{overrides:?}");
    }

    let (status, body) = exchange(
        &app,
        &[
            ("client_id", "enterprise-web"),
            ("subject_token_type", ACCESS_TOKEN),
            ("audience", "flow"),
        ],
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(body["error"], "invalid_request");

    let audit = shared.lock().await.audit_log().to_vec();
    assert!(audit.iter().any(|event| matches!(
        event,
        AuthAuditEvent::AccessTokenExchanged { client_id, subject, actor: None, audience, scope, subject_jti, .. }
            if client_id == "enterprise-web" && subject == "acct_ada" && audience == "flow"
                && scope == &vec!["flow.read".to_owned()] && subject_jti == &spa_jti
    )));
    assert!(audit.iter().any(|event| matches!(
        event,
        AuthAuditEvent::AccessTokenExchangeRejected {
            reason: AccessTokenExchangeError::ScopeNotAllowed,
            ..
        }
    )));
    assert!(audit.iter().any(|event| matches!(
        event,
        AuthAuditEvent::AccessTokenExchangeRejected {
            reason: AccessTokenExchangeError::SubjectTokenRevoked,
            ..
        }
    )));
}

/// Read a token's `jti` without verification, for audit correlation only.
fn verify_jti(token: &str) -> String {
    awaken_iam_server::decode_unverified_claims::<AccessTokenClaims>(token)
        .unwrap()
        .jti
}

/// Delegation decision table (business service = authenticated confidential
/// client, its service principal becomes `act`):
///
/// | client auth | subject token | params | result |
/// |---|---|---|---|
/// | secret ok | user token for the service | delegation audience, narrower scope | 200: sub user, act service, aud target, exp ≤ 300 s and ≤ subject |
/// | secret ok | subject expiring sooner | same | 200: exp = subject exp |
/// | secret wrong / missing | any | any | 401 invalid_client |
/// | secret ok | any | `actor_token` presented | 400 invalid_request (client is the actor) |
/// | secret ok | already delegated (`act`) | same | 400 invalid_grant (single level) |
/// | secret ok | service principal as subject | same | 400 invalid_grant |
/// | secret ok | user token for an unlisted client | same | 400 invalid_grant |
/// | secret ok | user token | widened scope | 400 invalid_scope |
/// | secret ok | user token | non-delegation audience | 400 invalid_target |
#[tokio::test]
async fn delegation_records_the_service_actor_and_refuses_every_other_shape() {
    let mut api = configured();
    let spa_token = user_token(
        &mut api,
        "acct_ada",
        "enterprise-web",
        &["openid", "flow.read", "business.command"],
        1_800,
    )
    .await;
    let short = user_token(&mut api, "acct_ada", "business", &["flow.read"], 120).await;
    let nested = api
        .token_authority()
        .mint_delegated(&DelegatedAccessTokenClaims {
            claims: claims("acct_ada", AccessTokenSubjectKind::Account, "business"),
            act: Some(AccessTokenActor {
                sub: "svc-other".into(),
                subject_kind: AccessTokenSubjectKind::Service,
            }),
        })
        .await
        .unwrap();
    let service_subject = raw_token(
        &api,
        claims("svc-batch", AccessTokenSubjectKind::Service, "business"),
    )
    .await;
    let (app, shared) = router(api);

    // The browser first re-targets its token at the business service, which
    // then exchanges that token for a delegated Flow token.
    let (status, body) = exchange(
        &app,
        &[
            ("client_id", "enterprise-web"),
            ("subject_token", &spa_token),
            ("subject_token_type", ACCESS_TOKEN),
            ("audience", "business"),
            ("scope", "flow.read business.command"),
        ],
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    let business_token = body["access_token"].as_str().unwrap().to_owned();

    let started = now();
    let (status, body) = exchange(
        &app,
        &[
            ("client_id", "business"),
            ("client_secret", BUSINESS_SECRET),
            ("subject_token", &business_token),
            ("subject_token_type", ACCESS_TOKEN),
            ("audience", "flow"),
            ("scope", "flow.read"),
        ],
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert!(body["expires_in"].as_i64().unwrap() <= DELEGATED_TOKEN_MAX_LIFETIME_SECS);
    let delegated = verified(&shared, body["access_token"].as_str().unwrap()).await;
    assert_eq!(delegated.claims.sub, "acct_ada");
    assert_eq!(
        delegated.claims.subject_kind,
        AccessTokenSubjectKind::Account
    );
    assert_eq!(delegated.claims.aud, "flow");
    assert_eq!(delegated.claims.scope, vec!["flow.read".to_owned()]);
    assert_eq!(
        delegated.act,
        Some(AccessTokenActor {
            sub: "svc-business".into(),
            subject_kind: AccessTokenSubjectKind::Service,
        })
    );
    assert!(delegated.claims.exp <= now() + DELEGATED_TOKEN_MAX_LIFETIME_SECS);
    assert!(delegated.claims.exp >= started + DELEGATED_TOKEN_MAX_LIFETIME_SECS - 1);
    assert!(delegated.claims.exp <= verified(&shared, &business_token).await.claims.exp);

    let (status, body) = exchange(
        &app,
        &[
            ("client_id", "business"),
            ("client_secret", BUSINESS_SECRET),
            ("subject_token", &short),
            ("subject_token_type", ACCESS_TOKEN),
            ("audience", "flow"),
        ],
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    let bounded = verified(&shared, body["access_token"].as_str().unwrap()).await;
    assert_eq!(
        bounded.claims.exp,
        verified(&shared, &short).await.claims.exp
    );

    // A delegated token cannot be exchanged again: delegation is single-level.
    let redelegated = body["access_token"].as_str().unwrap().to_owned();
    let (status, body) = exchange(
        &app,
        &[
            ("client_id", "business"),
            ("client_secret", BUSINESS_SECRET),
            ("subject_token", &redelegated),
            ("subject_token_type", ACCESS_TOKEN),
            ("audience", "flow"),
        ],
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(body["error"], "invalid_grant");

    let refusals: Vec<Refusal> = vec![
        (
            vec![("client_secret", "wrong")],
            StatusCode::UNAUTHORIZED,
            "invalid_client",
        ),
        (
            vec![
                ("actor_token", &spa_token),
                ("actor_token_type", ACCESS_TOKEN),
            ],
            StatusCode::BAD_REQUEST,
            "invalid_request",
        ),
        (
            vec![("subject_token", &nested)],
            StatusCode::BAD_REQUEST,
            "invalid_grant",
        ),
        (
            vec![("subject_token", &service_subject)],
            StatusCode::BAD_REQUEST,
            "invalid_grant",
        ),
        (
            vec![("subject_token", &spa_token)],
            StatusCode::BAD_REQUEST,
            "invalid_grant",
        ),
        (
            vec![("scope", "flow.read flow.admin")],
            StatusCode::BAD_REQUEST,
            "invalid_scope",
        ),
        (
            vec![("audience", "business")],
            StatusCode::BAD_REQUEST,
            "invalid_target",
        ),
    ];
    for (overrides, expected_status, expected_code) in refusals {
        let mut fields = vec![
            ("client_id", "business"),
            ("client_secret", BUSINESS_SECRET),
            ("subject_token", business_token.as_str()),
            ("subject_token_type", ACCESS_TOKEN),
            ("audience", "flow"),
        ];
        for (key, value) in &overrides {
            match fields.iter_mut().find(|(existing, _)| existing == key) {
                Some(field) => field.1 = value,
                None => fields.push((key, value)),
            }
        }
        let (status, body) = exchange(&app, &fields).await;
        assert_eq!(status, expected_status, "{overrides:?}: {body}");
        assert_eq!(body["error"], expected_code, "{overrides:?}");
    }

    // Missing secret on the confidential client is client-authentication
    // failure, never an anonymous delegation.
    let (status, body) = exchange(
        &app,
        &[
            ("client_id", "business"),
            ("subject_token", &business_token),
            ("subject_token_type", ACCESS_TOKEN),
            ("audience", "flow"),
        ],
    )
    .await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
    assert_eq!(body["error"], "invalid_client");

    let audit = shared.lock().await.audit_log().to_vec();
    let business_jti = verify_jti(&business_token);
    assert!(audit.iter().any(|event| matches!(
        event,
        AuthAuditEvent::AccessTokenExchanged {
            client_id, subject, actor: Some(actor), audience, subject_jti, jti, ..
        } if client_id == "business" && subject == "acct_ada" && actor == "svc-business"
            && audience == "flow" && subject_jti == &business_jti && jti == &delegated.claims.jti
    )));
    for reason in [
        AccessTokenExchangeError::InvalidClient,
        AccessTokenExchangeError::ActorTokenUnsupported,
        AccessTokenExchangeError::NestedDelegation,
        AccessTokenExchangeError::SubjectNotAccount,
        AccessTokenExchangeError::SubjectAudienceMismatch,
    ] {
        assert!(
            audit.iter().any(|event| matches!(
                event,
                AuthAuditEvent::AccessTokenExchangeRejected { reason: logged, .. } if *logged == reason
            )),
            "{reason:?} audited"
        );
    }
}

/// Discovery advertises the token-exchange grant beside the existing grants
/// and every supported token-endpoint client authentication method.
#[tokio::test]
async fn discovery_advertises_token_exchange() {
    let (app, _) = router(configured());
    let response = app
        .oneshot(
            Request::builder()
                .uri("/.well-known/openid-configuration")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    let bytes = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .unwrap();
    let metadata: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
    assert!(
        metadata["grant_types_supported"]
            .as_array()
            .unwrap()
            .iter()
            .any(|grant| grant == EXCHANGE)
    );
    assert_eq!(
        metadata["token_endpoint_auth_methods_supported"],
        serde_json::json!(["client_secret_basic", "client_secret_post", "none"])
    );
}

async fn token_request(
    app: &Router,
    authorization: Option<&str>,
    body: String,
    content_type: &str,
) -> (StatusCode, axum::http::HeaderMap, serde_json::Value) {
    let mut request = Request::builder()
        .method("POST")
        .uri("/v1/oauth/token")
        .header(header::CONTENT_TYPE, content_type);
    if let Some(authorization) = authorization {
        request = request.header(header::AUTHORIZATION, authorization);
    }
    let response = app
        .clone()
        .oneshot(request.body(Body::from(body)).unwrap())
        .await
        .unwrap();
    let status = response.status();
    let headers = response.headers().clone();
    let bytes = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .unwrap();
    (status, headers, serde_json::from_slice(&bytes).unwrap())
}

fn basic(client_id: &str, secret: &str) -> String {
    use base64::Engine as _;
    format!(
        "Basic {}",
        base64::engine::general_purpose::STANDARD.encode(format!("{client_id}:{secret}"))
    )
}

/// RFC 6749 §2.3.1 client authentication decision table at the token
/// endpoint (shared by every grant):
///
/// | Authorization header | body credentials | result |
/// |---|---|---|
/// | Basic, correct secret | none | 200 (client_secret_basic) |
/// | Basic, correct secret | same client_id only | 200 |
/// | Basic | client_secret too | 400 invalid_request (two methods) |
/// | Basic | different client_id | 400 invalid_request |
/// | Basic, wrong secret | none | 401 invalid_client + WWW-Authenticate: Basic |
/// | malformed Basic | none | 401 invalid_client + challenge |
/// | none | none | 400 invalid_request (never 422) |
/// | any | non-form body | 400 invalid_request (never 422) |
#[tokio::test]
async fn token_endpoint_accepts_client_secret_basic_and_answers_oauth_errors() {
    let mut api = configured();
    let business_token = user_token(&mut api, "acct_ada", "business", &["flow.read"], 600).await;
    let (app, shared) = router(api);
    let mut form = url::form_urlencoded::Serializer::new(String::new());
    form.append_pair("grant_type", EXCHANGE)
        .append_pair("subject_token", &business_token)
        .append_pair("subject_token_type", ACCESS_TOKEN)
        .append_pair("audience", "flow");
    let body = form.finish();
    let urlencoded = "application/x-www-form-urlencoded";
    let good = basic("business", BUSINESS_SECRET);

    let (status, _, json) = token_request(&app, Some(&good), body.clone(), urlencoded).await;
    assert_eq!(status, StatusCode::OK, "{json}");
    let issued = verified(&shared, json["access_token"].as_str().unwrap()).await;
    assert_eq!(
        issued.act.map(|actor| actor.sub),
        Some("svc-business".into())
    );
    let (status, _, _) = token_request(
        &app,
        Some(&good),
        format!("{body}&client_id=business"),
        urlencoded,
    )
    .await;
    assert_eq!(status, StatusCode::OK);

    for (extra, authorization) in [
        (format!("&client_secret={BUSINESS_SECRET}"), good.clone()),
        ("&client_id=enterprise-web".to_owned(), good.clone()),
    ] {
        let (status, _, json) = token_request(
            &app,
            Some(&authorization),
            format!("{body}{extra}"),
            urlencoded,
        )
        .await;
        assert_eq!(status, StatusCode::BAD_REQUEST, "{extra}");
        assert_eq!(json["error"], "invalid_request", "{extra}");
    }
    for authorization in [basic("business", "wrong"), "Basic !!!".to_owned()] {
        let (status, headers, json) =
            token_request(&app, Some(&authorization), body.clone(), urlencoded).await;
        assert_eq!(status, StatusCode::UNAUTHORIZED, "{authorization}");
        assert_eq!(json["error"], "invalid_client");
        assert!(
            headers[header::WWW_AUTHENTICATE]
                .to_str()
                .unwrap()
                .starts_with("Basic")
        );
    }
    let (status, _, json) = token_request(&app, None, body.clone(), urlencoded).await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(json["error"], "invalid_request");
    let (status, _, json) = token_request(&app, Some(&good), "{}".into(), "application/json").await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(json["error"], "invalid_request");
}
