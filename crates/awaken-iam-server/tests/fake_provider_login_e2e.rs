//! End-to-end coverage for the fake-provider login loop.
//!
//! This drives the *whole* third-party login loop — start, identity-provider
//! authorize, callback, session cookie, `/v1/session`, and the authorize
//! decision path — against the deterministic [`FakeOidcProvider`] test double,
//! exactly as a browser would experience it.
//!
//! The MVP exposes the browser-facing auth surface as a framework-agnostic
//! in-process API ([`AuthApi`]) rather than over HTTP, and the workspace ships
//! no web/browser runtime, so the "browser" is simulated here: each step carries
//! the hardened correlation and session cookies across the boundary by value,
//! and the identity provider's authorize endpoint is invoked by parsing the
//! authorization URL the relying party hands back. That keeps the exchange fully
//! deterministic — no network, no wall clock, no flaky browser — while still
//! exercising every hop a real login traverses, including the negative
//! state/replay/expiry and provider-failure paths.
//!
//! A [`FakeOidcAdapter`] bridges the relying-party side of the loop to the
//! provider: it constructs the authorization redirect and, on callback, redeems
//! the code at the provider's token endpoint, verifies the issued `id_token`
//! against the published JWKS, and normalizes the userinfo claims.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use awaken_iam_client::IamClient;
use awaken_iam_contract::{
    ActionKey, AuthorizationDecision, AuthorizationRequest, ExternalIdentityClaims,
    ExternalSubject, IdentityProviderConfig, IdentityProviderConfigId, IdentityProviderKey,
    IdentityProviderKind, PrincipalRef, ScopeRef, Timestamp,
};
use awaken_iam_core::{
    AuthorizationRedirect, AuthorizationUrlRequest, AuthorizeRequest, CallbackExchange,
    EntropySource, FailureMode, FakeOidcProvider, FakeUser, IdentityProviderAdapter, OidcError,
    ProviderError, TokenRequest,
};
use awaken_iam_server::{
    AuthApi, AuthApiError, AuthAuditEvent, AuthFailureReason, CallbackOutcome, CallbackRequest,
    DEFAULT_LOGIN_COOKIE_NAME, DEFAULT_LOGIN_PROOF_COOKIE_NAME, DEFAULT_SESSION_COOKIE_NAME,
    IamServer, ProviderRegistration, ReturnToPolicy, SessionCookieConfig, StartLogin,
    StartLoginOutcome,
};

const ISSUER: &str = "https://idp.test";
const CLIENT_ID: &str = "client-iam";
const REDIRECT_URI: &str = "https://app.test/v1/auth/callback/fake";
const PROVIDER_KEY: &str = "fake";

/// Deterministic entropy so minted ids and secrets are reproducible across runs.
#[derive(Clone, Default)]
struct CountingEntropy {
    next: u8,
}

impl EntropySource for CountingEntropy {
    fn fill_bytes(&mut self, buf: &mut [u8]) {
        for byte in buf.iter_mut() {
            *byte = self.next;
            self.next = self.next.wrapping_add(1);
        }
    }
}

/// Relying-party adapter that speaks the fake provider's OIDC flow.
///
/// Holds a shared handle to the same [`FakeOidcProvider`] the simulated browser
/// drives, so the authorization code minted at authorize time is redeemable at
/// callback time.
struct FakeOidcAdapter {
    provider: Arc<Mutex<FakeOidcProvider>>,
}

impl IdentityProviderAdapter for FakeOidcAdapter {
    fn provider_kind(&self) -> IdentityProviderKind {
        IdentityProviderKind::Fake
    }

    fn authorization_url(
        &self,
        config: &IdentityProviderConfig,
        request: &AuthorizationUrlRequest,
    ) -> Result<AuthorizationRedirect, ProviderError> {
        self.ensure_kind(config)?;
        let issuer = config
            .issuer_url
            .as_deref()
            .ok_or(ProviderError::MissingConfiguration {
                field: "issuer_url",
            })?;
        let client_id = config
            .client_id
            .as_deref()
            .ok_or(ProviderError::MissingConfiguration { field: "client_id" })?;

        let mut url = format!(
            "{issuer}/authorize?response_type=code&client_id={}&redirect_uri={}&state={}&scope={}",
            percent_encode(client_id),
            percent_encode(&request.redirect_uri),
            percent_encode(&request.state),
            percent_encode(&request.scopes.join(" ")),
        );
        if let Some(nonce) = &request.nonce {
            url.push_str(&format!("&nonce={}", percent_encode(nonce)));
        }
        if let Some(pkce) = &request.pkce_challenge {
            url.push_str(&format!(
                "&code_challenge={}&code_challenge_method=S256",
                percent_encode(&pkce.challenge),
            ));
        }
        Ok(AuthorizationRedirect { url })
    }

    fn exchange_callback(
        &self,
        config: &IdentityProviderConfig,
        callback: &CallbackExchange,
    ) -> Result<ExternalIdentityClaims, ProviderError> {
        self.ensure_kind(config)?;
        let client_id = config
            .client_id
            .clone()
            .ok_or(ProviderError::MissingConfiguration { field: "client_id" })?;

        let mut provider = self.provider.lock().expect("provider lock");
        let tokens = provider
            .token(&TokenRequest {
                grant_type: "authorization_code".to_owned(),
                code: callback.code.clone(),
                redirect_uri: callback.redirect_uri.clone(),
                client_id,
                code_verifier: callback.pkce_verifier.clone(),
            })
            .map_err(|err| ProviderError::ExchangeRejected {
                reason: err.to_string(),
            })?;

        // Verify the id_token signature against the published JWKS, then read the
        // user's claims from the userinfo endpoint.
        let id_claims = provider.verify_id_token(&tokens.id_token).map_err(|err| {
            ProviderError::MalformedClaims {
                reason: err.to_string(),
            }
        })?;
        let info = provider.userinfo(&tokens.access_token).map_err(|err| {
            ProviderError::ExchangeRejected {
                reason: err.to_string(),
            }
        })?;

        Ok(ExternalIdentityClaims {
            subject: ExternalSubject(id_claims.sub),
            email: info.email,
            email_verified: info.email_verified,
            display_name: info.name,
            username: info.preferred_username,
            avatar_url: info.picture,
            locale: info.locale,
        })
    }
}

/// Build an [`AuthApi`] wired to a fresh fake provider, returning both so a test
/// can drive the relying party and the simulated identity provider together.
fn setup(failure: Option<FailureMode>) -> (AuthApi<CountingEntropy>, Arc<Mutex<FakeOidcProvider>>) {
    let mut provider = FakeOidcProvider::new(ISSUER, CLIENT_ID)
        .with_user(FakeUser::with_email("user-1", "user@example.com"));
    if let Some(failure) = failure {
        provider = provider.with_failure(failure);
    }
    let shared = Arc::new(Mutex::new(provider));

    let mut api = AuthApi::with_entropy(CountingEntropy::default()).with_return_to_policy(
        ReturnToPolicy::new("/home", ["/dashboard".to_owned(), "/home".to_owned()]),
    );
    api.register_provider(ProviderRegistration {
        config: IdentityProviderConfig {
            id: IdentityProviderConfigId("cfg_fake".into()),
            provider_key: IdentityProviderKey(PROVIDER_KEY.into()),
            kind: IdentityProviderKind::Fake,
            display_name: "Fake".into(),
            issuer_url: Some(ISSUER.into()),
            authorization_endpoint: Some(format!("{ISSUER}/authorize")),
            token_endpoint: Some(format!("{ISSUER}/token")),
            client_id: Some(CLIENT_ID.into()),
            enabled: true,
        },
        adapter: Box::new(FakeOidcAdapter {
            provider: Arc::clone(&shared),
        }),
        redirect_uri: REDIRECT_URI.into(),
        scopes: vec!["openid".into(), "email".into(), "profile".into()],
        include_nonce: true,
        include_pkce: true,
    });

    (api, shared)
}

fn key() -> IdentityProviderKey {
    IdentityProviderKey(PROVIDER_KEY.into())
}

fn ts(value: &str) -> Timestamp {
    Timestamp(value.into())
}

fn begin(api: &mut AuthApi<CountingEntropy>, return_to: Option<&str>) -> StartLoginOutcome {
    api.start_login(StartLogin {
        provider_key: key(),
        return_to: return_to.map(str::to_owned),
        created_at: ts("2026-06-19T00:00:00Z"),
        expires_at: ts("2026-06-19T00:05:00Z"),
        cookie_max_age_secs: Some(300),
    })
    .expect("start login")
}

/// Replay the correlation cookie the start step set, as the browser would.
fn login_cookie_header(outcome: &StartLoginOutcome) -> String {
    format!(
        "{}; {}",
        outcome.set_cookie.split(';').next().unwrap(),
        outcome.set_proof_cookie.split(';').next().unwrap()
    )
}

/// Replay the session cookie the callback established, as the browser would.
fn session_cookie_header(outcome: &CallbackOutcome) -> String {
    let token = SessionCookieConfig::default()
        .extract_token(&outcome.set_session_cookie)
        .expect("session cookie");
    format!("{DEFAULT_SESSION_COOKIE_NAME}={token}")
}

/// Simulate the browser following the authorization redirect: parse the
/// authorization URL, consent at the fake identity provider, and return the
/// callback redirect URL the provider would send the browser back to.
fn idp_authorize(
    provider: &Arc<Mutex<FakeOidcProvider>>,
    authorization_url: &str,
    login_as: Option<&str>,
) -> Result<String, OidcError> {
    let params = parse_query(authorization_url);
    let request = AuthorizeRequest {
        client_id: params.get("client_id").cloned().unwrap_or_default(),
        redirect_uri: params.get("redirect_uri").cloned().unwrap_or_default(),
        response_type: params.get("response_type").cloned().unwrap_or_default(),
        state: params.get("state").cloned().unwrap_or_default(),
        nonce: params.get("nonce").cloned(),
        code_challenge: params.get("code_challenge").cloned(),
        login_as: login_as.map(str::to_owned),
    };
    let redirect = provider
        .lock()
        .expect("provider lock")
        .authorize(&request)?;
    Ok(redirect.location)
}

/// Parse the query component of a URL into decoded key/value pairs.
fn parse_query(url: &str) -> HashMap<String, String> {
    let query = url.split_once('?').map(|(_, q)| q).unwrap_or("");
    query
        .split('&')
        .filter(|pair| !pair.is_empty())
        .filter_map(|pair| pair.split_once('='))
        .map(|(name, value)| (name.to_owned(), percent_decode(value)))
        .collect()
}

fn percent_encode(value: &str) -> String {
    let mut out = String::with_capacity(value.len());
    for byte in value.bytes() {
        match byte {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'.' | b'_' | b'~' => {
                out.push(byte as char);
            }
            _ => out.push_str(&format!("%{byte:02X}")),
        }
    }
    out
}

fn percent_decode(value: &str) -> String {
    let bytes = value.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut index = 0;
    while index < bytes.len() {
        match bytes[index] {
            b'%' if index + 2 < bytes.len() => {
                match (hex_value(bytes[index + 1]), hex_value(bytes[index + 2])) {
                    (Some(high), Some(low)) => {
                        out.push((high << 4) | low);
                        index += 3;
                    }
                    _ => {
                        out.push(b'%');
                        index += 1;
                    }
                }
            }
            b'+' => {
                out.push(b' ');
                index += 1;
            }
            byte => {
                out.push(byte);
                index += 1;
            }
        }
    }
    String::from_utf8(out).expect("decoded value is valid utf8")
}

fn hex_value(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        b'A'..=b'F' => Some(byte - b'A' + 10),
        _ => None,
    }
}

#[test]
fn fake_provider_login_loop_closes_session_and_authorize_path() {
    let (mut api, provider) = setup(None);

    // 1. Browser hits IAM start; it gets a hardened correlation cookie and the
    //    provider authorization redirect.
    let start = begin(&mut api, Some("/dashboard"));
    assert!(start.set_cookie.contains(DEFAULT_LOGIN_COOKIE_NAME));
    assert!(
        start
            .set_proof_cookie
            .contains(DEFAULT_LOGIN_PROOF_COOKIE_NAME)
    );
    assert!(start.set_cookie.contains("; HttpOnly"));
    assert!(start.set_cookie.contains("; Secure"));
    assert!(
        start
            .redirect_url
            .starts_with(&format!("{ISSUER}/authorize?"))
    );

    // 2. Browser follows the redirect to the fake IdP, which consents and bounces
    //    back to the IAM callback with a code bound to the echoed state.
    let callback_location =
        idp_authorize(&provider, &start.redirect_url, None).expect("idp authorize");
    assert!(callback_location.starts_with(REDIRECT_URI));
    let returned = parse_query(&callback_location);
    assert!(returned.contains_key("code"));

    // 3. Browser delivers the code + state to the IAM callback carrying the
    //    correlation cookie; IAM exchanges the code and mints a session.
    let outcome = api
        .complete_callback(CallbackRequest {
            provider_key: key(),
            cookie_header: login_cookie_header(&start),
            code: returned["code"].clone(),
            state: returned["state"].clone(),
            now: ts("2026-06-19T00:01:00Z"),
            session_expires_at: ts("2026-06-20T00:00:00Z"),
            session_cookie_max_age_secs: Some(3600),
        })
        .expect("complete callback");
    assert!(outcome.registered);
    assert_eq!(outcome.redirect_to, "/dashboard");
    assert!(
        outcome
            .set_session_cookie
            .contains(DEFAULT_SESSION_COOKIE_NAME)
    );
    assert!(outcome.clear_login_cookie.contains("; Max-Age=0"));
    assert!(outcome.clear_login_proof_cookie.contains("; Max-Age=0"));
    assert!(outcome.session.external_identity_id.is_some());

    // 4. /v1/session resolves the live session from the session cookie.
    let session_cookie = session_cookie_header(&outcome);
    let view = api
        .current_session(&session_cookie, ts("2026-06-19T01:00:00Z"))
        .expect("current session");
    assert_eq!(view.session_id, outcome.session.session_id);
    assert_eq!(view.account_id, outcome.session.account_id);

    // 5. The authenticated account flows into the authorize decision path; the
    //    MVP evaluator denies by default until grant policy is wired.
    let server = IamServer::new();
    let decision = server.authorize(AuthorizationRequest {
        principal: PrincipalRef::Account {
            account_id: view.account_id.clone(),
        },
        on_behalf_of: Vec::new(),
        action: ActionKey("pack.publish".into()),
        scope: ScopeRef::Global,
    });
    assert_eq!(decision, AuthorizationDecision::Deny);

    // The audit trail records the successful login transition.
    assert!(
        api.audit_log()
            .iter()
            .any(|event| matches!(event, AuthAuditEvent::LoginSucceeded { .. }))
    );
}

#[test]
fn forged_state_is_rejected_and_burns_the_challenge() {
    let (mut api, provider) = setup(None);
    let start = begin(&mut api, Some("/dashboard"));
    let location = idp_authorize(&provider, &start.redirect_url, None).expect("idp authorize");
    let returned = parse_query(&location);

    // A callback echoing a state that never matches the minted challenge fails
    // closed before any token exchange.
    let err = api
        .complete_callback(CallbackRequest {
            provider_key: key(),
            cookie_header: login_cookie_header(&start),
            code: returned["code"].clone(),
            state: "forged-state".into(),
            now: ts("2026-06-19T00:01:00Z"),
            session_expires_at: ts("2026-06-20T00:00:00Z"),
            session_cookie_max_age_secs: None,
        })
        .expect_err("forged state must fail");
    assert!(matches!(err, AuthApiError::Login(_)));
    assert!(api.audit_log().iter().any(|event| matches!(
        event,
        AuthAuditEvent::LoginFailed {
            reason: AuthFailureReason::StateMismatch,
            ..
        }
    )));

    // Replaying the now-burned challenge, even with the correct state, no longer
    // correlates: the transient secrets were dropped.
    let replay = api
        .complete_callback(CallbackRequest {
            provider_key: key(),
            cookie_header: login_cookie_header(&start),
            code: returned["code"].clone(),
            state: returned["state"].clone(),
            now: ts("2026-06-19T00:02:00Z"),
            session_expires_at: ts("2026-06-20T00:00:00Z"),
            session_cookie_max_age_secs: None,
        })
        .expect_err("replay must fail");
    assert!(matches!(replay, AuthApiError::MissingCorrelation));
}

#[test]
fn expired_challenge_is_rejected_at_callback() {
    let (mut api, provider) = setup(None);
    let start = begin(&mut api, Some("/dashboard"));
    let location = idp_authorize(&provider, &start.redirect_url, None).expect("idp authorize");
    let returned = parse_query(&location);

    // The callback arrives after the challenge TTL elapsed.
    let err = api
        .complete_callback(CallbackRequest {
            provider_key: key(),
            cookie_header: login_cookie_header(&start),
            code: returned["code"].clone(),
            state: returned["state"].clone(),
            now: ts("2026-06-19T00:10:00Z"),
            session_expires_at: ts("2026-06-20T00:00:00Z"),
            session_cookie_max_age_secs: None,
        })
        .expect_err("expired challenge must fail");
    assert!(matches!(err, AuthApiError::Login(_)));
    assert!(api.audit_log().iter().any(|event| matches!(
        event,
        AuthAuditEvent::LoginFailed {
            reason: AuthFailureReason::ChallengeRejected,
            ..
        }
    )));
}

#[test]
fn session_expiry_closes_the_session_loop() {
    let (mut api, provider) = setup(None);
    let start = begin(&mut api, Some("/dashboard"));
    let location = idp_authorize(&provider, &start.redirect_url, None).expect("idp authorize");
    let returned = parse_query(&location);
    let outcome = api
        .complete_callback(CallbackRequest {
            provider_key: key(),
            cookie_header: login_cookie_header(&start),
            code: returned["code"].clone(),
            state: returned["state"].clone(),
            now: ts("2026-06-19T00:01:00Z"),
            session_expires_at: ts("2026-06-20T00:00:00Z"),
            session_cookie_max_age_secs: Some(3600),
        })
        .expect("complete callback");
    let session_cookie = session_cookie_header(&outcome);

    // Live before expiry, rejected once the session window elapses.
    api.current_session(&session_cookie, ts("2026-06-19T12:00:00Z"))
        .expect("session is live before expiry");
    let err = api
        .current_session(&session_cookie, ts("2026-06-21T00:00:00Z"))
        .expect_err("expired session must fail");
    assert!(matches!(err, AuthApiError::Login(_)));
}

#[test]
fn idp_denied_consent_returns_error_without_code() {
    let (mut api, provider) = setup(Some(FailureMode::DenyAuthorization));
    let start = begin(&mut api, Some("/dashboard"));

    // The identity provider refuses consent and redirects back with an error and
    // no authorization code.
    let location = idp_authorize(&provider, &start.redirect_url, None).expect("idp authorize");
    let returned = parse_query(&location);
    assert_eq!(
        returned.get("error").map(String::as_str),
        Some("access_denied")
    );
    assert!(!returned.contains_key("code"));
}

#[test]
fn idp_token_exchange_failure_fails_the_callback() {
    let (mut api, provider) = setup(Some(FailureMode::RejectTokenExchange));
    let start = begin(&mut api, Some("/dashboard"));
    let location = idp_authorize(&provider, &start.redirect_url, None).expect("idp authorize");
    let returned = parse_query(&location);

    // The challenge verifies, but the provider rejects the code-for-token
    // exchange, so the callback fails and audits a provider rejection.
    let err = api
        .complete_callback(CallbackRequest {
            provider_key: key(),
            cookie_header: login_cookie_header(&start),
            code: returned["code"].clone(),
            state: returned["state"].clone(),
            now: ts("2026-06-19T00:01:00Z"),
            session_expires_at: ts("2026-06-20T00:00:00Z"),
            session_cookie_max_age_secs: None,
        })
        .expect_err("token exchange failure must fail the callback");
    assert!(matches!(err, AuthApiError::Provider(_)));
    assert!(api.audit_log().iter().any(|event| matches!(
        event,
        AuthAuditEvent::LoginFailed {
            reason: AuthFailureReason::ProviderRejected,
            ..
        }
    )));
}
