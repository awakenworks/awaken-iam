//! Provider contract tests for the Google (OIDC) and GitHub (OAuth2) adapters.
//!
//! The adapters' inline unit tests exercise individual seams with hand-built
//! stubs. These contract tests instead drive each adapter end to end through its
//! public [`IdentityProviderAdapter`] surface while *mocking the provider
//! endpoints at the wire level*: the Google adapter is fed canned JWKS and token
//! responses through its [`HttpTransport`] seam, and the GitHub adapter is fed
//! canned token / user / emails JSON through its [`GithubTransport`] seam, with
//! each response deserialized exactly as the live REST bodies would be.
//!
//! Pinning the wire shapes here locks the contract each adapter relies on and
//! covers the security-critical rejection paths an attacker would probe: a bad
//! ID-token issuer, a wrong audience, a replayed/forged nonce, a tampered
//! signature, a login that came back without the email scope, and the
//! email-verification normalization both providers must get right.
//!
//! Note on Google "discovery": the MVP Google adapter resolves its token and
//! JWKS endpoints from [`IdentityProviderConfig`] (falling back to Google's
//! well-known defaults) rather than fetching the OIDC discovery document, so the
//! contract these tests pin is the token + JWKS exchange the adapter actually
//! performs.

use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;

use awaken_iam_contract::{
    ExternalSubject, IdentityProviderConfig, IdentityProviderConfigId, IdentityProviderKey,
    IdentityProviderKind,
};
use awaken_iam_core::{
    AuthorizationUrlRequest, CallbackExchange, GithubAccessToken, GithubEmail,
    GithubProviderAdapter, GithubTokenRequest, GithubTransport, GithubTransportError, GithubUser,
    GoogleOidcProvider, GoogleProviderSecrets, HttpRequest, HttpTransport, IdTokenVerification,
    IdentityProviderAdapter, Jwk, JwkSet, JwsVerifier, ProviderError, verify_id_token,
};

// ---------------------------------------------------------------------------
// Google (OIDC) wire mocks
// ---------------------------------------------------------------------------

/// Signature the [`StubVerifier`] treats as a valid RS256 signature; any other
/// signature segment models a tampered token.
const VALID_SIGNATURE: &[u8] = b"valid-rs256-signature";

/// Mock Google token + JWKS endpoints.
///
/// Routes by request URL the same way the live deployment would: the JWKS certs
/// endpoint serves the published keys and the token endpoint serves the code
/// exchange. An `Err` body models a non-2xx response from that endpoint.
struct GoogleEndpoints {
    token: Result<String, String>,
    jwks: Result<String, String>,
}

impl HttpTransport for GoogleEndpoints {
    fn execute(&self, request: &HttpRequest) -> Result<Vec<u8>, String> {
        let body = if request.url.contains("certs") || request.url.contains("jwks") {
            &self.jwks
        } else if request.url.contains("token") {
            &self.token
        } else {
            return Err(format!("unexpected endpoint: {}", request.url));
        };
        body.clone().map(String::into_bytes)
    }
}

/// Verifier that accepts only the canonical [`VALID_SIGNATURE`] under RS256, so a
/// tampered signature segment is rejected without real asymmetric crypto.
struct StubVerifier;

impl JwsVerifier for StubVerifier {
    fn verify(&self, alg: &str, _jwk: &Jwk, _signing_input: &[u8], signature: &[u8]) -> bool {
        alg == "RS256" && signature == VALID_SIGNATURE
    }
}

fn b64(bytes: &[u8]) -> String {
    URL_SAFE_NO_PAD.encode(bytes)
}

/// Assemble a compact JWS from raw header/payload JSON and a raw signature.
fn jws(header: &str, payload: &str, signature: &[u8]) -> String {
    format!(
        "{}.{}.{}",
        b64(header.as_bytes()),
        b64(payload.as_bytes()),
        b64(signature)
    )
}

const GOOGLE_HEADER: &str = r#"{"alg":"RS256","kid":"key-1"}"#;

/// Published JWKS document matching the `key-1` header `kid`.
fn google_jwks_body() -> String {
    r#"{"keys":[{"kid":"key-1","kty":"RSA","alg":"RS256","n":"modulus","e":"AQAB"}]}"#.to_owned()
}

/// An ID-token payload with the given issuer/audience and a verified email.
fn google_payload(issuer: &str, audience: &str, email_verified: bool) -> String {
    format!(
        r#"{{"iss":"{issuer}","aud":"{audience}","sub":"google-sub-1","exp":2000000000,
            "nonce":"nonce-token","email":"ada@example.com","email_verified":{email_verified},
            "name":"Ada Lovelace","picture":"https://img.example/a.png","locale":"en"}}"#
    )
}

/// Token-endpoint body wrapping `id_token` signed with `signature`.
fn google_token_body(payload: &str, signature: &[u8]) -> String {
    format!(
        r#"{{"id_token":"{}"}}"#,
        jws(GOOGLE_HEADER, payload, signature)
    )
}

fn google_config() -> IdentityProviderConfig {
    IdentityProviderConfig {
        id: IdentityProviderConfigId("cfg_google".into()),
        provider_key: IdentityProviderKey("google".into()),
        kind: IdentityProviderKind::Oidc,
        display_name: "Google".into(),
        issuer_url: Some(awaken_iam_core::GOOGLE_ISSUER.into()),
        authorization_endpoint: Some(awaken_iam_core::GOOGLE_AUTHORIZATION_ENDPOINT.into()),
        token_endpoint: Some(awaken_iam_core::GOOGLE_TOKEN_ENDPOINT.into()),
        client_id: Some("client-123".into()),
        enabled: true,
    }
}

/// Build a Google adapter over the supplied endpoint mock at a clock well before
/// the tokens' `exp`.
fn google_provider(
    endpoints: GoogleEndpoints,
) -> GoogleOidcProvider<GoogleEndpoints, StubVerifier> {
    GoogleOidcProvider::new(
        GoogleProviderSecrets::new("client-secret"),
        endpoints,
        StubVerifier,
    )
}

fn google_callback() -> CallbackExchange {
    CallbackExchange {
        redirect_uri: "https://app.example/callback".into(),
        code: "auth-code".into(),
        pkce_verifier: Some("verifier".into()),
    }
}

#[test]
fn google_exchange_normalizes_verified_claims_off_the_wire() {
    let payload = google_payload(awaken_iam_core::GOOGLE_ISSUER, "client-123", true);
    let provider = google_provider(GoogleEndpoints {
        token: Ok(google_token_body(&payload, VALID_SIGNATURE)),
        jwks: Ok(google_jwks_body()),
    });

    let claims = provider
        .exchange_callback(&google_config(), &google_callback())
        .expect("verified Google login normalizes to claims");

    assert_eq!(claims.subject, ExternalSubject("google-sub-1".into()));
    assert_eq!(claims.email.as_deref(), Some("ada@example.com"));
    assert_eq!(claims.email_verified, Some(true));
    assert_eq!(claims.display_name.as_deref(), Some("Ada Lovelace"));
    assert_eq!(
        claims.avatar_url.as_deref(),
        Some("https://img.example/a.png")
    );
    assert_eq!(claims.locale.as_deref(), Some("en"));
}

#[test]
fn google_exchange_propagates_unverified_email() {
    let payload = google_payload(awaken_iam_core::GOOGLE_ISSUER, "client-123", false);
    let provider = google_provider(GoogleEndpoints {
        token: Ok(google_token_body(&payload, VALID_SIGNATURE)),
        jwks: Ok(google_jwks_body()),
    });

    let claims = provider
        .exchange_callback(&google_config(), &google_callback())
        .expect("login still completes with an unverified email");

    // The adapter must not silently upgrade trust: an unverified email stays
    // unverified for downstream linking policy.
    assert_eq!(claims.email_verified, Some(false));
}

#[test]
fn google_exchange_rejects_untrusted_issuer() {
    let payload = google_payload("https://evil.example", "client-123", true);
    let provider = google_provider(GoogleEndpoints {
        token: Ok(google_token_body(&payload, VALID_SIGNATURE)),
        jwks: Ok(google_jwks_body()),
    });

    let err = provider
        .exchange_callback(&google_config(), &google_callback())
        .expect_err("an untrusted issuer must be rejected");
    match err {
        ProviderError::ExchangeRejected { reason } => assert!(reason.contains("issuer")),
        other => panic!("unexpected error: {other:?}"),
    }
}

#[test]
fn google_exchange_rejects_wrong_audience() {
    let payload = google_payload(awaken_iam_core::GOOGLE_ISSUER, "someone-else", true);
    let provider = google_provider(GoogleEndpoints {
        token: Ok(google_token_body(&payload, VALID_SIGNATURE)),
        jwks: Ok(google_jwks_body()),
    });

    let err = provider
        .exchange_callback(&google_config(), &google_callback())
        .expect_err("a token minted for another client must be rejected");
    match err {
        ProviderError::ExchangeRejected { reason } => assert!(reason.contains("audience")),
        other => panic!("unexpected error: {other:?}"),
    }
}

#[test]
fn google_exchange_rejects_tampered_signature() {
    let payload = google_payload(awaken_iam_core::GOOGLE_ISSUER, "client-123", true);
    let provider = google_provider(GoogleEndpoints {
        token: Ok(google_token_body(&payload, b"tampered")),
        jwks: Ok(google_jwks_body()),
    });

    let err = provider
        .exchange_callback(&google_config(), &google_callback())
        .expect_err("a token the JWKS cannot verify must be rejected");
    match err {
        ProviderError::ExchangeRejected { reason } => assert!(reason.contains("signature")),
        other => panic!("unexpected error: {other:?}"),
    }
}

#[test]
fn google_exchange_surfaces_token_endpoint_failure() {
    let provider = google_provider(GoogleEndpoints {
        token: Err("503 service unavailable".into()),
        jwks: Ok(google_jwks_body()),
    });

    let err = provider
        .exchange_callback(&google_config(), &google_callback())
        .expect_err("a token endpoint outage must fail the exchange");
    match err {
        ProviderError::ExchangeRejected { reason } => {
            assert!(reason.contains("token endpoint request failed"))
        }
        other => panic!("unexpected error: {other:?}"),
    }
}

#[test]
fn google_verify_rejects_replayed_nonce() {
    // The adapter delegates the nonce binding to the challenge service, so the
    // nonce check is pinned directly on the pure verification entry point: a
    // token whose nonce does not match the login's nonce is rejected.
    let payload = google_payload(awaken_iam_core::GOOGLE_ISSUER, "client-123", true);
    let id_token = jws(GOOGLE_HEADER, &payload, VALID_SIGNATURE);
    let jwks: JwkSet = serde_json::from_str(&google_jwks_body()).expect("jwks parses");
    let params = IdTokenVerification {
        id_token: &id_token,
        jwks: &jwks,
        expected_issuer: awaken_iam_core::GOOGLE_ISSUER,
        expected_audience: "client-123",
        expected_nonce: Some("different-nonce"),
        now_unix: 1_000_000_000,
    };

    let err = verify_id_token(&params, &StubVerifier).expect_err("nonce mismatch must be rejected");
    match err {
        ProviderError::ExchangeRejected { reason } => assert!(reason.contains("nonce")),
        other => panic!("unexpected error: {other:?}"),
    }
}

#[test]
fn google_verify_accepts_bound_nonce() {
    let payload = google_payload(awaken_iam_core::GOOGLE_ISSUER, "client-123", true);
    let id_token = jws(GOOGLE_HEADER, &payload, VALID_SIGNATURE);
    let jwks: JwkSet = serde_json::from_str(&google_jwks_body()).expect("jwks parses");
    let params = IdTokenVerification {
        id_token: &id_token,
        jwks: &jwks,
        expected_issuer: awaken_iam_core::GOOGLE_ISSUER,
        expected_audience: "client-123",
        expected_nonce: Some("nonce-token"),
        now_unix: 1_000_000_000,
    };

    let claims = verify_id_token(&params, &StubVerifier).expect("matching nonce verifies");
    assert_eq!(claims.subject, ExternalSubject("google-sub-1".into()));
}

// ---------------------------------------------------------------------------
// GitHub (OAuth2) wire mocks
// ---------------------------------------------------------------------------

/// Mock GitHub token / user / emails endpoints.
///
/// Each field holds the raw JSON body the corresponding REST endpoint returns;
/// the transport deserializes it exactly as the live client would, so the wire
/// contract (field names, optionality) is exercised. An `Err` body models a
/// non-2xx response — for example a `403` from `/user/emails` when the login was
/// granted without the `user:email` scope.
struct GithubEndpoints {
    token: Result<String, String>,
    user: Result<String, String>,
    emails: Result<String, String>,
}

impl GithubTransport for GithubEndpoints {
    fn exchange_code(
        &self,
        _request: &GithubTokenRequest<'_>,
    ) -> Result<GithubAccessToken, GithubTransportError> {
        let body = self.token.clone().map_err(GithubTransportError)?;
        serde_json::from_str(&body).map_err(|err| GithubTransportError(err.to_string()))
    }

    fn fetch_user(&self, _access_token: &str) -> Result<GithubUser, GithubTransportError> {
        let body = self.user.clone().map_err(GithubTransportError)?;
        serde_json::from_str(&body).map_err(|err| GithubTransportError(err.to_string()))
    }

    fn fetch_emails(&self, _access_token: &str) -> Result<Vec<GithubEmail>, GithubTransportError> {
        let body = self.emails.clone().map_err(GithubTransportError)?;
        serde_json::from_str(&body).map_err(|err| GithubTransportError(err.to_string()))
    }
}

fn github_config() -> IdentityProviderConfig {
    IdentityProviderConfig {
        id: IdentityProviderConfigId("cfg_github".into()),
        provider_key: IdentityProviderKey("github".into()),
        kind: IdentityProviderKind::OAuth2,
        display_name: "GitHub".into(),
        issuer_url: None,
        authorization_endpoint: Some(awaken_iam_core::DEFAULT_AUTHORIZE_ENDPOINT.into()),
        token_endpoint: Some(awaken_iam_core::DEFAULT_TOKEN_ENDPOINT.into()),
        client_id: Some("Iv1.client".into()),
        enabled: true,
    }
}

fn github_callback() -> CallbackExchange {
    CallbackExchange {
        redirect_uri: "https://app.example/cb".into(),
        code: "gh-code".into(),
        pkce_verifier: None,
    }
}

/// A token response carrying an access token and the granted `scope` string.
fn github_token_body(scope: &str) -> String {
    format!(r#"{{"access_token":"gho_token","token_type":"bearer","scope":"{scope}"}}"#)
}

/// A `GET /user` body with unknown extra fields, as GitHub really returns.
fn github_user_body() -> String {
    r#"{"id":583231,"login":"octocat","name":"The Octocat",
        "email":null,"avatar_url":"https://avatars.example/u/583231",
        "company":"GitHub","type":"User"}"#
        .to_owned()
}

#[test]
fn github_exchange_uses_numeric_id_and_verified_primary_email() {
    let provider = GithubProviderAdapter::new(GithubEndpoints {
        token: Ok(github_token_body("read:user user:email")),
        user: Ok(github_user_body()),
        emails: Ok(
            r#"[{"email":"octocat@users.noreply.example","primary":false,"verified":true},
                       {"email":"primary@example.com","primary":true,"verified":true},
                       {"email":"old@example.com","primary":false,"verified":false}]"#
                .to_owned(),
        ),
    });

    let claims = provider
        .exchange_callback(&github_config(), &github_callback())
        .expect("a complete GitHub login normalizes to claims");

    // The immutable numeric id, not the mutable login, is the subject.
    assert_eq!(claims.subject, ExternalSubject("583231".into()));
    assert_eq!(claims.username.as_deref(), Some("octocat"));
    assert_eq!(claims.display_name.as_deref(), Some("The Octocat"));
    assert_eq!(claims.email.as_deref(), Some("primary@example.com"));
    assert_eq!(claims.email_verified, Some(true));
    assert_eq!(
        claims.avatar_url.as_deref(),
        Some("https://avatars.example/u/583231")
    );
}

#[test]
fn github_exchange_reports_unverified_email_when_none_verified() {
    let provider = GithubProviderAdapter::new(GithubEndpoints {
        token: Ok(github_token_body("read:user user:email")),
        user: Ok(github_user_body()),
        emails: Ok(
            r#"[{"email":"primary@example.com","primary":true,"verified":false}]"#.to_owned(),
        ),
    });

    let claims = provider
        .exchange_callback(&github_config(), &github_callback())
        .expect("login completes even with no verified address");

    assert_eq!(claims.email.as_deref(), Some("primary@example.com"));
    assert_eq!(claims.email_verified, Some(false));
}

#[test]
fn github_exchange_fails_when_email_scope_missing() {
    // Without the `user:email` scope GitHub answers `GET /user/emails` with a
    // 403; the adapter must surface that rather than inventing claims.
    let provider = GithubProviderAdapter::new(GithubEndpoints {
        token: Ok(github_token_body("read:user")),
        user: Ok(github_user_body()),
        emails: Err("403 Forbidden: missing the user:email scope".into()),
    });

    let err = provider
        .exchange_callback(&github_config(), &github_callback())
        .expect_err("a login without the email scope must fail closed");
    match err {
        ProviderError::MalformedClaims { reason } => {
            assert!(reason.contains("failed to read user emails"));
            assert!(reason.contains("user:email"));
        }
        other => panic!("unexpected error: {other:?}"),
    }
}

#[test]
fn github_exchange_surfaces_token_endpoint_error() {
    let provider = GithubProviderAdapter::new(GithubEndpoints {
        token: Ok(r#"{"error":"bad_verification_code",
                      "error_description":"The code passed is incorrect or expired."}"#
            .to_owned()),
        user: Ok(github_user_body()),
        emails: Ok("[]".to_owned()),
    });

    let err = provider
        .exchange_callback(&github_config(), &github_callback())
        .expect_err("a rejected code exchange must fail");
    assert_eq!(
        err,
        ProviderError::ExchangeRejected {
            reason: "bad_verification_code: The code passed is incorrect or expired.".into(),
        }
    );
}

#[test]
fn github_exchange_rejects_empty_access_token() {
    let provider = GithubProviderAdapter::new(GithubEndpoints {
        token: Ok(r#"{"token_type":"bearer","scope":"read:user user:email"}"#.to_owned()),
        user: Ok(github_user_body()),
        emails: Ok("[]".to_owned()),
    });

    let err = provider
        .exchange_callback(&github_config(), &github_callback())
        .expect_err("a token response without an access token must fail");
    assert_eq!(
        err,
        ProviderError::MalformedClaims {
            reason: "token endpoint returned no access token".into(),
        }
    );
}

#[test]
fn github_authorization_url_omits_nonce_and_pkce() {
    let provider = GithubProviderAdapter::new(GithubEndpoints {
        token: Ok(github_token_body("read:user user:email")),
        user: Ok(github_user_body()),
        emails: Ok("[]".to_owned()),
    });
    let request = AuthorizationUrlRequest {
        redirect_uri: "https://app.example/auth/callback".into(),
        state: "state-token".into(),
        nonce: Some("ignored-nonce".into()),
        pkce_challenge: None,
        scopes: vec!["read:user".into(), "user:email".into()],
    };

    let redirect = provider
        .authorization_url(&github_config(), &request)
        .expect("authorization url builds");

    assert!(
        redirect
            .url
            .starts_with(awaken_iam_core::DEFAULT_AUTHORIZE_ENDPOINT)
    );
    assert!(redirect.url.contains("client_id=Iv1.client"));
    assert!(redirect.url.contains("scope=read%3Auser%20user%3Aemail"));
    // Classic GitHub OAuth carries neither an OIDC nonce nor a PKCE challenge.
    assert!(!redirect.url.contains("nonce"));
    assert!(!redirect.url.contains("code_challenge"));
}
