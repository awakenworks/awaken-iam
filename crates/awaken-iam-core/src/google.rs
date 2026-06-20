//! Google OpenID Connect login provider.
//!
//! This is the concrete [`IdentityProviderAdapter`] for "Sign in with Google".
//! It owns both halves of the login loop for the OIDC family:
//!
//! 1. [`GoogleOidcProvider::authorization_url`] builds the Google authorization
//!    redirect, embedding the cleartext `state`, optional OIDC `nonce`, and
//!    optional PKCE challenge minted by [`crate::OAuthChallengeService`].
//! 2. [`GoogleOidcProvider::exchange_callback`] redeems the authorization `code`
//!    at Google's token endpoint, fetches the published JWKS, and verifies the
//!    returned ID token before normalizing it into [`ExternalIdentityClaims`].
//!
//! Network access and asymmetric signature verification are the only two pieces
//! that cannot live inside a pure domain crate, so each is a trait seam
//! ([`HttpTransport`], [`JwsVerifier`]) supplied by the deployment. Wall-clock
//! time is a third seam ([`Clock`]) so expiry checks are deterministic under
//! test. Everything else — endpoint selection, ID token parsing, and the
//! issuer/audience/nonce/expiry checks the OIDC spec requires — is implemented
//! here and exercised without any real I/O.
//!
//! The ID token verification itself is exposed as the pure [`verify_id_token`]
//! function over an [`IdTokenVerification`] request, so the security-critical
//! checks can be tested directly, independent of the transport.

use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use serde::{Deserialize, Serialize};

use awaken_iam_contract::{
    ExternalIdentityClaims, ExternalSubject, IdentityProviderConfig, IdentityProviderKind,
};

use crate::provider::{
    AuthorizationRedirect, AuthorizationUrlRequest, CallbackExchange, IdentityProviderAdapter,
    ProviderError,
};
use crate::{PkceChallenge, PkceMethod};

/// Google's canonical OIDC issuer, `https`-prefixed form.
pub const GOOGLE_ISSUER: &str = "https://accounts.google.com";
/// Google's canonical OIDC issuer, bare-host form (also accepted in ID tokens).
pub const GOOGLE_ISSUER_BARE: &str = "accounts.google.com";
/// Google's OAuth 2.0 / OIDC authorization endpoint.
pub const GOOGLE_AUTHORIZATION_ENDPOINT: &str = "https://accounts.google.com/o/oauth2/v2/auth";
/// Google's OAuth 2.0 token endpoint.
pub const GOOGLE_TOKEN_ENDPOINT: &str = "https://oauth2.googleapis.com/token";
/// Google's published JWKS (signing certificate) endpoint.
pub const GOOGLE_JWKS_URI: &str = "https://www.googleapis.com/oauth2/v3/certs";

/// Default OIDC scopes requested when a login does not specify its own.
const DEFAULT_SCOPES: [&str; 3] = ["openid", "email", "profile"];

/// A single outbound HTTP request issued by the adapter.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HttpRequest {
    /// HTTP method, uppercased (`GET` or `POST`).
    pub method: &'static str,
    /// Absolute request URL.
    pub url: String,
    /// `(name, value)` request headers.
    pub headers: Vec<(String, String)>,
    /// Request body, empty for `GET`.
    pub body: String,
}

impl HttpRequest {
    /// Build a `GET` request for `url`.
    pub fn get(url: String) -> Self {
        Self {
            method: "GET",
            url,
            headers: Vec::new(),
            body: String::new(),
        }
    }

    /// Build a `POST` request for `url` carrying `body`.
    pub fn post(url: String, body: String) -> Self {
        Self {
            method: "POST",
            url,
            headers: Vec::new(),
            body,
        }
    }

    /// Append a request header.
    #[must_use]
    pub fn with_header(mut self, name: &str, value: &str) -> Self {
        self.headers.push((name.to_owned(), value.to_owned()));
        self
    }
}

/// Transport seam used to reach Google's token and JWKS endpoints.
///
/// Keeping the network behind a trait keeps `awaken-iam-core` free of any
/// concrete HTTP client while letting the deployment inject one. Implementations
/// return the raw response body on a `2xx` status and surface anything else as a
/// failure string.
pub trait HttpTransport {
    /// Execute `request`, returning the response body bytes on success.
    fn execute(&self, request: &HttpRequest) -> Result<Vec<u8>, String>;
}

/// Signature-verification seam for the ID token's JWS.
///
/// RS256 verification needs asymmetric crypto, which a pure domain crate must
/// not embed. The deployment supplies the implementation; the adapter owns key
/// selection (by `kid`), claim validation, and error mapping.
pub trait JwsVerifier {
    /// Return `true` when `signature` is a valid `alg` signature over
    /// `signing_input` for the resolved `jwk`.
    fn verify(&self, alg: &str, jwk: &Jwk, signing_input: &[u8], signature: &[u8]) -> bool;
}

/// Wall-clock seam, so token-expiry checks are deterministic under test.
pub trait Clock {
    /// Current time as seconds since the Unix epoch.
    fn now_unix(&self) -> i64;
}

/// System clock backed by [`std::time::SystemTime`].
#[derive(Debug, Default, Clone, Copy)]
pub struct SystemClock;

impl Clock for SystemClock {
    fn now_unix(&self) -> i64 {
        use std::time::{SystemTime, UNIX_EPOCH};
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs() as i64)
            .unwrap_or(0)
    }
}

/// A single JSON Web Key from Google's JWKS.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Jwk {
    /// Key id matched against the JWT header `kid`.
    pub kid: String,
    /// Key type, for example `RSA`.
    #[serde(default)]
    pub kty: String,
    /// Intended signing algorithm, for example `RS256`.
    #[serde(default)]
    pub alg: String,
    /// RSA modulus, base64url, when present.
    #[serde(default)]
    pub n: String,
    /// RSA exponent, base64url, when present.
    #[serde(default)]
    pub e: String,
}

/// A JWKS document as published at Google's certs endpoint.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct JwkSet {
    /// Published signing keys.
    pub keys: Vec<Jwk>,
}

impl JwkSet {
    /// Resolve the key whose `kid` matches `kid`, if any.
    fn key_for(&self, kid: &str) -> Option<&Jwk> {
        self.keys.iter().find(|key| key.kid == kid)
    }
}

/// Deployment secrets and overrides for a Google OIDC adapter.
///
/// Public, non-secret values (issuer, authorization/token endpoints, client id)
/// arrive per call on the [`IdentityProviderConfig`]; only the secret and the
/// JWKS location live here. Every endpoint falls back to Google's well-known
/// default when the config leaves it unset.
#[derive(Debug, Clone)]
pub struct GoogleProviderSecrets {
    /// OAuth client secret presented at the token endpoint.
    pub client_secret: String,
    /// JWKS URI to fetch signing keys from.
    pub jwks_uri: String,
}

impl GoogleProviderSecrets {
    /// Build secrets that fetch keys from Google's default JWKS endpoint.
    pub fn new(client_secret: impl Into<String>) -> Self {
        Self {
            client_secret: client_secret.into(),
            jwks_uri: GOOGLE_JWKS_URI.to_owned(),
        }
    }
}

/// Google OpenID Connect identity provider adapter.
#[derive(Debug, Clone)]
pub struct GoogleOidcProvider<T, V, C = SystemClock> {
    secrets: GoogleProviderSecrets,
    transport: T,
    verifier: V,
    clock: C,
}

impl<T, V> GoogleOidcProvider<T, V, SystemClock> {
    /// Build an adapter using the system clock for expiry checks.
    pub fn new(secrets: GoogleProviderSecrets, transport: T, verifier: V) -> Self {
        Self {
            secrets,
            transport,
            verifier,
            clock: SystemClock,
        }
    }
}

impl<T, V, C> GoogleOidcProvider<T, V, C> {
    /// Build an adapter with an explicit clock seam.
    pub fn with_clock(secrets: GoogleProviderSecrets, transport: T, verifier: V, clock: C) -> Self {
        Self {
            secrets,
            transport,
            verifier,
            clock,
        }
    }
}

impl<T: HttpTransport, V: JwsVerifier, C: Clock> GoogleOidcProvider<T, V, C> {
    /// Resolve the authorization endpoint, preferring the config override.
    fn authorization_endpoint<'a>(&self, config: &'a IdentityProviderConfig) -> &'a str {
        config
            .authorization_endpoint
            .as_deref()
            .unwrap_or(GOOGLE_AUTHORIZATION_ENDPOINT)
    }

    /// Resolve the token endpoint, preferring the config override.
    fn token_endpoint<'a>(&self, config: &'a IdentityProviderConfig) -> &'a str {
        config
            .token_endpoint
            .as_deref()
            .unwrap_or(GOOGLE_TOKEN_ENDPOINT)
    }

    /// Resolve the expected issuer, preferring the config override.
    fn issuer<'a>(&self, config: &'a IdentityProviderConfig) -> &'a str {
        config.issuer_url.as_deref().unwrap_or(GOOGLE_ISSUER)
    }

    /// Read the required public client id off the config.
    fn client_id<'a>(&self, config: &'a IdentityProviderConfig) -> Result<&'a str, ProviderError> {
        config
            .client_id
            .as_deref()
            .ok_or(ProviderError::MissingConfiguration { field: "client_id" })
    }

    /// Exchange the authorization `code` for an ID token at the token endpoint.
    fn exchange_code(
        &self,
        config: &IdentityProviderConfig,
        callback: &CallbackExchange,
    ) -> Result<String, ProviderError> {
        let client_id = self.client_id(config)?;
        let mut form = format!(
            "grant_type=authorization_code&code={code}&client_id={client_id}\
             &client_secret={secret}&redirect_uri={redirect}",
            code = percent_encode(&callback.code),
            client_id = percent_encode(client_id),
            secret = percent_encode(&self.secrets.client_secret),
            redirect = percent_encode(&callback.redirect_uri),
        );
        if let Some(verifier) = callback.pkce_verifier.as_deref() {
            form.push_str(&format!("&code_verifier={}", percent_encode(verifier)));
        }

        let request = HttpRequest::post(self.token_endpoint(config).to_owned(), form)
            .with_header("content-type", "application/x-www-form-urlencoded")
            .with_header("accept", "application/json");
        let body =
            self.transport
                .execute(&request)
                .map_err(|reason| ProviderError::ExchangeRejected {
                    reason: format!("token endpoint request failed: {reason}"),
                })?;
        let response: TokenResponse =
            serde_json::from_slice(&body).map_err(|err| ProviderError::MalformedClaims {
                reason: format!("token response was not valid JSON: {err}"),
            })?;
        match response.id_token {
            Some(id_token) => Ok(id_token),
            None => Err(ProviderError::ExchangeRejected {
                reason: "token response did not include an id_token".to_owned(),
            }),
        }
    }

    /// Fetch the provider JWKS from the configured certs endpoint.
    fn fetch_jwks(&self) -> Result<JwkSet, ProviderError> {
        let request = HttpRequest::get(self.secrets.jwks_uri.clone());
        let body =
            self.transport
                .execute(&request)
                .map_err(|reason| ProviderError::ExchangeRejected {
                    reason: format!("jwks request failed: {reason}"),
                })?;
        serde_json::from_slice(&body).map_err(|err| ProviderError::MalformedClaims {
            reason: format!("jwks document was not valid JSON: {err}"),
        })
    }
}

/// Everything needed to verify a Google ID token, independent of transport.
#[derive(Debug, Clone)]
pub struct IdTokenVerification<'a> {
    /// The compact-serialized JWS (`header.payload.signature`).
    pub id_token: &'a str,
    /// Signing keys to resolve the JWT header `kid` against.
    pub jwks: &'a JwkSet,
    /// Issuer the token's `iss` must match (Google's two canonical forms are
    /// treated as equivalent).
    pub expected_issuer: &'a str,
    /// Audience the token's `aud` must contain (the OAuth client id).
    pub expected_audience: &'a str,
    /// Nonce bound to the originating login, when one was minted.
    pub expected_nonce: Option<&'a str>,
    /// Current time, seconds since the Unix epoch, for the expiry check.
    pub now_unix: i64,
}

/// Verify a Google ID token and normalize it into [`ExternalIdentityClaims`].
///
/// The token is rejected unless, in order: it is a three-part JWS; the header
/// `kid` resolves to a published key; the JWS signature verifies; the `iss`
/// matches the expected issuer; the `aud` contains the expected audience; the
/// `nonce` matches the bound nonce (when one was minted); and `exp` is still in
/// the future. Only then are `sub`/`email`/`email_verified`/`name`/`picture`
/// (and `locale`) extracted.
pub fn verify_id_token<V: JwsVerifier>(
    params: &IdTokenVerification<'_>,
    verifier: &V,
) -> Result<ExternalIdentityClaims, ProviderError> {
    let segments: Vec<&str> = params.id_token.split('.').collect();
    if segments.len() != 3 {
        return Err(ProviderError::MalformedClaims {
            reason: "id token is not a three-part JWS".to_owned(),
        });
    }

    let header: JwtHeader = decode_segment(segments[0], "header")?;
    let claims: IdTokenClaims = decode_segment(segments[1], "payload")?;
    let signature =
        URL_SAFE_NO_PAD
            .decode(segments[2])
            .map_err(|_| ProviderError::MalformedClaims {
                reason: "id token signature is not base64url".to_owned(),
            })?;

    let key = params
        .jwks
        .key_for(&header.kid)
        .ok_or_else(|| ProviderError::ExchangeRejected {
            reason: format!("no signing key matches kid {}", header.kid),
        })?;

    let signing_input = format!("{}.{}", segments[0], segments[1]);
    if !verifier.verify(&header.alg, key, signing_input.as_bytes(), &signature) {
        return Err(ProviderError::ExchangeRejected {
            reason: "id token signature did not verify".to_owned(),
        });
    }

    if !issuer_matches(&claims.iss, params.expected_issuer) {
        return Err(ProviderError::ExchangeRejected {
            reason: format!("id token issuer {} is not trusted", claims.iss),
        });
    }
    if !claims.aud.contains(params.expected_audience) {
        return Err(ProviderError::ExchangeRejected {
            reason: "id token audience does not include this client".to_owned(),
        });
    }
    if let Some(expected) = params.expected_nonce
        && claims.nonce.as_deref() != Some(expected)
    {
        return Err(ProviderError::ExchangeRejected {
            reason: "id token nonce does not match the login nonce".to_owned(),
        });
    }
    if claims.exp <= params.now_unix {
        return Err(ProviderError::ExchangeRejected {
            reason: "id token has expired".to_owned(),
        });
    }

    Ok(ExternalIdentityClaims {
        subject: ExternalSubject(claims.sub),
        email: claims.email,
        email_verified: claims.email_verified,
        display_name: claims.name,
        username: None,
        avatar_url: claims.picture,
        locale: claims.locale,
    })
}

impl<T: HttpTransport, V: JwsVerifier, C: Clock> IdentityProviderAdapter
    for GoogleOidcProvider<T, V, C>
{
    fn provider_kind(&self) -> IdentityProviderKind {
        IdentityProviderKind::Oidc
    }

    fn authorization_url(
        &self,
        config: &IdentityProviderConfig,
        request: &AuthorizationUrlRequest,
    ) -> Result<AuthorizationRedirect, ProviderError> {
        self.ensure_kind(config)?;
        let client_id = self.client_id(config)?;
        let endpoint = self.authorization_endpoint(config);

        let scopes = if request.scopes.is_empty() {
            DEFAULT_SCOPES.iter().map(|s| (*s).to_owned()).collect()
        } else {
            request.scopes.clone()
        };

        let mut url = format!(
            "{endpoint}?response_type=code&client_id={client_id}&redirect_uri={redirect}&scope={scope}&state={state}",
            client_id = percent_encode(client_id),
            redirect = percent_encode(&request.redirect_uri),
            scope = percent_encode(&scopes.join(" ")),
            state = percent_encode(&request.state),
        );
        if let Some(nonce) = request.nonce.as_deref() {
            url.push_str(&format!("&nonce={}", percent_encode(nonce)));
        }
        if let Some(pkce) = request.pkce_challenge.as_ref() {
            url.push_str(&pkce_query(pkce));
        }
        Ok(AuthorizationRedirect { url })
    }

    fn exchange_callback(
        &self,
        config: &IdentityProviderConfig,
        callback: &CallbackExchange,
    ) -> Result<ExternalIdentityClaims, ProviderError> {
        self.ensure_kind(config)?;
        if callback.code.is_empty() {
            return Err(ProviderError::ExchangeRejected {
                reason: "empty authorization code".to_owned(),
            });
        }
        let client_id = self.client_id(config)?.to_owned();
        let id_token = self.exchange_code(config, callback)?;
        let jwks = self.fetch_jwks()?;

        // The OIDC `nonce` binding is verified in constant time against the
        // stored hash by `OAuthChallengeService::complete_login`; the adapter
        // re-checks every other ID token invariant here.
        let verification = IdTokenVerification {
            id_token: &id_token,
            jwks: &jwks,
            expected_issuer: self.issuer(config),
            expected_audience: &client_id,
            expected_nonce: None,
            now_unix: self.clock.now_unix(),
        };
        verify_id_token(&verification, &self.verifier)
    }
}

/// Token-endpoint response; only the ID token is consumed for OIDC login.
#[derive(Debug, Deserialize)]
struct TokenResponse {
    #[serde(default)]
    id_token: Option<String>,
}

/// Minimal JOSE header fields the adapter needs.
#[derive(Debug, Deserialize)]
struct JwtHeader {
    alg: String,
    kid: String,
}

/// ID token audience, which may be a single string or an array.
#[derive(Debug, Deserialize)]
#[serde(untagged)]
enum Audience {
    One(String),
    Many(Vec<String>),
}

impl Audience {
    fn contains(&self, client_id: &str) -> bool {
        match self {
            Audience::One(value) => value == client_id,
            Audience::Many(values) => values.iter().any(|value| value == client_id),
        }
    }
}

/// ID token claims this adapter reads.
#[derive(Debug, Deserialize)]
struct IdTokenClaims {
    iss: String,
    aud: Audience,
    sub: String,
    exp: i64,
    #[serde(default)]
    nonce: Option<String>,
    #[serde(default)]
    email: Option<String>,
    #[serde(default)]
    email_verified: Option<bool>,
    #[serde(default)]
    name: Option<String>,
    #[serde(default)]
    picture: Option<String>,
    #[serde(default)]
    locale: Option<String>,
}

/// Treat Google's `https`-prefixed and bare-host issuer forms as equivalent.
fn issuer_matches(actual: &str, expected: &str) -> bool {
    if actual == expected {
        return true;
    }
    let google = |iss: &str| iss == GOOGLE_ISSUER || iss == GOOGLE_ISSUER_BARE;
    google(actual) && google(expected)
}

/// Decode and deserialize one base64url JWT segment.
fn decode_segment<D: for<'de> Deserialize<'de>>(
    segment: &str,
    which: &str,
) -> Result<D, ProviderError> {
    let bytes = URL_SAFE_NO_PAD
        .decode(segment)
        .map_err(|_| ProviderError::MalformedClaims {
            reason: format!("id token {which} is not base64url"),
        })?;
    serde_json::from_slice(&bytes).map_err(|err| ProviderError::MalformedClaims {
        reason: format!("id token {which} is not valid JSON: {err}"),
    })
}

/// Render the PKCE query fragment for the authorization URL.
fn pkce_query(pkce: &PkceChallenge) -> String {
    let method = match pkce.method {
        PkceMethod::S256 => "S256",
    };
    format!(
        "&code_challenge={}&code_challenge_method={method}",
        percent_encode(&pkce.challenge)
    )
}

/// Percent-encode a query value, escaping everything outside the unreserved set
/// (`ALPHA` / `DIGIT` / `-` `.` `_` `~`) per RFC 3986.
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

#[cfg(test)]
mod tests {
    use super::*;
    use awaken_iam_contract::{IdentityProviderConfigId, IdentityProviderKey};

    /// Transport that replays canned bodies for the token and JWKS endpoints.
    struct StubTransport {
        token_body: Vec<u8>,
        jwks_body: Vec<u8>,
        fail: Option<String>,
    }

    impl HttpTransport for StubTransport {
        fn execute(&self, request: &HttpRequest) -> Result<Vec<u8>, String> {
            if let Some(reason) = &self.fail {
                return Err(reason.clone());
            }
            if request.url.contains("certs") || request.url.contains("jwks") {
                Ok(self.jwks_body.clone())
            } else {
                Ok(self.token_body.clone())
            }
        }
    }

    /// Verifier whose verdict is fixed, recording the algorithm it saw.
    struct StubVerifier {
        accept: bool,
    }

    impl JwsVerifier for StubVerifier {
        fn verify(&self, _alg: &str, _jwk: &Jwk, _input: &[u8], _sig: &[u8]) -> bool {
            self.accept
        }
    }

    struct FixedClock(i64);
    impl Clock for FixedClock {
        fn now_unix(&self) -> i64 {
            self.0
        }
    }

    fn b64(value: &str) -> String {
        URL_SAFE_NO_PAD.encode(value.as_bytes())
    }

    /// Build a JWS-shaped token from raw header/payload JSON plus a signature.
    fn token(header: &str, payload: &str, signature: &str) -> String {
        format!("{}.{}.{}", b64(header), b64(payload), b64(signature))
    }

    fn google_payload() -> String {
        format!(
            r#"{{"iss":"{GOOGLE_ISSUER}","aud":"client-123","sub":"google-sub-1",
               "exp":2000000000,"nonce":"nonce-token","email":"user@example.com",
               "email_verified":true,"name":"Ada Lovelace",
               "picture":"https://img.example/a.png","locale":"en"}}"#
        )
    }

    fn jwks() -> JwkSet {
        JwkSet {
            keys: vec![Jwk {
                kid: "key-1".into(),
                kty: "RSA".into(),
                alg: "RS256".into(),
                n: "modulus".into(),
                e: "AQAB".into(),
            }],
        }
    }

    fn config() -> IdentityProviderConfig {
        IdentityProviderConfig {
            id: IdentityProviderConfigId("cfg_google".into()),
            provider_key: IdentityProviderKey("google".into()),
            kind: IdentityProviderKind::Oidc,
            display_name: "Google".into(),
            issuer_url: Some(GOOGLE_ISSUER.into()),
            authorization_endpoint: Some(GOOGLE_AUTHORIZATION_ENDPOINT.into()),
            token_endpoint: Some(GOOGLE_TOKEN_ENDPOINT.into()),
            client_id: Some("client-123".into()),
            enabled: true,
        }
    }

    fn provider(
        accept: bool,
        now: i64,
    ) -> GoogleOidcProvider<StubTransport, StubVerifier, FixedClock> {
        let token_body = format!(
            r#"{{"id_token":"{}"}}"#,
            token(r#"{"alg":"RS256","kid":"key-1"}"#, &google_payload(), "sig")
        )
        .into_bytes();
        let jwks_body = serde_json::to_vec(&jwks()).unwrap();
        GoogleOidcProvider::with_clock(
            GoogleProviderSecrets::new("client-secret"),
            StubTransport {
                token_body,
                jwks_body,
                fail: None,
            },
            StubVerifier { accept },
            FixedClock(now),
        )
    }

    fn verify(
        params_payload: &str,
        accept: bool,
        nonce: Option<&str>,
        now: i64,
    ) -> Result<ExternalIdentityClaims, ProviderError> {
        let id_token = token(r#"{"alg":"RS256","kid":"key-1"}"#, params_payload, "sig");
        let keys = jwks();
        let params = IdTokenVerification {
            id_token: &id_token,
            jwks: &keys,
            expected_issuer: GOOGLE_ISSUER,
            expected_audience: "client-123",
            expected_nonce: nonce,
            now_unix: now,
        };
        verify_id_token(&params, &StubVerifier { accept })
    }

    #[test]
    fn authorization_url_is_google_oidc_shaped() {
        let p = provider(true, 0);
        let request = AuthorizationUrlRequest {
            redirect_uri: "https://app.example/callback".into(),
            state: "state token".into(),
            nonce: Some("nonce-token".into()),
            pkce_challenge: Some(PkceChallenge {
                method: PkceMethod::S256,
                challenge: "challenge-value".into(),
            }),
            scopes: vec!["openid".into(), "email".into()],
        };

        let redirect = p.authorization_url(&config(), &request).unwrap();

        assert!(redirect.url.starts_with(GOOGLE_AUTHORIZATION_ENDPOINT));
        assert!(redirect.url.contains("response_type=code"));
        assert!(redirect.url.contains("client_id=client-123"));
        assert!(
            redirect
                .url
                .contains("redirect_uri=https%3A%2F%2Fapp.example%2Fcallback")
        );
        assert!(redirect.url.contains("scope=openid%20email"));
        // The space in the state value is percent-encoded, not left raw.
        assert!(redirect.url.contains("state=state%20token"));
        assert!(redirect.url.contains("nonce=nonce-token"));
        assert!(redirect.url.contains("code_challenge=challenge-value"));
        assert!(redirect.url.contains("code_challenge_method=S256"));
    }

    #[test]
    fn authorization_url_defaults_scopes_and_endpoint() {
        let p = provider(true, 0);
        let mut cfg = config();
        cfg.authorization_endpoint = None;
        let request = AuthorizationUrlRequest {
            redirect_uri: "https://app.example/callback".into(),
            state: "s".into(),
            nonce: None,
            pkce_challenge: None,
            scopes: Vec::new(),
        };

        let redirect = p.authorization_url(&cfg, &request).unwrap();
        assert!(redirect.url.starts_with(GOOGLE_AUTHORIZATION_ENDPOINT));
        assert!(redirect.url.contains("scope=openid%20email%20profile"));
    }

    #[test]
    fn authorization_url_requires_client_id() {
        let p = provider(true, 0);
        let mut cfg = config();
        cfg.client_id = None;
        let request = AuthorizationUrlRequest {
            redirect_uri: "https://app.example/callback".into(),
            state: "s".into(),
            nonce: None,
            pkce_challenge: None,
            scopes: vec!["openid".into()],
        };
        let err = p.authorization_url(&cfg, &request).unwrap_err();
        assert_eq!(
            err,
            ProviderError::MissingConfiguration { field: "client_id" }
        );
    }

    #[test]
    fn adapter_rejects_non_oidc_config() {
        let p = provider(true, 0);
        let mut cfg = config();
        cfg.kind = IdentityProviderKind::OAuth2;
        let callback = CallbackExchange {
            redirect_uri: "https://app.example/callback".into(),
            code: "code".into(),
            pkce_verifier: None,
        };
        let err = p.exchange_callback(&cfg, &callback).unwrap_err();
        assert_eq!(
            err,
            ProviderError::UnsupportedProviderKind {
                expected: IdentityProviderKind::Oidc,
                actual: IdentityProviderKind::OAuth2,
            }
        );
    }

    #[test]
    fn exchange_callback_normalizes_google_claims() {
        let p = provider(true, 1_000_000_000);
        let callback = CallbackExchange {
            redirect_uri: "https://app.example/callback".into(),
            code: "auth-code".into(),
            pkce_verifier: Some("verifier".into()),
        };

        let claims = p.exchange_callback(&config(), &callback).unwrap();
        assert_eq!(claims.subject, ExternalSubject("google-sub-1".into()));
        assert_eq!(claims.email.as_deref(), Some("user@example.com"));
        assert_eq!(claims.email_verified, Some(true));
        assert_eq!(claims.display_name.as_deref(), Some("Ada Lovelace"));
        assert_eq!(
            claims.avatar_url.as_deref(),
            Some("https://img.example/a.png")
        );
        assert_eq!(claims.locale.as_deref(), Some("en"));
    }

    #[test]
    fn exchange_callback_rejects_empty_code() {
        let p = provider(true, 0);
        let callback = CallbackExchange {
            redirect_uri: "https://app.example/callback".into(),
            code: String::new(),
            pkce_verifier: None,
        };
        let err = p.exchange_callback(&config(), &callback).unwrap_err();
        assert_eq!(
            err,
            ProviderError::ExchangeRejected {
                reason: "empty authorization code".to_owned(),
            }
        );
    }

    #[test]
    fn exchange_callback_surfaces_transport_failure() {
        let token_body = b"{}".to_vec();
        let jwks_body = b"{}".to_vec();
        let p = GoogleOidcProvider::with_clock(
            GoogleProviderSecrets::new("secret"),
            StubTransport {
                token_body,
                jwks_body,
                fail: Some("connection refused".into()),
            },
            StubVerifier { accept: true },
            FixedClock(0),
        );
        let callback = CallbackExchange {
            redirect_uri: "https://app.example/callback".into(),
            code: "auth-code".into(),
            pkce_verifier: None,
        };
        let err = p.exchange_callback(&config(), &callback).unwrap_err();
        match err {
            ProviderError::ExchangeRejected { reason } => {
                assert!(reason.contains("token endpoint request failed"));
            }
            other => panic!("unexpected error: {other:?}"),
        }
    }

    #[test]
    fn verify_extracts_normalized_claims() {
        let claims = verify(&google_payload(), true, Some("nonce-token"), 1_000_000_000).unwrap();
        assert_eq!(claims.subject, ExternalSubject("google-sub-1".into()));
        assert_eq!(claims.email_verified, Some(true));
    }

    #[test]
    fn verify_accepts_bare_host_issuer() {
        let payload = r#"{"iss":"accounts.google.com","aud":"client-123","sub":"s",
                          "exp":2000000000}"#;
        let claims = verify(payload, true, None, 0).unwrap();
        assert_eq!(claims.subject, ExternalSubject("s".into()));
    }

    #[test]
    fn verify_accepts_audience_array() {
        let payload = r#"{"iss":"https://accounts.google.com",
                          "aud":["other","client-123"],"sub":"s","exp":2000000000}"#;
        assert!(verify(payload, true, None, 0).is_ok());
    }

    #[test]
    fn verify_rejects_bad_signature() {
        let err = verify(&google_payload(), false, Some("nonce-token"), 0).unwrap_err();
        match err {
            ProviderError::ExchangeRejected { reason } => assert!(reason.contains("signature")),
            other => panic!("unexpected error: {other:?}"),
        }
    }

    #[test]
    fn verify_rejects_bad_issuer() {
        let payload = r#"{"iss":"https://evil.example","aud":"client-123","sub":"s",
                          "exp":2000000000}"#;
        let err = verify(payload, true, None, 0).unwrap_err();
        match err {
            ProviderError::ExchangeRejected { reason } => assert!(reason.contains("issuer")),
            other => panic!("unexpected error: {other:?}"),
        }
    }

    #[test]
    fn verify_rejects_bad_audience() {
        let payload = r#"{"iss":"https://accounts.google.com","aud":"someone-else",
                          "sub":"s","exp":2000000000}"#;
        let err = verify(payload, true, None, 0).unwrap_err();
        match err {
            ProviderError::ExchangeRejected { reason } => assert!(reason.contains("audience")),
            other => panic!("unexpected error: {other:?}"),
        }
    }

    #[test]
    fn verify_rejects_nonce_mismatch() {
        let err = verify(&google_payload(), true, Some("different-nonce"), 0).unwrap_err();
        match err {
            ProviderError::ExchangeRejected { reason } => assert!(reason.contains("nonce")),
            other => panic!("unexpected error: {other:?}"),
        }
    }

    #[test]
    fn verify_rejects_expired_token() {
        // `exp` is 2_000_000_000; a later clock must reject it.
        let err = verify(&google_payload(), true, Some("nonce-token"), 2_000_000_001).unwrap_err();
        match err {
            ProviderError::ExchangeRejected { reason } => assert!(reason.contains("expired")),
            other => panic!("unexpected error: {other:?}"),
        }
    }

    #[test]
    fn verify_rejects_unknown_kid() {
        let id_token = token(
            r#"{"alg":"RS256","kid":"unknown"}"#,
            &google_payload(),
            "sig",
        );
        let keys = jwks();
        let params = IdTokenVerification {
            id_token: &id_token,
            jwks: &keys,
            expected_issuer: GOOGLE_ISSUER,
            expected_audience: "client-123",
            expected_nonce: None,
            now_unix: 0,
        };
        let err = verify_id_token(&params, &StubVerifier { accept: true }).unwrap_err();
        match err {
            ProviderError::ExchangeRejected { reason } => assert!(reason.contains("kid")),
            other => panic!("unexpected error: {other:?}"),
        }
    }

    #[test]
    fn verify_rejects_malformed_token() {
        let keys = jwks();
        let params = IdTokenVerification {
            id_token: "abc.def",
            jwks: &keys,
            expected_issuer: GOOGLE_ISSUER,
            expected_audience: "client-123",
            expected_nonce: None,
            now_unix: 0,
        };
        let err = verify_id_token(&params, &StubVerifier { accept: true }).unwrap_err();
        assert_eq!(
            err,
            ProviderError::MalformedClaims {
                reason: "id token is not a three-part JWS".to_owned(),
            }
        );
    }

    #[test]
    fn provider_kind_is_oidc() {
        assert_eq!(
            provider(true, 0).provider_kind(),
            IdentityProviderKind::Oidc
        );
    }

    #[test]
    fn google_provider_is_object_safe() {
        let registry: Vec<Box<dyn IdentityProviderAdapter>> = vec![Box::new(provider(true, 0))];
        assert_eq!(registry[0].provider_kind(), IdentityProviderKind::Oidc);
    }
}
