//! Deterministic fake OIDC provider for end-to-end tests.
//!
//! Real IAM E2E coverage needs to drive the whole login loop — authorization
//! redirect, code/token exchange, and claim retrieval — without a network
//! dependency on a real identity provider. This module supplies that test double:
//! a self-contained, fully deterministic OpenID Connect provider that answers the
//! five endpoints a relying party touches:
//!
//! * **discovery** ([`FakeOidcProvider::discovery_document`]) — the
//!   `/.well-known/openid-configuration` document advertising the other endpoints;
//! * **JWKS** ([`FakeOidcProvider::jwks`]) — the signing keys an RP uses to verify
//!   an issued `id_token`;
//! * **authorize** ([`FakeOidcProvider::authorize`]) — consents as a preconfigured
//!   user and returns the authorization-code redirect;
//! * **token** ([`FakeOidcProvider::token`]) — redeems a code for an access token
//!   and a signed `id_token`;
//! * **userinfo** ([`FakeOidcProvider::userinfo`]) — returns the user's claims for
//!   a bearer access token.
//!
//! Determinism is the whole point: identifiers (authorization codes, access
//! tokens) come from an internal monotonic counter, the signing key is derived
//! from the issuer and client id, and token timestamps come from configuration
//! rather than the wall clock. Given the same construction and call sequence the
//! provider emits byte-identical artifacts, so CI assertions never flake.
//!
//! Because this is explicitly a non-production double, the `id_token` is signed
//! with HMAC-SHA256 (`HS256`) and the symmetric key is published in the JWKS as an
//! `oct` key. That lets an E2E relying party verify signatures end to end with no
//! asymmetric-crypto dependency; it is deliberately *not* how a real OIDC provider
//! protects its keys. To exercise relying-party error handling, the provider can
//! be configured with a [`FailureMode`] that makes a single endpoint misbehave in
//! a controlled way (denied consent, rejected exchange, tampered token, rotated
//! signing key, or a userinfo error).

use std::collections::BTreeMap;

use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use awaken_iam_contract::{ExternalIdentityClaims, ExternalSubject};

/// SHA-256 block size in bytes, used by the HMAC construction.
const SHA256_BLOCK: usize = 64;

/// A single controllable misbehavior the provider can be configured to exhibit.
///
/// Exactly one mode is active at a time (or none). Each mode targets one endpoint
/// so an E2E suite can assert that the relying party handles that specific failure
/// without perturbing the rest of the flow.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FailureMode {
    /// The authorize endpoint refuses consent and redirects back with
    /// `error=access_denied` instead of an authorization code.
    DenyAuthorization,
    /// The token endpoint rejects an otherwise-valid code exchange with
    /// `error=invalid_grant`.
    RejectTokenExchange,
    /// The token endpoint issues an `id_token` whose signature has been tampered
    /// with, so verification against the JWKS fails.
    TamperIdTokenSignature,
    /// The JWKS is served with a different key id than the one used to sign the
    /// `id_token`, so an RP cannot find a matching verification key.
    RotateSigningKey,
    /// The userinfo endpoint rejects the bearer token with
    /// `error=invalid_token`.
    RejectUserinfo,
}

/// OpenID Connect provider-metadata (discovery) document.
///
/// Only the fields a relying party in this project consumes are modeled; the
/// shape matches the `openid-configuration` JSON an RP fetches from the issuer.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct OidcDiscoveryDocument {
    /// Issuer identifier; equals the configured issuer URL.
    pub issuer: String,
    /// Authorization endpoint the browser is redirected to.
    pub authorization_endpoint: String,
    /// Token endpoint the RP exchanges the code at.
    pub token_endpoint: String,
    /// Userinfo endpoint the RP fetches claims from.
    pub userinfo_endpoint: String,
    /// JWKS endpoint advertising the `id_token` signing keys.
    pub jwks_uri: String,
    /// Response types supported; this provider only supports `code`.
    pub response_types_supported: Vec<String>,
    /// Subject identifier types supported; `public` only.
    pub subject_types_supported: Vec<String>,
    /// `id_token` signing algorithms supported; `HS256` only.
    pub id_token_signing_alg_values_supported: Vec<String>,
    /// Scopes advertised as available.
    pub scopes_supported: Vec<String>,
}

/// A JSON Web Key Set as served from the JWKS endpoint.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct JsonWebKeySet {
    /// The set of published keys.
    pub keys: Vec<JsonWebKey>,
}

/// A single JSON Web Key.
///
/// This double publishes the symmetric `id_token` signing key as an `oct` key so
/// an E2E relying party can verify `HS256` signatures end to end.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct JsonWebKey {
    /// Key type; always `oct` for this provider.
    pub kty: String,
    /// Key identifier echoed in the `id_token` header.
    pub kid: String,
    /// Algorithm the key is used with; `HS256`.
    pub alg: String,
    /// Intended use; `sig`.
    #[serde(rename = "use")]
    pub key_use: String,
    /// Base64url-encoded symmetric key material (`oct` key parameter).
    pub k: String,
}

/// A user the provider can authenticate.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FakeUser {
    /// Provider-scoped immutable subject identifier.
    pub subject: ExternalSubject,
    /// Normalized claims returned for this user across `id_token` and userinfo.
    pub claims: ExternalIdentityClaims,
}

impl FakeUser {
    /// Build a user from a subject and email with the email marked verified.
    ///
    /// Convenience for the common E2E case; richer profiles can set
    /// [`FakeUser::claims`] directly.
    pub fn with_email(subject: impl Into<String>, email: impl Into<String>) -> Self {
        let subject = subject.into();
        Self {
            subject: ExternalSubject(subject.clone()),
            claims: ExternalIdentityClaims {
                subject: ExternalSubject(subject),
                email: Some(email.into()),
                email_verified: Some(true),
                display_name: None,
                username: None,
                avatar_url: None,
                locale: None,
            },
        }
    }
}

/// Parameters presented to the authorize endpoint.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuthorizeRequest {
    /// Client id the RP identifies itself with.
    pub client_id: String,
    /// Callback URL to redirect back to.
    pub redirect_uri: String,
    /// OAuth response type; must be `code`.
    pub response_type: String,
    /// Opaque `state` the RP wants echoed back.
    pub state: String,
    /// OIDC `nonce` to bind into the `id_token`, when supplied.
    pub nonce: Option<String>,
    /// PKCE `code_challenge`, when the RP uses PKCE.
    pub code_challenge: Option<String>,
    /// Subject to authenticate as. When absent the configured default user is
    /// used. This is the deterministic stand-in for a human picking an account.
    pub login_as: Option<String>,
}

/// A redirect produced by the authorize endpoint.
///
/// On success the location carries `code` and `state`; under
/// [`FailureMode::DenyAuthorization`] it carries `error` and `state`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuthorizeRedirect {
    /// Absolute redirect URL back to the relying party's callback.
    pub location: String,
}

/// Parameters presented to the token endpoint.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TokenRequest {
    /// OAuth grant type; must be `authorization_code`.
    pub grant_type: String,
    /// Authorization code issued by the authorize endpoint.
    pub code: String,
    /// Callback URL; must match the one used at authorize time.
    pub redirect_uri: String,
    /// Client id; must match the one used at authorize time.
    pub client_id: String,
    /// PKCE `code_verifier`, required when the flow used a challenge.
    pub code_verifier: Option<String>,
}

/// A successful token-endpoint response.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TokenResponse {
    /// Opaque access token used at the userinfo endpoint.
    pub access_token: String,
    /// Token type; `Bearer`.
    pub token_type: String,
    /// Lifetime of the access token in seconds.
    pub expires_in: u64,
    /// Signed OIDC identity token (`HS256` compact JWT).
    pub id_token: String,
    /// Scopes granted.
    pub scope: String,
}

/// The userinfo-endpoint response.
///
/// Field names follow the OIDC standard-claim spelling so an RP can map them
/// directly; values mirror the user's [`ExternalIdentityClaims`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct UserInfoResponse {
    /// Subject identifier.
    pub sub: String,
    /// Email claim, when present.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub email: Option<String>,
    /// Email-verified claim, when present.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub email_verified: Option<bool>,
    /// Display-name claim, when present.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    /// Preferred-username claim, when present.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub preferred_username: Option<String>,
    /// Avatar URL claim, when present.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub picture: Option<String>,
    /// Locale claim, when present.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub locale: Option<String>,
}

/// Claims encoded into the issued `id_token` payload.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct IdTokenClaims {
    /// Issuer; equals the provider issuer URL.
    pub iss: String,
    /// Subject identifier.
    pub sub: String,
    /// Audience; the client id the token was minted for.
    pub aud: String,
    /// Expiration time (seconds since the Unix epoch).
    pub exp: u64,
    /// Issued-at time (seconds since the Unix epoch).
    pub iat: u64,
    /// Bound `nonce`, echoed from the authorize request when present.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub nonce: Option<String>,
    /// Email claim, when present.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub email: Option<String>,
    /// Email-verified claim, when present.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub email_verified: Option<bool>,
}

/// An OAuth/OIDC wire error body returned by the token and userinfo endpoints.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error, Serialize, Deserialize)]
#[error("{error}: {error_description}")]
pub struct OidcError {
    /// Machine-readable error code (`invalid_grant`, `invalid_client`, ...).
    pub error: String,
    /// Human-readable description.
    pub error_description: String,
}

impl OidcError {
    fn new(error: &str, description: impl Into<String>) -> Self {
        Self {
            error: error.to_owned(),
            error_description: description.into(),
        }
    }
}

/// State recorded when an authorization code is issued, redeemed at the token
/// endpoint.
#[derive(Debug, Clone)]
struct IssuedCode {
    subject: String,
    client_id: String,
    redirect_uri: String,
    nonce: Option<String>,
    code_challenge: Option<String>,
    consumed: bool,
}

/// Deterministic fake OpenID Connect provider for end-to-end tests.
///
/// Construct with [`FakeOidcProvider::new`], register users, and optionally pin a
/// [`FailureMode`]. Authorize/token are `&mut self` because they advance the
/// internal issuance counter and record per-code state; discovery, JWKS, and
/// userinfo are read-only.
#[derive(Debug, Clone)]
pub struct FakeOidcProvider {
    issuer: String,
    client_id: String,
    signing_kid: String,
    signing_key: Vec<u8>,
    token_ttl_secs: u64,
    issued_at: u64,
    users: BTreeMap<String, ExternalIdentityClaims>,
    default_subject: Option<String>,
    failure: Option<FailureMode>,
    codes: BTreeMap<String, IssuedCode>,
    access_tokens: BTreeMap<String, String>,
    seq: u64,
}

impl FakeOidcProvider {
    /// Create a provider for `issuer` serving relying party `client_id`.
    ///
    /// The issuer should be an absolute base URL with no trailing slash (for
    /// example `https://idp.test`); endpoint URLs are derived from it. The signing
    /// key is deterministically derived from the issuer and client id.
    pub fn new(issuer: impl Into<String>, client_id: impl Into<String>) -> Self {
        let issuer = issuer.into();
        let client_id = client_id.into();
        let signing_key = derive_signing_key(&issuer, &client_id);
        let signing_kid = derive_kid(&signing_key);
        Self {
            issuer,
            client_id,
            signing_kid,
            signing_key,
            token_ttl_secs: 3600,
            issued_at: 1_750_000_000,
            users: BTreeMap::new(),
            default_subject: None,
            failure: None,
            codes: BTreeMap::new(),
            access_tokens: BTreeMap::new(),
            seq: 0,
        }
    }

    /// Register a user the provider can authenticate. The first registered user
    /// becomes the default login when an authorize request omits `login_as`.
    pub fn with_user(mut self, user: FakeUser) -> Self {
        if self.default_subject.is_none() {
            self.default_subject = Some(user.subject.0.clone());
        }
        self.users.insert(user.subject.0.clone(), user.claims);
        self
    }

    /// Pin the active [`FailureMode`]. Without this the provider behaves nominally.
    pub fn with_failure(mut self, failure: FailureMode) -> Self {
        self.failure = Some(failure);
        self
    }

    /// Override the deterministic `iat` stamp written into issued `id_token`s.
    pub fn with_issued_at(mut self, issued_at: u64) -> Self {
        self.issued_at = issued_at;
        self
    }

    /// Issuer identifier this provider advertises.
    pub fn issuer(&self) -> &str {
        &self.issuer
    }

    fn authorization_endpoint(&self) -> String {
        format!("{}/authorize", self.issuer)
    }

    fn token_endpoint(&self) -> String {
        format!("{}/token", self.issuer)
    }

    fn userinfo_endpoint(&self) -> String {
        format!("{}/userinfo", self.issuer)
    }

    fn jwks_uri(&self) -> String {
        format!("{}/jwks", self.issuer)
    }

    /// Build the OIDC discovery document advertising this provider's endpoints.
    pub fn discovery_document(&self) -> OidcDiscoveryDocument {
        OidcDiscoveryDocument {
            issuer: self.issuer.clone(),
            authorization_endpoint: self.authorization_endpoint(),
            token_endpoint: self.token_endpoint(),
            userinfo_endpoint: self.userinfo_endpoint(),
            jwks_uri: self.jwks_uri(),
            response_types_supported: vec!["code".to_owned()],
            subject_types_supported: vec!["public".to_owned()],
            id_token_signing_alg_values_supported: vec!["HS256".to_owned()],
            scopes_supported: vec![
                "openid".to_owned(),
                "email".to_owned(),
                "profile".to_owned(),
            ],
        }
    }

    /// Build the JWKS advertising the `id_token` signing key.
    ///
    /// Under [`FailureMode::RotateSigningKey`] the published key id differs from
    /// the one used to sign tokens, so an RP cannot find a matching key.
    pub fn jwks(&self) -> JsonWebKeySet {
        let kid = if self.failure == Some(FailureMode::RotateSigningKey) {
            format!("{}-rotated", self.signing_kid)
        } else {
            self.signing_kid.clone()
        };
        JsonWebKeySet {
            keys: vec![JsonWebKey {
                kty: "oct".to_owned(),
                kid,
                alg: "HS256".to_owned(),
                key_use: "sig".to_owned(),
                k: URL_SAFE_NO_PAD.encode(&self.signing_key),
            }],
        }
    }

    /// Handle an authorize request, returning the callback redirect.
    ///
    /// Invalid client or request parameters fail closed with an [`OidcError`]
    /// rather than redirecting (an RP must never be redirected on an unverified
    /// callback). A valid request returns a redirect carrying a fresh code and the
    /// echoed `state`; under [`FailureMode::DenyAuthorization`] it returns a
    /// redirect carrying `error=access_denied` and the echoed `state`.
    pub fn authorize(
        &mut self,
        request: &AuthorizeRequest,
    ) -> Result<AuthorizeRedirect, OidcError> {
        if request.client_id != self.client_id {
            return Err(OidcError::new("unauthorized_client", "unknown client id"));
        }
        if request.response_type != "code" {
            return Err(OidcError::new(
                "unsupported_response_type",
                "only response_type=code is supported",
            ));
        }
        if request.redirect_uri.is_empty() {
            return Err(OidcError::new(
                "invalid_request",
                "redirect_uri is required",
            ));
        }

        let subject = match request.login_as.as_deref() {
            Some(subject) => subject.to_owned(),
            None => self
                .default_subject
                .clone()
                .ok_or_else(|| OidcError::new("access_denied", "no user is configured"))?,
        };
        if !self.users.contains_key(&subject) {
            return Err(OidcError::new("access_denied", "no such user"));
        }

        if self.failure == Some(FailureMode::DenyAuthorization) {
            return Ok(AuthorizeRedirect {
                location: format!(
                    "{}?error=access_denied&error_description=user+denied+consent&state={}",
                    request.redirect_uri,
                    encode_query(&request.state),
                ),
            });
        }

        let code = self.next_id("fc");
        self.codes.insert(
            code.clone(),
            IssuedCode {
                subject,
                client_id: request.client_id.clone(),
                redirect_uri: request.redirect_uri.clone(),
                nonce: request.nonce.clone(),
                code_challenge: request.code_challenge.clone(),
                consumed: false,
            },
        );
        Ok(AuthorizeRedirect {
            location: format!(
                "{}?code={}&state={}",
                request.redirect_uri,
                encode_query(&code),
                encode_query(&request.state),
            ),
        })
    }

    /// Redeem an authorization code for tokens.
    ///
    /// Enforces grant type, single-use codes, and client/redirect/PKCE binding.
    /// The returned `id_token` is a signed `HS256` JWT verifiable against
    /// [`FakeOidcProvider::jwks`].
    pub fn token(&mut self, request: &TokenRequest) -> Result<TokenResponse, OidcError> {
        if request.grant_type != "authorization_code" {
            return Err(OidcError::new(
                "unsupported_grant_type",
                "only authorization_code is supported",
            ));
        }
        if self.failure == Some(FailureMode::RejectTokenExchange) {
            return Err(OidcError::new(
                "invalid_grant",
                "authorization code exchange rejected",
            ));
        }

        let code = self
            .codes
            .get_mut(&request.code)
            .ok_or_else(|| OidcError::new("invalid_grant", "unknown authorization code"))?;
        if code.consumed {
            return Err(OidcError::new(
                "invalid_grant",
                "authorization code already redeemed",
            ));
        }
        if request.client_id != code.client_id {
            return Err(OidcError::new("invalid_client", "client id mismatch"));
        }
        if request.redirect_uri != code.redirect_uri {
            return Err(OidcError::new("invalid_grant", "redirect_uri mismatch"));
        }
        match (&code.code_challenge, &request.code_verifier) {
            (Some(challenge), Some(verifier)) => {
                if &pkce_s256(verifier) != challenge {
                    return Err(OidcError::new("invalid_grant", "PKCE verifier mismatch"));
                }
            }
            (Some(_), None) => {
                return Err(OidcError::new("invalid_grant", "PKCE verifier required"));
            }
            (None, _) => {}
        }

        code.consumed = true;
        let subject = code.subject.clone();
        let nonce = code.nonce.clone();
        let claims = self
            .users
            .get(&subject)
            .cloned()
            .ok_or_else(|| OidcError::new("invalid_grant", "user no longer exists"))?;

        let id_token = self.sign_id_token(&subject, nonce.as_deref(), &claims);
        let access_token = self.next_id("fat");
        self.access_tokens
            .insert(access_token.clone(), subject.clone());

        Ok(TokenResponse {
            access_token,
            token_type: "Bearer".to_owned(),
            expires_in: self.token_ttl_secs,
            id_token,
            scope: "openid email profile".to_owned(),
        })
    }

    /// Return the userinfo claims for a bearer access token.
    ///
    /// Under [`FailureMode::RejectUserinfo`] every request fails with
    /// `invalid_token`.
    pub fn userinfo(&self, access_token: &str) -> Result<UserInfoResponse, OidcError> {
        if self.failure == Some(FailureMode::RejectUserinfo) {
            return Err(OidcError::new("invalid_token", "bearer token rejected"));
        }
        let subject = self
            .access_tokens
            .get(access_token)
            .ok_or_else(|| OidcError::new("invalid_token", "unknown access token"))?;
        let claims = self
            .users
            .get(subject)
            .ok_or_else(|| OidcError::new("invalid_token", "user no longer exists"))?;
        Ok(UserInfoResponse {
            sub: subject.clone(),
            email: claims.email.clone(),
            email_verified: claims.email_verified,
            name: claims.display_name.clone(),
            preferred_username: claims.username.clone(),
            picture: claims.avatar_url.clone(),
            locale: claims.locale.clone(),
        })
    }

    /// Verify an `id_token` against this provider's signing key and return its
    /// decoded claims.
    ///
    /// This is the relying-party side of the JWKS round-trip: it recomputes the
    /// `HS256` signature with the published key and rejects a token whose
    /// signature, header `kid`, or algorithm does not match. E2E suites use it to
    /// assert both the happy path and the
    /// [`FailureMode::TamperIdTokenSignature`] / [`FailureMode::RotateSigningKey`]
    /// failures.
    pub fn verify_id_token(&self, id_token: &str) -> Result<IdTokenClaims, OidcError> {
        let mut parts = id_token.split('.');
        let (header_b64, payload_b64, signature_b64) =
            match (parts.next(), parts.next(), parts.next(), parts.next()) {
                (Some(h), Some(p), Some(s), None) => (h, p, s),
                _ => return Err(OidcError::new("invalid_token", "malformed JWT")),
            };

        let header: serde_json::Value = decode_json(header_b64)?;
        if header.get("alg").and_then(|v| v.as_str()) != Some("HS256") {
            return Err(OidcError::new(
                "invalid_token",
                "unexpected signing algorithm",
            ));
        }
        let published = self.jwks();
        let key = published
            .keys
            .iter()
            .find(|k| Some(k.kid.as_str()) == header.get("kid").and_then(|v| v.as_str()))
            .ok_or_else(|| OidcError::new("invalid_token", "no matching signing key"))?;
        let key_bytes = URL_SAFE_NO_PAD
            .decode(&key.k)
            .map_err(|_| OidcError::new("invalid_token", "unreadable signing key"))?;

        let signing_input = format!("{header_b64}.{payload_b64}");
        let expected = URL_SAFE_NO_PAD.encode(hmac_sha256(&key_bytes, signing_input.as_bytes()));
        if expected != signature_b64 {
            return Err(OidcError::new("invalid_token", "signature mismatch"));
        }
        decode_json(payload_b64)
    }

    fn sign_id_token(
        &self,
        subject: &str,
        nonce: Option<&str>,
        claims: &ExternalIdentityClaims,
    ) -> String {
        let header = serde_json::json!({
            "alg": "HS256",
            "typ": "JWT",
            "kid": self.signing_kid,
        });
        let payload = IdTokenClaims {
            iss: self.issuer.clone(),
            sub: subject.to_owned(),
            aud: self.client_id.clone(),
            exp: self.issued_at + self.token_ttl_secs,
            iat: self.issued_at,
            nonce: nonce.map(str::to_owned),
            email: claims.email.clone(),
            email_verified: claims.email_verified,
        };
        let header_b64 = URL_SAFE_NO_PAD.encode(serde_json::to_vec(&header).expect("header JSON"));
        let payload_b64 =
            URL_SAFE_NO_PAD.encode(serde_json::to_vec(&payload).expect("payload JSON"));
        let signing_input = format!("{header_b64}.{payload_b64}");
        let mut signature =
            URL_SAFE_NO_PAD.encode(hmac_sha256(&self.signing_key, signing_input.as_bytes()));
        if self.failure == Some(FailureMode::TamperIdTokenSignature) {
            signature = tamper(&signature);
        }
        format!("{signing_input}.{signature}")
    }

    /// Mint the next deterministic identifier with the given prefix.
    fn next_id(&mut self, prefix: &str) -> String {
        self.seq += 1;
        format!("{prefix}_{:08}", self.seq)
    }
}

/// Derive the deterministic symmetric signing key from issuer and client id.
fn derive_signing_key(issuer: &str, client_id: &str) -> Vec<u8> {
    let mut hasher = Sha256::new();
    hasher.update(b"awaken-iam.fake-oidc.signing-key\0");
    hasher.update(issuer.as_bytes());
    hasher.update(b"\0");
    hasher.update(client_id.as_bytes());
    hasher.finalize().to_vec()
}

/// Derive a stable key id from the signing key material.
fn derive_kid(signing_key: &[u8]) -> String {
    let digest = Sha256::digest(signing_key);
    format!("fake-{}", hex8(&digest))
}

/// Lowercase-hex encode the first eight bytes of `bytes`.
fn hex8(bytes: &[u8]) -> String {
    bytes
        .iter()
        .take(8)
        .map(|b| format!("{b:02x}"))
        .collect::<String>()
}

/// Compute the PKCE `S256` challenge for a verifier: `BASE64URL(SHA256(verifier))`.
fn pkce_s256(verifier: &str) -> String {
    URL_SAFE_NO_PAD.encode(Sha256::digest(verifier.as_bytes()))
}

/// HMAC-SHA256 of `msg` under `key`, per RFC 2104.
fn hmac_sha256(key: &[u8], msg: &[u8]) -> [u8; 32] {
    let mut block = [0u8; SHA256_BLOCK];
    if key.len() > SHA256_BLOCK {
        let digest = Sha256::digest(key);
        block[..digest.len()].copy_from_slice(&digest);
    } else {
        block[..key.len()].copy_from_slice(key);
    }
    let mut ipad = [0x36u8; SHA256_BLOCK];
    let mut opad = [0x5cu8; SHA256_BLOCK];
    for index in 0..SHA256_BLOCK {
        ipad[index] ^= block[index];
        opad[index] ^= block[index];
    }
    let mut inner = Sha256::new();
    inner.update(ipad);
    inner.update(msg);
    let inner_digest = inner.finalize();
    let mut outer = Sha256::new();
    outer.update(opad);
    outer.update(inner_digest);
    outer.finalize().into()
}

/// Flip the leading character of a base64url signature to a different one so the
/// signature no longer verifies, while staying a valid base64url string.
fn tamper(signature: &str) -> String {
    let mut chars = signature.chars();
    match chars.next() {
        Some(first) => {
            let replacement = if first == 'A' { 'B' } else { 'A' };
            let mut tampered = String::with_capacity(signature.len());
            tampered.push(replacement);
            tampered.extend(chars);
            tampered
        }
        None => "A".to_owned(),
    }
}

/// Minimal `application/x-www-form-urlencoded` value encoding for the redirect
/// query parameters this provider emits (codes, states, and fixed descriptions).
fn encode_query(value: &str) -> String {
    let mut out = String::with_capacity(value.len());
    for byte in value.bytes() {
        match byte {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                out.push(byte as char);
            }
            b' ' => out.push('+'),
            _ => out.push_str(&format!("%{byte:02X}")),
        }
    }
    out
}

/// Decode a base64url JWT segment into a deserializable value.
fn decode_json<T: for<'de> Deserialize<'de>>(segment: &str) -> Result<T, OidcError> {
    let bytes = URL_SAFE_NO_PAD
        .decode(segment)
        .map_err(|_| OidcError::new("invalid_token", "segment is not base64url"))?;
    serde_json::from_slice(&bytes)
        .map_err(|_| OidcError::new("invalid_token", "segment is not valid JSON"))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn provider() -> FakeOidcProvider {
        FakeOidcProvider::new("https://idp.test", "client-123")
            .with_user(FakeUser::with_email("subject-1", "user@example.com"))
    }

    fn authorize_request() -> AuthorizeRequest {
        AuthorizeRequest {
            client_id: "client-123".into(),
            redirect_uri: "https://rp.test/callback".into(),
            response_type: "code".into(),
            state: "state token".into(),
            nonce: Some("nonce-1".into()),
            code_challenge: None,
            login_as: None,
        }
    }

    fn code_from(redirect: &AuthorizeRedirect) -> String {
        let query = redirect.location.split_once('?').unwrap().1;
        query
            .split('&')
            .find_map(|pair| pair.strip_prefix("code="))
            .unwrap()
            .to_owned()
    }

    #[test]
    fn discovery_document_advertises_all_endpoints() {
        let doc = provider().discovery_document();
        assert_eq!(doc.issuer, "https://idp.test");
        assert_eq!(doc.authorization_endpoint, "https://idp.test/authorize");
        assert_eq!(doc.token_endpoint, "https://idp.test/token");
        assert_eq!(doc.userinfo_endpoint, "https://idp.test/userinfo");
        assert_eq!(doc.jwks_uri, "https://idp.test/jwks");
        assert_eq!(doc.response_types_supported, vec!["code".to_owned()]);
        assert_eq!(
            doc.id_token_signing_alg_values_supported,
            vec!["HS256".to_owned()]
        );
    }

    #[test]
    fn jwks_publishes_the_signing_key() {
        let jwks = provider().jwks();
        assert_eq!(jwks.keys.len(), 1);
        let key = &jwks.keys[0];
        assert_eq!(key.kty, "oct");
        assert_eq!(key.alg, "HS256");
        assert_eq!(key.key_use, "sig");
        assert!(key.kid.starts_with("fake-"));
        assert!(!key.k.is_empty());
    }

    #[test]
    fn provider_is_deterministic_across_instances() {
        let first = provider().jwks();
        let second = provider().jwks();
        assert_eq!(first, second);

        let mut a = provider();
        let mut b = provider();
        let ra = a.authorize(&authorize_request()).unwrap();
        let rb = b.authorize(&authorize_request()).unwrap();
        assert_eq!(ra, rb);
    }

    #[test]
    fn happy_path_authorize_token_userinfo_round_trip() {
        let mut idp = provider();
        let redirect = idp.authorize(&authorize_request()).unwrap();
        assert!(redirect.location.starts_with("https://rp.test/callback?"));
        assert!(redirect.location.contains("state=state+token"));
        let code = code_from(&redirect);

        let tokens = idp
            .token(&TokenRequest {
                grant_type: "authorization_code".into(),
                code: code.clone(),
                redirect_uri: "https://rp.test/callback".into(),
                client_id: "client-123".into(),
                code_verifier: None,
            })
            .unwrap();
        assert_eq!(tokens.token_type, "Bearer");

        let claims = idp.verify_id_token(&tokens.id_token).unwrap();
        assert_eq!(claims.iss, "https://idp.test");
        assert_eq!(claims.sub, "subject-1");
        assert_eq!(claims.aud, "client-123");
        assert_eq!(claims.nonce.as_deref(), Some("nonce-1"));
        assert_eq!(claims.email.as_deref(), Some("user@example.com"));
        assert_eq!(claims.exp, claims.iat + 3600);

        let info = idp.userinfo(&tokens.access_token).unwrap();
        assert_eq!(info.sub, "subject-1");
        assert_eq!(info.email.as_deref(), Some("user@example.com"));
        assert_eq!(info.email_verified, Some(true));
    }

    #[test]
    fn authorization_code_is_single_use() {
        let mut idp = provider();
        let redirect = idp.authorize(&authorize_request()).unwrap();
        let code = code_from(&redirect);
        let request = TokenRequest {
            grant_type: "authorization_code".into(),
            code,
            redirect_uri: "https://rp.test/callback".into(),
            client_id: "client-123".into(),
            code_verifier: None,
        };
        idp.token(&request).unwrap();
        let reuse = idp.token(&request).unwrap_err();
        assert_eq!(reuse.error, "invalid_grant");
    }

    #[test]
    fn token_rejects_redirect_uri_mismatch() {
        let mut idp = provider();
        let redirect = idp.authorize(&authorize_request()).unwrap();
        let code = code_from(&redirect);
        let err = idp
            .token(&TokenRequest {
                grant_type: "authorization_code".into(),
                code,
                redirect_uri: "https://rp.test/other".into(),
                client_id: "client-123".into(),
                code_verifier: None,
            })
            .unwrap_err();
        assert_eq!(err.error, "invalid_grant");
    }

    #[test]
    fn pkce_challenge_is_enforced() {
        let verifier = "the-pkce-code-verifier-value-1234567890";
        let challenge = pkce_s256(verifier);
        let mut idp = provider();
        let mut request = authorize_request();
        request.code_challenge = Some(challenge);
        let redirect = idp.authorize(&request).unwrap();
        let code = code_from(&redirect);

        let wrong = idp
            .token(&TokenRequest {
                grant_type: "authorization_code".into(),
                code: code.clone(),
                redirect_uri: "https://rp.test/callback".into(),
                client_id: "client-123".into(),
                code_verifier: Some("wrong-verifier".into()),
            })
            .unwrap_err();
        assert_eq!(wrong.error, "invalid_grant");

        let ok = idp.token(&TokenRequest {
            grant_type: "authorization_code".into(),
            code,
            redirect_uri: "https://rp.test/callback".into(),
            client_id: "client-123".into(),
            code_verifier: Some(verifier.into()),
        });
        assert!(ok.is_ok());
    }

    #[test]
    fn unknown_client_is_rejected_without_redirect() {
        let mut idp = provider();
        let mut request = authorize_request();
        request.client_id = "intruder".into();
        let err = idp.authorize(&request).unwrap_err();
        assert_eq!(err.error, "unauthorized_client");
    }

    #[test]
    fn login_as_selects_a_registered_user() {
        let mut idp = provider().with_user(FakeUser::with_email("subject-2", "two@example.com"));
        let mut request = authorize_request();
        request.login_as = Some("subject-2".into());
        let redirect = idp.authorize(&request).unwrap();
        let code = code_from(&redirect);
        let tokens = idp
            .token(&TokenRequest {
                grant_type: "authorization_code".into(),
                code,
                redirect_uri: "https://rp.test/callback".into(),
                client_id: "client-123".into(),
                code_verifier: None,
            })
            .unwrap();
        let info = idp.userinfo(&tokens.access_token).unwrap();
        assert_eq!(info.sub, "subject-2");
        assert_eq!(info.email.as_deref(), Some("two@example.com"));
    }

    #[test]
    fn deny_authorization_failure_redirects_with_error() {
        let mut idp = provider().with_failure(FailureMode::DenyAuthorization);
        let redirect = idp.authorize(&authorize_request()).unwrap();
        assert!(redirect.location.contains("error=access_denied"));
        assert!(redirect.location.contains("state=state+token"));
        assert!(!redirect.location.contains("code="));
    }

    #[test]
    fn reject_token_exchange_failure_returns_invalid_grant() {
        let mut idp = provider().with_failure(FailureMode::RejectTokenExchange);
        let redirect = idp.authorize(&authorize_request()).unwrap();
        let code = code_from(&redirect);
        let err = idp
            .token(&TokenRequest {
                grant_type: "authorization_code".into(),
                code,
                redirect_uri: "https://rp.test/callback".into(),
                client_id: "client-123".into(),
                code_verifier: None,
            })
            .unwrap_err();
        assert_eq!(err.error, "invalid_grant");
    }

    #[test]
    fn tampered_id_token_fails_verification() {
        let mut idp = provider().with_failure(FailureMode::TamperIdTokenSignature);
        let redirect = idp.authorize(&authorize_request()).unwrap();
        let code = code_from(&redirect);
        let tokens = idp
            .token(&TokenRequest {
                grant_type: "authorization_code".into(),
                code,
                redirect_uri: "https://rp.test/callback".into(),
                client_id: "client-123".into(),
                code_verifier: None,
            })
            .unwrap();
        let err = idp.verify_id_token(&tokens.id_token).unwrap_err();
        assert_eq!(err.error, "invalid_token");
    }

    #[test]
    fn rotated_signing_key_breaks_verification() {
        // Sign with the real key, then serve a JWKS under a rotated kid.
        let mut signed = provider();
        let redirect = signed.authorize(&authorize_request()).unwrap();
        let code = code_from(&redirect);
        let tokens = signed
            .token(&TokenRequest {
                grant_type: "authorization_code".into(),
                code,
                redirect_uri: "https://rp.test/callback".into(),
                client_id: "client-123".into(),
                code_verifier: None,
            })
            .unwrap();
        let rotated = provider().with_failure(FailureMode::RotateSigningKey);
        let err = rotated.verify_id_token(&tokens.id_token).unwrap_err();
        assert_eq!(err.error, "invalid_token");
    }

    #[test]
    fn reject_userinfo_failure_returns_invalid_token() {
        let mut idp = provider().with_failure(FailureMode::RejectUserinfo);
        let redirect = idp.authorize(&authorize_request()).unwrap();
        let code = code_from(&redirect);
        let tokens = idp
            .token(&TokenRequest {
                grant_type: "authorization_code".into(),
                code,
                redirect_uri: "https://rp.test/callback".into(),
                client_id: "client-123".into(),
                code_verifier: None,
            })
            .unwrap();
        let err = idp.userinfo(&tokens.access_token).unwrap_err();
        assert_eq!(err.error, "invalid_token");
    }

    #[test]
    fn userinfo_rejects_unknown_token() {
        let err = provider().userinfo("fat_99999999").unwrap_err();
        assert_eq!(err.error, "invalid_token");
    }

    #[test]
    fn discovery_and_token_response_serialize_to_json() {
        let doc = provider().discovery_document();
        let json = serde_json::to_string(&doc).unwrap();
        assert!(json.contains("\"issuer\":\"https://idp.test\""));
        let round: OidcDiscoveryDocument = serde_json::from_str(&json).unwrap();
        assert_eq!(round, doc);

        let jwks = provider().jwks();
        let key_json = serde_json::to_string(&jwks).unwrap();
        assert!(key_json.contains("\"use\":\"sig\""));
    }

    #[test]
    fn hmac_matches_known_rfc4231_vector() {
        // RFC 4231 test case 2: key "Jefe", data "what do ya want for nothing?".
        let mac = hmac_sha256(b"Jefe", b"what do ya want for nothing?");
        let hex = mac.iter().map(|b| format!("{b:02x}")).collect::<String>();
        assert_eq!(
            hex,
            "5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843"
        );
    }
}
