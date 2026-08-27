//! Downstream OAuth 2.0 authorization server (IAM as the provider).
//!
//! This is the **internal** half of the broker posture in
//! [auth server](../../../docs/design/auth-server.md): where the upstream
//! adapters make IAM a *client* of Google/GitHub/any OIDC provider, this module
//! makes IAM an **authorization server** that *its own* product clients integrate
//! against with the standard authorization-code + PKCE flow. A product redirects
//! the browser to IAM, IAM authenticates the end-user through its session core,
//! issues a single-use authorization code bound to the client, and redeems that
//! code for an authorized grant the caller mints an opaque access token from.
//!
//! Scope of this core: the security-critical state machine — registered-client
//! validation, redirect-URI allowlisting, scope down-scoping, single-use/expiring
//! codes, confidential-client authentication, and PKCE S256 verification. Tokens
//! are **opaque** (minted by [`SessionMinter`](crate::SessionMinter) /
//! [`ApiTokenMinter`](crate::ApiTokenMinter) and validated at the userinfo
//! endpoint), so this module needs no JWT signing; asymmetric `id_token` issuance
//! and JWKS publication are a separate, additive layer.

use std::collections::{BTreeSet, HashMap};
use std::sync::{Arc, RwLock};

use awaken_iam_contract::{AccountId, Timestamp};
use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use sha2::{Digest, Sha256};

use crate::EntropySource;
use crate::hash_session_token;
use crate::repositories::{
    AuthCodeRepository, OAuthClientRepository, RepositoryError, RepositoryResult,
};

/// Bytes of entropy in a freshly minted authorization code.
const CODE_BYTES: usize = 32;

/// Failure modes of the downstream authorization-code flow.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum OAuthProviderError {
    /// No client is registered under the presented `client_id`.
    #[error("unknown oauth client")]
    UnknownClient,
    /// The `redirect_uri` is not one the client registered.
    #[error("redirect uri is not registered for this client")]
    UnregisteredRedirectUri,
    /// A requested scope is outside the client's allowed set.
    #[error("requested scope is not allowed for this client")]
    ScopeNotAllowed,
    /// A public client started a flow without a PKCE challenge.
    #[error("public clients must use pkce")]
    PkceRequired,
    /// A PKCE challenge used a method other than the supported `S256`.
    #[error("unsupported code_challenge_method (only S256)")]
    UnsupportedCodeChallengeMethod,
    /// The authorization code is unknown, already used, or expired.
    #[error("invalid or expired authorization grant")]
    InvalidGrant,
    /// The `redirect_uri` at redemption does not match the one at issuance.
    #[error("redirect uri does not match the authorization request")]
    RedirectUriMismatch,
    /// A confidential client presented a missing or wrong secret.
    #[error("invalid client authentication")]
    InvalidClientSecret,
    /// The PKCE verifier was missing or did not match the stored challenge.
    #[error("pkce verification failed")]
    PkceVerificationFailed,
    /// The authoritative OAuth repository could not serve the operation.
    #[error("oauth authorization storage is unavailable")]
    StorageUnavailable,
}

/// A product client registered to integrate against IAM as an OAuth provider.
///
/// The value is serialisable so a persistence adapter can round-trip it as the
/// stored shape of a registered client — only the `secret_hash` is retained, the
/// cleartext secret never is.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct RegisteredClient {
    /// Public client identifier.
    pub client_id: String,
    /// Exact redirect URIs the client may use (allowlisted, never pattern-matched).
    pub redirect_uris: Vec<String>,
    /// Scopes this client may request; a request may down-scope but never widen.
    pub allowed_scopes: BTreeSet<String>,
    /// Hashed secret for a confidential client; `None` for a public client,
    /// which must therefore use PKCE.
    pub secret_hash: Option<String>,
}

impl RegisteredClient {
    /// Register a public client (no secret); it must use PKCE.
    pub fn public<I, S>(client_id: impl Into<String>, redirect_uris: Vec<String>, scopes: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        Self {
            client_id: client_id.into(),
            redirect_uris,
            allowed_scopes: scopes.into_iter().map(Into::into).collect(),
            secret_hash: None,
        }
    }

    /// Register a confidential client from a cleartext secret (hashed at rest).
    pub fn confidential<I, S>(
        client_id: impl Into<String>,
        client_secret: &str,
        redirect_uris: Vec<String>,
        scopes: I,
    ) -> Self
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        Self {
            client_id: client_id.into(),
            redirect_uris,
            allowed_scopes: scopes.into_iter().map(Into::into).collect(),
            secret_hash: Some(hash_session_token(client_secret)),
        }
    }

    fn is_public(&self) -> bool {
        self.secret_hash.is_none()
    }

    fn allows_redirect(&self, redirect_uri: &str) -> bool {
        self.redirect_uris.iter().any(|uri| uri == redirect_uri)
    }

    fn allows_scopes(&self, scopes: &[String]) -> bool {
        scopes
            .iter()
            .all(|scope| self.allowed_scopes.contains(scope))
    }
}

/// Registry of clients that may integrate against IAM as an OAuth provider.
#[derive(Debug, Default, Clone)]
pub struct OAuthClientRegistry {
    clients: Arc<RwLock<HashMap<String, RegisteredClient>>>,
}

impl OAuthClientRegistry {
    /// An empty registry.
    pub fn new() -> Self {
        Self::default()
    }

    /// Register or replace a client.
    pub fn register(&self, client: RegisteredClient) {
        self.clients
            .write()
            .expect("oauth client registry lock poisoned")
            .insert(client.client_id.clone(), client);
    }

    /// Look up a registered client by id.
    pub fn get(&self, client_id: &str) -> Option<RegisteredClient> {
        self.clients
            .read()
            .expect("oauth client registry lock poisoned")
            .get(client_id)
            .cloned()
    }

    /// List the registered clients ordered by id for stable iteration.
    pub fn clients(&self) -> Vec<RegisteredClient> {
        let mut clients: Vec<RegisteredClient> = self
            .clients
            .read()
            .expect("oauth client registry lock poisoned")
            .values()
            .cloned()
            .collect();
        clients.sort_by(|left, right| left.client_id.cmp(&right.client_id));
        clients
    }
}

impl OAuthClientRepository for OAuthClientRegistry {
    fn upsert(&self, client: RegisteredClient) -> RepositoryResult<()> {
        self.register(client);
        Ok(())
    }

    fn get(&self, client_id: &str) -> RepositoryResult<Option<RegisteredClient>> {
        Ok(OAuthClientRegistry::get(self, client_id))
    }

    fn list(&self) -> RepositoryResult<Vec<RegisteredClient>> {
        Ok(self.clients())
    }

    fn remove(&self, client_id: &str) -> RepositoryResult<()> {
        self.clients
            .write()
            .expect("oauth client registry lock poisoned")
            .remove(client_id)
            .map(|_| ())
            .ok_or_else(|| RepositoryError::NotFound(format!("oauth client {client_id} not found")))
    }
}

/// A downstream authorization request (`GET /v1/oauth/authorize` parameters).
///
/// The end-user is authenticated separately through the IAM session core; the
/// caller passes the resolved [`AccountId`] to [`OAuthAuthorizationServer::issue_code`].
#[derive(Debug, Clone)]
pub struct AuthorizationRequest {
    /// Requesting client id.
    pub client_id: String,
    /// Redirect URI to return the code to; must be registered for the client.
    pub redirect_uri: String,
    /// Requested scopes; must be a subset of the client's allowed scopes.
    pub scopes: Vec<String>,
    /// PKCE code challenge (S256). Required for public clients.
    pub code_challenge: Option<String>,
    /// PKCE challenge method; only `S256` is supported when present.
    pub code_challenge_method: Option<String>,
    /// OIDC `nonce` echoed back to the client on redemption.
    pub nonce: Option<String>,
    /// Opaque `state` echoed back alongside the issued code.
    pub state: Option<String>,
}

/// The cleartext authorization code, returned exactly once at issuance.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IssuedAuthorizationCode {
    /// Cleartext code to deliver to the client's redirect URI.
    pub code: String,
    /// The `state` echoed from the request, if any.
    pub state: Option<String>,
}

/// A token-endpoint redemption (`POST /v1/oauth/token`, `authorization_code`).
#[derive(Debug, Clone)]
pub struct TokenRedemption {
    /// Client id presented at the token endpoint.
    pub client_id: String,
    /// Client secret for a confidential client; `None` for a public client.
    pub client_secret: Option<String>,
    /// The authorization code to redeem.
    pub code: String,
    /// Redirect URI; must match the one bound at issuance.
    pub redirect_uri: String,
    /// PKCE verifier; required when the code carries a challenge.
    pub code_verifier: Option<String>,
}

/// The authorized grant a successful redemption resolves to.
///
/// The caller mints an opaque access token (and any refresh token) for this
/// account and scopes; this module never holds token material.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuthorizedGrant {
    /// Account the end-user authenticated as.
    pub account_id: AccountId,
    /// Granted scopes (the request's down-scoped set).
    pub scopes: Vec<String>,
    /// OIDC `nonce` to bind into an issued `id_token`, if the request carried one.
    pub nonce: Option<String>,
}

/// Internal record of an issued, not-yet-redeemed authorization code.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StoredAuthorizationCode {
    /// SHA-256 hash of the cleartext browser code.
    pub code_hash: String,
    /// Client the code was issued to.
    pub client_id: String,
    /// Exact redirect URI bound at issuance.
    pub redirect_uri: String,
    /// Authenticated account the grant represents.
    pub account_id: AccountId,
    /// Down-scoped grant scopes.
    pub scopes: Vec<String>,
    /// Optional PKCE S256 challenge.
    pub code_challenge: Option<String>,
    /// Optional OIDC nonce.
    pub nonce: Option<String>,
    /// Exclusive expiry boundary.
    pub expires_at: Timestamp,
    /// Consumption timestamp; `None` until the atomic replay fence succeeds.
    pub consumed_at: Option<Timestamp>,
}

/// Process-local authorization-code repository for tests and single-process
/// compositions. Durable compositions inject their shared SQL store instead.
#[derive(Debug, Default)]
struct InMemoryAuthCodeRepository {
    codes: RwLock<HashMap<String, StoredAuthorizationCode>>,
}

impl AuthCodeRepository for InMemoryAuthCodeRepository {
    fn create(&self, code: StoredAuthorizationCode) -> RepositoryResult<()> {
        let mut codes = self.codes.write().expect("oauth code lock poisoned");
        if codes.contains_key(&code.code_hash) {
            return Err(RepositoryError::Conflict(
                "duplicate authorization code".into(),
            ));
        }
        codes.insert(code.code_hash.clone(), code);
        Ok(())
    }

    fn get(&self, code_hash: &str) -> RepositoryResult<Option<StoredAuthorizationCode>> {
        Ok(self
            .codes
            .read()
            .expect("oauth code lock poisoned")
            .get(code_hash)
            .cloned())
    }

    fn consume_if_live(&self, code_hash: &str, now: &Timestamp) -> RepositoryResult<bool> {
        let mut codes = self.codes.write().expect("oauth code lock poisoned");
        let Some(code) = codes.get_mut(code_hash) else {
            return Ok(false);
        };
        if code.consumed_at.is_some() || code.expires_at.0 <= now.0 {
            return Ok(false);
        }
        code.consumed_at = Some(now.clone());
        Ok(true)
    }
}

/// IAM's downstream OAuth 2.0 authorization server.
pub struct OAuthAuthorizationServer<E: EntropySource> {
    clients: Arc<dyn OAuthClientRepository>,
    codes: Arc<dyn AuthCodeRepository>,
    entropy: E,
}

impl<E: EntropySource> std::fmt::Debug for OAuthAuthorizationServer<E> {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("OAuthAuthorizationServer")
            .field("clients", &"oauth-client-repository")
            .field("codes", &"authorization-code-repository")
            .finish_non_exhaustive()
    }
}

impl<E: EntropySource> OAuthAuthorizationServer<E> {
    /// Build a server over a client registry and an entropy source.
    pub fn new(registry: OAuthClientRegistry, entropy: E) -> Self {
        Self {
            clients: Arc::new(registry),
            codes: Arc::new(InMemoryAuthCodeRepository::default()),
            entropy,
        }
    }

    /// Build over caller-selected authoritative repositories.
    pub fn with_repositories(
        clients: Arc<dyn OAuthClientRepository>,
        codes: Arc<dyn AuthCodeRepository>,
        entropy: E,
    ) -> Self {
        Self {
            clients,
            codes,
            entropy,
        }
    }

    /// Register or replace a client in the underlying registry.
    ///
    /// Lets a caller that built the server over an empty registry add clients
    /// later (e.g. as a deployment provisions its product integrations) without
    /// reconstructing the server and discarding issued codes.
    pub fn register_client(&self, client: RegisteredClient) -> Result<(), OAuthProviderError> {
        self.clients
            .upsert(client)
            .map_err(|_| OAuthProviderError::StorageUnavailable)
    }

    /// Authenticate a client at the token endpoint (RFC 6749 §2.3) for a grant
    /// that does not redeem a freshly issued code — notably the `refresh_token`
    /// grant, where there is no authorization code to carry the client binding.
    ///
    /// A confidential client must present the secret it registered with; a public
    /// client presents none. The presented secret is compared against the stored
    /// hash, never the cleartext. On success the registered client is returned so
    /// the caller can apply any further client-scoped checks; failures collapse to
    /// [`OAuthProviderError::UnknownClient`] or
    /// [`OAuthProviderError::InvalidClientSecret`] so a caller cannot probe which
    /// clients exist or distinguish a missing from a wrong secret.
    pub fn authenticate_client(
        &self,
        client_id: &str,
        client_secret: Option<&str>,
    ) -> Result<RegisteredClient, OAuthProviderError> {
        let client = self
            .clients
            .get(client_id)
            .map_err(|_| OAuthProviderError::StorageUnavailable)?
            .ok_or(OAuthProviderError::UnknownClient)?;
        if let Some(expected) = &client.secret_hash {
            let presented = client_secret.ok_or(OAuthProviderError::InvalidClientSecret)?;
            if &hash_session_token(presented) != expected {
                return Err(OAuthProviderError::InvalidClientSecret);
            }
        }
        Ok(client)
    }

    /// Validate an authorization request and issue a single-use code bound to the
    /// authenticated `account_id`.
    ///
    /// `expires_at` must be strictly after `now`. The cleartext code is returned
    /// once; only its hash is retained.
    pub fn issue_code(
        &mut self,
        account_id: AccountId,
        request: &AuthorizationRequest,
        now: Timestamp,
        expires_at: Timestamp,
    ) -> Result<IssuedAuthorizationCode, OAuthProviderError> {
        let client = self
            .clients
            .get(&request.client_id)
            .map_err(|_| OAuthProviderError::StorageUnavailable)?
            .ok_or(OAuthProviderError::UnknownClient)?;
        if !client.allows_redirect(&request.redirect_uri) {
            return Err(OAuthProviderError::UnregisteredRedirectUri);
        }
        if !client.allows_scopes(&request.scopes) {
            return Err(OAuthProviderError::ScopeNotAllowed);
        }
        if request
            .code_challenge_method
            .as_deref()
            .is_some_and(|method| method != "S256")
        {
            return Err(OAuthProviderError::UnsupportedCodeChallengeMethod);
        }
        // Public clients have no secret, so PKCE is mandatory to bind the code to
        // the initiating user agent.
        if client.is_public() && request.code_challenge.is_none() {
            return Err(OAuthProviderError::PkceRequired);
        }
        if expires_at.0 <= now.0 {
            return Err(OAuthProviderError::InvalidGrant);
        }

        let mut buf = [0u8; CODE_BYTES];
        self.entropy.fill_bytes(&mut buf);
        let code = URL_SAFE_NO_PAD.encode(buf);

        self.codes
            .create(StoredAuthorizationCode {
                code_hash: hash_session_token(&code),
                client_id: client.client_id.clone(),
                redirect_uri: request.redirect_uri.clone(),
                account_id,
                scopes: request.scopes.clone(),
                code_challenge: request.code_challenge.clone(),
                nonce: request.nonce.clone(),
                expires_at,
                consumed_at: None,
            })
            .map_err(|_| OAuthProviderError::StorageUnavailable)?;

        Ok(IssuedAuthorizationCode {
            code,
            state: request.state.clone(),
        })
    }

    /// Redeem an authorization code for its authorized grant, enforcing
    /// single-use, expiry, client authentication, redirect-URI match, and PKCE.
    pub fn redeem_code(
        &mut self,
        redemption: &TokenRedemption,
        now: Timestamp,
    ) -> Result<AuthorizedGrant, OAuthProviderError> {
        let client = self
            .clients
            .get(&redemption.client_id)
            .map_err(|_| OAuthProviderError::StorageUnavailable)?
            .ok_or(OAuthProviderError::UnknownClient)?;

        // Confidential clients authenticate; public clients present no secret.
        if let Some(expected) = &client.secret_hash {
            let presented = redemption
                .client_secret
                .as_deref()
                .ok_or(OAuthProviderError::InvalidClientSecret)?;
            if &hash_session_token(presented) != expected {
                return Err(OAuthProviderError::InvalidClientSecret);
            }
        }

        let code_hash = hash_session_token(&redemption.code);
        let stored = self
            .codes
            .get(&code_hash)
            .map_err(|_| OAuthProviderError::StorageUnavailable)?
            .ok_or(OAuthProviderError::InvalidGrant)?;

        // Single-use and expiry, evaluated independently of the rest.
        if stored.consumed_at.is_some() || now.0 >= stored.expires_at.0 {
            return Err(OAuthProviderError::InvalidGrant);
        }
        // The code is bound to the client it was issued to.
        if stored.client_id != redemption.client_id {
            return Err(OAuthProviderError::InvalidGrant);
        }
        if stored.redirect_uri != redemption.redirect_uri {
            return Err(OAuthProviderError::RedirectUriMismatch);
        }
        // PKCE: a code carrying a challenge requires a matching S256 verifier.
        if let Some(challenge) = &stored.code_challenge {
            let verifier = redemption
                .code_verifier
                .as_deref()
                .ok_or(OAuthProviderError::PkceVerificationFailed)?;
            if &pkce_s256_challenge(verifier) != challenge {
                return Err(OAuthProviderError::PkceVerificationFailed);
            }
        }

        // Consume the code so it can never be replayed.
        if !self
            .codes
            .consume_if_live(&code_hash, &now)
            .map_err(|_| OAuthProviderError::StorageUnavailable)?
        {
            return Err(OAuthProviderError::InvalidGrant);
        }
        Ok(AuthorizedGrant {
            account_id: stored.account_id.clone(),
            scopes: stored.scopes.clone(),
            nonce: stored.nonce.clone(),
        })
    }
}

/// Compute the PKCE S256 challenge for a verifier: `base64url(sha256(verifier))`.
fn pkce_s256_challenge(verifier: &str) -> String {
    let digest = Sha256::digest(verifier.as_bytes());
    URL_SAFE_NO_PAD.encode(digest)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::{Arc, Barrier};

    /// Deterministic entropy: each draw is a fixed, distinct byte pattern so two
    /// issued codes differ.
    struct SeqEntropy {
        next: u8,
    }

    impl EntropySource for SeqEntropy {
        fn fill_bytes(&mut self, buf: &mut [u8]) {
            for byte in buf.iter_mut() {
                *byte = self.next;
            }
            self.next = self.next.wrapping_add(1);
        }
    }

    fn now() -> Timestamp {
        Timestamp("2026-06-21T00:00:00Z".into())
    }

    fn soon() -> Timestamp {
        Timestamp("2026-06-21T00:05:00Z".into())
    }

    fn account() -> AccountId {
        AccountId("acct_ada".into())
    }

    fn public_registry() -> OAuthClientRegistry {
        let registry = OAuthClientRegistry::new();
        registry.register(RegisteredClient::public(
            "product-web",
            vec!["https://product.example/cb".into()],
            ["openid", "email", "profile"],
        ));
        registry
    }

    fn server(registry: OAuthClientRegistry) -> OAuthAuthorizationServer<SeqEntropy> {
        OAuthAuthorizationServer::new(registry, SeqEntropy { next: 1 })
    }

    // A real PKCE pair: verifier and its S256 challenge.
    fn pkce_pair() -> (String, String) {
        let verifier = "verifier-0123456789-0123456789-0123456789".to_string();
        let challenge = pkce_s256_challenge(&verifier);
        (verifier, challenge)
    }

    fn authz_request(challenge: Option<String>) -> AuthorizationRequest {
        AuthorizationRequest {
            client_id: "product-web".into(),
            redirect_uri: "https://product.example/cb".into(),
            scopes: vec!["openid".into(), "email".into()],
            code_challenge: challenge,
            code_challenge_method: Some("S256".into()),
            nonce: Some("nonce-1".into()),
            state: Some("state-1".into()),
        }
    }

    #[test]
    fn public_client_completes_authorization_code_with_pkce() {
        let (verifier, challenge) = pkce_pair();
        let mut server = server(public_registry());
        let issued = server
            .issue_code(account(), &authz_request(Some(challenge)), now(), soon())
            .expect("issue");
        assert_eq!(issued.state.as_deref(), Some("state-1"));

        let grant = server
            .redeem_code(
                &TokenRedemption {
                    client_id: "product-web".into(),
                    client_secret: None,
                    code: issued.code.clone(),
                    redirect_uri: "https://product.example/cb".into(),
                    code_verifier: Some(verifier),
                },
                now(),
            )
            .expect("redeem");
        assert_eq!(grant.account_id, account());
        assert_eq!(
            grant.scopes,
            vec!["openid".to_string(), "email".to_string()]
        );
        assert_eq!(grant.nonce.as_deref(), Some("nonce-1"));
    }

    #[test]
    fn a_code_is_single_use() {
        let (verifier, challenge) = pkce_pair();
        let mut server = server(public_registry());
        let issued = server
            .issue_code(account(), &authz_request(Some(challenge)), now(), soon())
            .expect("issue");
        let redeem = || TokenRedemption {
            client_id: "product-web".into(),
            client_secret: None,
            code: issued.code.clone(),
            redirect_uri: "https://product.example/cb".into(),
            code_verifier: Some(verifier.clone()),
        };
        assert!(server.redeem_code(&redeem(), now()).is_ok());
        assert_eq!(
            server.redeem_code(&redeem(), now()),
            Err(OAuthProviderError::InvalidGrant),
            "a consumed code must not redeem again"
        );
    }

    #[test]
    fn an_expired_code_is_rejected() {
        let (verifier, challenge) = pkce_pair();
        let mut server = server(public_registry());
        let issued = server
            .issue_code(account(), &authz_request(Some(challenge)), now(), soon())
            .expect("issue");
        let later = Timestamp("2026-06-21T01:00:00Z".into());
        assert_eq!(
            server.redeem_code(
                &TokenRedemption {
                    client_id: "product-web".into(),
                    client_secret: None,
                    code: issued.code,
                    redirect_uri: "https://product.example/cb".into(),
                    code_verifier: Some(verifier),
                },
                later,
            ),
            Err(OAuthProviderError::InvalidGrant)
        );
    }

    #[test]
    fn pkce_verifier_must_match_the_challenge() {
        let (_verifier, challenge) = pkce_pair();
        let mut server = server(public_registry());
        let issued = server
            .issue_code(account(), &authz_request(Some(challenge)), now(), soon())
            .expect("issue");
        assert_eq!(
            server.redeem_code(
                &TokenRedemption {
                    client_id: "product-web".into(),
                    client_secret: None,
                    code: issued.code,
                    redirect_uri: "https://product.example/cb".into(),
                    code_verifier: Some("the-wrong-verifier".into()),
                },
                now(),
            ),
            Err(OAuthProviderError::PkceVerificationFailed)
        );
    }

    #[test]
    fn public_client_must_use_pkce() {
        let mut server = server(public_registry());
        assert_eq!(
            server.issue_code(account(), &authz_request(None), now(), soon()),
            Err(OAuthProviderError::PkceRequired)
        );
    }

    #[test]
    fn unregistered_redirect_uri_is_rejected() {
        let (_v, challenge) = pkce_pair();
        let mut server = server(public_registry());
        let mut request = authz_request(Some(challenge));
        request.redirect_uri = "https://evil.example/cb".into();
        assert_eq!(
            server.issue_code(account(), &request, now(), soon()),
            Err(OAuthProviderError::UnregisteredRedirectUri)
        );
    }

    #[test]
    fn scopes_cannot_widen_beyond_the_client_allowlist() {
        let (_v, challenge) = pkce_pair();
        let mut server = server(public_registry());
        let mut request = authz_request(Some(challenge));
        request.scopes = vec!["openid".into(), "admin".into()];
        assert_eq!(
            server.issue_code(account(), &request, now(), soon()),
            Err(OAuthProviderError::ScopeNotAllowed)
        );
    }

    #[test]
    fn confidential_client_authenticates_with_its_secret() {
        let registry = OAuthClientRegistry::new();
        registry.register(RegisteredClient::confidential(
            "service-client",
            "top-secret",
            vec!["https://svc.example/cb".into()],
            ["openid"],
        ));
        let mut server = server(registry);
        // A confidential client may skip PKCE; it authenticates with its secret.
        let request = AuthorizationRequest {
            client_id: "service-client".into(),
            redirect_uri: "https://svc.example/cb".into(),
            scopes: vec!["openid".into()],
            code_challenge: None,
            code_challenge_method: None,
            nonce: None,
            state: None,
        };
        let issued = server
            .issue_code(account(), &request, now(), soon())
            .expect("issue");

        let redeem = |secret: Option<&str>| TokenRedemption {
            client_id: "service-client".into(),
            client_secret: secret.map(Into::into),
            code: issued.code.clone(),
            redirect_uri: "https://svc.example/cb".into(),
            code_verifier: None,
        };
        // Wrong secret fails closed; the code is not consumed by a failed attempt.
        assert_eq!(
            server.redeem_code(&redeem(Some("wrong")), now()),
            Err(OAuthProviderError::InvalidClientSecret)
        );
        assert!(
            server
                .redeem_code(&redeem(Some("top-secret")), now())
                .is_ok()
        );
    }

    #[test]
    fn a_code_is_bound_to_its_redirect_uri() {
        let registry = OAuthClientRegistry::new();
        registry.register(RegisteredClient::confidential(
            "svc",
            "s3cr3t",
            vec![
                "https://svc.example/cb".into(),
                "https://svc.example/other".into(),
            ],
            ["openid"],
        ));
        let mut server = server(registry);
        let request = AuthorizationRequest {
            client_id: "svc".into(),
            redirect_uri: "https://svc.example/cb".into(),
            scopes: vec!["openid".into()],
            code_challenge: None,
            code_challenge_method: None,
            nonce: None,
            state: None,
        };
        let issued = server
            .issue_code(account(), &request, now(), soon())
            .expect("issue");
        assert_eq!(
            server.redeem_code(
                &TokenRedemption {
                    client_id: "svc".into(),
                    client_secret: Some("s3cr3t".into()),
                    code: issued.code,
                    // A different — though still registered — redirect URI.
                    redirect_uri: "https://svc.example/other".into(),
                    code_verifier: None,
                },
                now(),
            ),
            Err(OAuthProviderError::RedirectUriMismatch)
        );
    }

    #[test]
    fn confidential_client_authenticates_at_the_token_endpoint() {
        let registry = OAuthClientRegistry::new();
        registry.register(RegisteredClient::confidential(
            "service-client",
            "top-secret",
            vec!["https://svc.example/cb".into()],
            ["openid"],
        ));
        let server = server(registry);

        // The right secret authenticates and yields the registered client.
        let client = server
            .authenticate_client("service-client", Some("top-secret"))
            .expect("authenticate");
        assert_eq!(client.client_id, "service-client");

        // A wrong or missing secret fails closed.
        assert_eq!(
            server.authenticate_client("service-client", Some("wrong")),
            Err(OAuthProviderError::InvalidClientSecret)
        );
        assert_eq!(
            server.authenticate_client("service-client", None),
            Err(OAuthProviderError::InvalidClientSecret)
        );
    }

    #[test]
    fn public_client_authenticates_without_a_secret() {
        let server = server(public_registry());
        let client = server
            .authenticate_client("product-web", None)
            .expect("authenticate");
        assert!(client.client_id == "product-web");
    }

    #[test]
    fn an_unknown_client_is_rejected_at_authentication() {
        let server = server(public_registry());
        assert_eq!(
            server.authenticate_client("ghost", Some("anything")),
            Err(OAuthProviderError::UnknownClient)
        );
    }

    /// Durable downstream OAuth cause/effect decision table:
    /// C1=two server instances share client/code repositories, C2=client was
    /// registered through A, C3=A issued a live PKCE-bound code. Effects:
    /// E1=B observes the client without registry hydration; E2=B redeems A's
    /// code exactly once. R1(C1,C2,!C3)->B authenticates client; R2(C1,C2,C3)
    /// ->B returns the grant. This covers replica replacement and cross-Pod
    /// authorize/token routing through one authoritative store.
    #[test]
    fn shared_repositories_make_clients_and_codes_visible_across_instances() {
        let clients = Arc::new(OAuthClientRegistry::new());
        let codes = Arc::new(InMemoryAuthCodeRepository::default());
        let mut first = OAuthAuthorizationServer::with_repositories(
            clients.clone(),
            codes.clone(),
            SeqEntropy { next: 20 },
        );
        let mut second =
            OAuthAuthorizationServer::with_repositories(clients, codes, SeqEntropy { next: 40 });
        first
            .register_client(RegisteredClient::public(
                "product-web",
                vec!["https://product.example/cb".into()],
                ["openid", "email"],
            ))
            .unwrap();
        assert_eq!(
            second
                .authenticate_client("product-web", None)
                .unwrap()
                .client_id,
            "product-web"
        );

        let (verifier, challenge) = pkce_pair();
        let issued = first
            .issue_code(account(), &authz_request(Some(challenge)), now(), soon())
            .unwrap();
        let grant = second
            .redeem_code(
                &TokenRedemption {
                    client_id: "product-web".into(),
                    client_secret: None,
                    code: issued.code,
                    redirect_uri: "https://product.example/cb".into(),
                    code_verifier: Some(verifier),
                },
                now(),
            )
            .unwrap();
        assert_eq!(grant.account_id, account());
    }

    /// Atomic-consume cause/effect decision table:
    /// C1=one live code, C2=two replicas pass identical client/redirect/PKCE
    /// validation concurrently. The only permitted effect is E1=one grant and
    /// one InvalidGrant. R1(C1,C2)->CAS winner succeeds; CAS loser fails. Zero
    /// or two successes would violate availability or replay safety.
    #[test]
    fn concurrent_redemption_has_exactly_one_winner() {
        let clients = Arc::new(OAuthClientRegistry::new());
        let codes = Arc::new(InMemoryAuthCodeRepository::default());
        let mut issuer = OAuthAuthorizationServer::with_repositories(
            clients.clone(),
            codes.clone(),
            SeqEntropy { next: 60 },
        );
        issuer
            .register_client(RegisteredClient::public(
                "product-web",
                vec!["https://product.example/cb".into()],
                ["openid", "email"],
            ))
            .unwrap();
        let (verifier, challenge) = pkce_pair();
        let issued = issuer
            .issue_code(account(), &authz_request(Some(challenge)), now(), soon())
            .unwrap();
        let redemption = TokenRedemption {
            client_id: "product-web".into(),
            client_secret: None,
            code: issued.code,
            redirect_uri: "https://product.example/cb".into(),
            code_verifier: Some(verifier),
        };
        let barrier = Arc::new(Barrier::new(2));
        let handles = [80, 100].map(|next| {
            let clients = clients.clone();
            let codes = codes.clone();
            let redemption = redemption.clone();
            let barrier = barrier.clone();
            std::thread::spawn(move || {
                let mut replica = OAuthAuthorizationServer::with_repositories(
                    clients,
                    codes,
                    SeqEntropy { next },
                );
                barrier.wait();
                replica.redeem_code(&redemption, now())
            })
        });
        let results = handles.map(|handle| handle.join().unwrap());
        assert_eq!(results.iter().filter(|result| result.is_ok()).count(), 1);
        assert_eq!(
            results
                .iter()
                .filter(|result| **result == Err(OAuthProviderError::InvalidGrant))
                .count(),
            1
        );
    }

    /// Validation/non-consumption decision table:
    /// C1=client binding matches, C2=redirect matches, C3=PKCE matches,
    /// C4=code is live. E1=consume+grant only for R1(C1,C2,C3,C4); R2(!C1),
    /// R3(!C2), and R4(!C3) reject without consuming so a later R1 succeeds;
    /// R5(!C4) rejects and leaves consumed_at absent for expiry audit/cleanup.
    #[test]
    fn invalid_bindings_and_expiry_never_consume_a_code() {
        let clients = Arc::new(OAuthClientRegistry::new());
        let codes = Arc::new(InMemoryAuthCodeRepository::default());
        let mut server = OAuthAuthorizationServer::with_repositories(
            clients,
            codes.clone(),
            SeqEntropy { next: 120 },
        );
        for client_id in ["product-web", "other-product"] {
            server
                .register_client(RegisteredClient::public(
                    client_id,
                    vec!["https://product.example/cb".into()],
                    ["openid", "email"],
                ))
                .unwrap();
        }
        let (verifier, challenge) = pkce_pair();
        let issued = server
            .issue_code(account(), &authz_request(Some(challenge)), now(), soon())
            .unwrap();
        let valid = TokenRedemption {
            client_id: "product-web".into(),
            client_secret: None,
            code: issued.code.clone(),
            redirect_uri: "https://product.example/cb".into(),
            code_verifier: Some(verifier),
        };
        let mut wrong_client = valid.clone();
        wrong_client.client_id = "other-product".into();
        assert_eq!(
            server.redeem_code(&wrong_client, now()),
            Err(OAuthProviderError::InvalidGrant)
        );
        let mut wrong_redirect = valid.clone();
        wrong_redirect.redirect_uri = "https://product.example/other".into();
        assert_eq!(
            server.redeem_code(&wrong_redirect, now()),
            Err(OAuthProviderError::RedirectUriMismatch)
        );
        let mut wrong_pkce = valid.clone();
        wrong_pkce.code_verifier = Some("wrong-verifier".into());
        assert_eq!(
            server.redeem_code(&wrong_pkce, now()),
            Err(OAuthProviderError::PkceVerificationFailed)
        );
        assert!(server.redeem_code(&valid, now()).is_ok());

        let (_, challenge) = pkce_pair();
        let expired = server
            .issue_code(account(), &authz_request(Some(challenge)), now(), soon())
            .unwrap();
        let mut expired_redemption = valid;
        expired_redemption.code = expired.code.clone();
        assert_eq!(
            server.redeem_code(&expired_redemption, soon()),
            Err(OAuthProviderError::InvalidGrant)
        );
        assert!(
            codes
                .get(&hash_session_token(&expired.code))
                .unwrap()
                .unwrap()
                .consumed_at
                .is_none()
        );
    }

    #[derive(Debug)]
    struct FailingCodeRepository;

    impl AuthCodeRepository for FailingCodeRepository {
        fn create(&self, _: StoredAuthorizationCode) -> RepositoryResult<()> {
            Err(RepositoryError::Backend("offline".into()))
        }

        fn get(&self, _: &str) -> RepositoryResult<Option<StoredAuthorizationCode>> {
            Err(RepositoryError::Backend("offline".into()))
        }

        fn consume_if_live(&self, _: &str, _: &Timestamp) -> RepositoryResult<bool> {
            Err(RepositoryError::Backend("offline".into()))
        }
    }

    #[derive(Debug)]
    struct FailingClientRepository;

    impl OAuthClientRepository for FailingClientRepository {
        fn upsert(&self, _: RegisteredClient) -> RepositoryResult<()> {
            Err(RepositoryError::Backend("offline".into()))
        }

        fn get(&self, _: &str) -> RepositoryResult<Option<RegisteredClient>> {
            Err(RepositoryError::Backend("offline".into()))
        }

        fn list(&self) -> RepositoryResult<Vec<RegisteredClient>> {
            Err(RepositoryError::Backend("offline".into()))
        }

        fn remove(&self, _: &str) -> RepositoryResult<()> {
            Err(RepositoryError::Backend("offline".into()))
        }
    }

    /// Repository-failure decision rules: C1=client exists, C2=code store is
    /// unavailable, C3=client store is unavailable. R1(C1,C2,issue)
    /// ->StorageUnavailable and no cleartext code; R2(C1,C2,redeem)
    /// ->StorageUnavailable and no grant; R3(C3,authenticate/issue) returns the
    /// same fail-closed class. No in-memory fallback is permitted because it
    /// would create replica-local authority.
    #[test]
    fn authorization_code_storage_failure_fails_closed() {
        let clients = Arc::new(OAuthClientRegistry::new());
        clients.register(RegisteredClient::public(
            "product-web",
            vec!["https://product.example/cb".into()],
            ["openid", "email"],
        ));
        let mut server = OAuthAuthorizationServer::with_repositories(
            clients,
            Arc::new(FailingCodeRepository),
            SeqEntropy { next: 140 },
        );
        let (verifier, challenge) = pkce_pair();
        assert_eq!(
            server.issue_code(account(), &authz_request(Some(challenge)), now(), soon()),
            Err(OAuthProviderError::StorageUnavailable)
        );
        assert_eq!(
            server.redeem_code(
                &TokenRedemption {
                    client_id: "product-web".into(),
                    client_secret: None,
                    code: "unknown".into(),
                    redirect_uri: "https://product.example/cb".into(),
                    code_verifier: Some(verifier),
                },
                now(),
            ),
            Err(OAuthProviderError::StorageUnavailable)
        );

        let mut client_store_offline = OAuthAuthorizationServer::with_repositories(
            Arc::new(FailingClientRepository),
            Arc::new(InMemoryAuthCodeRepository::default()),
            SeqEntropy { next: 160 },
        );
        assert_eq!(
            client_store_offline.authenticate_client("product-web", None),
            Err(OAuthProviderError::StorageUnavailable)
        );
        assert_eq!(
            client_store_offline.issue_code(
                account(),
                &authz_request(Some(pkce_pair().1)),
                now(),
                soon()
            ),
            Err(OAuthProviderError::StorageUnavailable)
        );
    }
}
