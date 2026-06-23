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

use awaken_iam_contract::{AccountId, Timestamp};
use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use sha2::{Digest, Sha256};

use crate::EntropySource;
use crate::hash_session_token;

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
}

/// A product client registered to integrate against IAM as an OAuth provider.
#[derive(Debug, Clone, PartialEq, Eq)]
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
    clients: HashMap<String, RegisteredClient>,
}

impl OAuthClientRegistry {
    /// An empty registry.
    pub fn new() -> Self {
        Self::default()
    }

    /// Register or replace a client.
    pub fn register(&mut self, client: RegisteredClient) {
        self.clients.insert(client.client_id.clone(), client);
    }

    /// Look up a registered client by id.
    pub fn get(&self, client_id: &str) -> Option<&RegisteredClient> {
        self.clients.get(client_id)
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
#[derive(Debug, Clone)]
struct StoredAuthCode {
    code_hash: String,
    client_id: String,
    redirect_uri: String,
    account_id: AccountId,
    scopes: Vec<String>,
    code_challenge: Option<String>,
    nonce: Option<String>,
    expires_at: Timestamp,
    consumed: bool,
}

/// IAM's downstream OAuth 2.0 authorization server.
#[derive(Debug)]
pub struct OAuthAuthorizationServer<E: EntropySource> {
    registry: OAuthClientRegistry,
    codes: Vec<StoredAuthCode>,
    entropy: E,
}

impl<E: EntropySource> OAuthAuthorizationServer<E> {
    /// Build a server over a client registry and an entropy source.
    pub fn new(registry: OAuthClientRegistry, entropy: E) -> Self {
        Self {
            registry,
            codes: Vec::new(),
            entropy,
        }
    }

    /// Borrow the client registry.
    pub fn registry(&self) -> &OAuthClientRegistry {
        &self.registry
    }

    /// Register or replace a client in the underlying registry.
    ///
    /// Lets a caller that built the server over an empty registry add clients
    /// later (e.g. as a deployment provisions its product integrations) without
    /// reconstructing the server and discarding issued codes.
    pub fn register_client(&mut self, client: RegisteredClient) {
        self.registry.register(client);
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
            .registry
            .get(&request.client_id)
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

        self.codes.push(StoredAuthCode {
            code_hash: hash_session_token(&code),
            client_id: client.client_id.clone(),
            redirect_uri: request.redirect_uri.clone(),
            account_id,
            scopes: request.scopes.clone(),
            code_challenge: request.code_challenge.clone(),
            nonce: request.nonce.clone(),
            expires_at,
            consumed: false,
        });

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
            .registry
            .get(&redemption.client_id)
            .cloned()
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
            .iter_mut()
            .find(|c| c.code_hash == code_hash)
            .ok_or(OAuthProviderError::InvalidGrant)?;

        // Single-use and expiry, evaluated independently of the rest.
        if stored.consumed || now.0 >= stored.expires_at.0 {
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
        stored.consumed = true;
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
        let mut registry = OAuthClientRegistry::new();
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
        let mut registry = OAuthClientRegistry::new();
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
        let mut registry = OAuthClientRegistry::new();
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
}
