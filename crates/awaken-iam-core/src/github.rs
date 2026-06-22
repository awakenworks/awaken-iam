//! GitHub OAuth login provider adapter.
//!
//! GitHub speaks a plain OAuth 2.0 dialect: the browser is sent to the
//! authorize endpoint with a `state` value, the callback `code` is redeemed for
//! an opaque access token at the token endpoint, and the authenticated user is
//! read back from the REST API (`GET /user` and `GET /user/emails`). GitHub does
//! not issue an ID token, so there is no OIDC `nonce`, and classic OAuth apps do
//! not support PKCE; those fields of [`AuthorizationUrlRequest`] are therefore
//! ignored here rather than placed on the wire.
//!
//! Two pieces of normalization are GitHub-specific and live in this module:
//!
//! 1. *Subject.* GitHub usernames (`login`) are mutable and reusable, so the
//!    immutable, numeric account **id** is used as the [`ExternalSubject`]. The
//!    `login` is carried as a mutable username claim.
//! 2. *Email.* `GET /user` only returns an email when the account marks one
//!    public, so the verified primary address from `GET /user/emails` is
//!    preferred. [`select_email`] encodes the precedence and is unit tested in
//!    isolation.
//!
//! All byte transport is delegated to [`GithubTransport`], the seam a deployment
//! implements over its HTTP client. Core stays I/O-free: it builds the requests,
//! drives the two API reads, and normalizes the result into provider-agnostic
//! [`ExternalIdentityClaims`].

use awaken_iam_contract::{
    ExternalIdentityClaims, ExternalSubject, IdentityProviderConfig, IdentityProviderKind,
};
use serde::{Deserialize, Serialize};

use crate::provider::{
    AuthorizationRedirect, AuthorizationUrlRequest, CallbackExchange, IdentityProviderAdapter,
    ProviderError,
};

/// Default GitHub authorize endpoint used when a config omits its own.
pub const DEFAULT_AUTHORIZE_ENDPOINT: &str = "https://github.com/login/oauth/authorize";
/// Default GitHub token endpoint used when a config omits its own.
pub const DEFAULT_TOKEN_ENDPOINT: &str = "https://github.com/login/oauth/access_token";

/// Profile fields read from `GET /user`.
///
/// Only the fields the adapter normalizes are modeled; GitHub returns many more
/// and unknown fields are ignored on deserialization.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GithubUser {
    /// Immutable, numeric account id used as the external subject.
    pub id: u64,
    /// Mutable username / handle.
    pub login: String,
    /// Optional display name, when the account set one.
    #[serde(default)]
    pub name: Option<String>,
    /// Public profile email, only present when the account made one public.
    #[serde(default)]
    pub email: Option<String>,
    /// Optional avatar URL.
    #[serde(default)]
    pub avatar_url: Option<String>,
}

/// A single address row from `GET /user/emails`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GithubEmail {
    /// The email address.
    pub email: String,
    /// Whether GitHub marks this as the account's primary address.
    pub primary: bool,
    /// Whether GitHub has verified ownership of this address.
    pub verified: bool,
}

/// Access token returned by the GitHub token endpoint.
///
/// GitHub answers the token exchange with a form body or, when
/// `Accept: application/json` is sent, this JSON shape. An error response sets
/// [`GithubAccessToken::error`] instead of [`GithubAccessToken::access_token`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GithubAccessToken {
    /// Opaque bearer token, present on success.
    #[serde(default)]
    pub access_token: Option<String>,
    /// Token type, typically `bearer`.
    #[serde(default)]
    pub token_type: Option<String>,
    /// Granted scope string, space or comma delimited.
    #[serde(default)]
    pub scope: Option<String>,
    /// Error code, present when the exchange was rejected.
    #[serde(default)]
    pub error: Option<String>,
    /// Human-readable error description, when present.
    #[serde(default)]
    pub error_description: Option<String>,
}

/// Inputs the adapter hands the transport to redeem a callback code.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TokenRequest<'a> {
    /// Token endpoint to POST to.
    pub token_endpoint: &'a str,
    /// Public OAuth client id.
    pub client_id: &'a str,
    /// Authorization `code` returned on the callback.
    pub code: &'a str,
    /// Callback URL registered for the flow; GitHub requires it to match.
    pub redirect_uri: &'a str,
}

/// Byte-transport seam for the GitHub REST calls.
///
/// Implementors own the HTTP client and the deployment's client **secret** — it
/// is intentionally absent from [`IdentityProviderConfig`], so the transport
/// attaches it when redeeming the code. Keeping transport behind a trait lets the
/// adapter logic (URL construction, email precedence, claim normalization) be
/// unit tested without network access.
pub trait GithubTransport {
    /// Redeem an authorization code for an access token.
    fn exchange_code(
        &self,
        request: &TokenRequest<'_>,
    ) -> Result<GithubAccessToken, GithubTransportError>;

    /// Read the authenticated user's profile (`GET /user`).
    fn fetch_user(&self, access_token: &str) -> Result<GithubUser, GithubTransportError>;

    /// Read the authenticated user's addresses (`GET /user/emails`).
    fn fetch_emails(&self, access_token: &str) -> Result<Vec<GithubEmail>, GithubTransportError>;
}

/// Failure reported by a [`GithubTransport`] implementation.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("github transport failed: {0}")]
pub struct GithubTransportError(pub String);

/// GitHub OAuth identity provider adapter.
///
/// Generic over the [`GithubTransport`] seam so a deployment injects its HTTP
/// client while tests inject a deterministic fake. One instance serves every
/// GitHub [`IdentityProviderConfig`] of a deployment.
#[derive(Debug, Clone)]
pub struct GithubProviderAdapter<T> {
    transport: T,
}

impl<T> GithubProviderAdapter<T> {
    /// Build an adapter over the given transport.
    pub fn new(transport: T) -> Self {
        Self { transport }
    }

    /// Borrow the underlying transport.
    pub fn transport(&self) -> &T {
        &self.transport
    }
}

impl<T: GithubTransport> GithubProviderAdapter<T> {
    /// Normalize a fetched profile and address list into claims.
    ///
    /// Exposed for callers that already hold the GitHub responses; the trait's
    /// [`exchange_callback`](IdentityProviderAdapter::exchange_callback) drives
    /// the two reads and then funnels into this same path.
    pub fn normalize(user: &GithubUser, emails: &[GithubEmail]) -> ExternalIdentityClaims {
        let selected = select_email(user, emails);
        ExternalIdentityClaims {
            subject: ExternalSubject(user.id.to_string()),
            email: selected.as_ref().map(|s| s.email.clone()),
            email_verified: selected.as_ref().map(|s| s.verified),
            display_name: user.name.clone(),
            username: Some(user.login.clone()),
            avatar_url: user
                .avatar_url
                .as_ref()
                .filter(|url| !url.is_empty())
                .cloned(),
            locale: None,
        }
    }
}

/// Outcome of [`select_email`]: the chosen address and its verification state.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SelectedEmail {
    /// The chosen email address.
    pub email: String,
    /// Whether the chosen address is verified by GitHub.
    pub verified: bool,
}

/// Select the best email claim for a GitHub login.
///
/// Precedence, highest first:
/// 1. the **verified primary** address (the issue's required behavior),
/// 2. any other **verified** address,
/// 3. the primary address even if unverified,
/// 4. the first listed address,
/// 5. the public profile email from `GET /user`.
///
/// Returns `None` only when GitHub exposed no address at all.
pub fn select_email(user: &GithubUser, emails: &[GithubEmail]) -> Option<SelectedEmail> {
    if let Some(primary) = emails.iter().find(|e| e.primary && e.verified) {
        return Some(SelectedEmail {
            email: primary.email.clone(),
            verified: true,
        });
    }
    if let Some(verified) = emails.iter().find(|e| e.verified) {
        return Some(SelectedEmail {
            email: verified.email.clone(),
            verified: true,
        });
    }
    if let Some(primary) = emails.iter().find(|e| e.primary) {
        return Some(SelectedEmail {
            email: primary.email.clone(),
            verified: false,
        });
    }
    if let Some(first) = emails.first() {
        return Some(SelectedEmail {
            email: first.email.clone(),
            verified: first.verified,
        });
    }
    user.email.as_ref().map(|email| SelectedEmail {
        email: email.clone(),
        verified: false,
    })
}

/// Percent-encode a single query-parameter value per RFC 3986.
///
/// Only the unreserved set (`A-Z a-z 0-9 - _ . ~`) passes through; everything
/// else is escaped, so redirect URIs and scopes are placed on the wire safely.
fn encode_query_value(value: &str) -> String {
    let mut out = String::with_capacity(value.len());
    for byte in value.bytes() {
        match byte {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                out.push(byte as char);
            }
            _ => {
                out.push('%');
                out.push(hex_digit(byte >> 4));
                out.push(hex_digit(byte & 0x0f));
            }
        }
    }
    out
}

/// Map a nibble to its uppercase hexadecimal digit.
fn hex_digit(nibble: u8) -> char {
    match nibble {
        0..=9 => (b'0' + nibble) as char,
        _ => (b'A' + (nibble - 10)) as char,
    }
}

impl<T: GithubTransport> IdentityProviderAdapter for GithubProviderAdapter<T> {
    fn provider_kind(&self) -> IdentityProviderKind {
        IdentityProviderKind::OAuth2
    }

    fn authorization_url(
        &self,
        config: &IdentityProviderConfig,
        request: &AuthorizationUrlRequest,
    ) -> Result<AuthorizationRedirect, ProviderError> {
        self.ensure_kind(config)?;
        let client_id = config
            .client_id
            .as_deref()
            .ok_or(ProviderError::MissingConfiguration { field: "client_id" })?;
        let endpoint = config
            .authorization_endpoint
            .as_deref()
            .unwrap_or(DEFAULT_AUTHORIZE_ENDPOINT);

        let mut url = format!(
            "{endpoint}?response_type=code&client_id={}&redirect_uri={}&state={}",
            encode_query_value(client_id),
            encode_query_value(&request.redirect_uri),
            encode_query_value(&request.state),
        );
        if !request.scopes.is_empty() {
            url.push_str("&scope=");
            url.push_str(&encode_query_value(&request.scopes.join(" ")));
        }
        // GitHub classic OAuth apps support neither OIDC `nonce` nor PKCE, so
        // those minted values are deliberately not placed on the wire.
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
                reason: "empty authorization code".into(),
            });
        }
        let client_id = config
            .client_id
            .as_deref()
            .ok_or(ProviderError::MissingConfiguration { field: "client_id" })?;
        let token_endpoint = config
            .token_endpoint
            .as_deref()
            .unwrap_or(DEFAULT_TOKEN_ENDPOINT);

        let token = self
            .transport
            .exchange_code(&TokenRequest {
                token_endpoint,
                client_id,
                code: &callback.code,
                redirect_uri: &callback.redirect_uri,
            })
            .map_err(|err| ProviderError::ExchangeRejected {
                reason: err.0.clone(),
            })?;

        if let Some(error) = token.error.as_deref() {
            let reason = match token.error_description.as_deref() {
                Some(desc) => format!("{error}: {desc}"),
                None => error.to_owned(),
            };
            return Err(ProviderError::ExchangeRejected { reason });
        }
        let access_token = token
            .access_token
            .filter(|t| !t.is_empty())
            .ok_or_else(|| ProviderError::MalformedClaims {
                reason: "token endpoint returned no access token".into(),
            })?;

        let user = self.transport.fetch_user(&access_token).map_err(|err| {
            ProviderError::MalformedClaims {
                reason: format!("failed to read user profile: {}", err.0),
            }
        })?;
        let emails = self.transport.fetch_emails(&access_token).map_err(|err| {
            ProviderError::MalformedClaims {
                reason: format!("failed to read user emails: {}", err.0),
            }
        })?;

        Ok(Self::normalize(&user, &emails))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::provider::IdentityProviderAdapter;
    use awaken_iam_contract::{IdentityProviderConfigId, IdentityProviderKey};
    use std::cell::RefCell;

    /// Canned transport recording the access token it was asked to use.
    struct FakeTransport {
        token: Result<GithubAccessToken, GithubTransportError>,
        user: Result<GithubUser, GithubTransportError>,
        emails: Result<Vec<GithubEmail>, GithubTransportError>,
        seen_token: RefCell<Option<String>>,
    }

    impl FakeTransport {
        fn ok(user: GithubUser, emails: Vec<GithubEmail>) -> Self {
            Self {
                token: Ok(GithubAccessToken {
                    access_token: Some("gho_token".into()),
                    token_type: Some("bearer".into()),
                    scope: Some("read:user user:email".into()),
                    error: None,
                    error_description: None,
                }),
                user: Ok(user),
                emails: Ok(emails),
                seen_token: RefCell::new(None),
            }
        }
    }

    impl GithubTransport for FakeTransport {
        fn exchange_code(
            &self,
            _request: &TokenRequest<'_>,
        ) -> Result<GithubAccessToken, GithubTransportError> {
            self.token.clone()
        }

        fn fetch_user(&self, access_token: &str) -> Result<GithubUser, GithubTransportError> {
            *self.seen_token.borrow_mut() = Some(access_token.to_owned());
            self.user.clone()
        }

        fn fetch_emails(
            &self,
            _access_token: &str,
        ) -> Result<Vec<GithubEmail>, GithubTransportError> {
            self.emails.clone()
        }
    }

    fn github_config() -> IdentityProviderConfig {
        IdentityProviderConfig {
            id: IdentityProviderConfigId("cfg_github".into()),
            provider_key: IdentityProviderKey("github".into()),
            kind: IdentityProviderKind::OAuth2,
            display_name: "GitHub".into(),
            issuer_url: None,
            authorization_endpoint: Some("https://github.com/login/oauth/authorize".into()),
            token_endpoint: Some("https://github.com/login/oauth/access_token".into()),
            client_id: Some("Iv1.client".into()),
            enabled: true,
        }
    }

    fn email(addr: &str, primary: bool, verified: bool) -> GithubEmail {
        GithubEmail {
            email: addr.into(),
            primary,
            verified,
        }
    }

    fn user() -> GithubUser {
        GithubUser {
            id: 583231,
            login: "octocat".into(),
            name: Some("The Octocat".into()),
            email: None,
            avatar_url: Some("https://avatars.example/u/583231".into()),
        }
    }

    #[test]
    fn authorization_url_uses_github_shape_and_encodes_values() {
        let adapter = GithubProviderAdapter::new(FakeTransport::ok(user(), vec![]));
        let request = AuthorizationUrlRequest {
            redirect_uri: "https://app.example/auth/callback".into(),
            state: "state-token".into(),
            nonce: Some("ignored-nonce".into()),
            pkce_challenge: None,
            scopes: vec!["read:user".into(), "user:email".into()],
        };

        let redirect = adapter
            .authorization_url(&github_config(), &request)
            .unwrap();

        assert!(
            redirect
                .url
                .starts_with("https://github.com/login/oauth/authorize?")
        );
        assert!(redirect.url.contains("client_id=Iv1.client"));
        assert!(redirect.url.contains("state=state-token"));
        // Redirect URI is percent-encoded.
        assert!(
            redirect
                .url
                .contains("redirect_uri=https%3A%2F%2Fapp.example%2Fauth%2Fcallback")
        );
        // Scopes are space-joined then encoded.
        assert!(redirect.url.contains("scope=read%3Auser%20user%3Aemail"));
        // GitHub flow carries neither nonce nor PKCE.
        assert!(!redirect.url.contains("nonce"));
        assert!(!redirect.url.contains("code_challenge"));
    }

    #[test]
    fn authorization_url_falls_back_to_default_endpoint() {
        let adapter = GithubProviderAdapter::new(FakeTransport::ok(user(), vec![]));
        let mut config = github_config();
        config.authorization_endpoint = None;
        let request = AuthorizationUrlRequest {
            redirect_uri: "https://app.example/cb".into(),
            state: "s".into(),
            nonce: None,
            pkce_challenge: None,
            scopes: vec![],
        };

        let redirect = adapter.authorization_url(&config, &request).unwrap();
        assert!(redirect.url.starts_with(DEFAULT_AUTHORIZE_ENDPOINT));
        assert!(!redirect.url.contains("scope="));
    }

    #[test]
    fn authorization_url_requires_client_id() {
        let adapter = GithubProviderAdapter::new(FakeTransport::ok(user(), vec![]));
        let mut config = github_config();
        config.client_id = None;
        let request = AuthorizationUrlRequest {
            redirect_uri: "https://app.example/cb".into(),
            state: "s".into(),
            nonce: None,
            pkce_challenge: None,
            scopes: vec![],
        };

        let err = adapter.authorization_url(&config, &request).unwrap_err();
        assert_eq!(
            err,
            ProviderError::MissingConfiguration { field: "client_id" }
        );
    }

    #[test]
    fn exchange_callback_uses_id_as_subject_and_verified_primary_email() {
        let emails = vec![
            email("octocat@users.noreply.example", false, true),
            email("primary@example.com", true, true),
            email("old@example.com", false, false),
        ];
        let adapter = GithubProviderAdapter::new(FakeTransport::ok(user(), emails));
        let callback = CallbackExchange {
            redirect_uri: "https://app.example/cb".into(),
            code: "gh-code".into(),
            pkce_verifier: None,
        };

        let claims = adapter
            .exchange_callback(&github_config(), &callback)
            .unwrap();

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
    fn exchange_callback_forwards_bearer_token_to_reads() {
        let adapter = GithubProviderAdapter::new(FakeTransport::ok(
            user(),
            vec![email("primary@example.com", true, true)],
        ));
        let callback = CallbackExchange {
            redirect_uri: "https://app.example/cb".into(),
            code: "gh-code".into(),
            pkce_verifier: None,
        };

        adapter
            .exchange_callback(&github_config(), &callback)
            .unwrap();

        assert_eq!(
            adapter.transport().seen_token.borrow().as_deref(),
            Some("gho_token")
        );
    }

    #[test]
    fn exchange_callback_rejects_empty_code() {
        let adapter = GithubProviderAdapter::new(FakeTransport::ok(user(), vec![]));
        let callback = CallbackExchange {
            redirect_uri: "https://app.example/cb".into(),
            code: String::new(),
            pkce_verifier: None,
        };

        let err = adapter
            .exchange_callback(&github_config(), &callback)
            .unwrap_err();
        assert_eq!(
            err,
            ProviderError::ExchangeRejected {
                reason: "empty authorization code".into(),
            }
        );
    }

    #[test]
    fn exchange_callback_surfaces_token_error() {
        let mut transport = FakeTransport::ok(user(), vec![]);
        transport.token = Ok(GithubAccessToken {
            access_token: None,
            token_type: None,
            scope: None,
            error: Some("bad_verification_code".into()),
            error_description: Some("The code passed is incorrect or expired.".into()),
        });
        let adapter = GithubProviderAdapter::new(transport);
        let callback = CallbackExchange {
            redirect_uri: "https://app.example/cb".into(),
            code: "stale".into(),
            pkce_verifier: None,
        };

        let err = adapter
            .exchange_callback(&github_config(), &callback)
            .unwrap_err();
        assert_eq!(
            err,
            ProviderError::ExchangeRejected {
                reason: "bad_verification_code: The code passed is incorrect or expired.".into(),
            }
        );
    }

    #[test]
    fn exchange_callback_rejects_missing_access_token() {
        let mut transport = FakeTransport::ok(user(), vec![]);
        transport.token = Ok(GithubAccessToken {
            access_token: None,
            token_type: None,
            scope: None,
            error: None,
            error_description: None,
        });
        let adapter = GithubProviderAdapter::new(transport);
        let callback = CallbackExchange {
            redirect_uri: "https://app.example/cb".into(),
            code: "code".into(),
            pkce_verifier: None,
        };

        let err = adapter
            .exchange_callback(&github_config(), &callback)
            .unwrap_err();
        assert_eq!(
            err,
            ProviderError::MalformedClaims {
                reason: "token endpoint returned no access token".into(),
            }
        );
    }

    #[test]
    fn exchange_callback_maps_user_read_failure() {
        let mut transport = FakeTransport::ok(user(), vec![]);
        transport.user = Err(GithubTransportError("503 from /user".into()));
        let adapter = GithubProviderAdapter::new(transport);
        let callback = CallbackExchange {
            redirect_uri: "https://app.example/cb".into(),
            code: "code".into(),
            pkce_verifier: None,
        };

        let err = adapter
            .exchange_callback(&github_config(), &callback)
            .unwrap_err();
        assert_eq!(
            err,
            ProviderError::MalformedClaims {
                reason: "failed to read user profile: 503 from /user".into(),
            }
        );
    }

    #[test]
    fn rejects_mismatched_provider_kind() {
        let adapter = GithubProviderAdapter::new(FakeTransport::ok(user(), vec![]));
        let mut config = github_config();
        config.kind = IdentityProviderKind::Oidc;
        let callback = CallbackExchange {
            redirect_uri: "https://app.example/cb".into(),
            code: "code".into(),
            pkce_verifier: None,
        };

        let err = adapter.exchange_callback(&config, &callback).unwrap_err();
        assert_eq!(
            err,
            ProviderError::UnsupportedProviderKind {
                expected: IdentityProviderKind::OAuth2,
                actual: IdentityProviderKind::Oidc,
            }
        );
    }

    #[test]
    fn select_email_prefers_verified_primary_over_other_verified() {
        let u = user();
        let emails = vec![
            email("verified-secondary@example.com", false, true),
            email("verified-primary@example.com", true, true),
        ];
        let selected = select_email(&u, &emails).unwrap();
        assert_eq!(selected.email, "verified-primary@example.com");
        assert!(selected.verified);
    }

    #[test]
    fn select_email_falls_back_to_any_verified_when_primary_unverified() {
        let u = user();
        let emails = vec![
            email("primary-unverified@example.com", true, false),
            email("secondary-verified@example.com", false, true),
        ];
        let selected = select_email(&u, &emails).unwrap();
        assert_eq!(selected.email, "secondary-verified@example.com");
        assert!(selected.verified);
    }

    #[test]
    fn select_email_falls_back_to_unverified_primary_then_profile() {
        let u = user();
        let only_unverified = vec![email("p@example.com", true, false)];
        let selected = select_email(&u, &only_unverified).unwrap();
        assert_eq!(selected.email, "p@example.com");
        assert!(!selected.verified);

        let mut with_profile = user();
        with_profile.email = Some("public@example.com".into());
        let selected = select_email(&with_profile, &[]).unwrap();
        assert_eq!(selected.email, "public@example.com");
        assert!(!selected.verified);
    }

    #[test]
    fn select_email_is_none_without_any_address() {
        let mut u = user();
        u.email = None;
        assert!(select_email(&u, &[]).is_none());
    }

    #[test]
    fn github_user_deserializes_ignoring_unknown_fields() {
        let raw = r#"{
            "id": 42,
            "login": "octocat",
            "name": "The Octocat",
            "email": null,
            "avatar_url": "https://avatars.example/u/42",
            "company": "GitHub",
            "type": "User"
        }"#;
        let user: GithubUser = serde_json::from_str(raw).unwrap();
        assert_eq!(user.id, 42);
        assert_eq!(user.login, "octocat");
        assert_eq!(user.email, None);
    }

    #[test]
    fn adapter_is_object_safe_for_a_registry() {
        let registry: Vec<Box<dyn IdentityProviderAdapter>> = vec![Box::new(
            GithubProviderAdapter::new(FakeTransport::ok(user(), vec![])),
        )];
        assert_eq!(registry[0].provider_kind(), IdentityProviderKind::OAuth2);
    }
}
