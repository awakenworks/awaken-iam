//! Generic, configuration-driven OAuth 2.0 / OIDC upstream provider adapter.
//!
//! Where [`GoogleOidcProvider`](crate::GoogleOidcProvider) and
//! [`GithubProviderAdapter`](crate::GithubProviderAdapter) each encode one
//! vendor's dialect, this adapter speaks the **standard** authorization-code flow
//! entirely
//! from an [`IdentityProviderConfig`] plus a deployment-supplied
//! [`GenericOAuthSecrets`]. A new external identity provider — Microsoft Entra,
//! Okta, Auth0, a self-hosted Keycloak, any compliant OIDC/OAuth2 server — is
//! therefore onboarded by **configuration, not code**: register its endpoints and
//! client id and it logs in through the same loop. This is the ACL over arbitrary
//! upstream IdPs, complementing the per-vendor adapters.
//!
//! For a compliant OIDC provider the endpoints need not even be configured: when
//! the authorization, token, or userinfo endpoint is absent the adapter resolves
//! it from the provider's
//! [`/.well-known/openid-configuration`](https://openid.net/specs/openid-connect-discovery-1_0.html)
//! discovery document, derived from the single `issuer_url`. A new OIDC IdP is
//! then onboarded with nothing but its issuer URL and client credentials.
//!
//! Flow:
//! 1. *Authorization URL* — a standard `response_type=code` request carrying the
//!    client id, redirect, scopes, `state`, and (when the login minted them) an
//!    OIDC `nonce` and a PKCE S256 challenge.
//! 2. *Code exchange* — redeem the callback `code` at the configured
//!    `token_endpoint` for an access token (with the PKCE verifier when present).
//! 3. *Userinfo* — read the authenticated subject from the provider's OIDC
//!    `userinfo` endpoint and normalize the standard claims into the
//!    provider-agnostic [`ExternalIdentityClaims`].
//!
//! All byte transport is delegated to the same [`HttpTransport`] seam the vendor
//! adapters use, so core stays I/O-free and the flow is unit-tested without a
//! network.

use awaken_iam_contract::{
    ExternalIdentityClaims, ExternalSubject, IdentityProviderConfig, IdentityProviderKind,
};
use serde::Deserialize;

use crate::google::{HttpRequest, HttpTransport};
use crate::login::{PkceChallenge, PkceMethod};
use crate::provider::{
    AuthorizationRedirect, AuthorizationUrlRequest, CallbackExchange, IdentityProviderAdapter,
    ProviderError,
};

/// Deployment-supplied material for a generic provider that does not belong in
/// the shared [`IdentityProviderConfig`] DTO.
///
/// The client secret is a deployment secret; the userinfo endpoint and default
/// scopes are operational details kept out of the contract (mirroring how
/// [`GoogleProviderSecrets`](crate::GoogleProviderSecrets) carries the JWKS URI
/// separately from the config).
#[derive(Debug, Clone)]
pub struct GenericOAuthSecrets {
    /// OAuth client secret used at the token endpoint.
    pub client_secret: String,
    /// OIDC `userinfo` endpoint read for the authenticated subject and claims.
    ///
    /// `None` defers to OIDC discovery: the endpoint is read from the provider's
    /// `/.well-known/openid-configuration` document at exchange time.
    pub userinfo_endpoint: Option<String>,
    /// Scopes requested when a login does not specify its own.
    pub default_scopes: Vec<String>,
}

impl GenericOAuthSecrets {
    /// Build secrets with an explicit userinfo endpoint and the standard OIDC
    /// default scopes (`openid email profile`).
    pub fn new(client_secret: impl Into<String>, userinfo_endpoint: impl Into<String>) -> Self {
        Self {
            client_secret: client_secret.into(),
            userinfo_endpoint: Some(userinfo_endpoint.into()),
            default_scopes: vec!["openid".into(), "email".into(), "profile".into()],
        }
    }

    /// Build secrets for a discovery-driven provider, leaving the userinfo
    /// endpoint to be resolved from the provider's discovery document.
    ///
    /// Paired with a config that carries only `issuer_url`, this onboards an
    /// OIDC provider with no endpoint configuration at all.
    pub fn discovered(client_secret: impl Into<String>) -> Self {
        Self {
            client_secret: client_secret.into(),
            userinfo_endpoint: None,
            default_scopes: vec!["openid".into(), "email".into(), "profile".into()],
        }
    }

    /// Override the default scopes requested when a login specifies none.
    pub fn with_default_scopes<I, S>(mut self, scopes: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        self.default_scopes = scopes.into_iter().map(Into::into).collect();
        self
    }
}

/// Config-driven OAuth2/OIDC adapter over the [`HttpTransport`] seam.
#[derive(Debug, Clone)]
pub struct GenericOAuthProvider<T> {
    secrets: GenericOAuthSecrets,
    transport: T,
}

impl<T> GenericOAuthProvider<T> {
    /// Build a generic provider from its secrets and a transport.
    pub fn new(secrets: GenericOAuthSecrets, transport: T) -> Self {
        Self { secrets, transport }
    }

    /// Borrow the underlying transport.
    pub fn transport(&self) -> &T {
        &self.transport
    }

    /// Read the required public client id off the config.
    fn client_id<'a>(&self, config: &'a IdentityProviderConfig) -> Result<&'a str, ProviderError> {
        config
            .client_id
            .as_deref()
            .ok_or(ProviderError::MissingConfiguration { field: "client_id" })
    }
}

impl<T: HttpTransport> IdentityProviderAdapter for GenericOAuthProvider<T> {
    fn provider_kind(&self) -> IdentityProviderKind {
        IdentityProviderKind::Oidc
    }

    /// This adapter serves both the OAuth2 and OIDC families; only the
    /// non-production fake provider is rejected.
    fn ensure_kind(&self, config: &IdentityProviderConfig) -> Result<(), ProviderError> {
        match config.kind {
            IdentityProviderKind::OAuth2 | IdentityProviderKind::Oidc => Ok(()),
            actual => Err(ProviderError::UnsupportedProviderKind {
                expected: IdentityProviderKind::Oidc,
                actual,
            }),
        }
    }

    fn authorization_url(
        &self,
        config: &IdentityProviderConfig,
        request: &AuthorizationUrlRequest,
    ) -> Result<AuthorizationRedirect, ProviderError> {
        self.ensure_kind(config)?;
        let endpoint = self.authorization_endpoint(config)?;
        let endpoint = endpoint.as_str();
        let client_id = self.client_id(config)?;
        let scopes = if request.scopes.is_empty() {
            self.secrets.default_scopes.clone()
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
        let (token_endpoint, userinfo_endpoint) = self.exchange_endpoints(config)?;
        let access_token = self.redeem_code(config, callback, &token_endpoint)?;
        let info = self.fetch_userinfo(&access_token, &userinfo_endpoint)?;
        if info.sub.is_empty() {
            return Err(ProviderError::MalformedClaims {
                reason: "userinfo response did not include a subject".to_owned(),
            });
        }
        Ok(ExternalIdentityClaims {
            subject: ExternalSubject(info.sub),
            email: info.email,
            email_verified: info.email_verified,
            display_name: info.name,
            username: info.preferred_username,
            avatar_url: info.picture,
            locale: info.locale,
        })
    }
}

impl<T: HttpTransport> GenericOAuthProvider<T> {
    /// Resolve the authorization endpoint, preferring the explicit config value
    /// and falling back to the provider's OIDC discovery document.
    fn authorization_endpoint(
        &self,
        config: &IdentityProviderConfig,
    ) -> Result<String, ProviderError> {
        if let Some(endpoint) = nonempty(config.authorization_endpoint.as_deref()) {
            return Ok(endpoint.to_owned());
        }
        let doc = self.discover(config)?;
        nonempty(doc.authorization_endpoint.as_deref())
            .map(str::to_owned)
            .ok_or(ProviderError::MissingConfiguration {
                field: "authorization_endpoint",
            })
    }

    /// Resolve the token and userinfo endpoints the code exchange needs.
    ///
    /// Each prefers its explicit value (config `token_endpoint`, secrets
    /// `userinfo_endpoint`); when either is missing the provider's discovery
    /// document is fetched once and supplies both.
    fn exchange_endpoints(
        &self,
        config: &IdentityProviderConfig,
    ) -> Result<(String, String), ProviderError> {
        let token = nonempty(config.token_endpoint.as_deref()).map(str::to_owned);
        let userinfo = nonempty(self.secrets.userinfo_endpoint.as_deref()).map(str::to_owned);
        if let (Some(token), Some(userinfo)) = (&token, &userinfo) {
            return Ok((token.clone(), userinfo.clone()));
        }
        let doc = self.discover(config)?;
        let token = token
            .or_else(|| nonempty(doc.token_endpoint.as_deref()).map(str::to_owned))
            .ok_or(ProviderError::MissingConfiguration {
                field: "token_endpoint",
            })?;
        let userinfo = userinfo
            .or_else(|| nonempty(doc.userinfo_endpoint.as_deref()).map(str::to_owned))
            .ok_or(ProviderError::MissingConfiguration {
                field: "userinfo_endpoint",
            })?;
        Ok((token, userinfo))
    }

    /// Fetch and parse the provider's `/.well-known/openid-configuration`
    /// discovery document, derived from the configured `issuer_url`.
    fn discover(
        &self,
        config: &IdentityProviderConfig,
    ) -> Result<DiscoveryDocument, ProviderError> {
        let issuer =
            nonempty(config.issuer_url.as_deref()).ok_or(ProviderError::MissingConfiguration {
                field: "issuer_url",
            })?;
        let url = format!(
            "{}/.well-known/openid-configuration",
            issuer.trim_end_matches('/')
        );
        let request = HttpRequest::get(url).with_header("accept", "application/json");
        let body =
            self.transport
                .execute(&request)
                .map_err(|reason| ProviderError::ExchangeRejected {
                    reason: format!("discovery request failed: {reason}"),
                })?;
        serde_json::from_slice(&body).map_err(|err| ProviderError::MalformedClaims {
            reason: format!("discovery document was not valid JSON: {err}"),
        })
    }

    /// Redeem the authorization `code` for an access token at the token endpoint.
    fn redeem_code(
        &self,
        config: &IdentityProviderConfig,
        callback: &CallbackExchange,
        token_endpoint: &str,
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

        let request = HttpRequest::post(token_endpoint.to_owned(), form)
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
        response
            .access_token
            .filter(|token| !token.is_empty())
            .ok_or(ProviderError::ExchangeRejected {
                reason: "token response did not include an access_token".to_owned(),
            })
    }

    /// Read the authenticated subject and profile from the userinfo endpoint.
    fn fetch_userinfo(
        &self,
        access_token: &str,
        userinfo_endpoint: &str,
    ) -> Result<UserInfo, ProviderError> {
        let request = HttpRequest::get(userinfo_endpoint.to_owned())
            .with_header("authorization", &format!("Bearer {access_token}"))
            .with_header("accept", "application/json");
        let body =
            self.transport
                .execute(&request)
                .map_err(|reason| ProviderError::ExchangeRejected {
                    reason: format!("userinfo request failed: {reason}"),
                })?;
        serde_json::from_slice(&body).map_err(|err| ProviderError::MalformedClaims {
            reason: format!("userinfo response was not valid JSON: {err}"),
        })
    }
}

/// Token-endpoint response; only the access token is consumed.
#[derive(Debug, Deserialize)]
struct TokenResponse {
    #[serde(default)]
    access_token: Option<String>,
}

/// The subset of an OIDC `/.well-known/openid-configuration` document this
/// adapter resolves endpoints from; all other metadata fields are ignored.
#[derive(Debug, Deserialize)]
struct DiscoveryDocument {
    #[serde(default)]
    authorization_endpoint: Option<String>,
    #[serde(default)]
    token_endpoint: Option<String>,
    #[serde(default)]
    userinfo_endpoint: Option<String>,
}

/// Treat a present-but-empty configuration string as absent.
fn nonempty(value: Option<&str>) -> Option<&str> {
    value.filter(|candidate| !candidate.is_empty())
}

/// Standard OIDC userinfo claims this adapter normalizes.
#[derive(Debug, Deserialize)]
struct UserInfo {
    sub: String,
    #[serde(default)]
    email: Option<String>,
    #[serde(default)]
    email_verified: Option<bool>,
    #[serde(default)]
    name: Option<String>,
    #[serde(default)]
    preferred_username: Option<String>,
    #[serde(default)]
    picture: Option<String>,
    #[serde(default)]
    locale: Option<String>,
}

/// The `&code_challenge=…&code_challenge_method=S256` PKCE query fragment.
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

    fn config(kind: IdentityProviderKind) -> IdentityProviderConfig {
        IdentityProviderConfig {
            id: IdentityProviderConfigId("cfg_generic".into()),
            provider_key: IdentityProviderKey("acme-idp".into()),
            kind,
            display_name: "ACME SSO".into(),
            issuer_url: Some("https://idp.acme.example".into()),
            authorization_endpoint: Some("https://idp.acme.example/authorize".into()),
            token_endpoint: Some("https://idp.acme.example/token".into()),
            client_id: Some("client-123".into()),
            enabled: true,
        }
    }

    fn auth_request() -> AuthorizationUrlRequest {
        AuthorizationUrlRequest {
            redirect_uri: "https://app.example/v1/auth/callback/acme-idp".into(),
            state: "state-xyz".into(),
            nonce: Some("nonce-abc".into()),
            pkce_challenge: Some(PkceChallenge {
                method: PkceMethod::S256,
                challenge: "chal-123".into(),
            }),
            scopes: Vec::new(),
        }
    }

    /// A transport that routes by URL: the discovery, token, and userinfo
    /// endpoints each return their canned body, or a failure when set.
    struct RoutingTransport {
        discovery_body: Vec<u8>,
        token_body: Vec<u8>,
        userinfo_body: Vec<u8>,
        fail: Option<String>,
    }

    impl HttpTransport for RoutingTransport {
        fn execute(&self, request: &HttpRequest) -> Result<Vec<u8>, String> {
            if let Some(reason) = &self.fail {
                return Err(reason.clone());
            }
            if request.url.contains("/.well-known/openid-configuration") {
                Ok(self.discovery_body.clone())
            } else if request.url.contains("/token") {
                Ok(self.token_body.clone())
            } else if request.url.contains("/userinfo") {
                Ok(self.userinfo_body.clone())
            } else {
                Err(format!("unexpected url {}", request.url))
            }
        }
    }

    fn provider(transport: RoutingTransport) -> GenericOAuthProvider<RoutingTransport> {
        GenericOAuthProvider::new(
            GenericOAuthSecrets::new("topsecret", "https://idp.acme.example/userinfo"),
            transport,
        )
    }

    fn ok_transport() -> RoutingTransport {
        RoutingTransport {
            discovery_body: discovery_body(),
            token_body: br#"{"access_token":"at-789","token_type":"bearer"}"#.to_vec(),
            userinfo_body: br#"{
                "sub":"idp-sub-001",
                "email":"ada@acme.example",
                "email_verified":true,
                "name":"Ada Lovelace",
                "preferred_username":"ada",
                "picture":"https://idp.acme.example/ada.png",
                "locale":"en-GB"
            }"#
            .to_vec(),
            fail: None,
        }
    }

    /// A standard discovery document whose endpoints sit under the issuer host.
    fn discovery_body() -> Vec<u8> {
        br#"{
            "issuer":"https://idp.acme.example",
            "authorization_endpoint":"https://idp.acme.example/authorize",
            "token_endpoint":"https://idp.acme.example/token",
            "userinfo_endpoint":"https://idp.acme.example/userinfo"
        }"#
        .to_vec()
    }

    /// A config that supplies only `issuer_url`, forcing endpoint discovery.
    fn discovery_only_config(kind: IdentityProviderKind) -> IdentityProviderConfig {
        let mut cfg = config(kind);
        cfg.authorization_endpoint = None;
        cfg.token_endpoint = None;
        cfg
    }

    /// A provider whose userinfo endpoint is also resolved via discovery.
    fn discovered_provider(transport: RoutingTransport) -> GenericOAuthProvider<RoutingTransport> {
        GenericOAuthProvider::new(GenericOAuthSecrets::discovered("topsecret"), transport)
    }

    #[test]
    fn authorization_url_resolves_endpoint_via_discovery() {
        let provider = discovered_provider(ok_transport());
        let redirect = provider
            .authorization_url(
                &discovery_only_config(IdentityProviderKind::Oidc),
                &auth_request(),
            )
            .expect("authorization url from discovery");
        // The authorization endpoint came from the discovery document, not config.
        assert!(
            redirect
                .url
                .starts_with("https://idp.acme.example/authorize?")
        );
        assert!(redirect.url.contains("client_id=client-123"));
    }

    #[test]
    fn exchange_callback_resolves_token_and_userinfo_via_discovery() {
        let provider = discovered_provider(ok_transport());
        let callback = CallbackExchange {
            redirect_uri: "https://app.example/v1/auth/callback/acme-idp".into(),
            code: "auth-code-disc".into(),
            pkce_verifier: Some("verifier-disc".into()),
        };
        let claims = provider
            .exchange_callback(
                &discovery_only_config(IdentityProviderKind::Oidc),
                &callback,
            )
            .expect("claims via discovery");
        // Token and userinfo endpoints both resolved from the discovery document.
        assert_eq!(claims.subject, ExternalSubject("idp-sub-001".into()));
        assert_eq!(claims.email.as_deref(), Some("ada@acme.example"));
    }

    #[test]
    fn discovery_requires_an_issuer_url() {
        let provider = discovered_provider(ok_transport());
        let mut cfg = discovery_only_config(IdentityProviderKind::Oidc);
        cfg.issuer_url = None;
        let err = provider
            .authorization_url(&cfg, &auth_request())
            .expect_err("missing issuer url");
        assert_eq!(
            err,
            ProviderError::MissingConfiguration {
                field: "issuer_url"
            }
        );
    }

    #[test]
    fn discovery_document_missing_endpoint_is_reported() {
        // A discovery document that omits the authorization endpoint surfaces the
        // same MissingConfiguration error as an unconfigured one.
        let transport = RoutingTransport {
            discovery_body: br#"{"issuer":"https://idp.acme.example"}"#.to_vec(),
            ..ok_transport()
        };
        let provider = discovered_provider(transport);
        let err = provider
            .authorization_url(
                &discovery_only_config(IdentityProviderKind::Oidc),
                &auth_request(),
            )
            .expect_err("discovery without authorization endpoint");
        assert_eq!(
            err,
            ProviderError::MissingConfiguration {
                field: "authorization_endpoint"
            }
        );
    }

    #[test]
    fn explicit_endpoints_skip_discovery() {
        // With endpoints configured and a userinfo secret, no discovery call is
        // made — proven by a transport whose discovery branch would error.
        let transport = RoutingTransport {
            discovery_body: b"not-json".to_vec(),
            ..ok_transport()
        };
        let provider = provider(transport);
        let callback = CallbackExchange {
            redirect_uri: "https://app.example/v1/auth/callback/acme-idp".into(),
            code: "auth-code-1".into(),
            pkce_verifier: None,
        };
        let claims = provider
            .exchange_callback(&config(IdentityProviderKind::Oidc), &callback)
            .expect("claims without discovery");
        assert_eq!(claims.subject, ExternalSubject("idp-sub-001".into()));
    }

    #[test]
    fn authorization_url_is_standard_oidc_shaped() {
        let provider = provider(ok_transport());
        let redirect = provider
            .authorization_url(&config(IdentityProviderKind::Oidc), &auth_request())
            .expect("authorization url");
        let url = redirect.url;
        assert!(url.starts_with("https://idp.acme.example/authorize?"));
        assert!(url.contains("response_type=code"));
        assert!(url.contains("client_id=client-123"));
        assert!(url.contains("state=state-xyz"));
        // Default OIDC scopes are requested when the login specifies none.
        assert!(url.contains("scope=openid%20email%20profile"));
        // OIDC nonce and PKCE S256 challenge are placed on the wire.
        assert!(url.contains("nonce=nonce-abc"));
        assert!(url.contains("code_challenge=chal-123"));
        assert!(url.contains("code_challenge_method=S256"));
    }

    #[test]
    fn authorization_url_requires_a_client_id() {
        let provider = provider(ok_transport());
        let mut cfg = config(IdentityProviderKind::Oidc);
        cfg.client_id = None;
        let err = provider
            .authorization_url(&cfg, &auth_request())
            .expect_err("missing client id");
        assert_eq!(
            err,
            ProviderError::MissingConfiguration { field: "client_id" }
        );
    }

    #[test]
    fn exchange_callback_normalizes_standard_userinfo_claims() {
        let provider = provider(ok_transport());
        let callback = CallbackExchange {
            redirect_uri: "https://app.example/v1/auth/callback/acme-idp".into(),
            code: "auth-code-1".into(),
            pkce_verifier: Some("verifier-1".into()),
        };
        let claims = provider
            .exchange_callback(&config(IdentityProviderKind::Oidc), &callback)
            .expect("claims");
        assert_eq!(claims.subject, ExternalSubject("idp-sub-001".into()));
        assert_eq!(claims.email.as_deref(), Some("ada@acme.example"));
        assert_eq!(claims.email_verified, Some(true));
        assert_eq!(claims.display_name.as_deref(), Some("Ada Lovelace"));
        assert_eq!(claims.username.as_deref(), Some("ada"));
        assert_eq!(claims.locale.as_deref(), Some("en-GB"));
    }

    #[test]
    fn exchange_callback_serves_plain_oauth2_too() {
        // The same adapter serves an OAuth2 provider (no id_token), reading the
        // subject from userinfo just the same.
        let provider = provider(ok_transport());
        let callback = CallbackExchange {
            redirect_uri: "https://app.example/v1/auth/callback/acme-idp".into(),
            code: "auth-code-2".into(),
            pkce_verifier: None,
        };
        let claims = provider
            .exchange_callback(&config(IdentityProviderKind::OAuth2), &callback)
            .expect("claims");
        assert_eq!(claims.subject, ExternalSubject("idp-sub-001".into()));
    }

    #[test]
    fn rejects_the_fake_provider_kind() {
        let provider = provider(ok_transport());
        let err = provider
            .authorization_url(&config(IdentityProviderKind::Fake), &auth_request())
            .expect_err("fake kind rejected");
        assert!(matches!(
            err,
            ProviderError::UnsupportedProviderKind {
                actual: IdentityProviderKind::Fake,
                ..
            }
        ));
    }

    #[test]
    fn exchange_callback_rejects_an_empty_code() {
        let provider = provider(ok_transport());
        let callback = CallbackExchange {
            redirect_uri: "https://app.example/cb".into(),
            code: String::new(),
            pkce_verifier: None,
        };
        let err = provider
            .exchange_callback(&config(IdentityProviderKind::Oidc), &callback)
            .expect_err("empty code rejected");
        assert!(matches!(err, ProviderError::ExchangeRejected { .. }));
    }

    #[test]
    fn exchange_callback_surfaces_transport_failure() {
        let provider = provider(RoutingTransport {
            discovery_body: Vec::new(),
            token_body: Vec::new(),
            userinfo_body: Vec::new(),
            fail: Some("boom".into()),
        });
        let callback = CallbackExchange {
            redirect_uri: "https://app.example/cb".into(),
            code: "auth-code".into(),
            pkce_verifier: None,
        };
        let err = provider
            .exchange_callback(&config(IdentityProviderKind::Oidc), &callback)
            .expect_err("transport failure surfaces");
        assert!(matches!(err, ProviderError::ExchangeRejected { .. }));
    }

    fn callback(code: &str) -> CallbackExchange {
        CallbackExchange {
            redirect_uri: "https://app.example/cb".into(),
            code: code.into(),
            pkce_verifier: None,
        }
    }

    #[test]
    fn overriding_default_scopes_and_request_scopes_reach_the_url() {
        // Custom default scopes are used when the request carries none.
        let secrets = GenericOAuthSecrets::new("topsecret", "https://idp.acme.example/userinfo")
            .with_default_scopes(["openid", "groups"]);
        let provider = GenericOAuthProvider::new(secrets, ok_transport());
        assert_eq!(provider.provider_kind(), IdentityProviderKind::Oidc);
        // The transport is borrowable through the accessor.
        let _ = provider.transport();
        let redirect = provider
            .authorization_url(&config(IdentityProviderKind::Oidc), &auth_request())
            .expect("url");
        assert!(redirect.url.contains("scope=openid%20groups"));

        // A request that names its own scopes overrides the defaults.
        let mut req = auth_request();
        req.scopes = vec!["openid".into(), "offline_access".into()];
        let redirect = provider
            .authorization_url(&config(IdentityProviderKind::Oidc), &req)
            .expect("url");
        assert!(redirect.url.contains("scope=openid%20offline_access"));
    }


    #[test]
    fn token_response_must_be_valid_json() {
        let provider = provider(RoutingTransport {
            discovery_body: Vec::new(),
            token_body: b"not-json".to_vec(),
            userinfo_body: Vec::new(),
            fail: None,
        });
        let err = provider
            .exchange_callback(&config(IdentityProviderKind::Oidc), &callback("auth-code"))
            .expect_err("malformed token json");
        assert!(matches!(err, ProviderError::MalformedClaims { .. }));
    }

    #[test]
    fn token_response_must_carry_a_non_empty_access_token() {
        // Missing access_token, then an empty one, both reject as exchange errors.
        for body in [&b"{}"[..], br#"{"access_token":""}"#] {
            let provider = provider(RoutingTransport {
                discovery_body: Vec::new(),
                token_body: body.to_vec(),
                userinfo_body: ok_transport().userinfo_body,
                fail: None,
            });
            let err = provider
                .exchange_callback(&config(IdentityProviderKind::Oidc), &callback("auth-code"))
                .expect_err("no usable access token");
            assert!(matches!(err, ProviderError::ExchangeRejected { .. }));
        }
    }

    #[test]
    fn userinfo_response_must_be_valid_json() {
        let provider = provider(RoutingTransport {
            discovery_body: Vec::new(),
            token_body: ok_transport().token_body,
            userinfo_body: b"<html>".to_vec(),
            fail: None,
        });
        let err = provider
            .exchange_callback(&config(IdentityProviderKind::Oidc), &callback("auth-code"))
            .expect_err("malformed userinfo json");
        assert!(matches!(err, ProviderError::MalformedClaims { .. }));
    }

    #[test]
    fn userinfo_request_failure_surfaces_after_a_successful_redeem() {
        // A transport that redeems the token but fails the userinfo fetch, so the
        // failure surfaces from the second leg, not the first.
        struct UserinfoFails;
        impl HttpTransport for UserinfoFails {
            fn execute(&self, request: &HttpRequest) -> Result<Vec<u8>, String> {
                if request.url.contains("/token") {
                    Ok(br#"{"access_token":"at"}"#.to_vec())
                } else {
                    Err("userinfo down".into())
                }
            }
        }
        let provider = GenericOAuthProvider::new(
            GenericOAuthSecrets::new("topsecret", "https://idp.acme.example/userinfo"),
            UserinfoFails,
        );
        let err = provider
            .exchange_callback(&config(IdentityProviderKind::Oidc), &callback("auth-code"))
            .expect_err("userinfo failure surfaces");
        match err {
            ProviderError::ExchangeRejected { reason } => {
                assert!(reason.contains("userinfo"), "reason was {reason}");
            }
            other => panic!("unexpected error {other:?}"),
        }
    }

    #[test]
    fn userinfo_must_include_a_subject() {
        let provider = provider(RoutingTransport {
            discovery_body: Vec::new(),
            token_body: ok_transport().token_body,
            userinfo_body: br#"{"sub":""}"#.to_vec(),
            fail: None,
        });
        let err = provider
            .exchange_callback(&config(IdentityProviderKind::Oidc), &callback("auth-code"))
            .expect_err("empty subject");
        assert!(matches!(err, ProviderError::MalformedClaims { .. }));
    }
}
