//! Native public-client login through IAM's canonical OpenID Provider.
//!
//! The adapter owns only desktop concerns: PKCE/state generation, a bounded
//! loopback callback listener, token exchange/refresh and persistence through
//! [`CredentialCache`]. Provider selection and upstream credentials stay in
//! IAM's browser session bounded context.

use std::io::{Read as _, Write as _};
use std::net::{IpAddr, Ipv4Addr, SocketAddr, TcpListener};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use awaken_iam_contract::{AccountId, OpenIdProviderMetadata, PrincipalRef, UserInfo};
use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use reqwest::blocking::Client;
use serde::Deserialize;
use sha2::{Digest as _, Sha256};
use url::Url;

use crate::{CachedCredential, CachedOAuthGrant, CredentialCache, RedactedString};

/// Desktop OAuth settings for one registered IAM public client.
#[derive(Debug, Clone)]
pub struct DesktopOAuthConfig {
    /// Canonical IAM issuer, normally `https://accounts.awakenworks.com`.
    pub issuer: String,
    /// Registered public-client id.
    pub client_id: String,
    /// Exact registered loopback redirect URI.
    pub redirect_uri: String,
    /// Requested scopes. `openid` is required.
    pub scopes: Vec<String>,
    /// Maximum HTTP and browser callback wait.
    pub timeout: Duration,
}

impl DesktopOAuthConfig {
    /// Build the production default shape for a registered desktop client.
    pub fn new(
        issuer: impl Into<String>,
        client_id: impl Into<String>,
        redirect_uri: impl Into<String>,
    ) -> Self {
        Self {
            issuer: issuer.into(),
            client_id: client_id.into(),
            redirect_uri: redirect_uri.into(),
            scopes: vec!["openid".into(), "email".into(), "profile".into()],
            timeout: Duration::from_secs(120),
        }
    }
}

/// Stateful desktop OAuth adapter backed by one canonical credential cache.
#[derive(Debug, Clone)]
pub struct DesktopOAuthClient {
    config: DesktopOAuthConfig,
    http: Client,
    cache: CredentialCache,
    issuer: String,
    callback_addr: SocketAddr,
    callback_path: String,
}

impl DesktopOAuthClient {
    /// Validate configuration and construct the client.
    pub fn new(
        config: DesktopOAuthConfig,
        cache: CredentialCache,
    ) -> Result<Self, DesktopOAuthError> {
        let (issuer, callback_addr, callback_path) = validate_config(&config)?;
        let http = Client::builder()
            .timeout(config.timeout)
            .build()
            .map_err(|error| DesktopOAuthError::Transport(error.to_string()))?;
        Ok(Self {
            config,
            http,
            cache,
            issuer,
            callback_addr,
            callback_path,
        })
    }

    /// Return a live cached credential, refresh it, or run interactive login.
    ///
    /// `launch` receives the canonical IAM authorization URL. A GUI product can
    /// open it in the default browser; a headless product can print it.
    pub fn ensure_credential<F>(&self, launch: F) -> Result<CachedCredential, DesktopOAuthError>
    where
        F: FnOnce(&str) -> Result<(), String>,
    {
        if let Ok(Some(credential)) = self.cached_credential() {
            return Ok(credential);
        }
        self.login(launch)
    }

    /// Return or refresh the canonical cached credential without starting a
    /// browser interaction.
    ///
    /// `Ok(None)` means the caller must explicitly enter the interactive PKCE
    /// operation. A refresh transport or protocol failure remains observable so
    /// request paths can distinguish IAM unavailability from absent login state.
    pub fn cached_credential(&self) -> Result<Option<CachedCredential>, DesktopOAuthError> {
        if let Some(credential) = self.cache.load(&self.issuer) {
            return Ok(Some(credential));
        }
        let Some(stale) = self.cache.load_entry(&self.issuer) else {
            return Ok(None);
        };
        if !stale
            .oauth
            .as_ref()
            .is_some_and(|oauth| oauth.client_id == self.config.client_id)
        {
            return Ok(None);
        }
        self.refresh(&stale).map(Some)
    }

    fn login<F>(&self, launch: F) -> Result<CachedCredential, DesktopOAuthError>
    where
        F: FnOnce(&str) -> Result<(), String>,
    {
        let metadata = self.discover()?;
        let listener = TcpListener::bind(self.callback_addr)
            .map_err(|error| DesktopOAuthError::CallbackBind(error.to_string()))?;
        listener
            .set_nonblocking(true)
            .map_err(|error| DesktopOAuthError::CallbackBind(error.to_string()))?;

        let verifier = random_secret(48)?;
        let state = random_secret(32)?;
        let challenge = URL_SAFE_NO_PAD.encode(Sha256::digest(verifier.as_bytes()));
        let authorize_url = authorization_url(&metadata, &self.config, &challenge, &state)?;
        launch(authorize_url.as_str()).map_err(DesktopOAuthError::BrowserLaunch)?;

        let code = wait_for_callback(&listener, &self.callback_path, &state, self.config.timeout)?;
        let grant = self.exchange_code(&metadata, &code, &verifier)?;
        self.persist_grant(&metadata, grant, None)
    }

    fn refresh(&self, stale: &CachedCredential) -> Result<CachedCredential, DesktopOAuthError> {
        let oauth = stale
            .oauth
            .as_ref()
            .ok_or(DesktopOAuthError::RefreshUnavailable)?;
        let metadata = self.discover()?;
        let response = self
            .http
            .post(&metadata.token_endpoint)
            .form(&[
                ("grant_type", "refresh_token"),
                ("client_id", oauth.client_id.as_str()),
                ("refresh_token", oauth.refresh_token.expose()),
            ])
            .send()
            .map_err(|error| DesktopOAuthError::Transport(error.to_string()))?;
        let grant = decode_token_response(response)?;
        self.persist_grant(&metadata, grant, Some(oauth))
    }

    fn discover(&self) -> Result<OpenIdProviderMetadata, DesktopOAuthError> {
        let endpoint = format!("{}/.well-known/openid-configuration", self.issuer);
        let response = self
            .http
            .get(endpoint)
            .send()
            .map_err(|error| DesktopOAuthError::Transport(error.to_string()))?;
        if !response.status().is_success() {
            return Err(DesktopOAuthError::Protocol(format!(
                "discovery returned {}",
                response.status()
            )));
        }
        let metadata = response
            .json::<OpenIdProviderMetadata>()
            .map_err(|error| DesktopOAuthError::Protocol(error.to_string()))?;
        if metadata.issuer.trim_end_matches('/') != self.issuer {
            return Err(DesktopOAuthError::IssuerMismatch);
        }
        for endpoint in [
            &metadata.authorization_endpoint,
            &metadata.token_endpoint,
            &metadata.userinfo_endpoint,
        ] {
            validate_issuer_endpoint(&self.issuer, endpoint)?;
        }
        Ok(metadata)
    }

    fn exchange_code(
        &self,
        metadata: &OpenIdProviderMetadata,
        code: &str,
        verifier: &str,
    ) -> Result<TokenGrant, DesktopOAuthError> {
        let response = self
            .http
            .post(&metadata.token_endpoint)
            .form(&[
                ("grant_type", "authorization_code"),
                ("client_id", self.config.client_id.as_str()),
                ("code", code),
                ("redirect_uri", self.config.redirect_uri.as_str()),
                ("code_verifier", verifier),
            ])
            .send()
            .map_err(|error| DesktopOAuthError::Transport(error.to_string()))?;
        decode_token_response(response)
    }

    fn persist_grant(
        &self,
        metadata: &OpenIdProviderMetadata,
        grant: TokenGrant,
        previous: Option<&CachedOAuthGrant>,
    ) -> Result<CachedCredential, DesktopOAuthError> {
        if !grant.token_type.eq_ignore_ascii_case("bearer") || grant.access_token.is_empty() {
            return Err(DesktopOAuthError::Protocol(
                "token response did not contain a bearer access token".into(),
            ));
        }
        let info = self.userinfo(metadata, &grant.access_token)?;
        let refresh_token = grant
            .refresh_token
            .map(RedactedString::new)
            .or_else(|| previous.map(|oauth| oauth.refresh_token.clone()))
            .ok_or_else(|| {
                DesktopOAuthError::Protocol("token response omitted refresh token".into())
            })?;
        let scopes = grant
            .scope
            .as_deref()
            .map(|scope| scope.split_whitespace().map(str::to_owned).collect())
            .or_else(|| previous.map(|oauth| oauth.scopes.clone()))
            .unwrap_or_else(|| self.config.scopes.clone());
        let credential = CachedCredential {
            token: RedactedString::new(grant.access_token),
            principal: PrincipalRef::Account {
                account_id: AccountId(info.sub),
            },
            expires_at: unix_seconds().saturating_add(grant.expires_in),
            oauth: Some(CachedOAuthGrant {
                refresh_token,
                client_id: self.config.client_id.clone(),
                scopes,
            }),
        };
        self.cache
            .store(&self.issuer, credential.clone())
            .map_err(|error| DesktopOAuthError::Cache(error.to_string()))?;
        Ok(credential)
    }

    fn userinfo(
        &self,
        metadata: &OpenIdProviderMetadata,
        access_token: &str,
    ) -> Result<UserInfo, DesktopOAuthError> {
        let response = self
            .http
            .get(&metadata.userinfo_endpoint)
            .bearer_auth(access_token)
            .send()
            .map_err(|error| DesktopOAuthError::Transport(error.to_string()))?;
        if !response.status().is_success() {
            return Err(DesktopOAuthError::Protocol(format!(
                "userinfo returned {}",
                response.status()
            )));
        }
        response
            .json()
            .map_err(|error| DesktopOAuthError::Protocol(error.to_string()))
    }
}

#[derive(Debug, Deserialize)]
struct TokenGrant {
    access_token: String,
    token_type: String,
    expires_in: u64,
    refresh_token: Option<String>,
    scope: Option<String>,
}

fn decode_token_response(
    response: reqwest::blocking::Response,
) -> Result<TokenGrant, DesktopOAuthError> {
    if !response.status().is_success() {
        return Err(DesktopOAuthError::Protocol(format!(
            "token endpoint returned {}",
            response.status()
        )));
    }
    response
        .json()
        .map_err(|error| DesktopOAuthError::Protocol(error.to_string()))
}

fn validate_config(
    config: &DesktopOAuthConfig,
) -> Result<(String, SocketAddr, String), DesktopOAuthError> {
    if config.client_id.trim().is_empty()
        || !config.scopes.iter().any(|scope| scope == "openid")
        || config.timeout.is_zero()
    {
        return Err(DesktopOAuthError::InvalidConfig);
    }
    let issuer = Url::parse(&config.issuer).map_err(|_| DesktopOAuthError::InvalidConfig)?;
    let issuer_is_https = issuer.scheme() == "https";
    let issuer_is_loopback = issuer.scheme() == "http"
        && matches!(issuer.host_str(), Some("127.0.0.1") | Some("localhost"));
    if !issuer_is_https && !issuer_is_loopback
        || issuer.query().is_some()
        || issuer.fragment().is_some()
    {
        return Err(DesktopOAuthError::InvalidConfig);
    }

    let redirect =
        Url::parse(&config.redirect_uri).map_err(|_| DesktopOAuthError::InvalidConfig)?;
    if redirect.scheme() != "http"
        || redirect.host_str() != Some("127.0.0.1")
        || redirect.query().is_some()
        || redirect.fragment().is_some()
    {
        return Err(DesktopOAuthError::InvalidConfig);
    }
    let port = redirect.port().ok_or(DesktopOAuthError::InvalidConfig)?;
    let path = redirect.path().to_owned();
    if path.is_empty() || path == "/" {
        return Err(DesktopOAuthError::InvalidConfig);
    }
    let issuer = config.issuer.trim_end_matches('/').to_owned();
    Ok((
        issuer,
        SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), port),
        path,
    ))
}

fn validate_issuer_endpoint(issuer: &str, endpoint: &str) -> Result<(), DesktopOAuthError> {
    let issuer = Url::parse(issuer).map_err(|_| DesktopOAuthError::InvalidConfig)?;
    let endpoint = Url::parse(endpoint).map_err(|_| DesktopOAuthError::InvalidConfig)?;
    if issuer.scheme() != endpoint.scheme()
        || issuer.host_str() != endpoint.host_str()
        || issuer.port_or_known_default() != endpoint.port_or_known_default()
    {
        return Err(DesktopOAuthError::IssuerMismatch);
    }
    Ok(())
}

fn authorization_url(
    metadata: &OpenIdProviderMetadata,
    config: &DesktopOAuthConfig,
    challenge: &str,
    state: &str,
) -> Result<Url, DesktopOAuthError> {
    let mut url = Url::parse(&metadata.authorization_endpoint)
        .map_err(|_| DesktopOAuthError::InvalidConfig)?;
    url.query_pairs_mut()
        .append_pair("client_id", &config.client_id)
        .append_pair("redirect_uri", &config.redirect_uri)
        .append_pair("response_type", "code")
        .append_pair("scope", &config.scopes.join(" "))
        .append_pair("state", state)
        .append_pair("code_challenge", challenge)
        .append_pair("code_challenge_method", "S256");
    Ok(url)
}

fn random_secret(size: usize) -> Result<String, DesktopOAuthError> {
    let mut bytes = vec![0_u8; size];
    getrandom::fill(&mut bytes).map_err(|error| DesktopOAuthError::Entropy(error.to_string()))?;
    Ok(URL_SAFE_NO_PAD.encode(bytes))
}

fn wait_for_callback(
    listener: &TcpListener,
    expected_path: &str,
    expected_state: &str,
    timeout: Duration,
) -> Result<String, DesktopOAuthError> {
    let deadline = Instant::now() + timeout;
    loop {
        match listener.accept() {
            Ok((mut stream, _)) => {
                stream
                    .set_read_timeout(Some(Duration::from_secs(5)))
                    .map_err(|error| DesktopOAuthError::Callback(error.to_string()))?;
                let mut request = [0_u8; 8_192];
                let size = stream
                    .read(&mut request)
                    .map_err(|error| DesktopOAuthError::Callback(error.to_string()))?;
                let line = std::str::from_utf8(&request[..size])
                    .ok()
                    .and_then(|request| request.lines().next())
                    .ok_or_else(|| DesktopOAuthError::Callback("invalid HTTP request".into()))?;
                let target = line
                    .strip_prefix("GET ")
                    .and_then(|line| line.split_once(' ').map(|(target, _)| target))
                    .ok_or_else(|| DesktopOAuthError::Callback("invalid callback method".into()))?;
                let callback = Url::parse(&format!("http://127.0.0.1{target}"))
                    .map_err(|_| DesktopOAuthError::Callback("invalid callback URL".into()))?;
                let result = parse_callback(&callback, expected_path, expected_state);
                let (status, message) = if result.is_ok() {
                    ("200 OK", "Sign-in complete. You can return to Awaken.")
                } else {
                    ("400 Bad Request", "Sign-in could not be completed.")
                };
                let body = format!(
                    "<!doctype html><meta charset=\"utf-8\"><title>Awaken sign-in</title><p>{message}</p>"
                );
                let response = format!(
                    "HTTP/1.1 {status}\r\nContent-Type: text/html; charset=utf-8\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                    body.len()
                );
                stream
                    .write_all(response.as_bytes())
                    .map_err(|error| DesktopOAuthError::Callback(error.to_string()))?;
                return result;
            }
            Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                if Instant::now() >= deadline {
                    return Err(DesktopOAuthError::CallbackTimeout);
                }
                std::thread::sleep(Duration::from_millis(25));
            }
            Err(error) => return Err(DesktopOAuthError::Callback(error.to_string())),
        }
    }
}

fn parse_callback(
    callback: &Url,
    expected_path: &str,
    expected_state: &str,
) -> Result<String, DesktopOAuthError> {
    if callback.path() != expected_path {
        return Err(DesktopOAuthError::Callback(
            "unexpected callback path".into(),
        ));
    }
    let mut code = None;
    let mut state = None;
    let mut error = None;
    for (key, value) in callback.query_pairs() {
        match key.as_ref() {
            "code" => code = Some(value.into_owned()),
            "state" => state = Some(value.into_owned()),
            "error" => error = Some(value.into_owned()),
            _ => {}
        }
    }
    if let Some(error) = error {
        return Err(DesktopOAuthError::AuthorizationRejected(error));
    }
    if state.as_deref() != Some(expected_state) {
        return Err(DesktopOAuthError::StateMismatch);
    }
    code.filter(|code| !code.is_empty())
        .ok_or_else(|| DesktopOAuthError::Callback("callback omitted code".into()))
}

fn unix_seconds() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_secs())
        .unwrap_or(0)
}

/// Stable desktop login failures. Secret material is never included.
#[derive(Debug, thiserror::Error)]
pub enum DesktopOAuthError {
    /// Client or loopback coordinate is unsafe or incomplete.
    #[error("invalid desktop OAuth configuration")]
    InvalidConfig,
    /// Discovery returned a different authority.
    #[error("IAM discovery endpoint authority did not match the configured issuer")]
    IssuerMismatch,
    /// Secure random generation failed.
    #[error("desktop OAuth entropy failed: {0}")]
    Entropy(String),
    /// HTTP transport failed.
    #[error("desktop OAuth transport failed: {0}")]
    Transport(String),
    /// IAM returned an invalid or rejected protocol response.
    #[error("desktop OAuth protocol failed: {0}")]
    Protocol(String),
    /// The loopback port could not be reserved.
    #[error("desktop OAuth callback could not bind: {0}")]
    CallbackBind(String),
    /// The loopback callback was malformed.
    #[error("desktop OAuth callback failed: {0}")]
    Callback(String),
    /// The callback did not arrive before the configured deadline.
    #[error("desktop OAuth callback timed out")]
    CallbackTimeout,
    /// Browser launch or headless handoff failed.
    #[error("desktop OAuth browser launch failed: {0}")]
    BrowserLaunch(String),
    /// OAuth state did not match the local request.
    #[error("desktop OAuth state mismatch")]
    StateMismatch,
    /// IAM returned an authorization error.
    #[error("desktop OAuth authorization was rejected: {0}")]
    AuthorizationRejected(String),
    /// An expired cache entry had no refresh state.
    #[error("desktop OAuth refresh is unavailable")]
    RefreshUnavailable,
    /// The canonical credential cache could not persist the rotated grant.
    #[error("desktop OAuth credential cache failed: {0}")]
    Cache(String),
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::{Arc, Mutex};

    fn config() -> DesktopOAuthConfig {
        DesktopOAuthConfig::new(
            "https://accounts.example",
            "awaken-desktop",
            "http://127.0.0.1:34115/callback",
        )
    }

    /// Configuration cause/effect table:
    ///
    /// | issuer | redirect | effect |
    /// | HTTPS | exact IPv4 loopback with port/path | accepted |
    /// | loopback HTTP (development) | exact loopback | accepted |
    /// | non-TLS remote | any | rejected |
    /// | any | non-loopback, missing port/path, query, or fragment | rejected |
    #[test]
    fn configuration_accepts_only_one_safe_loopback_callback() {
        assert!(validate_config(&config()).is_ok());
        let mut local = config();
        local.issuer = "http://127.0.0.1:8080".into();
        assert!(validate_config(&local).is_ok());

        for (issuer, redirect) in [
            ("http://accounts.example", "http://127.0.0.1:34115/callback"),
            ("https://accounts.example", "https://app.example/callback"),
            ("https://accounts.example", "http://127.0.0.1/callback"),
            ("https://accounts.example", "http://127.0.0.1:34115/"),
            (
                "https://accounts.example",
                "http://127.0.0.1:34115/callback?x=1",
            ),
        ] {
            let invalid = DesktopOAuthConfig::new(issuer, "awaken-desktop", redirect);
            assert!(
                validate_config(&invalid).is_err(),
                "accepted {issuer} {redirect}"
            );
        }
    }

    /// Non-interactive credential decision table:
    ///
    /// | cached access | OAuth grant owner | effect |
    /// | live | any | return the live canonical entry |
    /// | absent | n/a | report interaction required without network/browser |
    /// | expired | another public client | report interaction required |
    ///
    /// Matching expired grants are covered by
    /// `expired_credential_refreshes_and_rotates_without_browser_login`, which
    /// proves the remaining rule: refresh and atomically return the replacement.
    #[test]
    fn cached_credential_distinguishes_live_and_interaction_required() {
        let cache_path = std::env::temp_dir().join(format!(
            "awaken-desktop-oauth-cached-{}-{}.json",
            std::process::id(),
            unix_seconds()
        ));
        let cache = CredentialCache::at(cache_path.clone());
        let client = DesktopOAuthClient::new(config(), cache.clone()).unwrap();
        assert!(client.cached_credential().unwrap().is_none());

        cache
            .store(
                "https://accounts.example",
                CachedCredential {
                    token: RedactedString::new("live"),
                    principal: PrincipalRef::Account {
                        account_id: AccountId("acct-live".into()),
                    },
                    expires_at: u64::MAX,
                    oauth: None,
                },
            )
            .unwrap();
        assert_eq!(
            client.cached_credential().unwrap().unwrap().token.expose(),
            "live"
        );

        cache
            .store(
                "https://accounts.example",
                CachedCredential {
                    token: RedactedString::new("expired"),
                    principal: PrincipalRef::Account {
                        account_id: AccountId("acct-old".into()),
                    },
                    expires_at: 0,
                    oauth: Some(CachedOAuthGrant {
                        refresh_token: RedactedString::new("other-refresh"),
                        client_id: "another-client".into(),
                        scopes: vec!["openid".into()],
                    }),
                },
            )
            .unwrap();
        assert!(client.cached_credential().unwrap().is_none());
        let _ = std::fs::remove_file(cache_path);
    }

    /// Callback decision table:
    ///
    /// | path | state | code/error | effect |
    /// | exact | matching | non-empty code | return code |
    /// | different | any | any | reject |
    /// | exact | absent/different | any | reject before exchange |
    /// | exact | matching | OAuth error or absent code | reject |
    #[test]
    fn callback_requires_exact_path_state_and_code() {
        let valid = Url::parse("http://127.0.0.1/callback?code=code-1&state=state-1").unwrap();
        assert_eq!(
            parse_callback(&valid, "/callback", "state-1").unwrap(),
            "code-1"
        );
        for url in [
            "http://127.0.0.1/other?code=code-1&state=state-1",
            "http://127.0.0.1/callback?code=code-1&state=wrong",
            "http://127.0.0.1/callback?error=access_denied&state=state-1",
            "http://127.0.0.1/callback?state=state-1",
        ] {
            assert!(parse_callback(&Url::parse(url).unwrap(), "/callback", "state-1").is_err());
        }
    }

    #[test]
    fn authorization_request_is_public_client_pkce_s256() {
        let metadata = OpenIdProviderMetadata::for_issuer("https://accounts.example");
        let url = authorization_url(&metadata, &config(), "challenge", "state").unwrap();
        let pairs = url
            .query_pairs()
            .collect::<std::collections::HashMap<_, _>>();
        assert_eq!(
            pairs.get("client_id").map(|v| v.as_ref()),
            Some("awaken-desktop")
        );
        assert_eq!(
            pairs.get("code_challenge").map(|v| v.as_ref()),
            Some("challenge")
        );
        assert_eq!(
            pairs.get("code_challenge_method").map(|v| v.as_ref()),
            Some("S256")
        );
        assert!(!pairs.contains_key("client_secret"));
    }

    /// Credential lifecycle decision table:
    ///
    /// | cached access | matching refresh state | refresh response | effect |
    /// | live | any | not called | reuse the canonical cached credential |
    /// | expired | yes | rotating grant + UserInfo | atomically replace cache; do not launch browser |
    /// | expired/absent | no or rejected | n/a | enter the interactive PKCE path |
    #[test]
    fn expired_credential_refreshes_and_rotates_without_browser_login() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let issuer = format!("http://{}", listener.local_addr().unwrap());
        let requests = Arc::new(Mutex::new(Vec::new()));
        let captured = Arc::clone(&requests);
        let server_issuer = issuer.clone();
        let server = std::thread::spawn(move || {
            let metadata =
                serde_json::to_vec(&OpenIdProviderMetadata::for_issuer(&server_issuer)).unwrap();
            let grant = br#"{"access_token":"access-new","token_type":"Bearer","expires_in":3600,"refresh_token":"refresh-new","scope":"openid profile"}"#;
            let userinfo = br#"{"sub":"acct-refreshed","name":"Refreshed"}"#;
            for body in [metadata.as_slice(), grant.as_slice(), userinfo.as_slice()] {
                let (mut stream, _) = listener.accept().unwrap();
                let request = read_test_request(&mut stream);
                captured.lock().unwrap().push(request);
                write_test_json(&mut stream, body);
            }
        });

        let cache_path = std::env::temp_dir().join(format!(
            "awaken-desktop-oauth-refresh-{}-{}.json",
            std::process::id(),
            unix_seconds()
        ));
        let cache = CredentialCache::at(cache_path);
        cache
            .store(
                &issuer,
                CachedCredential {
                    token: RedactedString::new("access-old"),
                    principal: PrincipalRef::Account {
                        account_id: AccountId("acct-old".into()),
                    },
                    expires_at: 0,
                    oauth: Some(CachedOAuthGrant {
                        refresh_token: RedactedString::new("refresh-old"),
                        client_id: "awaken-desktop".into(),
                        scopes: vec!["openid".into()],
                    }),
                },
            )
            .unwrap();
        let client = DesktopOAuthClient::new(
            DesktopOAuthConfig::new(&issuer, "awaken-desktop", "http://127.0.0.1:34115/callback"),
            cache.clone(),
        )
        .unwrap();

        let refreshed = client
            .ensure_credential(|_| panic!("refresh must not launch a browser"))
            .unwrap();
        server.join().unwrap();
        assert_eq!(refreshed.token.expose(), "access-new");
        assert_eq!(
            refreshed.principal,
            PrincipalRef::Account {
                account_id: AccountId("acct-refreshed".into())
            }
        );
        assert_eq!(
            cache
                .load(&issuer)
                .unwrap()
                .oauth
                .unwrap()
                .refresh_token
                .expose(),
            "refresh-new"
        );
        let requests = requests.lock().unwrap();
        assert!(requests[1].contains("grant_type=refresh_token"));
        assert!(requests[1].contains("refresh_token=refresh-old"));
        assert!(
            requests[2]
                .to_ascii_lowercase()
                .contains("authorization: bearer access-new")
        );
    }

    fn read_test_request(stream: &mut std::net::TcpStream) -> String {
        stream
            .set_read_timeout(Some(Duration::from_secs(2)))
            .unwrap();
        let mut bytes = Vec::new();
        let mut chunk = [0_u8; 1_024];
        loop {
            let read = stream.read(&mut chunk).unwrap();
            if read == 0 {
                break;
            }
            bytes.extend_from_slice(&chunk[..read]);
            let Some(headers_end) = bytes.windows(4).position(|part| part == b"\r\n\r\n") else {
                continue;
            };
            let headers = String::from_utf8_lossy(&bytes[..headers_end]);
            let content_length = headers
                .lines()
                .find_map(|line| {
                    line.to_ascii_lowercase()
                        .strip_prefix("content-length:")
                        .and_then(|value| value.trim().parse::<usize>().ok())
                })
                .unwrap_or(0);
            if bytes.len() >= headers_end + 4 + content_length {
                break;
            }
        }
        String::from_utf8(bytes).unwrap()
    }

    fn write_test_json(stream: &mut std::net::TcpStream, body: &[u8]) {
        let headers = format!(
            "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
            body.len()
        );
        stream.write_all(headers.as_bytes()).unwrap();
        stream.write_all(body).unwrap();
    }
}
