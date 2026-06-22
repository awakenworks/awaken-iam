//! Session cookie and `/v1/session` assembly.
//!
//! This is the server-side seam that closes the login session loop for browser
//! clients. After a login resolves to an account, [`SessionGateway`] mints a
//! session through [`SessionMinter`](awaken_iam_core::SessionMinter), persists it
//! in its [`SessionDirectory`], and returns a `Set-Cookie` header carrying the
//! opaque bearer token with `HttpOnly`, `Secure`, and `SameSite` set.
//!
//! The cookie value is the cleartext token; only its hash is persisted, so a
//! presented cookie is resolved by hashing the token and looking the session up
//! by hash. `GET /v1/session` returns a [`SessionView`] (never the token), and
//! logout revokes the session server-side and returns a cookie that clears the
//! browser copy. Expiry and revocation are enforced by the directory: a revoked
//! or expired session no longer authenticates.

use awaken_iam_contract::{SessionId, SessionView, Timestamp};
use awaken_iam_core::{
    EntropySource, EstablishSession, IamError, OsEntropy, SessionDirectory, SessionMinter,
    hash_session_token,
};

/// Default session cookie name.
///
/// The `__Host-` prefix binds the cookie to `Secure`, `Path=/`, and no `Domain`,
/// which the default [`SessionCookieConfig`] satisfies.
pub const DEFAULT_SESSION_COOKIE_NAME: &str = "__Host-awaken_session";

/// `SameSite` cookie attribute.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SameSite {
    /// Only sent for same-site requests.
    Strict,
    /// Sent for same-site requests and top-level cross-site navigations.
    Lax,
    /// Sent for all requests; requires `Secure`.
    None,
}

impl SameSite {
    /// Render the attribute value used in a `Set-Cookie` header.
    pub fn as_str(self) -> &'static str {
        match self {
            SameSite::Strict => "Strict",
            SameSite::Lax => "Lax",
            SameSite::None => "None",
        }
    }
}

/// Attributes applied to the session cookie.
///
/// Defaults are the hardened production shape: `HttpOnly` (no script access),
/// `Secure` (TLS only), `SameSite=Lax`, and `Path=/`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SessionCookieConfig {
    /// Cookie name.
    pub name: String,
    /// Cookie `Path` attribute.
    pub path: String,
    /// Whether to set the `Secure` attribute.
    pub secure: bool,
    /// Whether to set the `HttpOnly` attribute.
    pub http_only: bool,
    /// `SameSite` policy.
    pub same_site: SameSite,
}

impl Default for SessionCookieConfig {
    fn default() -> Self {
        Self {
            name: DEFAULT_SESSION_COOKIE_NAME.to_owned(),
            path: "/".to_owned(),
            secure: true,
            http_only: true,
            same_site: SameSite::Lax,
        }
    }
}

impl SessionCookieConfig {
    /// Render a `Set-Cookie` header value carrying `value`, optionally bounded by
    /// `Max-Age` (seconds).
    pub fn render_set_cookie(&self, value: &str, max_age_secs: Option<u64>) -> String {
        self.render(value, max_age_secs)
    }

    /// Render a `Set-Cookie` header value that clears the cookie in the browser.
    pub fn render_clear_cookie(&self) -> String {
        self.render("", Some(0))
    }

    fn render(&self, value: &str, max_age_secs: Option<u64>) -> String {
        let mut cookie = format!("{}={}", self.name, value);
        cookie.push_str("; Path=");
        cookie.push_str(&self.path);
        if let Some(max_age) = max_age_secs {
            cookie.push_str("; Max-Age=");
            cookie.push_str(&max_age.to_string());
        }
        if self.http_only {
            cookie.push_str("; HttpOnly");
        }
        if self.secure {
            cookie.push_str("; Secure");
        }
        cookie.push_str("; SameSite=");
        cookie.push_str(self.same_site.as_str());
        cookie
    }

    /// Extract this cookie's value from a request `Cookie` header, if present.
    pub fn extract_token(&self, cookie_header: &str) -> Option<String> {
        cookie_header.split(';').find_map(|pair| {
            let (name, value) = pair.split_once('=')?;
            if name.trim() == self.name {
                Some(value.trim().to_owned())
            } else {
                None
            }
        })
    }
}

/// Result of establishing a session: the public view plus the `Set-Cookie`
/// header value to return to the browser.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EstablishedSession {
    /// Public, token-free view of the new session.
    pub view: SessionView,
    /// `Set-Cookie` header value carrying the bearer token.
    pub set_cookie: String,
}

/// Server-side session manager backing the session cookie and `/v1/session`.
#[derive(Debug, Default)]
pub struct SessionGateway<E: EntropySource = OsEntropy> {
    directory: SessionDirectory,
    minter: SessionMinter<E>,
    cookie: SessionCookieConfig,
}

impl SessionGateway<OsEntropy> {
    /// Build a gateway over the OS entropy source and default cookie attributes.
    pub fn new() -> Self {
        Self::default()
    }
}

impl<E: EntropySource> SessionGateway<E> {
    /// Build a gateway over a custom entropy source and cookie configuration.
    pub fn with_entropy(entropy: E, cookie: SessionCookieConfig) -> Self {
        Self {
            directory: SessionDirectory::new(),
            minter: SessionMinter::new(entropy),
            cookie,
        }
    }

    /// The cookie configuration applied by this gateway.
    pub fn cookie_config(&self) -> &SessionCookieConfig {
        &self.cookie
    }

    /// Borrow the underlying session directory.
    pub fn directory(&self) -> &SessionDirectory {
        &self.directory
    }

    /// Establish a session after a successful login and build its session
    /// cookie. `cookie_max_age_secs` optionally bounds the browser cookie; the
    /// server-side session expiry is carried by `request.expires_at`.
    pub fn establish_session(
        &mut self,
        request: EstablishSession,
        cookie_max_age_secs: Option<u64>,
    ) -> Result<EstablishedSession, IamError> {
        let issued = self.minter.establish(&mut self.directory, request)?;
        let set_cookie = self
            .cookie
            .render_set_cookie(&issued.token, cookie_max_age_secs);
        Ok(EstablishedSession {
            view: SessionView::from(&issued.session),
            set_cookie,
        })
    }

    /// Resolve the current session from a presented bearer token (`GET
    /// /v1/session`), refreshing its activity stamp.
    ///
    /// Fails closed when the token is unknown, revoked, or expired.
    pub fn current_session(
        &mut self,
        token: &str,
        now: Timestamp,
    ) -> Result<SessionView, IamError> {
        let token_hash = hash_session_token(token);
        let session = self
            .directory
            .authenticate_by_token_hash(&token_hash, now)?;
        Ok(SessionView::from(session))
    }

    /// Resolve the current session directly from a request `Cookie` header.
    ///
    /// A missing session cookie fails closed as [`IamError::SessionNotFound`].
    pub fn current_session_from_cookie(
        &mut self,
        cookie_header: &str,
        now: Timestamp,
    ) -> Result<SessionView, IamError> {
        let token =
            self.cookie
                .extract_token(cookie_header)
                .ok_or_else(|| IamError::SessionNotFound {
                    id: SessionId(String::new()),
                })?;
        self.current_session(&token, now)
    }

    /// Log out: revoke the session bound to the presented token and return a
    /// `Set-Cookie` header that clears the browser cookie.
    ///
    /// Revocation is idempotent; an unknown token fails closed.
    pub fn logout(&mut self, token: &str, now: Timestamp) -> Result<String, IamError> {
        let token_hash = hash_session_token(token);
        let id = self
            .directory
            .session_id_for_token_hash(&token_hash)
            .cloned()
            .ok_or_else(|| IamError::SessionNotFound {
                id: SessionId(String::new()),
            })?;
        self.directory.revoke_session(&id, now)?;
        Ok(self.cookie.render_clear_cookie())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use awaken_iam_contract::{AccountId, ExternalIdentityId};

    /// Deterministic entropy so minted tokens are distinct and reproducible.
    #[derive(Default)]
    struct SequentialEntropy {
        next: u8,
    }

    impl EntropySource for SequentialEntropy {
        fn fill_bytes(&mut self, buf: &mut [u8]) {
            for byte in buf.iter_mut() {
                *byte = self.next;
                self.next = self.next.wrapping_add(1);
            }
        }
    }

    fn gateway() -> SessionGateway<SequentialEntropy> {
        SessionGateway::with_entropy(SequentialEntropy::default(), SessionCookieConfig::default())
    }

    fn establish_request(id: &str, expires_at: &str) -> EstablishSession {
        EstablishSession {
            id: SessionId(id.into()),
            account_id: AccountId("acct_1".into()),
            external_identity_id: Some(ExternalIdentityId("ext_1".into())),
            created_at: Timestamp("2026-06-19T00:00:00Z".into()),
            expires_at: Timestamp(expires_at.into()),
        }
    }

    #[test]
    fn establish_sets_hardened_cookie_and_hides_token() {
        let mut gateway = gateway();
        let established = gateway
            .establish_session(
                establish_request("sess_1", "2026-06-20T00:00:00Z"),
                Some(3600),
            )
            .unwrap();

        let cookie = &established.set_cookie;
        assert!(cookie.starts_with(DEFAULT_SESSION_COOKIE_NAME));
        assert!(cookie.contains("; HttpOnly"));
        assert!(cookie.contains("; Secure"));
        assert!(cookie.contains("; SameSite=Lax"));
        assert!(cookie.contains("; Path=/"));
        assert!(cookie.contains("; Max-Age=3600"));

        // The public view exposes coordinates but never the bearer token.
        assert_eq!(established.view.session_id, SessionId("sess_1".into()));
        assert_eq!(established.view.account_id, AccountId("acct_1".into()));
        let view_json = serde_json::to_string(&established.view).unwrap();
        assert!(!view_json.contains("token"));
    }

    #[test]
    fn current_session_resolves_from_cookie_then_logout_revokes() {
        let mut gateway = gateway();
        let established = gateway
            .establish_session(establish_request("sess_1", "2026-06-20T00:00:00Z"), None)
            .unwrap();

        // The cookie the browser would send back on the next request.
        let token = SessionCookieConfig::default()
            .extract_token(&established.set_cookie)
            .unwrap();
        let cookie_header = format!("other=1; {}={}", DEFAULT_SESSION_COOKIE_NAME, token);

        // GET /v1/session resolves the live session.
        let view = gateway
            .current_session_from_cookie(&cookie_header, Timestamp("2026-06-19T06:00:00Z".into()))
            .unwrap();
        assert_eq!(view.session_id, SessionId("sess_1".into()));
        assert_eq!(view.last_seen_at, Timestamp("2026-06-19T06:00:00Z".into()));

        // Logout revokes server-side and clears the browser cookie.
        let clear = gateway
            .logout(&token, Timestamp("2026-06-19T07:00:00Z".into()))
            .unwrap();
        assert!(clear.contains("; Max-Age=0"));
        assert!(clear.contains("; HttpOnly"));

        // After logout the session no longer authenticates.
        let err = gateway
            .current_session(&token, Timestamp("2026-06-19T08:00:00Z".into()))
            .unwrap_err();
        assert_eq!(
            err,
            IamError::SessionRevoked {
                id: SessionId("sess_1".into()),
            }
        );
    }

    #[test]
    fn expired_session_does_not_authenticate() {
        let mut gateway = gateway();
        let established = gateway
            .establish_session(establish_request("sess_1", "2026-06-20T00:00:00Z"), None)
            .unwrap();
        let token = SessionCookieConfig::default()
            .extract_token(&established.set_cookie)
            .unwrap();

        let err = gateway
            .current_session(&token, Timestamp("2026-06-21T00:00:00Z".into()))
            .unwrap_err();
        assert_eq!(
            err,
            IamError::SessionExpired {
                id: SessionId("sess_1".into()),
            }
        );
    }

    #[test]
    fn unknown_cookie_fails_closed() {
        let mut gateway = gateway();
        let err = gateway
            .current_session_from_cookie("unrelated=1", Timestamp("2026-06-19T00:00:00Z".into()))
            .unwrap_err();
        assert!(matches!(err, IamError::SessionNotFound { .. }));
    }

    #[test]
    fn samesite_none_requires_secure_pairing_in_render() {
        let cfg = SessionCookieConfig {
            same_site: SameSite::None,
            ..SessionCookieConfig::default()
        };
        let cookie = cfg.render_set_cookie("abc", None);
        assert!(cookie.contains("; SameSite=None"));
        assert!(cookie.contains("; Secure"));
    }
}
