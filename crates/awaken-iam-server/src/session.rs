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

use std::sync::Arc;

use awaken_iam_contract::{Session, SessionId, SessionView, Timestamp};
use awaken_iam_core::{
    EntropySource, EstablishSession, IamError, OsEntropy, RepoError, SessionMinter, SessionRepo,
    hash_session_token,
};

use crate::store::InMemoryStore;

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
pub struct SessionGateway<E: EntropySource = OsEntropy> {
    repository: Arc<dyn SessionRepo>,
    minter: SessionMinter<E>,
    cookie: SessionCookieConfig,
}

impl<E: EntropySource> std::fmt::Debug for SessionGateway<E> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SessionGateway")
            .field("repository", &"SessionRepo")
            .field("cookie", &self.cookie)
            .finish_non_exhaustive()
    }
}

impl SessionGateway<OsEntropy> {
    /// Build a gateway over the OS entropy source and default cookie attributes.
    pub fn new() -> Self {
        Self::with_entropy(OsEntropy, SessionCookieConfig::default())
    }
}

impl Default for SessionGateway<OsEntropy> {
    fn default() -> Self {
        Self::new()
    }
}

impl<E: EntropySource> SessionGateway<E> {
    /// Build a gateway over a custom entropy source and cookie configuration.
    pub fn with_entropy(entropy: E, cookie: SessionCookieConfig) -> Self {
        Self::with_repository(entropy, cookie, Arc::new(InMemoryStore::new()))
    }

    /// Build a gateway over one caller-selected authoritative session repository.
    pub fn with_repository(
        entropy: E,
        cookie: SessionCookieConfig,
        repository: Arc<dyn SessionRepo>,
    ) -> Self {
        Self {
            repository,
            minter: SessionMinter::new(entropy),
            cookie,
        }
    }

    /// The cookie configuration applied by this gateway.
    pub fn cookie_config(&self) -> &SessionCookieConfig {
        &self.cookie
    }

    /// Clone the authoritative repository handle for composition builders that
    /// replace cookie policy without changing storage ownership.
    pub(crate) fn repository(&self) -> Arc<dyn SessionRepo> {
        Arc::clone(&self.repository)
    }

    /// Establish a session after a successful login and build its session
    /// cookie. `cookie_max_age_secs` optionally bounds the browser cookie; the
    /// server-side session expiry is carried by `request.expires_at`.
    pub fn establish_session(
        &mut self,
        request: EstablishSession,
        cookie_max_age_secs: Option<u64>,
    ) -> Result<EstablishedSession, IamError> {
        let session_id = request.id.clone();
        let issued = self.minter.issue(request)?;
        self.repository
            .create(issued.session.clone())
            .map_err(|error| repository_error(error, session_id))?;
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
        let mut session = self
            .repository
            .get_by_token_hash(&token_hash)
            .map_err(|_| IamError::SessionStorageUnavailable)?
            .ok_or_else(unknown_session)?;
        authenticate(&session, &now)?;
        session.last_seen_at = now;
        self.repository
            .update(session.clone())
            .map_err(|_| IamError::SessionStorageUnavailable)?;
        Ok(SessionView::from(&session))
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
        let mut session = self
            .repository
            .get_by_token_hash(&token_hash)
            .map_err(|_| IamError::SessionStorageUnavailable)?
            .ok_or_else(unknown_session)?;
        session.revoked_at.get_or_insert(now);
        self.repository
            .update(session)
            .map_err(|_| IamError::SessionStorageUnavailable)?;
        Ok(self.cookie.render_clear_cookie())
    }

    /// Resolve the server-side id for audit without exposing repository access.
    pub fn session_id_for_token(&self, token: &str) -> Result<Option<SessionId>, IamError> {
        self.repository
            .get_by_token_hash(&hash_session_token(token))
            .map(|session| session.map(|value| value.id))
            .map_err(|_| IamError::SessionStorageUnavailable)
    }
}

fn authenticate(session: &Session, now: &Timestamp) -> Result<(), IamError> {
    if session.revoked_at.is_some() {
        return Err(IamError::SessionRevoked {
            id: session.id.clone(),
        });
    }
    if now.0 >= session.expires_at.0 {
        return Err(IamError::SessionExpired {
            id: session.id.clone(),
        });
    }
    Ok(())
}

fn unknown_session() -> IamError {
    IamError::SessionNotFound {
        id: SessionId(String::new()),
    }
}

fn repository_error(error: RepoError, id: SessionId) -> IamError {
    match error {
        RepoError::Conflict(_) => IamError::DuplicateSession { id },
        RepoError::NotFound(_) | RepoError::Backend(_) => IamError::SessionStorageUnavailable,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use awaken_iam_contract::{AccountId, ExternalIdentityId};

    struct UnavailableSessionRepo;

    impl SessionRepo for UnavailableSessionRepo {
        fn get(&self, _: &SessionId) -> awaken_iam_core::RepoResult<Option<Session>> {
            Err(RepoError::Backend("unavailable".into()))
        }

        fn get_by_token_hash(&self, _: &str) -> awaken_iam_core::RepoResult<Option<Session>> {
            Err(RepoError::Backend("unavailable".into()))
        }

        fn create(&self, _: Session) -> awaken_iam_core::RepoResult<()> {
            Err(RepoError::Backend("unavailable".into()))
        }

        fn update(&self, _: Session) -> awaken_iam_core::RepoResult<()> {
            Err(RepoError::Backend("unavailable".into()))
        }
    }

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

    /// Repository-backed session cause/effect design:
    /// C1=session is live, C2=Gateway is reconstructed over the same repository,
    /// C3=logout is persisted. R1(C1,C2,!C3) authenticates and refreshes activity;
    /// R2(C1,C2,C3) rejects after another reconstruction. This is the restart
    /// durability and non-resurrection rule without a second hydration cache.
    #[test]
    fn repository_backed_session_survives_reconstruction_and_logout_does_not() {
        let repository = Arc::new(InMemoryStore::new());
        let mut first = SessionGateway::with_repository(
            SequentialEntropy::default(),
            SessionCookieConfig::default(),
            repository.clone(),
        );
        let established = first
            .establish_session(establish_request("sess_1", "2026-06-20T00:00:00Z"), None)
            .unwrap();
        let token = first
            .cookie_config()
            .extract_token(&established.set_cookie)
            .unwrap();
        drop(first);

        let mut restarted = SessionGateway::with_repository(
            SequentialEntropy::default(),
            SessionCookieConfig::default(),
            repository.clone(),
        );
        let live = restarted
            .current_session(&token, Timestamp("2026-06-19T06:00:00Z".into()))
            .unwrap();
        assert_eq!(live.session_id, SessionId("sess_1".into()));
        assert_eq!(live.last_seen_at, Timestamp("2026-06-19T06:00:00Z".into()));
        restarted
            .logout(&token, Timestamp("2026-06-19T07:00:00Z".into()))
            .unwrap();
        drop(restarted);

        let mut after_logout = SessionGateway::with_repository(
            SequentialEntropy::default(),
            SessionCookieConfig::default(),
            repository,
        );
        assert_eq!(
            after_logout
                .current_session(&token, Timestamp("2026-06-19T08:00:00Z".into()))
                .unwrap_err(),
            IamError::SessionRevoked {
                id: SessionId("sess_1".into()),
            }
        );
    }

    /// Repository-failure decision rows: create/read/revoke backend failures all
    /// collapse to one opaque storage-unavailable error; no cookie or principal
    /// is accepted and no backend detail crosses the session boundary.
    #[test]
    fn repository_failure_fails_every_session_transition_closed() {
        let repository: Arc<dyn SessionRepo> = Arc::new(UnavailableSessionRepo);
        let mut gateway = SessionGateway::with_repository(
            SequentialEntropy::default(),
            SessionCookieConfig::default(),
            repository,
        );
        assert_eq!(
            gateway
                .establish_session(establish_request("sess_1", "2026-06-20T00:00:00Z"), None)
                .unwrap_err(),
            IamError::SessionStorageUnavailable
        );
        assert_eq!(
            gateway
                .current_session("opaque", Timestamp("2026-06-19T06:00:00Z".into()))
                .unwrap_err(),
            IamError::SessionStorageUnavailable
        );
        assert_eq!(
            gateway
                .logout("opaque", Timestamp("2026-06-19T07:00:00Z".into()))
                .unwrap_err(),
            IamError::SessionStorageUnavailable
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
