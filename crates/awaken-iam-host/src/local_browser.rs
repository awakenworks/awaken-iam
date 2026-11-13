//! Shared local-browser bootstrap and session HTTP boundary.
//!
//! Products mount this router and attach [`LocalBrowserAuth::gate`] to their
//! existing authorization middleware. The setup secret is a one-time handoff,
//! while the resulting HttpOnly cookie authenticates through the same PDP as
//! API tokens and access tokens.

use std::fmt::Write as _;
use std::sync::{Arc, Mutex};

use awaken_iam_contract::{AccountId, SessionId, SessionView, Timestamp};
use awaken_iam_core::{EntropySource, OsEntropy, SessionRepository};
use awaken_iam_server::{
    BeginLocalSetup, ExchangeLocalSetup, LocalSetupError, LocalSetupGateway, LocalSetupId,
    RenewLocalSetup, SameSite, SessionCookieConfig, SessionGateway,
};
use axum::extract::State;
use axum::http::header::{COOKIE, HOST, ORIGIN, SET_COOKIE};
use axum::http::{HeaderMap, HeaderValue, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::{Json, Router};
use serde::{Deserialize, Serialize};

use crate::time::{timestamp_after, wall_clock_now};
use crate::{BrowserSessionAttachment, IamGate};

const SETUP_LIFETIME_SECS: u64 = 5 * 60;
const SESSION_LIFETIME_SECS: u64 = 30 * 24 * 60 * 60;
const LOCAL_COOKIE_NAME: &str = "awaken_local_session";

/// Cleartext value the CLI hands to the local operator exactly once.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LocalSetupHandoff {
    pub setup_token: String,
    pub expires_at: Timestamp,
}

/// Shared state behind the local-browser HTTP routes and IAM gate.
#[derive(Clone)]
pub struct LocalBrowserAuth {
    setup_id: LocalSetupId,
    setup: Arc<Mutex<LocalSetupGateway<OsEntropy>>>,
    sessions: Arc<Mutex<SessionGateway<OsEntropy>>>,
    session_ids: Arc<Mutex<OsEntropy>>,
}

impl LocalBrowserAuth {
    /// Rotate this authority's original challenge after product authorization.
    /// Existing sessions, gate attachment and account binding are unchanged.
    pub fn renew_handoff(&self) -> Result<LocalSetupHandoff, LocalBrowserAuthError> {
        let (now_secs, now) = wall_clock_now();
        let issued = self
            .setup
            .lock()
            .map_err(|_| LocalBrowserAuthError::Unavailable)?
            .renew(RenewLocalSetup {
                id: self.setup_id.clone(),
                created_at: now,
                expires_at: timestamp_after(now_secs, SETUP_LIFETIME_SECS),
            })?;
        Ok(LocalSetupHandoff {
            setup_token: issued.setup_token,
            expires_at: issued.expires_at,
        })
    }

    /// Start one five-minute setup window for a stable local account.
    pub fn begin(
        account_id: AccountId,
    ) -> Result<(Self, LocalSetupHandoff), LocalBrowserAuthError> {
        Self::begin_with_gateway(
            account_id,
            SessionGateway::with_entropy(OsEntropy, local_cookie_config()),
        )
    }

    /// Start a setup window whose resulting sessions use an existing repository.
    ///
    /// Persistent local products pass the same migrated IAM identity store they
    /// already own; no product-local session cache or hydration path is created.
    pub fn begin_with_session_repository(
        account_id: AccountId,
        repository: Arc<dyn SessionRepository>,
    ) -> Result<(Self, LocalSetupHandoff), LocalBrowserAuthError> {
        Self::begin_with_gateway(
            account_id,
            SessionGateway::with_repository(OsEntropy, local_cookie_config(), repository),
        )
    }

    fn begin_with_gateway(
        account_id: AccountId,
        sessions: SessionGateway<OsEntropy>,
    ) -> Result<(Self, LocalSetupHandoff), LocalBrowserAuthError> {
        let (now_secs, now) = wall_clock_now();
        let setup_id = LocalSetupId(format!("local-setup-{now_secs}"));
        let mut setup = LocalSetupGateway::new(OsEntropy);
        let issued = setup
            .begin(BeginLocalSetup {
                id: setup_id.clone(),
                account_id,
                created_at: now,
                expires_at: timestamp_after(now_secs, SETUP_LIFETIME_SECS),
            })
            .map_err(|_| LocalBrowserAuthError::Unavailable)?;
        Ok((
            Self {
                setup_id,
                setup: Arc::new(Mutex::new(setup)),
                sessions: Arc::new(Mutex::new(sessions)),
                session_ids: Arc::new(Mutex::new(OsEntropy)),
            },
            LocalSetupHandoff {
                setup_token: issued.setup_token,
                expires_at: issued.expires_at,
            },
        ))
    }

    /// Attach browser-cookie authentication to a product's existing IAM gate.
    pub fn gate(&self, gate: IamGate) -> Result<IamGate, LocalBrowserAuthError> {
        gate.with_browser_sessions(Arc::clone(&self.sessions))
    }

    /// Attach this authority to an already-shared product gate.
    pub fn attach_to(&self, gate: &IamGate) -> Result<(), LocalBrowserAuthError> {
        self.reserve_attachment(gate)?.publish();
        Ok(())
    }

    /// Reserve the gate's original slot before persisting a browser binding.
    ///
    /// On durable failure, drop this value without publication. On ACK,
    /// `publish` installs this same gateway without another fallible operation.
    /// A caller holding LocalIamState must acquire State before Attachment.
    pub fn reserve_attachment<'gate>(
        &self,
        gate: &'gate IamGate,
    ) -> Result<BrowserSessionAttachment<'gate>, LocalBrowserAuthError> {
        gate.reserve_browser_sessions(Arc::clone(&self.sessions))
    }
}

fn local_cookie_config() -> SessionCookieConfig {
    SessionCookieConfig {
        name: LOCAL_COOKIE_NAME.to_owned(),
        secure: false,
        same_site: SameSite::Strict,
        ..SessionCookieConfig::default()
    }
}

/// Build the common local-auth routes.
pub fn local_browser_router(auth: LocalBrowserAuth) -> Router {
    Router::new()
        .route("/v1/auth/local/exchange", post(exchange))
        .route("/v1/session", get(current_session).delete(logout))
        .with_state(auth)
}

#[derive(Debug, Deserialize)]
struct ExchangeRequest {
    setup_token: String,
}

#[derive(Debug, Serialize)]
struct SessionResponse {
    session: SessionView,
}

async fn exchange(
    State(auth): State<LocalBrowserAuth>,
    headers: HeaderMap,
    Json(request): Json<ExchangeRequest>,
) -> Result<Response, LocalBrowserAuthError> {
    require_same_origin(&headers)?;
    let (now_secs, now) = wall_clock_now();
    let mut session_ids = auth
        .session_ids
        .lock()
        .map_err(|_| LocalBrowserAuthError::Unavailable)?;
    let mut setup = auth
        .setup
        .lock()
        .map_err(|_| LocalBrowserAuthError::Unavailable)?;
    let mut sessions = auth
        .sessions
        .lock()
        .map_err(|_| LocalBrowserAuthError::Unavailable)?;
    let session_id = random_session_id(&mut *session_ids);
    let established = setup
        .exchange(
            ExchangeLocalSetup {
                id: auth.setup_id.clone(),
                setup_token: request.setup_token,
                session_id,
                now,
                session_expires_at: timestamp_after(now_secs, SESSION_LIFETIME_SECS),
                cookie_max_age_secs: Some(SESSION_LIFETIME_SECS),
            },
            &mut sessions,
        )
        .map_err(LocalBrowserAuthError::from)?;
    let mut response = Json(SessionResponse {
        session: established.view,
    })
    .into_response();
    response.headers_mut().insert(
        SET_COOKIE,
        HeaderValue::from_str(&established.set_cookie)
            .map_err(|_| LocalBrowserAuthError::Unavailable)?,
    );
    Ok(response)
}

fn random_session_id(entropy: &mut impl EntropySource) -> SessionId {
    let mut bytes = [0_u8; 32];
    entropy.fill_bytes(&mut bytes);
    let mut value = String::with_capacity("local-session-".len() + bytes.len() * 2);
    value.push_str("local-session-");
    for byte in bytes {
        write!(value, "{byte:02x}").expect("writing to a String cannot fail");
    }
    SessionId(value)
}

async fn current_session(
    State(auth): State<LocalBrowserAuth>,
    headers: HeaderMap,
) -> Result<Json<SessionResponse>, LocalBrowserAuthError> {
    let cookie = cookie_header(&headers)?;
    let (_, now) = wall_clock_now();
    let session = auth
        .sessions
        .lock()
        .map_err(|_| LocalBrowserAuthError::Unavailable)?
        .current_session_from_cookie(cookie, now)
        .map_err(|error| match error {
            awaken_iam_core::IamError::SessionStorageUnavailable => {
                LocalBrowserAuthError::Unavailable
            }
            _ => LocalBrowserAuthError::Unauthenticated,
        })?;
    Ok(Json(SessionResponse { session }))
}

async fn logout(
    State(auth): State<LocalBrowserAuth>,
    headers: HeaderMap,
) -> Result<Response, LocalBrowserAuthError> {
    let (_, now) = wall_clock_now();
    let mut sessions = auth
        .sessions
        .lock()
        .map_err(|_| LocalBrowserAuthError::Unavailable)?;
    let token = headers
        .get(COOKIE)
        .and_then(|value| value.to_str().ok())
        .and_then(|header| sessions.cookie_config().extract_token(header));
    let clear = if let Some(token) = token {
        match sessions.logout(&token, now) {
            Ok(clear) => clear,
            Err(awaken_iam_core::IamError::SessionStorageUnavailable) => {
                return Err(LocalBrowserAuthError::Unavailable);
            }
            Err(_) => sessions.cookie_config().render_clear_cookie(),
        }
    } else {
        sessions.cookie_config().render_clear_cookie()
    };
    let mut response = StatusCode::NO_CONTENT.into_response();
    if let Ok(value) = HeaderValue::from_str(&clear) {
        response.headers_mut().insert(SET_COOKIE, value);
    }
    Ok(response)
}

fn cookie_header(headers: &HeaderMap) -> Result<&str, LocalBrowserAuthError> {
    headers
        .get(COOKIE)
        .and_then(|value| value.to_str().ok())
        .ok_or(LocalBrowserAuthError::Unauthenticated)
}

/// A browser exchange must be same-origin when the browser supplies `Origin`.
/// Requests without `Origin` remain valid for same-host tools and tests.
pub fn require_same_origin(headers: &HeaderMap) -> Result<(), LocalBrowserAuthError> {
    let Some(origin) = headers.get(ORIGIN).and_then(|value| value.to_str().ok()) else {
        return Ok(());
    };
    let host = headers
        .get(HOST)
        .and_then(|value| value.to_str().ok())
        .ok_or(LocalBrowserAuthError::InvalidOrigin)?;
    let authority = origin
        .strip_prefix("http://")
        .or_else(|| origin.strip_prefix("https://"))
        .ok_or(LocalBrowserAuthError::InvalidOrigin)?;
    if authority.trim_end_matches('/') == host {
        Ok(())
    } else {
        Err(LocalBrowserAuthError::InvalidOrigin)
    }
}

/// Coarse HTTP errors that do not reveal setup-token state.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum LocalBrowserAuthError {
    #[error("local authentication failed")]
    Unauthenticated,
    #[error("request origin is not the local application")]
    InvalidOrigin,
    #[error("local authentication is unavailable")]
    Unavailable,
}

impl From<LocalSetupError> for LocalBrowserAuthError {
    fn from(error: LocalSetupError) -> Self {
        match error {
            LocalSetupError::SessionUnavailable => Self::Unavailable,
            LocalSetupError::InvalidChallenge
            | LocalSetupError::InvalidWindow
            | LocalSetupError::Session => Self::Unauthenticated,
        }
    }
}

impl IntoResponse for LocalBrowserAuthError {
    fn into_response(self) -> Response {
        let status = match self {
            Self::Unauthenticated => StatusCode::UNAUTHORIZED,
            Self::InvalidOrigin => StatusCode::FORBIDDEN,
            Self::Unavailable => StatusCode::SERVICE_UNAVAILABLE,
        };
        (
            status,
            Json(serde_json::json!({
                "type": "https://iam.awakenworks.io/problems/local-browser-auth",
                "title": self.to_string(),
                "status": status.as_u16(),
            })),
        )
            .into_response()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use awaken_iam_server::InMemoryStore;
    use axum::body::Body;
    use axum::http::Request;
    use tower::ServiceExt;

    #[derive(Default)]
    struct SequentialEntropy(u8);

    impl EntropySource for SequentialEntropy {
        fn fill_bytes(&mut self, bytes: &mut [u8]) {
            for byte in bytes {
                *byte = self.0;
                self.0 = self.0.wrapping_add(1);
            }
        }
    }

    fn exchange_request(token: &str, origin: &str) -> Request<Body> {
        Request::builder()
            .method("POST")
            .uri("/v1/auth/local/exchange")
            .header(HOST, "127.0.0.1:8080")
            .header(ORIGIN, origin)
            .header("content-type", "application/json")
            .body(Body::from(
                serde_json::json!({ "setup_token": token }).to_string(),
            ))
            .unwrap()
    }

    /// Persisted-id cause/effect: process-local counters may restart at the same
    /// wall-clock second, while consecutive entropy draws must still produce
    /// distinct opaque ids that disclose neither account nor storage location.
    #[test]
    fn local_session_ids_are_entropy_owned_and_distinct() {
        let mut entropy = SequentialEntropy::default();
        let first = random_session_id(&mut entropy);
        let second = random_session_id(&mut entropy);
        assert_ne!(first, second);
        assert!(first.0.starts_with("local-session-"));
        assert_eq!(first.0.len(), "local-session-".len() + 64);
    }

    // Cause/effect decision table:
    // fresh setup+same origin -> HttpOnly session+principal;
    // replay or foreign origin -> no session.
    #[tokio::test]
    async fn exchange_closes_the_cli_to_browser_authentication_loop_once() {
        let (auth, handoff) = LocalBrowserAuth::begin(AccountId("local-admin".into())).unwrap();
        let app = local_browser_router(auth.clone());
        let response = app
            .clone()
            .oneshot(exchange_request(
                &handoff.setup_token,
                "http://127.0.0.1:8080",
            ))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let set_cookie = response
            .headers()
            .get(SET_COOKIE)
            .unwrap()
            .to_str()
            .unwrap();
        assert!(set_cookie.contains("; HttpOnly"));
        assert!(set_cookie.contains("; SameSite=Strict"));
        assert!(!set_cookie.contains("; Secure"));

        let cookie = set_cookie.split(';').next().unwrap();
        let (_, now) = wall_clock_now();
        assert_eq!(
            auth.gate(IamGate::open())
                .unwrap()
                .authenticate_session_cookie(cookie, now)
                .unwrap(),
            awaken_iam_contract::PrincipalRef::Account {
                account_id: AccountId("local-admin".into())
            }
        );

        // R3 consumed setup + explicit host renewal -> same router accepts the
        // successor while the original cookie still resolves the same account.
        let next = auth.renew_handoff().unwrap();
        assert_ne!(next.setup_token, handoff.setup_token);
        assert_eq!(
            app.clone()
                .oneshot(exchange_request(&next.setup_token, "http://127.0.0.1:8080"))
                .await
                .unwrap()
                .status(),
            StatusCode::OK
        );
        assert_eq!(
            app.clone()
                .oneshot(
                    Request::get("/v1/session")
                        .header(COOKIE, cookie)
                        .body(Body::empty())
                        .unwrap()
                )
                .await
                .unwrap()
                .status(),
            StatusCode::OK
        );

        let replay = app
            .oneshot(exchange_request(
                &handoff.setup_token,
                "http://127.0.0.1:8080",
            ))
            .await
            .unwrap();
        assert_eq!(replay.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn foreign_origin_cannot_consume_the_setup_token() {
        let (auth, handoff) = LocalBrowserAuth::begin(AccountId("local-admin".into())).unwrap();
        let app = local_browser_router(auth);
        let response = app
            .oneshot(exchange_request(
                &handoff.setup_token,
                "http://attacker.invalid",
            ))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::FORBIDDEN);
    }

    /// Local-browser restart decision table:
    /// C1=one exchanged cookie, C2=same SessionRepository after authority rebuild,
    /// C3=persisted logout. R1(C1,C2,!C3) GETs the current session without the
    /// new setup token; R2(C1,C2,C3) rejects after another rebuild.
    #[tokio::test]
    async fn repository_backed_browser_cookie_survives_authority_restart() {
        let repository: Arc<dyn SessionRepository> = Arc::new(InMemoryStore::new());
        let (first, handoff) = LocalBrowserAuth::begin_with_session_repository(
            AccountId("local-admin".into()),
            repository.clone(),
        )
        .unwrap();
        let exchange = local_browser_router(first)
            .oneshot(exchange_request(
                &handoff.setup_token,
                "http://127.0.0.1:8080",
            ))
            .await
            .unwrap();
        let cookie = exchange.headers()[SET_COOKIE]
            .to_str()
            .unwrap()
            .split(';')
            .next()
            .unwrap()
            .to_owned();

        let (restarted, _) = LocalBrowserAuth::begin_with_session_repository(
            AccountId("local-admin".into()),
            repository.clone(),
        )
        .unwrap();
        let restarted_app = local_browser_router(restarted);
        let current = restarted_app
            .clone()
            .oneshot(
                Request::get("/v1/session")
                    .header(COOKIE, &cookie)
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(current.status(), StatusCode::OK);

        let logout = restarted_app
            .oneshot(
                Request::delete("/v1/session")
                    .header(COOKIE, &cookie)
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(logout.status(), StatusCode::NO_CONTENT);

        let (after_logout, _) = LocalBrowserAuth::begin_with_session_repository(
            AccountId("local-admin".into()),
            repository,
        )
        .unwrap();
        let rejected = local_browser_router(after_logout)
            .oneshot(
                Request::get("/v1/session")
                    .header(COOKIE, cookie)
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(rejected.status(), StatusCode::UNAUTHORIZED);
    }

    fn poison<T: Send + 'static>(state: Arc<Mutex<T>>) {
        assert!(
            std::thread::spawn(move || {
                let _guard = state.lock().unwrap();
                panic!("injected failure while an original browser authority is locked");
            })
            .join()
            .is_err()
        );
    }

    #[tokio::test]
    async fn exchange_refuses_any_poison_before_consuming_the_challenge() {
        // B1 entropy lock, B2 setup lock, B3 session lock poisoned ->503,
        // no cookie, and poison remains. Acquire ALL original guards before
        // drawing entropy/calling exchange: B3 must not consume the healthy
        // setup challenge before finding the poisoned session authority.
        // The final probe uses the SAME original setup kernel with a test-only
        // healthy Gateway, not a production recovery or a mirrored oracle.
        for poisoned in ["entropy", "setup", "sessions"] {
            let (auth, handoff) = LocalBrowserAuth::begin(AccountId("local-admin".into())).unwrap();
            match poisoned {
                "entropy" => poison(auth.session_ids.clone()),
                "setup" => poison(auth.setup.clone()),
                "sessions" => poison(auth.sessions.clone()),
                _ => unreachable!(),
            }
            let response = local_browser_router(auth.clone())
                .oneshot(exchange_request(
                    &handoff.setup_token,
                    "http://127.0.0.1:8080",
                ))
                .await
                .unwrap();
            assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
            assert!(response.headers().get(SET_COOKIE).is_none());
            assert_eq!(auth.session_ids.is_poisoned(), poisoned == "entropy");
            assert_eq!(auth.setup.is_poisoned(), poisoned == "setup");
            assert_eq!(auth.sessions.is_poisoned(), poisoned == "sessions");
            if poisoned != "setup" {
                let (seconds, now) = wall_clock_now();
                let mut healthy_sessions =
                    SessionGateway::with_entropy(OsEntropy, local_cookie_config());
                assert!(
                    auth.setup
                        .lock()
                        .unwrap()
                        .exchange(
                            ExchangeLocalSetup {
                                id: auth.setup_id.clone(),
                                setup_token: handoff.setup_token,
                                session_id: SessionId("unchanged-challenge-probe".into()),
                                now,
                                session_expires_at: timestamp_after(seconds, SESSION_LIFETIME_SECS),
                                cookie_max_age_secs: Some(SESSION_LIFETIME_SECS),
                            },
                            &mut healthy_sessions,
                        )
                        .is_ok()
                );
            }
        }
    }

    #[tokio::test]
    async fn poisoned_session_and_attachment_preserve_unavailability_without_clearing() {
        // B4 a real exchanged session then session poison -> current/logout503
        // and no clear-cookie; Gate auth is Unavailable, not Invalid. B5 a
        // poisoned attachment refuses both existing attachment APIs and cookie
        // auth. Healthy unknown-cookie denial remains Invalid/401 elsewhere.
        let (auth, handoff) = LocalBrowserAuth::begin(AccountId("local-admin".into())).unwrap();
        let gate = auth.gate(IamGate::open()).unwrap();
        let response = local_browser_router(auth.clone())
            .oneshot(exchange_request(
                &handoff.setup_token,
                "http://127.0.0.1:8080",
            ))
            .await
            .unwrap();
        let cookie = response.headers()[SET_COOKIE]
            .to_str()
            .unwrap()
            .split(';')
            .next()
            .unwrap()
            .to_owned();
        poison(auth.sessions.clone());
        let (_, now) = wall_clock_now();
        assert_eq!(
            gate.authenticate_session_cookie(&cookie, now),
            Err(crate::AuthReject::Unavailable)
        );
        for method in ["GET", "DELETE"] {
            let response = local_browser_router(auth.clone())
                .oneshot(
                    Request::builder()
                        .method(method)
                        .uri("/v1/session")
                        .header(COOKIE, &cookie)
                        .body(Body::empty())
                        .unwrap(),
                )
                .await
                .unwrap();
            assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
            assert!(response.headers().get(SET_COOKIE).is_none());
            assert!(auth.sessions.is_poisoned());
        }
        let gate = IamGate::open();
        poison(gate.browser_sessions.clone());
        assert_eq!(
            auth.attach_to(&gate),
            Err(LocalBrowserAuthError::Unavailable)
        );
        assert!(matches!(
            auth.reserve_attachment(&gate),
            Err(LocalBrowserAuthError::Unavailable)
        ));
        assert!(matches!(
            auth.gate(gate.clone()),
            Err(LocalBrowserAuthError::Unavailable)
        ));
        let (_, now) = wall_clock_now();
        assert_eq!(
            gate.authenticate_session_cookie(&cookie, now),
            Err(crate::AuthReject::Unavailable)
        );
        assert!(gate.browser_sessions.is_poisoned());
    }

    struct ReadFaultRepository {
        inner: InMemoryStore,
        fail_reads: std::sync::atomic::AtomicBool,
    }

    impl SessionRepository for ReadFaultRepository {
        fn get(
            &self,
            id: &SessionId,
        ) -> awaken_iam_core::RepositoryResult<Option<awaken_iam_contract::Session>> {
            SessionRepository::get(&self.inner, id)
        }
        fn get_by_token_hash(
            &self,
            hash: &str,
        ) -> awaken_iam_core::RepositoryResult<Option<awaken_iam_contract::Session>> {
            if self.fail_reads.load(std::sync::atomic::Ordering::SeqCst) {
                Err(awaken_iam_core::RepositoryError::Backend(
                    "injected repository outage".into(),
                ))
            } else {
                self.inner.get_by_token_hash(hash)
            }
        }
        fn create(
            &self,
            session: awaken_iam_contract::Session,
        ) -> awaken_iam_core::RepositoryResult<()> {
            SessionRepository::create(&self.inner, session)
        }
        fn update(
            &self,
            session: awaken_iam_contract::Session,
        ) -> awaken_iam_core::RepositoryResult<()> {
            SessionRepository::update(&self.inner, session)
        }
    }

    #[tokio::test]
    async fn repository_failure_is_not_an_invalid_cookie_or_successful_logout() {
        // B6 same real session/repository, healthy ->200; read outage -> Gate
        // Unavailable and GET/DELETE503 without Set-Cookie. Restored dependency
        // -> same cookie still200; ordinary logout then keeps the original401.
        // This fault adapter delegates all stored facts to the existing Memory
        // repository. It injects only a typed IO refusal, no session evaluator.
        let repository = Arc::new(ReadFaultRepository {
            inner: InMemoryStore::new(),
            fail_reads: std::sync::atomic::AtomicBool::new(false),
        });
        let (auth, handoff) = LocalBrowserAuth::begin_with_session_repository(
            AccountId("local-admin".into()),
            repository.clone(),
        )
        .unwrap();
        let gate = auth.gate(IamGate::open()).unwrap();
        let app = local_browser_router(auth);
        let exchanged = app
            .clone()
            .oneshot(exchange_request(
                &handoff.setup_token,
                "http://127.0.0.1:8080",
            ))
            .await
            .unwrap();
        let cookie = exchanged.headers()[SET_COOKIE]
            .to_str()
            .unwrap()
            .split(';')
            .next()
            .unwrap()
            .to_owned();
        repository
            .fail_reads
            .store(true, std::sync::atomic::Ordering::SeqCst);
        let (_, now) = wall_clock_now();
        assert_eq!(
            gate.authenticate_session_cookie(&cookie, now),
            Err(crate::AuthReject::Unavailable)
        );
        for method in ["GET", "DELETE"] {
            let response = app
                .clone()
                .oneshot(
                    Request::builder()
                        .method(method)
                        .uri("/v1/session")
                        .header(COOKIE, &cookie)
                        .body(Body::empty())
                        .unwrap(),
                )
                .await
                .unwrap();
            assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
            assert!(response.headers().get(SET_COOKIE).is_none());
        }
        repository
            .fail_reads
            .store(false, std::sync::atomic::Ordering::SeqCst);
        let (_, now) = wall_clock_now();
        assert!(gate.authenticate_session_cookie(&cookie, now).is_ok());
        let response = app
            .clone()
            .oneshot(
                Request::delete("/v1/session")
                    .header(COOKIE, &cookie)
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::NO_CONTENT);
        let (_, now) = wall_clock_now();
        assert_eq!(
            gate.authenticate_session_cookie(&cookie, now),
            Err(crate::AuthReject::Invalid)
        );
    }

    #[test]
    fn attachment_reservation_keeps_the_old_slot_until_explicit_publication() {
        // P1 actual slot reserved + durable refusal -> drop leaves old Arc.
        // P2 same reservation + durable ACK -> publish installs the fixed new
        // Arc with no IO/re-lock. try_lock proves this owns the ORIGINAL slot,
        // so concurrent replacement cannot enter the guarded DB interval.
        // Real SQL success/failure is owned by the Native publication tests;
        // this test proves only the Host resource/selection and drop law.
        let (old, _) = LocalBrowserAuth::begin(AccountId("old".into())).unwrap();
        let (next, _) = LocalBrowserAuth::begin(AccountId("next".into())).unwrap();
        let gate = old.gate(IamGate::open()).unwrap();
        let reserved = next.reserve_attachment(&gate).unwrap();
        assert!(matches!(
            gate.browser_sessions.try_lock(),
            Err(std::sync::TryLockError::WouldBlock)
        ));
        drop(reserved);
        {
            let slot = gate.browser_sessions.lock().unwrap();
            assert!(Arc::ptr_eq(slot.as_ref().unwrap(), &old.sessions));
        }
        next.reserve_attachment(&gate).unwrap().publish();
        let slot = gate.browser_sessions.lock().unwrap();
        assert!(Arc::ptr_eq(slot.as_ref().unwrap(), &next.sessions));
    }
}
