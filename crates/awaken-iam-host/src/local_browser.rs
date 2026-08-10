//! Shared local-browser bootstrap and session HTTP boundary.
//!
//! Products mount this router and attach [`LocalBrowserAuth::gate`] to their
//! existing authorization middleware. The setup secret is a one-time handoff,
//! while the resulting HttpOnly cookie authenticates through the same PDP as
//! API tokens and access tokens.

use std::fmt::Write as _;
use std::sync::{Arc, Mutex};

use awaken_iam_contract::{AccountId, SessionId, SessionView, Timestamp};
use awaken_iam_core::{EntropySource, OsEntropy, SessionRepo};
use awaken_iam_server::{
    BeginLocalSetup, ExchangeLocalSetup, LocalSetupError, LocalSetupGateway, LocalSetupId,
    SameSite, SessionCookieConfig, SessionGateway,
};
use axum::extract::State;
use axum::http::header::{COOKIE, HOST, ORIGIN, SET_COOKIE};
use axum::http::{HeaderMap, HeaderValue, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::{Json, Router};
use serde::{Deserialize, Serialize};

use crate::IamGate;
use crate::time::{timestamp_after, wall_clock_now};

const SETUP_LIFETIME_SECS: u64 = 5 * 60;
const SESSION_LIFETIME_SECS: u64 = 30 * 24 * 60 * 60;
const LOCAL_COOKIE_NAME: &str = "awaken_local_session";

/// Cleartext value the CLI hands to the local operator exactly once.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
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
        repository: Arc<dyn SessionRepo>,
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
    pub fn gate(&self, gate: IamGate) -> IamGate {
        gate.with_browser_sessions(Arc::clone(&self.sessions))
    }

    /// Attach this authority to an already-shared product gate.
    pub fn attach_to(&self, gate: &IamGate) {
        gate.attach_browser_sessions(Arc::clone(&self.sessions));
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
    let session_id = random_session_id(&mut *auth.session_ids.lock().expect("session id lock"));
    let established = auth
        .setup
        .lock()
        .expect("local setup lock")
        .exchange(
            ExchangeLocalSetup {
                id: auth.setup_id.clone(),
                setup_token: request.setup_token,
                session_id,
                now,
                session_expires_at: timestamp_after(now_secs, SESSION_LIFETIME_SECS),
                cookie_max_age_secs: Some(SESSION_LIFETIME_SECS),
            },
            &mut auth.sessions.lock().expect("browser session lock"),
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
        .expect("browser session lock")
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
    let mut sessions = auth.sessions.lock().expect("browser session lock");
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
fn require_same_origin(headers: &HeaderMap) -> Result<(), LocalBrowserAuthError> {
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
                .authenticate_session_cookie(cookie, now)
                .unwrap(),
            awaken_iam_contract::PrincipalRef::Account {
                account_id: AccountId("local-admin".into())
            }
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
    /// C1=one exchanged cookie, C2=same SessionRepo after authority rebuild,
    /// C3=persisted logout. R1(C1,C2,!C3) GETs the current session without the
    /// new setup token; R2(C1,C2,C3) rejects after another rebuild.
    #[tokio::test]
    async fn repository_backed_browser_cookie_survives_authority_restart() {
        let repository: Arc<dyn SessionRepo> = Arc::new(InMemoryStore::new());
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
}
