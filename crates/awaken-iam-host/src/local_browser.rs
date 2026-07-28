//! Shared local-browser bootstrap and session HTTP boundary.
//!
//! Products mount this router and attach [`LocalBrowserAuth::gate`] to their
//! existing authorization middleware. The setup secret is a one-time handoff,
//! while the resulting HttpOnly cookie authenticates through the same PDP as
//! API tokens and access tokens.

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};

use awaken_iam_contract::{AccountId, SessionId, SessionView, Timestamp};
use awaken_iam_core::OsEntropy;
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
    session_sequence: Arc<AtomicU64>,
}

impl LocalBrowserAuth {
    /// Start one five-minute setup window for a stable local account.
    pub fn begin(
        account_id: AccountId,
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
        let sessions = SessionGateway::with_entropy(
            OsEntropy,
            SessionCookieConfig {
                name: LOCAL_COOKIE_NAME.to_owned(),
                secure: false,
                same_site: SameSite::Strict,
                ..SessionCookieConfig::default()
            },
        );
        Ok((
            Self {
                setup_id,
                setup: Arc::new(Mutex::new(setup)),
                sessions: Arc::new(Mutex::new(sessions)),
                session_sequence: Arc::new(AtomicU64::new(1)),
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
    let sequence = auth.session_sequence.fetch_add(1, Ordering::Relaxed);
    let established = auth
        .setup
        .lock()
        .expect("local setup lock")
        .exchange(
            ExchangeLocalSetup {
                id: auth.setup_id.clone(),
                setup_token: request.setup_token,
                session_id: SessionId(format!("local-session-{now_secs}-{sequence}")),
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
        .map_err(|_| LocalBrowserAuthError::Unauthenticated)?;
    Ok(Json(SessionResponse { session }))
}

async fn logout(State(auth): State<LocalBrowserAuth>, headers: HeaderMap) -> Response {
    let (_, now) = wall_clock_now();
    let mut sessions = auth.sessions.lock().expect("browser session lock");
    let clear = headers
        .get(COOKIE)
        .and_then(|value| value.to_str().ok())
        .and_then(|header| sessions.cookie_config().extract_token(header))
        .and_then(|token| sessions.logout(&token, now).ok())
        .unwrap_or_else(|| sessions.cookie_config().render_clear_cookie());
    let mut response = StatusCode::NO_CONTENT.into_response();
    if let Ok(value) = HeaderValue::from_str(&clear) {
        response.headers_mut().insert(SET_COOKIE, value);
    }
    response
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
    fn from(_: LocalSetupError) -> Self {
        Self::Unauthenticated
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
    use axum::body::Body;
    use axum::http::Request;
    use tower::ServiceExt;

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
}
