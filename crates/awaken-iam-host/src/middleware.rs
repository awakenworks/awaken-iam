//! Axum bearer-auth middleware: authenticate → resolve principal → authorize.
//!
//! [`auth_layer`] wraps any axum router with an IAM-backed bearer-auth guard.
//! The guard is generic over [`RouteActions`], which maps each route's HTTP
//! method and path to an [`ActionKey`] so the middleware can authorize per-route
//! without knowing the product's action vocabulary.
//!
//! ## Flow (per request)
//!
//! 1. Extract `Authorization: Bearer <token>` from the request headers.
//! 2. In `Open` mode: skip all auth and call `next`.
//! 3. When the header is absent: `401 Unauthorized`.
//! 4. Authenticate via [`IamGate::authenticate_bearer`]:
//!    - `sk-awaken-`/`sk-ant-` prefix → API-token directory introspection.
//!    - Everything else → EdDSA JWT verification against JWKS.
//!    - On failure: `401 Unauthorized`.
//! 5. Look up the action for `(method, path)` via `actions.action_for`.
//!    When `None`, no action is required and the request passes through.
//! 6. Authorize `(principal, action, ScopeRef::Global)` via `gate.authorize`.
//!    `Deny` or `RequireApproval` → `403 Forbidden`.
//! 7. Insert the resolved [`PrincipalRef`] into the request extensions.
//! 8. Call `next`.

use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};

use axum::{
    extract::Request,
    http::{StatusCode, header::AUTHORIZATION},
    response::{IntoResponse, Response},
};
use tower::{Layer, Service};

use awaken_iam_client::IamClient;
use awaken_iam_contract::{ActionKey, AuthorizationDecision, ScopeRef, Timestamp};

use crate::gate::IamGate;

/// Return the current wall-clock instant as `(unix_secs_i64, Timestamp)`.
///
/// Both values are derived from a single `SystemTime::now()` call so the API-token
/// expiry check (RFC 3339 string comparison) and the JWT `exp` check (unix integer)
/// use a consistent instant.
fn wall_clock_now() -> (i64, Timestamp) {
    let secs = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    let ts = Timestamp(format_rfc3339(secs));
    (secs as i64, ts)
}

fn format_rfc3339(secs: u64) -> String {
    let days = (secs / 86_400) as i64;
    let time = secs % 86_400;
    let (hour, minute, second) = (time / 3600, (time % 3600) / 60, time % 60);
    let (year, month, day) = civil_from_days(days);
    format!("{year:04}-{month:02}-{day:02}T{hour:02}:{minute:02}:{second:02}Z")
}

fn civil_from_days(days: i64) -> (i64, u32, u32) {
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097) as u64;
    let yoe = (doe - doe / 1_460 + doe / 36_524 - doe / 146_096) / 365;
    let y = yoe as i64 + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = if m <= 2 { y + 1 } else { y };
    (y, m as u32, d as u32)
}

/// Map a route's HTTP method and path to an [`ActionKey`].
///
/// Implement this trait on a product-side struct that knows the route→action
/// vocabulary. Return `None` for routes that require no authorization check
/// (authentication still happens, just no grant lookup).
pub trait RouteActions: Send + Sync + 'static {
    /// Return the [`ActionKey`] required to access `(method, path)`, or `None`
    /// if no authorization check is needed for this route.
    fn action_for(&self, method: &axum::http::Method, path: &str) -> Option<ActionKey>;
}

/// Error variants surfaced by the auth middleware as HTTP responses.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum AuthError {
    /// No bearer token was presented.
    #[error("missing Authorization header")]
    MissingToken,
    /// The presented token did not authenticate.
    #[error("the credential does not authenticate")]
    InvalidToken,
    /// The principal is not authorized for the requested action.
    #[error("the principal does not hold a grant for this action")]
    Forbidden,
}

impl IntoResponse for AuthError {
    fn into_response(self) -> Response {
        let status = match self {
            AuthError::MissingToken | AuthError::InvalidToken => StatusCode::UNAUTHORIZED,
            AuthError::Forbidden => StatusCode::FORBIDDEN,
        };
        let body = serde_json::json!({
            "type": "https://iam.awakenworks.io/problems/auth-error",
            "title": self.to_string(),
            "status": status.as_u16(),
        });
        (status, axum::Json(body)).into_response()
    }
}

/// Build an axum [`Layer`] that enforces IAM bearer-auth on every request.
///
/// The returned layer is `Clone` and may be passed to `Router::layer`.
///
/// ```rust,ignore
/// let app = Router::new()
///     .route("/api/widgets", get(list_widgets))
///     .layer(auth_layer(gate, MyActions));
/// ```
pub fn auth_layer<A>(gate: IamGate, actions: A) -> IamAuthLayer<A>
where
    A: RouteActions + Clone,
{
    IamAuthLayer {
        state: Arc::new(AuthState { gate, actions }),
    }
}

/// Internal state shared across requests.
struct AuthState<A> {
    gate: IamGate,
    actions: A,
}

/// The axum-compatible [`Layer`] returned by [`auth_layer`].
pub struct IamAuthLayer<A> {
    state: Arc<AuthState<A>>,
}

impl<A> Clone for IamAuthLayer<A> {
    fn clone(&self) -> Self {
        Self {
            state: Arc::clone(&self.state),
        }
    }
}

impl<A, S> Layer<S> for IamAuthLayer<A>
where
    A: RouteActions + Clone,
    S: Clone,
{
    type Service = IamAuthService<A, S>;

    fn layer(&self, inner: S) -> Self::Service {
        IamAuthService {
            state: Arc::clone(&self.state),
            inner,
        }
    }
}

/// The tower [`Service`] that enforces auth for each request.
pub struct IamAuthService<A, S> {
    state: Arc<AuthState<A>>,
    inner: S,
}

impl<A, S> Clone for IamAuthService<A, S>
where
    S: Clone,
{
    fn clone(&self) -> Self {
        Self {
            state: Arc::clone(&self.state),
            inner: self.inner.clone(),
        }
    }
}

type BoxFuture<T> = Pin<Box<dyn Future<Output = T> + Send + 'static>>;

impl<A, S> Service<Request> for IamAuthService<A, S>
where
    A: RouteActions + Clone + 'static,
    S: Service<Request, Response = Response, Error = std::convert::Infallible>
        + Clone
        + Send
        + 'static,
    S::Future: Send + 'static,
{
    type Response = Response;
    type Error = std::convert::Infallible;
    type Future = BoxFuture<Result<Response, std::convert::Infallible>>;

    fn poll_ready(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.inner.poll_ready(cx)
    }

    fn call(&mut self, req: Request) -> Self::Future {
        let state = Arc::clone(&self.state);
        let mut inner = self.inner.clone();
        Box::pin(async move {
            if state.gate.is_open() {
                return inner.call(req).await;
            }

            let token = match extract_bearer(&req) {
                Some(t) => t,
                None => return Ok(AuthError::MissingToken.into_response()),
            };

            let (now_unix, now) = wall_clock_now();
            let principal = match state.gate.authenticate_bearer(&token, &now, now_unix) {
                Some(p) => p,
                None => return Ok(AuthError::InvalidToken.into_response()),
            };

            let method = req.method().clone();
            let path = req.uri().path().to_owned();
            if let Some(action) = state.actions.action_for(&method, &path) {
                let decision = state
                    .gate
                    .authorize(awaken_iam_contract::AuthorizationRequest {
                        principal: principal.clone(),
                        on_behalf_of: Vec::new(),
                        action,
                        scope: ScopeRef::Global,
                    });
                if decision != AuthorizationDecision::Allow {
                    return Ok(AuthError::Forbidden.into_response());
                }
            }

            let mut req = req;
            req.extensions_mut().insert(principal);
            inner.call(req).await
        })
    }
}

fn extract_bearer(req: &Request) -> Option<String> {
    let header = req.headers().get(AUTHORIZATION)?.to_str().ok()?;
    let token = header.strip_prefix("Bearer ")?;
    Some(token.to_owned())
}
