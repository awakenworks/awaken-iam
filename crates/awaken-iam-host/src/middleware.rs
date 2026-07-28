//! Axum bearer-auth middleware: authenticate → resolve principal → authorize.
//!
//! [`auth_layer`] wraps any axum router with an IAM-backed bearer-auth guard.
//! The guard is generic over [`RouteActions`], which maps each route's HTTP
//! method and path to an [`ActionKey`] so the middleware can authorize per-route
//! without knowing the product's action vocabulary.
//!
//! ## Flow (per request)
//!
//! 1. Extract `Authorization: Bearer <token>` or the configured browser cookie.
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
    http::StatusCode,
    response::{IntoResponse, Response},
};
use tower::{Layer, Service};

use awaken_iam_client::IamClient;
use awaken_iam_contract::{ActionKey, AuthorizationDecision, ScopeRef};

use crate::gate::IamGate;
use crate::time::wall_clock_now;

/// Map a route's HTTP method and path to an [`ActionKey`].
///
/// Implement this trait on a product-side struct that knows the route→action
/// vocabulary. Return `None` for routes that require no authorization check
/// (authentication still happens, just no grant lookup).
pub trait RouteActions: Send + Sync + 'static {
    /// Return the [`ActionKey`] required to access `(method, path)`, or `None`
    /// if no authorization check is needed for this route.
    fn action_for(&self, method: &axum::http::Method, path: &str) -> Option<ActionKey>;

    /// Derive the authorization **scope** for this request.
    ///
    /// The default returns [`ScopeRef::Global`], preserving the pre-scope
    /// behavior where every mapped action is authorized platform-wide. Override
    /// it to authorize **per-tenant**: return e.g. `ScopeRef::Workspace { .. }`
    /// parsed from the path or query, so a principal whose `RoleBinding` is
    /// confined to one workspace is *denied* on another — the middleware feeds
    /// this scope straight into `gate.authorize`, so the returned value is the
    /// scope the grant lookup runs at.
    ///
    /// `extensions` carries the request's typed extensions, letting a product's
    /// own *preceding* layer inject an already-computed scope (e.g. a workspace
    /// parsed out of the request body, which this trait deliberately never
    /// reads) for this method to read back — keeping the middleware body-agnostic
    /// while still supporting body-carried tenancy.
    fn scope_for(
        &self,
        _method: &axum::http::Method,
        _uri: &axum::http::Uri,
        _extensions: &axum::http::Extensions,
    ) -> ScopeRef {
        ScopeRef::Global
    }

    /// Extract the bearer credential from the request headers, or `None` to
    /// answer `401`.
    ///
    /// The default reads `Authorization: Bearer <token>`. Override to accept a
    /// product-specific carrier as well (e.g. the `x-api-key` header the
    /// Anthropic SDK sends), returning the raw token string.
    fn extract_credential(&self, headers: &axum::http::HeaderMap) -> Option<String> {
        let header = headers
            .get(axum::http::header::AUTHORIZATION)?
            .to_str()
            .ok()?;
        header.strip_prefix("Bearer ").map(|token| token.to_owned())
    }

    /// Render an [`AuthError`] into the response the client sees.
    ///
    /// The default is host's problem+json shape. Override to answer in the
    /// product's own error envelope (keep 401 for missing/invalid credentials
    /// and 403 for a denied action, per [`AuthError`]'s status mapping).
    fn render_auth_error(&self, error: &AuthError) -> Response {
        error.clone().into_response()
    }
}

/// The authenticated API token's home workspace, inserted into the request
/// extensions by the auth middleware after authentication so
/// [`RouteActions::scope_for`] and downstream handlers can read it. Absent for
/// JWT (account-scoped) credentials.
#[derive(Debug, Clone)]
pub struct TokenWorkspace(pub awaken_iam_contract::WorkspaceId);

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

            let (now_unix, now) = wall_clock_now();
            let authenticated = if let Some(token) = state.actions.extract_credential(req.headers())
            {
                state
                    .gate
                    .authenticate_scoped(&token, &now, now_unix as i64)
            } else if let Some(cookie) = req
                .headers()
                .get(axum::http::header::COOKIE)
                .and_then(|value| value.to_str().ok())
            {
                state
                    .gate
                    .authenticate_session_cookie(cookie, now.clone())
                    .ok()
                    .map(|principal| (principal, None))
            } else {
                return Ok(state.actions.render_auth_error(&AuthError::MissingToken));
            };
            let (principal, token_workspace) = match authenticated {
                Some(pair) => pair,
                None => return Ok(state.actions.render_auth_error(&AuthError::InvalidToken)),
            };

            // Stash the resolved identity BEFORE scope derivation so `scope_for`
            // (and downstream handlers) can read it: the principal, and — for API
            // tokens — the token's home workspace, which a product uses to scope
            // a workspace-less route at the token's own workspace.
            let mut req = req;
            req.extensions_mut().insert(principal.clone());
            if let Some(workspace) = token_workspace {
                req.extensions_mut().insert(TokenWorkspace(workspace));
            }

            let method = req.method().clone();
            let path = req.uri().path().to_owned();
            if let Some(action) = state.actions.action_for(&method, &path) {
                // Per-request scope: `RouteActions::scope_for` derives it from the
                // request (path/query/extensions); the default is `Global`, so
                // consumers that do not override it keep the pre-scope behavior.
                let scope = state
                    .actions
                    .scope_for(&method, req.uri(), req.extensions());
                let decision = state
                    .gate
                    .authorize(awaken_iam_contract::AuthorizationRequest {
                        principal: principal.clone(),
                        on_behalf_of: Vec::new(),
                        action,
                        scope,
                    });
                if decision != AuthorizationDecision::Allow {
                    return Ok(state.actions.render_auth_error(&AuthError::Forbidden));
                }
            }

            inner.call(req).await
        })
    }
}
