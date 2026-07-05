//! `IamGate`: combined authentication + authorization gate for all three modes.
//!
//! [`IamGate`] wraps either an in-process [`AuthzApi`] (local mode), a
//! [`RemoteIamClient`] delegating to the IAM daemon (remote mode), or a no-op
//! open mode for development. It implements [`IamClient`] for authorization
//! decisions and exposes [`IamGate::authenticate_bearer`] for credential
//! resolution so the middleware has one handle for both steps.

use std::sync::{Arc, Mutex};

use awaken_iam_client::{HttpAuthzTransport, IamClient, RemoteIamClient};
use awaken_iam_contract::{
    AccountId, AuthorizationDecision, AuthorizationRequest, EntitlementDecision,
    EntitlementRequest, Jwks, PrincipalRef, Timestamp, TokenIntrospectionRequest,
};
use awaken_iam_core::ApiTokenDirectory;
use awaken_iam_server::{AuthzApi, verify_access_token};

/// Combined authentication + authorization gate.
///
/// Cloneable via inner [`Arc`], so it is cheap to pass into axum middleware state
/// and to clone per-request. The three modes correspond to the three
/// [`HostMode`](crate::HostMode) values; `Open` is a no-auth bypass for dev/test,
/// `Local` routes to an in-process [`AuthzApi`], and `Remote` delegates to the
/// IAM daemon.
#[derive(Clone)]
pub struct IamGate {
    pub(crate) inner: Arc<GateInner>,
    /// Optional audience claim to validate on JWT tokens.
    pub(crate) audience: Option<String>,
    /// Optional issuer claim to validate on JWT tokens.
    pub(crate) issuer: Option<String>,
}

pub(crate) enum GateInner {
    /// No authentication or authorization; every request is allowed.
    Open,
    /// In-process IAM backed by a SQLite database.
    Local {
        /// Authorization engine (policy evaluation).
        authz: Arc<Mutex<AuthzApi>>,
        /// API-token authentication directory (separate from AuthzApi's internal one).
        directory: Arc<Mutex<ApiTokenDirectory>>,
        /// JWKS for EdDSA JWT verification (present when a seal key is configured).
        jwks: Option<Jwks>,
    },
    /// Remote IAM daemon: authorization delegated over HTTP.
    Remote {
        client: RemoteIamClient<HttpAuthzTransport>,
        /// JWKS fetched from the remote daemon for local JWT pre-verification.
        jwks: Option<Jwks>,
    },
}

impl IamGate {
    /// Open mode: no authentication, all requests allowed.
    pub fn open() -> Self {
        Self {
            inner: Arc::new(GateInner::Open),
            audience: None,
            issuer: None,
        }
    }

    pub(crate) fn local(
        authz: Arc<Mutex<AuthzApi>>,
        directory: Arc<Mutex<ApiTokenDirectory>>,
        jwks: Option<Jwks>,
    ) -> Self {
        Self {
            inner: Arc::new(GateInner::Local {
                authz,
                directory,
                jwks,
            }),
            audience: None,
            issuer: None,
        }
    }

    pub(crate) fn remote(client: RemoteIamClient<HttpAuthzTransport>, jwks: Option<Jwks>) -> Self {
        Self {
            inner: Arc::new(GateInner::Remote { client, jwks }),
            audience: None,
            issuer: None,
        }
    }

    /// Set the JWT audience claim to validate.
    pub fn with_audience(mut self, audience: impl Into<String>) -> Self {
        self.audience = Some(audience.into());
        self
    }

    /// Set the JWT issuer claim to validate.
    pub fn with_issuer(mut self, issuer: impl Into<String>) -> Self {
        self.issuer = Some(issuer.into());
        self
    }

    pub(crate) fn with_audience_opt(mut self, audience: Option<String>) -> Self {
        self.audience = audience;
        self
    }

    pub(crate) fn with_issuer_opt(mut self, issuer: Option<String>) -> Self {
        self.issuer = issuer;
        self
    }

    /// Authenticate a bearer credential, returning the principal on success.
    ///
    /// Dispatches by prefix:
    /// - `sk-awaken-` / `sk-ant-` → API token directory introspection.
    /// - Everything else is attempted as an EdDSA JWT against the configured JWKS.
    ///
    /// Returns `None` when the token does not authenticate for any reason
    /// (fail-closed). In `Open` mode this always returns `None`; callers should
    /// check [`is_open`](Self::is_open) first.
    pub fn authenticate_bearer(
        &self,
        token: &str,
        now: &Timestamp,
        now_unix: i64,
    ) -> Option<PrincipalRef> {
        match self.inner.as_ref() {
            GateInner::Open => None,
            GateInner::Local {
                directory, jwks, ..
            } => {
                if is_api_token(token) {
                    let dir = directory.lock().expect("directory lock");
                    dir.authenticate(token, now)
                        .ok()
                        .map(|t| t.principal.clone())
                } else if let Some(jwks) = jwks {
                    self.verify_jwt(token, jwks, now_unix)
                } else {
                    None
                }
            }
            GateInner::Remote { client, jwks } => {
                if is_api_token(token) {
                    let req = TokenIntrospectionRequest {
                        token: token.to_owned(),
                    };
                    client.introspect_token(&req).ok().map(|r| r.principal)
                } else if let Some(jwks) = jwks {
                    self.verify_jwt(token, jwks, now_unix)
                } else {
                    None
                }
            }
        }
    }

    fn verify_jwt(&self, token: &str, jwks: &Jwks, now_unix: i64) -> Option<PrincipalRef> {
        let claims = verify_access_token(token, jwks).ok()?;

        if claims.exp <= now_unix {
            return None;
        }
        if let Some(ref expected_iss) = self.issuer
            && &claims.iss != expected_iss
        {
            return None;
        }
        if let Some(ref expected_aud) = self.audience
            && &claims.aud != expected_aud
        {
            return None;
        }
        Some(PrincipalRef::Account {
            account_id: AccountId(claims.sub),
        })
    }

    /// Returns `true` when the gate is in open (no-auth) mode.
    pub fn is_open(&self) -> bool {
        matches!(self.inner.as_ref(), GateInner::Open)
    }
}

fn is_api_token(token: &str) -> bool {
    token.starts_with("sk-awaken-") || token.starts_with("sk-ant-")
}

impl IamClient for IamGate {
    fn authorize(&self, request: AuthorizationRequest) -> AuthorizationDecision {
        match self.inner.as_ref() {
            GateInner::Open => AuthorizationDecision::Allow,
            GateInner::Local { authz, .. } => {
                let guard = authz.lock().expect("authz lock");
                guard.authorize(&request).decision
            }
            GateInner::Remote { client, .. } => client.authorize(request),
        }
    }

    fn check_entitlement(&self, request: EntitlementRequest) -> EntitlementDecision {
        match self.inner.as_ref() {
            GateInner::Open => EntitlementDecision::Allow,
            GateInner::Local { authz, .. } => {
                let guard = authz.lock().expect("authz lock");
                guard.check_entitlement(&request).decision
            }
            GateInner::Remote { client, .. } => client.check_entitlement(request),
        }
    }
}
