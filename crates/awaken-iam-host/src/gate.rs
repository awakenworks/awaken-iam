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
    EntitlementRequest, Jwks, PrincipalRef, Timestamp, TokenIntrospectionRequest, WorkspaceId,
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

/// Product-owned local IAM state: the authorization engine and the API-token
/// directory behind **one** lock.
///
/// Holding both under a single mutex lets a product's mint perform its paired
/// write — the token row into `directory` and the principal→role binding into
/// `authz`'s policy — without a concurrent `authenticate`/`authorize` observing
/// one write but not the other. [`IamGate::from_local_state`] wraps this into a
/// Local gate; the product keeps its own `Arc<Mutex<LocalIamState>>` to mint and
/// hydrate through the same lock.
pub struct LocalIamState {
    /// Authorization engine (policy evaluation).
    pub authz: AuthzApi,
    /// API-token authentication directory.
    pub directory: ApiTokenDirectory,
}

pub(crate) enum GateInner {
    /// No authentication or authorization; every request is allowed.
    Open,
    /// In-process IAM backed by a SQLite database.
    Local {
        /// Authorization engine + token directory behind one lock.
        state: Arc<Mutex<LocalIamState>>,
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

    pub(crate) fn local(state: Arc<Mutex<LocalIamState>>, jwks: Option<Jwks>) -> Self {
        Self {
            inner: Arc::new(GateInner::Local { state, jwks }),
            audience: None,
            issuer: None,
        }
    }

    /// Build a **Local**-mode gate around a product-owned [`LocalIamState`]
    /// (its [`AuthzApi`] + API-token [`ApiTokenDirectory`] behind one lock).
    ///
    /// Use this when the *product* owns its embed — its own bootstrap identity,
    /// its seeded role→action grants, and its schema migration — and wants only
    /// the gate + PEP over that state. [`embed_local`](crate::embed_local)
    /// instead assembles a fresh default embed (a fixed bootstrap identity and,
    /// by design, no product grants), which a product with its own tenancy model
    /// and grant catalog cannot reuse losslessly. The product keeps a clone of
    /// the `Arc` to mint and hydrate through the same lock the gate reads under,
    /// so its paired writes stay atomic to the gate. API-token authentication
    /// needs no JWKS; add EdDSA JWT verification with
    /// [`with_audience`](Self::with_audience) / [`with_issuer`](Self::with_issuer)
    /// if the product mints access tokens.
    pub fn from_local_state(state: Arc<Mutex<LocalIamState>>) -> Self {
        Self::local(state, None)
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
        self.authenticate_scoped(token, now, now_unix)
            .map(|(principal, _)| principal)
    }

    /// Authenticate a bearer credential, returning the principal **and** its
    /// workspace binding when the credential carries one.
    ///
    /// API tokens are minted at a workspace, so a resolved API token yields
    /// `Some(workspace)`; JWT access tokens are account-scoped and yield `None`.
    /// A product whose authorization scopes a workspace-less route at the
    /// *token's* home workspace needs this binding — [`authenticate_bearer`]
    /// drops it. Fail-closed like `authenticate_bearer`.
    pub fn authenticate_scoped(
        &self,
        token: &str,
        now: &Timestamp,
        now_unix: i64,
    ) -> Option<(PrincipalRef, Option<WorkspaceId>)> {
        match self.inner.as_ref() {
            GateInner::Open => None,
            GateInner::Local { state, jwks } => {
                if is_api_token(token) {
                    let guard = state.lock().expect("local state lock");
                    guard
                        .directory
                        .authenticate(token, now)
                        .ok()
                        .map(|t| (t.principal.clone(), Some(t.workspace.clone())))
                } else if let Some(jwks) = jwks {
                    self.verify_jwt(token, jwks, now_unix).map(|p| (p, None))
                } else {
                    None
                }
            }
            GateInner::Remote { client, jwks } => {
                if is_api_token(token) {
                    let req = TokenIntrospectionRequest {
                        token: token.to_owned(),
                    };
                    client
                        .introspect_token(&req)
                        .ok()
                        .map(|r| (r.principal, None))
                } else if let Some(jwks) = jwks {
                    self.verify_jwt(token, jwks, now_unix).map(|p| (p, None))
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
            GateInner::Local { state, .. } => {
                let guard = state.lock().expect("local state lock");
                guard.authz.authorize(&request).decision
            }
            GateInner::Remote { client, .. } => client.authorize(request),
        }
    }

    fn check_entitlement(&self, request: EntitlementRequest) -> EntitlementDecision {
        match self.inner.as_ref() {
            GateInner::Open => EntitlementDecision::Allow,
            GateInner::Local { state, .. } => {
                let guard = state.lock().expect("local state lock");
                guard.authz.check_entitlement(&request).decision
            }
            GateInner::Remote { client, .. } => client.check_entitlement(request),
        }
    }
}
