//! `IamGate`: combined authentication + authorization gate for all three modes.
//!
//! [`IamGate`] wraps either an in-process [`AuthzApi`] (local mode), a
//! [`RemoteIamClient`] delegating to the IAM daemon (remote mode), or a no-op
//! open mode for development. It implements [`IamClient`] for authorization
//! decisions and exposes [`IamGate::authenticate_bearer`] for credential
//! resolution so the middleware has one handle for both steps.
//! Decision Result methods preserve local poison or remote unavailability;
//! legacy infallible decision methods project those failures to Deny.

use std::sync::{Arc, Mutex, MutexGuard};

use awaken_iam_client::{
    HttpAuthzTransport, IamClient, IamDecisionError, RemoteError, RemoteIamClient,
};
use awaken_iam_contract::{
    ActionKey, AuthorizationDecision, AuthorizationOutcome, AuthorizationRequest,
    EntitlementDecision, EntitlementRequest, Jwks, PrincipalRef, ResourceAuthorizationRequest,
    ScopeRef, Timestamp, TokenIntrospectionRequest, TokenIntrospectionResponse, WorkspaceId,
};
use awaken_iam_core::{ApiTokenDirectory, IamError, OsEntropy};
use awaken_iam_server::{
    AccessTokenClaims, AuthzApi, SessionGateway, verify_delegated_access_token,
};

use crate::local_browser::LocalBrowserAuthError;
mod current_account;
mod scoped;

type SharedBrowserSessions = Arc<Mutex<SessionGateway<OsEntropy>>>;
type BrowserSessionAttachmentSlot = Arc<Mutex<Option<SharedBrowserSessions>>>;

/// A short-lived reservation of the gate's existing browser attachment slot.
///
/// Hold this guard while the caller commits its original durable binding. The
/// selected gateway is fixed at reservation; dropping without publication
/// preserves the old attachment. No database, policy, or additional lock is
/// owned by this value. Callers also holding local IAM state acquire that state
/// guard before reserving this attachment and never reenter the gate's PDP.
pub struct BrowserSessionAttachment<'gate> {
    slot: MutexGuard<'gate, Option<SharedBrowserSessions>>,
    sessions: SharedBrowserSessions,
}

impl BrowserSessionAttachment<'_> {
    /// Publish the already-selected gateway after the durable operation ACK.
    /// This performs no IO, policy evaluation, or second lock acquisition.
    pub fn publish(mut self) {
        *self.slot = Some(self.sessions);
    }
}

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
    /// Browser sessions are opt-in and share the same authorization path as
    /// bearer credentials. Local hosts attach the canonical session gateway.
    pub(crate) browser_sessions: BrowserSessionAttachmentSlot,
}

/// Why a credential failed to authenticate, or could not be evaluated.
///
/// Returned by [`IamGate::authenticate_detailed`] so a product can answer the
/// distinct rejection reasons or service unavailability instead of one opaque
/// credential failure.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AuthReject {
    /// The credential is past its expiry.
    Expired,
    /// The credential was revoked.
    Revoked,
    /// The credential does not exist, does not verify, or is malformed.
    Invalid,
    /// The authority cannot currently verify this credential.
    Unavailable,
}

/// Every coordinate of a successfully authenticated bearer credential.
///
/// Returned by [`IamGate::authenticate_verified`] and [`IamGate::verify_jwt`].
/// Older accessors ([`IamGate::authenticate_bearer`],
/// [`IamGate::authenticate_scoped`], [`IamGate::authenticate_detailed`]) are
/// projections of this value and keep their shapes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifiedBearer {
    /// The authenticated subject. For a delegated token this is the end-user.
    pub principal: PrincipalRef,
    /// Home workspace of an API token; `None` for JWT access tokens.
    pub workspace: Option<WorkspaceId>,
    /// RFC 8693 `act`: the service acting on behalf of `principal`, if any.
    pub actor: Option<PrincipalRef>,
    /// Verified access-token claims (audience, scope, `jti`, expiry); `None`
    /// for API tokens, which carry no JWT claims.
    pub access_token: Option<AccessTokenClaims>,
}

impl VerifiedBearer {
    fn api_token(principal: PrincipalRef, workspace: WorkspaceId) -> Self {
        Self {
            principal,
            workspace: Some(workspace),
            actor: None,
            access_token: None,
        }
    }

    /// Build the authorization request for this credential.
    ///
    /// A direct credential authorizes its principal alone. A delegated
    /// credential authorizes the acting service with the end-user as its
    /// conjunctive `on_behalf_of` link, so the effective permission is the
    /// intersection of what both principals hold.
    pub fn authorization_request(
        &self,
        action: ActionKey,
        scope: ScopeRef,
    ) -> AuthorizationRequest {
        match &self.actor {
            Some(actor) => AuthorizationRequest {
                principal: actor.clone(),
                on_behalf_of: vec![self.principal.clone()],
                action,
                scope,
            },
            None => AuthorizationRequest::direct(self.principal.clone(), action, scope),
        }
    }
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
    /// Opt-in verification for an owner that additionally fences its exact
    /// route and invokes live consent authorization. Generic bearer verification
    /// deliberately continues rejecting this family, including in Local mode.
    pub fn authenticate_personal_delegation(
        &self,
        token: &str,
        now: i64,
    ) -> Result<awaken_iam_contract::PersonalDelegationTokenClaims, AuthReject> {
        let GateInner::Remote {
            jwks: Some(jwks), ..
        } = self.inner.as_ref()
        else {
            return Err(AuthReject::Invalid);
        };
        let issuer = self.issuer.as_deref().ok_or(AuthReject::Invalid)?;
        let audience = self.audience.as_deref().ok_or(AuthReject::Invalid)?;
        awaken_iam_server::verify_personal_delegation_token(token, jwks, issuer, audience, now)
            .map_err(|_| AuthReject::Invalid)
    }
    /// No local/cache fallback can attest a live durable personal consent.
    pub fn authorize_personal_delegation(
        &self,
        request: awaken_iam_contract::AuthorizePersonalDelegation,
    ) -> Result<AuthorizationOutcome, IamDecisionError> {
        let GateInner::Remote { client, .. } = self.inner.as_ref() else {
            return Err(IamDecisionError::Unavailable);
        };
        client
            .authorize_personal_delegation(&request)
            .map_err(|_| IamDecisionError::Unavailable)
    }
    /// Open mode: no authentication, all requests allowed.
    pub fn open() -> Self {
        Self {
            inner: Arc::new(GateInner::Open),
            audience: None,
            issuer: None,
            browser_sessions: Arc::new(Mutex::new(None)),
        }
    }

    pub(crate) fn local(state: Arc<Mutex<LocalIamState>>, jwks: Option<Jwks>) -> Self {
        Self {
            inner: Arc::new(GateInner::Local { state, jwks }),
            audience: None,
            issuer: None,
            browser_sessions: Arc::new(Mutex::new(None)),
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
            browser_sessions: Arc::new(Mutex::new(None)),
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

    /// Attach the canonical browser-session authority to this gate.
    pub fn with_browser_sessions(
        self,
        sessions: Arc<Mutex<SessionGateway<OsEntropy>>>,
    ) -> Result<Self, LocalBrowserAuthError> {
        self.attach_browser_sessions(sessions)?;
        Ok(self)
    }

    /// Attach browser sessions after a product has shared the gate.
    pub fn attach_browser_sessions(
        &self,
        sessions: Arc<Mutex<SessionGateway<OsEntropy>>>,
    ) -> Result<(), LocalBrowserAuthError> {
        self.reserve_browser_sessions(sessions)?.publish();
        Ok(())
    }

    pub(crate) fn reserve_browser_sessions(
        &self,
        sessions: SharedBrowserSessions,
    ) -> Result<BrowserSessionAttachment<'_>, LocalBrowserAuthError> {
        let slot = self
            .browser_sessions
            .lock()
            .map_err(|_| LocalBrowserAuthError::Unavailable)?;
        Ok(BrowserSessionAttachment { slot, sessions })
    }

    /// Authenticate an HttpOnly browser session cookie.
    pub fn authenticate_session_cookie(
        &self,
        cookie_header: &str,
        now: Timestamp,
    ) -> Result<PrincipalRef, AuthReject> {
        let sessions = self
            .browser_sessions
            .lock()
            .map_err(|_| AuthReject::Unavailable)?
            .clone()
            .ok_or(AuthReject::Invalid)?;
        let view = sessions
            .lock()
            .map_err(|_| AuthReject::Unavailable)?
            .current_session_from_cookie(cookie_header, now)
            .map_err(|error| match error {
                IamError::SessionStorageUnavailable => AuthReject::Unavailable,
                _ => AuthReject::Invalid,
            })?;
        Ok(PrincipalRef::Account {
            account_id: view.account_id,
        })
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
    /// drops it. Fail-closed like `authenticate_bearer`; use
    /// [`authenticate_detailed`](Self::authenticate_detailed) to distinguish
    /// *why* a credential failed.
    pub fn authenticate_scoped(
        &self,
        token: &str,
        now: &Timestamp,
        now_unix: i64,
    ) -> Option<(PrincipalRef, Option<WorkspaceId>)> {
        self.authenticate_detailed(token, now, now_unix).ok()
    }

    /// Authenticate a bearer credential, surfacing *why* it failed.
    ///
    /// Like [`authenticate_scoped`](Self::authenticate_scoped) on success, but on
    /// failure returns an [`AuthReject`] so a product can answer the distinct
    /// rejection reasons its API documents (expired vs revoked vs invalid), or
    /// unavailability, rather than one opaque "invalid". A verified JWT keeps its explicit expiry reason;
    /// introspection failures remain opaque because the remote protocol does not
    /// disclose whether an API token was invalid, expired, or revoked.
    pub fn authenticate_detailed(
        &self,
        token: &str,
        now: &Timestamp,
        now_unix: i64,
    ) -> Result<(PrincipalRef, Option<WorkspaceId>), AuthReject> {
        self.authenticate_verified(token, now, now_unix)
            .map(|verified| (verified.principal, verified.workspace))
    }

    /// Authenticate a bearer credential and return every verified coordinate a
    /// relying party may act on, including the RFC 8693 delegation actor.
    ///
    /// For a delegated IAM access token, [`VerifiedBearer::principal`] is the
    /// end-user (`sub`) and [`VerifiedBearer::actor`] is the service acting for
    /// them (`act`). A relying party that authorizes such a request must
    /// evaluate both principals — see
    /// [`authorization_request`](VerifiedBearer::authorization_request).
    /// Failure reasons match [`authenticate_detailed`](Self::authenticate_detailed).
    pub fn authenticate_verified(
        &self,
        token: &str,
        now: &Timestamp,
        now_unix: i64,
    ) -> Result<VerifiedBearer, AuthReject> {
        match self.inner.as_ref() {
            GateInner::Open => Err(AuthReject::Invalid),
            GateInner::Local { state, jwks } => {
                if is_api_token(token) {
                    let guard = state.lock().map_err(|_| AuthReject::Unavailable)?;
                    match guard.directory.authenticate(token, now) {
                        Ok(t) => Ok(VerifiedBearer::api_token(
                            t.principal.clone(),
                            t.workspace.clone(),
                        )),
                        Err(IamError::ApiTokenExpired { .. }) => Err(AuthReject::Expired),
                        Err(IamError::ApiTokenRevoked { .. }) => Err(AuthReject::Revoked),
                        Err(_) => Err(AuthReject::Invalid),
                    }
                } else if let Some(jwks) = jwks {
                    self.verify_jwt(token, jwks, now_unix)
                } else {
                    Err(AuthReject::Invalid)
                }
            }
            GateInner::Remote { client, jwks } => {
                if is_api_token(token) {
                    let req = TokenIntrospectionRequest {
                        token: token.to_owned(),
                    };
                    client
                        .introspect_token(&req)
                        .map_err(remote_authentication_failure)
                        .map(introspected_identity)
                        .map(|(principal, workspace)| VerifiedBearer {
                            principal,
                            workspace,
                            actor: None,
                            access_token: None,
                        })
                } else if let Some(jwks) = jwks {
                    self.verify_jwt(token, jwks, now_unix)
                } else {
                    Err(AuthReject::Invalid)
                }
            }
        }
    }

    /// Verify an IAM access-token JWT against `jwks` and this gate's exact
    /// issuer/audience policy.
    pub fn verify_jwt(
        &self,
        token: &str,
        jwks: &Jwks,
        now_unix: i64,
    ) -> Result<VerifiedBearer, AuthReject> {
        let verified =
            verify_delegated_access_token(token, jwks).map_err(|_| AuthReject::Invalid)?;
        let actor = verified.actor_principal();
        let claims = verified.claims;

        if claims.exp <= now_unix {
            return Err(AuthReject::Expired);
        }
        if let Some(ref expected_iss) = self.issuer
            && &claims.iss != expected_iss
        {
            return Err(AuthReject::Invalid);
        }
        if let Some(ref expected_aud) = self.audience
            && &claims.aud != expected_aud
        {
            return Err(AuthReject::Invalid);
        }
        Ok(VerifiedBearer {
            principal: claims.principal(),
            workspace: None,
            actor,
            access_token: Some(claims),
        })
    }

    /// Returns `true` when the gate is in open (no-auth) mode.
    pub fn is_open(&self) -> bool {
        matches!(self.inner.as_ref(), GateInner::Open)
    }
}

fn remote_authentication_failure(error: RemoteError) -> AuthReject {
    // Only the introspection owner's 401 attests credential rejection. A 403
    // can be a service/proxy failure; diagnostic text never establishes it.
    match error.status() {
        Some(401) => AuthReject::Invalid,
        _ => AuthReject::Unavailable,
    }
}

fn introspected_identity(
    response: TokenIntrospectionResponse,
) -> (PrincipalRef, Option<WorkspaceId>) {
    (response.principal, Some(response.workspace))
}

#[cfg(test)]
mod tests {
    use super::*;
    use awaken_iam_contract::ApiTokenStatus;

    #[test]
    fn remote_authentication_uses_status_evidence_not_diagnostic_words() {
        // A1 typed introspection401 -> Invalid. A2 403/503 or no response ->
        // Unavailable. A3 words resembling401/expiry with no status cannot
        // authenticate a rejection. The HTTP owner's real socket table below
        // this boundary separately establishes where this metadata comes from.
        for (error, expected) in [
            (
                RemoteError::response(401, "opaque".into()),
                AuthReject::Invalid,
            ),
            (
                RemoteError::response(403, "invalid".into()),
                AuthReject::Unavailable,
            ),
            (
                RemoteError::response(503, "expired".into()),
                AuthReject::Unavailable,
            ),
            (
                RemoteError::new("unexpected status 401 Unauthorized".into()),
                AuthReject::Unavailable,
            ),
            (
                RemoteError::new("expired or revoked".into()),
                AuthReject::Unavailable,
            ),
        ] {
            assert_eq!(remote_authentication_failure(error), expected);
        }
    }

    #[test]
    fn remote_decision_results_preserve_transport_unavailability() {
        // C1=the real HTTP transport cannot build a request from its URL.
        // R1(C1,Result)->Err(Unavailable), not Ok(Deny); R2(C1,legacy)->Deny.
        // This uses the existing transport/client and Gate, with no fake PDP or
        // network listener. Credential authentication is a separate boundary.
        let transport = HttpAuthzTransport::new(awaken_iam_client::HttpTransportConfig::new(
            "not a valid URL",
        ))
        .unwrap();
        let gate = IamGate::remote(RemoteIamClient::new(transport), None);
        let request = AuthorizationRequest::direct(
            PrincipalRef::Service {
                service_id: "remote-result".into(),
            },
            ActionKey("product.read".into()),
            ScopeRef::Global,
        );
        let resource = ResourceAuthorizationRequest {
            request: request.clone(),
            context: Default::default(),
        };
        let entitlement = EntitlementRequest {
            principal: request.principal.clone(),
            entitlement: "ai.basic".into(),
            resource: None,
        };
        assert_eq!(
            gate.authorize_result(request.clone()),
            Err(IamDecisionError::Unavailable)
        );
        assert_eq!(
            gate.authorize_resource_result(resource),
            Err(IamDecisionError::Unavailable)
        );
        assert_eq!(
            gate.check_entitlement_result(entitlement.clone()),
            Err(IamDecisionError::Unavailable)
        );
        assert_eq!(gate.authorize(request), AuthorizationDecision::Deny);
        assert_eq!(
            gate.check_entitlement(entitlement),
            EntitlementDecision::Deny
        );
    }

    #[test]
    fn remote_api_token_preserves_its_authoritative_workspace() {
        // Cause/effect graph: C1=IAM introspection succeeded; C2=response has
        // principal and mandatory workspace. Effect E1=the product receives
        // both coordinates. Decision rule R1(C1∧C2)->E1. Dropping workspace
        // would silently widen a one-workspace credential into an unscoped one.
        let principal = PrincipalRef::ApiToken {
            token_id: "token-a".into(),
        };
        let workspace = WorkspaceId("workspace-a".into());
        assert_eq!(
            introspected_identity(TokenIntrospectionResponse {
                principal: principal.clone(),
                workspace: workspace.clone(),
                status: ApiTokenStatus::Active,
            }),
            (principal, Some(workspace))
        );
    }
}

fn is_api_token(token: &str) -> bool {
    token.starts_with("sk-awaken-") || token.starts_with("sk-ant-")
}

impl IamClient for IamGate {
    fn profile_publication_state(
        &self,
        namespace: &awaken_iam_contract::NamespaceId,
    ) -> Result<awaken_iam_contract::AuthorizationProfilePublicationState, IamDecisionError> {
        match self.inner.as_ref() {
            GateInner::Remote { client, .. } => {
                IamClient::profile_publication_state(client, namespace)
            }
            // This gate owns the PDP, not Profile administration history.
            // Embedded products query their existing native PAP owner directly.
            GateInner::Open | GateInner::Local { .. } => Err(IamDecisionError::Unavailable),
        }
    }
    fn authorize_resource_result(
        &self,
        request: ResourceAuthorizationRequest,
    ) -> Result<AuthorizationOutcome, IamDecisionError> {
        match self.inner.as_ref() {
            GateInner::Open => Ok(AuthorizationOutcome {
                decision: AuthorizationDecision::Allow,
                reason: "open_mode".into(),
                matched_grants: Vec::new(),
                matched_roles: Vec::new(),
                obligation: None,
            }),
            GateInner::Local { state, .. } => {
                let guard = state.lock().map_err(|_| IamDecisionError::Unavailable)?;
                Ok(guard.authz.authorize_resource(&request))
            }
            GateInner::Remote { client, .. } => client.authorize_resource_result(request),
        }
    }
    fn authorize(&self, request: AuthorizationRequest) -> AuthorizationDecision {
        self.authorize_result(request)
            .unwrap_or(AuthorizationDecision::Deny)
    }

    fn authorize_result(
        &self,
        request: AuthorizationRequest,
    ) -> Result<AuthorizationDecision, IamDecisionError> {
        match self.inner.as_ref() {
            GateInner::Open => Ok(AuthorizationDecision::Allow),
            GateInner::Local { state, .. } => {
                let guard = state.lock().map_err(|_| IamDecisionError::Unavailable)?;
                Ok(guard.authz.authorize(&request).decision)
            }
            GateInner::Remote { client, .. } => client.authorize_result(request),
        }
    }

    fn check_entitlement(&self, request: EntitlementRequest) -> EntitlementDecision {
        self.check_entitlement_result(request)
            .unwrap_or(EntitlementDecision::Deny)
    }

    fn check_entitlement_result(
        &self,
        request: EntitlementRequest,
    ) -> Result<EntitlementDecision, IamDecisionError> {
        match self.inner.as_ref() {
            GateInner::Open => Ok(EntitlementDecision::Allow),
            GateInner::Local { state, .. } => {
                let guard = state.lock().map_err(|_| IamDecisionError::Unavailable)?;
                Ok(guard.authz.check_entitlement(&request).decision)
            }
            GateInner::Remote { client, .. } => client.check_entitlement_result(request),
        }
    }
}
