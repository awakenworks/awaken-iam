//! Third-party authentication HTTP API surface.
//!
//! This module is the framework-agnostic seam that exposes the browser-facing
//! auth endpoints on top of the login loop primitives in
//! [`awaken_iam_core`]. It deliberately speaks in logical request/response
//! values (URLs, `Set-Cookie` header strings, view DTOs) rather than binding to
//! a concrete HTTP framework, matching the MVP in-process shape used elsewhere
//! in the server crate. A deployment maps these onto its router of choice.
//!
//! The routes form one canonical `/v1` auth tree (plus the well-known discovery
//! paths), as specified by the auth-server design — never two paths for one job:
//!
//! | Route | Method on [`AuthApi`] |
//! |---|---|
//! | `GET /.well-known/openid-configuration` | [`AuthApi::openid_configuration`] |
//! | `GET /v1/auth/providers` | [`AuthApi::list_providers`] |
//! | `GET /v1/auth/login/{provider}` | [`AuthApi::start_login`] |
//! | `GET /v1/auth/callback/{provider}` | [`AuthApi::complete_callback`] |
//! | `GET /v1/session` | [`AuthApi::current_session`] |
//! | `DELETE /v1/session` | [`AuthApi::logout`] |
//! | `GET /v1/oauth/userinfo` | [`AuthApi::userinfo`] |
//! | `GET /v1/account/identities` | [`AuthApi::list_identities`] |
//! | `POST /v1/account/identities` | [`AuthApi::link_identity`] |
//! | `DELETE /v1/account/identities/{provider}/{subject}` | [`AuthApi::unlink_identity`] |
//!
//! Product services (Oversight Cloud, Pack Hub, Awaken Next Cloud) consume this
//! API as their authentication seam: rather than parsing a Google or GitHub
//! token, a product forwards the opaque IAM session cookie to
//! [`AuthApi::resolve_principal`] and receives the account [`PrincipalRef`] that
//! backs the live session. It then drives its own grant and entitlement checks
//! against [`AuthzApi`](crate::AuthzApi) with that principal. Resolution fails
//! closed for a missing, unknown, revoked, or expired session, and for a session
//! whose account is disabled, so a product can never manufacture a principal of
//! its own.
//!
//! The front half of the login loop mints a challenge whose hashes are persisted
//! in the [`SessionDirectory`](awaken_iam_core::SessionDirectory); the one-time
//! cleartext secrets needed to finish the exchange (the PKCE verifier and OIDC
//! nonce) are held in a transient in-memory pending map keyed by the login-state
//! id and dropped the instant the callback consumes them. The browser only
//! carries the login-state id in a hardened correlation cookie, never the
//! secrets. `return_to` is constrained by an allowlist so a crafted link cannot
//! turn login into an open redirect, and every transition emits an
//! [`AuthAuditEvent`].

use std::collections::HashMap;

use awaken_iam_contract::{
    Account, AccountId, AccountStatus, ExternalIdentity, ExternalIdentityClaims,
    ExternalIdentityId, ExternalSubject, IdentityProviderConfig, IdentityProviderKey,
    IdentityProviderKind, OAuthLoginStateId, OpenIdProviderMetadata, PrincipalRef, SessionId,
    SessionView, Timestamp, UserInfo,
};
use awaken_iam_core::{
    AuthorizationUrlRequest, BeginLogin, CallbackExchange, EntropySource, EstablishSession,
    IamError, IdentityDirectory, IdentityProviderAdapter, LoginAttempt, OAuthChallengeService,
    OsEntropy, ProviderError, SessionDirectory,
};
use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;

use crate::{SessionCookieConfig, SessionGateway};

/// Number of random bytes drawn for each generated id (256 bits).
const ID_BYTES: usize = 32;

/// Default name of the short-lived login correlation cookie.
///
/// The `__Host-` prefix binds it to `Secure`, `Path=/`, and no `Domain`, which
/// the default [`SessionCookieConfig`] satisfies.
pub const DEFAULT_LOGIN_COOKIE_NAME: &str = "__Host-awaken_login";

/// Allowlist policy constraining post-login `return_to` destinations.
///
/// A `return_to` is honoured only when it is a same-site relative path that
/// begins with one of the configured prefixes; anything else (an absolute URL,
/// a protocol-relative `//host` value, or a path outside the allowlist) falls
/// back to [`ReturnToPolicy::default_return_to`] so login can never be coerced
/// into an open redirect.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReturnToPolicy {
    default_return_to: String,
    allowed_prefixes: Vec<String>,
}

impl Default for ReturnToPolicy {
    fn default() -> Self {
        Self {
            default_return_to: "/".to_owned(),
            allowed_prefixes: vec!["/".to_owned()],
        }
    }
}

/// Outcome of resolving a requested `return_to` against the allowlist.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ReturnToDecision {
    /// The requested destination was honoured verbatim.
    Allowed(String),
    /// The request was missing or rejected; the safe default is used instead.
    RejectedFallback(String),
}

impl ReturnToDecision {
    /// The destination to actually redirect to.
    pub fn destination(&self) -> &str {
        match self {
            ReturnToDecision::Allowed(value) | ReturnToDecision::RejectedFallback(value) => value,
        }
    }

    /// Whether a non-empty requested destination was rejected by the allowlist.
    pub fn was_rejected(&self) -> bool {
        matches!(self, ReturnToDecision::RejectedFallback(_))
    }
}

impl ReturnToPolicy {
    /// Build a policy with an explicit default and prefix allowlist.
    pub fn new(
        default_return_to: impl Into<String>,
        allowed_prefixes: impl IntoIterator<Item = String>,
    ) -> Self {
        Self {
            default_return_to: default_return_to.into(),
            allowed_prefixes: allowed_prefixes.into_iter().collect(),
        }
    }

    /// The destination used when no allowed `return_to` was supplied.
    pub fn default_return_to(&self) -> &str {
        &self.default_return_to
    }

    /// Resolve a requested `return_to` against the allowlist.
    pub fn resolve(&self, requested: Option<&str>) -> ReturnToDecision {
        match requested {
            Some(candidate) if self.is_allowed(candidate) => {
                ReturnToDecision::Allowed(candidate.to_owned())
            }
            _ => ReturnToDecision::RejectedFallback(self.default_return_to.clone()),
        }
    }

    fn is_allowed(&self, candidate: &str) -> bool {
        // Reject protocol-relative (`//host`) and backslash-smuggled values that
        // browsers may treat as cross-origin even though they start with `/`.
        if candidate.starts_with("//") || candidate.starts_with("/\\") {
            return false;
        }
        self.allowed_prefixes
            .iter()
            .any(|prefix| candidate.starts_with(prefix))
    }
}

/// Audit event emitted as the auth API drives the login session loop.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AuthAuditEvent {
    /// A login challenge was started for a provider.
    LoginStarted {
        /// Provider the login targets.
        provider_key: IdentityProviderKey,
        /// Persisted login-state id correlating start and callback.
        login_state_id: OAuthLoginStateId,
        /// When the challenge was started.
        at: Timestamp,
    },
    /// A login callback resolved to an authenticated session.
    LoginSucceeded {
        /// Provider that authenticated the subject.
        provider_key: IdentityProviderKey,
        /// Account the session authenticates.
        account_id: AccountId,
        /// Established session id.
        session_id: SessionId,
        /// External identity used to establish the session.
        external_identity_id: ExternalIdentityId,
        /// Whether a new account was provisioned on this login.
        registered: bool,
        /// When the session was established.
        at: Timestamp,
    },
    /// A login attempt failed before a session could be established.
    LoginFailed {
        /// Provider the failed login targeted.
        provider_key: IdentityProviderKey,
        /// Stable machine-readable failure reason.
        reason: AuthFailureReason,
        /// When the failure was observed.
        at: Timestamp,
    },
    /// A requested `return_to` was rejected and replaced with the safe default.
    ReturnToRejected {
        /// Provider whose login carried the rejected destination.
        provider_key: IdentityProviderKey,
        /// The rejected destination, verbatim.
        rejected: String,
        /// When the rejection happened.
        at: Timestamp,
    },
    /// A session was revoked through logout.
    LoggedOut {
        /// Session that was revoked.
        session_id: SessionId,
        /// When logout happened.
        at: Timestamp,
    },
    /// An external identity was linked to an account.
    IdentityLinked {
        /// Account the identity was attached to.
        account_id: AccountId,
        /// New external identity id.
        external_identity_id: ExternalIdentityId,
        /// Provider that issued the subject.
        provider_key: IdentityProviderKey,
        /// When the link was created.
        at: Timestamp,
    },
    /// An external identity was unlinked from an account.
    IdentityUnlinked {
        /// Account the identity was detached from.
        account_id: AccountId,
        /// Provider that issued the subject.
        provider_key: IdentityProviderKey,
        /// Detached provider subject.
        subject: ExternalSubject,
        /// When the link was removed.
        at: Timestamp,
    },
    /// A product service resolved a session principal at the authentication
    /// seam, ready to drive its own grant and entitlement checks.
    PrincipalResolved {
        /// Account principal resolved from the presented IAM session.
        principal: PrincipalRef,
        /// When the principal was resolved.
        at: Timestamp,
    },
    /// A product service presented a session that could not be resolved to an
    /// active account principal, so the request failed closed.
    PrincipalResolutionFailed {
        /// Stable machine-readable reason resolution failed.
        reason: PrincipalResolutionFailure,
        /// When the failure was observed.
        at: Timestamp,
    },
}

/// Stable machine-readable reason a session could not be resolved to an active
/// account principal at the product authentication seam.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PrincipalResolutionFailure {
    /// No live session backed the presented cookie (missing, unknown, revoked,
    /// or expired).
    Unauthenticated,
    /// The session resolved to an account that is disabled or unknown.
    AccountDisabled,
}

/// Stable machine-readable reason a login attempt failed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AuthFailureReason {
    /// The login correlation cookie was absent or unparseable.
    MissingCorrelation,
    /// The presented OAuth `state` did not match the minted challenge.
    StateMismatch,
    /// The challenge was expired, replayed, or otherwise unusable.
    ChallengeRejected,
    /// The provider exchange rejected the callback.
    ProviderRejected,
}

/// Compact provider descriptor returned by `GET /v1/auth/providers`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProviderSummary {
    /// Stable provider key used in login routes.
    pub provider_key: IdentityProviderKey,
    /// Provider implementation family.
    pub kind: IdentityProviderKind,
    /// Human-readable provider name.
    pub display_name: String,
}

/// Inputs to register a provider with the auth API.
pub struct ProviderRegistration {
    /// Shared provider configuration.
    pub config: IdentityProviderConfig,
    /// Provider-specific URL/exchange adapter.
    pub adapter: Box<dyn IdentityProviderAdapter + Send + Sync>,
    /// Absolute callback URL the provider redirects back to.
    pub redirect_uri: String,
    /// OAuth scopes requested at the authorization endpoint.
    pub scopes: Vec<String>,
    /// Whether to mint an OIDC nonce for this provider.
    pub include_nonce: bool,
    /// Whether to mint a PKCE verifier/challenge for this provider.
    pub include_pkce: bool,
}

struct RegisteredProvider {
    config: IdentityProviderConfig,
    adapter: Box<dyn IdentityProviderAdapter + Send + Sync>,
    redirect_uri: String,
    scopes: Vec<String>,
    include_nonce: bool,
    include_pkce: bool,
}

/// Transient cleartext secrets retained between start and callback.
struct PendingLogin {
    nonce: Option<String>,
    pkce_verifier: Option<String>,
}

/// Request to begin a login (`GET /v1/auth/login/{provider}`).
#[derive(Debug, Clone)]
pub struct StartLogin {
    /// Provider selected for the login.
    pub provider_key: IdentityProviderKey,
    /// Requested post-login destination, validated against the allowlist.
    pub return_to: Option<String>,
    /// Challenge creation timestamp.
    pub created_at: Timestamp,
    /// Challenge expiration timestamp; must be strictly after `created_at`.
    pub expires_at: Timestamp,
    /// Optional `Max-Age` (seconds) bounding the login correlation cookie.
    pub cookie_max_age_secs: Option<u64>,
}

/// Result of beginning a login.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StartLoginOutcome {
    /// Provider authorization URL to redirect the browser to.
    pub redirect_url: String,
    /// `Set-Cookie` header value carrying the login correlation cookie.
    pub set_cookie: String,
    /// Resolved `return_to` destination after allowlist enforcement.
    pub return_to: ReturnToDecision,
}

/// Request to complete a login (`GET /v1/auth/callback/{provider}`).
#[derive(Debug, Clone)]
pub struct CallbackRequest {
    /// Provider key from the callback route.
    pub provider_key: IdentityProviderKey,
    /// Raw request `Cookie` header carrying the login correlation cookie.
    pub cookie_header: String,
    /// Authorization `code` returned by the provider.
    pub code: String,
    /// OAuth `state` echoed by the provider.
    pub state: String,
    /// Callback observation timestamp.
    pub now: Timestamp,
    /// Session expiration timestamp.
    pub session_expires_at: Timestamp,
    /// Optional `Max-Age` (seconds) bounding the session cookie.
    pub session_cookie_max_age_secs: Option<u64>,
}

/// Result of completing a login.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CallbackOutcome {
    /// Destination to redirect the browser to after login.
    pub redirect_to: String,
    /// `Set-Cookie` header value establishing the session cookie.
    pub set_session_cookie: String,
    /// `Set-Cookie` header value clearing the login correlation cookie.
    pub clear_login_cookie: String,
    /// Public, token-free view of the new session.
    pub session: SessionView,
    /// Whether a new account was provisioned on this login.
    pub registered: bool,
}

/// Result of logging out.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LogoutOutcome {
    /// `Set-Cookie` header value clearing the browser session cookie.
    pub clear_session_cookie: String,
}

/// Request to link an already-verified external identity to an account.
#[derive(Debug, Clone)]
pub struct LinkIdentity {
    /// Account to attach the identity to.
    pub account_id: AccountId,
    /// Provider that issued the subject.
    pub provider_key: IdentityProviderKey,
    /// Verified normalized claims for the subject.
    pub claims: ExternalIdentityClaims,
    /// Link timestamp.
    pub now: Timestamp,
}

/// Request to unlink an external identity from an account.
#[derive(Debug, Clone)]
pub struct UnlinkIdentity {
    /// Account the identity is attached to.
    pub account_id: AccountId,
    /// Provider that issued the subject.
    pub provider_key: IdentityProviderKey,
    /// Provider subject to detach.
    pub subject: ExternalSubject,
    /// Unlink timestamp.
    pub now: Timestamp,
}

/// Errors surfaced by the auth API.
#[derive(Debug, PartialEq, Eq, thiserror::Error)]
pub enum AuthApiError {
    /// No provider is registered for the requested key.
    #[error("unknown identity provider: {0:?}")]
    UnknownProvider(IdentityProviderKey),
    /// The provider exists but is disabled for new logins.
    #[error("identity provider is disabled: {0:?}")]
    ProviderDisabled(IdentityProviderKey),
    /// The callback provider key disagreed with the started challenge.
    #[error("callback provider does not match the started login")]
    ProviderMismatch,
    /// The login correlation cookie was missing or unusable.
    #[error("login correlation cookie is missing")]
    MissingCorrelation,
    /// The login-state invariants rejected the operation.
    #[error(transparent)]
    Login(#[from] IamError),
    /// The provider adapter rejected the exchange.
    #[error(transparent)]
    Provider(#[from] ProviderError),
    /// The external identity is linked to a different account.
    #[error("external identity is linked to a different account")]
    IdentityAccountMismatch,
    /// The presented IAM session could not be resolved to a live session.
    #[error("request is not authenticated by a live IAM session")]
    Unauthenticated,
    /// The session resolved to an account that is disabled or no longer exists.
    #[error("session principal account is disabled")]
    AccountDisabled,
}

/// Browser-facing third-party auth API over the login session loop.
pub struct AuthApi<E: EntropySource + Clone = OsEntropy> {
    providers: Vec<RegisteredProvider>,
    challenge: OAuthChallengeService<E>,
    login_directory: SessionDirectory,
    sessions: SessionGateway<E>,
    directory: IdentityDirectory,
    pending: HashMap<OAuthLoginStateId, PendingLogin>,
    return_to: ReturnToPolicy,
    login_cookie: SessionCookieConfig,
    audit: Vec<AuthAuditEvent>,
    ids: E,
}

impl AuthApi<OsEntropy> {
    /// Build an auth API over OS entropy and hardened default cookies.
    pub fn new() -> Self {
        Self::with_entropy(OsEntropy)
    }
}

impl Default for AuthApi<OsEntropy> {
    fn default() -> Self {
        Self::new()
    }
}

impl<E: EntropySource + Clone> AuthApi<E> {
    /// Build an auth API over a custom entropy source and default policies.
    pub fn with_entropy(entropy: E) -> Self {
        let login_cookie = SessionCookieConfig {
            name: DEFAULT_LOGIN_COOKIE_NAME.to_owned(),
            ..SessionCookieConfig::default()
        };
        Self {
            providers: Vec::new(),
            challenge: OAuthChallengeService::new(entropy.clone()),
            login_directory: SessionDirectory::new(),
            sessions: SessionGateway::with_entropy(entropy.clone(), SessionCookieConfig::default()),
            directory: IdentityDirectory::new(),
            pending: HashMap::new(),
            return_to: ReturnToPolicy::default(),
            login_cookie,
            audit: Vec::new(),
            ids: entropy,
        }
    }

    /// Replace the `return_to` allowlist policy.
    pub fn with_return_to_policy(mut self, policy: ReturnToPolicy) -> Self {
        self.return_to = policy;
        self
    }

    /// Replace the session cookie configuration.
    pub fn with_session_cookie(mut self, cookie: SessionCookieConfig) -> Self {
        self.sessions = SessionGateway::with_entropy(self.ids.clone(), cookie);
        self
    }

    /// Replace the login correlation cookie configuration.
    pub fn with_login_cookie(mut self, cookie: SessionCookieConfig) -> Self {
        self.login_cookie = cookie;
        self
    }

    /// Register a provider with its adapter and flow configuration.
    pub fn register_provider(&mut self, registration: ProviderRegistration) {
        self.providers.push(RegisteredProvider {
            config: registration.config,
            adapter: registration.adapter,
            redirect_uri: registration.redirect_uri,
            scopes: registration.scopes,
            include_nonce: registration.include_nonce,
            include_pkce: registration.include_pkce,
        });
    }

    /// Borrow the identity directory backing account/identity reads.
    pub fn directory(&self) -> &IdentityDirectory {
        &self.directory
    }

    /// The accumulated audit trail for this API instance.
    pub fn audit_log(&self) -> &[AuthAuditEvent] {
        &self.audit
    }

    /// `GET /v1/auth/providers`: list providers currently enabled for login.
    pub fn list_providers(&self) -> Vec<ProviderSummary> {
        self.providers
            .iter()
            .filter(|provider| provider.config.enabled)
            .map(|provider| ProviderSummary {
                provider_key: provider.config.provider_key.clone(),
                kind: provider.config.kind,
                display_name: provider.config.display_name.clone(),
            })
            .collect()
    }

    /// `GET /v1/auth/login/{provider}`: mint a challenge and build the provider
    /// authorization redirect plus its correlation cookie.
    pub fn start_login(&mut self, request: StartLogin) -> Result<StartLoginOutcome, AuthApiError> {
        let index = self.provider_index(&request.provider_key)?;
        if !self.providers[index].config.enabled {
            return Err(AuthApiError::ProviderDisabled(request.provider_key));
        }

        let return_to = self.return_to.resolve(request.return_to.as_deref());
        if return_to.was_rejected()
            && let Some(rejected) = request.return_to.clone()
        {
            self.audit.push(AuthAuditEvent::ReturnToRejected {
                provider_key: request.provider_key.clone(),
                rejected,
                at: request.created_at.clone(),
            });
        }

        let login_state_id = OAuthLoginStateId(self.mint_id("login"));
        let (include_nonce, include_pkce) = {
            let provider = &self.providers[index];
            (provider.include_nonce, provider.include_pkce)
        };

        let issued = self.challenge.begin_login(
            &mut self.login_directory,
            BeginLogin {
                id: login_state_id.clone(),
                provider_key: request.provider_key.clone(),
                return_to: Some(return_to.destination().to_owned()),
                include_nonce,
                include_pkce,
                created_at: request.created_at.clone(),
                expires_at: request.expires_at,
            },
        )?;

        let provider = &self.providers[index];
        let url_request = AuthorizationUrlRequest {
            redirect_uri: provider.redirect_uri.clone(),
            state: issued.secrets.state.clone(),
            nonce: issued.secrets.nonce.clone(),
            pkce_challenge: issued.secrets.pkce_challenge.clone(),
            scopes: provider.scopes.clone(),
        };
        let redirect = provider
            .adapter
            .authorization_url(&provider.config, &url_request)?;

        self.pending.insert(
            login_state_id.clone(),
            PendingLogin {
                nonce: issued.secrets.nonce.clone(),
                pkce_verifier: issued.secrets.pkce_verifier.clone(),
            },
        );

        let set_cookie = self
            .login_cookie
            .render_set_cookie(&login_state_id.0, request.cookie_max_age_secs);

        self.audit.push(AuthAuditEvent::LoginStarted {
            provider_key: request.provider_key,
            login_state_id,
            at: request.created_at,
        });

        Ok(StartLoginOutcome {
            redirect_url: redirect.url,
            set_cookie,
            return_to,
        })
    }

    /// `GET /v1/auth/callback/{provider}`: verify the challenge, exchange the
    /// code for claims, resolve or provision the account, and establish a
    /// session.
    pub fn complete_callback(
        &mut self,
        request: CallbackRequest,
    ) -> Result<CallbackOutcome, AuthApiError> {
        let index = self.provider_index(&request.provider_key)?;

        let login_state_id = match self.login_cookie.extract_token(&request.cookie_header) {
            Some(token) if !token.is_empty() => OAuthLoginStateId(token),
            _ => {
                self.record_failure(
                    &request.provider_key,
                    AuthFailureReason::MissingCorrelation,
                    &request.now,
                );
                return Err(AuthApiError::MissingCorrelation);
            }
        };

        let pending = match self.pending.remove(&login_state_id) {
            Some(pending) => pending,
            None => {
                self.record_failure(
                    &request.provider_key,
                    AuthFailureReason::MissingCorrelation,
                    &request.now,
                );
                return Err(AuthApiError::MissingCorrelation);
            }
        };

        let attempt = LoginAttempt {
            id: login_state_id.clone(),
            state: request.state.clone(),
            nonce: pending.nonce.clone(),
            pkce_verifier: pending.pkce_verifier.clone(),
        };
        let consumed = match self.challenge.complete_login(
            &mut self.login_directory,
            &attempt,
            request.now.clone(),
        ) {
            Ok(consumed) => consumed,
            Err(err) => {
                let reason = match err {
                    IamError::LoginStateMismatch { .. } => AuthFailureReason::StateMismatch,
                    _ => AuthFailureReason::ChallengeRejected,
                };
                self.record_failure(&request.provider_key, reason, &request.now);
                return Err(AuthApiError::Login(err));
            }
        };

        if consumed.provider_key != request.provider_key {
            self.record_failure(
                &request.provider_key,
                AuthFailureReason::StateMismatch,
                &request.now,
            );
            return Err(AuthApiError::ProviderMismatch);
        }
        let return_to = consumed
            .return_to
            .clone()
            .unwrap_or_else(|| self.return_to.default_return_to().to_owned());

        let claims = {
            let provider = &self.providers[index];
            let exchange = CallbackExchange {
                redirect_uri: provider.redirect_uri.clone(),
                code: request.code.clone(),
                pkce_verifier: pending.pkce_verifier.clone(),
            };
            match provider
                .adapter
                .exchange_callback(&provider.config, &exchange)
            {
                Ok(claims) => claims,
                Err(err) => {
                    self.record_failure(
                        &request.provider_key,
                        AuthFailureReason::ProviderRejected,
                        &request.now,
                    );
                    return Err(AuthApiError::Provider(err));
                }
            }
        };

        let (account_id, external_identity_id, registered) =
            self.resolve_account(&request.provider_key, claims, &request.now)?;

        let session_id = SessionId(self.mint_id("sess"));
        let established = self.sessions.establish_session(
            EstablishSession {
                id: session_id.clone(),
                account_id: account_id.clone(),
                external_identity_id: Some(external_identity_id.clone()),
                created_at: request.now.clone(),
                expires_at: request.session_expires_at,
            },
            request.session_cookie_max_age_secs,
        )?;

        self.audit.push(AuthAuditEvent::LoginSucceeded {
            provider_key: request.provider_key,
            account_id,
            session_id,
            external_identity_id,
            registered,
            at: request.now,
        });

        Ok(CallbackOutcome {
            redirect_to: return_to,
            set_session_cookie: established.set_cookie,
            clear_login_cookie: self.login_cookie.render_clear_cookie(),
            session: established.view,
            registered,
        })
    }

    /// `GET /v1/session`: resolve the live session from the request cookie.
    pub fn current_session(
        &mut self,
        cookie_header: &str,
        now: Timestamp,
    ) -> Result<SessionView, AuthApiError> {
        Ok(self
            .sessions
            .current_session_from_cookie(cookie_header, now)?)
    }

    /// Resolve the account principal backing the presented IAM session.
    ///
    /// This is the shared authentication seam product services consume: rather
    /// than parsing a Google or GitHub token, Oversight Cloud, Pack Hub, and
    /// Awaken Next Cloud forward the opaque IAM session cookie and let IAM
    /// resolve the live session to its [`PrincipalRef::Account`]. The product
    /// then drives its own grant and entitlement checks against
    /// [`AuthzApi`](crate::AuthzApi) with that principal — IAM resolves *who*,
    /// never *what* the product domain decides.
    ///
    /// Resolution fails closed: it returns [`AuthApiError::Unauthenticated`]
    /// when the cookie does not back a live session (missing, unknown, revoked,
    /// or expired), and [`AuthApiError::AccountDisabled`] when the session
    /// resolves to a disabled or unknown account. The product can therefore
    /// never manufacture a principal of its own. Every outcome is audited.
    pub fn resolve_principal(
        &mut self,
        cookie_header: &str,
        now: Timestamp,
    ) -> Result<PrincipalRef, AuthApiError> {
        let account_id = match self
            .sessions
            .current_session_from_cookie(cookie_header, now.clone())
        {
            Ok(view) => view.account_id,
            Err(_) => {
                self.audit.push(AuthAuditEvent::PrincipalResolutionFailed {
                    reason: PrincipalResolutionFailure::Unauthenticated,
                    at: now,
                });
                return Err(AuthApiError::Unauthenticated);
            }
        };

        match self.directory.account(&account_id) {
            Some(account) if account.status == AccountStatus::Active => {
                let principal = PrincipalRef::Account { account_id };
                self.audit.push(AuthAuditEvent::PrincipalResolved {
                    principal: principal.clone(),
                    at: now,
                });
                Ok(principal)
            }
            _ => {
                self.audit.push(AuthAuditEvent::PrincipalResolutionFailed {
                    reason: PrincipalResolutionFailure::AccountDisabled,
                    at: now,
                });
                Err(AuthApiError::AccountDisabled)
            }
        }
    }

    /// `GET /.well-known/openid-configuration`: advertise this provider's
    /// canonical endpoints for the `issuer` base URL.
    ///
    /// IAM is the OpenID Provider; the document lets relying parties discover
    /// the `/v1` auth tree rather than hardcoding paths.
    pub fn openid_configuration(&self, issuer: &str) -> OpenIdProviderMetadata {
        OpenIdProviderMetadata::for_issuer(issuer)
    }

    /// `GET /v1/oauth/userinfo`: return the authenticated subject's OIDC claims.
    ///
    /// Resolves the live session from the request cookie (failing closed when it
    /// is missing, revoked, or expired), then projects the account and its
    /// latest linked provider claims into [`UserInfo`]. `sub` is IAM's own
    /// account subject, never the upstream provider subject.
    pub fn userinfo(
        &mut self,
        cookie_header: &str,
        now: Timestamp,
    ) -> Result<UserInfo, AuthApiError> {
        let view = self.current_session(cookie_header, now)?;
        let identity = view.external_identity_id.as_ref().and_then(|external_id| {
            self.directory
                .identities_for_account(&view.account_id)
                .into_iter()
                .find(|identity| &identity.id == external_id)
        });
        let userinfo = UserInfo::project(
            &view.account_id,
            identity.map(|identity| &identity.claims),
            identity.map(|identity| &identity.last_seen_at),
        );
        Ok(userinfo)
    }

    /// `DELETE /v1/session`: revoke the presented session and clear its cookie.
    pub fn logout(
        &mut self,
        cookie_header: &str,
        now: Timestamp,
    ) -> Result<LogoutOutcome, AuthApiError> {
        let token = self
            .sessions
            .cookie_config()
            .extract_token(cookie_header)
            .ok_or(AuthApiError::Login(IamError::SessionNotFound {
                id: SessionId(String::new()),
            }))?;
        let session_id = self
            .sessions
            .directory()
            .session_id_for_token_hash(&awaken_iam_core::hash_session_token(&token))
            .cloned();
        let clear_session_cookie = self.sessions.logout(&token, now.clone())?;
        if let Some(session_id) = session_id {
            self.audit.push(AuthAuditEvent::LoggedOut {
                session_id,
                at: now,
            });
        }
        Ok(LogoutOutcome {
            clear_session_cookie,
        })
    }

    /// `GET /v1/account/identities`: list the identities linked to an account.
    pub fn list_identities(&self, account_id: &AccountId) -> Vec<ExternalIdentity> {
        self.directory
            .identities_for_account(account_id)
            .into_iter()
            .cloned()
            .collect()
    }

    /// `POST /v1/account/identities`: link a verified external identity to an
    /// account.
    pub fn link_identity(
        &mut self,
        request: LinkIdentity,
    ) -> Result<ExternalIdentity, AuthApiError> {
        let external_identity_id = ExternalIdentityId(self.mint_id("ext"));
        let identity = ExternalIdentity {
            id: external_identity_id.clone(),
            account_id: request.account_id.clone(),
            provider_key: request.provider_key.clone(),
            claims: request.claims,
            first_seen_at: request.now.clone(),
            last_seen_at: request.now.clone(),
        };
        self.directory.link_external_identity(identity.clone())?;
        self.audit.push(AuthAuditEvent::IdentityLinked {
            account_id: request.account_id,
            external_identity_id,
            provider_key: request.provider_key,
            at: request.now,
        });
        Ok(identity)
    }

    /// `DELETE /v1/account/identities/{provider}/{subject}`: detach an identity
    /// owned by the account.
    pub fn unlink_identity(&mut self, request: UnlinkIdentity) -> Result<(), AuthApiError> {
        let owned = self
            .directory
            .external_identity(&request.provider_key, &request.subject)
            .map(|identity| identity.account_id == request.account_id);
        match owned {
            None => Err(AuthApiError::Login(IamError::ExternalIdentityNotFound {
                provider_key: request.provider_key,
                subject: request.subject,
            })),
            Some(false) => Err(AuthApiError::IdentityAccountMismatch),
            Some(true) => {
                self.directory
                    .remove_external_identity(&request.provider_key, &request.subject)?;
                self.audit.push(AuthAuditEvent::IdentityUnlinked {
                    account_id: request.account_id,
                    provider_key: request.provider_key,
                    subject: request.subject,
                    at: request.now,
                });
                Ok(())
            }
        }
    }

    /// Resolve the account for a set of verified claims, provisioning a new
    /// account and link on first login.
    fn resolve_account(
        &mut self,
        provider_key: &IdentityProviderKey,
        claims: ExternalIdentityClaims,
        now: &Timestamp,
    ) -> Result<(AccountId, ExternalIdentityId, bool), AuthApiError> {
        if let Some(existing) = self
            .directory
            .external_identity(provider_key, &claims.subject)
        {
            let account_id = existing.account_id.clone();
            let external_identity_id = existing.id.clone();
            self.directory.update_external_identity_claims(
                provider_key.clone(),
                claims,
                now.clone(),
            )?;
            return Ok((account_id, external_identity_id, false));
        }

        let account_id = AccountId(self.mint_id("acct"));
        self.directory.upsert_account(Account {
            id: account_id.clone(),
            status: AccountStatus::Active,
            display_name: claims.display_name.clone(),
            created_at: now.clone(),
            updated_at: now.clone(),
        });
        let external_identity_id = ExternalIdentityId(self.mint_id("ext"));
        self.directory.link_external_identity(ExternalIdentity {
            id: external_identity_id.clone(),
            account_id: account_id.clone(),
            provider_key: provider_key.clone(),
            claims,
            first_seen_at: now.clone(),
            last_seen_at: now.clone(),
        })?;
        Ok((account_id, external_identity_id, true))
    }

    fn provider_index(&self, provider_key: &IdentityProviderKey) -> Result<usize, AuthApiError> {
        self.providers
            .iter()
            .position(|provider| &provider.config.provider_key == provider_key)
            .ok_or_else(|| AuthApiError::UnknownProvider(provider_key.clone()))
    }

    fn record_failure(
        &mut self,
        provider_key: &IdentityProviderKey,
        reason: AuthFailureReason,
        at: &Timestamp,
    ) {
        self.audit.push(AuthAuditEvent::LoginFailed {
            provider_key: provider_key.clone(),
            reason,
            at: at.clone(),
        });
    }

    fn mint_id(&mut self, prefix: &str) -> String {
        let mut buf = [0u8; ID_BYTES];
        self.ids.fill_bytes(&mut buf);
        format!("{prefix}_{}", URL_SAFE_NO_PAD.encode(buf))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::DEFAULT_SESSION_COOKIE_NAME;
    use awaken_iam_contract::IdentityProviderConfigId;

    /// Deterministic entropy so minted ids and secrets are reproducible.
    #[derive(Clone, Default)]
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

    /// Minimal deterministic adapter: embeds `state` in the authorization URL and
    /// decodes a `subject:email` callback code into normalized claims.
    struct FakeAdapter;

    impl IdentityProviderAdapter for FakeAdapter {
        fn provider_kind(&self) -> IdentityProviderKind {
            IdentityProviderKind::Fake
        }

        fn authorization_url(
            &self,
            config: &IdentityProviderConfig,
            request: &AuthorizationUrlRequest,
        ) -> Result<awaken_iam_core::AuthorizationRedirect, ProviderError> {
            self.ensure_kind(config)?;
            Ok(awaken_iam_core::AuthorizationRedirect {
                url: format!(
                    "https://provider.example/authorize?redirect_uri={}&state={}",
                    request.redirect_uri, request.state
                ),
            })
        }

        fn exchange_callback(
            &self,
            config: &IdentityProviderConfig,
            callback: &CallbackExchange,
        ) -> Result<ExternalIdentityClaims, ProviderError> {
            self.ensure_kind(config)?;
            let (subject, email) =
                callback
                    .code
                    .split_once(':')
                    .ok_or_else(|| ProviderError::MalformedClaims {
                        reason: "code is not subject:email".into(),
                    })?;
            Ok(ExternalIdentityClaims {
                subject: ExternalSubject(subject.to_owned()),
                email: Some(email.to_owned()),
                email_verified: Some(true),
                display_name: Some("Fake User".into()),
                username: None,
                avatar_url: None,
                locale: None,
            })
        }
    }

    fn config(enabled: bool) -> IdentityProviderConfig {
        IdentityProviderConfig {
            id: IdentityProviderConfigId("cfg_fake".into()),
            provider_key: IdentityProviderKey("fake".into()),
            kind: IdentityProviderKind::Fake,
            display_name: "Fake".into(),
            issuer_url: Some("https://provider.example".into()),
            authorization_endpoint: Some("https://provider.example/authorize".into()),
            token_endpoint: Some("https://provider.example/token".into()),
            client_id: Some("client-fake".into()),
            enabled,
        }
    }

    fn api() -> AuthApi<SequentialEntropy> {
        let mut api = AuthApi::with_entropy(SequentialEntropy::default()).with_return_to_policy(
            ReturnToPolicy::new("/home", ["/dashboard".to_owned(), "/home".to_owned()]),
        );
        api.register_provider(ProviderRegistration {
            config: config(true),
            adapter: Box::new(FakeAdapter),
            redirect_uri: "https://app.example/v1/auth/callback/fake".into(),
            scopes: vec!["openid".into(), "email".into()],
            include_nonce: true,
            include_pkce: true,
        });
        api
    }

    fn start(api: &mut AuthApi<SequentialEntropy>, return_to: Option<&str>) -> StartLoginOutcome {
        api.start_login(StartLogin {
            provider_key: IdentityProviderKey("fake".into()),
            return_to: return_to.map(str::to_owned),
            created_at: Timestamp("2026-06-19T00:00:00Z".into()),
            expires_at: Timestamp("2026-06-19T00:05:00Z".into()),
            cookie_max_age_secs: Some(300),
        })
        .unwrap()
    }

    fn login_cookie_header(outcome: &StartLoginOutcome) -> String {
        let cfg = SessionCookieConfig {
            name: DEFAULT_LOGIN_COOKIE_NAME.to_owned(),
            ..SessionCookieConfig::default()
        };
        let id = cfg.extract_token(&outcome.set_cookie).unwrap();
        format!("{DEFAULT_LOGIN_COOKIE_NAME}={id}")
    }

    fn state_from_redirect(outcome: &StartLoginOutcome) -> String {
        outcome
            .redirect_url
            .split("state=")
            .nth(1)
            .unwrap()
            .to_owned()
    }

    fn callback(
        api: &mut AuthApi<SequentialEntropy>,
        outcome: &StartLoginOutcome,
        code: &str,
    ) -> Result<CallbackOutcome, AuthApiError> {
        api.complete_callback(CallbackRequest {
            provider_key: IdentityProviderKey("fake".into()),
            cookie_header: login_cookie_header(outcome),
            code: code.into(),
            state: state_from_redirect(outcome),
            now: Timestamp("2026-06-19T00:01:00Z".into()),
            session_expires_at: Timestamp("2026-06-20T00:00:00Z".into()),
            session_cookie_max_age_secs: Some(3600),
        })
    }

    #[test]
    fn list_providers_hides_disabled_providers() {
        let mut api = api();
        api.register_provider(ProviderRegistration {
            config: IdentityProviderConfig {
                provider_key: IdentityProviderKey("github".into()),
                enabled: false,
                ..config(false)
            },
            adapter: Box::new(FakeAdapter),
            redirect_uri: "https://app.example/v1/auth/callback/github".into(),
            scopes: vec![],
            include_nonce: false,
            include_pkce: true,
        });

        let providers = api.list_providers();
        assert_eq!(providers.len(), 1);
        assert_eq!(
            providers[0].provider_key,
            IdentityProviderKey("fake".into())
        );
        assert_eq!(providers[0].kind, IdentityProviderKind::Fake);
    }

    #[test]
    fn start_login_unknown_provider_fails_closed() {
        let mut api = api();
        let err = api
            .start_login(StartLogin {
                provider_key: IdentityProviderKey("nope".into()),
                return_to: None,
                created_at: Timestamp("2026-06-19T00:00:00Z".into()),
                expires_at: Timestamp("2026-06-19T00:05:00Z".into()),
                cookie_max_age_secs: None,
            })
            .unwrap_err();
        assert_eq!(
            err,
            AuthApiError::UnknownProvider(IdentityProviderKey("nope".into()))
        );
    }

    #[test]
    fn full_login_loop_provisions_account_and_establishes_session() {
        let mut api = api();
        let outcome = start(&mut api, Some("/dashboard"));
        assert!(outcome.set_cookie.contains(DEFAULT_LOGIN_COOKIE_NAME));
        assert!(outcome.set_cookie.contains("; HttpOnly"));
        assert!(outcome.set_cookie.contains("; Secure"));
        assert_eq!(
            outcome.return_to,
            ReturnToDecision::Allowed("/dashboard".into())
        );

        let result = callback(&mut api, &outcome, "subject-1:user@example.com").unwrap();
        assert!(result.registered);
        assert_eq!(result.redirect_to, "/dashboard");
        assert!(
            result
                .set_session_cookie
                .contains(DEFAULT_SESSION_COOKIE_NAME)
        );
        assert!(result.clear_login_cookie.contains("; Max-Age=0"));

        // The new session resolves from its cookie.
        let session_cookie = {
            let token = SessionCookieConfig::default()
                .extract_token(&result.set_session_cookie)
                .unwrap();
            format!("{DEFAULT_SESSION_COOKIE_NAME}={token}")
        };
        let view = api
            .current_session(&session_cookie, Timestamp("2026-06-19T01:00:00Z".into()))
            .unwrap();
        assert_eq!(view.session_id, result.session.session_id);

        // A second login for the same provider subject reuses the account.
        let outcome2 = start(&mut api, None);
        let result2 = callback(&mut api, &outcome2, "subject-1:new@example.com").unwrap();
        assert!(!result2.registered);
        assert_eq!(result2.session.account_id, result.session.account_id);
        // Default return_to applies when none was requested.
        assert_eq!(result2.redirect_to, "/home");

        // The audit trail records both login transitions.
        let succeeded = api
            .audit_log()
            .iter()
            .filter(|event| matches!(event, AuthAuditEvent::LoginSucceeded { .. }))
            .count();
        assert_eq!(succeeded, 2);
    }

    #[test]
    fn return_to_open_redirect_is_rejected_and_audited() {
        let mut api = api();
        let outcome = start(&mut api, Some("https://evil.example/steal"));
        assert_eq!(
            outcome.return_to,
            ReturnToDecision::RejectedFallback("/home".into())
        );
        assert!(
            api.audit_log()
                .iter()
                .any(|event| matches!(event, AuthAuditEvent::ReturnToRejected { .. }))
        );

        // The callback honours the safe default, not the crafted destination.
        let result = callback(&mut api, &outcome, "subject-1:user@example.com").unwrap();
        assert_eq!(result.redirect_to, "/home");
    }

    #[test]
    fn protocol_relative_return_to_is_rejected() {
        let policy = ReturnToPolicy::default();
        assert_eq!(
            policy.resolve(Some("//evil.example")),
            ReturnToDecision::RejectedFallback("/".into())
        );
        assert_eq!(
            policy.resolve(Some("/safe/path")),
            ReturnToDecision::Allowed("/safe/path".into())
        );
    }

    #[test]
    fn callback_without_correlation_cookie_fails_and_audits() {
        let mut api = api();
        let outcome = start(&mut api, Some("/dashboard"));
        let err = api
            .complete_callback(CallbackRequest {
                provider_key: IdentityProviderKey("fake".into()),
                cookie_header: "unrelated=1".into(),
                code: "subject-1:user@example.com".into(),
                state: state_from_redirect(&outcome),
                now: Timestamp("2026-06-19T00:01:00Z".into()),
                session_expires_at: Timestamp("2026-06-20T00:00:00Z".into()),
                session_cookie_max_age_secs: None,
            })
            .unwrap_err();
        assert_eq!(err, AuthApiError::MissingCorrelation);
        assert!(api.audit_log().iter().any(|event| matches!(
            event,
            AuthAuditEvent::LoginFailed {
                reason: AuthFailureReason::MissingCorrelation,
                ..
            }
        )));
    }

    #[test]
    fn forged_state_fails_closed_and_burns_challenge() {
        let mut api = api();
        let outcome = start(&mut api, Some("/dashboard"));
        let err = api
            .complete_callback(CallbackRequest {
                provider_key: IdentityProviderKey("fake".into()),
                cookie_header: login_cookie_header(&outcome),
                code: "subject-1:user@example.com".into(),
                state: "forged-state".into(),
                now: Timestamp("2026-06-19T00:01:00Z".into()),
                session_expires_at: Timestamp("2026-06-20T00:00:00Z".into()),
                session_cookie_max_age_secs: None,
            })
            .unwrap_err();
        assert!(matches!(
            err,
            AuthApiError::Login(IamError::LoginStateMismatch { .. })
        ));
        assert!(api.audit_log().iter().any(|event| matches!(
            event,
            AuthAuditEvent::LoginFailed {
                reason: AuthFailureReason::StateMismatch,
                ..
            }
        )));

        // The burned challenge cannot be replayed even with the correct state.
        let replay = callback(&mut api, &outcome, "subject-1:user@example.com").unwrap_err();
        assert!(matches!(replay, AuthApiError::MissingCorrelation));
    }

    #[test]
    fn logout_revokes_session_and_clears_cookie() {
        let mut api = api();
        let outcome = start(&mut api, Some("/dashboard"));
        let result = callback(&mut api, &outcome, "subject-1:user@example.com").unwrap();
        let token = SessionCookieConfig::default()
            .extract_token(&result.set_session_cookie)
            .unwrap();
        let cookie = format!("{DEFAULT_SESSION_COOKIE_NAME}={token}");

        let logout = api
            .logout(&cookie, Timestamp("2026-06-19T02:00:00Z".into()))
            .unwrap();
        assert!(logout.clear_session_cookie.contains("; Max-Age=0"));
        assert!(
            api.audit_log()
                .iter()
                .any(|event| matches!(event, AuthAuditEvent::LoggedOut { .. }))
        );

        // After logout the session no longer authenticates.
        let err = api
            .current_session(&cookie, Timestamp("2026-06-19T03:00:00Z".into()))
            .unwrap_err();
        assert!(matches!(
            err,
            AuthApiError::Login(IamError::SessionRevoked { .. })
        ));
    }

    #[test]
    fn link_list_and_unlink_external_identities() {
        let mut api = api();
        let outcome = start(&mut api, Some("/dashboard"));
        let result = callback(&mut api, &outcome, "subject-1:user@example.com").unwrap();
        let account_id = result.session.account_id.clone();

        // Link a second provider identity to the same account.
        let linked = api
            .link_identity(LinkIdentity {
                account_id: account_id.clone(),
                provider_key: IdentityProviderKey("github".into()),
                claims: ExternalIdentityClaims {
                    subject: ExternalSubject("gh-1".into()),
                    email: Some("user@github.test".into()),
                    email_verified: Some(true),
                    display_name: None,
                    username: Some("octocat".into()),
                    avatar_url: None,
                    locale: None,
                },
                now: Timestamp("2026-06-19T04:00:00Z".into()),
            })
            .unwrap();
        assert_eq!(linked.account_id, account_id);

        let identities = api.list_identities(&account_id);
        assert_eq!(identities.len(), 2);

        // Unlinking an identity owned by a different account fails closed.
        let mismatch = api
            .unlink_identity(UnlinkIdentity {
                account_id: AccountId("acct_other".into()),
                provider_key: IdentityProviderKey("github".into()),
                subject: ExternalSubject("gh-1".into()),
                now: Timestamp("2026-06-19T05:00:00Z".into()),
            })
            .unwrap_err();
        assert_eq!(mismatch, AuthApiError::IdentityAccountMismatch);

        // Unlinking the owned identity removes it and audits the change.
        api.unlink_identity(UnlinkIdentity {
            account_id: account_id.clone(),
            provider_key: IdentityProviderKey("github".into()),
            subject: ExternalSubject("gh-1".into()),
            now: Timestamp("2026-06-19T05:00:00Z".into()),
        })
        .unwrap();
        assert_eq!(api.list_identities(&account_id).len(), 1);
        assert!(
            api.audit_log()
                .iter()
                .any(|event| matches!(event, AuthAuditEvent::IdentityUnlinked { .. }))
        );
    }

    #[test]
    fn linking_a_subject_twice_is_rejected() {
        let mut api = api();
        let link = || LinkIdentity {
            account_id: AccountId("acct_1".into()),
            provider_key: IdentityProviderKey("github".into()),
            claims: ExternalIdentityClaims {
                subject: ExternalSubject("gh-1".into()),
                email: None,
                email_verified: None,
                display_name: None,
                username: None,
                avatar_url: None,
                locale: None,
            },
            now: Timestamp("2026-06-19T04:00:00Z".into()),
        };
        api.link_identity(link()).unwrap();
        let err = api.link_identity(link()).unwrap_err();
        assert!(matches!(
            err,
            AuthApiError::Login(IamError::DuplicateExternalIdentity { .. })
        ));
    }

    #[test]
    fn openid_configuration_advertises_canonical_endpoints() {
        let api = api();
        // A trailing slash on the issuer must not double the path separator.
        let metadata = api.openid_configuration("https://iam.example/");
        assert_eq!(metadata.issuer, "https://iam.example");
        assert_eq!(
            metadata.authorization_endpoint,
            "https://iam.example/v1/auth/login"
        );
        assert_eq!(
            metadata.token_endpoint,
            "https://iam.example/v1/oauth/token"
        );
        assert_eq!(
            metadata.userinfo_endpoint,
            "https://iam.example/v1/oauth/userinfo"
        );
        assert_eq!(
            metadata.jwks_uri,
            "https://iam.example/.well-known/jwks.json"
        );
        assert_eq!(metadata.response_types_supported, vec!["code".to_owned()]);
        assert!(metadata.scopes_supported.contains(&"openid".to_owned()));

        // The discovery document round-trips through the OIDC wire field names.
        let json = serde_json::to_value(&metadata).unwrap();
        assert_eq!(json["issuer"], "https://iam.example");
        assert_eq!(
            json["userinfo_endpoint"],
            "https://iam.example/v1/oauth/userinfo"
        );
    }

    #[test]
    fn userinfo_projects_session_subject_and_claims() {
        let mut api = api();
        let outcome = start(&mut api, Some("/dashboard"));
        let result = callback(&mut api, &outcome, "subject-1:user@example.com").unwrap();
        let session_cookie = {
            let token = SessionCookieConfig::default()
                .extract_token(&result.set_session_cookie)
                .unwrap();
            format!("{DEFAULT_SESSION_COOKIE_NAME}={token}")
        };

        let userinfo = api
            .userinfo(&session_cookie, Timestamp("2026-06-19T01:30:00Z".into()))
            .unwrap();
        // `sub` is IAM's account subject, not the upstream provider subject.
        assert_eq!(userinfo.sub, result.session.account_id.0);
        assert_ne!(userinfo.sub, "subject-1");
        assert_eq!(userinfo.email.as_deref(), Some("user@example.com"));
        assert_eq!(userinfo.email_verified, Some(true));
        assert_eq!(userinfo.name.as_deref(), Some("Fake User"));
        assert!(userinfo.updated_at.is_some());

        // Absent claims are omitted from the serialized response.
        let json = serde_json::to_value(&userinfo).unwrap();
        assert!(json.get("picture").is_none());
        assert_eq!(json["email"], "user@example.com");
    }

    #[test]
    fn userinfo_fails_closed_without_a_session() {
        let mut api = api();
        let err = api
            .userinfo("unrelated=1", Timestamp("2026-06-19T01:30:00Z".into()))
            .unwrap_err();
        assert!(matches!(
            err,
            AuthApiError::Login(IamError::SessionNotFound { .. })
        ));
    }

    #[test]
    fn userinfo_fails_closed_after_logout() {
        let mut api = api();
        let outcome = start(&mut api, Some("/dashboard"));
        let result = callback(&mut api, &outcome, "subject-1:user@example.com").unwrap();
        let token = SessionCookieConfig::default()
            .extract_token(&result.set_session_cookie)
            .unwrap();
        let cookie = format!("{DEFAULT_SESSION_COOKIE_NAME}={token}");

        api.logout(&cookie, Timestamp("2026-06-19T02:00:00Z".into()))
            .unwrap();

        let err = api
            .userinfo(&cookie, Timestamp("2026-06-19T03:00:00Z".into()))
            .unwrap_err();
        assert!(matches!(
            err,
            AuthApiError::Login(IamError::SessionRevoked { .. })
        ));
    }

    /// Drive a full login and return the live session cookie header a product
    /// service forwards to IAM on a subsequent request.
    fn logged_in_session(api: &mut AuthApi<SequentialEntropy>) -> (CallbackOutcome, String) {
        let outcome = start(api, Some("/dashboard"));
        let result = callback(api, &outcome, "subject-1:user@example.com").unwrap();
        let token = SessionCookieConfig::default()
            .extract_token(&result.set_session_cookie)
            .unwrap();
        let cookie = format!("{DEFAULT_SESSION_COOKIE_NAME}={token}");
        (result, cookie)
    }

    #[test]
    fn product_resolves_principal_from_iam_session() {
        let mut api = api();
        let (result, cookie) = logged_in_session(&mut api);

        // The product forwards only the opaque IAM session cookie — never a
        // Google or GitHub token — and IAM resolves the account principal.
        let principal = api
            .resolve_principal(&cookie, Timestamp("2026-06-19T01:00:00Z".into()))
            .unwrap();
        assert_eq!(
            principal,
            PrincipalRef::Account {
                account_id: result.session.account_id.clone(),
            }
        );
        assert!(
            api.audit_log()
                .iter()
                .any(|event| matches!(event, AuthAuditEvent::PrincipalResolved { .. }))
        );
    }

    #[test]
    fn session_principal_drives_remote_authorize() {
        use crate::AuthzApi;
        use awaken_iam_contract::{
            ActionKey, AuthorizationDecision, AuthorizationRequest, ScopeRef,
        };
        use awaken_iam_core::{ActionPattern, Effect, Grant, GrantId, GrantSubject};

        let mut api = api();
        let (_result, cookie) = logged_in_session(&mut api);
        let principal = api
            .resolve_principal(&cookie, Timestamp("2026-06-19T01:00:00Z".into()))
            .unwrap();

        // The product takes the session-resolved principal to the authorization
        // seam (`POST /v1/authorize`). Default-deny without a grant.
        let publish = AuthorizationRequest::direct(
            principal.clone(),
            ActionKey("pack.publish".into()),
            ScopeRef::Global,
        );
        let mut authz = AuthzApi::new();
        assert_eq!(
            authz.authorize(&publish).decision,
            AuthorizationDecision::Deny
        );

        // Granting the action to the session principal flips the decision —
        // proving the product authorizes the principal IAM resolved, not one it
        // asserts on its own.
        authz.policy_mut().add_grant(Grant {
            id: GrantId("g1".into()),
            subject: GrantSubject::Principal(principal.clone()),
            action_pattern: ActionPattern("pack.publish".into()),
            scope: ScopeRef::Global,
            effect: Effect::Allow,
        });
        assert_eq!(
            authz.authorize(&publish).decision,
            AuthorizationDecision::Allow
        );
    }

    #[test]
    fn resolve_principal_without_session_fails_closed() {
        let mut api = api();
        let err = api
            .resolve_principal("unrelated=1", Timestamp("2026-06-19T01:00:00Z".into()))
            .unwrap_err();
        assert_eq!(err, AuthApiError::Unauthenticated);
        assert!(api.audit_log().iter().any(|event| matches!(
            event,
            AuthAuditEvent::PrincipalResolutionFailed {
                reason: PrincipalResolutionFailure::Unauthenticated,
                ..
            }
        )));
    }

    #[test]
    fn resolve_principal_after_logout_fails_closed() {
        let mut api = api();
        let (_result, cookie) = logged_in_session(&mut api);
        api.logout(&cookie, Timestamp("2026-06-19T02:00:00Z".into()))
            .unwrap();

        // A revoked session cannot be replayed to resolve a principal.
        let err = api
            .resolve_principal(&cookie, Timestamp("2026-06-19T03:00:00Z".into()))
            .unwrap_err();
        assert_eq!(err, AuthApiError::Unauthenticated);
    }

    #[test]
    fn resolve_principal_for_disabled_account_fails_closed() {
        let mut api = api();
        let (result, cookie) = logged_in_session(&mut api);
        let account_id = result.session.account_id.clone();

        // Disable the account behind the otherwise-live session.
        let mut account = api.directory().account(&account_id).unwrap().clone();
        account.status = AccountStatus::Disabled;
        account.updated_at = Timestamp("2026-06-19T02:00:00Z".into());
        api.directory.upsert_account(account);

        let err = api
            .resolve_principal(&cookie, Timestamp("2026-06-19T03:00:00Z".into()))
            .unwrap_err();
        assert_eq!(err, AuthApiError::AccountDisabled);
        assert!(api.audit_log().iter().any(|event| matches!(
            event,
            AuthAuditEvent::PrincipalResolutionFailed {
                reason: PrincipalResolutionFailure::AccountDisabled,
                ..
            }
        )));
    }
}
