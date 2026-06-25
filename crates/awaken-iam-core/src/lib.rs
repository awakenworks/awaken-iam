//! Core IAM evaluation primitives.

mod api_token;
mod authorization;
mod consumer_namespace;
mod directory;
mod entitlement;
mod events;
mod fake_provider;
mod generic_oauth;
mod github;
mod google;
mod linking;
mod login;
mod oauth_provider;
mod ports;
mod provider;
mod provision;
mod refresh_token;
mod resource_model;
mod session;
mod shadow;
pub mod smoke;
mod trust;

use std::collections::HashMap;
use std::collections::hash_map::Entry;

pub use api_token::{
    ApiTokenDirectory, ApiTokenMinter, IssuedApiToken, MintApiToken, parse_presented_token,
};
pub use authorization::{
    ActionPattern, AuthorizationTrace, DecisionReason, Effect, Grant, GrantId, GrantSubject,
    GroupRoleBinding, PolicySet, RoleBinding, RoleId, ScopeGraph,
};
pub use consumer_namespace::{ConsumerNamespaces, action_namespace};
pub use directory::{Group, GroupId, Organization, RoleDef, RoleInvariant};
pub use entitlement::{
    EntitlementCatalog, EntitlementEngine, EntitlementMode, EntitlementOutcome,
    EntitlementProvider, EntitlementReason, EntitlementResolver, LicenseEntitlements, Plan, PlanId,
    PlanTier, Quota, RateLimit, RateWindow,
};
pub use events::{AuditLedger, DecisionTrace, DomainEvent};
pub use fake_provider::{
    AuthorizeRedirect, AuthorizeRequest, FailureMode, FakeOidcProvider, FakeUser, IdTokenClaims,
    JsonWebKey, JsonWebKeySet, OidcDiscoveryDocument, OidcError, TokenRequest, TokenResponse,
    UserInfoResponse,
};
pub use generic_oauth::{GenericOAuthProvider, GenericOAuthSecrets};
pub use github::{
    DEFAULT_AUTHORIZE_ENDPOINT, DEFAULT_TOKEN_ENDPOINT, GithubAccessToken, GithubEmail,
    GithubProviderAdapter, GithubTransport, GithubTransportError, GithubUser, SelectedEmail,
    TokenRequest as GithubTokenRequest, select_email,
};
pub use google::{
    Clock, GOOGLE_AUTHORIZATION_ENDPOINT, GOOGLE_ISSUER, GOOGLE_ISSUER_BARE, GOOGLE_JWKS_URI,
    GOOGLE_TOKEN_ENDPOINT, GoogleOidcProvider, GoogleProviderSecrets, HttpRequest, HttpTransport,
    IdTokenVerification, Jwk, JwkSet, JwsVerifier, SystemClock, verify_id_token,
};
pub use linking::{AccountLinker, LoginResolution, ResolveLogin};
pub use login::{
    BeginLogin, EntropySource, IssuedLogin, LoginAttempt, LoginSecrets, OAuthChallengeService,
    OsEntropy, PkceChallenge, PkceMethod,
};
pub use oauth_provider::{
    AuthorizationRequest as OAuthAuthorizationRequest, AuthorizedGrant, IssuedAuthorizationCode,
    OAuthAuthorizationServer, OAuthClientRegistry, OAuthProviderError, RegisteredClient,
    TokenRedemption,
};
pub use ports::{
    AccountRepo, ApiTokenRepo, AuditEvent, AuditSink, ExternalIdentityRepo, GrantRepo, GroupRepo,
    LoginFlowRepo, OAuthClientRepo, OrgRepo, PlanRepo, RepoError, RepoResult, ResourceModelRepo,
    RoleBindingRepo, RoleRepo, SessionRepo, external_identity_id_hint, seed_roles,
};
pub use provider::{
    AuthorizationRedirect, AuthorizationUrlRequest, CallbackExchange, IdentityProviderAdapter,
    ProviderError,
};
pub use provision::apply_resource_provision;
pub use refresh_token::{
    IssuedRefreshToken, MintRefreshToken, RefreshTokenDirectory, RefreshTokenMinter,
    RotateRefreshToken, parse_presented_refresh_token,
};
pub use resource_model::{ResourceEdge, ResourceModel, ResourceTypeDef};
pub use session::{EstablishSession, IssuedSession, SessionMinter, hash_session_token};
pub use shadow::{DecisionSource, Divergence, ShadowAuthorizer, ShadowOutcome, ShadowReport};
pub use trust::{NamespaceGrant, NamespaceTrustDirectory, TrustError};

use awaken_iam_contract::{
    Account, AccountId, ApiTokenId, ApiTokenPrefix, AuthorizationDecision, AuthorizationRequest,
    ExternalIdentity, ExternalIdentityClaims, ExternalIdentityKey, ExternalSubject,
    IdentityProviderKey, OAuthLoginState, OAuthLoginStateId, RefreshTokenChainId, RefreshTokenId,
    Session, SessionId, Timestamp,
};

/// Identifies which bound login value failed verification on callback.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LoginBinding {
    /// The opaque OAuth `state` value.
    State,
    /// The OIDC `nonce` value.
    Nonce,
    /// The PKCE code verifier.
    PkceVerifier,
}

/// Errors returned by IAM evaluation.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum IamError {
    /// The request could not be evaluated because required identity data is missing.
    #[error("missing principal")]
    MissingPrincipal,
    /// An external provider subject is already linked to an account.
    #[error("external identity is already linked")]
    DuplicateExternalIdentity {
        /// Provider key that issued the subject.
        provider_key: IdentityProviderKey,
        /// Provider-scoped subject.
        subject: ExternalSubject,
        /// Account already linked to this provider subject.
        existing_account_id: AccountId,
    },
    /// The requested external identity does not exist.
    #[error("external identity was not found")]
    ExternalIdentityNotFound {
        /// Provider key that issued the subject.
        provider_key: IdentityProviderKey,
        /// Provider-scoped subject.
        subject: ExternalSubject,
    },
    /// The external identity exists but is linked to a different account than the
    /// one the unlink was requested for.
    #[error("external identity is linked to a different account")]
    ExternalIdentityNotLinkedToAccount {
        /// Provider key that issued the subject.
        provider_key: IdentityProviderKey,
        /// Provider-scoped subject.
        subject: ExternalSubject,
        /// Account the unlink was requested for.
        account_id: AccountId,
    },
    /// Unlinking the requested identity would orphan the account from its last
    /// remaining sign-in method, so it is refused.
    #[error("cannot unlink the account's last external identity")]
    CannotUnlinkLastIdentity {
        /// Account that would be left with no external identity.
        account_id: AccountId,
    },
    /// A new account could not be created because the id is already in use.
    #[error("account already exists")]
    DuplicateAccount {
        /// Conflicting account id.
        id: AccountId,
    },
    /// A login-state challenge with this id was already started.
    #[error("login state is already started")]
    DuplicateLoginState {
        /// Conflicting login-state id.
        id: OAuthLoginStateId,
    },
    /// The referenced login-state challenge does not exist.
    #[error("login state was not found")]
    LoginStateNotFound {
        /// Missing login-state id.
        id: OAuthLoginStateId,
    },
    /// The login-state challenge has already been consumed and cannot be reused.
    #[error("login state was already consumed")]
    LoginStateAlreadyConsumed {
        /// Consumed login-state id.
        id: OAuthLoginStateId,
    },
    /// The OIDC provider returned a validation error.
    #[error("provider validation error")]
    ProviderValidationError {
        /// The original error returned by the provider.
        error: String,
    },
    /// The login-state challenge failed to verify at least one of its OIDC bindings.
    #[error("login state binding verification failed")]
    LoginStateBindingFailed {
        /// Binding that failed.
        binding: LoginBinding,
    },
    /// The login-state challenge expired before it was consumed.
    #[error("login state has expired")]
    LoginStateExpired {
        /// Expired login-state id.
        id: OAuthLoginStateId,
    },
    /// A presented login binding (state, nonce, or PKCE verifier) did not match
    /// the value bound when the challenge was issued.
    #[error("login state binding mismatch: {binding:?}")]
    LoginStateMismatch {
        /// Login-state id whose binding failed to verify.
        id: OAuthLoginStateId,
        /// Which bound value failed verification.
        binding: LoginBinding,
    },
    /// The requested login window was not a valid forward-going TTL.
    #[error("login state window is invalid")]
    InvalidLoginWindow {
        /// Login-state id with the rejected window.
        id: OAuthLoginStateId,
    },
    /// The requested session window was not a valid forward-going TTL.
    #[error("session window is invalid")]
    InvalidSessionWindow {
        /// Session id with the rejected window.
        id: SessionId,
    },
    /// A session with this id already exists.
    #[error("session already exists")]
    DuplicateSession {
        /// Conflicting session id.
        id: SessionId,
    },
    /// The referenced session does not exist.
    #[error("session was not found")]
    SessionNotFound {
        /// Missing session id.
        id: SessionId,
    },
    /// The session was revoked and can no longer authenticate.
    #[error("session was revoked")]
    SessionRevoked {
        /// Revoked session id.
        id: SessionId,
    },
    /// The session expired and can no longer authenticate.
    #[error("session has expired")]
    SessionExpired {
        /// Expired session id.
        id: SessionId,
    },
    /// The requested API-token expiry was not strictly after creation.
    #[error("api token window is invalid")]
    InvalidApiTokenWindow {
        /// API-token id with the rejected window.
        id: ApiTokenId,
    },
    /// An API token with this id already exists.
    #[error("api token already exists")]
    DuplicateApiToken {
        /// Conflicting API-token id.
        id: ApiTokenId,
    },
    /// An API token with this public prefix already exists.
    #[error("api token prefix already exists")]
    DuplicateApiTokenPrefix {
        /// Conflicting API-token prefix.
        prefix: ApiTokenPrefix,
    },
    /// The referenced API token does not exist.
    #[error("api token was not found")]
    ApiTokenNotFound {
        /// Missing API-token id.
        id: ApiTokenId,
    },
    /// A presented API token could not be authenticated.
    ///
    /// An unparseable token, an unknown prefix, and a wrong secret all collapse
    /// to this single opaque error so a caller cannot probe which tokens exist.
    #[error("api token is invalid")]
    ApiTokenInvalid,
    /// The API token was revoked and can no longer authenticate.
    #[error("api token was revoked")]
    ApiTokenRevoked {
        /// Revoked API-token id.
        id: ApiTokenId,
    },
    /// The API token expired and can no longer authenticate.
    #[error("api token has expired")]
    ApiTokenExpired {
        /// Expired API-token id.
        id: ApiTokenId,
    },
    /// Hashing or verifying an API-token secret failed.
    #[error("api token hashing failed: {detail}")]
    ApiTokenHashFailure {
        /// Underlying argon2 error detail.
        detail: String,
    },
    /// The requested refresh-token expiry was not strictly after creation.
    #[error("refresh token window is invalid")]
    InvalidRefreshTokenWindow {
        /// Refresh-token id with the rejected window.
        id: RefreshTokenId,
    },
    /// A refresh token with this id already exists.
    #[error("refresh token already exists")]
    DuplicateRefreshToken {
        /// Conflicting refresh-token id.
        id: RefreshTokenId,
    },
    /// Two refresh tokens hashed to the same stored value (entropy collision).
    #[error("refresh token hash already exists")]
    DuplicateRefreshTokenHash,
    /// A presented refresh token could not be matched to a live chain.
    ///
    /// An unparseable token, an unknown hash, and a revoked chain all collapse to
    /// this single opaque error so a caller cannot probe which tokens exist.
    #[error("refresh token is invalid")]
    RefreshTokenInvalid,
    /// The refresh token expired and can no longer be rotated.
    #[error("refresh token has expired")]
    RefreshTokenExpired {
        /// Expired refresh-token id.
        id: RefreshTokenId,
    },
    /// A retired refresh token was replayed — a theft signal. The whole chain is
    /// revoked as a side effect.
    #[error("refresh token was reused; the chain has been revoked")]
    RefreshTokenReuseDetected {
        /// Chain revoked in response to the replay.
        chain_id: RefreshTokenChainId,
    },
}

/// Authorization evaluator over an in-process [`PolicySet`].
///
/// Evaluation is default-deny: an empty policy denies every request. Grants and
/// role bindings are added to the [`PolicySet`] and resolved through the scope
/// graph, with deny effects taking precedence over allow.
#[derive(Debug, Default)]
pub struct IamCore {
    policy: PolicySet,
}

impl IamCore {
    /// Create an IAM core evaluator with an empty (default-deny) policy.
    pub fn new() -> Self {
        Self::default()
    }

    /// Create an IAM core evaluator backed by `policy`.
    pub fn with_policy(policy: PolicySet) -> Self {
        Self { policy }
    }

    /// Mutable access to the policy for registering grants, role bindings, and
    /// scope-graph links.
    pub fn policy_mut(&mut self) -> &mut PolicySet {
        &mut self.policy
    }

    /// Read-only access to the policy.
    pub fn policy(&self) -> &PolicySet {
        &self.policy
    }

    /// Evaluate authorization and return only the allow/deny decision.
    pub fn authorize(&self, request: &AuthorizationRequest) -> AuthorizationDecision {
        self.evaluate(request).decision
    }

    /// Evaluate authorization and return the full decision trace (decision,
    /// reason code, and matched grant/role ids).
    pub fn evaluate(&self, request: &AuthorizationRequest) -> AuthorizationTrace {
        self.policy.evaluate(request)
    }

    /// Filter `candidates` to the scopes on which `principal` may perform
    /// `action`, in input order, in a single pass. Lets list endpoints answer
    /// "which of these rows are visible" without one authorize call per row.
    pub fn visible(
        &self,
        principal: &awaken_iam_contract::PrincipalRef,
        action: &awaken_iam_contract::ActionKey,
        candidates: &[awaken_iam_contract::ScopeRef],
    ) -> Vec<awaken_iam_contract::ScopeRef> {
        self.policy.visible(principal, action, candidates)
    }

    /// Evaluate entitlement. v1 starts as default-allow seam until billing / SKU
    /// management and true entitlement controls are wired in downstream.
    pub fn entitle(&self) -> EntitlementEngine {
        EntitlementEngine::default()
    }
}

/// Minimal identity directory enforcing account/external-identity invariants.
#[derive(Debug, Default)]
pub struct IdentityDirectory {
    accounts: HashMap<AccountId, Account>,
    external_identities: HashMap<ExternalIdentityKey, ExternalIdentity>,
}

impl IdentityDirectory {
    /// Create an empty identity directory.
    pub fn new() -> Self {
        Self::default()
    }

    /// Insert or replace account metadata.
    pub fn upsert_account(&mut self, account: Account) {
        self.accounts.insert(account.id.clone(), account);
    }

    /// Get an account by id.
    pub fn account(&self, account_id: &AccountId) -> Option<&Account> {
        self.accounts.get(account_id)
    }

    /// Link a provider subject to an account.
    ///
    /// The uniqueness key is `(provider_key, subject)`. Mutable claims such as
    /// email do not participate in identity lookup.
    pub fn link_external_identity(&mut self, identity: ExternalIdentity) -> Result<(), IamError> {
        let key = identity.key();
        match self.external_identities.entry(key) {
            Entry::Vacant(entry) => {
                entry.insert(identity);
                Ok(())
            }
            Entry::Occupied(entry) => {
                let existing = entry.get();
                Err(IamError::DuplicateExternalIdentity {
                    provider_key: existing.provider_key.clone(),
                    subject: existing.claims.subject.clone(),
                    existing_account_id: existing.account_id.clone(),
                })
            }
        }
    }

    /// Refresh mutable claims for an existing external identity.
    pub fn update_external_identity_claims(
        &mut self,
        provider_key: IdentityProviderKey,
        claims: ExternalIdentityClaims,
        last_seen_at: Timestamp,
    ) -> Result<&ExternalIdentity, IamError> {
        let key = ExternalIdentityKey::from_claims(provider_key.clone(), &claims);
        let identity = self.external_identities.get_mut(&key).ok_or_else(|| {
            IamError::ExternalIdentityNotFound {
                provider_key,
                subject: claims.subject.clone(),
            }
        })?;
        identity.claims = claims;
        identity.last_seen_at = last_seen_at;
        Ok(identity)
    }

    /// Resolve an account already linked to a verified copy of `email`.
    ///
    /// This backs the email-match confirmation policy: a login whose
    /// `(provider, subject)` is unknown may still belong to a person who already
    /// holds an account under the same verified email through another provider.
    /// Matching is case-insensitive and considers only identities whose provider
    /// asserted the email *verified* — an unverified claim can never select an
    /// account, so a forged or unconfirmed email cannot reach someone else's
    /// account. The owning account of the lexicographically-smallest matching
    /// external identity id is returned for a deterministic candidate.
    pub fn account_for_verified_email(&self, email: &str) -> Option<AccountId> {
        let needle = email.trim().to_ascii_lowercase();
        if needle.is_empty() {
            return None;
        }
        let mut matches: Vec<&ExternalIdentity> = self
            .external_identities
            .values()
            .filter(|identity| identity.claims.email_verified == Some(true))
            .filter(|identity| {
                identity
                    .claims
                    .email
                    .as_deref()
                    .map(|email| email.trim().to_ascii_lowercase())
                    .as_deref()
                    == Some(needle.as_str())
            })
            .collect();
        matches.sort_by(|left, right| left.id.0.cmp(&right.id.0));
        matches.first().map(|identity| identity.account_id.clone())
    }

    /// Resolve an external identity by provider and subject.
    pub fn external_identity(
        &self,
        provider_key: &IdentityProviderKey,
        subject: &ExternalSubject,
    ) -> Option<&ExternalIdentity> {
        self.external_identities.get(&ExternalIdentityKey {
            provider_key: provider_key.clone(),
            subject: subject.clone(),
        })
    }

    /// List the external identities linked to an account.
    ///
    /// Results are ordered by external identity id so callers and tests observe
    /// a stable sequence regardless of map iteration order.
    pub fn identities_for_account(&self, account_id: &AccountId) -> Vec<&ExternalIdentity> {
        let mut identities: Vec<&ExternalIdentity> = self
            .external_identities
            .values()
            .filter(|identity| &identity.account_id == account_id)
            .collect();
        identities.sort_by(|left, right| left.id.0.cmp(&right.id.0));
        identities
    }

    /// Remove the external identity for a provider subject, returning the
    /// detached link.
    ///
    /// Fails closed with [`IamError::ExternalIdentityNotFound`] when no identity
    /// matches the provider and subject.
    pub fn remove_external_identity(
        &mut self,
        provider_key: &IdentityProviderKey,
        subject: &ExternalSubject,
    ) -> Result<ExternalIdentity, IamError> {
        let key = ExternalIdentityKey {
            provider_key: provider_key.clone(),
            subject: subject.clone(),
        };
        self.external_identities
            .remove(&key)
            .ok_or_else(|| IamError::ExternalIdentityNotFound {
                provider_key: provider_key.clone(),
                subject: subject.clone(),
            })
    }
}

/// In-memory directory enforcing login-state and session invariants.
///
/// This closes the login loop on top of [`IdentityDirectory`]: an OAuth
/// login-state challenge is started once and consumed at most once, and the
/// resulting session can authenticate only while it is unrevoked and unexpired.
///
/// Timestamps are compared as canonical RFC 3339 UTC strings (`...Z`), which is
/// the form produced across the contract. Lexical ordering of that canonical
/// form matches chronological ordering.
#[derive(Debug, Default)]
pub struct SessionDirectory {
    login_states: HashMap<OAuthLoginStateId, OAuthLoginState>,
    sessions: HashMap<SessionId, Session>,
    /// Secondary index from session `token_hash` to session id, so a presented
    /// bearer token (the cookie value, hashed) resolves to its session without
    /// scanning. Populated on [`SessionDirectory::create_session`].
    sessions_by_token_hash: HashMap<String, SessionId>,
}

impl SessionDirectory {
    /// Create an empty session directory.
    pub fn new() -> Self {
        Self::default()
    }

    /// Record a freshly issued OAuth login-state challenge.
    ///
    /// Each login-state id may be started only once.
    pub fn start_login(&mut self, state: OAuthLoginState) -> Result<(), IamError> {
        match self.login_states.entry(state.id.clone()) {
            Entry::Vacant(entry) => {
                entry.insert(state);
                Ok(())
            }
            Entry::Occupied(entry) => Err(IamError::DuplicateLoginState {
                id: entry.key().clone(),
            }),
        }
    }

    /// Resolve a login-state challenge by id without consuming it.
    pub fn login_state(&self, id: &OAuthLoginStateId) -> Option<&OAuthLoginState> {
        self.login_states.get(id)
    }

    /// Consume a login-state challenge exactly once.
    ///
    /// The challenge must exist, be unexpired at `now`, and not have been
    /// consumed already. On success it is marked consumed and returned so the
    /// caller can validate the bound `state`/`nonce`/PKCE hashes.
    pub fn consume_login_state(
        &mut self,
        id: &OAuthLoginStateId,
        now: Timestamp,
    ) -> Result<&OAuthLoginState, IamError> {
        let state = self
            .login_states
            .get_mut(id)
            .ok_or_else(|| IamError::LoginStateNotFound { id: id.clone() })?;
        if state.consumed_at.is_some() {
            return Err(IamError::LoginStateAlreadyConsumed { id: id.clone() });
        }
        if now.0 >= state.expires_at.0 {
            return Err(IamError::LoginStateExpired { id: id.clone() });
        }
        state.consumed_at = Some(now);
        Ok(state)
    }

    /// Persist a newly established session.
    ///
    /// Each session id may be created only once. The session's `token_hash` is
    /// indexed so the session can later be resolved from a presented bearer
    /// token.
    pub fn create_session(&mut self, session: Session) -> Result<(), IamError> {
        match self.sessions.entry(session.id.clone()) {
            Entry::Vacant(entry) => {
                let token_hash = session.token_hash.clone();
                let id = session.id.clone();
                entry.insert(session);
                self.sessions_by_token_hash.insert(token_hash, id);
                Ok(())
            }
            Entry::Occupied(entry) => Err(IamError::DuplicateSession {
                id: entry.key().clone(),
            }),
        }
    }

    /// Resolve a session by id without checking its liveness.
    pub fn session(&self, id: &SessionId) -> Option<&Session> {
        self.sessions.get(id)
    }

    /// Resolve the session id bound to a `token_hash` without checking liveness.
    pub fn session_id_for_token_hash(&self, token_hash: &str) -> Option<&SessionId> {
        self.sessions_by_token_hash.get(token_hash)
    }

    /// Authenticate a session by its bearer `token_hash`, refreshing activity.
    ///
    /// Resolves the session bound to the presented token hash, then applies the
    /// same liveness rules as [`SessionDirectory::authenticate`]. An unknown
    /// token hash fails closed as [`IamError::SessionNotFound`].
    pub fn authenticate_by_token_hash(
        &mut self,
        token_hash: &str,
        now: Timestamp,
    ) -> Result<&Session, IamError> {
        let id = self
            .sessions_by_token_hash
            .get(token_hash)
            .cloned()
            .ok_or_else(|| IamError::SessionNotFound {
                id: SessionId(String::new()),
            })?;
        self.authenticate(&id, now)
    }

    /// Authenticate a session, refreshing its `last_seen_at` activity stamp.
    ///
    /// Returns an error when the session is unknown, revoked, or expired at
    /// `now`.
    pub fn authenticate(&mut self, id: &SessionId, now: Timestamp) -> Result<&Session, IamError> {
        let session = self
            .sessions
            .get_mut(id)
            .ok_or_else(|| IamError::SessionNotFound { id: id.clone() })?;
        if session.revoked_at.is_some() {
            return Err(IamError::SessionRevoked { id: id.clone() });
        }
        if now.0 >= session.expires_at.0 {
            return Err(IamError::SessionExpired { id: id.clone() });
        }
        session.last_seen_at = now;
        Ok(session)
    }

    /// Revoke a session so it can no longer authenticate.
    ///
    /// Revocation is idempotent: the first `revoked_at` stamp is preserved.
    pub fn revoke_session(&mut self, id: &SessionId, now: Timestamp) -> Result<(), IamError> {
        let session = self
            .sessions
            .get_mut(id)
            .ok_or_else(|| IamError::SessionNotFound { id: id.clone() })?;
        session.revoked_at.get_or_insert(now);
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn authorize_denies_empty_policy_by_default() {
        let core = IamCore::new();
        let request = AuthorizationRequest {
            principal: awaken_iam_contract::PrincipalRef::Account {
                account_id: AccountId("test".into()),
            },
            on_behalf_of: Vec::new(),
            action: awaken_iam_contract::ActionKey("pack.read".into()),
            scope: awaken_iam_contract::ScopeRef::Global,
        };
        assert_eq!(core.authorize(&request), AuthorizationDecision::Deny);
    }

    #[test]
    fn authorize_allows_through_a_loaded_policy() {
        let mut core = IamCore::new();
        core.policy_mut().add_grant(Grant {
            id: GrantId("g1".into()),
            subject: GrantSubject::Principal(awaken_iam_contract::PrincipalRef::Service {
                service_id: "svc".into(),
            }),
            action_pattern: ActionPattern("pack.publish".into()),
            scope: awaken_iam_contract::ScopeRef::Global,
            effect: Effect::Allow,
        });
        let request = AuthorizationRequest {
            principal: awaken_iam_contract::PrincipalRef::Service {
                service_id: "svc".into(),
            },
            on_behalf_of: Vec::new(),
            action: awaken_iam_contract::ActionKey("pack.publish".into()),
            scope: awaken_iam_contract::ScopeRef::Global,
        };

        assert_eq!(core.authorize(&request), AuthorizationDecision::Allow);
        let trace = core.evaluate(&request);
        assert_eq!(trace.reason, DecisionReason::AllowedByGrant);
        assert_eq!(trace.matched_grants, vec![GrantId("g1".into())]);
    }

    #[test]
    fn visible_filters_candidates_through_the_facade() {
        let mut core = IamCore::new();
        let principal = awaken_iam_contract::PrincipalRef::Account {
            account_id: AccountId("ada".into()),
        };
        core.policy_mut().add_grant(Grant {
            id: GrantId("g_global".into()),
            subject: GrantSubject::Principal(principal.clone()),
            action_pattern: ActionPattern("pack.read".into()),
            scope: awaken_iam_contract::ScopeRef::Global,
            effect: Effect::Allow,
        });

        let candidates = vec![
            awaken_iam_contract::ScopeRef::Namespace {
                namespace_id: awaken_iam_contract::NamespaceId("acme".into()),
            },
            awaken_iam_contract::ScopeRef::Global,
        ];
        let visible = core.visible(
            &principal,
            &awaken_iam_contract::ActionKey("pack.read".into()),
            &candidates,
        );
        // A global grant covers every candidate scope beneath it.
        assert_eq!(visible, candidates);
    }

    #[test]
    fn entitlement_seam_defaults_allow() {
        let request = awaken_iam_contract::EntitlementRequest {
            principal: awaken_iam_contract::PrincipalRef::Account {
                account_id: AccountId("test".into()),
            },
            entitlement: "model.strong_access".into(),
            resource: None,
        };
        let outcome = IamCore::new().entitle().evaluate(&request);
        assert_eq!(
            outcome.decision,
            awaken_iam_contract::EntitlementDecision::Allow
        );
        assert_eq!(outcome.reason, EntitlementReason::DefaultAllow);
    }
}
