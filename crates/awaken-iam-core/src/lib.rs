//! Core IAM evaluation primitives.

mod fake_provider;
mod github;
mod login;
mod provider;
mod session;

use std::collections::HashMap;
use std::collections::hash_map::Entry;

pub use fake_provider::{
    AuthorizeRedirect, AuthorizeRequest, FailureMode, FakeOidcProvider, FakeUser, IdTokenClaims,
    JsonWebKey, JsonWebKeySet, OidcDiscoveryDocument, OidcError, TokenRequest, TokenResponse,
    UserInfoResponse,
};
pub use github::{
    DEFAULT_AUTHORIZE_ENDPOINT, DEFAULT_TOKEN_ENDPOINT, GithubAccessToken, GithubEmail,
    GithubProviderAdapter, GithubTransport, GithubTransportError, GithubUser, SelectedEmail,
    TokenRequest, select_email,
};
pub use login::{
    BeginLogin, EntropySource, IssuedLogin, LoginAttempt, LoginSecrets, OAuthChallengeService,
    OsEntropy, PkceChallenge, PkceMethod,
};
pub use provider::{
    AuthorizationRedirect, AuthorizationUrlRequest, CallbackExchange, IdentityProviderAdapter,
    ProviderError,
};
pub use session::{EstablishSession, IssuedSession, SessionMinter, hash_session_token};

use awaken_iam_contract::{
    Account, AccountId, AuthorizationDecision, AuthorizationRequest, EntitlementDecision,
    ExternalIdentity, ExternalIdentityClaims, ExternalIdentityKey, ExternalSubject,
    IdentityProviderKey, OAuthLoginState, OAuthLoginStateId, Session, SessionId, Timestamp,
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
        /// Login-state id that was already consumed.
        id: OAuthLoginStateId,
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
}

/// Minimal authorizer seam.
#[derive(Debug, Default)]
pub struct IamCore;

impl IamCore {
    /// Create an IAM core evaluator.
    pub fn new() -> Self {
        Self
    }

    /// Evaluate authorization. The initial skeleton denies by default; concrete
    /// grant stores will extend this through explicit policy inputs.
    pub fn authorize(&self, _request: &AuthorizationRequest) -> AuthorizationDecision {
        AuthorizationDecision::Deny
    }

    /// Evaluate entitlement. v1 starts as default-allow seam until billing / SKU
    /// policy is implemented by a product deployment.
    pub fn entitlement_default_allow(&self) -> EntitlementDecision {
        EntitlementDecision::Allow
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
    use awaken_iam_contract::{
        AccountStatus, ActionKey, ExternalIdentityId, PrincipalRef, ScopeRef,
    };

    #[test]
    fn authorization_denies_by_default() {
        let core = IamCore::new();
        let request = AuthorizationRequest {
            principal: PrincipalRef::Service {
                service_id: "svc".into(),
            },
            action: ActionKey("pack.publish".into()),
            scope: ScopeRef::Global,
        };
        assert_eq!(core.authorize(&request), AuthorizationDecision::Deny);
    }

    #[test]
    fn entitlement_seam_defaults_allow() {
        assert_eq!(
            IamCore::new().entitlement_default_allow(),
            EntitlementDecision::Allow
        );
    }

    #[test]
    fn identity_directory_enforces_provider_subject_uniqueness() {
        let mut directory = IdentityDirectory::new();
        directory.upsert_account(account("acct_1"));
        directory.upsert_account(account("acct_2"));

        directory
            .link_external_identity(external_identity(
                "ext_1",
                "acct_1",
                "fake",
                "subject_1",
                Some("first@example.com"),
            ))
            .unwrap();

        let duplicate = directory
            .link_external_identity(external_identity(
                "ext_2",
                "acct_2",
                "fake",
                "subject_1",
                Some("second@example.com"),
            ))
            .unwrap_err();

        assert_eq!(
            duplicate,
            IamError::DuplicateExternalIdentity {
                provider_key: IdentityProviderKey("fake".into()),
                subject: ExternalSubject("subject_1".into()),
                existing_account_id: AccountId("acct_1".into()),
            }
        );
    }

    #[test]
    fn identity_directory_updates_email_as_mutable_claim() {
        let mut directory = IdentityDirectory::new();
        directory.upsert_account(account("acct_1"));
        directory
            .link_external_identity(external_identity(
                "ext_1",
                "acct_1",
                "fake",
                "subject_1",
                Some("first@example.com"),
            ))
            .unwrap();

        let updated = directory
            .update_external_identity_claims(
                IdentityProviderKey("fake".into()),
                claims("subject_1", Some("second@example.com")),
                Timestamp("2026-06-19T01:00:00Z".into()),
            )
            .unwrap();

        assert_eq!(updated.account_id, AccountId("acct_1".into()));
        assert_eq!(updated.claims.email.as_deref(), Some("second@example.com"));
        assert_eq!(
            directory
                .external_identity(
                    &IdentityProviderKey("fake".into()),
                    &ExternalSubject("subject_1".into())
                )
                .unwrap()
                .claims
                .email
                .as_deref(),
            Some("second@example.com")
        );
    }

    #[test]
    fn login_state_is_single_use() {
        let mut directory = SessionDirectory::new();
        directory
            .start_login(login_state("login_1", "2026-06-19T01:00:00Z"))
            .unwrap();

        let consumed = directory
            .consume_login_state(
                &OAuthLoginStateId("login_1".into()),
                Timestamp("2026-06-19T00:30:00Z".into()),
            )
            .unwrap();
        assert!(consumed.consumed_at.is_some());

        let reuse = directory
            .consume_login_state(
                &OAuthLoginStateId("login_1".into()),
                Timestamp("2026-06-19T00:31:00Z".into()),
            )
            .unwrap_err();
        assert_eq!(
            reuse,
            IamError::LoginStateAlreadyConsumed {
                id: OAuthLoginStateId("login_1".into()),
            }
        );
    }

    #[test]
    fn expired_login_state_cannot_be_consumed() {
        let mut directory = SessionDirectory::new();
        directory
            .start_login(login_state("login_1", "2026-06-19T01:00:00Z"))
            .unwrap();

        let expired = directory
            .consume_login_state(
                &OAuthLoginStateId("login_1".into()),
                Timestamp("2026-06-19T02:00:00Z".into()),
            )
            .unwrap_err();
        assert_eq!(
            expired,
            IamError::LoginStateExpired {
                id: OAuthLoginStateId("login_1".into()),
            }
        );
        assert!(
            directory
                .login_state(&OAuthLoginStateId("login_1".into()))
                .unwrap()
                .consumed_at
                .is_none()
        );
    }

    #[test]
    fn duplicate_login_state_is_rejected() {
        let mut directory = SessionDirectory::new();
        directory
            .start_login(login_state("login_1", "2026-06-19T01:00:00Z"))
            .unwrap();
        let duplicate = directory
            .start_login(login_state("login_1", "2026-06-19T03:00:00Z"))
            .unwrap_err();
        assert_eq!(
            duplicate,
            IamError::DuplicateLoginState {
                id: OAuthLoginStateId("login_1".into()),
            }
        );
    }

    #[test]
    fn session_authenticates_until_revoked() {
        let mut directory = SessionDirectory::new();
        directory
            .create_session(session("sess_1", "acct_1", "2026-06-20T00:00:00Z"))
            .unwrap();

        let live = directory
            .authenticate(
                &SessionId("sess_1".into()),
                Timestamp("2026-06-19T06:00:00Z".into()),
            )
            .unwrap();
        assert_eq!(live.account_id, AccountId("acct_1".into()));
        assert_eq!(live.last_seen_at, Timestamp("2026-06-19T06:00:00Z".into()));

        directory
            .revoke_session(
                &SessionId("sess_1".into()),
                Timestamp("2026-06-19T07:00:00Z".into()),
            )
            .unwrap();

        let revoked = directory
            .authenticate(
                &SessionId("sess_1".into()),
                Timestamp("2026-06-19T08:00:00Z".into()),
            )
            .unwrap_err();
        assert_eq!(
            revoked,
            IamError::SessionRevoked {
                id: SessionId("sess_1".into()),
            }
        );
    }

    #[test]
    fn expired_session_cannot_authenticate() {
        let mut directory = SessionDirectory::new();
        directory
            .create_session(session("sess_1", "acct_1", "2026-06-20T00:00:00Z"))
            .unwrap();

        let expired = directory
            .authenticate(
                &SessionId("sess_1".into()),
                Timestamp("2026-06-21T00:00:00Z".into()),
            )
            .unwrap_err();
        assert_eq!(
            expired,
            IamError::SessionExpired {
                id: SessionId("sess_1".into()),
            }
        );
    }

    fn login_state(id: &str, expires_at: &str) -> OAuthLoginState {
        OAuthLoginState {
            id: OAuthLoginStateId(id.into()),
            provider_key: IdentityProviderKey("fake".into()),
            state_hash: "state-hash".into(),
            nonce_hash: None,
            pkce_verifier_hash: None,
            return_to: None,
            created_at: Timestamp("2026-06-19T00:00:00Z".into()),
            expires_at: Timestamp(expires_at.into()),
            consumed_at: None,
        }
    }

    fn session(id: &str, account_id: &str, expires_at: &str) -> Session {
        Session {
            id: SessionId(id.into()),
            account_id: AccountId(account_id.into()),
            token_hash: "token-hash".into(),
            external_identity_id: None,
            created_at: Timestamp("2026-06-19T00:00:00Z".into()),
            last_seen_at: Timestamp("2026-06-19T00:00:00Z".into()),
            expires_at: Timestamp(expires_at.into()),
            revoked_at: None,
        }
    }

    fn account(id: &str) -> Account {
        Account {
            id: AccountId(id.into()),
            status: AccountStatus::Active,
            display_name: None,
            created_at: Timestamp("2026-06-19T00:00:00Z".into()),
            updated_at: Timestamp("2026-06-19T00:00:00Z".into()),
        }
    }

    fn external_identity(
        id: &str,
        account_id: &str,
        provider_key: &str,
        subject: &str,
        email: Option<&str>,
    ) -> ExternalIdentity {
        ExternalIdentity {
            id: ExternalIdentityId(id.into()),
            account_id: AccountId(account_id.into()),
            provider_key: IdentityProviderKey(provider_key.into()),
            claims: claims(subject, email),
            first_seen_at: Timestamp("2026-06-19T00:00:00Z".into()),
            last_seen_at: Timestamp("2026-06-19T00:00:00Z".into()),
        }
    }

    fn claims(subject: &str, email: Option<&str>) -> ExternalIdentityClaims {
        ExternalIdentityClaims {
            subject: ExternalSubject(subject.into()),
            email: email.map(str::to_owned),
            email_verified: Some(true),
            display_name: None,
            username: None,
            avatar_url: None,
            locale: None,
        }
    }
}
