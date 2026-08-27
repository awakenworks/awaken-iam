//! Deployment-time construction for the browser authentication API.
//!
//! Runtime login, callback, session, and token transitions stay in the parent
//! module. This bounded extension owns only dependency and policy injection.

use super::*;

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
        let login_proof_cookie = SessionCookieConfig {
            name: DEFAULT_LOGIN_PROOF_COOKIE_NAME.to_owned(),
            ..SessionCookieConfig::default()
        };
        // Draw the bootstrap signing seed from a clone so the live `ids` stream
        // (and therefore minted ids) is unaffected by key generation.
        let mut bootstrap = entropy.clone();
        let mut seed = [0u8; 32];
        bootstrap.fill_bytes(&mut seed);
        let tokens = AccessTokenAuthority::new(LocalSeedSigner::new(DEFAULT_SIGNING_KID, seed));
        let identity_store = crate::store::InMemoryStore::new();
        Self {
            providers: Vec::new(),
            challenge: OAuthChallengeService::new(entropy.clone()),
            login_flows: Arc::new(crate::store::InMemoryStore::new()),
            sessions: SessionGateway::with_entropy(entropy.clone(), SessionCookieConfig::default()),
            accounts: Arc::new(identity_store.clone()),
            external_identities: Arc::new(identity_store.clone()),
            identity_commands: Arc::new(identity_store),
            return_to: ReturnToPolicy::default(),
            login_cookie,
            login_proof_cookie,
            tokens,
            refresh_tokens: RefreshTokenDirectory::new(),
            refresh_minter: RefreshTokenMinter::new(entropy.clone()),
            access_revocations: AccessTokenRevocations::new(),
            trusted_issuers: TrustedIssuerRegistry::new(),
            iam_issuer: String::new(),
            oauth_provider: OAuthAuthorizationServer::new(
                OAuthClientRegistry::new(),
                entropy.clone(),
            ),
            audit: Vec::new(),
            ids: entropy,
        }
    }

    /// Replace the `return_to` allowlist policy.
    pub fn with_return_to_policy(mut self, policy: ReturnToPolicy) -> Self {
        self.return_to = policy;
        self
    }

    /// Replace the session cookie configuration without changing its store.
    pub fn with_session_cookie(mut self, cookie: SessionCookieConfig) -> Self {
        let repository = self.sessions.repository();
        self.sessions = SessionGateway::with_repository(self.ids.clone(), cookie, repository);
        self
    }

    /// Replace the browser-session repository selected by deployment assembly.
    ///
    /// Durable server compositions inject their shared SQL store here; local
    /// and test compositions retain the in-memory default. Cookie configuration
    /// and repository selection are intentionally independent and may be
    /// applied in either builder order without reverting to an in-memory store.
    pub fn with_session_repository(mut self, repository: Arc<dyn SessionRepository>) -> Self {
        let cookie = self.sessions.cookie_config().clone();
        self.sessions = SessionGateway::with_repository(self.ids.clone(), cookie, repository);
        self
    }

    /// Replace the platform-global Account query repositories and the single
    /// atomic Account+ExternalIdentity command owner selected by deployment.
    pub fn with_identity_repositories(
        mut self,
        accounts: Arc<dyn AccountRepository>,
        external_identities: Arc<dyn ExternalIdentityRepository>,
        identity_commands: Arc<dyn AccountIdentityRepository>,
    ) -> Self {
        self.accounts = accounts;
        self.external_identities = external_identities;
        self.identity_commands = identity_commands;
        self
    }

    /// Replace downstream OAuth client and authorization-code repositories.
    ///
    /// Durable compositions pass two trait-object views of the same shared SQL
    /// store. This runs during assembly before clients or codes are issued;
    /// every later lookup and single-use transition goes directly through the
    /// repositories, with no hydrated per-process registry.
    pub fn with_oauth_repositories(
        mut self,
        clients: Arc<dyn OAuthClientRepository>,
        codes: Arc<dyn AuthCodeRepository>,
    ) -> Self {
        self.oauth_provider =
            OAuthAuthorizationServer::with_repositories(clients, codes, self.ids.clone());
        self
    }

    /// Replace the single authoritative upstream login-flow repository.
    ///
    /// Durable compositions inject the same shared SQL store used by sessions
    /// and downstream OAuth state. No process-local compatibility path remains.
    pub fn with_login_repository(mut self, repository: Arc<dyn LoginFlowRepository>) -> Self {
        self.login_flows = repository;
        self
    }

    /// Replace the login correlation cookie configuration.
    pub fn with_login_cookie(mut self, cookie: SessionCookieConfig) -> Self {
        self.login_cookie = cookie;
        self
    }

    /// Replace the one-time callback-proof cookie configuration.
    pub fn with_login_proof_cookie(mut self, cookie: SessionCookieConfig) -> Self {
        self.login_proof_cookie = cookie;
        self
    }

    /// Set the IAM issuer (`iss`) stamped into tokens minted by federated token
    /// exchange. A deployment configures this to its own canonical base URL.
    pub fn with_issuer(mut self, issuer: impl Into<String>) -> Self {
        self.iam_issuer = issuer.into();
        self
    }

    /// Use one shared, jointly rotated signing authority for every token family.
    pub fn with_access_token_authority(mut self, authority: AccessTokenAuthority) -> Self {
        self.tokens = authority;
        self
    }

    /// Replace the shared authority during deployment assembly or key rollout.
    pub fn set_access_token_authority(&mut self, authority: AccessTokenAuthority) {
        self.tokens = authority;
    }
}
