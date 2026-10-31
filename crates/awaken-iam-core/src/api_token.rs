//! Long-lived, workspace-scoped API tokens (permission mechanism 8).
//!
//! API tokens authenticate machine and automation callers; a key carries no
//! per-key scope and its authority comes entirely from its principal's role
//! bindings, evaluated through [`PolicySet`] like any account (ADR-0008
//! decision 3). A token is two halves: a public, non-secret
//! *prefix* used to locate the row, and a high-entropy *secret* that is hashed
//! with **argon2id** and stored only as its PHC hash. The full cleartext token
//! (`sk-awaken-<prefix>.<secret>`) is returned exactly once at mint time and is
//! never recoverable afterwards — mirroring how sessions and login secrets are
//! handled, but with a memory-hard hash because the secret is a long-lived
//! credential rather than a short-TTL challenge.
//!
//! [`ApiTokenMinter`] draws the prefix, secret, and argon2 salt from the same
//! [`EntropySource`] seam the rest of the crate uses, so deployments inject the
//! OS CSPRNG while tests inject a deterministic generator. [`ApiTokenDirectory`]
//! resolves a presented token by its prefix, verifies the secret against the
//! stored argon2id hash in constant time, and fails closed on an unknown prefix,
//! a wrong secret, revocation, or expiry. Unknown-prefix and wrong-secret both
//! collapse to one opaque [`IamError::ApiTokenInvalid`] so a caller cannot probe
//! which tokens exist.

use std::collections::HashMap;

use argon2::Argon2;
use argon2::password_hash::{PasswordHash, PasswordHasher, PasswordVerifier, SaltString};
use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;

use awaken_iam_contract::{
    AccountId, ApiToken, ApiTokenId, ApiTokenPrefix, PrincipalRef, ScopeRef, Timestamp, WorkspaceId,
};

use crate::{
    ApiTokenRepository, EntropySource, IamError, PolicySet, RepositoryResult, RoleBinding, RoleId,
};

/// Scheme marker every newly-minted token carries, before the `<prefix>.<secret>`
/// body, so a presented credential is recognizable and unambiguously parsed.
///
/// Awaken-branded (`sk-awaken-`) to distinguish Awaken management tokens from
/// real Anthropic provider keys (`sk-ant-…`). base64url never contains `.`, and
/// the marker is stripped literally before the body is split, so the parse is
/// unambiguous even though the marker itself ends in `-`.
const TOKEN_SCHEME: &str = "sk-awaken-";

/// Legacy scheme accepted during the deprecation window.
///
/// Tokens minted before the `sk-awaken-` migration carry this prefix; they are
/// still verified but new tokens are never minted under it. Operators should
/// rotate all existing tokens to invalidate the legacy scheme in their
/// environment.
const LEGACY_TOKEN_SCHEME: &str = "sk-ant-";

/// Random bytes drawn for the public lookup prefix (64 bits).
const PREFIX_BYTES: usize = 8;

/// Random bytes drawn for the secret half (256 bits).
const SECRET_BYTES: usize = 32;

/// Random bytes drawn for the per-token argon2id salt (128 bits).
const SALT_BYTES: usize = 16;

/// Request to mint a new API token.
///
/// A key holds no per-key scope: minting names the `workspace` the key belongs
/// to and the `role` it holds there, and the minter writes both the credential
/// and the workspace-scoped [`RoleBinding`] in one step (ADR-0008 decision 4).
/// The caller chooses `role` — in the product, the creating member's workspace
/// role — and that defaulting lives with the caller.
///
/// `created_at`/`expires_at` follow the rest of the contract: time math lives
/// with the caller as canonical RFC 3339 strings. `expires_at` is optional — a
/// token without one never expires and lives until revoked — but when present it
/// must be strictly after `created_at`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MintApiToken {
    /// Row id assigned to the persisted token.
    pub id: ApiTokenId,
    /// Principal the token authenticates as.
    pub principal: PrincipalRef,
    /// Workspace the key belongs to: its credential attribution and the scope
    /// at which its [`RoleBinding`] is written.
    pub workspace: WorkspaceId,
    /// Workspace role the key holds; bound to `principal` at `workspace` so the
    /// key's authority flows through [`PolicySet::evaluate`] like any account.
    pub role: RoleId,
    /// Token mint timestamp.
    pub created_at: Timestamp,
    /// Optional expiration timestamp; must be strictly after `created_at`.
    pub expires_at: Option<Timestamp>,
}

/// Result of minting a token: the persisted row plus its one-time cleartext.
///
/// The `secret` is the full `sk-awaken-<prefix>.<secret>` credential to hand to
/// the caller exactly once; only the argon2id hash on [`IssuedApiToken::token`]
/// is persisted.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IssuedApiToken {
    /// The persisted token row (argon2id hash only).
    pub token: ApiToken,
    /// One-time cleartext token presented by the caller on later requests.
    pub secret: String,
}

/// A service-account token minted through the accountable admin path.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IssuedServiceAccountToken {
    /// The issued token and its one-time cleartext.
    pub issued: IssuedApiToken,
    /// The accountable human owner recorded for the token.
    pub owner: AccountId,
}

/// Why the accountable service-account mint path refused a request.
#[derive(Debug, PartialEq, Eq, thiserror::Error)]
pub enum ServiceAccountTokenError {
    /// The request's principal is not a [`PrincipalRef::Service`].
    #[error("service account tokens must authenticate a service principal")]
    NotAServiceAccount,
    /// The request carried no expiry.
    #[error("service account tokens require an expiry")]
    ExpiryRequired,
    /// The underlying mint failed (window, duplicate id or prefix, hashing).
    #[error(transparent)]
    Mint(#[from] IamError),
}

/// Mints argon2id-hashed API tokens and persists their rows.
#[derive(Debug, Default, Clone)]
pub struct ApiTokenMinter<E: EntropySource> {
    entropy: E,
}

impl<E: EntropySource> ApiTokenMinter<E> {
    /// Build a minter over the given entropy source.
    pub fn new(entropy: E) -> Self {
        Self { entropy }
    }

    /// Mint a token, persist its argon2id hash, bind its workspace role, and
    /// return the one-time cleartext credential.
    ///
    /// The credential and the [`RoleBinding`] are written in one step: the row
    /// lands in `directory` and a binding of the token's principal to
    /// `request.role` at `Workspace { workspace }` lands in `policy`, so the
    /// key's authority flows through [`PolicySet::evaluate`] with no per-key
    /// scope and no side path (ADR-0008 decisions 3 and 4). The binding is only
    /// written once the credential persists, so a rejected mint leaves no
    /// dangling authority.
    ///
    /// Fails with [`IamError::InvalidApiTokenWindow`] when an expiry is not
    /// strictly after creation, or with the duplicate errors from
    /// [`ApiTokenDirectory::create`] when the id or prefix is reused.
    pub fn mint(
        &mut self,
        directory: &mut ApiTokenDirectory,
        policy: &mut PolicySet,
        request: MintApiToken,
    ) -> Result<IssuedApiToken, IamError> {
        if let Some(expires_at) = &request.expires_at
            && expires_at.0 <= request.created_at.0
        {
            return Err(IamError::InvalidApiTokenWindow { id: request.id });
        }

        let prefix = self.random_b64(PREFIX_BYTES);
        let secret = self.random_b64(SECRET_BYTES);

        let mut salt = [0u8; SALT_BYTES];
        self.entropy.fill_bytes(&mut salt);
        let secret_hash = hash_secret_argon2(&secret, &salt)?;

        let token = ApiToken {
            id: request.id,
            prefix: ApiTokenPrefix(prefix.clone()),
            principal: request.principal.clone(),
            secret_hash,
            workspace: request.workspace.clone(),
            created_at: request.created_at,
            expires_at: request.expires_at,
            revoked_at: None,
        };

        directory.create(token.clone())?;

        policy.bind_role(RoleBinding {
            principal: request.principal,
            role: request.role,
            scope: ScopeRef::Workspace {
                workspace_id: request.workspace,
            },
        });

        Ok(IssuedApiToken {
            token,
            secret: render_token(&prefix, &secret),
        })
    }

    /// The accountable administrative mint path for service-account tokens
    /// (ADR-0017): the principal must be a [`PrincipalRef::Service`], the
    /// request must carry an expiry, and `owner` — the human accountable for
    /// the key — is recorded beside the token in `directory`.
    ///
    /// [`mint`](Self::mint) keeps its original contract for library callers;
    /// administrative surfaces that issue service-account keys use this
    /// method so ownership and expiry are always present.
    pub fn mint_service_account(
        &mut self,
        directory: &mut ApiTokenDirectory,
        policy: &mut PolicySet,
        request: MintApiToken,
        owner: AccountId,
    ) -> Result<IssuedServiceAccountToken, ServiceAccountTokenError> {
        if !matches!(request.principal, PrincipalRef::Service { .. }) {
            return Err(ServiceAccountTokenError::NotAServiceAccount);
        }
        if request.expires_at.is_none() {
            return Err(ServiceAccountTokenError::ExpiryRequired);
        }
        let issued = self.mint(directory, policy, request)?;
        directory
            .owners
            .insert(issued.token.id.clone(), owner.clone());
        Ok(IssuedServiceAccountToken { issued, owner })
    }

    fn random_b64(&mut self, bytes: usize) -> String {
        let mut buf = vec![0u8; bytes];
        self.entropy.fill_bytes(&mut buf);
        URL_SAFE_NO_PAD.encode(&buf)
    }
}

/// In-memory directory enforcing API-token uniqueness, authentication, and
/// revocation invariants.
///
/// A token is indexed by its public prefix (for presented-credential lookup) and
/// by its id (for management operations like revoke). Authentication verifies
/// the secret against the stored argon2id hash and applies liveness; there is no
/// per-key authorization path — an authenticated key's authority is resolved by
/// [`PolicySet::evaluate`] from its principal's role bindings (ADR-0008).
#[derive(Debug, Default)]
pub struct ApiTokenDirectory {
    by_prefix: HashMap<ApiTokenPrefix, ApiToken>,
    by_id: HashMap<ApiTokenId, ApiTokenPrefix>,
    owners: HashMap<ApiTokenId, AccountId>,
}

impl ApiTokenDirectory {
    /// Create an empty directory.
    pub fn new() -> Self {
        Self::default()
    }

    /// Persist a newly minted token.
    ///
    /// Each id and each prefix may be created only once, failing closed with
    /// [`IamError::DuplicateApiToken`] or [`IamError::DuplicateApiTokenPrefix`].
    pub fn create(&mut self, token: ApiToken) -> Result<(), IamError> {
        if self.by_id.contains_key(&token.id) {
            return Err(IamError::DuplicateApiToken { id: token.id });
        }
        if self.by_prefix.contains_key(&token.prefix) {
            return Err(IamError::DuplicateApiTokenPrefix {
                prefix: token.prefix,
            });
        }
        self.by_id.insert(token.id.clone(), token.prefix.clone());
        self.by_prefix.insert(token.prefix.clone(), token);
        Ok(())
    }

    /// Resolve a token by id without checking liveness.
    pub fn token(&self, id: &ApiTokenId) -> Option<&ApiToken> {
        self.by_id
            .get(id)
            .and_then(|prefix| self.by_prefix.get(prefix))
    }

    /// Resolve a token by its public prefix without checking liveness.
    pub fn token_by_prefix(&self, prefix: &ApiTokenPrefix) -> Option<&ApiToken> {
        self.by_prefix.get(prefix)
    }

    /// List every token held by a principal, ordered by token id for stable
    /// iteration regardless of map order.
    pub fn list_for_principal(&self, principal: &PrincipalRef) -> Vec<&ApiToken> {
        let mut tokens: Vec<&ApiToken> = self
            .by_prefix
            .values()
            .filter(|token| &token.principal == principal)
            .collect();
        tokens.sort_by(|left, right| left.id.0.cmp(&right.id.0));
        tokens
    }

    /// Authenticate a presented cleartext token, returning the live row.
    ///
    /// Resolves the row by the presented prefix and verifies the secret against
    /// the stored argon2id hash in constant time. An unparseable token, an
    /// unknown prefix, and a wrong secret all collapse to the opaque
    /// [`IamError::ApiTokenInvalid`] so callers cannot probe which tokens exist.
    /// A verified-but-revoked or verified-but-expired token fails with
    /// [`IamError::ApiTokenRevoked`] / [`IamError::ApiTokenExpired`].
    pub fn authenticate(&self, presented: &str, now: &Timestamp) -> Result<&ApiToken, IamError> {
        let (prefix, secret) = parse_presented_token(presented).ok_or(IamError::ApiTokenInvalid)?;
        let token = self
            .by_prefix
            .get(&prefix)
            .ok_or(IamError::ApiTokenInvalid)?;
        if !verify_secret_argon2(&secret, &token.secret_hash) {
            return Err(IamError::ApiTokenInvalid);
        }
        if token.revoked_at.is_some() {
            return Err(IamError::ApiTokenRevoked {
                id: token.id.clone(),
            });
        }
        if let Some(expires_at) = &token.expires_at
            && now.0 >= expires_at.0
        {
            return Err(IamError::ApiTokenExpired {
                id: token.id.clone(),
            });
        }
        Ok(token)
    }

    /// The accountable owner recorded by
    /// [`ApiTokenMinter::mint_service_account`], if any.
    pub fn owner(&self, id: &ApiTokenId) -> Option<&AccountId> {
        self.owners.get(id)
    }

    /// Revoke every unrevoked token held by `principal` — e.g. all keys of one
    /// service account — returning the ids newly revoked, ordered by id.
    ///
    /// Idempotent: already-revoked tokens keep their first stamp and are not
    /// reported again. A principal without tokens yields an empty list.
    pub fn revoke_principal(
        &mut self,
        principal: &PrincipalRef,
        now: Timestamp,
    ) -> Vec<ApiTokenId> {
        let mut revoked: Vec<ApiTokenId> = self
            .by_prefix
            .values_mut()
            .filter(|token| &token.principal == principal && token.revoked_at.is_none())
            .map(|token| {
                token.revoked_at = Some(now.clone());
                token.id.clone()
            })
            .collect();
        revoked.sort_by(|left, right| left.0.cmp(&right.0));
        revoked
    }

    /// Revoke a token by id so it can no longer authenticate.
    ///
    /// Revocation is idempotent: the first `revoked_at` stamp is preserved. An
    /// unknown id fails closed with [`IamError::ApiTokenNotFound`].
    pub fn revoke(&mut self, id: &ApiTokenId, now: Timestamp) -> Result<(), IamError> {
        let prefix = self
            .by_id
            .get(id)
            .cloned()
            .ok_or_else(|| IamError::ApiTokenNotFound { id: id.clone() })?;
        let token = self
            .by_prefix
            .get_mut(&prefix)
            .expect("prefix index points at a stored token");
        token.revoked_at.get_or_insert(now);
        Ok(())
    }
}

/// Revoke every live persisted token held by `principal` — the durable
/// counterpart of [`ApiTokenDirectory::revoke_principal`] used to retire all
/// keys of one service account at once.
///
/// Each row is revoked through [`ApiTokenRepository::update`], so the store's
/// own admission rules apply exactly as for a single revoke. Already-revoked
/// rows are left untouched; the ids newly revoked are returned in id order. A
/// failure stops at that row and is returned; rows revoked before it stay
/// revoked, and a retry revokes only the remainder.
pub fn revoke_api_tokens_for_principal(
    repository: &dyn ApiTokenRepository,
    principal: &PrincipalRef,
    now: &Timestamp,
) -> RepositoryResult<Vec<ApiTokenId>> {
    let mut revoked = Vec::new();
    for mut token in repository.list_for_principal(principal)? {
        if token.revoked_at.is_some() {
            continue;
        }
        token.revoked_at = Some(now.clone());
        let id = token.id.clone();
        repository.update(token)?;
        revoked.push(id);
    }
    revoked.sort_by(|left, right| left.0.cmp(&right.0));
    Ok(revoked)
}

/// Render the one-time cleartext credential from its prefix and secret halves.
fn render_token(prefix: &str, secret: &str) -> String {
    format!("{TOKEN_SCHEME}{prefix}.{secret}")
}

/// Split a presented credential into its prefix and secret halves.
///
/// Returns `None` when the scheme marker is missing or either half is empty, so
/// a malformed token never reaches the hash comparison. base64url never contains
/// `.`, so the single split is unambiguous.
///
/// Accepts both `sk-awaken-` (current) and `sk-ant-` (legacy deprecation window)
/// so operators can rotate existing tokens without a hard cutover.
pub fn parse_presented_token(presented: &str) -> Option<(ApiTokenPrefix, String)> {
    let body = presented
        .strip_prefix(TOKEN_SCHEME)
        .or_else(|| presented.strip_prefix(LEGACY_TOKEN_SCHEME))?;
    let (prefix, secret) = body.split_once('.')?;
    if prefix.is_empty() || secret.is_empty() {
        return None;
    }
    Some((ApiTokenPrefix(prefix.to_owned()), secret.to_owned()))
}

/// Hash a token secret with argon2id, returning its PHC-string representation.
fn hash_secret_argon2(secret: &str, salt_bytes: &[u8]) -> Result<String, IamError> {
    let salt = SaltString::encode_b64(salt_bytes).map_err(|err| IamError::ApiTokenHashFailure {
        detail: err.to_string(),
    })?;
    let hash = Argon2::default()
        .hash_password(secret.as_bytes(), &salt)
        .map_err(|err| IamError::ApiTokenHashFailure {
            detail: err.to_string(),
        })?;
    Ok(hash.to_string())
}

/// Verify a presented secret against a stored argon2id PHC hash in constant
/// time. A malformed stored hash fails closed.
fn verify_secret_argon2(secret: &str, phc: &str) -> bool {
    match PasswordHash::new(phc) {
        Ok(parsed) => Argon2::default()
            .verify_password(secret.as_bytes(), &parsed)
            .is_ok(),
        Err(_) => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Deterministic counter-based entropy so each minted value is distinct and
    /// reproducible across calls.
    #[derive(Default)]
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

    fn mint_request(id: &str, expires_at: Option<&str>) -> MintApiToken {
        MintApiToken {
            id: ApiTokenId(id.into()),
            principal: PrincipalRef::Service {
                service_id: "ci".into(),
            },
            workspace: WorkspaceId("wrkspc_default".into()),
            role: RoleId("workspace_developer".into()),
            created_at: Timestamp("2026-06-19T00:00:00Z".into()),
            expires_at: expires_at.map(|value| Timestamp(value.into())),
        }
    }

    /// Accountable service-account mint decision table (ADR-0017 I4):
    ///
    /// | path | principal | expiry | result |
    /// |---|---|---|---|
    /// | mint_service_account | service | yes | issued, owner recorded |
    /// | mint_service_account | service | no | ExpiryRequired, nothing stored |
    /// | mint_service_account | account | yes | NotAServiceAccount |
    /// | mint (library) | service | no | issued unchanged, no owner |
    #[test]
    fn service_account_admin_path_requires_an_owner_and_an_expiry() {
        let mut minter = ApiTokenMinter::new(SequentialEntropy::default());
        let mut directory = ApiTokenDirectory::new();
        let mut policy = PolicySet::new();
        let owner = AccountId("acct_owner".into());
        let owned = minter
            .mint_service_account(
                &mut directory,
                &mut policy,
                mint_request("tok_owned", Some("2027-06-19T00:00:00Z")),
                owner.clone(),
            )
            .unwrap();
        assert_eq!(owned.owner, owner);
        assert_eq!(
            directory.owner(&ApiTokenId("tok_owned".into())),
            Some(&owner)
        );

        assert_eq!(
            minter.mint_service_account(
                &mut directory,
                &mut policy,
                mint_request("tok_unbounded", None),
                owner.clone(),
            ),
            Err(ServiceAccountTokenError::ExpiryRequired)
        );
        assert!(
            directory
                .token(&ApiTokenId("tok_unbounded".into()))
                .is_none()
        );
        let mut account = mint_request("tok_account", Some("2027-06-19T00:00:00Z"));
        account.principal = PrincipalRef::Account {
            account_id: AccountId("acct_ada".into()),
        };
        assert_eq!(
            minter.mint_service_account(&mut directory, &mut policy, account, owner),
            Err(ServiceAccountTokenError::NotAServiceAccount)
        );

        let legacy = minter
            .mint(
                &mut directory,
                &mut policy,
                mint_request("tok_legacy", None),
            )
            .unwrap();
        assert_eq!(legacy.token.expires_at, None);
        assert_eq!(directory.owner(&legacy.token.id), None);
    }

    #[test]
    fn revoke_principal_retires_every_live_token_of_one_service_account_only() {
        let mut minter = ApiTokenMinter::new(SequentialEntropy::default());
        let mut directory = ApiTokenDirectory::new();
        let mut policy = PolicySet::new();
        let first = minter
            .mint(&mut directory, &mut policy, mint_request("tok_a", None))
            .unwrap();
        let second = minter
            .mint(&mut directory, &mut policy, mint_request("tok_b", None))
            .unwrap();
        let mut other = mint_request("tok_other", None);
        other.principal = PrincipalRef::Service {
            service_id: "other".into(),
        };
        let other = minter.mint(&mut directory, &mut policy, other).unwrap();
        let earlier = Timestamp("2026-06-19T01:00:00Z".into());
        directory
            .revoke(&ApiTokenId("tok_a".into()), earlier.clone())
            .unwrap();

        let now = Timestamp("2026-06-19T02:00:00Z".into());
        let ci = PrincipalRef::Service {
            service_id: "ci".into(),
        };
        assert_eq!(
            directory.revoke_principal(&ci, now.clone()),
            vec![ApiTokenId("tok_b".into())]
        );
        assert!(directory.revoke_principal(&ci, now.clone()).is_empty());
        assert_eq!(
            directory
                .token(&ApiTokenId("tok_a".into()))
                .unwrap()
                .revoked_at,
            Some(earlier),
            "first stamp preserved"
        );
        for secret in [&first.secret, &second.secret] {
            assert!(matches!(
                directory.authenticate(secret, &now),
                Err(IamError::ApiTokenRevoked { .. })
            ));
        }
        assert!(directory.authenticate(&other.secret, &now).is_ok());
    }

    #[test]
    fn mint_persists_only_a_hash_and_returns_cleartext_once() {
        let mut minter = ApiTokenMinter::new(SequentialEntropy::default());
        let mut directory = ApiTokenDirectory::new();
        let mut policy = PolicySet::new();

        let issued = minter
            .mint(
                &mut directory,
                &mut policy,
                mint_request("tok_1", Some("2026-07-19T00:00:00Z")),
            )
            .unwrap();

        // The cleartext carries the scheme + the stored public prefix.
        assert!(issued.secret.starts_with(TOKEN_SCHEME));
        assert!(issued.secret.contains(&issued.token.prefix.0));
        // The secret hash is an argon2id PHC string, never the cleartext.
        assert!(issued.token.secret_hash.starts_with("$argon2id$"));
        assert!(!issued.secret.contains(&issued.token.secret_hash));

        // The persisted row is the one held in the directory.
        assert_eq!(
            directory.token(&ApiTokenId("tok_1".into())),
            Some(&issued.token)
        );
    }

    #[test]
    fn cleartext_renders_in_the_sk_awaken_shape_and_parses_back() {
        let mut minter = ApiTokenMinter::new(SequentialEntropy::default());
        let mut directory = ApiTokenDirectory::new();
        let mut policy = PolicySet::new();
        let issued = minter
            .mint(&mut directory, &mut policy, mint_request("tok_1", None))
            .unwrap();

        // Awaken-branded marker, not the old Anthropic-compatible `sk-ant-`.
        assert!(issued.secret.starts_with("sk-awaken-"));
        assert!(!issued.secret.starts_with("sk-ant-"));
        assert!(!issued.secret.starts_with("oiam_"));

        // The marker is stripped and the body splits back into the stored prefix
        // and a non-empty secret, even though the marker itself ends in `-`.
        let (prefix, secret) = parse_presented_token(&issued.secret).unwrap();
        assert_eq!(prefix, issued.token.prefix);
        assert!(!secret.is_empty());
    }

    #[test]
    fn legacy_sk_ant_tokens_are_accepted_during_deprecation_window() {
        // parse_presented_token must accept the old sk-ant- scheme so operators
        // can rotate tokens without a hard cutover.
        let result = parse_presented_token("sk-ant-someprefix.somesecret");
        assert!(result.is_some());
        let (prefix, secret) = result.unwrap();
        assert_eq!(prefix.0, "someprefix");
        assert_eq!(secret, "somesecret");

        // But a token with no recognised scheme marker is still rejected.
        assert!(parse_presented_token("oiam_someprefix.somesecret").is_none());
    }

    #[test]
    fn authenticate_round_trips_a_freshly_minted_token() {
        let mut minter = ApiTokenMinter::new(SequentialEntropy::default());
        let mut directory = ApiTokenDirectory::new();
        let mut policy = PolicySet::new();
        let issued = minter
            .mint(&mut directory, &mut policy, mint_request("tok_1", None))
            .unwrap();

        let live = directory
            .authenticate(&issued.secret, &Timestamp("2026-06-19T06:00:00Z".into()))
            .unwrap();
        assert_eq!(live.id, ApiTokenId("tok_1".into()));
        assert_eq!(
            live.principal,
            PrincipalRef::Service {
                service_id: "ci".into()
            }
        );
        // The token carries its workspace binding for credential attribution; it
        // holds no per-key authority of its own.
        assert_eq!(live.workspace, WorkspaceId("wrkspc_default".into()));
    }

    #[test]
    fn mint_binds_the_workspace_role_so_the_key_authorizes_through_the_engine() {
        use awaken_iam_contract::{ActionKey, AuthorizationDecision, AuthorizationRequest};

        use crate::{ActionPattern, Effect, Grant, GrantId, GrantSubject};

        let mut minter = ApiTokenMinter::new(SequentialEntropy::default());
        let mut directory = ApiTokenDirectory::new();
        let mut policy = PolicySet::new();

        // The workspace_developer role may publish in the key's workspace.
        policy.add_grant(Grant {
            id: GrantId("g_dev".into()),
            subject: GrantSubject::Role(RoleId("workspace_developer".into())),
            action_pattern: ActionPattern("pack.publish".into()),
            scope: ScopeRef::Workspace {
                workspace_id: WorkspaceId("wrkspc_default".into()),
            },
            effect: Effect::Allow,
        });

        // Minting writes the credential and the workspace-scoped role binding in
        // one step; no per-key scope is attached.
        minter
            .mint(&mut directory, &mut policy, mint_request("tok_1", None))
            .unwrap();

        let principal = PrincipalRef::Service {
            service_id: "ci".into(),
        };
        let workspace = ScopeRef::Workspace {
            workspace_id: WorkspaceId("wrkspc_default".into()),
        };

        // Authority flows through the engine via the bound role — no side path.
        let allowed = policy.evaluate(&AuthorizationRequest::direct(
            principal.clone(),
            ActionKey("pack.publish".into()),
            workspace.clone(),
        ));
        assert_eq!(allowed.decision, AuthorizationDecision::Allow);
        assert_eq!(
            allowed.matched_roles,
            vec![RoleId("workspace_developer".into())]
        );

        // Guardrail: an action the role does not cover stays denied by default —
        // the key holds no authority of its own.
        let denied = policy.evaluate(&AuthorizationRequest::direct(
            principal,
            ActionKey("pack.delete".into()),
            workspace,
        ));
        assert_eq!(denied.decision, AuthorizationDecision::Deny);
    }

    #[test]
    fn unknown_prefix_and_wrong_secret_fail_closed_identically() {
        let mut minter = ApiTokenMinter::new(SequentialEntropy::default());
        let mut directory = ApiTokenDirectory::new();
        let mut policy = PolicySet::new();
        let issued = minter
            .mint(&mut directory, &mut policy, mint_request("tok_1", None))
            .unwrap();
        let now = Timestamp("2026-06-19T06:00:00Z".into());

        // A presented token for an unregistered prefix (new scheme).
        let unknown = directory
            .authenticate("sk-awaken-ZZZZZZZZ.deadbeef", &now)
            .unwrap_err();
        assert_eq!(unknown, IamError::ApiTokenInvalid);

        // Legacy scheme with an unregistered prefix also fails closed.
        let unknown_legacy = directory
            .authenticate("sk-ant-ZZZZZZZZ.deadbeef", &now)
            .unwrap_err();
        assert_eq!(unknown_legacy, IamError::ApiTokenInvalid);

        // The right prefix but the wrong secret half collapses to the same error.
        let forged = format!("{TOKEN_SCHEME}{}.not-the-secret", issued.token.prefix.0);
        let wrong_secret = directory.authenticate(&forged, &now).unwrap_err();
        assert_eq!(wrong_secret, IamError::ApiTokenInvalid);

        // A token missing the scheme marker never reaches the hash comparison.
        let malformed = directory.authenticate("not-a-token", &now).unwrap_err();
        assert_eq!(malformed, IamError::ApiTokenInvalid);
    }

    #[test]
    fn expired_token_fails_closed() {
        let mut minter = ApiTokenMinter::new(SequentialEntropy::default());
        let mut directory = ApiTokenDirectory::new();
        let mut policy = PolicySet::new();
        let issued = minter
            .mint(
                &mut directory,
                &mut policy,
                mint_request("tok_1", Some("2026-06-20T00:00:00Z")),
            )
            .unwrap();

        let err = directory
            .authenticate(&issued.secret, &Timestamp("2026-06-20T00:00:00Z".into()))
            .unwrap_err();
        assert_eq!(
            err,
            IamError::ApiTokenExpired {
                id: ApiTokenId("tok_1".into()),
            }
        );
    }

    #[test]
    fn revocation_is_idempotent_and_blocks_authentication() {
        let mut minter = ApiTokenMinter::new(SequentialEntropy::default());
        let mut directory = ApiTokenDirectory::new();
        let mut policy = PolicySet::new();
        let issued = minter
            .mint(&mut directory, &mut policy, mint_request("tok_1", None))
            .unwrap();
        let now = Timestamp("2026-06-19T06:00:00Z".into());

        directory
            .revoke(&ApiTokenId("tok_1".into()), now.clone())
            .unwrap();
        // Re-revoking keeps the first stamp and still succeeds.
        directory
            .revoke(
                &ApiTokenId("tok_1".into()),
                Timestamp("2026-06-19T07:00:00Z".into()),
            )
            .unwrap();
        assert_eq!(
            directory
                .token(&ApiTokenId("tok_1".into()))
                .unwrap()
                .revoked_at,
            Some(now.clone())
        );

        let err = directory.authenticate(&issued.secret, &now).unwrap_err();
        assert_eq!(
            err,
            IamError::ApiTokenRevoked {
                id: ApiTokenId("tok_1".into()),
            }
        );

        // Revoking an unknown id fails closed.
        let missing = directory
            .revoke(&ApiTokenId("nope".into()), now)
            .unwrap_err();
        assert_eq!(
            missing,
            IamError::ApiTokenNotFound {
                id: ApiTokenId("nope".into()),
            }
        );
    }

    #[test]
    fn mint_rejects_a_non_forward_expiry_window() {
        let mut minter = ApiTokenMinter::new(SequentialEntropy::default());
        let mut directory = ApiTokenDirectory::new();
        let mut policy = PolicySet::new();
        let err = minter
            .mint(
                &mut directory,
                &mut policy,
                mint_request("tok_1", Some("2026-06-19T00:00:00Z")),
            )
            .unwrap_err();
        assert_eq!(
            err,
            IamError::InvalidApiTokenWindow {
                id: ApiTokenId("tok_1".into()),
            }
        );
        assert!(directory.token(&ApiTokenId("tok_1".into())).is_none());
    }

    #[test]
    fn create_rejects_a_duplicate_id() {
        let mut minter = ApiTokenMinter::new(SequentialEntropy::default());
        let mut directory = ApiTokenDirectory::new();
        let mut policy = PolicySet::new();
        minter
            .mint(&mut directory, &mut policy, mint_request("tok_1", None))
            .unwrap();
        let err = minter
            .mint(&mut directory, &mut policy, mint_request("tok_1", None))
            .unwrap_err();
        assert_eq!(
            err,
            IamError::DuplicateApiToken {
                id: ApiTokenId("tok_1".into()),
            }
        );
    }

    #[test]
    fn list_for_principal_orders_by_id() {
        let mut minter = ApiTokenMinter::new(SequentialEntropy::default());
        let mut directory = ApiTokenDirectory::new();
        let mut policy = PolicySet::new();
        minter
            .mint(&mut directory, &mut policy, mint_request("tok_2", None))
            .unwrap();
        minter
            .mint(&mut directory, &mut policy, mint_request("tok_1", None))
            .unwrap();

        let principal = PrincipalRef::Service {
            service_id: "ci".into(),
        };
        let ids: Vec<&str> = directory
            .list_for_principal(&principal)
            .into_iter()
            .map(|token| token.id.0.as_str())
            .collect();
        assert_eq!(ids, ["tok_1", "tok_2"]);

        let other = PrincipalRef::Service {
            service_id: "other".into(),
        };
        assert!(directory.list_for_principal(&other).is_empty());
    }
}
