//! Long-lived, workspace-scoped API tokens (permission mechanism 8).
//!
//! API tokens authenticate machine and automation callers; a key carries no
//! per-key scope and its authority comes entirely from its principal's role
//! bindings, evaluated through [`PolicySet`] like any account (ADR-0008
//! decision 3). A token is two halves: a public, non-secret
//! *prefix* used to locate the row, and a high-entropy *secret* that is hashed
//! with a versioned, prefix-bound SHA-256 verifier. Legacy Argon2 PHC verifiers
//! remain readable until operators rotate their tokens. The full cleartext token
//! (`sk-awaken-<prefix>.<secret>`) is returned exactly once at mint time and is
//! never recoverable afterwards. The 256-bit OS-generated secret provides the
//! entropy required by the fast verifier; passwords and caller-chosen secrets
//! cannot be minted through this API.
//!
//! [`ApiTokenMinter`] draws the prefix and secret from the same
//! [`EntropySource`] seam the rest of the crate uses, so deployments inject the
//! OS CSPRNG while tests inject a deterministic generator. [`ApiTokenDirectory`]
//! resolves a presented token by its prefix, verifies the secret against the
//! stored verifier in constant time, and fails closed on an unknown prefix,
//! a wrong secret, revocation, or expiry. Unknown-prefix and wrong-secret both
//! collapse to the same opaque [`IamError::ApiTokenInvalid`] result.

use std::collections::HashMap;

use argon2::Argon2;
use argon2::password_hash::{PasswordHash, PasswordVerifier};
#[cfg(test)]
use argon2::password_hash::{PasswordHasher, SaltString};
use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;

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

/// Versioned encoding of a 32-byte, prefix-bound API-token verifier.
const TOKEN_HASH_V1_PREFIX: &str = "sha256:v1:";

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
/// the caller exactly once; only the versioned verifier on [`IssuedApiToken::token`]
/// is persisted.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IssuedApiToken {
    /// The persisted token row (versioned verifier only).
    pub token: ApiToken,
    /// One-time cleartext token presented by the caller on later requests.
    pub secret: String,
}

/// A validated mint held exclusively against its original live directory.
///
/// Preparing has no live effect. Persist only `token()` and `binding()` through
/// one atomic store command, then publish after its commit ACK. The value owns
/// the one-time secret but deliberately implements neither Debug nor Serialize.
///
/// ```compile_fail,E0277
/// use awaken_iam_core::PreparedApiTokenMint;
/// fn requires_debug<T: std::fmt::Debug>() {}
/// requires_debug::<PreparedApiTokenMint<'static>>();
/// ```
/// ```compile_fail,E0277
/// use awaken_iam_core::PreparedApiTokenMint;
/// fn requires_serialize<T: serde::Serialize>() {}
/// requires_serialize::<PreparedApiTokenMint<'static>>();
/// ```
#[must_use = "dropping a prepared mint leaves the live directory unchanged"]
pub struct PreparedApiTokenMint<'a> {
    directory: &'a mut ApiTokenDirectory,
    issued: IssuedApiToken,
    binding: RoleBinding,
    owner: Option<AccountId>,
}

impl PreparedApiTokenMint<'_> {
    pub fn token(&self) -> &ApiToken {
        &self.issued.token
    }
    pub fn binding(&self) -> &RoleBinding {
        &self.binding
    }

    /// Read the frozen one-time credential for an owner-only durable handoff
    /// while the original state guard remains held. This neither publishes the
    /// live token nor permits replacing/regenerating the secret.
    pub fn secret(&self) -> &str {
        &self.issued.secret
    }

    /// Publish only after durable commit, under the caller's same state guard.
    /// This performs no IO or fallible lookup. Obtain `policy_mut()` only here,
    /// after the commit, so a refused preparation cannot advance its version.
    pub fn publish(self, policy: &mut PolicySet) -> IssuedApiToken {
        self.directory.insert_validated(self.issued.token.clone());
        if let Some(owner) = self.owner {
            self.directory
                .owners
                .insert(self.issued.token.id.clone(), owner);
        }
        policy.bind_role(self.binding);
        self.issued
    }
}

/// An exclusive borrow of the original token slot before durable revocation.
#[must_use = "dropping a prepared revocation leaves the live token unchanged"]
pub struct PreparedApiTokenRevocation<'a> {
    token: &'a mut ApiToken,
}

impl PreparedApiTokenRevocation<'_> {
    pub fn token(&self) -> &ApiToken {
        self.token
    }

    /// Install the store-acknowledged first stamp without another lookup or IO.
    /// The store must have checked the frozen token identity before commit.
    pub fn publish(self, committed_at: Timestamp) -> ApiToken {
        self.token.revoked_at = Some(api_token_revocation_stamp(
            self.token.revoked_at.as_ref(),
            &committed_at,
        ));
        self.token.clone()
    }
}

/// The single first-revocation-stamp law for live and durable token paths.
pub fn api_token_revocation_stamp(existing: Option<&Timestamp>, now: &Timestamp) -> Timestamp {
    existing.unwrap_or(now).clone()
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

/// Mints high-entropy API tokens and persists their verifier rows.
#[derive(Debug, Default, Clone)]
pub struct ApiTokenMinter<E: EntropySource> {
    entropy: E,
}

impl<E: EntropySource> ApiTokenMinter<E> {
    /// Build a minter over the given entropy source.
    pub fn new(entropy: E) -> Self {
        Self { entropy }
    }

    /// Mint a token, persist its versioned verifier, bind its workspace role, and
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
        Ok(self.prepare(directory, request)?.publish(policy))
    }

    /// Prepare the original mint algorithm without changing its directory or
    /// policy. The exclusive directory borrow prevents intervening live writes.
    pub fn prepare<'a>(
        &mut self,
        directory: &'a mut ApiTokenDirectory,
        request: MintApiToken,
    ) -> Result<PreparedApiTokenMint<'a>, IamError> {
        if let Some(expires_at) = &request.expires_at
            && expires_at.0 <= request.created_at.0
        {
            return Err(IamError::InvalidApiTokenWindow { id: request.id });
        }

        let prefix = self.random_b64(PREFIX_BYTES);
        let mut secret_bytes = [0u8; SECRET_BYTES];
        self.entropy.fill_bytes(&mut secret_bytes);
        let secret = URL_SAFE_NO_PAD.encode(secret_bytes);
        let secret_hash = format!(
            "{TOKEN_HASH_V1_PREFIX}{}",
            URL_SAFE_NO_PAD.encode(api_token_secret_digest(&prefix, &secret_bytes))
        );

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

        directory.validate_create(&token)?;
        let binding = RoleBinding {
            principal: request.principal,
            role: request.role,
            scope: ScopeRef::Workspace {
                workspace_id: request.workspace,
            },
        };
        Ok(PreparedApiTokenMint {
            directory,
            issued: IssuedApiToken {
                token,
                secret: render_token(&prefix, &secret),
            },
            binding,
            owner: None,
        })
    }

    /// Prepare the accountable path with the original service/expiry checks,
    /// without obtaining the live policy or recording an owner before publish.
    pub fn prepare_service_account<'a>(
        &mut self,
        directory: &'a mut ApiTokenDirectory,
        request: MintApiToken,
        owner: AccountId,
    ) -> Result<PreparedApiTokenMint<'a>, ServiceAccountTokenError> {
        if !matches!(request.principal, PrincipalRef::Service { .. }) {
            return Err(ServiceAccountTokenError::NotAServiceAccount);
        }
        if request.expires_at.is_none() {
            return Err(ServiceAccountTokenError::ExpiryRequired);
        }
        let mut pending = self.prepare(directory, request)?;
        pending.owner = Some(owner);
        Ok(pending)
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
        let issued = self
            .prepare_service_account(directory, request, owner.clone())?
            .publish(policy);
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
/// the secret against the stored verifier and applies liveness; there is no
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
        self.validate_create(&token)?;
        self.insert_validated(token);
        Ok(())
    }

    fn validate_create(&self, token: &ApiToken) -> Result<(), IamError> {
        if self.by_id.contains_key(&token.id) {
            return Err(IamError::DuplicateApiToken {
                id: token.id.clone(),
            });
        }
        if self.by_prefix.contains_key(&token.prefix) {
            return Err(IamError::DuplicateApiTokenPrefix {
                prefix: token.prefix.clone(),
            });
        }
        Ok(())
    }

    fn insert_validated(&mut self, token: ApiToken) {
        self.by_id.insert(token.id.clone(), token.prefix.clone());
        self.by_prefix.insert(token.prefix.clone(), token);
    }

    /// Borrow the original slot before persistence; a refused store operation
    /// drops this value without changing the token or either directory index.
    pub fn prepare_revoke(
        &mut self,
        id: &ApiTokenId,
    ) -> Result<PreparedApiTokenRevocation<'_>, IamError> {
        let prefix = self
            .by_id
            .get(id)
            .ok_or_else(|| IamError::ApiTokenNotFound { id: id.clone() })?;
        let token = self
            .by_prefix
            .get_mut(prefix)
            .ok_or_else(|| IamError::ApiTokenNotFound { id: id.clone() })?;
        Ok(PreparedApiTokenRevocation { token })
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
    /// the stored verifier in constant time. An unparseable token, an
    /// unknown prefix, and a wrong secret all collapse to the opaque
    /// [`IamError::ApiTokenInvalid`] result.
    /// A verified-but-revoked or verified-but-expired token fails with
    /// [`IamError::ApiTokenRevoked`] / [`IamError::ApiTokenExpired`].
    pub fn authenticate(&self, presented: &str, now: &Timestamp) -> Result<&ApiToken, IamError> {
        let (prefix, secret) = parse_presented_token(presented).ok_or(IamError::ApiTokenInvalid)?;
        let token = self
            .by_prefix
            .get(&prefix)
            .ok_or(IamError::ApiTokenInvalid)?;
        if !verify_api_token_secret(&token.prefix, &secret, &token.secret_hash) {
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
                token.revoked_at =
                    Some(api_token_revocation_stamp(token.revoked_at.as_ref(), &now));
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
        self.prepare_revoke(id)?.publish(now);
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
        token.revoked_at = Some(api_token_revocation_stamp(token.revoked_at.as_ref(), now));
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
/// Authenticate a presented token against a durable repository with the same
/// rules as [`ApiTokenDirectory::authenticate`]. `Ok(None)` covers every
/// refusal (unparseable, unknown, wrong secret, revoked, expired) so callers
/// receive one opaque authentication result. Storage failures remain errors.
pub fn authenticate_stored_api_token<R: crate::ApiTokenRepository + ?Sized>(
    repository: &R,
    presented: &str,
    now: &Timestamp,
) -> crate::RepositoryResult<Option<ApiToken>> {
    let Some((prefix, secret)) = parse_presented_token(presented) else {
        return Ok(None);
    };
    let Some(token) = repository.get_by_prefix(&prefix)? else {
        return Ok(None);
    };
    let live = verify_api_token_secret(&token.prefix, &secret, &token.secret_hash)
        && token.revoked_at.is_none()
        && token
            .expires_at
            .as_ref()
            .is_none_or(|expires_at| now.0 < expires_at.0);
    Ok(live.then_some(token))
}

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

/// Bind the verifier to this token's public lookup prefix and random secret.
fn api_token_secret_digest(prefix: &str, secret: &[u8; SECRET_BYTES]) -> [u8; 32] {
    let mut digest = Sha256::new();
    digest.update(b"awaken-iam/api-token/v1\0");
    digest.update((prefix.len() as u64).to_be_bytes());
    digest.update(prefix.as_bytes());
    digest.update(secret);
    digest.finalize().into()
}

fn verify_api_token_secret(prefix: &ApiTokenPrefix, secret: &str, stored: &str) -> bool {
    let Some(encoded) = stored.strip_prefix(TOKEN_HASH_V1_PREFIX) else {
        return verify_secret_argon2(secret, stored);
    };
    let mut secret_bytes = [0u8; SECRET_BYTES];
    let mut expected = [0u8; 32];
    // Each v1 field encodes exactly 256 bits with canonical unpadded base64url.
    if secret.len() != 43
        || encoded.len() != 43
        || URL_SAFE_NO_PAD.decode_slice(secret, &mut secret_bytes) != Ok(SECRET_BYTES)
        || URL_SAFE_NO_PAD.decode_slice(encoded, &mut expected) != Ok(32)
    {
        return false;
    }
    let actual = api_token_secret_digest(&prefix.0, &secret_bytes);
    bool::from(actual.as_slice().ct_eq(expected.as_slice()))
}

#[cfg(test)]
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
    use std::sync::{
        Mutex,
        atomic::{AtomicBool, AtomicUsize, Ordering},
    };

    #[derive(Default)]
    struct StoredTokenRepository {
        token: Mutex<Option<ApiToken>>,
        reads: AtomicUsize,
        writes: AtomicUsize,
        fail_reads: AtomicBool,
    }

    impl ApiTokenRepository for StoredTokenRepository {
        fn create(&self, token: ApiToken) -> RepositoryResult<()> {
            let mut stored = self.token.lock().unwrap();
            if stored.is_some() {
                return Err(crate::RepositoryError::Conflict("duplicate token".into()));
            }
            *stored = Some(token);
            self.writes.fetch_add(1, Ordering::Relaxed);
            Ok(())
        }

        fn get(&self, id: &ApiTokenId) -> RepositoryResult<Option<ApiToken>> {
            Ok(self
                .token
                .lock()
                .unwrap()
                .clone()
                .filter(|token| &token.id == id))
        }

        fn get_by_prefix(&self, prefix: &ApiTokenPrefix) -> RepositoryResult<Option<ApiToken>> {
            self.reads.fetch_add(1, Ordering::Relaxed);
            if self.fail_reads.load(Ordering::Relaxed) {
                return Err(crate::RepositoryError::Backend(
                    "injected token read failure".into(),
                ));
            }
            Ok(self
                .token
                .lock()
                .unwrap()
                .clone()
                .filter(|token| &token.prefix == prefix))
        }

        fn list_for_principal(&self, principal: &PrincipalRef) -> RepositoryResult<Vec<ApiToken>> {
            Ok(self
                .token
                .lock()
                .unwrap()
                .iter()
                .filter(|token| &token.principal == principal)
                .cloned()
                .collect())
        }

        fn update(&self, token: ApiToken) -> RepositoryResult<()> {
            let mut stored = self.token.lock().unwrap();
            if stored.as_ref().is_none_or(|current| current.id != token.id) {
                return Err(crate::RepositoryError::NotFound("token".into()));
            }
            *stored = Some(token);
            self.writes.fetch_add(1, Ordering::Relaxed);
            Ok(())
        }
    }

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
        // Accountable preparation also has no live owner/binding effect on
        // drop; the legacy path below then exercises that same publish law.
        {
            let pending = minter
                .prepare_service_account(
                    &mut directory,
                    mint_request("tok_unpublished_owner", Some("2027-06-19T00:00:00Z")),
                    owner.clone(),
                )
                .unwrap();
            drop(pending);
        }
        assert!(
            directory
                .token(&ApiTokenId("tok_unpublished_owner".into()))
                .is_none()
        );
        assert!(
            directory
                .owner(&ApiTokenId("tok_unpublished_owner".into()))
                .is_none()
        );
        assert!(policy.snapshot(1).role_bindings.is_empty());
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
    fn prepared_token_mutations_publish_only_when_consumed() {
        // P1 prepare/drop -> original empty directory/policy; P2 publish ->
        // one exact token+binding and usable secret; P3 revoke prepare/drop ->
        // still usable; P4 acknowledged publish/replay -> original first stamp.
        // Core owns no SQL here. The real store tests inject failure between
        // prepare and publish, using these same borrowed values.
        let mut minter = ApiTokenMinter::new(SequentialEntropy::default());
        let mut directory = ApiTokenDirectory::new();
        let mut policy = PolicySet::new();
        let before = policy.snapshot(1);
        {
            let pending = minter
                .prepare(&mut directory, mint_request("dropped", None))
                .unwrap();
            assert_eq!(pending.token().id, ApiTokenId("dropped".into()));
            assert_eq!(pending.binding().principal, pending.token().principal);
        }
        assert!(directory.token(&ApiTokenId("dropped".into())).is_none());
        assert_eq!(policy.snapshot(1), before);
        let pending = minter
            .prepare(&mut directory, mint_request("published", None))
            .unwrap();
        let binding = pending.binding().clone();
        let handoff = pending.secret().to_owned();
        let issued = pending.publish(&mut policy);
        assert_eq!(issued.secret, handoff);
        assert_eq!(directory.token(&issued.token.id), Some(&issued.token));
        assert_eq!(policy.snapshot(1).role_bindings.len(), 1);
        assert_eq!(
            policy.snapshot(1).role_bindings[0].principal,
            binding.principal
        );
        let now = Timestamp("2026-06-19T01:00:00Z".into());
        assert!(directory.authenticate(&issued.secret, &now).is_ok());
        {
            let pending = directory.prepare_revoke(&issued.token.id).unwrap();
            assert_eq!(pending.token().revoked_at, None);
        }
        assert!(directory.authenticate(&issued.secret, &now).is_ok());
        let revoked = directory
            .prepare_revoke(&issued.token.id)
            .unwrap()
            .publish(now.clone());
        assert_eq!(revoked.revoked_at, Some(now.clone()));
        directory
            .revoke(&issued.token.id, Timestamp("2026-06-19T02:00:00Z".into()))
            .unwrap();
        assert_eq!(
            directory.token(&issued.token.id).unwrap().revoked_at,
            Some(now)
        );
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
        // The stored versioned verifier never contains the cleartext token.
        assert!(issued.token.secret_hash.starts_with(TOKEN_HASH_V1_PREFIX));
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

    #[test]
    fn v1_mint_keeps_256_secret_bits_separate_from_the_public_prefix() {
        let mut minter = ApiTokenMinter::new(SequentialEntropy::default());
        let issued = minter
            .mint(
                &mut ApiTokenDirectory::new(),
                &mut PolicySet::new(),
                mint_request("tok_v1", None),
            )
            .unwrap();
        let (prefix, secret) = parse_presented_token(&issued.secret).unwrap();
        assert_eq!(
            URL_SAFE_NO_PAD.decode(&prefix.0).unwrap(),
            (0..8).collect::<Vec<u8>>()
        );
        assert_eq!(
            URL_SAFE_NO_PAD.decode(&secret).unwrap(),
            (8..40).collect::<Vec<u8>>()
        );
        assert_eq!(secret.len(), 43);
        assert!(verify_api_token_secret(
            &prefix,
            &secret,
            &issued.token.secret_hash
        ));
        assert!(!verify_api_token_secret(
            &ApiTokenPrefix("different-prefix".into()),
            &secret,
            &issued.token.secret_hash,
        ));
    }

    #[test]
    fn v1_verifier_rejects_unknown_truncated_padded_and_noncanonical_fields() {
        let prefix = ApiTokenPrefix("public-prefix".into());
        let secret = URL_SAFE_NO_PAD.encode([0x33; SECRET_BYTES]);
        let encoded =
            URL_SAFE_NO_PAD.encode(api_token_secret_digest(&prefix.0, &[0x33; SECRET_BYTES]));
        let stored = format!("{TOKEN_HASH_V1_PREFIX}{encoded}");
        assert!(verify_api_token_secret(&prefix, &secret, &stored));
        assert_eq!(
            stored,
            "sha256:v1:nmYAFIr0iB3dV_hTFNMEZ43zIjDTqAr6F-ToNt2ut5k"
        );
        assert_eq!(
            URL_SAFE_NO_PAD.encode(api_token_secret_digest("préfix", &[0x33; SECRET_BYTES])),
            "40KXkU_GtG8lhZe8BahP1Y6a7USUOPiQTrvi4-NjMic"
        );
        for invalid in [
            format!("sha256:v2:{encoded}"),
            TOKEN_HASH_V1_PREFIX.to_owned(),
            format!("{stored}="),
            stored[..stored.len() - 1].to_owned(),
            format!(
                "{TOKEN_HASH_V1_PREFIX}{}",
                URL_SAFE_NO_PAD.encode([0u8; 31])
            ),
            format!("{TOKEN_HASH_V1_PREFIX}{}", "/".repeat(43)),
            format!("{TOKEN_HASH_V1_PREFIX}{}B", "A".repeat(42)),
            format!(
                "{TOKEN_HASH_V1_PREFIX}{}",
                URL_SAFE_NO_PAD.encode([0u8; 32])
            ),
        ] {
            assert!(!verify_api_token_secret(&prefix, &secret, &invalid));
        }
        for invalid in [
            URL_SAFE_NO_PAD.encode([0x44; SECRET_BYTES]),
            "short-secret".to_owned(),
            format!("{secret}="),
            secret[..42].to_owned(),
            format!("{secret}A"),
            "!".repeat(43),
            format!("{}B", "A".repeat(42)),
        ] {
            assert!(!verify_api_token_secret(&prefix, &invalid, &stored));
        }
    }

    #[test]
    fn legacy_phc_keeps_its_original_secret_and_scheme_compatibility() {
        let mut minter = ApiTokenMinter::new(SequentialEntropy::default());
        let mut issued = minter
            .mint(
                &mut ApiTokenDirectory::new(),
                &mut PolicySet::new(),
                mint_request("tok_legacy", None),
            )
            .unwrap();
        let legacy_fixture = "existing-legacy-secret";
        issued.token.secret_hash = hash_secret_argon2(legacy_fixture, &[0x55; 16]).unwrap();
        let mut directory = ApiTokenDirectory::new();
        directory.create(issued.token.clone()).unwrap();
        let now = Timestamp("2026-06-19T06:00:00Z".into());
        for scheme in [TOKEN_SCHEME, LEGACY_TOKEN_SCHEME] {
            let presented = format!("{scheme}{}.{legacy_fixture}", issued.token.prefix.0);
            assert_eq!(
                directory.authenticate(&presented, &now).unwrap(),
                &issued.token
            );
        }
        assert!(!verify_api_token_secret(
            &issued.token.prefix,
            "wrong-secret",
            &issued.token.secret_hash
        ));
        assert!(!verify_api_token_secret(
            &issued.token.prefix,
            legacy_fixture,
            "$argon2id$malformed"
        ));
    }

    #[test]
    fn stored_verifiers_read_live_liveness_and_fail_closed_for_both_formats() {
        let now = Timestamp("2026-06-19T06:00:00Z".into());
        for legacy in [false, true] {
            let mut minter = ApiTokenMinter::new(SequentialEntropy::default());
            let mut issued = minter
                .mint(
                    &mut ApiTokenDirectory::new(),
                    &mut PolicySet::new(),
                    mint_request("tok_stored", None),
                )
                .unwrap();
            if legacy {
                let (_, secret) = parse_presented_token(&issued.secret).unwrap();
                issued.token.secret_hash = hash_secret_argon2(&secret, &[0x55; 16]).unwrap();
            }
            let repository = StoredTokenRepository::default();
            repository.create(issued.token.clone()).unwrap();
            assert_eq!(
                authenticate_stored_api_token(&repository, &issued.secret, &now).unwrap(),
                Some(issued.token.clone())
            );

            let mut expired = issued.token.clone();
            expired.expires_at = Some(now.clone());
            repository.update(expired).unwrap();
            assert!(
                authenticate_stored_api_token(&repository, &issued.secret, &now)
                    .unwrap()
                    .is_none()
            );

            let mut revoked = issued.token.clone();
            revoked.revoked_at = Some(now.clone());
            repository.update(revoked).unwrap();
            assert!(
                authenticate_stored_api_token(&repository, &issued.secret, &now)
                    .unwrap()
                    .is_none()
            );

            let mut changed_verifier = issued.token.clone();
            changed_verifier.secret_hash = "sha256:v2:unrecognized".into();
            repository.update(changed_verifier).unwrap();
            assert!(
                authenticate_stored_api_token(&repository, &issued.secret, &now)
                    .unwrap()
                    .is_none()
            );

            *repository.token.lock().unwrap() = None;
            assert!(
                authenticate_stored_api_token(&repository, &issued.secret, &now)
                    .unwrap()
                    .is_none()
            );
            repository.fail_reads.store(true, Ordering::Relaxed);
            assert!(matches!(
                authenticate_stored_api_token(&repository, &issued.secret, &now),
                Err(crate::RepositoryError::Backend(_))
            ));
            assert_eq!(repository.reads.load(Ordering::Relaxed), 6);
            assert_eq!(repository.writes.load(Ordering::Relaxed), 4);
        }
    }
}
