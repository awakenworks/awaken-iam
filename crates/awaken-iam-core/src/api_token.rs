//! Long-lived, principal-scoped API tokens (permission mechanism 8).
//!
//! API tokens authenticate machine and automation callers whose authority is a
//! fixed [`ActionKey`] scope set. A token is two halves: a public, non-secret
//! *prefix* used to locate the row, and a high-entropy *secret* that is hashed
//! with **argon2id** and stored only as its PHC hash. The full cleartext token
//! (`oiam_<prefix>.<secret>`) is returned exactly once at mint time and is never
//! recoverable afterwards — mirroring how sessions and login secrets are
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
    ActionKey, ApiToken, ApiTokenId, ApiTokenPrefix, PrincipalRef, Timestamp,
};

use crate::{EntropySource, IamError};

/// Scheme marker every rendered token carries, before the `<prefix>.<secret>`
/// body, so a presented credential is recognizable and unambiguously parsed.
const TOKEN_SCHEME: &str = "oiam_";

/// Random bytes drawn for the public lookup prefix (64 bits).
const PREFIX_BYTES: usize = 8;

/// Random bytes drawn for the secret half (256 bits).
const SECRET_BYTES: usize = 32;

/// Random bytes drawn for the per-token argon2id salt (128 bits).
const SALT_BYTES: usize = 16;

/// Request to mint a new API token.
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
    /// Action scope the token may exercise; an empty set authorizes nothing.
    pub scope: Vec<ActionKey>,
    /// Token mint timestamp.
    pub created_at: Timestamp,
    /// Optional expiration timestamp; must be strictly after `created_at`.
    pub expires_at: Option<Timestamp>,
}

/// Result of minting a token: the persisted row plus its one-time cleartext.
///
/// The `secret` is the full `oiam_<prefix>.<secret>` credential to hand to the
/// caller exactly once; only the argon2id hash on [`IssuedApiToken::token`] is
/// persisted.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IssuedApiToken {
    /// The persisted token row (argon2id hash only).
    pub token: ApiToken,
    /// One-time cleartext token presented by the caller on later requests.
    pub secret: String,
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

    /// Mint a token, persist its argon2id hash, and return the one-time
    /// cleartext credential.
    ///
    /// Fails with [`IamError::InvalidApiTokenWindow`] when an expiry is not
    /// strictly after creation, or with the duplicate errors from
    /// [`ApiTokenDirectory::create`] when the id or prefix is reused.
    pub fn mint(
        &mut self,
        directory: &mut ApiTokenDirectory,
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
            principal: request.principal,
            secret_hash,
            scope: request.scope,
            created_at: request.created_at,
            expires_at: request.expires_at,
            revoked_at: None,
        };

        directory.create(token.clone())?;

        Ok(IssuedApiToken {
            token,
            secret: render_token(&prefix, &secret),
        })
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
/// the secret against the stored argon2id hash and applies liveness; scope
/// enforcement is layered on top by [`ApiTokenDirectory::authorize`].
#[derive(Debug, Default)]
pub struct ApiTokenDirectory {
    by_prefix: HashMap<ApiTokenPrefix, ApiToken>,
    by_id: HashMap<ApiTokenId, ApiTokenPrefix>,
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

    /// Authenticate a presented token and require `action` to be in its scope.
    ///
    /// Layers scope enforcement over [`ApiTokenDirectory::authenticate`]: a live
    /// token whose scope set does not contain `action` fails closed with
    /// [`IamError::ApiTokenInsufficientScope`].
    pub fn authorize(
        &self,
        presented: &str,
        action: &ActionKey,
        now: &Timestamp,
    ) -> Result<&ApiToken, IamError> {
        let token = self.authenticate(presented, now)?;
        if !token.authorizes(action) {
            return Err(IamError::ApiTokenInsufficientScope {
                id: token.id.clone(),
                action: action.clone(),
            });
        }
        Ok(token)
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

/// Render the one-time cleartext credential from its prefix and secret halves.
fn render_token(prefix: &str, secret: &str) -> String {
    format!("{TOKEN_SCHEME}{prefix}.{secret}")
}

/// Split a presented credential into its prefix and secret halves.
///
/// Returns `None` when the scheme marker is missing or either half is empty, so
/// a malformed token never reaches the hash comparison. base64url never contains
/// `.`, so the single split is unambiguous.
pub fn parse_presented_token(presented: &str) -> Option<(ApiTokenPrefix, String)> {
    let body = presented.strip_prefix(TOKEN_SCHEME)?;
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
            scope: vec![ActionKey("pack.publish".into())],
            created_at: Timestamp("2026-06-19T00:00:00Z".into()),
            expires_at: expires_at.map(|value| Timestamp(value.into())),
        }
    }

    #[test]
    fn mint_persists_only_a_hash_and_returns_cleartext_once() {
        let mut minter = ApiTokenMinter::new(SequentialEntropy::default());
        let mut directory = ApiTokenDirectory::new();

        let issued = minter
            .mint(
                &mut directory,
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
    fn authenticate_round_trips_a_freshly_minted_token() {
        let mut minter = ApiTokenMinter::new(SequentialEntropy::default());
        let mut directory = ApiTokenDirectory::new();
        let issued = minter
            .mint(&mut directory, mint_request("tok_1", None))
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
    }

    #[test]
    fn authorize_enforces_the_action_scope_set() {
        let mut minter = ApiTokenMinter::new(SequentialEntropy::default());
        let mut directory = ApiTokenDirectory::new();
        let issued = minter
            .mint(&mut directory, mint_request("tok_1", None))
            .unwrap();
        let now = Timestamp("2026-06-19T06:00:00Z".into());

        // An in-scope action is authorized.
        directory
            .authorize(&issued.secret, &ActionKey("pack.publish".into()), &now)
            .unwrap();

        // An out-of-scope action fails closed naming the missing action.
        let err = directory
            .authorize(&issued.secret, &ActionKey("pack.yank".into()), &now)
            .unwrap_err();
        assert_eq!(
            err,
            IamError::ApiTokenInsufficientScope {
                id: ApiTokenId("tok_1".into()),
                action: ActionKey("pack.yank".into()),
            }
        );
    }

    #[test]
    fn unknown_prefix_and_wrong_secret_fail_closed_identically() {
        let mut minter = ApiTokenMinter::new(SequentialEntropy::default());
        let mut directory = ApiTokenDirectory::new();
        let issued = minter
            .mint(&mut directory, mint_request("tok_1", None))
            .unwrap();
        let now = Timestamp("2026-06-19T06:00:00Z".into());

        // A presented token for an unregistered prefix.
        let unknown = directory
            .authenticate("oiam_ZZZZZZZZ.deadbeef", &now)
            .unwrap_err();
        assert_eq!(unknown, IamError::ApiTokenInvalid);

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
        let issued = minter
            .mint(
                &mut directory,
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
        let issued = minter
            .mint(&mut directory, mint_request("tok_1", None))
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
        let err = minter
            .mint(
                &mut directory,
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
        minter
            .mint(&mut directory, mint_request("tok_1", None))
            .unwrap();
        let err = minter
            .mint(&mut directory, mint_request("tok_1", None))
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
        minter
            .mint(&mut directory, mint_request("tok_2", None))
            .unwrap();
        minter
            .mint(&mut directory, mint_request("tok_1", None))
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
