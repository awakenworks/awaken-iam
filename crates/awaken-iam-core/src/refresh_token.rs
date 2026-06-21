//! Refresh-token rotation with reuse (theft) detection.
//!
//! A refresh token renews short-lived access tokens. It is opaque and high
//! entropy, stored only as its SHA-256 hash, and the cleartext is handed to the
//! caller exactly once — mirroring how sessions are handled. The hard-won rule
//! from the auth-server design is **rotation with reuse detection**: every use of
//! a refresh token retires it (stamps `rotated_at`) and issues a *successor*
//! under the same [`chain_id`](awaken_iam_contract::RefreshToken::chain_id). A
//! legitimate client always holds the newest token, so presenting a token that is
//! already retired can only mean the token leaked and is being replayed — that
//! reuse revokes the **whole chain** as a theft signal.
//!
//! [`RefreshTokenMinter`] draws the opaque secret from the same [`EntropySource`]
//! seam the rest of the crate uses, while [`RefreshTokenDirectory`] holds the
//! rows, the hash index, and the chain index, and enforces the rotation/reuse/
//! revocation invariants. An unparseable token, an unknown hash, and a
//! revoked-chain token all collapse to one opaque [`IamError::RefreshTokenInvalid`]
//! so a caller cannot probe which tokens exist.

use std::collections::HashMap;

use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;

use awaken_iam_contract::{
    AccountId, RefreshToken, RefreshTokenChainId, RefreshTokenId, Timestamp,
};

use crate::login::hash_secret;
use crate::{EntropySource, IamError};

/// Scheme marker every rendered refresh token carries before its secret body, so
/// a presented credential is recognizable and unambiguously parsed.
const TOKEN_SCHEME: &str = "oiamr_";

/// Random bytes drawn for the opaque secret (256 bits).
const SECRET_BYTES: usize = 32;

/// Request to issue the first refresh token of a new chain.
///
/// `created_at`/`expires_at` follow the rest of the contract: time math lives
/// with the caller as canonical RFC 3339 strings, and `expires_at` must be
/// strictly after `created_at`. The grant coordinates (`subject`, `audience`,
/// `scope`) travel with the token so a later rotation can mint a matching access
/// token without trusting client-supplied claims.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MintRefreshToken {
    /// Row id assigned to the persisted token.
    pub id: RefreshTokenId,
    /// Chain id assigned to the new lineage.
    pub chain_id: RefreshTokenChainId,
    /// Account the refreshed access tokens authenticate.
    pub account_id: AccountId,
    /// Subject stamped into access tokens minted from this chain.
    pub subject: String,
    /// Audience stamped into access tokens minted from this chain.
    pub audience: String,
    /// Scopes carried by access tokens minted from this chain.
    pub scope: Vec<String>,
    /// Issue timestamp.
    pub created_at: Timestamp,
    /// Expiration timestamp; must be strictly after `created_at`.
    pub expires_at: Timestamp,
}

/// Request to rotate a presented refresh token into its successor.
///
/// The successor inherits the presented token's chain and grant coordinates;
/// only its id and validity window are supplied here. `now` is the rotation time
/// and `expires_at` must be strictly after it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RotateRefreshToken {
    /// Cleartext token presented by the caller (`oiamr_<secret>`).
    pub presented: String,
    /// Row id assigned to the successor token.
    pub successor_id: RefreshTokenId,
    /// Rotation timestamp; the successor's `created_at`.
    pub now: Timestamp,
    /// Successor expiration timestamp; must be strictly after `now`.
    pub expires_at: Timestamp,
}

/// Result of issuing/rotating a token: the persisted row plus its one-time
/// cleartext credential.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IssuedRefreshToken {
    /// The persisted token row (hash only).
    pub token: RefreshToken,
    /// One-time cleartext credential to present on the next refresh.
    pub secret: String,
}

/// Mints opaque refresh tokens and drives rotation against a directory.
#[derive(Debug, Default, Clone)]
pub struct RefreshTokenMinter<E: EntropySource> {
    entropy: E,
}

impl<E: EntropySource> RefreshTokenMinter<E> {
    /// Build a minter over the given entropy source.
    pub fn new(entropy: E) -> Self {
        Self { entropy }
    }

    /// Issue the first refresh token of a new chain and persist its hash.
    ///
    /// Fails with [`IamError::InvalidRefreshTokenWindow`] when the window is not
    /// forward-going, or the duplicate errors from [`RefreshTokenDirectory::create`]
    /// when the id or hash is reused.
    pub fn issue(
        &mut self,
        directory: &mut RefreshTokenDirectory,
        request: MintRefreshToken,
    ) -> Result<IssuedRefreshToken, IamError> {
        if request.expires_at.0 <= request.created_at.0 {
            return Err(IamError::InvalidRefreshTokenWindow { id: request.id });
        }
        let secret = self.random_secret();
        let token = RefreshToken {
            id: request.id,
            chain_id: request.chain_id,
            account_id: request.account_id,
            token_hash: hash_secret(&secret),
            subject: request.subject,
            audience: request.audience,
            scope: request.scope,
            created_at: request.created_at,
            expires_at: request.expires_at,
            rotated_at: None,
            revoked_at: None,
        };
        directory.create(token.clone())?;
        Ok(IssuedRefreshToken {
            token,
            secret: render_token(&secret),
        })
    }

    /// Rotate a presented refresh token: retire it and issue a successor under
    /// the same chain.
    ///
    /// Reuse detection is the core invariant. A presented token is resolved by
    /// its hash and then classified:
    /// - unparseable / unknown hash / revoked chain → [`IamError::RefreshTokenInvalid`];
    /// - already rotated (retired) → the replay revokes the **whole chain** and
    ///   fails with [`IamError::RefreshTokenReuseDetected`];
    /// - expired → [`IamError::RefreshTokenExpired`];
    /// - live → the token is stamped `rotated_at` and a successor is issued with
    ///   the inherited grant coordinates and a fresh secret.
    pub fn rotate(
        &mut self,
        directory: &mut RefreshTokenDirectory,
        request: RotateRefreshToken,
    ) -> Result<IssuedRefreshToken, IamError> {
        if request.expires_at.0 <= request.now.0 {
            return Err(IamError::InvalidRefreshTokenWindow {
                id: request.successor_id,
            });
        }
        let secret = parse_presented_refresh_token(&request.presented)
            .ok_or(IamError::RefreshTokenInvalid)?;
        let hash = hash_secret(secret);
        let id = directory
            .id_by_hash(&hash)
            .cloned()
            .ok_or(IamError::RefreshTokenInvalid)?;

        // Classify the presented token before mutating anything.
        {
            let token = directory
                .token(&id)
                .expect("hash index points at a stored token");
            if token.is_revoked() {
                // A revoked chain is indistinguishable from an unknown token to
                // the caller — fail closed without leaking that the row exists.
                return Err(IamError::RefreshTokenInvalid);
            }
            if token.is_retired() {
                let chain_id = token.chain_id.clone();
                directory.revoke_chain(&chain_id, &request.now);
                return Err(IamError::RefreshTokenReuseDetected { chain_id });
            }
            if request.now.0 >= token.expires_at.0 {
                return Err(IamError::RefreshTokenExpired { id });
            }
        }

        // Retire the presented token and mint its successor in the same chain.
        let predecessor = directory.mark_rotated(&id, request.now.clone());
        let secret = self.random_secret();
        let successor = RefreshToken {
            id: request.successor_id,
            chain_id: predecessor.chain_id,
            account_id: predecessor.account_id,
            token_hash: hash_secret(&secret),
            subject: predecessor.subject,
            audience: predecessor.audience,
            scope: predecessor.scope,
            created_at: request.now,
            expires_at: request.expires_at,
            rotated_at: None,
            revoked_at: None,
        };
        directory.create(successor.clone())?;
        Ok(IssuedRefreshToken {
            token: successor,
            secret: render_token(&secret),
        })
    }

    fn random_secret(&mut self) -> String {
        let mut buf = [0u8; SECRET_BYTES];
        self.entropy.fill_bytes(&mut buf);
        URL_SAFE_NO_PAD.encode(buf)
    }
}

/// In-memory directory enforcing refresh-token rotation, reuse, and revocation
/// invariants.
///
/// A token is indexed by its hash (for presented-credential lookup), by its id
/// (for management), and by its chain (so a reuse signal or an RFC 7009 revoke
/// can retire an entire lineage at once).
#[derive(Debug, Default)]
pub struct RefreshTokenDirectory {
    by_id: HashMap<RefreshTokenId, RefreshToken>,
    id_by_hash: HashMap<String, RefreshTokenId>,
    chains: HashMap<RefreshTokenChainId, Vec<RefreshTokenId>>,
}

impl RefreshTokenDirectory {
    /// Create an empty directory.
    pub fn new() -> Self {
        Self::default()
    }

    /// Persist a freshly minted token.
    ///
    /// Each id and each hash may be created only once, failing closed with
    /// [`IamError::DuplicateRefreshToken`] or [`IamError::DuplicateRefreshTokenHash`].
    pub fn create(&mut self, token: RefreshToken) -> Result<(), IamError> {
        if self.by_id.contains_key(&token.id) {
            return Err(IamError::DuplicateRefreshToken { id: token.id });
        }
        if self.id_by_hash.contains_key(&token.token_hash) {
            return Err(IamError::DuplicateRefreshTokenHash);
        }
        self.id_by_hash
            .insert(token.token_hash.clone(), token.id.clone());
        self.chains
            .entry(token.chain_id.clone())
            .or_default()
            .push(token.id.clone());
        self.by_id.insert(token.id.clone(), token);
        Ok(())
    }

    /// Resolve a token by id without checking liveness.
    pub fn token(&self, id: &RefreshTokenId) -> Option<&RefreshToken> {
        self.by_id.get(id)
    }

    /// Resolve the row id bound to a token hash without checking liveness.
    pub fn id_by_hash(&self, token_hash: &str) -> Option<&RefreshTokenId> {
        self.id_by_hash.get(token_hash)
    }

    /// Resolve a token by its presented hash without checking liveness.
    pub fn token_by_hash(&self, token_hash: &str) -> Option<&RefreshToken> {
        self.id_by_hash
            .get(token_hash)
            .and_then(|id| self.by_id.get(id))
    }

    /// List every token in a chain, ordered by creation (id-stable for ties).
    pub fn chain(&self, chain_id: &RefreshTokenChainId) -> Vec<&RefreshToken> {
        let mut tokens: Vec<&RefreshToken> = self
            .chains
            .get(chain_id)
            .into_iter()
            .flatten()
            .filter_map(|id| self.by_id.get(id))
            .collect();
        tokens.sort_by(|left, right| {
            left.created_at
                .0
                .cmp(&right.created_at.0)
                .then_with(|| left.id.0.cmp(&right.id.0))
        });
        tokens
    }

    /// Stamp a token retired and return a clone of the retired row.
    ///
    /// Idempotent: the first `rotated_at` stamp is preserved. The id must exist;
    /// callers resolve it through [`id_by_hash`](Self::id_by_hash) first.
    fn mark_rotated(&mut self, id: &RefreshTokenId, now: Timestamp) -> RefreshToken {
        let token = self
            .by_id
            .get_mut(id)
            .expect("mark_rotated called with a resolved id");
        token.rotated_at.get_or_insert(now);
        token.clone()
    }

    /// Revoke every token in a chain so none can be rotated again.
    ///
    /// Revocation is idempotent per token: an existing `revoked_at` stamp is
    /// preserved. Returns the number of tokens whose revocation stamp was newly
    /// set. An unknown chain revokes nothing and returns `0`.
    pub fn revoke_chain(&mut self, chain_id: &RefreshTokenChainId, now: &Timestamp) -> usize {
        let ids = match self.chains.get(chain_id) {
            Some(ids) => ids.clone(),
            None => return 0,
        };
        let mut revoked = 0;
        for id in ids {
            if let Some(token) = self.by_id.get_mut(&id)
                && token.revoked_at.is_none()
            {
                token.revoked_at = Some(now.clone());
                revoked += 1;
            }
        }
        revoked
    }
}

/// Render the one-time cleartext credential from its secret body.
fn render_token(secret: &str) -> String {
    format!("{TOKEN_SCHEME}{secret}")
}

/// Strip the scheme marker from a presented refresh token, returning its secret
/// body. Returns `None` when the scheme is missing or the body is empty, so a
/// malformed token never reaches the hash comparison.
pub fn parse_presented_refresh_token(presented: &str) -> Option<&str> {
    let body = presented.strip_prefix(TOKEN_SCHEME)?;
    if body.is_empty() { None } else { Some(body) }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Deterministic counter-based entropy so each minted secret is distinct and
    /// reproducible across calls.
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

    fn mint_request(id: &str, chain: &str) -> MintRefreshToken {
        MintRefreshToken {
            id: RefreshTokenId(id.into()),
            chain_id: RefreshTokenChainId(chain.into()),
            account_id: AccountId("acct_1".into()),
            subject: "acct_1".into(),
            audience: "packs-service".into(),
            scope: vec!["pack.read".into()],
            created_at: Timestamp("2026-06-19T00:00:00Z".into()),
            expires_at: Timestamp("2026-07-19T00:00:00Z".into()),
        }
    }

    fn rotate_request(presented: &str, successor: &str, now: &str) -> RotateRefreshToken {
        RotateRefreshToken {
            presented: presented.into(),
            successor_id: RefreshTokenId(successor.into()),
            now: Timestamp(now.into()),
            expires_at: Timestamp("2026-08-19T00:00:00Z".into()),
        }
    }

    #[test]
    fn issue_persists_only_a_hash_and_returns_cleartext_once() {
        let mut minter = RefreshTokenMinter::new(SequentialEntropy::default());
        let mut dir = RefreshTokenDirectory::new();
        let issued = minter
            .issue(&mut dir, mint_request("rt_1", "chain_1"))
            .unwrap();

        assert!(issued.secret.starts_with(TOKEN_SCHEME));
        // Only the hash is stored, never the cleartext.
        assert_ne!(issued.secret, issued.token.token_hash);
        assert!(!issued.secret.contains(&issued.token.token_hash));
        assert_eq!(
            dir.token(&RefreshTokenId("rt_1".into())),
            Some(&issued.token)
        );
        assert!(
            issued
                .token
                .is_live(&Timestamp("2026-06-20T00:00:00Z".into()))
        );
    }

    #[test]
    fn rotation_retires_the_old_token_and_issues_a_successor() {
        let mut minter = RefreshTokenMinter::new(SequentialEntropy::default());
        let mut dir = RefreshTokenDirectory::new();
        let first = minter
            .issue(&mut dir, mint_request("rt_1", "chain_1"))
            .unwrap();

        let second = minter
            .rotate(
                &mut dir,
                rotate_request(&first.secret, "rt_2", "2026-06-20T00:00:00Z"),
            )
            .unwrap();

        // The successor shares the chain and inherits the grant coordinates.
        assert_eq!(second.token.chain_id, RefreshTokenChainId("chain_1".into()));
        assert_eq!(second.token.subject, "acct_1");
        assert_eq!(second.token.audience, "packs-service");
        assert_eq!(second.token.scope, vec!["pack.read".to_owned()]);
        assert_ne!(first.secret, second.secret);

        // The predecessor is now retired (rotated) but not revoked.
        let retired = dir.token(&RefreshTokenId("rt_1".into())).unwrap();
        assert!(retired.is_retired());
        assert!(!retired.is_revoked());

        // The successor is the only live token in the chain.
        let live: Vec<&RefreshTokenId> = dir
            .chain(&RefreshTokenChainId("chain_1".into()))
            .into_iter()
            .filter(|t| t.is_live(&Timestamp("2026-06-21T00:00:00Z".into())))
            .map(|t| &t.id)
            .collect();
        assert_eq!(live, vec![&RefreshTokenId("rt_2".into())]);
    }

    #[test]
    fn replaying_a_retired_token_revokes_the_whole_chain() {
        let mut minter = RefreshTokenMinter::new(SequentialEntropy::default());
        let mut dir = RefreshTokenDirectory::new();
        let first = minter
            .issue(&mut dir, mint_request("rt_1", "chain_1"))
            .unwrap();
        let _second = minter
            .rotate(
                &mut dir,
                rotate_request(&first.secret, "rt_2", "2026-06-20T00:00:00Z"),
            )
            .unwrap();

        // Replaying the now-retired first token is a theft signal.
        let err = minter
            .rotate(
                &mut dir,
                rotate_request(&first.secret, "rt_3", "2026-06-20T01:00:00Z"),
            )
            .unwrap_err();
        assert_eq!(
            err,
            IamError::RefreshTokenReuseDetected {
                chain_id: RefreshTokenChainId("chain_1".into()),
            }
        );

        // The entire chain — predecessor and the live successor — is revoked.
        for token in dir.chain(&RefreshTokenChainId("chain_1".into())) {
            assert!(token.is_revoked(), "{:?} should be revoked", token.id);
        }
        // The leaked successor token cannot be rotated either; it now reads as an
        // opaque invalid token (revoked chain).
        let still_invalid = minter
            .rotate(
                &mut dir,
                rotate_request(&_second.secret, "rt_4", "2026-06-20T02:00:00Z"),
            )
            .unwrap_err();
        assert_eq!(still_invalid, IamError::RefreshTokenInvalid);
    }

    #[test]
    fn unknown_and_malformed_tokens_fail_closed_identically() {
        let mut minter = RefreshTokenMinter::new(SequentialEntropy::default());
        let mut dir = RefreshTokenDirectory::new();
        minter
            .issue(&mut dir, mint_request("rt_1", "chain_1"))
            .unwrap();

        // A well-formed but unregistered token.
        let unknown = minter
            .rotate(
                &mut dir,
                rotate_request("oiamr_deadbeef", "rt_x", "2026-06-20T00:00:00Z"),
            )
            .unwrap_err();
        assert_eq!(unknown, IamError::RefreshTokenInvalid);

        // A token missing the scheme marker never reaches the hash comparison.
        let malformed = minter
            .rotate(
                &mut dir,
                rotate_request("not-a-token", "rt_y", "2026-06-20T00:00:00Z"),
            )
            .unwrap_err();
        assert_eq!(malformed, IamError::RefreshTokenInvalid);
    }

    #[test]
    fn expired_token_fails_closed() {
        let mut minter = RefreshTokenMinter::new(SequentialEntropy::default());
        let mut dir = RefreshTokenDirectory::new();
        let first = minter
            .issue(&mut dir, mint_request("rt_1", "chain_1"))
            .unwrap();

        let err = minter
            .rotate(
                &mut dir,
                rotate_request(&first.secret, "rt_2", "2026-07-19T00:00:00Z"),
            )
            .unwrap_err();
        assert_eq!(
            err,
            IamError::RefreshTokenExpired {
                id: RefreshTokenId("rt_1".into()),
            }
        );
    }

    #[test]
    fn revoke_chain_is_idempotent_and_blocks_rotation() {
        let mut minter = RefreshTokenMinter::new(SequentialEntropy::default());
        let mut dir = RefreshTokenDirectory::new();
        let first = minter
            .issue(&mut dir, mint_request("rt_1", "chain_1"))
            .unwrap();

        let now = Timestamp("2026-06-20T00:00:00Z".into());
        assert_eq!(
            dir.revoke_chain(&RefreshTokenChainId("chain_1".into()), &now),
            1
        );
        // Re-revoking newly stamps nothing.
        assert_eq!(
            dir.revoke_chain(
                &RefreshTokenChainId("chain_1".into()),
                &Timestamp("2026-06-20T01:00:00Z".into())
            ),
            0
        );
        // The first revocation stamp is preserved.
        assert_eq!(
            dir.token(&RefreshTokenId("rt_1".into()))
                .unwrap()
                .revoked_at,
            Some(now)
        );

        // A revoked chain cannot be rotated; it reads as opaque invalid.
        let err = minter
            .rotate(
                &mut dir,
                rotate_request(&first.secret, "rt_2", "2026-06-21T00:00:00Z"),
            )
            .unwrap_err();
        assert_eq!(err, IamError::RefreshTokenInvalid);

        // An unknown chain revokes nothing.
        assert_eq!(
            dir.revoke_chain(&RefreshTokenChainId("nope".into()), &now_ref()),
            0
        );
    }

    fn now_ref() -> Timestamp {
        Timestamp("2026-06-20T00:00:00Z".into())
    }

    #[test]
    fn create_rejects_a_duplicate_id() {
        let mut minter = RefreshTokenMinter::new(SequentialEntropy::default());
        let mut dir = RefreshTokenDirectory::new();
        minter
            .issue(&mut dir, mint_request("rt_1", "chain_1"))
            .unwrap();
        // A second issue under the same id fails closed.
        let err = minter
            .issue(&mut dir, mint_request("rt_1", "chain_2"))
            .unwrap_err();
        assert_eq!(
            err,
            IamError::DuplicateRefreshToken {
                id: RefreshTokenId("rt_1".into()),
            }
        );
    }

    #[test]
    fn issue_rejects_a_non_forward_window() {
        let mut minter = RefreshTokenMinter::new(SequentialEntropy::default());
        let mut dir = RefreshTokenDirectory::new();
        let mut request = mint_request("rt_1", "chain_1");
        request.expires_at = request.created_at.clone();
        let err = minter.issue(&mut dir, request).unwrap_err();
        assert_eq!(
            err,
            IamError::InvalidRefreshTokenWindow {
                id: RefreshTokenId("rt_1".into()),
            }
        );
        assert!(dir.token(&RefreshTokenId("rt_1".into())).is_none());
    }
}
