//! Session establishment: minting the bearer session token after login.
//!
//! The front half of the login loop ([`crate::OAuthChallengeService`]) proves
//! who came back from the provider. This module closes the back half: once a
//! login resolves to an account, [`SessionMinter`] draws a fresh opaque session
//! token, persists a [`Session`] holding only the token's *hash*, and returns
//! the cleartext token once so the caller can place it in the session cookie.
//!
//! Like the login secrets, the cleartext token is never stored. Liveness
//! (expiry/revocation) and presented-token resolution are enforced by
//! [`SessionDirectory`]; this module only mints and persists.

use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;

use awaken_iam_contract::{AccountId, ExternalIdentityId, Session, SessionId, Timestamp};

use crate::login::hash_secret;
use crate::{EntropySource, IamError, SessionDirectory};

/// Number of random bytes drawn for a session token (256 bits).
const TOKEN_BYTES: usize = 32;

/// Hash a cleartext session token into its stored, comparable representation.
///
/// Callers that hold a presented cookie token (rather than minting one) use this
/// to derive the lookup key for
/// [`SessionDirectory::authenticate_by_token_hash`].
pub fn hash_session_token(token: &str) -> String {
    hash_secret(token)
}

/// Request to establish a session for an authenticated account.
///
/// Time math lives with the caller, consistent with the rest of the contract:
/// `created_at`/`expires_at` are canonical RFC 3339 strings passed in
/// explicitly, and `expires_at` must be strictly after `created_at`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EstablishSession {
    /// Row id assigned to the persisted session.
    pub id: SessionId,
    /// Account the session authenticates.
    pub account_id: AccountId,
    /// External identity used to establish the session, when applicable.
    pub external_identity_id: Option<ExternalIdentityId>,
    /// Session creation timestamp.
    pub created_at: Timestamp,
    /// Session expiration timestamp; must be strictly after `created_at`.
    pub expires_at: Timestamp,
}

/// Result of establishing a session: the persisted row plus its cleartext token.
///
/// The `token` is returned exactly once for the caller to set in the session
/// cookie. Only its hash is persisted on [`IssuedSession::session`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IssuedSession {
    /// The persisted session row (token hash only).
    pub session: Session,
    /// One-time cleartext bearer token for the session cookie.
    pub token: String,
}

/// Mints opaque session tokens and persists their sessions.
#[derive(Debug, Default, Clone)]
pub struct SessionMinter<E: EntropySource> {
    entropy: E,
}

impl<E: EntropySource> SessionMinter<E> {
    /// Build a minter over the given entropy source.
    pub fn new(entropy: E) -> Self {
        Self { entropy }
    }

    /// Mint a session token, persist its hash with the requested window, and
    /// return the one-time cleartext token.
    ///
    /// Fails with [`IamError::InvalidSessionWindow`] when the window is not
    /// forward-going, or [`IamError::DuplicateSession`] when the id is reused.
    pub fn establish(
        &mut self,
        directory: &mut SessionDirectory,
        request: EstablishSession,
    ) -> Result<IssuedSession, IamError> {
        let issued = self.issue(request)?;
        directory.create_session(issued.session.clone())?;
        Ok(issued)
    }

    /// Mint one session without selecting a persistence adapter.
    ///
    /// Server composition uses this seam with the canonical [`SessionRepository`](crate::SessionRepository),
    /// while the legacy in-memory directory helper above remains available to
    /// core-only consumers. The cleartext token is still returned exactly once.
    pub fn issue(&mut self, request: EstablishSession) -> Result<IssuedSession, IamError> {
        if request.expires_at.0 <= request.created_at.0 {
            return Err(IamError::InvalidSessionWindow {
                id: request.id.clone(),
            });
        }

        let token = self.random_token();
        let token_hash = hash_secret(&token);

        let session = Session {
            id: request.id,
            account_id: request.account_id,
            token_hash,
            external_identity_id: request.external_identity_id,
            created_at: request.created_at.clone(),
            last_seen_at: request.created_at,
            expires_at: request.expires_at,
            revoked_at: None,
        };

        Ok(IssuedSession { session, token })
    }

    fn random_token(&mut self) -> String {
        let mut buf = [0u8; TOKEN_BYTES];
        self.entropy.fill_bytes(&mut buf);
        URL_SAFE_NO_PAD.encode(buf)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Deterministic counter-based entropy so each minted token is distinct and
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

    fn establish_request(id: &str, expires_at: &str) -> EstablishSession {
        EstablishSession {
            id: SessionId(id.into()),
            account_id: AccountId("acct_1".into()),
            external_identity_id: Some(ExternalIdentityId("ext_1".into())),
            created_at: Timestamp("2026-06-19T00:00:00Z".into()),
            expires_at: Timestamp(expires_at.into()),
        }
    }

    #[test]
    fn establish_persists_only_token_hash_and_returns_cleartext_once() {
        let mut minter = SessionMinter::new(SequentialEntropy::default());
        let mut directory = SessionDirectory::new();

        let issued = minter
            .establish(
                &mut directory,
                establish_request("sess_1", "2026-06-20T00:00:00Z"),
            )
            .unwrap();

        // Cleartext token is never the stored value.
        assert_ne!(issued.token, issued.session.token_hash);
        // The stored hash matches the public hashing helper.
        assert_eq!(hash_session_token(&issued.token), issued.session.token_hash);
        // last_seen_at starts at creation.
        assert_eq!(issued.session.created_at, issued.session.last_seen_at);
        assert!(issued.session.revoked_at.is_none());

        // The persisted row is resolvable by the presented token's hash.
        let live = directory
            .authenticate_by_token_hash(
                &hash_session_token(&issued.token),
                Timestamp("2026-06-19T06:00:00Z".into()),
            )
            .unwrap();
        assert_eq!(live.id, SessionId("sess_1".into()));
        assert_eq!(live.account_id, AccountId("acct_1".into()));
    }

    #[test]
    fn establish_rejects_non_forward_window() {
        let mut minter = SessionMinter::new(SequentialEntropy::default());
        let mut directory = SessionDirectory::new();
        let mut request = establish_request("sess_1", "2026-06-20T00:00:00Z");
        request.expires_at = request.created_at.clone();

        let err = minter.establish(&mut directory, request).unwrap_err();
        assert_eq!(
            err,
            IamError::InvalidSessionWindow {
                id: SessionId("sess_1".into()),
            }
        );
        assert!(directory.session(&SessionId("sess_1".into())).is_none());
    }

    #[test]
    fn unknown_token_hash_fails_closed() {
        let mut directory = SessionDirectory::new();
        let err = directory
            .authenticate_by_token_hash("missing", Timestamp("2026-06-19T00:00:00Z".into()))
            .unwrap_err();
        assert!(matches!(err, IamError::SessionNotFound { .. }));
    }
}
