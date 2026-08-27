//! OAuth login-challenge generation and callback verification.
//!
//! This closes the front half of the login loop: an [`OAuthChallengeService`]
//! mints the `state`, optional OIDC `nonce`, and optional PKCE verifier for a
//! pending login, derives the PKCE `S256` challenge, and persists a short-TTL
//! [`OAuthLoginState`] holding only the *hashes* of those secrets. The cleartext
//! secrets are returned once to the caller so they can be sent to the provider
//! and the browser; they are never stored.
//!
//! On callback the service consumes the challenge exactly once through the
//! authoritative [`LoginFlowRepository`] and verifies the presented
//! values against the stored hashes in constant time. Any mismatch, expiry, or
//! replay fails closed, and the challenge is burned regardless of the outcome so
//! a failed attempt cannot be retried.

use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;

use awaken_iam_contract::{IdentityProviderKey, OAuthLoginState, OAuthLoginStateId, Timestamp};

use crate::{IamError, LoginBinding, LoginFlowRepository, RepositoryError};

/// Number of random bytes drawn for each minted login secret (256 bits).
const SECRET_BYTES: usize = 32;

/// Source of cryptographically strong randomness.
///
/// Generation is parameterized over this seam so deployments inject the OS
/// CSPRNG ([`OsEntropy`]) while tests inject a deterministic generator.
pub trait EntropySource {
    /// Fill `buf` with cryptographically strong random bytes.
    fn fill_bytes(&mut self, buf: &mut [u8]);
}

/// Operating-system backed entropy source.
#[derive(Debug, Default, Clone, Copy)]
pub struct OsEntropy;

impl EntropySource for OsEntropy {
    fn fill_bytes(&mut self, buf: &mut [u8]) {
        getrandom::fill(buf).expect("operating system entropy source is unavailable");
    }
}

/// PKCE challenge transform method.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PkceMethod {
    /// `BASE64URL(SHA256(verifier))`, the only method this service issues.
    S256,
}

/// PKCE challenge derived from a freshly minted verifier.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PkceChallenge {
    /// Transform used to derive [`PkceChallenge::challenge`].
    pub method: PkceMethod,
    /// The `code_challenge` value to send to the authorization endpoint.
    pub challenge: String,
}

/// Request to begin an OAuth login.
///
/// `created_at`/`expires_at` define the short TTL window; time math lives with
/// the caller, consistent with the rest of the contract where timestamps are
/// canonical RFC 3339 strings passed in explicitly.
#[derive(Debug, Clone)]
pub struct BeginLogin {
    /// Row id assigned to the persisted challenge.
    pub id: OAuthLoginStateId,
    /// Provider selected for the pending login.
    pub provider_key: IdentityProviderKey,
    /// Optional post-login return path.
    pub return_to: Option<String>,
    /// Whether to mint an OIDC nonce.
    pub include_nonce: bool,
    /// Whether to mint a PKCE verifier and challenge.
    pub include_pkce: bool,
    /// Challenge creation timestamp.
    pub created_at: Timestamp,
    /// Challenge expiration timestamp; must be strictly after `created_at`.
    pub expires_at: Timestamp,
}

/// Cleartext secrets returned once to the caller of [`OAuthChallengeService::begin_login`].
///
/// These are sent to the provider/browser and then discarded; only their hashes
/// are persisted in the [`OAuthLoginState`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LoginSecrets {
    /// The opaque OAuth `state` value.
    pub state: String,
    /// The OIDC `nonce`, when requested.
    pub nonce: Option<String>,
    /// The PKCE code verifier, when requested.
    pub pkce_verifier: Option<String>,
    /// The PKCE challenge derived from the verifier, when requested.
    pub pkce_challenge: Option<PkceChallenge>,
}

/// Result of beginning a login: the persisted challenge plus its cleartext secrets.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IssuedLogin {
    /// The persisted login-state row (hashes only).
    pub state: OAuthLoginState,
    /// One-time cleartext secrets for the caller.
    pub secrets: LoginSecrets,
}

/// Values presented on the provider callback to complete a login.
#[derive(Debug, Clone)]
pub struct LoginAttempt {
    /// Login-state id echoed back from the issued challenge.
    pub id: OAuthLoginStateId,
    /// Presented OAuth `state` value.
    pub state: String,
    /// Presented OIDC `nonce`, if any.
    pub nonce: Option<String>,
    /// Presented PKCE verifier, if any.
    pub pkce_verifier: Option<String>,
}

/// Mints and verifies OAuth login challenges.
#[derive(Debug, Default, Clone)]
pub struct OAuthChallengeService<E: EntropySource> {
    entropy: E,
}

impl<E: EntropySource> OAuthChallengeService<E> {
    /// Build a service over the given entropy source.
    pub fn new(entropy: E) -> Self {
        Self { entropy }
    }

    /// Mint a login challenge, persist its hashes with a short TTL, and return
    /// the one-time cleartext secrets.
    ///
    /// Fails with [`IamError::InvalidLoginWindow`] when the window is not
    /// forward-going, or [`IamError::DuplicateLoginState`] when the id is reused.
    pub fn begin_login(
        &mut self,
        repository: &dyn LoginFlowRepository,
        request: BeginLogin,
    ) -> Result<IssuedLogin, IamError> {
        if request.expires_at.0 <= request.created_at.0 {
            return Err(IamError::InvalidLoginWindow { id: request.id });
        }

        let state = self.random_token();
        let state_hash = hash_secret(&state);

        let nonce = request.include_nonce.then(|| self.random_token());
        let nonce_hash = nonce.as_deref().map(hash_secret);

        let pkce_verifier = request.include_pkce.then(|| self.random_token());
        // `S256` is `BASE64URL(SHA256(verifier))`, which is exactly the stored
        // verifier hash; the challenge sent to the provider and the persisted
        // hash are the same derived value.
        let pkce_verifier_hash = pkce_verifier.as_deref().map(hash_secret);
        let pkce_challenge = pkce_verifier_hash.clone().map(|challenge| PkceChallenge {
            method: PkceMethod::S256,
            challenge,
        });

        let login_state = OAuthLoginState {
            id: request.id,
            provider_key: request.provider_key,
            state_hash,
            nonce_hash,
            pkce_verifier_hash,
            return_to: request.return_to,
            created_at: request.created_at,
            expires_at: request.expires_at,
            consumed_at: None,
        };

        repository
            .start(login_state.clone())
            .map_err(|error| match error {
                RepositoryError::Conflict(_) => IamError::DuplicateLoginState {
                    id: login_state.id.clone(),
                },
                RepositoryError::NotFound(_) | RepositoryError::Backend(_) => {
                    IamError::LoginFlowStorageUnavailable
                }
            })?;

        Ok(IssuedLogin {
            state: login_state,
            secrets: LoginSecrets {
                state,
                nonce,
                pkce_verifier,
                pkce_challenge,
            },
        })
    }

    /// Consume a login challenge and verify the presented bindings.
    ///
    /// The challenge is consumed first — so expiry, replay, and unknown-id all
    /// fail closed through [`LoginFlowRepository`] and a single
    /// attempt is burned even when a binding later mismatches. Then `state`,
    /// `nonce`, and the PKCE verifier are each verified in constant time against
    /// the stored hashes, including presence parity. Returns the consumed
    /// challenge on success.
    pub fn complete_login(
        &self,
        repository: &dyn LoginFlowRepository,
        attempt: &LoginAttempt,
        now: Timestamp,
    ) -> Result<OAuthLoginState, IamError> {
        let mut consumed = repository
            .get(&attempt.id)
            .map_err(|_| IamError::LoginFlowStorageUnavailable)?
            .ok_or_else(|| IamError::LoginStateNotFound {
                id: attempt.id.clone(),
            })?;
        if consumed.consumed_at.is_some() {
            return Err(IamError::LoginStateAlreadyConsumed {
                id: attempt.id.clone(),
            });
        }
        if now.0 >= consumed.expires_at.0 {
            return Err(IamError::LoginStateExpired {
                id: attempt.id.clone(),
            });
        }
        repository
            .mark_consumed(&attempt.id, now.clone())
            .map_err(|error| match error {
                RepositoryError::Conflict(_) => IamError::LoginStateAlreadyConsumed {
                    id: attempt.id.clone(),
                },
                RepositoryError::NotFound(_) => IamError::LoginStateNotFound {
                    id: attempt.id.clone(),
                },
                RepositoryError::Backend(_) => IamError::LoginFlowStorageUnavailable,
            })?;
        consumed.consumed_at = Some(now);

        verify_binding(
            &consumed.id,
            LoginBinding::State,
            Some(attempt.state.as_str()),
            Some(consumed.state_hash.as_str()),
        )?;
        verify_binding(
            &consumed.id,
            LoginBinding::Nonce,
            attempt.nonce.as_deref(),
            consumed.nonce_hash.as_deref(),
        )?;
        verify_binding(
            &consumed.id,
            LoginBinding::PkceVerifier,
            attempt.pkce_verifier.as_deref(),
            consumed.pkce_verifier_hash.as_deref(),
        )?;

        Ok(consumed)
    }

    fn random_token(&mut self) -> String {
        let mut buf = [0u8; SECRET_BYTES];
        self.entropy.fill_bytes(&mut buf);
        URL_SAFE_NO_PAD.encode(buf)
    }
}

/// Hash a login secret into its stored, comparable representation.
pub(crate) fn hash_secret(secret: &str) -> String {
    let digest = Sha256::digest(secret.as_bytes());
    URL_SAFE_NO_PAD.encode(digest)
}

/// Verify one presented binding against its stored hash, enforcing presence
/// parity and a constant-time hash comparison.
fn verify_binding(
    id: &OAuthLoginStateId,
    binding: LoginBinding,
    presented: Option<&str>,
    stored_hash: Option<&str>,
) -> Result<(), IamError> {
    let mismatch = || IamError::LoginStateMismatch {
        id: id.clone(),
        binding,
    };
    match (presented, stored_hash) {
        (Some(value), Some(stored)) => {
            let computed = hash_secret(value);
            if bool::from(computed.as_bytes().ct_eq(stored.as_bytes())) {
                Ok(())
            } else {
                Err(mismatch())
            }
        }
        (None, None) => Ok(()),
        // A binding was bound but not presented, or presented but never bound.
        _ => Err(mismatch()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;
    use std::sync::Mutex;

    #[derive(Default)]
    struct TestLoginRepository(Mutex<HashMap<OAuthLoginStateId, OAuthLoginState>>);

    impl LoginFlowRepository for TestLoginRepository {
        fn start(&self, state: OAuthLoginState) -> crate::RepositoryResult<()> {
            let mut states = self.0.lock().unwrap();
            if states.contains_key(&state.id) {
                return Err(RepositoryError::Conflict("duplicate login flow".into()));
            }
            states.insert(state.id.clone(), state);
            Ok(())
        }

        fn get(&self, id: &OAuthLoginStateId) -> crate::RepositoryResult<Option<OAuthLoginState>> {
            Ok(self.0.lock().unwrap().get(id).cloned())
        }

        fn mark_consumed(
            &self,
            id: &OAuthLoginStateId,
            at: Timestamp,
        ) -> crate::RepositoryResult<()> {
            let mut states = self.0.lock().unwrap();
            let state = states
                .get_mut(id)
                .ok_or_else(|| RepositoryError::NotFound("login flow".into()))?;
            if state.consumed_at.is_some() {
                return Err(RepositoryError::Conflict("login flow consumed".into()));
            }
            state.consumed_at = Some(at);
            Ok(())
        }
    }

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

    fn begin_request(id: &str, include_nonce: bool, include_pkce: bool) -> BeginLogin {
        BeginLogin {
            id: OAuthLoginStateId(id.into()),
            provider_key: IdentityProviderKey("fake".into()),
            return_to: Some("/dashboard".into()),
            include_nonce,
            include_pkce,
            created_at: Timestamp("2026-06-19T00:00:00Z".into()),
            expires_at: Timestamp("2026-06-19T00:05:00Z".into()),
        }
    }

    #[test]
    fn begin_login_mints_distinct_secrets_and_stores_only_hashes() {
        let mut service = OAuthChallengeService::new(SequentialEntropy::default());
        let repository = TestLoginRepository::default();

        let issued = service
            .begin_login(&repository, begin_request("login_1", true, true))
            .unwrap();

        let secrets = &issued.secrets;
        let nonce = secrets.nonce.as_deref().unwrap();
        let verifier = secrets.pkce_verifier.as_deref().unwrap();
        // State, nonce, and verifier are independently minted and distinct.
        assert_ne!(secrets.state, nonce);
        assert_ne!(secrets.state, verifier);
        assert_ne!(nonce, verifier);

        // Cleartext is never the stored value.
        assert_ne!(secrets.state, issued.state.state_hash);
        assert_ne!(Some(verifier.to_owned()), issued.state.pkce_verifier_hash);

        // PKCE S256 challenge equals the stored verifier hash.
        let challenge = secrets.pkce_challenge.as_ref().unwrap();
        assert_eq!(challenge.method, PkceMethod::S256);
        assert_eq!(
            Some(challenge.challenge.clone()),
            issued.state.pkce_verifier_hash
        );

        // The persisted row is the one held in the repository and is unconsumed.
        assert_eq!(
            repository
                .get(&OAuthLoginStateId("login_1".into()))
                .unwrap(),
            Some(issued.state.clone())
        );
        assert!(issued.state.consumed_at.is_none());
    }

    #[test]
    fn begin_login_omits_optional_secrets_when_not_requested() {
        let mut service = OAuthChallengeService::new(SequentialEntropy::default());
        let repository = TestLoginRepository::default();

        let issued = service
            .begin_login(&repository, begin_request("login_1", false, false))
            .unwrap();

        assert!(issued.secrets.nonce.is_none());
        assert!(issued.secrets.pkce_verifier.is_none());
        assert!(issued.secrets.pkce_challenge.is_none());
        assert!(issued.state.nonce_hash.is_none());
        assert!(issued.state.pkce_verifier_hash.is_none());
    }

    #[test]
    fn begin_login_rejects_non_forward_window() {
        let mut service = OAuthChallengeService::new(SequentialEntropy::default());
        let repository = TestLoginRepository::default();
        let mut request = begin_request("login_1", true, true);
        request.expires_at = request.created_at.clone();

        let err = service.begin_login(&repository, request).unwrap_err();
        assert_eq!(
            err,
            IamError::InvalidLoginWindow {
                id: OAuthLoginStateId("login_1".into()),
            }
        );
        // Nothing is persisted on a rejected window.
        assert!(
            repository
                .get(&OAuthLoginStateId("login_1".into()))
                .unwrap()
                .is_none()
        );
    }

    #[test]
    fn complete_login_succeeds_and_consumes_on_matching_bindings() {
        // Cause/effect graph: C1=row exists, C2=unconsumed, C3=live,
        // C4=state/nonce/PKCE match, C5=repository available. Effects are one
        // atomic consume and the bound row returned. Decision-table rule
        // C1+C2+C3+C4+C5 succeeds; !C1/not C2/not C3/not C4/!C5 each fails
        // closed. This case selects success plus the not-C2 replay row; sibling
        // cases select expiry and each binding mismatch.
        let mut service = OAuthChallengeService::new(SequentialEntropy::default());
        let repository = TestLoginRepository::default();
        let issued = service
            .begin_login(&repository, begin_request("login_1", true, true))
            .unwrap();

        let attempt = LoginAttempt {
            id: OAuthLoginStateId("login_1".into()),
            state: issued.secrets.state.clone(),
            nonce: issued.secrets.nonce.clone(),
            pkce_verifier: issued.secrets.pkce_verifier.clone(),
        };

        let consumed = service
            .complete_login(
                &repository,
                &attempt,
                Timestamp("2026-06-19T00:01:00Z".into()),
            )
            .unwrap();
        assert!(consumed.consumed_at.is_some());

        // Replay of even a perfectly valid attempt fails closed.
        let replay = service
            .complete_login(
                &repository,
                &attempt,
                Timestamp("2026-06-19T00:02:00Z".into()),
            )
            .unwrap_err();
        assert_eq!(
            replay,
            IamError::LoginStateAlreadyConsumed {
                id: OAuthLoginStateId("login_1".into()),
            }
        );
    }

    #[test]
    fn complete_login_fails_closed_on_state_mismatch_and_burns_challenge() {
        let mut service = OAuthChallengeService::new(SequentialEntropy::default());
        let repository = TestLoginRepository::default();
        let issued = service
            .begin_login(&repository, begin_request("login_1", false, false))
            .unwrap();

        let forged = LoginAttempt {
            id: OAuthLoginStateId("login_1".into()),
            state: "forged-state".into(),
            nonce: None,
            pkce_verifier: None,
        };

        let err = service
            .complete_login(
                &repository,
                &forged,
                Timestamp("2026-06-19T00:01:00Z".into()),
            )
            .unwrap_err();
        assert_eq!(
            err,
            IamError::LoginStateMismatch {
                id: OAuthLoginStateId("login_1".into()),
                binding: LoginBinding::State,
            }
        );

        // The mismatched attempt still burned the single-use challenge, so even
        // the correct state can no longer be replayed.
        let retry = LoginAttempt {
            id: OAuthLoginStateId("login_1".into()),
            state: issued.secrets.state.clone(),
            nonce: None,
            pkce_verifier: None,
        };
        let retry_err = service
            .complete_login(
                &repository,
                &retry,
                Timestamp("2026-06-19T00:02:00Z".into()),
            )
            .unwrap_err();
        assert_eq!(
            retry_err,
            IamError::LoginStateAlreadyConsumed {
                id: OAuthLoginStateId("login_1".into()),
            }
        );
    }

    #[test]
    fn complete_login_requires_presented_nonce_and_pkce() {
        let mut service = OAuthChallengeService::new(SequentialEntropy::default());
        let repository = TestLoginRepository::default();
        let issued = service
            .begin_login(&repository, begin_request("login_1", true, true))
            .unwrap();

        // Omitting the bound nonce fails closed.
        let missing_nonce = LoginAttempt {
            id: OAuthLoginStateId("login_1".into()),
            state: issued.secrets.state.clone(),
            nonce: None,
            pkce_verifier: issued.secrets.pkce_verifier.clone(),
        };
        let err = service
            .complete_login(
                &repository,
                &missing_nonce,
                Timestamp("2026-06-19T00:01:00Z".into()),
            )
            .unwrap_err();
        assert_eq!(
            err,
            IamError::LoginStateMismatch {
                id: OAuthLoginStateId("login_1".into()),
                binding: LoginBinding::Nonce,
            }
        );
    }

    #[test]
    fn complete_login_rejects_wrong_pkce_verifier() {
        let mut service = OAuthChallengeService::new(SequentialEntropy::default());
        let repository = TestLoginRepository::default();
        let issued = service
            .begin_login(&repository, begin_request("login_1", false, true))
            .unwrap();

        let wrong_pkce = LoginAttempt {
            id: OAuthLoginStateId("login_1".into()),
            state: issued.secrets.state.clone(),
            nonce: None,
            pkce_verifier: Some("not-the-verifier".into()),
        };
        let err = service
            .complete_login(
                &repository,
                &wrong_pkce,
                Timestamp("2026-06-19T00:01:00Z".into()),
            )
            .unwrap_err();
        assert_eq!(
            err,
            IamError::LoginStateMismatch {
                id: OAuthLoginStateId("login_1".into()),
                binding: LoginBinding::PkceVerifier,
            }
        );
    }

    #[test]
    fn complete_login_rejects_expired_challenge() {
        let mut service = OAuthChallengeService::new(SequentialEntropy::default());
        let repository = TestLoginRepository::default();
        let issued = service
            .begin_login(&repository, begin_request("login_1", false, false))
            .unwrap();

        let attempt = LoginAttempt {
            id: OAuthLoginStateId("login_1".into()),
            state: issued.secrets.state.clone(),
            nonce: None,
            pkce_verifier: None,
        };
        let err = service
            .complete_login(
                &repository,
                &attempt,
                Timestamp("2026-06-19T01:00:00Z".into()),
            )
            .unwrap_err();
        assert_eq!(
            err,
            IamError::LoginStateExpired {
                id: OAuthLoginStateId("login_1".into()),
            }
        );
    }
}
