//! One-time local setup challenge exchange into the canonical browser session.
//!
//! Local products do not invent a second session or persist an administrator API
//! token in browser storage. The CLI issues a short-lived challenge here; the
//! browser consumes it exactly once and this service delegates session creation
//! to [`SessionGateway`].

use std::collections::HashMap;

use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use sha2::{Digest, Sha256};

use awaken_iam_contract::{AccountId, SessionId, Timestamp};
use awaken_iam_core::{EntropySource, EstablishSession};

use crate::{EstablishedSession, SessionGateway};

const SETUP_TOKEN_BYTES: usize = 32;

/// Stable identifier of one local setup challenge.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct LocalSetupId(pub String);

/// Inputs controlled by the local host when issuing a setup challenge.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BeginLocalSetup {
    pub id: LocalSetupId,
    pub account_id: AccountId,
    pub created_at: Timestamp,
    pub expires_at: Timestamp,
}

/// One-time cleartext hand-off returned to the CLI.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IssuedLocalSetup {
    pub id: LocalSetupId,
    pub setup_token: String,
    pub expires_at: Timestamp,
}

/// Browser exchange request. Session identity is pinned by the challenge;
/// callers only choose the session id and lifetime.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExchangeLocalSetup {
    pub id: LocalSetupId,
    pub setup_token: String,
    pub session_id: SessionId,
    pub now: Timestamp,
    pub session_expires_at: Timestamp,
    pub cookie_max_age_secs: Option<u64>,
}

#[derive(Debug, Clone)]
struct LocalSetupChallenge {
    account_id: AccountId,
    token_hash: String,
    expires_at: Timestamp,
    consumed_at: Option<Timestamp>,
}

/// Coarse, non-enumerating failure contract for local setup.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum LocalSetupError {
    #[error("local setup challenge is invalid")]
    InvalidChallenge,
    #[error("local setup window is invalid")]
    InvalidWindow,
    #[error("local setup session could not be established")]
    Session,
    #[error("local setup session storage is unavailable")]
    SessionUnavailable,
}

/// Issues and atomically consumes local setup challenges.
#[derive(Debug)]
pub struct LocalSetupGateway<E: EntropySource> {
    entropy: E,
    challenges: HashMap<LocalSetupId, LocalSetupChallenge>,
}

impl<E: EntropySource> LocalSetupGateway<E> {
    pub fn new(entropy: E) -> Self {
        Self {
            entropy,
            challenges: HashMap::new(),
        }
    }

    /// Issue a short-lived challenge. Only its SHA-256 digest remains in memory.
    pub fn begin(&mut self, request: BeginLocalSetup) -> Result<IssuedLocalSetup, LocalSetupError> {
        if request.expires_at.0 <= request.created_at.0 {
            return Err(LocalSetupError::InvalidWindow);
        }
        if self.challenges.contains_key(&request.id) {
            return Err(LocalSetupError::InvalidChallenge);
        }
        let mut bytes = [0_u8; SETUP_TOKEN_BYTES];
        self.entropy.fill_bytes(&mut bytes);
        let setup_token = URL_SAFE_NO_PAD.encode(bytes);
        self.challenges.insert(
            request.id.clone(),
            LocalSetupChallenge {
                account_id: request.account_id,
                token_hash: hash(&setup_token),
                expires_at: request.expires_at.clone(),
                consumed_at: None,
            },
        );
        Ok(IssuedLocalSetup {
            id: request.id,
            setup_token,
            expires_at: request.expires_at,
        })
    }

    /// Consume the challenge once and establish a session through the existing
    /// session authority. A failed session mint does not make the setup token
    /// reusable: replay safety wins over retrying a partially failed exchange.
    pub fn exchange<S: EntropySource>(
        &mut self,
        request: ExchangeLocalSetup,
        sessions: &mut SessionGateway<S>,
    ) -> Result<EstablishedSession, LocalSetupError> {
        let challenge = self
            .challenges
            .get_mut(&request.id)
            .ok_or(LocalSetupError::InvalidChallenge)?;
        if challenge.consumed_at.is_some()
            || request.now.0 >= challenge.expires_at.0
            || hash(&request.setup_token) != challenge.token_hash
        {
            return Err(LocalSetupError::InvalidChallenge);
        }
        challenge.consumed_at = Some(request.now.clone());
        sessions
            .establish_session(
                EstablishSession {
                    id: request.session_id,
                    account_id: challenge.account_id.clone(),
                    external_identity_id: None,
                    created_at: request.now,
                    expires_at: request.session_expires_at,
                },
                request.cookie_max_age_secs,
            )
            .map_err(|error| match error {
                awaken_iam_core::IamError::SessionStorageUnavailable => {
                    LocalSetupError::SessionUnavailable
                }
                _ => LocalSetupError::Session,
            })
    }
}

fn hash(secret: &str) -> String {
    URL_SAFE_NO_PAD.encode(Sha256::digest(secret.as_bytes()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{SameSite, SessionCookieConfig};

    #[derive(Debug, Default)]
    struct SequentialEntropy(u8);

    impl EntropySource for SequentialEntropy {
        fn fill_bytes(&mut self, buf: &mut [u8]) {
            for byte in buf {
                *byte = self.0;
                self.0 = self.0.wrapping_add(1);
            }
        }
    }

    fn begin() -> BeginLocalSetup {
        BeginLocalSetup {
            id: LocalSetupId("setup-1".into()),
            account_id: AccountId("local-installation".into()),
            created_at: Timestamp("2026-07-28T00:00:00Z".into()),
            expires_at: Timestamp("2026-07-28T00:05:00Z".into()),
        }
    }

    fn exchange(token: String, now: &str) -> ExchangeLocalSetup {
        ExchangeLocalSetup {
            id: LocalSetupId("setup-1".into()),
            setup_token: token,
            session_id: SessionId("session-1".into()),
            now: Timestamp(now.into()),
            session_expires_at: Timestamp("2026-07-29T00:00:00Z".into()),
            cookie_max_age_secs: Some(86_400),
        }
    }

    fn sessions() -> SessionGateway<SequentialEntropy> {
        SessionGateway::with_entropy(
            SequentialEntropy(128),
            SessionCookieConfig {
                secure: false,
                same_site: SameSite::Strict,
                ..SessionCookieConfig::default()
            },
        )
    }

    // Cause/effect decision table:
    // valid+fresh+unused -> session; wrong/expired/consumed -> same coarse error.
    #[test]
    fn challenge_exchanges_once_into_the_existing_hardened_session() {
        let mut setup = LocalSetupGateway::new(SequentialEntropy::default());
        let issued = setup.begin(begin()).unwrap();
        let mut sessions = sessions();
        let established = setup
            .exchange(
                exchange(issued.setup_token.clone(), "2026-07-28T00:01:00Z"),
                &mut sessions,
            )
            .unwrap();
        assert_eq!(
            established.view.account_id,
            AccountId("local-installation".into())
        );
        assert!(established.set_cookie.contains("; HttpOnly"));
        assert!(established.set_cookie.contains("; SameSite=Strict"));
        assert!(!established.set_cookie.contains("; Secure"));
        assert_eq!(
            setup
                .exchange(
                    exchange(issued.setup_token, "2026-07-28T00:02:00Z"),
                    &mut sessions
                )
                .unwrap_err(),
            LocalSetupError::InvalidChallenge
        );
    }

    #[test]
    fn wrong_and_expired_tokens_fail_with_the_same_public_error() {
        for (token, now) in [
            ("wrong".to_owned(), "2026-07-28T00:01:00Z"),
            (
                LocalSetupGateway::new(SequentialEntropy::default())
                    .begin(begin())
                    .unwrap()
                    .setup_token,
                "2026-07-28T00:05:00Z",
            ),
        ] {
            let mut setup = LocalSetupGateway::new(SequentialEntropy::default());
            let issued = setup.begin(begin()).unwrap();
            let presented = if token == "wrong" {
                token
            } else {
                issued.setup_token
            };
            assert_eq!(
                setup
                    .exchange(exchange(presented, now), &mut sessions())
                    .unwrap_err(),
                LocalSetupError::InvalidChallenge
            );
        }
    }
}
