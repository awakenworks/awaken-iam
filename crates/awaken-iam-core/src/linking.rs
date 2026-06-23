//! Account-creation and external-identity linking policy.
//!
//! This is the back half of [`crate::OAuthChallengeService::complete_login`]:
//! once the challenge has proven *who* came back from the provider, the
//! [`AccountLinker`] decides *which account* the normalized
//! [`ExternalIdentityClaims`] resolve to, mutating the [`IdentityDirectory`]
//! exactly once per resolution. It realizes step 4 of the
//! [auth server](../../../docs/design/auth-server.md) login flow.
//!
//! The policy, in priority order:
//!
//! 1. **Existing link.** A known `(provider, subject)` selects its account and
//!    refreshes the mutable claims; the subject never forks a second account.
//! 2. **Duplicate-subject protection.** A subject already owned by one account
//!    can never be re-pointed at a *different* current-session account; that
//!    fails closed with [`IamError::DuplicateExternalIdentity`].
//! 3. **Current-session linking.** When the callback completes while a session
//!    is live, an unknown subject is linked to that session's account.
//! 4. **Email-match confirmation.** When nobody is signed in and the subject is
//!    unknown, a *verified* email that already belongs to an account does **not**
//!    silently merge: the resolution returns [`LoginResolution::EmailMatchPending`]
//!    and only links after the caller re-resolves with `email_match_confirmed`.
//! 5. **New account creation.** Otherwise a fresh account is created and the
//!    identity linked to it.
//!
//! Email is treated as a mutable claim throughout — it is never an identity key
//! and an unverified email can never reach an existing account.

use awaken_iam_contract::{
    Account, AccountId, AccountStatus, ExternalIdentity, ExternalIdentityClaims,
    ExternalIdentityId, ExternalSubject, IdentityProviderKey, Timestamp,
};

use crate::{IamError, IdentityDirectory};

/// Request to resolve a completed provider callback to an account.
///
/// `claims` are the normalized provider claims; `provider_key` plus
/// `claims.subject` form the immutable identity coordinate. Ids for any row the
/// resolution may create are supplied by the caller, consistent with the rest of
/// the login loop where id and time math live with the caller.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResolveLogin {
    /// Provider that issued the subject.
    pub provider_key: IdentityProviderKey,
    /// Normalized claims received from the provider on this callback.
    pub claims: ExternalIdentityClaims,
    /// Resolution timestamp; stamped onto created/refreshed rows.
    pub now: Timestamp,
    /// Account of the currently authenticated session, when the callback
    /// completed while a session was live (drives current-session linking).
    pub current_account: Option<AccountId>,
    /// Whether the caller has explicitly confirmed linking to an account matched
    /// only by a verified email. Ignored unless an email match is found.
    pub email_match_confirmed: bool,
    /// Account id to assign when a new account is created.
    pub new_account_id: AccountId,
    /// External-identity row id to assign when a link is created.
    pub external_identity_id: ExternalIdentityId,
}

/// Outcome of resolving a provider callback to an account.
///
/// Every variant except [`LoginResolution::EmailMatchPending`] reflects a
/// committed mutation of the directory; `EmailMatchPending` is the one outcome
/// that mutates nothing and asks the caller to re-resolve with explicit consent.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LoginResolution {
    /// The `(provider, subject)` was already linked; its account was selected and
    /// its mutable claims refreshed.
    Existing {
        /// Account the subject resolves to.
        account_id: AccountId,
        /// The refreshed external identity.
        identity: ExternalIdentity,
    },
    /// An unknown subject was linked to the currently authenticated account.
    LinkedToSession {
        /// Account the session authenticated.
        account_id: AccountId,
        /// The newly created link.
        identity: ExternalIdentity,
    },
    /// An unknown subject was linked to an email-matched account after explicit
    /// confirmation.
    LinkedByEmailConfirmation {
        /// Account the verified email resolved to.
        account_id: AccountId,
        /// The newly created link.
        identity: ExternalIdentity,
    },
    /// A new account was created and the subject linked to it.
    Created {
        /// The freshly created account id.
        account_id: AccountId,
        /// The newly created link.
        identity: ExternalIdentity,
    },
    /// An unknown subject carried a verified email that already belongs to an
    /// account. Nothing was changed; the caller must obtain explicit user
    /// confirmation and re-resolve with `email_match_confirmed` set.
    EmailMatchPending {
        /// Account the verified email currently belongs to.
        candidate_account_id: AccountId,
        /// The verified email that matched.
        email: String,
    },
}

/// Stateless domain service implementing the account-linking policy.
#[derive(Debug, Default, Clone, Copy)]
pub struct AccountLinker;

impl AccountLinker {
    /// Resolve a completed provider callback to an account, applying the linking
    /// policy and mutating `directory` at most once.
    pub fn resolve(
        &self,
        directory: &mut IdentityDirectory,
        request: ResolveLogin,
    ) -> Result<LoginResolution, IamError> {
        let ResolveLogin {
            provider_key,
            claims,
            now,
            current_account,
            email_match_confirmed,
            new_account_id,
            external_identity_id,
        } = request;

        // 1. Known `(provider, subject)` selects its account.
        let linked_account = directory
            .external_identity(&provider_key, &claims.subject)
            .map(|identity| identity.account_id.clone());
        if let Some(existing_account) = linked_account {
            // 2. Duplicate-subject protection: a subject already owned by one
            // account can never be moved onto a different current account.
            if let Some(current) = &current_account
                && current != &existing_account
            {
                return Err(IamError::DuplicateExternalIdentity {
                    provider_key,
                    subject: claims.subject.clone(),
                    existing_account_id: existing_account,
                });
            }
            let refreshed = directory
                .update_external_identity_claims(provider_key, claims, now)?
                .clone();
            return Ok(LoginResolution::Existing {
                account_id: existing_account,
                identity: refreshed,
            });
        }

        // 3. Link an unknown subject to the live session's account.
        if let Some(current) = current_account {
            if directory.account(&current).is_none() {
                return Err(IamError::MissingPrincipal);
            }
            let identity = make_identity(
                external_identity_id,
                current.clone(),
                provider_key,
                claims,
                now,
            );
            directory.link_external_identity(identity.clone())?;
            return Ok(LoginResolution::LinkedToSession {
                account_id: current,
                identity,
            });
        }

        // 4. Email-match confirmation policy (verified email only).
        if claims.email_verified == Some(true)
            && let Some(email) = claims.email.clone()
            && let Some(candidate) = directory.account_for_verified_email(&email)
        {
            if !email_match_confirmed {
                return Ok(LoginResolution::EmailMatchPending {
                    candidate_account_id: candidate,
                    email,
                });
            }
            let identity = make_identity(
                external_identity_id,
                candidate.clone(),
                provider_key,
                claims,
                now,
            );
            directory.link_external_identity(identity.clone())?;
            return Ok(LoginResolution::LinkedByEmailConfirmation {
                account_id: candidate,
                identity,
            });
        }

        // 5. New account creation.
        if directory.account(&new_account_id).is_some() {
            return Err(IamError::DuplicateAccount { id: new_account_id });
        }
        let account = Account {
            id: new_account_id.clone(),
            status: AccountStatus::Active,
            display_name: claims.display_name.clone(),
            created_at: now.clone(),
            updated_at: now.clone(),
        };
        directory.upsert_account(account);
        let identity = make_identity(
            external_identity_id,
            new_account_id.clone(),
            provider_key,
            claims,
            now,
        );
        directory.link_external_identity(identity.clone())?;
        Ok(LoginResolution::Created {
            account_id: new_account_id,
            identity,
        })
    }

    /// Unlink an external identity from an account under the safe-unlink rules.
    ///
    /// The identity must exist and belong to `account_id`, and it must not be the
    /// account's *last* external identity — unlinking the last sign-in method
    /// would orphan the account, so it fails closed with
    /// [`IamError::CannotUnlinkLastIdentity`]. Returns the detached link.
    pub fn unlink(
        &self,
        directory: &mut IdentityDirectory,
        account_id: &AccountId,
        provider_key: &IdentityProviderKey,
        subject: &ExternalSubject,
    ) -> Result<ExternalIdentity, IamError> {
        let owner = directory
            .external_identity(provider_key, subject)
            .map(|identity| identity.account_id.clone())
            .ok_or_else(|| IamError::ExternalIdentityNotFound {
                provider_key: provider_key.clone(),
                subject: subject.clone(),
            })?;
        if &owner != account_id {
            return Err(IamError::ExternalIdentityNotLinkedToAccount {
                provider_key: provider_key.clone(),
                subject: subject.clone(),
                account_id: account_id.clone(),
            });
        }
        if directory.identities_for_account(account_id).len() <= 1 {
            return Err(IamError::CannotUnlinkLastIdentity {
                account_id: account_id.clone(),
            });
        }
        directory.remove_external_identity(provider_key, subject)
    }
}

/// Build a freshly linked external identity stamped at `now`.
fn make_identity(
    id: ExternalIdentityId,
    account_id: AccountId,
    provider_key: IdentityProviderKey,
    claims: ExternalIdentityClaims,
    now: Timestamp,
) -> ExternalIdentity {
    ExternalIdentity {
        id,
        account_id,
        provider_key,
        claims,
        first_seen_at: now.clone(),
        last_seen_at: now,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn claims(
        subject: &str,
        email: Option<&str>,
        verified: Option<bool>,
    ) -> ExternalIdentityClaims {
        ExternalIdentityClaims {
            subject: ExternalSubject(subject.into()),
            email: email.map(str::to_owned),
            email_verified: verified,
            display_name: Some("Ada Lovelace".into()),
            username: Some("ada".into()),
            avatar_url: None,
            locale: None,
        }
    }

    fn request(claims: ExternalIdentityClaims) -> ResolveLogin {
        ResolveLogin {
            provider_key: IdentityProviderKey("google".into()),
            claims,
            now: Timestamp("2026-06-21T00:00:00Z".into()),
            current_account: None,
            email_match_confirmed: false,
            new_account_id: AccountId("acct_new".into()),
            external_identity_id: ExternalIdentityId("ext_new".into()),
        }
    }

    #[test]
    fn unknown_subject_creates_a_new_account_and_link() {
        let linker = AccountLinker;
        let mut directory = IdentityDirectory::new();

        let outcome = linker
            .resolve(
                &mut directory,
                request(claims("sub_1", Some("ada@example.com"), Some(true))),
            )
            .unwrap();

        let (account_id, identity) = match outcome {
            LoginResolution::Created {
                account_id,
                identity,
            } => (account_id, identity),
            other => panic!("expected Created, got {other:?}"),
        };
        assert_eq!(account_id, AccountId("acct_new".into()));
        assert_eq!(identity.id, ExternalIdentityId("ext_new".into()));
        // The account exists, is active, and inherits the display-name claim.
        let account = directory.account(&account_id).unwrap();
        assert_eq!(account.status, AccountStatus::Active);
        assert_eq!(account.display_name.as_deref(), Some("Ada Lovelace"));
        // The identity is resolvable by its provider+subject coordinate.
        assert_eq!(
            directory
                .external_identity(
                    &IdentityProviderKey("google".into()),
                    &ExternalSubject("sub_1".into())
                )
                .map(|id| id.account_id.clone()),
            Some(account_id)
        );
    }

    #[test]
    fn known_subject_selects_account_and_refreshes_claims_without_forking() {
        let linker = AccountLinker;
        let mut directory = IdentityDirectory::new();
        linker
            .resolve(
                &mut directory,
                request(claims("sub_1", Some("ada@example.com"), Some(true))),
            )
            .unwrap();

        // A later login with a *changed* email selects the same account and only
        // refreshes the mutable claim — email never forks a second account.
        let mut second = request(claims("sub_1", Some("ada@new.example.com"), Some(true)));
        second.now = Timestamp("2026-06-22T00:00:00Z".into());
        second.new_account_id = AccountId("acct_should_not_be_used".into());
        let outcome = linker.resolve(&mut directory, second).unwrap();

        let identity = match outcome {
            LoginResolution::Existing {
                account_id,
                identity,
            } => {
                assert_eq!(account_id, AccountId("acct_new".into()));
                identity
            }
            other => panic!("expected Existing, got {other:?}"),
        };
        assert_eq!(
            identity.claims.email.as_deref(),
            Some("ada@new.example.com")
        );
        assert_eq!(
            identity.last_seen_at,
            Timestamp("2026-06-22T00:00:00Z".into())
        );
        // No second account was created.
        assert!(
            directory
                .account(&AccountId("acct_should_not_be_used".into()))
                .is_none()
        );
    }

    #[test]
    fn current_session_links_unknown_subject_to_that_account() {
        let linker = AccountLinker;
        let mut directory = IdentityDirectory::new();
        directory.upsert_account(Account {
            id: AccountId("acct_live".into()),
            status: AccountStatus::Active,
            display_name: None,
            created_at: Timestamp("2026-06-01T00:00:00Z".into()),
            updated_at: Timestamp("2026-06-01T00:00:00Z".into()),
        });

        let mut req = request(claims("sub_gh", Some("ada@example.com"), Some(true)));
        req.provider_key = IdentityProviderKey("github".into());
        req.current_account = Some(AccountId("acct_live".into()));
        let outcome = linker.resolve(&mut directory, req).unwrap();

        match outcome {
            LoginResolution::LinkedToSession { account_id, .. } => {
                assert_eq!(account_id, AccountId("acct_live".into()));
            }
            other => panic!("expected LinkedToSession, got {other:?}"),
        }
        assert_eq!(
            directory
                .identities_for_account(&AccountId("acct_live".into()))
                .len(),
            1
        );
    }

    #[test]
    fn current_session_with_unknown_account_fails_closed() {
        let linker = AccountLinker;
        let mut directory = IdentityDirectory::new();
        let mut req = request(claims("sub_1", None, None));
        req.current_account = Some(AccountId("ghost".into()));
        let err = linker.resolve(&mut directory, req).unwrap_err();
        assert_eq!(err, IamError::MissingPrincipal);
    }

    #[test]
    fn duplicate_subject_cannot_be_relinked_to_a_different_account() {
        let linker = AccountLinker;
        let mut directory = IdentityDirectory::new();
        // Subject already owned by acct_new.
        linker
            .resolve(
                &mut directory,
                request(claims("sub_1", Some("ada@example.com"), Some(true))),
            )
            .unwrap();
        directory.upsert_account(Account {
            id: AccountId("acct_other".into()),
            status: AccountStatus::Active,
            display_name: None,
            created_at: Timestamp("2026-06-01T00:00:00Z".into()),
            updated_at: Timestamp("2026-06-01T00:00:00Z".into()),
        });

        let mut req = request(claims("sub_1", Some("ada@example.com"), Some(true)));
        req.current_account = Some(AccountId("acct_other".into()));
        let err = linker.resolve(&mut directory, req).unwrap_err();
        assert_eq!(
            err,
            IamError::DuplicateExternalIdentity {
                provider_key: IdentityProviderKey("google".into()),
                subject: ExternalSubject("sub_1".into()),
                existing_account_id: AccountId("acct_new".into()),
            }
        );
    }

    #[test]
    fn verified_email_match_is_pending_until_confirmed() {
        let linker = AccountLinker;
        let mut directory = IdentityDirectory::new();
        // Existing account reachable through a github identity with a verified email.
        let mut seed = request(claims("sub_gh", Some("ada@example.com"), Some(true)));
        seed.provider_key = IdentityProviderKey("github".into());
        seed.new_account_id = AccountId("acct_seed".into());
        seed.external_identity_id = ExternalIdentityId("ext_seed".into());
        linker.resolve(&mut directory, seed).unwrap();

        // A different provider/subject with the same verified email must not merge
        // silently.
        let pending = linker
            .resolve(
                &mut directory,
                request(claims("sub_g", Some("ADA@example.com"), Some(true))),
            )
            .unwrap();
        match pending {
            LoginResolution::EmailMatchPending {
                candidate_account_id,
                email,
            } => {
                assert_eq!(candidate_account_id, AccountId("acct_seed".into()));
                assert_eq!(email, "ADA@example.com");
            }
            other => panic!("expected EmailMatchPending, got {other:?}"),
        }
        // Nothing was linked or created.
        assert!(directory.account(&AccountId("acct_new".into())).is_none());

        // With explicit confirmation, the identity links to the matched account.
        let mut confirmed = request(claims("sub_g", Some("ADA@example.com"), Some(true)));
        confirmed.email_match_confirmed = true;
        let outcome = linker.resolve(&mut directory, confirmed).unwrap();
        match outcome {
            LoginResolution::LinkedByEmailConfirmation { account_id, .. } => {
                assert_eq!(account_id, AccountId("acct_seed".into()));
            }
            other => panic!("expected LinkedByEmailConfirmation, got {other:?}"),
        }
        assert_eq!(
            directory
                .identities_for_account(&AccountId("acct_seed".into()))
                .len(),
            2
        );
    }

    #[test]
    fn unverified_email_never_matches_an_existing_account() {
        let linker = AccountLinker;
        let mut directory = IdentityDirectory::new();
        let mut seed = request(claims("sub_gh", Some("ada@example.com"), Some(true)));
        seed.provider_key = IdentityProviderKey("github".into());
        seed.new_account_id = AccountId("acct_seed".into());
        seed.external_identity_id = ExternalIdentityId("ext_seed".into());
        linker.resolve(&mut directory, seed).unwrap();

        // Same email but unverified -> falls through to new-account creation.
        let outcome = linker
            .resolve(
                &mut directory,
                request(claims("sub_g", Some("ada@example.com"), Some(false))),
            )
            .unwrap();
        assert!(matches!(outcome, LoginResolution::Created { .. }));
    }

    #[test]
    fn unlink_refuses_to_orphan_the_last_identity() {
        let linker = AccountLinker;
        let mut directory = IdentityDirectory::new();
        linker
            .resolve(
                &mut directory,
                request(claims("sub_1", Some("ada@example.com"), Some(true))),
            )
            .unwrap();

        let err = linker
            .unlink(
                &mut directory,
                &AccountId("acct_new".into()),
                &IdentityProviderKey("google".into()),
                &ExternalSubject("sub_1".into()),
            )
            .unwrap_err();
        assert_eq!(
            err,
            IamError::CannotUnlinkLastIdentity {
                account_id: AccountId("acct_new".into()),
            }
        );
    }

    #[test]
    fn unlink_detaches_a_non_last_identity() {
        let linker = AccountLinker;
        let mut directory = IdentityDirectory::new();
        linker
            .resolve(
                &mut directory,
                request(claims("sub_1", Some("ada@example.com"), Some(true))),
            )
            .unwrap();
        // Link a second identity to the same account via the live session.
        let mut second = request(claims("sub_2", Some("ada@example.com"), Some(true)));
        second.provider_key = IdentityProviderKey("github".into());
        second.current_account = Some(AccountId("acct_new".into()));
        second.external_identity_id = ExternalIdentityId("ext_2".into());
        linker.resolve(&mut directory, second).unwrap();

        let detached = linker
            .unlink(
                &mut directory,
                &AccountId("acct_new".into()),
                &IdentityProviderKey("github".into()),
                &ExternalSubject("sub_2".into()),
            )
            .unwrap();
        assert_eq!(detached.id, ExternalIdentityId("ext_2".into()));
        assert_eq!(
            directory
                .identities_for_account(&AccountId("acct_new".into()))
                .len(),
            1
        );
    }

    #[test]
    fn unlink_rejects_identity_owned_by_another_account() {
        let linker = AccountLinker;
        let mut directory = IdentityDirectory::new();
        linker
            .resolve(
                &mut directory,
                request(claims("sub_1", Some("ada@example.com"), Some(true))),
            )
            .unwrap();

        let err = linker
            .unlink(
                &mut directory,
                &AccountId("acct_intruder".into()),
                &IdentityProviderKey("google".into()),
                &ExternalSubject("sub_1".into()),
            )
            .unwrap_err();
        assert_eq!(
            err,
            IamError::ExternalIdentityNotLinkedToAccount {
                provider_key: IdentityProviderKey("google".into()),
                subject: ExternalSubject("sub_1".into()),
                account_id: AccountId("acct_intruder".into()),
            }
        );
    }
}
