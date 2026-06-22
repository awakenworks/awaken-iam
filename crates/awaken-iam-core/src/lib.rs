//! Core IAM evaluation primitives.

use std::collections::HashMap;
use std::collections::hash_map::Entry;

use awaken_iam_contract::{
    Account, AccountId, AuthorizationDecision, AuthorizationRequest, EntitlementDecision,
    ExternalIdentity, ExternalIdentityClaims, ExternalIdentityKey, ExternalSubject,
    IdentityProviderKey, Timestamp,
};

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
