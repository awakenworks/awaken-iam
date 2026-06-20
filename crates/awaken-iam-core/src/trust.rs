//! Namespace ownership, signer-key binding, and namespace-scope authorization.
//!
//! This is the IAM side of Pack Hub's trust model. [`NamespaceTrustDirectory`]
//! records who owns a namespace, which principals may act on it, and which
//! public signing keys are bound to it, then answers authorization at
//! [`ScopeRef::Namespace`] and the verification-time signer lookup.
//!
//! See [the namespace trust model](../../../docs/design/namespace-trust-model.md).

use std::collections::HashMap;

use awaken_iam_contract::{
    ActionKey, AuthorizationDecision, AuthorizationRequest, NamespaceId, NamespaceOwner,
    PrincipalRef, ScopeRef, SignerKey, SignerKeyFingerprint, SignerKeyId, SignerKeyStatus,
    Timestamp,
};

/// Errors raised while mutating namespace trust state.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum TrustError {
    /// The namespace has no ownership record, so the operation fails closed.
    #[error("namespace is not owned")]
    UnknownNamespace {
        /// Namespace that was referenced without an owner.
        namespace_id: NamespaceId,
    },
    /// Another active key in the namespace already uses this fingerprint.
    #[error("signer key fingerprint is already registered")]
    DuplicateFingerprint {
        /// Conflicting fingerprint.
        fingerprint: SignerKeyFingerprint,
    },
    /// A signer key with this id already exists in the namespace.
    #[error("signer key id is already registered")]
    DuplicateSignerKeyId {
        /// Conflicting key id.
        id: SignerKeyId,
    },
    /// The referenced signer key does not exist in the namespace.
    #[error("signer key was not found")]
    SignerKeyNotFound {
        /// Missing key id.
        id: SignerKeyId,
    },
}

/// A grant authorizing a principal to perform an action pattern at a namespace.
///
/// Patterns match exactly, by a `segment.*` prefix, or by the full `*` wildcard.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NamespaceGrant {
    /// Principal the grant applies to.
    pub principal: PrincipalRef,
    /// Action pattern the principal may perform.
    pub action_pattern: ActionKey,
}

impl NamespaceGrant {
    fn matches(&self, principal: &PrincipalRef, action: &ActionKey) -> bool {
        &self.principal == principal && pattern_matches(&self.action_pattern.0, &action.0)
    }
}

/// Whether `action` is covered by `pattern`.
fn pattern_matches(pattern: &str, action: &str) -> bool {
    if pattern == "*" {
        return true;
    }
    if let Some(prefix) = pattern.strip_suffix('*') {
        // `seg.*` matches any action under the `seg.` prefix.
        if let Some(segment) = prefix.strip_suffix('.') {
            return action == segment || action.starts_with(prefix);
        }
        return action.starts_with(prefix);
    }
    pattern == action
}

/// Per-namespace trust state.
#[derive(Debug)]
struct NamespaceEntry {
    owner: NamespaceOwner,
    grants: Vec<NamespaceGrant>,
    signers: Vec<SignerKey>,
}

impl NamespaceEntry {
    fn new(owner: NamespaceOwner) -> Self {
        Self {
            owner,
            grants: Vec::new(),
            signers: Vec::new(),
        }
    }
}

/// Records namespace ownership, grants, and signer-key bindings, and evaluates
/// namespace-scope authorization plus verification-time signer lookup.
#[derive(Debug, Default)]
pub struct NamespaceTrustDirectory {
    namespaces: HashMap<NamespaceId, NamespaceEntry>,
}

impl NamespaceTrustDirectory {
    /// Create an empty trust directory.
    pub fn new() -> Self {
        Self::default()
    }

    /// Establish or replace namespace ownership.
    ///
    /// Existing grants and signer keys for the namespace are preserved; only the
    /// ownership record is updated.
    pub fn set_namespace_owner(&mut self, owner: NamespaceOwner) {
        let namespace_id = owner.namespace_id.clone();
        match self.namespaces.get_mut(&namespace_id) {
            Some(entry) => entry.owner = owner,
            None => {
                self.namespaces
                    .insert(namespace_id, NamespaceEntry::new(owner));
            }
        }
    }

    /// Look up the owner of a namespace, if one is recorded.
    pub fn namespace_owner(&self, namespace_id: &NamespaceId) -> Option<&NamespaceOwner> {
        self.entry(namespace_id).map(|entry| &entry.owner)
    }

    /// Grant a principal an action pattern at a namespace.
    ///
    /// The namespace must already be owned. Re-granting the same principal and
    /// pattern is idempotent.
    pub fn grant(
        &mut self,
        namespace_id: &NamespaceId,
        principal: PrincipalRef,
        action_pattern: ActionKey,
    ) -> Result<(), TrustError> {
        let entry = self.entry_mut(namespace_id)?;
        let grant = NamespaceGrant {
            principal,
            action_pattern,
        };
        if !entry.grants.contains(&grant) {
            entry.grants.push(grant);
        }
        Ok(())
    }

    /// Remove a previously recorded grant. Removing an absent grant is a no-op
    /// and reports `false`.
    pub fn revoke_grant(
        &mut self,
        namespace_id: &NamespaceId,
        principal: &PrincipalRef,
        action_pattern: &ActionKey,
    ) -> Result<bool, TrustError> {
        let entry = self.entry_mut(namespace_id)?;
        let before = entry.grants.len();
        entry.grants.retain(|grant| {
            !(&grant.principal == principal && &grant.action_pattern == action_pattern)
        });
        Ok(entry.grants.len() != before)
    }

    /// Evaluate an authorization request.
    ///
    /// Only `ScopeRef::Namespace` requests are answered here; every other scope
    /// is denied so it can be resolved by its own scope authority. A namespace
    /// request is allowed only when a recorded grant matches the principal and
    /// action.
    pub fn authorize(&self, request: &AuthorizationRequest) -> AuthorizationDecision {
        let ScopeRef::Namespace { namespace_id } = &request.scope else {
            return AuthorizationDecision::Deny;
        };
        let allowed = self.entry(namespace_id).is_some_and(|entry| {
            entry
                .grants
                .iter()
                .any(|grant| grant.matches(&request.principal, &request.action))
        });
        if allowed {
            AuthorizationDecision::Allow
        } else {
            AuthorizationDecision::Deny
        }
    }

    /// Bind a public signing key to its namespace.
    ///
    /// The namespace must be owned, the key's `namespace_id` must match, and both
    /// the fingerprint and id must be free of an existing active conflict.
    pub fn register_signer_key(&mut self, key: SignerKey) -> Result<(), TrustError> {
        let namespace_id = key.namespace_id.clone();
        let entry = self.entry_mut(&namespace_id)?;
        if entry.signers.iter().any(|existing| existing.id == key.id) {
            return Err(TrustError::DuplicateSignerKeyId { id: key.id });
        }
        if entry
            .signers
            .iter()
            .any(|existing| existing.is_active() && existing.fingerprint == key.fingerprint)
        {
            return Err(TrustError::DuplicateFingerprint {
                fingerprint: key.fingerprint,
            });
        }
        entry.signers.push(key);
        Ok(())
    }

    /// Revoke a signer key. Revocation is idempotent: revoking an already-revoked
    /// key succeeds without changing its recorded `revoked_at`.
    pub fn revoke_signer_key(
        &mut self,
        namespace_id: &NamespaceId,
        id: &SignerKeyId,
        revoked_at: Timestamp,
    ) -> Result<&SignerKey, TrustError> {
        let entry = self.entry_mut(namespace_id)?;
        let key = entry
            .signers
            .iter_mut()
            .find(|key| &key.id == id)
            .ok_or_else(|| TrustError::SignerKeyNotFound { id: id.clone() })?;
        if key.is_active() {
            key.status = SignerKeyStatus::Revoked;
            key.revoked_at = Some(revoked_at);
        }
        Ok(key)
    }

    /// Fetch a signer key by id regardless of status.
    pub fn signer_key(&self, namespace_id: &NamespaceId, id: &SignerKeyId) -> Option<&SignerKey> {
        self.entry(namespace_id)?
            .signers
            .iter()
            .find(|key| &key.id == id)
    }

    /// Verification-time lookup: resolve a fingerprint to its bound key only when
    /// that key is active. A revoked or unknown fingerprint yields `None`.
    pub fn lookup_signer(
        &self,
        namespace_id: &NamespaceId,
        fingerprint: &SignerKeyFingerprint,
    ) -> Option<&SignerKey> {
        self.entry(namespace_id)?
            .signers
            .iter()
            .find(|key| key.is_active() && &key.fingerprint == fingerprint)
    }

    /// Whether the fingerprint is a currently-authorized signer for the namespace.
    pub fn is_authorized_signer(
        &self,
        namespace_id: &NamespaceId,
        fingerprint: &SignerKeyFingerprint,
    ) -> bool {
        self.lookup_signer(namespace_id, fingerprint).is_some()
    }

    /// List the active signer keys for a namespace, ordered by key id for a
    /// stable, deterministic sequence.
    pub fn active_signers(&self, namespace_id: &NamespaceId) -> Vec<&SignerKey> {
        let mut signers: Vec<&SignerKey> = match self.entry(namespace_id) {
            Some(entry) => entry.signers.iter().filter(|key| key.is_active()).collect(),
            None => Vec::new(),
        };
        signers.sort_by(|left, right| left.id.0.cmp(&right.id.0));
        signers
    }

    fn entry(&self, namespace_id: &NamespaceId) -> Option<&NamespaceEntry> {
        self.namespaces.get(namespace_id)
    }

    fn entry_mut(&mut self, namespace_id: &NamespaceId) -> Result<&mut NamespaceEntry, TrustError> {
        self.namespaces
            .get_mut(namespace_id)
            .ok_or_else(|| TrustError::UnknownNamespace {
                namespace_id: namespace_id.clone(),
            })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use awaken_iam_contract::{
        OrgId, SignerKeyAlgorithm, SignerKeyFingerprint, SignerKeyId, SignerKeyStatus,
    };

    fn ts(value: &str) -> Timestamp {
        Timestamp(value.into())
    }

    fn namespace() -> NamespaceId {
        NamespaceId("acme".into())
    }

    fn account(id: &str) -> PrincipalRef {
        PrincipalRef::Account {
            account_id: awaken_iam_contract::AccountId(id.into()),
        }
    }

    fn owned_directory() -> NamespaceTrustDirectory {
        let mut directory = NamespaceTrustDirectory::new();
        directory.set_namespace_owner(NamespaceOwner {
            namespace_id: namespace(),
            owner_org_id: OrgId("org_acme".into()),
            created_at: ts("2026-06-20T00:00:00Z"),
        });
        directory
    }

    fn signer_key(id: &str, fingerprint: &str) -> SignerKey {
        SignerKey {
            id: SignerKeyId(id.into()),
            namespace_id: namespace(),
            fingerprint: SignerKeyFingerprint(fingerprint.into()),
            algorithm: SignerKeyAlgorithm::Ed25519,
            public_key: "base64-public-key".into(),
            status: SignerKeyStatus::Active,
            label: Some("release signer".into()),
            registered_at: ts("2026-06-20T00:00:00Z"),
            revoked_at: None,
        }
    }

    fn request(principal: PrincipalRef, action: &str) -> AuthorizationRequest {
        AuthorizationRequest {
            principal,
            on_behalf_of: Vec::new(),
            action: ActionKey(action.into()),
            scope: ScopeRef::Namespace {
                namespace_id: namespace(),
            },
        }
    }

    #[test]
    fn ownership_round_trips() {
        let directory = owned_directory();
        let owner = directory.namespace_owner(&namespace()).unwrap();
        assert_eq!(owner.owner_org_id, OrgId("org_acme".into()));
        assert!(
            directory
                .namespace_owner(&NamespaceId("other".into()))
                .is_none()
        );
    }

    #[test]
    fn grant_enables_publish_authorization_at_namespace_scope() {
        let mut directory = owned_directory();
        let principal = account("acct_publisher");
        directory
            .grant(
                &namespace(),
                principal.clone(),
                ActionKey("pack.publish".into()),
            )
            .unwrap();

        assert_eq!(
            directory.authorize(&request(principal.clone(), "pack.publish")),
            AuthorizationDecision::Allow
        );
        // An action the principal was not granted is denied.
        assert_eq!(
            directory.authorize(&request(principal, "namespace.signer.use")),
            AuthorizationDecision::Deny
        );
    }

    #[test]
    fn signer_use_authorization_is_principal_scoped() {
        let mut directory = owned_directory();
        let signer = account("acct_signer");
        directory
            .grant(
                &namespace(),
                signer.clone(),
                ActionKey("namespace.signer.use".into()),
            )
            .unwrap();

        assert_eq!(
            directory.authorize(&request(signer, "namespace.signer.use")),
            AuthorizationDecision::Allow
        );
        // A different principal with no grant is denied.
        assert_eq!(
            directory.authorize(&request(account("acct_other"), "namespace.signer.use")),
            AuthorizationDecision::Deny
        );
    }

    #[test]
    fn wildcard_pattern_covers_namespace_admin_actions() {
        let mut directory = owned_directory();
        let admin = account("acct_admin");
        directory
            .grant(&namespace(), admin.clone(), ActionKey("namespace.*".into()))
            .unwrap();

        assert_eq!(
            directory.authorize(&request(admin.clone(), "namespace.signer.manage")),
            AuthorizationDecision::Allow
        );
        // The prefix grant does not leak into unrelated action families.
        assert_eq!(
            directory.authorize(&request(admin, "pack.publish")),
            AuthorizationDecision::Deny
        );
    }

    #[test]
    fn authorization_denies_non_namespace_scope() {
        let mut directory = owned_directory();
        let principal = account("acct_publisher");
        directory
            .grant(&namespace(), principal.clone(), ActionKey("*".into()))
            .unwrap();

        let global = AuthorizationRequest {
            principal,
            on_behalf_of: Vec::new(),
            action: ActionKey("pack.publish".into()),
            scope: ScopeRef::Global,
        };
        assert_eq!(directory.authorize(&global), AuthorizationDecision::Deny);
    }

    #[test]
    fn authorization_denies_unowned_namespace() {
        let directory = NamespaceTrustDirectory::new();
        assert_eq!(
            directory.authorize(&request(account("acct"), "pack.publish")),
            AuthorizationDecision::Deny
        );
    }

    #[test]
    fn grant_requires_owned_namespace() {
        let mut directory = NamespaceTrustDirectory::new();
        let err = directory
            .grant(
                &namespace(),
                account("acct"),
                ActionKey("pack.publish".into()),
            )
            .unwrap_err();
        assert_eq!(
            err,
            TrustError::UnknownNamespace {
                namespace_id: namespace()
            }
        );
    }

    #[test]
    fn grant_is_idempotent_and_revocable() {
        let mut directory = owned_directory();
        let principal = account("acct");
        let action = ActionKey("pack.publish".into());
        directory
            .grant(&namespace(), principal.clone(), action.clone())
            .unwrap();
        directory
            .grant(&namespace(), principal.clone(), action.clone())
            .unwrap();

        assert!(
            directory
                .revoke_grant(&namespace(), &principal, &action)
                .unwrap()
        );
        // Second revoke is a no-op.
        assert!(
            !directory
                .revoke_grant(&namespace(), &principal, &action)
                .unwrap()
        );
        assert_eq!(
            directory.authorize(&request(principal, "pack.publish")),
            AuthorizationDecision::Deny
        );
    }

    #[test]
    fn register_and_lookup_signer_key() {
        let mut directory = owned_directory();
        directory
            .register_signer_key(signer_key("key_1", "fp_abc"))
            .unwrap();

        let looked_up = directory
            .lookup_signer(&namespace(), &SignerKeyFingerprint("fp_abc".into()))
            .unwrap();
        assert_eq!(looked_up.id, SignerKeyId("key_1".into()));
        assert!(
            directory.is_authorized_signer(&namespace(), &SignerKeyFingerprint("fp_abc".into()))
        );
        // Unknown fingerprint is not trusted.
        assert!(
            directory
                .lookup_signer(&namespace(), &SignerKeyFingerprint("fp_missing".into()))
                .is_none()
        );
    }

    #[test]
    fn register_requires_owned_namespace() {
        let mut directory = NamespaceTrustDirectory::new();
        let err = directory
            .register_signer_key(signer_key("key_1", "fp_abc"))
            .unwrap_err();
        assert_eq!(
            err,
            TrustError::UnknownNamespace {
                namespace_id: namespace()
            }
        );
    }

    #[test]
    fn duplicate_signer_key_id_is_rejected() {
        let mut directory = owned_directory();
        directory
            .register_signer_key(signer_key("key_1", "fp_abc"))
            .unwrap();
        let err = directory
            .register_signer_key(signer_key("key_1", "fp_other"))
            .unwrap_err();
        assert_eq!(
            err,
            TrustError::DuplicateSignerKeyId {
                id: SignerKeyId("key_1".into())
            }
        );
    }

    #[test]
    fn duplicate_active_fingerprint_is_rejected() {
        let mut directory = owned_directory();
        directory
            .register_signer_key(signer_key("key_1", "fp_abc"))
            .unwrap();
        let err = directory
            .register_signer_key(signer_key("key_2", "fp_abc"))
            .unwrap_err();
        assert_eq!(
            err,
            TrustError::DuplicateFingerprint {
                fingerprint: SignerKeyFingerprint("fp_abc".into())
            }
        );
    }

    #[test]
    fn revoked_key_drops_out_of_verification_and_frees_fingerprint() {
        let mut directory = owned_directory();
        directory
            .register_signer_key(signer_key("key_1", "fp_abc"))
            .unwrap();

        let revoked = directory
            .revoke_signer_key(
                &namespace(),
                &SignerKeyId("key_1".into()),
                ts("2026-06-21T00:00:00Z"),
            )
            .unwrap();
        assert_eq!(revoked.status, SignerKeyStatus::Revoked);
        assert_eq!(revoked.revoked_at, Some(ts("2026-06-21T00:00:00Z")));

        // No longer honored at verification time.
        assert!(
            directory
                .lookup_signer(&namespace(), &SignerKeyFingerprint("fp_abc".into()))
                .is_none()
        );
        assert!(directory.active_signers(&namespace()).is_empty());
        // A fresh active key may reuse the freed fingerprint.
        directory
            .register_signer_key(signer_key("key_2", "fp_abc"))
            .unwrap();
        assert!(
            directory.is_authorized_signer(&namespace(), &SignerKeyFingerprint("fp_abc".into()))
        );
    }

    #[test]
    fn revoke_is_idempotent() {
        let mut directory = owned_directory();
        directory
            .register_signer_key(signer_key("key_1", "fp_abc"))
            .unwrap();
        let first = directory
            .revoke_signer_key(
                &namespace(),
                &SignerKeyId("key_1".into()),
                ts("2026-06-21T00:00:00Z"),
            )
            .unwrap()
            .revoked_at
            .clone();
        let second = directory
            .revoke_signer_key(
                &namespace(),
                &SignerKeyId("key_1".into()),
                ts("2026-06-22T00:00:00Z"),
            )
            .unwrap()
            .revoked_at
            .clone();
        // The later revoke does not overwrite the original revocation time.
        assert_eq!(first, second);
    }

    #[test]
    fn revoke_unknown_key_fails() {
        let mut directory = owned_directory();
        let err = directory
            .revoke_signer_key(
                &namespace(),
                &SignerKeyId("missing".into()),
                ts("2026-06-21T00:00:00Z"),
            )
            .unwrap_err();
        assert_eq!(
            err,
            TrustError::SignerKeyNotFound {
                id: SignerKeyId("missing".into())
            }
        );
    }

    #[test]
    fn active_signers_are_ordered_by_id() {
        let mut directory = owned_directory();
        directory
            .register_signer_key(signer_key("key_b", "fp_b"))
            .unwrap();
        directory
            .register_signer_key(signer_key("key_a", "fp_a"))
            .unwrap();
        let ids: Vec<&str> = directory
            .active_signers(&namespace())
            .iter()
            .map(|key| key.id.0.as_str())
            .collect();
        assert_eq!(ids, vec!["key_a", "key_b"]);
    }

    #[test]
    fn setting_owner_preserves_grants_and_signers() {
        let mut directory = owned_directory();
        let principal = account("acct");
        directory
            .grant(
                &namespace(),
                principal.clone(),
                ActionKey("pack.publish".into()),
            )
            .unwrap();
        directory
            .register_signer_key(signer_key("key_1", "fp_abc"))
            .unwrap();

        // Re-recording ownership (e.g. org transfer metadata refresh) keeps state.
        directory.set_namespace_owner(NamespaceOwner {
            namespace_id: namespace(),
            owner_org_id: OrgId("org_new".into()),
            created_at: ts("2026-06-25T00:00:00Z"),
        });
        assert_eq!(
            directory
                .namespace_owner(&namespace())
                .unwrap()
                .owner_org_id,
            OrgId("org_new".into())
        );
        assert_eq!(
            directory.authorize(&request(principal, "pack.publish")),
            AuthorizationDecision::Allow
        );
        assert!(
            directory.is_authorized_signer(&namespace(), &SignerKeyFingerprint("fp_abc".into()))
        );
    }
}
