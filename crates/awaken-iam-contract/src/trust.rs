use serde::{Deserialize, Serialize};

use crate::{NamespaceId, OrgId, Timestamp};

/// Signer-key row identifier, unique within a namespace.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct SignerKeyId(pub String);

/// Stable content address of a public signing key.
///
/// This is the value Pack Hub observes on a signature and uses for
/// verification-time lookup, so it is unique within a namespace.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct SignerKeyFingerprint(pub String);

/// Signing algorithm a key is bound to.
///
/// Kept extensible so Pack Hub's signature & trust model can add algorithms
/// without an IAM schema break.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SignerKeyAlgorithm {
    /// Ed25519 public-key signatures.
    Ed25519,
}

/// Lifecycle state of a registered signer key.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SignerKeyStatus {
    /// Key may sign and is honored at verification time.
    Active,
    /// Key has been revoked and is never honored at verification time.
    Revoked,
}

/// Ownership record binding a package namespace to its organization owner.
///
/// Ownership is the precondition for granting namespace actions and registering
/// signer keys.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct NamespaceOwner {
    /// Owned namespace.
    pub namespace_id: NamespaceId,
    /// Organization that owns the namespace.
    pub owner_org_id: OrgId,
    /// When ownership was established.
    pub created_at: Timestamp,
}

/// A public signing key authorized to sign on a namespace's behalf.
///
/// Only the public half of the key is stored; private key material is never
/// held by IAM.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SignerKey {
    /// Row identifier, unique within the namespace.
    pub id: SignerKeyId,
    /// Namespace this key signs for.
    pub namespace_id: NamespaceId,
    /// Stable fingerprint used at verification time.
    pub fingerprint: SignerKeyFingerprint,
    /// Signing algorithm.
    pub algorithm: SignerKeyAlgorithm,
    /// Encoded public key material. Never a secret.
    pub public_key: String,
    /// Lifecycle status.
    pub status: SignerKeyStatus,
    /// Optional operator-facing label.
    pub label: Option<String>,
    /// When the key was registered.
    pub registered_at: Timestamp,
    /// When the key was revoked, if it has been.
    pub revoked_at: Option<Timestamp>,
}

impl SignerKey {
    /// Whether the key is currently active and may be honored at verification.
    pub fn is_active(&self) -> bool {
        matches!(self.status, SignerKeyStatus::Active)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn signer_key_serializes_status_and_algorithm_as_snake_case() {
        let key = SignerKey {
            id: SignerKeyId("key_1".into()),
            namespace_id: NamespaceId("acme".into()),
            fingerprint: SignerKeyFingerprint("fp_abc".into()),
            algorithm: SignerKeyAlgorithm::Ed25519,
            public_key: "base64".into(),
            status: SignerKeyStatus::Active,
            label: None,
            registered_at: Timestamp("2026-06-20T00:00:00Z".into()),
            revoked_at: None,
        };
        let json = serde_json::to_value(&key).unwrap();
        assert_eq!(json.get("algorithm").unwrap(), "ed25519");
        assert_eq!(json.get("status").unwrap(), "active");
        assert!(key.is_active());
    }

    #[test]
    fn namespace_owner_round_trips() {
        let owner = NamespaceOwner {
            namespace_id: NamespaceId("acme".into()),
            owner_org_id: OrgId("org_acme".into()),
            created_at: Timestamp("2026-06-20T00:00:00Z".into()),
        };
        let json = serde_json::to_string(&owner).unwrap();
        let restored: NamespaceOwner = serde_json::from_str(&json).unwrap();
        assert_eq!(owner, restored);
    }
}
