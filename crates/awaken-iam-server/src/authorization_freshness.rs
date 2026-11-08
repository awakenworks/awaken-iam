//! An observation of the existing native shared-store fence, never authority.
use crate::Fence;
use sha2::{Digest, Sha256};

/// Opaque stable observation. Both native fence components are mandatory.
#[must_use]
pub fn authorization_freshness(fence: Fence) -> String {
    let mut digest = Sha256::new();
    digest.update(b"iam-authorization-freshness-v1\0");
    digest.update(fence.version.to_be_bytes());
    digest.update(fence.epoch.to_be_bytes());
    format!("iam-fence-v1:{:x}", digest.finalize())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn neither_shared_policy_version_nor_revocation_epoch_can_be_omitted() {
        let original = authorization_freshness(Fence {
            version: 1,
            epoch: 0,
        });
        assert_eq!(
            original,
            authorization_freshness(Fence {
                version: 1,
                epoch: 0
            })
        );
        assert_ne!(
            original,
            authorization_freshness(Fence {
                version: 2,
                epoch: 0
            })
        );
        assert_ne!(
            original,
            authorization_freshness(Fence {
                version: 1,
                epoch: 1
            })
        );
    }
}
