//! Store-backed policy `version` / token `epoch` fence (HA rule 3).
//!
//! Freshness rides one monotonic fence: the policy `version` carried by
//! snapshots and signer sets, and the token `epoch` that revocations advance
//! (see [high availability](../../../../docs/design/high-availability.md) rule 3
//! and [permission mechanisms](../../../../docs/design/permission-mechanisms.md)).
//! For a single process an in-memory counter is correct, but multiple nodes only
//! stay coherent if the fence lives in the **shared store**: a bump on one node
//! must be visible to every node on the next read. This module is that seam.
//!
//! The fence is advanced in the *same transaction* as the change it fences — a
//! grant edit bumps `version` with the write, a revoke bumps `epoch` with the
//! write — so no separate invalidation channel exists or is needed. The
//! in-memory adapter advances it under its lock; a database adapter advances it
//! with the write in one transaction. Reads fail closed: a node that cannot read
//! the fence cannot prove its caches are fresh, so the caller treats the store as
//! unreachable rather than serving a stale `Allow`.

use awaken_iam_core::RepositoryResult;

/// The monotonic counters that fence cache freshness across nodes.
///
/// `version` starts at 1 (matching the policy snapshot's initial version) and
/// `epoch` at 0 (matching [`LeaseEpoch::initial`](crate::LeaseEpoch::initial)),
/// so a freshly migrated store reports the same fence an in-memory node would.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Fence {
    /// Monotonic policy snapshot version; a grant/role/membership change bumps it.
    pub version: u64,
    /// Monotonic lease epoch; a session revoke or capability-lease change bumps it.
    pub epoch: u64,
}

impl Fence {
    /// The fence a fresh store starts at: version 1, epoch 0.
    pub const fn initial() -> Self {
        Self {
            version: 1,
            epoch: 0,
        }
    }
}

impl Default for Fence {
    fn default() -> Self {
        Self::initial()
    }
}

/// Server-owned port for the shared-store freshness fence.
///
/// HA's rule 3 requires the policy `version` and token `epoch` to be advanced
/// **in the shared store**, in the same transaction as the change they fence, so
/// a bump on one node is visible to every node on the next read. Keeping the port
/// at the server edge (not in `core`) preserves the storage-free domain: HA is
/// edge adapters over the existing repository contracts, not a change to `contract`, `core`, or
/// `client`.
///
/// All methods take `&self`: the adapter owns its own interior synchronisation
/// (a `Mutex` in memory, a transaction in a database) so the fence advances
/// atomically even under concurrent node requests.
pub trait FenceStore {
    /// Read the current fence. Fails closed: an unreadable fence means the node
    /// cannot prove freshness and must treat the store as unreachable.
    fn fence(&self) -> RepositoryResult<Fence>;

    /// Atomically advance the policy `version`, returning the new value.
    ///
    /// Called in the same transaction as the grant/role/membership write it
    /// fences, so the bump and the change land together or not at all.
    fn advance_version(&self) -> RepositoryResult<u64>;

    /// Atomically advance the token `epoch`, returning the new value.
    ///
    /// Called in the same transaction as the session-revoke or capability-lease
    /// change it fences, invalidating every token minted at the prior epoch.
    fn advance_epoch(&self) -> RepositoryResult<u64>;
}

impl<T: FenceStore + ?Sized> FenceStore for &T {
    fn fence(&self) -> RepositoryResult<Fence> {
        (**self).fence()
    }

    fn advance_version(&self) -> RepositoryResult<u64> {
        (**self).advance_version()
    }

    fn advance_epoch(&self) -> RepositoryResult<u64> {
        (**self).advance_epoch()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::InMemoryStore;

    #[test]
    fn fresh_store_starts_at_the_initial_fence() {
        let store = InMemoryStore::new();
        assert_eq!(store.fence().unwrap(), Fence::initial());
        assert_eq!(Fence::initial(), Fence::default());
        assert_eq!(Fence::initial().version, 1);
        assert_eq!(Fence::initial().epoch, 0);
    }

    #[test]
    fn version_and_epoch_advance_monotonically_and_independently() {
        let store = InMemoryStore::new();
        assert_eq!(store.advance_version().unwrap(), 2);
        assert_eq!(store.advance_version().unwrap(), 3);
        // Advancing the version never moves the epoch, and vice versa.
        assert_eq!(
            store.fence().unwrap(),
            Fence {
                version: 3,
                epoch: 0
            }
        );
        assert_eq!(store.advance_epoch().unwrap(), 1);
        assert_eq!(
            store.fence().unwrap(),
            Fence {
                version: 3,
                epoch: 1
            }
        );
    }

    #[test]
    fn two_nodes_sharing_one_store_observe_each_others_bumps() {
        // The whole point of a store-backed fence (HA rule 3): a bump on one node
        // is visible to every node on the next read. Model two nodes as two
        // handles to the same store via the `&T` forwarding impl.
        let store = InMemoryStore::new();
        let node_a: &dyn FenceStore = &store;
        let node_b: &dyn FenceStore = &store;

        let after_a = node_a.advance_version().unwrap();
        // Node B, which made no change itself, sees node A's bump on its read.
        assert_eq!(node_b.fence().unwrap().version, after_a);

        let after_b = node_b.advance_epoch().unwrap();
        assert_eq!(node_a.fence().unwrap().epoch, after_b);
    }
}
