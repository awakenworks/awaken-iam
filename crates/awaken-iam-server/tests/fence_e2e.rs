//! End-to-end coverage of the shared-store freshness fence (HA rule 3).
//!
//! The fence is the cross-node monotonic counter a grant edit / revoke bumps
//! in the shared store. Two nodes holding handles to the same store via the
//! `&T` forwarding impl must observe each other's bumps on the next read,
//! proving the HA rule the design promises. Round-tripping every `Fence` and
//! `PolicyAdminApi::version` interaction through real backends (in-memory and
//! SQLite) keeps the fence contract honest.

use awaken_iam_server::FenceStore;
use awaken_iam_server::InMemoryStore;

#[test]
fn fence_initial_is_version_one_epoch_zero_and_eq_to_default() {
    use awaken_iam_server::Fence;
    let fence = Fence::initial();
    assert_eq!(fence.version, 1);
    assert_eq!(fence.epoch, 0);
    assert_eq!(fence, Fence::default());
}

#[test]
fn fence_advances_via_shared_reference_for_two_clients() {
    // Two simulated nodes hold `&dyn FenceStore` handles to the same
    // store (via the `&T` forwarding impl). One advances; the other reads.
    // The fence is shared state, not per-handle memory.
    let store = InMemoryStore::new();
    let node_a: &dyn FenceStore = &store;
    let node_b: &dyn FenceStore = &store;

    let bumped = node_a.advance_version().expect("bump version");
    assert_eq!(bumped, 2);
    // Node B observes node A's bump on its next read.
    assert_eq!(node_b.fence().expect("read fence").version, bumped);

    // Advancing the epoch on B is visible to A.
    let epoch = node_b.advance_epoch().expect("bump epoch");
    assert_eq!(epoch, 1);
    assert_eq!(node_a.fence().expect("read fence").epoch, 1);
    // And vice versa for an independent version bump.
    let bumped = node_a.advance_version().expect("bump version");
    assert_eq!(bumped, 3);
    assert_eq!(node_b.fence().expect("read fence").version, 3);
}

#[test]
fn fence_round_trips_through_the_in_memory_store_with_real_bumps() {
    // The InMemoryStore is the deployment-default single-process backend;
    // the fence contract is the one every adapter must satisfy.
    let store = InMemoryStore::new();
    let initial = store.fence().expect("read fence");
    assert_eq!(initial.version, 1);
    assert_eq!(initial.epoch, 0);

    let bumped = store.advance_version().expect("bump");
    assert_eq!(bumped, 2);
    let read_back = store.fence().expect("read fence");
    assert_eq!(read_back.version, 2);
    assert_eq!(read_back.epoch, 0);

    // Bumping epoch on the same store is independent of the version counter.
    let epoch = store.advance_epoch().expect("bump");
    assert_eq!(epoch, 1);
    let both = store.fence().expect("read fence");
    assert_eq!(both.version, 2);
    assert_eq!(both.epoch, 1);
}

#[test]
fn fence_round_trips_through_the_migrated_sqlite_store() {
    let store = awaken_iam_server::sqlite_in_memory_store("iam").expect("migrate sqlite");
    assert_eq!(store.fence().expect("initial fence").version, 1);
    assert_eq!(store.advance_version().expect("bump version"), 2);
    assert_eq!(store.advance_epoch().expect("bump epoch"), 1);
    let persisted = store.fence().expect("read persisted fence");
    assert_eq!(persisted.version, 2);
    assert_eq!(persisted.epoch, 1);
}

#[test]
fn policy_admin_api_seed_fence_advances_with_a_real_mutation() {
    // The admin API reads the seed fence from the store; a successful
    // mutation bumps it and a follow-up read sees the new fence.
    use awaken_iam_server::PolicyAdminApi;
    let mut pap = PolicyAdminApi::new(InMemoryStore::new());
    assert_eq!(pap.version(), 1);
    // The store_version reader reports the same value the cached version
    // started at.
    assert_eq!(pap.store_version().expect("read"), 1);

    pap.create_org(
        awaken_iam_core::Organization {
            id: awaken_iam_contract::OrgId("acme".into()),
            display_name: None,
            owner: awaken_iam_contract::PrincipalRef::Account {
                account_id: awaken_iam_contract::AccountId("ada".into()),
            },
            created_at: awaken_iam_contract::Timestamp("2026-06-21T00:00:00Z".into()),
            updated_at: awaken_iam_contract::Timestamp("2026-06-21T00:00:00Z".into()),
        },
        awaken_iam_contract::Timestamp("2026-06-21T00:00:00Z".into()),
    )
    .expect("create org");

    let after = pap.version();
    assert_eq!(after, 2, "the org create must advance the cached version");
    assert_eq!(pap.store_version().expect("read"), after);
}
