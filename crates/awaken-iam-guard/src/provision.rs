//! Idempotent IAM provisioning: seed preset roles into an already-migrated store.
//!
//! [`provision`] is the embedded-deployment entry point. It seeds the Anthropic
//! platform role catalog ([`seed_named_roles`]) and the awaken-runtime preset
//! roles ([`seed_runtime_roles`]) into an already-migrated IAM store.
//!
//! Migration (schema creation) must be run before calling [`provision`]. The
//! typical sequence for an embedded deployment:
//!
//! ```rust,ignore
//! // 1. Create and migrate the store (schema).
//! let store = awaken_iam_server::sqlite_migrated_store(backend, "iam")?;
//! // 2. Seed preset roles (data).
//! awaken_iam_guard::provision(&store, &now)?;
//! ```
//!
//! Both steps are idempotent: migrations skip already-applied steps, and seeding
//! upserts each role in place. Safe to call on every process startup.
//!
//! A remote deployment never calls this — the IAM server provisions its own
//! store at startup. Only a product that embeds the IAM server in-process
//! (or runs a co-located store) needs this function.

use awaken_iam_contract::Timestamp;
use awaken_iam_core::{RepoError, RoleRepo, seed_named_roles, seed_runtime_roles};

/// Error returned by [`provision`].
#[derive(Debug, thiserror::Error)]
pub enum ProvisionError {
    /// Role seeding failed.
    #[error("IAM role seeding failed: {0}")]
    Seeding(String),
}

impl From<RepoError> for ProvisionError {
    fn from(err: RepoError) -> Self {
        ProvisionError::Seeding(err.to_string())
    }
}

/// Seed the preset IAM role catalog into an already-migrated store.
///
/// Seeds:
/// - Anthropic platform roles via [`seed_named_roles`] (`admin`, `developer`,
///   `billing`, …).
/// - awaken-runtime preset roles via [`seed_runtime_roles`] (`runtime_admin`,
///   `runtime_user`).
///
/// Both operations are idempotent (upsert semantics). Call this once per
/// process startup after schema migration.
///
/// # Parameters
///
/// - `store`: any [`RoleRepo`] implementation (e.g. `SqlStore<SqliteBackend>`,
///   `SqlStore<PostgresBackend>`, `InMemoryStore`).
/// - `now`: the timestamp stamped on newly seeded roles.
pub fn provision(store: &dyn RoleRepo, now: &Timestamp) -> Result<(), ProvisionError> {
    seed_named_roles(store, now)?;
    seed_runtime_roles(store, now)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use awaken_iam_contract::Timestamp;
    use awaken_iam_core::{RoleId, RoleRepo};
    use awaken_iam_server::sqlite_in_memory_store;

    fn now() -> Timestamp {
        Timestamp("2026-07-04T00:00:00Z".into())
    }

    #[test]
    fn provision_seeds_anthropic_named_roles() {
        let store = sqlite_in_memory_store("iam").expect("store");
        provision(&store, &now()).expect("provision");

        let admin = store
            .get(&RoleId("admin".into()))
            .expect("get")
            .expect("admin present");
        assert_eq!(admin.id, RoleId("admin".into()));

        let developer = store
            .get(&RoleId("developer".into()))
            .expect("get")
            .expect("developer present");
        assert_eq!(developer.id, RoleId("developer".into()));
    }

    #[test]
    fn provision_seeds_runtime_roles() {
        let store = sqlite_in_memory_store("iam").expect("store");
        provision(&store, &now()).expect("provision");

        let runtime_admin = store
            .get(&RoleId("runtime_admin".into()))
            .expect("get")
            .expect("runtime_admin present");
        assert_eq!(runtime_admin.id, RoleId("runtime_admin".into()));

        let runtime_user = store
            .get(&RoleId("runtime_user".into()))
            .expect("get")
            .expect("runtime_user present");
        assert_eq!(runtime_user.id, RoleId("runtime_user".into()));
    }

    #[test]
    fn provision_is_idempotent() {
        let store = sqlite_in_memory_store("iam").expect("store");
        provision(&store, &now()).expect("first provision");
        provision(&store, &now()).expect("second provision — must not fail");

        // Role count must not double on re-provision.
        let roles = store.list().expect("list roles");
        let admin_count = roles
            .iter()
            .filter(|r| r.id == RoleId("admin".into()))
            .count();
        assert_eq!(admin_count, 1, "admin role must appear exactly once");
    }

    #[test]
    fn provision_works_with_in_memory_store() {
        use awaken_iam_server::InMemoryStore;
        let store = InMemoryStore::new();
        provision(&store, &now()).expect("provision with in-memory store");

        let roles = store.list().expect("list");
        let ids: Vec<_> = roles.iter().map(|r| r.id.0.as_str()).collect();
        assert!(ids.contains(&"admin"), "admin role seeded");
        assert!(ids.contains(&"runtime_admin"), "runtime_admin role seeded");
    }
}
