//! Storage edge for IAM: selected test repositories and the scope-partitioned
//! migration bundles used by the production database adapters.
//!
//! The core declares the [repository contracts](awaken_iam_core); this module is
//! the server-owned edge that provides adapters for them, keeping `contract`,
//! `core`, and `client` storage-free. The SQLite executor is the first concrete
//! database edge over the migration plan. See
//! [deployment](../../../../docs/design/deployment.md).

mod bundles;
mod fence;
mod health;
mod memory;
mod migration;
mod postgres;
mod sql;
mod sqlite;

pub use bundles::{BundleScope, bundles};
pub use fence::{Fence, FenceStore};
pub use health::{Liveness, Readiness};
pub use memory::InMemoryStore;
pub use migration::{
    Dialect, IamStore, MigrateReport, Migration, MigrationBundle, MigrationExecutor,
    PlannedMigration, RecordingExecutor,
};
pub use postgres::{PostgresBackend, migrated_store as postgres_migrated_store};
pub use sql::{SqlConn, SqlParam, SqlRow, SqlStore};
pub use sqlite::{
    SqliteBackend, in_memory_store as sqlite_in_memory_store,
    migrated_store as sqlite_migrated_store,
};

/// Atomic product projection and vocabulary persistence used by the guarded
/// standalone-daemon routes. The SQL adapters implement the same contract.
pub trait ResourceProjectionStore: Send + Sync {
    fn apply_projection(
        &self,
        batch: &awaken_iam_contract::ResourceProjectionBatch,
    ) -> awaken_iam_core::RepositoryResult<awaken_iam_contract::ResourceProjectionReceipt>;

    fn register_product_model(
        &self,
        request: &awaken_iam_contract::ProductResourceModelRequest,
    ) -> awaken_iam_core::RepositoryResult<awaken_iam_contract::ResourceModelRegistered>;
}
