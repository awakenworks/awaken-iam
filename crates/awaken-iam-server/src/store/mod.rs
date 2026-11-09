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
mod migration_compatibility;
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
pub use sql::{SqlConn, SqlParam, SqlRow, SqlStore, SqlTransaction};
pub use sqlite::{
    SqliteBackend, in_memory_store as sqlite_in_memory_store,
    migrated_store as sqlite_migrated_store,
};

/// Atomic product projection and vocabulary persistence used by the guarded
/// standalone-daemon routes. The SQL adapters implement the same contract.
/// Active, durable versioned ownership, never inferred from a bare scope leaf.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResourceProjectionObservation {
    pub product_id: awaken_iam_contract::ProductId,
    pub org_id: awaken_iam_contract::OrgId,
    pub projection_id: String,
    pub epoch: u64,
    pub parent: awaken_iam_contract::ScopeRef,
}

pub trait ResourceProjectionStore: Send + Sync {
    /// Exact typed vocabulary registered by this product's guarded PAP command.
    fn registered_product_action(
        &self,
        product: &awaken_iam_contract::ProductId,
        resource_type: &awaken_iam_contract::ResourceType,
        action: &awaken_iam_contract::ActionKey,
    ) -> awaken_iam_core::RepositoryResult<bool>;

    /// Resolve only a currently owned, non-retired edge in a committed stream.
    fn observe_resource_projection(
        &self,
        resource_type: &awaken_iam_contract::ResourceType,
        resource_id: &awaken_iam_contract::ResourceId,
    ) -> awaken_iam_core::RepositoryResult<Option<ResourceProjectionObservation>>;

    fn apply_projection(
        &self,
        batch: &awaken_iam_contract::ResourceProjectionBatch,
    ) -> awaken_iam_core::RepositoryResult<awaken_iam_contract::ResourceProjectionReceipt>;

    fn register_product_model(
        &self,
        request: &awaken_iam_contract::ProductResourceModelRequest,
    ) -> awaken_iam_core::RepositoryResult<awaken_iam_contract::ResourceModelRegistered>;
}

#[cfg(test)]
mod privacy_tests;
