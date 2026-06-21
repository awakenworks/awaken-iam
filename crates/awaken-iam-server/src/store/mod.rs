//! Storage edge for IAM: the in-memory adapter and the scope-partitioned
//! migration bundles the database adapter applies.
//!
//! The core declares the [repository ports](awaken_iam_core); this module is
//! the server-owned edge that provides adapters for them, keeping `contract`,
//! `core`, and `client` storage-free. The SQLite executor is the first concrete
//! database edge over the migration plan. See
//! [deployment](../../../../docs/design/deployment.md).

mod fence;
mod health;
mod memory;
mod migration;
mod postgres;
mod sql;
mod sqlite;

pub use fence::{Fence, FenceStore};
pub use health::{Liveness, Readiness};
pub use memory::InMemoryStore;
pub use migration::{
    BundleScope, Dialect, IamStore, MigrateReport, Migration, MigrationBundle, MigrationExecutor,
    PlannedMigration, RecordingExecutor, bundles,
};
pub use postgres::{PostgresBackend, migrated_store as postgres_migrated_store};
pub use sql::{SqlConn, SqlParam, SqlRow, SqlStore};
pub use sqlite::{
    SqliteBackend, in_memory_store as sqlite_in_memory_store,
    migrated_store as sqlite_migrated_store,
};
pub use sqlite::SqliteExecutor;
