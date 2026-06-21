//! Storage edge for IAM: the in-memory adapter and the scope-partitioned
//! migration bundles the database adapter applies.
//!
//! The core declares the [repository ports](awaken_iam_core); this module is
//! the server-owned edge that provides adapters for them, keeping `contract`,
//! `core`, and `client` storage-free. See
//! [deployment](../../../../docs/design/deployment.md).

mod memory;
mod migration;

pub use memory::InMemoryStore;
pub use migration::{
    BundleScope, Dialect, IamStore, MigrateReport, Migration, MigrationBundle, MigrationExecutor,
    PlannedMigration, RecordingExecutor, bundles,
};
