//! Scope-partitioned, self-contained schema migration bundles.
//!
//! IAM owns its schema as append-only, checksum-verified migration bundles, one
//! per subdomain scope. The bundle/checksum/plan **mechanism** is the shared
//! [`awaken-scoped-migration`](awaken_scoped_migration) foundation crate; this
//! module is the thin per-backend glue that drives the crate's pure core against
//! IAM's own database drivers. The bundles themselves — IAM's schema DDL — live
//! in [`super::bundles`], kept separate so the portable migration best-practice
//! hook discovers and checks them.
//!
//! The store is constructed with a table prefix —
//! [`IamStore::with_prefix`]`(pool, "iam")` yields `iam_accounts`,
//! `iam_grants`, … and the ledger `iam_schema_migrations`. The same DDL renders
//! against any prefix, which is what lets IAM deploy embedded (sharing a host's
//! database next to siblings using their own prefixes) or standalone (its own
//! database) from one codebase. The pool itself is supplied by the host through
//! a [`MigrationExecutor`]; this module is pool-agnostic so the core stays
//! storage-free and each backend executor (Postgres, SQLite) is a thin edge
//! adapter over the foundation crate's [`plan`](awaken_scoped_migration::plan).
//!
//! DDL is authored **dialect-neutral** using the foundation crate's portable
//! token vocabulary (`{prefix}`, `{json}`, `{timestamptz}`, `{now}`, `{blob}`,
//! `{pk_autoinc}`), which each backend renders to its dialect via
//! [`awaken_scoped_migration::render`] alongside the prefix. See
//! [ADR-0003](../../../../docs/adr/0003-storage-backends.md).
//!
//! ## Why the foundation crate's *core* and not its runner shells
//!
//! `awaken-scoped-migration` ships optional async-`sqlx` runner shells
//! (`postgres`, `sqlite-sqlx`); its synchronous rusqlite shell is the sibling
//! crate `awaken-scoped-migration-sqlite` (foundation ADR-0005). IAM's backends
//! use the *synchronous* `postgres` client and `rusqlite` directly, so IAM
//! depends on the crate with **default features** (the driver-agnostic pure core)
//! and writes its own thin shells here, exactly mirroring the pattern the crate's
//! own shells follow.

use std::collections::BTreeMap;

use awaken_iam_core::{RepoError, RepoResult};

pub use awaken_scoped_migration::{
    AppliedMigration, Dialect, Migration, MigrationBundle, MigrationError,
};
use awaken_scoped_migration::{plan as plan_bundle, render, sql_identifier};

use super::bundles::bundles;

/// Map a foundation [`MigrationError`] onto the IAM repository error taxonomy.
///
/// The whole migration mechanism reports through one error type; at the IAM edge
/// every variant is an opaque backend failure (a drifted checksum, an unreachable
/// ledger, an invalid prefix), surfaced verbatim so the cause is preserved.
pub(crate) fn migration_err(err: MigrationError) -> RepoError {
    RepoError::Backend(err.to_string())
}

/// A migration rendered for a concrete table prefix and dialect, ready to apply.
///
/// The flattened, ordered view of [`bundles`] a store exposes for inspection
/// (the readiness plan length, deployment-parity equality). The `checksum` is the
/// foundation-template identity, stable across dialects for a portable migration.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PlannedMigration {
    /// Owning bundle id (e.g. `iam.identity`).
    pub bundle: String,
    /// Migration version within the bundle.
    pub version: i64,
    /// Checksum of the canonical template under the active dialect.
    pub checksum: String,
    /// Prefix- and dialect-rendered DDL to execute for the active backend.
    pub sql: String,
}

/// Summary of an [`IamStore::migrate`] run.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MigrateReport {
    /// Steps applied this run.
    pub applied: usize,
    /// Steps skipped because they were already recorded.
    pub skipped: usize,
}

/// Executor seam a deployment provides to apply IAM's bundles and read its
/// ledger.
///
/// The Postgres and SQLite backends implement this over their own driver; tests
/// use the in-memory [`RecordingExecutor`]. Each implementation owns the
/// backend-specific apply transaction and single-applier guard, delegating the
/// *decision* of what to apply to [`awaken_scoped_migration::plan`] — so the
/// shared mechanism (ordering, checksums, drift detection, the ledger fence) is
/// identical across backends and only the driver edge differs.
pub trait MigrationExecutor {
    /// The SQL backend this executor applies and checksums migrations under.
    fn dialect(&self) -> Dialect;

    /// Apply every pending migration across `bundles` under `prefix`, in order,
    /// idempotently, under the backend's single-applier guard.
    ///
    /// Already-applied steps whose recorded checksum matches are skipped; a step
    /// whose recorded checksum differs is a drift error (bundles are append-only).
    /// Returns the steps applied this run.
    fn run_migrations(
        &mut self,
        prefix: &str,
        bundles: &[MigrationBundle],
    ) -> RepoResult<Vec<AppliedMigration>>;

    /// Read the recorded `(version -> checksum)` map for `bundle_id` under
    /// `prefix`, the input [`awaken_scoped_migration::plan`] verifies against.
    fn applied_versions(&self, prefix: &str, bundle_id: &str) -> RepoResult<BTreeMap<i64, String>>;
}

/// Storage adapter that owns IAM's schema for a given table prefix.
///
/// `Pool` is the host-supplied migration executor (a [`PostgresBackend`] /
/// [`SqliteBackend`] in real deployments, the [`RecordingExecutor`] in tests).
/// The store never opens or owns the pool's lifecycle in embedded mode — it owns
/// its *schema within* the shared database, isolated by the distinct prefix and
/// its own ledger.
///
/// [`PostgresBackend`]: super::PostgresBackend
/// [`SqliteBackend`]: super::SqliteBackend
#[derive(Debug, Clone)]
pub struct IamStore<Pool> {
    prefix: String,
    pool: Pool,
}

impl<Pool> IamStore<Pool> {
    /// Construct a store over `pool`, isolating IAM's tables behind `prefix`.
    ///
    /// `prefix` is validated by [`awaken_scoped_migration::sql_identifier`]
    /// (leading ASCII letter, then `[A-Za-z0-9_]`); it is concatenated into table
    /// names, so anything else is rejected to keep the rendered DDL injection-free.
    pub fn with_prefix(pool: Pool, prefix: impl Into<String>) -> RepoResult<Self> {
        let prefix = sql_identifier(&prefix.into()).map_err(migration_err)?;
        Ok(Self { prefix, pool })
    }

    /// The configured table prefix.
    pub fn prefix(&self) -> &str {
        &self.prefix
    }

    /// Borrow the underlying pool/executor handle.
    pub fn pool(&self) -> &Pool {
        &self.pool
    }

    /// Mutably borrow the underlying pool/executor handle.
    pub fn pool_mut(&mut self) -> &mut Pool {
        &mut self.pool
    }

    /// The ledger table name: `<prefix>_schema_migrations`.
    ///
    /// Each component keeps its own ledger so siblings sharing a database never
    /// contend on a single migration table.
    pub fn ledger_table(&self) -> String {
        format!("{}_schema_migrations", self.prefix)
    }
}

impl<Pool: MigrationExecutor> IamStore<Pool> {
    /// The full ordered set of migrations rendered for this prefix and the
    /// executor's backend [`Dialect`].
    ///
    /// The `checksum` is the neutral-template identity, so it is stable across
    /// dialects even though the rendered `sql` differs.
    pub fn plan(&self) -> Vec<PlannedMigration> {
        let dialect = self.pool.dialect();
        let mut planned = Vec::new();
        for bundle in bundles() {
            for migration in bundle.migrations() {
                planned.push(PlannedMigration {
                    bundle: bundle.bundle_id().to_owned(),
                    version: migration.version(),
                    checksum: migration.checksum_for(dialect),
                    sql: render(migration.sql_for(dialect), dialect, &self.prefix),
                });
            }
        }
        planned
    }

    /// Apply every pending migration in order, verifying already-applied steps.
    ///
    /// Idempotent and fail-closed: delegates the apply to the executor, which runs
    /// the foundation crate's plan under its single-applier guard so concurrent
    /// node startup is safe and a drifted step aborts the run.
    pub fn migrate(&mut self) -> RepoResult<MigrateReport> {
        let bundles = bundles();
        let total: usize = bundles.iter().map(|b| b.migrations().len()).sum();
        let applied = self.pool.run_migrations(&self.prefix, &bundles)?;
        Ok(MigrateReport {
            applied: applied.len(),
            skipped: total - applied.len(),
        })
    }

    /// Whether every planned migration is recorded with a matching checksum.
    ///
    /// The readiness ([`/readyz`](crate::Readiness)) probe behind it: it both
    /// confirms the node's own migrations are applied and, because it reads the
    /// ledger, proves the store is reachable. A pending step, a drifted checksum,
    /// or an unreadable ledger all report *not applied* — readiness fails closed.
    pub fn migrations_applied(&self) -> RepoResult<bool> {
        let dialect = self.pool.dialect();
        for bundle in bundles() {
            // An unreadable ledger errors here → not ready (fail closed).
            let applied = self
                .pool
                .applied_versions(&self.prefix, bundle.bundle_id())?;
            // A pending step (non-empty plan) or a drift/unknown-version error
            // (Err) both mean this node is not fully migrated.
            match plan_bundle(&bundle, &applied, dialect) {
                Ok(pending) if pending.is_empty() => {}
                _ => return Ok(false),
            }
        }
        Ok(true)
    }
}

/// In-memory [`MigrationExecutor`] for tests and the local adapter.
///
/// It drives the same foundation [`plan`](awaken_scoped_migration::plan) the real
/// backends do over an in-memory ledger, recording the rendered DDL it was asked
/// to run, so tests can assert ordering, idempotence, and drift handling without
/// a live database.
#[derive(Debug, Clone)]
pub struct RecordingExecutor {
    /// Recorded ledger rows keyed by `(bundle_id, version)` to their checksum.
    ledger: BTreeMap<(String, i64), String>,
    /// Backend dialect the plan is rendered and checksummed against.
    dialect: Dialect,
    /// DDL statements executed in order (the ledger DDL, then each applied body).
    pub executed: Vec<String>,
    /// Whether the ledger DDL has been recorded this executor's lifetime.
    ledger_created: bool,
}

impl Default for RecordingExecutor {
    fn default() -> Self {
        Self::new()
    }
}

impl RecordingExecutor {
    /// A fresh executor with an empty ledger, rendering for the
    /// [`Dialect::Postgres`] backend.
    pub fn new() -> Self {
        Self::with_dialect(Dialect::Postgres)
    }

    /// A fresh executor that renders the plan for a specific backend dialect.
    pub fn with_dialect(dialect: Dialect) -> Self {
        Self {
            ledger: BTreeMap::new(),
            dialect,
            executed: Vec::new(),
            ledger_created: false,
        }
    }

    /// Overwrite a ledger row's checksum to simulate a drifted prior apply.
    pub fn force_checksum(&mut self, bundle_id: &str, version: i64, checksum: &str) {
        self.ledger
            .insert((bundle_id.to_owned(), version), checksum.to_owned());
    }
}

impl MigrationExecutor for RecordingExecutor {
    fn dialect(&self) -> Dialect {
        self.dialect
    }

    fn run_migrations(
        &mut self,
        prefix: &str,
        bundles: &[MigrationBundle],
    ) -> RepoResult<Vec<AppliedMigration>> {
        if !self.ledger_created {
            self.executed.push(format!(
                "CREATE TABLE IF NOT EXISTS {prefix}_schema_migrations (...)"
            ));
            self.ledger_created = true;
        }
        let dialect = self.dialect;
        let mut applied = Vec::new();
        for bundle in bundles {
            let recorded = self.applied_versions(prefix, bundle.bundle_id())?;
            let pending = plan_bundle(bundle, &recorded, dialect).map_err(migration_err)?;
            for migration in pending {
                self.executed
                    .push(render(migration.sql_for(dialect), dialect, prefix));
                let checksum = migration.checksum_for(dialect);
                self.ledger.insert(
                    (bundle.bundle_id().to_owned(), migration.version()),
                    checksum.clone(),
                );
                applied.push(AppliedMigration {
                    bundle_id: bundle.bundle_id().to_owned(),
                    version: migration.version(),
                    checksum,
                    description: migration.ledger_description(),
                });
            }
        }
        Ok(applied)
    }

    fn applied_versions(
        &self,
        _prefix: &str,
        bundle_id: &str,
    ) -> RepoResult<BTreeMap<i64, String>> {
        Ok(self
            .ledger
            .iter()
            .filter(|((bundle, _), _)| bundle == bundle_id)
            .map(|((_, version), checksum)| (*version, checksum.clone()))
            .collect())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn store(prefix: &str) -> IamStore<RecordingExecutor> {
        IamStore::with_prefix(RecordingExecutor::new(), prefix).expect("valid prefix")
    }

    #[test]
    fn with_prefix_renders_table_and_ledger_names() {
        let store = store("iam");
        assert_eq!(store.ledger_table(), "iam_schema_migrations");
        let plan = store.plan();
        assert!(plan.iter().any(|m| m.sql.contains("iam_accounts")));
        assert!(plan.iter().any(|m| m.sql.contains("iam_api_tokens")));
        assert!(plan.iter().any(|m| m.sql.contains("iam_oauth_clients")));
        assert!(plan.iter().any(|m| m.sql.contains("iam_grants")));
        assert!(plan.iter().any(|m| m.sql.contains("iam_plans")));
        // No unrendered template tokens leak into the executed SQL.
        assert!(plan.iter().all(|m| !m.sql.contains('{')));
    }

    #[test]
    fn renders_postgres_and_sqlite_type_tokens_distinctly() {
        let pg = IamStore::with_prefix(RecordingExecutor::with_dialect(Dialect::Postgres), "iam")
            .expect("valid prefix");
        let lite = IamStore::with_prefix(RecordingExecutor::with_dialect(Dialect::Sqlite), "iam")
            .expect("valid prefix");

        let pg_sql: String = pg.plan().iter().map(|m| m.sql.clone()).collect();
        let lite_sql: String = lite.plan().iter().map(|m| m.sql.clone()).collect();

        // Postgres keeps JSONB; SQLite renders the portable TEXT form and never
        // emits a Postgres-only type.
        assert!(pg_sql.contains("claims JSONB"));
        assert!(!lite_sql.contains("JSONB"));
        assert!(lite_sql.contains("claims TEXT"));
    }

    #[test]
    fn checksum_is_dialect_independent_but_rendered_sql_is_not() {
        // The migration's recorded identity is the neutral template, so the
        // checksum is the same on either backend even though the rendered SQL is
        // dialect-specific.
        let pg = IamStore::with_prefix(RecordingExecutor::with_dialect(Dialect::Postgres), "iam")
            .expect("valid prefix");
        let lite = IamStore::with_prefix(RecordingExecutor::with_dialect(Dialect::Sqlite), "iam")
            .expect("valid prefix");
        let (pg_plan, lite_plan) = (pg.plan(), lite.plan());
        assert_eq!(pg_plan.len(), lite_plan.len());
        let mut any_diverged = false;
        for (a, b) in pg_plan.iter().zip(lite_plan.iter()) {
            assert_eq!(
                a.checksum, b.checksum,
                "{}::{} identity drifted",
                a.bundle, a.version
            );
            any_diverged |= a.sql != b.sql;
        }
        assert!(
            any_diverged,
            "no migration rendered dialect-specifically; type-token rendering is inert"
        );
    }

    #[test]
    fn both_dialects_migrate_cleanly_and_idempotently() {
        for dialect in [Dialect::Postgres, Dialect::Sqlite] {
            let mut store = IamStore::with_prefix(RecordingExecutor::with_dialect(dialect), "iam")
                .expect("valid prefix");
            let first = store.migrate().expect("first migrate");
            assert_eq!(first.applied, store.plan().len());
            assert_eq!(first.skipped, 0);
            let second = store.migrate().expect("second migrate");
            assert_eq!(second.applied, 0);
            assert_eq!(second.skipped, store.plan().len());
        }
    }

    #[test]
    fn a_different_prefix_isolates_a_sibling_in_the_same_database() {
        let store = store("iamx");
        assert_eq!(store.ledger_table(), "iamx_schema_migrations");
        assert!(store.plan().iter().all(|m| m.sql.contains("iamx_")));
    }

    #[test]
    fn invalid_prefixes_are_rejected() {
        // Empty, a leading digit, and an injection attempt are all rejected by the
        // shared identifier validation.
        assert!(IamStore::with_prefix(RecordingExecutor::new(), "").is_err());
        assert!(IamStore::with_prefix(RecordingExecutor::new(), "iam_accounts; DROP").is_err());
        assert!(IamStore::with_prefix(RecordingExecutor::new(), "1iam").is_err());
        // A bare lowercase identifier is accepted.
        assert!(IamStore::with_prefix(RecordingExecutor::new(), "iam").is_ok());
    }

    #[test]
    fn migrate_applies_every_step_once_then_is_idempotent() {
        let mut store = store("iam");
        let first = store.migrate().expect("first migrate");
        assert_eq!(first.applied, store.plan().len());
        assert_eq!(first.skipped, 0);

        let second = store.migrate().expect("second migrate");
        assert_eq!(second.applied, 0);
        assert_eq!(second.skipped, store.plan().len());

        // The ledger DDL ran exactly once.
        let ledger_runs = store
            .pool()
            .executed
            .iter()
            .filter(|s| s.contains("schema_migrations"))
            .count();
        assert_eq!(ledger_runs, 1);
    }

    #[test]
    fn migrate_detects_checksum_drift_in_an_applied_step() {
        let mut executor = RecordingExecutor::new();
        executor.force_checksum("iam.identity", 1, "deadbeef");
        let mut store = IamStore::with_prefix(executor, "iam").expect("valid prefix");
        let err = store.migrate().expect_err("drift must fail closed");
        assert!(matches!(err, RepoError::Backend(msg) if msg.contains("checksum mismatch")));
    }

    #[test]
    fn migrations_applied_is_false_before_and_true_after_migrate() {
        let mut store = store("iam");
        // Readiness fences on this: an un-migrated store is not applied.
        assert!(!store.migrations_applied().expect("probe"));
        store.migrate().expect("migrate");
        assert!(store.migrations_applied().expect("probe"));
    }

    #[test]
    fn migrations_applied_is_false_when_a_recorded_step_drifts() {
        let mut store = store("iam");
        store.migrate().expect("migrate");
        // Corrupt one recorded checksum: readiness must report not-applied, never
        // a hopeful ready over a ledger it can no longer trust.
        store.pool_mut().force_checksum("iam.authz", 3, "deadbeef");
        assert!(!store.migrations_applied().expect("probe"));
    }

    /// `check_migrations --audit`: validates every shipped bundle against the
    /// awaken-scoped-migration rules. Run directly via `cargo run -p xtask --
    /// check-migrations --audit` or implicitly by `cargo test --workspace`.
    #[test]
    fn check_migrations_audit_passes() {
        // Forbidden patterns in migration DDL templates.
        // Portable type tokens ({json}, {timestamptz}, {now}, {pk_autoinc}) are
        // all lowercase and do not contain these uppercase strings.
        let banned: &[(&str, &str)] = &[
            (
                "IF NOT EXISTS",
                "idempotency guard; the ledger handles this",
            ),
            ("JSONB", "raw Postgres type; use {json}"),
            ("TIMESTAMPTZ", "raw Postgres type; use {timestamptz}"),
            ("BIGSERIAL", "raw Postgres type; use {pk_autoinc}"),
            (" SERIAL ", "raw Postgres type; use {pk_autoinc}"),
            ("now()", "raw Postgres function; use {now}"),
        ];
        for bundle in bundles() {
            for m in bundle.migrations() {
                assert!(
                    !m.description().is_empty(),
                    "{}::{} has empty description",
                    bundle.bundle_id(),
                    m.label()
                );
                for (pat, reason) in banned {
                    assert!(
                        !m.sql_for(Dialect::Postgres).contains(pat),
                        "{}::{} contains forbidden pattern {pat:?}: {reason}",
                        bundle.bundle_id(),
                        m.label()
                    );
                }
            }
        }
    }

    #[test]
    fn checksums_are_stable_and_per_migration() {
        let plan = store("iam").plan();
        // Stable across renders/prefixes.
        let again = store("other").plan();
        for (a, b) in plan.iter().zip(again.iter()) {
            assert_eq!(a.checksum, b.checksum);
        }
        // Distinct migrations have distinct checksums.
        let mut sums: Vec<&str> = plan.iter().map(|m| m.checksum.as_str()).collect();
        sums.sort_unstable();
        sums.dedup();
        assert_eq!(sums.len(), plan.len());
    }
}
