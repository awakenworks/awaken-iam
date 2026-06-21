//! SQLite backend: a [`SqlConn`] and [`MigrationExecutor`] over a `rusqlite`
//! connection.
//!
//! SQLite serves the embedded, local, single-process, and small single-tenant
//! deployments (ADR-0003): a zero-operations, file-backed (or in-memory) store
//! with no server to provision. It is a single-writer engine, so the connection
//! lives behind a [`Mutex`] and the migration single-applier guard is SQLite's
//! own `BEGIN IMMEDIATE` reservation rather than an advisory lock.
//!
//! The connection handle is shared (`Arc<Mutex<..>>`) so the migration executor
//! and the [`SqlStore`] repositories operate on the *same* connection — essential
//! for an in-memory database, whose schema would otherwise be invisible to a
//! second connection.

use std::sync::{Arc, Mutex};

use rusqlite::types::Value;
use rusqlite::{Connection, TransactionBehavior, params_from_iter};

use awaken_iam_core::{RepoError, RepoResult};

use super::migration::{Dialect, IamStore, MigrationExecutor, PlannedMigration};
use super::sql::{SqlConn, SqlParam, SqlRow, SqlStore};

/// A SQLite connection usable as both a migration executor and a repository
/// backend. Cheap to [`Clone`]: clones share one connection.
#[derive(Clone)]
pub struct SqliteBackend {
    conn: Arc<Mutex<Connection>>,
}

impl std::fmt::Debug for SqliteBackend {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SqliteBackend").finish_non_exhaustive()
    }
}

impl SqliteBackend {
    /// Wrap an already-open connection.
    pub fn new(conn: Connection) -> Self {
        Self {
            conn: Arc::new(Mutex::new(conn)),
        }
    }

    /// Open a private in-memory database (tests, ephemeral deployments).
    pub fn open_in_memory() -> RepoResult<Self> {
        let conn = Connection::open_in_memory().map_err(backend_err)?;
        Ok(Self::new(conn))
    }

    /// Open (creating if absent) a file-backed database at `path`.
    pub fn open_path(path: impl AsRef<std::path::Path>) -> RepoResult<Self> {
        let conn = Connection::open(path).map_err(backend_err)?;
        Ok(Self::new(conn))
    }
}

/// Open an in-memory SQLite store, run every IAM migration, and return the
/// repository adapter ready to serve the ports — the common test/embedded path.
pub fn in_memory_store(prefix: &str) -> RepoResult<SqlStore<SqliteBackend>> {
    migrated_store(SqliteBackend::open_in_memory()?, prefix)
}

/// Migrate `backend` under `prefix` and return the repository adapter over it.
pub fn migrated_store(backend: SqliteBackend, prefix: &str) -> RepoResult<SqlStore<SqliteBackend>> {
    IamStore::with_prefix(backend.clone(), prefix)?.migrate()?;
    SqlStore::with_prefix(backend, prefix)
}

fn backend_err(err: rusqlite::Error) -> RepoError {
    // A uniqueness/constraint failure is a domain conflict; everything else is an
    // opaque backend error.
    if let rusqlite::Error::SqliteFailure(e, msg) = &err
        && e.code == rusqlite::ErrorCode::ConstraintViolation
    {
        return RepoError::Conflict(msg.clone().unwrap_or_else(|| err.to_string()));
    }
    RepoError::Backend(err.to_string())
}

/// Rewrite the portable placeholder dialect to SQLite's: a JSON parameter (`?j`)
/// binds into a `TEXT` column exactly like a plain `?`, so both collapse to `?`.
fn render(sql: &str) -> String {
    sql.replace("?j", "?")
}

fn values(params: &[SqlParam]) -> Vec<Value> {
    params
        .iter()
        .map(|cell| match cell {
            Some(text) => Value::Text(text.clone()),
            None => Value::Null,
        })
        .collect()
}

impl SqlConn for SqliteBackend {
    fn dialect(&self) -> Dialect {
        Dialect::Sqlite
    }

    fn execute(&self, sql: &str, params: &[SqlParam]) -> RepoResult<u64> {
        let conn = self.conn.lock().unwrap();
        let affected = conn
            .execute(&render(sql), params_from_iter(values(params)))
            .map_err(backend_err)?;
        Ok(affected as u64)
    }

    fn query(&self, sql: &str, params: &[SqlParam]) -> RepoResult<Vec<SqlRow>> {
        let conn = self.conn.lock().unwrap();
        let mut stmt = conn.prepare(&render(sql)).map_err(backend_err)?;
        let column_count = stmt.column_count();
        let rows = stmt
            .query_map(params_from_iter(values(params)), |row| {
                let mut out: SqlRow = Vec::with_capacity(column_count);
                for idx in 0..column_count {
                    out.push(row.get::<usize, Option<String>>(idx)?);
                }
                Ok(out)
            })
            .map_err(backend_err)?;
        let mut collected = Vec::new();
        for row in rows {
            collected.push(row.map_err(backend_err)?);
        }
        Ok(collected)
    }
}

impl MigrationExecutor for SqliteBackend {
//! SQLite [`MigrationExecutor`] — the embedded / local / single-node backend.
//!
//! This is the SQLite edge of the storage seam (ADR-0003): a thin adapter that
//! applies the dialect-neutral [migration plan](super::migration), rendered for
//! [`Dialect::Sqlite`], against a real `rusqlite` connection. It owns no schema
//! of its own beyond what the plan declares, and it stays storage-agnostic above
//! the wire — `contract`, `core`, and `client` never learn the backend.
//!
//! The single-applier guard (ADR-0003 decision 6) is SQLite's own single-writer
//! semantics: each step applies inside a `BEGIN IMMEDIATE` transaction that takes
//! the database write lock before the DDL runs and records the ledger row in the
//! same transaction, so a step's DDL and its ledger entry commit atomically or
//! not at all.

use rusqlite::{Connection, OptionalExtension, TransactionBehavior, params};

use awaken_iam_core::{RepoError, RepoResult};

use super::migration::{Dialect, MigrationExecutor, PlannedMigration};

/// A [`MigrationExecutor`] that applies the rendered plan against a `rusqlite`
/// [`Connection`].
///
/// Construct one over any connection the host owns — a file-backed database for
/// an embedded deployment, or an in-memory database for tests and ephemeral
/// runs (see [`SqliteExecutor::in_memory`]).
#[derive(Debug)]
pub struct SqliteExecutor {
    conn: Connection,
}

impl SqliteExecutor {
    /// Wrap a host-owned connection.
    pub fn new(conn: Connection) -> Self {
        Self { conn }
    }

    /// Open a fresh in-memory SQLite database and wrap it.
    ///
    /// The database lives only as long as the returned executor; it backs tests
    /// and ephemeral single-process runs where no durability is needed.
    pub fn in_memory() -> RepoResult<Self> {
        let conn = Connection::open_in_memory().map_err(backend)?;
        Ok(Self::new(conn))
    }

    /// Borrow the underlying connection (for read-only introspection).
    pub fn connection(&self) -> &Connection {
        &self.conn
    }
}

/// Map any `rusqlite` failure into the storage-neutral [`RepoError::Backend`].
fn backend(err: rusqlite::Error) -> RepoError {
    RepoError::Backend(format!("sqlite: {err}"))
}

impl MigrationExecutor for SqliteExecutor {
    fn dialect(&self) -> Dialect {
        Dialect::Sqlite
    }

    fn ensure_ledger(&mut self, ledger_ddl: &str) -> RepoResult<()> {
        let conn = self.conn.lock().unwrap();
        conn.execute_batch(ledger_ddl).map_err(backend_err)
        self.conn.execute_batch(ledger_ddl).map_err(backend)
    }

    fn recorded_checksum(
        &self,
        ledger: &str,
        bundle: &str,
        id: &str,
    ) -> RepoResult<Option<String>> {
        let conn = self.conn.lock().unwrap();
        let sql = format!("SELECT checksum FROM {ledger} WHERE bundle = ? AND id = ?");
        let mut stmt = conn.prepare(&sql).map_err(backend_err)?;
        let mut rows = stmt
            .query(params_from_iter([
                Value::Text(bundle.to_owned()),
                Value::Text(id.to_owned()),
            ]))
            .map_err(backend_err)?;
        match rows.next().map_err(backend_err)? {
            Some(row) => Ok(Some(row.get::<usize, String>(0).map_err(backend_err)?)),
            None => Ok(None),
        }
    }

    fn apply(&mut self, ledger: &str, migration: &PlannedMigration) -> RepoResult<()> {
        let mut conn = self.conn.lock().unwrap();
        // BEGIN IMMEDIATE reserves the single writer up front — SQLite's
        // single-applier guard (ADR-0003): a competing applier blocks here rather
        // than racing the DDL.
        let tx = conn
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(backend_err)?;
        tx.execute_batch(&migration.sql).map_err(backend_err)?;
        tx.execute(
            &format!("INSERT INTO {ledger} (bundle, id, checksum) VALUES (?, ?, ?)"),
            params_from_iter([
                Value::Text(migration.bundle.to_owned()),
                Value::Text(migration.id.to_owned()),
                Value::Text(migration.checksum.clone()),
            ]),
        )
        .map_err(backend_err)?;
        tx.commit().map_err(backend_err)
        // `ledger` is the prefix-validated ledger table name (see
        // `IamStore::with_prefix`), so it is safe to interpolate; the lookup keys
        // are bound parameters.
        let sql = format!("SELECT checksum FROM {ledger} WHERE bundle = ?1 AND id = ?2");
        self.conn
            .query_row(&sql, params![bundle, id], |row| row.get::<_, String>(0))
            .optional()
            .map_err(backend)
    }

    fn apply(&mut self, ledger: &str, migration: &PlannedMigration) -> RepoResult<()> {
        // BEGIN IMMEDIATE takes the write lock up front: the single-applier
        // guarantee for the single-writer backend. The step's DDL and its ledger
        // row commit together or roll back together.
        let tx = self
            .conn
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(backend)?;
        tx.execute_batch(&migration.sql).map_err(backend)?;
        let insert = format!("INSERT INTO {ledger} (bundle, id, checksum) VALUES (?1, ?2, ?3)");
        tx.execute(
            &insert,
            params![migration.bundle, migration.id, migration.checksum],
        )
        .map_err(backend)?;
        tx.commit().map_err(backend)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::store::IamStore;

    /// End-to-end: render the SQLite DDL for the canonical bundles and apply it
    /// against a real in-memory SQLite, proving the migrations parse and execute
    /// cleanly against the actual driver — not just a recording stub.
    #[test]
    fn migrations_apply_cleanly_against_a_real_in_memory_sqlite() {
        let mut store = IamStore::with_prefix(SqliteExecutor::in_memory().expect("open"), "iam")
            .expect("store");

        let plan_len = store.plan().len();
        let report = store
            .migrate()
            .expect("migrate applies against real sqlite");
        assert_eq!(report.applied, plan_len);
        assert_eq!(report.skipped, 0);

        // Every rendered table now exists in the live schema.
        let conn = store.pool().connection();
        for table in [
            "iam_schema_migrations",
            "iam_accounts",
            "iam_external_identities",
            "iam_sessions",
            "iam_login_flows",
            "iam_api_tokens",
            "iam_grants",
            "iam_role_bindings",
            "iam_resource_edges",
            "iam_plans",
            "iam_subscriptions",
        ] {
            let found: i64 = conn
                .query_row(
                    "SELECT count(*) FROM sqlite_master WHERE type = 'table' AND name = ?1",
                    params![table],
                    |row| row.get(0),
                )
                .expect("introspect schema");
            assert_eq!(found, 1, "table {table} missing after migrate");
        }

        // The ledger recorded exactly one row per applied step.
        let ledger_rows: i64 = conn
            .query_row("SELECT count(*) FROM iam_schema_migrations", [], |row| {
                row.get(0)
            })
            .expect("count ledger");
        assert_eq!(ledger_rows as usize, plan_len);
    }

    /// Re-running the migration against the same live database applies nothing
    /// new: the ledger short-circuits already-applied steps, proving the bundles
    /// are idempotent against a real driver.
    #[test]
    fn re_migrating_a_real_sqlite_is_idempotent() {
        let mut store = IamStore::with_prefix(SqliteExecutor::in_memory().expect("open"), "iam")
            .expect("store");
        let plan_len = store.plan().len();

        store.migrate().expect("first migrate");
        let second = store.migrate().expect("second migrate");
        assert_eq!(second.applied, 0);
        assert_eq!(second.skipped, plan_len);
    }

    /// The applied schema is usable: a row written through the live SQLite store
    /// round-trips, proving the rendered column types are valid SQLite — not just
    /// syntactically parseable DDL.
    #[test]
    fn the_rendered_schema_accepts_and_returns_a_row() {
        let mut store = IamStore::with_prefix(SqliteExecutor::in_memory().expect("open"), "iam")
            .expect("store");
        store.migrate().expect("migrate");

        let conn = store.pool().connection();
        conn.execute(
            "INSERT INTO iam_accounts (id, status, display_name, created_at, updated_at) \
             VALUES (?1, ?2, ?3, ?4, ?5)",
            params![
                "acct-1",
                "active",
                "Ada",
                "2026-06-22T00:00:00Z",
                "2026-06-22T00:00:00Z"
            ],
        )
        .expect("insert account");

        let status: String = conn
            .query_row(
                "SELECT status FROM iam_accounts WHERE id = ?1",
                params!["acct-1"],
                |row| row.get(0),
            )
            .expect("read back account");
        assert_eq!(status, "active");
    }
}
