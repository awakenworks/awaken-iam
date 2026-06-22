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
    fn dialect(&self) -> Dialect {
        Dialect::Sqlite
    }

    fn ensure_ledger(&mut self, ledger_ddl: &str) -> RepoResult<()> {
        let conn = self.conn.lock().unwrap();
        conn.execute_batch(ledger_ddl).map_err(backend_err)
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
    }
}
