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

use std::collections::BTreeMap;
use std::sync::{Arc, Mutex};

use rusqlite::types::Value;
use rusqlite::{Connection, TransactionBehavior, params_from_iter};

use awaken_scoped_migration::{
    AppliedMigration, LEDGER_VERSION, MigrationBundle, check_ledger_version, plan,
    render as render_ddl,
};

use awaken_iam_core::{RepoError, RepoResult};

use super::migration::{Dialect, IamStore, MigrationExecutor, migration_err};
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

impl SqliteBackend {
    /// The per-prefix ledger and its companion version-marker table names.
    fn ledger_tables(prefix: &str) -> (String, String) {
        (
            format!("{prefix}_schema_migrations"),
            format!("{prefix}_schema_migrations_meta"),
        )
    }

    /// Create the ledger and the version-marker table, seeding the marker exactly
    /// once with [`LEDGER_VERSION`]. Mirrors the foundation SQLite shell so an IAM
    /// ledger is identical in shape to any other consumer's.
    fn ensure_ledger(conn: &Connection, prefix: &str) -> RepoResult<()> {
        let (ledger, meta) = Self::ledger_tables(prefix);
        conn.execute_batch(&format!(
            "CREATE TABLE IF NOT EXISTS {ledger} (\
             bundle_id TEXT NOT NULL, \
             version INTEGER NOT NULL, \
             checksum TEXT NOT NULL, \
             description TEXT NOT NULL, \
             applied_at TEXT NOT NULL DEFAULT (datetime('now')), \
             applied_by TEXT NOT NULL, \
             PRIMARY KEY (bundle_id, version))"
        ))
        .map_err(backend_err)?;
        conn.execute_batch(&format!(
            "CREATE TABLE IF NOT EXISTS {meta} (ledger_version INTEGER NOT NULL)"
        ))
        .map_err(backend_err)?;
        conn.execute(
            &format!(
                "INSERT INTO {meta} (ledger_version) \
                 SELECT ?1 WHERE NOT EXISTS (SELECT 1 FROM {meta})"
            ),
            params_from_iter([Value::Integer(LEDGER_VERSION)]),
        )
        .map_err(backend_err)?;
        let found: i64 = conn
            .query_row(
                &format!("SELECT ledger_version FROM {meta} LIMIT 1"),
                [],
                |row| row.get(0),
            )
            .map_err(backend_err)?;
        check_ledger_version(&ledger, found).map_err(migration_err)
    }
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

    fn run_migrations(
        &mut self,
        prefix: &str,
        bundles: &[MigrationBundle],
    ) -> RepoResult<Vec<AppliedMigration>> {
        let dialect = Dialect::Sqlite;
        let (ledger, _meta) = Self::ledger_tables(prefix);
        let mut conn = self.conn.lock().unwrap();
        Self::ensure_ledger(&conn, prefix)?;

        let mut applied = Vec::new();
        for bundle in bundles {
            // BEGIN IMMEDIATE reserves the single writer up front — SQLite's
            // single-applier guard (ADR-0003): it takes the write lock before the
            // ledger is read, so a competing applier blocks here rather than racing
            // the DDL, then verifies. Commit/rollback releases it on every path.
            let tx = conn
                .transaction_with_behavior(TransactionBehavior::Immediate)
                .map_err(backend_err)?;

            let recorded = read_applied(&tx, &ledger, bundle.bundle_id())?;
            let pending = plan(bundle, &recorded, dialect).map_err(migration_err)?;
            for migration in pending {
                let sql = render_ddl(migration.sql_for(dialect), dialect, prefix);
                tx.execute_batch(&sql).map_err(backend_err)?;
                let checksum = migration.checksum_for(dialect);
                let description = migration.ledger_description();
                tx.execute(
                    &format!(
                        "INSERT INTO {ledger} \
                         (bundle_id, version, checksum, description, applied_by) \
                         VALUES (?1, ?2, ?3, ?4, ?5)"
                    ),
                    rusqlite::params![
                        bundle.bundle_id(),
                        migration.version(),
                        checksum,
                        description,
                        "awaken-iam",
                    ],
                )
                .map_err(backend_err)?;
                applied.push(AppliedMigration {
                    bundle_id: bundle.bundle_id().to_owned(),
                    version: migration.version(),
                    checksum,
                    description,
                });
            }
            tx.commit().map_err(backend_err)?;
        }
        Ok(applied)
    }

    fn applied_versions(&self, prefix: &str, bundle_id: &str) -> RepoResult<BTreeMap<i64, String>> {
        let (ledger, _meta) = Self::ledger_tables(prefix);
        let conn = self.conn.lock().unwrap();
        read_applied(&conn, &ledger, bundle_id)
    }
}

/// Read the recorded `(version -> checksum)` map for `bundle_id`. Works over a
/// plain connection or an open transaction (both deref to `&Connection`), so the
/// apply path reads under its `BEGIN IMMEDIATE` guard and readiness reads outside
/// one.
fn read_applied(
    conn: &Connection,
    ledger: &str,
    bundle_id: &str,
) -> RepoResult<BTreeMap<i64, String>> {
    let mut stmt = conn
        .prepare(&format!(
            "SELECT version, checksum FROM {ledger} WHERE bundle_id = ?1 ORDER BY version"
        ))
        .map_err(backend_err)?;
    let rows = stmt
        .query_map([bundle_id], |row| {
            Ok((row.get::<_, i64>(0)?, row.get::<_, String>(1)?))
        })
        .map_err(backend_err)?;
    let mut applied = BTreeMap::new();
    for row in rows {
        let (version, checksum) = row.map_err(backend_err)?;
        applied.insert(version, checksum);
    }
    Ok(applied)
}
