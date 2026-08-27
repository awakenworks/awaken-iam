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
    AppliedMigration, Dialect as MigrationDialect, LedgerBootstrapAction, LedgerSchema,
    MigrationBundle, MigrationError, check_ledger_version, plan, render as render_ddl,
};

use awaken_iam_core::{RepositoryError, RepositoryResult};

use super::migration::{Dialect, IamStore, MigrationExecutor, migration_err};
use super::sql::{SqlConn, SqlParam, SqlRow, SqlStore, SqlWrite};

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
    pub fn open_in_memory() -> RepositoryResult<Self> {
        let conn = Connection::open_in_memory().map_err(backend_err)?;
        Ok(Self::new(conn))
    }

    /// Open (creating if absent) a file-backed database at `path`.
    pub fn open_path(path: impl AsRef<std::path::Path>) -> RepositoryResult<Self> {
        let conn = Connection::open(path).map_err(backend_err)?;
        Ok(Self::new(conn))
    }
}

/// Open an in-memory SQLite store, run every IAM migration, and return the
/// repository adapter ready to serve the repository contracts — the common test/embedded path.
pub fn in_memory_store(prefix: &str) -> RepositoryResult<SqlStore<SqliteBackend>> {
    migrated_store(SqliteBackend::open_in_memory()?, prefix)
}

/// Migrate `backend` under `prefix` and return the repository adapter over it.
pub fn migrated_store(
    backend: SqliteBackend,
    prefix: &str,
) -> RepositoryResult<SqlStore<SqliteBackend>> {
    IamStore::with_prefix(backend.clone(), prefix)?.migrate()?;
    SqlStore::with_prefix(backend, prefix)
}

fn backend_err(err: rusqlite::Error) -> RepositoryError {
    // A uniqueness/constraint failure is a domain conflict; everything else is an
    // opaque backend error.
    if let rusqlite::Error::SqliteFailure(e, msg) = &err
        && e.code == rusqlite::ErrorCode::ConstraintViolation
    {
        return RepositoryError::Conflict(msg.clone().unwrap_or_else(|| err.to_string()));
    }
    RepositoryError::Backend(err.to_string())
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
    /// Bootstrap or validate the foundation-owned ledger generation under an
    /// IMMEDIATE transaction. IAM owns only the rusqlite calls; names, DDL, and
    /// the fail-closed state decision remain authoritative in foundation.
    fn ensure_ledger(conn: &mut Connection, prefix: &str) -> RepositoryResult<()> {
        let schema = LedgerSchema::with_prefix(prefix).map_err(migration_err)?;
        let tx = conn
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(backend_err)?;
        let exists = |table: &str| {
            tx.query_row(
                "SELECT EXISTS(SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = ?1)",
                [table],
                |row| row.get::<_, bool>(0),
            )
            .map_err(backend_err)
        };
        let action = schema
            .bootstrap_action(exists(schema.ledger_table())?, exists(schema.meta_table())?)
            .map_err(migration_err)?;
        if action == LedgerBootstrapAction::Create {
            for statement in schema.create_statements(MigrationDialect::Sqlite) {
                tx.execute_batch(&statement).map_err(backend_err)?;
            }
        }
        let mut statement = tx
            .prepare(&format!(
                "SELECT ledger_version FROM {}",
                schema.meta_table()
            ))
            .map_err(backend_err)?;
        let rows = statement
            .query_map([], |row| row.get::<_, i64>(0))
            .map_err(backend_err)?
            .collect::<Result<Vec<_>, _>>()
            .map_err(backend_err)?;
        drop(statement);
        if rows.len() != 1 {
            return Err(migration_err(MigrationError::LedgerMetadataRowCount {
                meta_table: schema.meta_table().to_string(),
                found: rows.len(),
            }));
        }
        check_ledger_version(schema.ledger_table(), rows[0]).map_err(migration_err)?;
        tx.commit().map_err(backend_err)
    }
}

impl SqlConn for SqliteBackend {
    fn dialect(&self) -> Dialect {
        Dialect::Sqlite
    }

    fn execute(&self, sql: &str, params: &[SqlParam]) -> RepositoryResult<u64> {
        let conn = self.conn.lock().unwrap();
        let affected = conn
            .execute(&render(sql), params_from_iter(values(params)))
            .map_err(backend_err)?;
        Ok(affected as u64)
    }

    fn query(&self, sql: &str, params: &[SqlParam]) -> RepositoryResult<Vec<SqlRow>> {
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

    fn execute_transaction(&self, writes: &[SqlWrite]) -> RepositoryResult<Vec<u64>> {
        let mut conn = self.conn.lock().unwrap();
        let tx = conn
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(backend_err)?;
        let mut affected = Vec::with_capacity(writes.len());
        for write in writes {
            affected.push(
                tx.execute(&render(&write.sql), params_from_iter(values(&write.params)))
                    .map_err(backend_err)? as u64,
            );
        }
        tx.commit().map_err(backend_err)?;
        Ok(affected)
    }

    fn execute_transaction_checked(
        &self,
        writes: &[SqlWrite],
        required: &[(usize, u64)],
    ) -> RepositoryResult<Vec<u64>> {
        let mut conn = self.conn.lock().unwrap();
        let tx = conn
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(backend_err)?;
        let mut affected = Vec::with_capacity(writes.len());
        for write in writes {
            affected.push(
                tx.execute(&render(&write.sql), params_from_iter(values(&write.params)))
                    .map_err(backend_err)? as u64,
            );
        }
        if let Some((index, expected)) = required
            .iter()
            .find(|(index, expected)| affected.get(*index) != Some(expected))
        {
            return Err(RepositoryError::Conflict(format!(
                "transaction write {index} affected {} rows; expected {expected}",
                affected.get(*index).copied().unwrap_or(0)
            )));
        }
        tx.commit().map_err(backend_err)?;
        Ok(affected)
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
    ) -> RepositoryResult<Vec<AppliedMigration>> {
        let dialect = Dialect::Sqlite;
        let schema = LedgerSchema::with_prefix(prefix).map_err(migration_err)?;
        let ledger = schema.ledger_table();
        let mut conn = self.conn.lock().unwrap();
        Self::ensure_ledger(&mut conn, prefix)?;

        let mut applied = Vec::new();
        for bundle in bundles {
            // BEGIN IMMEDIATE reserves the single writer up front — SQLite's
            // single-applier guard (ADR-0003): it takes the write lock before the
            // ledger is read, so a competing applier blocks here rather than racing
            // the DDL, then verifies. Commit/rollback releases it on every path.
            let tx = conn
                .transaction_with_behavior(TransactionBehavior::Immediate)
                .map_err(backend_err)?;

            let recorded = read_applied(&tx, ledger, bundle.bundle_id())?;
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

    fn applied_versions(
        &self,
        prefix: &str,
        bundle_id: &str,
    ) -> RepositoryResult<BTreeMap<i64, String>> {
        let schema = LedgerSchema::with_prefix(prefix).map_err(migration_err)?;
        let conn = self.conn.lock().unwrap();
        read_applied(&conn, schema.ledger_table(), bundle_id)
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
) -> RepositoryResult<BTreeMap<i64, String>> {
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

#[cfg(test)]
mod migration_tests {
    use super::*;

    #[test]
    fn ledger_bootstrap_is_deterministic_and_fail_closed() {
        // Cause/effect decision table:
        // R1 neither table exists -> create the foundation v1 schema once;
        // R2 both exist -> validate, leaving one metadata row;
        // R3/R4 exactly one exists -> Backend(IncompleteLedger), with no repair.
        let mut fresh = Connection::open_in_memory().unwrap();
        SqliteBackend::ensure_ledger(&mut fresh, "iam").unwrap();
        SqliteBackend::ensure_ledger(&mut fresh, "iam").unwrap();
        let stamps: i64 = fresh
            .query_row(
                "SELECT COUNT(*) FROM iam_schema_migrations_meta",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(stamps, 1);

        for create in [
            "CREATE TABLE iam_schema_migrations (\
             bundle_id TEXT NOT NULL, version INTEGER NOT NULL, checksum TEXT NOT NULL, \
             description TEXT NOT NULL, applied_at TEXT NOT NULL, applied_by TEXT NOT NULL, \
             PRIMARY KEY (bundle_id, version))",
            "CREATE TABLE iam_schema_migrations_meta (ledger_version INTEGER NOT NULL)",
        ] {
            let mut partial = Connection::open_in_memory().unwrap();
            partial.execute_batch(create).unwrap();
            let error = SqliteBackend::ensure_ledger(&mut partial, "iam").unwrap_err();
            assert!(error.to_string().contains("incomplete migration ledger"));
            let tables: i64 = partial
                .query_row(
                    "SELECT COUNT(*) FROM sqlite_master WHERE type = 'table' \
                     AND name IN ('iam_schema_migrations', 'iam_schema_migrations_meta')",
                    [],
                    |row| row.get(0),
                )
                .unwrap();
            assert_eq!(tables, 1, "partial ledger must not be repaired");
        }
    }
}
