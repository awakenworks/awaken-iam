//! Postgres backend: a [`SqlConn`] and [`MigrationExecutor`] over a synchronous
//! `postgres` client.
//!
//! Postgres serves the standalone, microservice, cloud, multi-node, and
//! highly-available deployments (ADR-0003). The same migration plan and
//! repository logic run as on SQLite; only the driver edge differs — `$1`
//! placeholders, an explicit `::jsonb` cast on JSON parameters, and the
//! single-applier guard implemented as a transaction-scoped `pg_advisory_lock`
//! rather than `BEGIN IMMEDIATE`.
//!
//! The client is `!Sync`, so it lives behind a [`Mutex`]; clones share it.

use std::hash::{Hash, Hasher};
use std::sync::{Arc, Mutex};

use postgres::error::SqlState;
use postgres::types::ToSql;
use postgres::{Client, NoTls};

use awaken_iam_core::{RepoError, RepoResult};

use super::migration::{Dialect, IamStore, MigrationExecutor, PlannedMigration};
use super::sql::{SqlConn, SqlParam, SqlRow, SqlStore};

/// A Postgres connection usable as both a migration executor and a repository
/// backend. Cheap to [`Clone`]: clones share one client.
#[derive(Clone)]
pub struct PostgresBackend {
    client: Arc<Mutex<Client>>,
}

impl std::fmt::Debug for PostgresBackend {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PostgresBackend").finish_non_exhaustive()
    }
}

impl PostgresBackend {
    /// Wrap an already-connected client.
    pub fn new(client: Client) -> Self {
        Self {
            client: Arc::new(Mutex::new(client)),
        }
    }

    /// Connect to Postgres using a libpq-style connection string or URL.
    pub fn connect(params: &str) -> RepoResult<Self> {
        let client = Client::connect(params, NoTls).map_err(backend_err)?;
        Ok(Self::new(client))
    }
}

/// Connect, run every IAM migration under `prefix`, and return the repository
/// adapter over the connection.
pub fn migrated_store(params: &str, prefix: &str) -> RepoResult<SqlStore<PostgresBackend>> {
    let backend = PostgresBackend::connect(params)?;
    IamStore::with_prefix(backend.clone(), prefix)?.migrate()?;
    SqlStore::with_prefix(backend, prefix)
}

fn backend_err(err: postgres::Error) -> RepoError {
    if let Some(db) = err.as_db_error()
        && db.code() == &SqlState::UNIQUE_VIOLATION
    {
        return RepoError::Conflict(db.message().to_owned());
    }
    RepoError::Backend(err.to_string())
}

/// Rewrite the portable placeholder dialect to Postgres numbered parameters:
/// `?` becomes `$n` and a JSON parameter `?j` becomes `$n::jsonb`, casting the
/// bound text into the column's `jsonb` type.
fn render(sql: &str) -> String {
    let mut out = String::with_capacity(sql.len() + 16);
    let mut next = 1usize;
    let bytes = sql.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'?' {
            if i + 1 < bytes.len() && bytes[i + 1] == b'j' {
                out.push_str(&format!("${next}::jsonb"));
                i += 2;
            } else {
                out.push_str(&format!("${next}"));
                i += 1;
            }
            next += 1;
        } else {
            out.push(bytes[i] as char);
            i += 1;
        }
    }
    out
}

/// Borrow the parameters as the trait-object slice the driver wants.
fn refs(params: &[SqlParam]) -> Vec<&(dyn ToSql + Sync)> {
    params
        .iter()
        .map(|cell| cell as &(dyn ToSql + Sync))
        .collect()
}

/// Stable, cross-process advisory-lock key for a ledger's migrations, so every
/// node applying the same component's bundles contends on one lock.
fn advisory_key(ledger: &str) -> i64 {
    let mut hasher = std::collections::hash_map::DefaultHasher::new();
    ledger.hash(&mut hasher);
    hasher.finish() as i64
}

impl SqlConn for PostgresBackend {
    fn dialect(&self) -> Dialect {
        Dialect::Postgres
    }

    fn execute(&self, sql: &str, params: &[SqlParam]) -> RepoResult<u64> {
        let mut client = self.client.lock().unwrap();
        client
            .execute(&render(sql), &refs(params))
            .map_err(backend_err)
    }

    fn query(&self, sql: &str, params: &[SqlParam]) -> RepoResult<Vec<SqlRow>> {
        let mut client = self.client.lock().unwrap();
        let rows = client
            .query(&render(sql), &refs(params))
            .map_err(backend_err)?;
        let mut out = Vec::with_capacity(rows.len());
        for row in &rows {
            let mut cells: SqlRow = Vec::with_capacity(row.len());
            for idx in 0..row.len() {
                cells.push(
                    row.try_get::<usize, Option<String>>(idx)
                        .map_err(backend_err)?,
                );
            }
            out.push(cells);
        }
        Ok(out)
    }
}

impl MigrationExecutor for PostgresBackend {
    fn dialect(&self) -> Dialect {
        Dialect::Postgres
    }

    fn ensure_ledger(&mut self, ledger_ddl: &str) -> RepoResult<()> {
        let mut client = self.client.lock().unwrap();
        client.batch_execute(ledger_ddl).map_err(backend_err)
    }

    fn recorded_checksum(
        &self,
        ledger: &str,
        bundle: &str,
        id: &str,
    ) -> RepoResult<Option<String>> {
        let mut client = self.client.lock().unwrap();
        let sql = format!("SELECT checksum FROM {ledger} WHERE bundle = $1 AND id = $2");
        let rows = client.query(&sql, &[&bundle, &id]).map_err(backend_err)?;
        match rows.first() {
            Some(row) => Ok(Some(row.try_get::<usize, String>(0).map_err(backend_err)?)),
            None => Ok(None),
        }
    }

    fn apply(&mut self, ledger: &str, migration: &PlannedMigration) -> RepoResult<()> {
        let mut client = self.client.lock().unwrap();
        let mut tx = client.transaction().map_err(backend_err)?;
        // Transaction-scoped advisory lock: the single-applier guard (ADR-0003).
        // It auto-releases at commit/rollback, so a competing applier waits here
        // and then finds the step already recorded.
        tx.execute("SELECT pg_advisory_xact_lock($1)", &[&advisory_key(ledger)])
            .map_err(backend_err)?;
        tx.batch_execute(&migration.sql).map_err(backend_err)?;
        tx.execute(
            &format!("INSERT INTO {ledger} (bundle, id, checksum) VALUES ($1, $2, $3)"),
            &[&migration.bundle, &migration.id, &migration.checksum],
        )
        .map_err(backend_err)?;
        tx.commit().map_err(backend_err)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn render_numbers_plain_and_json_placeholders_in_order() {
        let sql = "INSERT INTO t (a, b, c) VALUES (?, ?j, ?)";
        assert_eq!(
            render(sql),
            "INSERT INTO t (a, b, c) VALUES ($1, $2::jsonb, $3)"
        );
    }

    #[test]
    fn render_casts_every_json_parameter_to_jsonb() {
        let sql = "UPDATE t SET a = ?j, b = ?j WHERE c = ?j AND d = ?";
        assert_eq!(
            render(sql),
            "UPDATE t SET a = $1::jsonb, b = $2::jsonb WHERE c = $3::jsonb AND d = $4"
        );
    }

    #[test]
    fn advisory_key_is_stable_and_per_ledger() {
        assert_eq!(
            advisory_key("iam_schema_migrations"),
            advisory_key("iam_schema_migrations")
        );
        assert_ne!(
            advisory_key("iam_schema_migrations"),
            advisory_key("iamx_schema_migrations")
        );
    }
}
