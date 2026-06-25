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

use std::collections::BTreeMap;
use std::sync::{Arc, Mutex};

use postgres::error::SqlState;
use postgres::types::ToSql;
use postgres::{Client, NoTls};

use awaken_scoped_migration::{
    AppliedMigration, LEDGER_VERSION, MigrationBundle, check_ledger_version, plan,
    render as render_ddl,
};

use awaken_iam_core::{RepoError, RepoResult};

use super::migration::{Dialect, IamStore, MigrationExecutor, migration_err};
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

impl PostgresBackend {
    /// The per-prefix ledger and its companion version-marker table names.
    fn ledger_tables(prefix: &str) -> (String, String) {
        (
            format!("{prefix}_schema_migrations"),
            format!("{prefix}_schema_migrations_meta"),
        )
    }

    /// Create the ledger and the version-marker table, seeding the marker exactly
    /// once with [`LEDGER_VERSION`]. Mirrors the foundation Postgres shell so an
    /// IAM ledger is byte-identical to any other consumer's.
    fn ensure_ledger(client: &mut Client, prefix: &str) -> RepoResult<()> {
        let (ledger, meta) = Self::ledger_tables(prefix);
        client
            .batch_execute(&format!(
                "CREATE TABLE IF NOT EXISTS {ledger} (\
                 bundle_id TEXT NOT NULL, \
                 version BIGINT NOT NULL, \
                 checksum TEXT NOT NULL, \
                 description TEXT NOT NULL, \
                 applied_at TIMESTAMPTZ NOT NULL DEFAULT now(), \
                 applied_by TEXT NOT NULL, \
                 PRIMARY KEY (bundle_id, version))"
            ))
            .map_err(backend_err)?;
        client
            .batch_execute(&format!(
                "CREATE TABLE IF NOT EXISTS {meta} (ledger_version BIGINT NOT NULL)"
            ))
            .map_err(backend_err)?;
        client
            .execute(
                &format!(
                    "INSERT INTO {meta} (ledger_version) \
                     SELECT $1 WHERE NOT EXISTS (SELECT 1 FROM {meta})"
                ),
                &[&LEDGER_VERSION],
            )
            .map_err(backend_err)?;
        let found: i64 = client
            .query_one(&format!("SELECT ledger_version FROM {meta} LIMIT 1"), &[])
            .map_err(backend_err)?
            .get(0);
        check_ledger_version(&ledger, found).map_err(migration_err)
    }
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

    fn run_migrations(
        &mut self,
        prefix: &str,
        bundles: &[MigrationBundle],
    ) -> RepoResult<Vec<AppliedMigration>> {
        let dialect = Dialect::Postgres;
        let (ledger, _meta) = Self::ledger_tables(prefix);
        let mut client = self.client.lock().unwrap();
        Self::ensure_ledger(&mut client, prefix)?;

        let mut applied = Vec::new();
        for bundle in bundles {
            let mut tx = client.transaction().map_err(backend_err)?;
            // Transaction-scoped advisory lock keyed on the ledger and bundle id —
            // the single-applier guard (ADR-0003), released automatically at
            // commit/rollback. Held across the ledger read and the apply, it makes
            // exactly one node apply a pending bundle while the others wait, then
            // verify; a failed run never strands it.
            tx.execute(
                "SELECT pg_advisory_xact_lock(hashtext($1), hashtext($2))",
                &[&ledger, &bundle.bundle_id()],
            )
            .map_err(backend_err)?;

            let recorded = read_applied(&mut tx, &ledger, bundle.bundle_id())?;
            let pending = plan(bundle, &recorded, dialect).map_err(migration_err)?;
            for migration in pending {
                let sql = render_ddl(migration.sql_for(dialect), dialect, prefix);
                tx.batch_execute(&sql).map_err(backend_err)?;
                let checksum = migration.checksum_for(dialect);
                let description = migration.ledger_description();
                tx.execute(
                    &format!(
                        "INSERT INTO {ledger} \
                         (bundle_id, version, checksum, description, applied_by) \
                         VALUES ($1, $2, $3, $4, $5)"
                    ),
                    &[
                        &bundle.bundle_id(),
                        &migration.version(),
                        &checksum,
                        &description,
                        &"awaken-iam",
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
        let mut client = self.client.lock().unwrap();
        let rows = client
            .query(
                &format!(
                    "SELECT version, checksum FROM {ledger} \
                     WHERE bundle_id = $1 ORDER BY version"
                ),
                &[&bundle_id],
            )
            .map_err(backend_err)?;
        let mut applied = BTreeMap::new();
        for row in &rows {
            let version: i64 = row.try_get(0).map_err(backend_err)?;
            let checksum: String = row.try_get(1).map_err(backend_err)?;
            applied.insert(version, checksum);
        }
        Ok(applied)
    }
}

/// Read the recorded `(version -> checksum)` map for `bundle_id` inside an open
/// transaction, so the read and the subsequent apply share the advisory guard.
fn read_applied(
    tx: &mut postgres::Transaction<'_>,
    ledger: &str,
    bundle_id: &str,
) -> RepoResult<BTreeMap<i64, String>> {
    let rows = tx
        .query(
            &format!(
                "SELECT version, checksum FROM {ledger} \
                 WHERE bundle_id = $1 ORDER BY version"
            ),
            &[&bundle_id],
        )
        .map_err(backend_err)?;
    let mut applied = BTreeMap::new();
    for row in &rows {
        let version: i64 = row.try_get(0).map_err(backend_err)?;
        let checksum: String = row.try_get(1).map_err(backend_err)?;
        applied.insert(version, checksum);
    }
    Ok(applied)
}

#[cfg(test)]
mod tests {
    use super::render as render_placeholders;

    #[test]
    fn render_numbers_plain_and_json_placeholders_in_order() {
        let sql = "INSERT INTO t (a, b, c) VALUES (?, ?j, ?)";
        assert_eq!(
            render_placeholders(sql),
            "INSERT INTO t (a, b, c) VALUES ($1, $2::jsonb, $3)"
        );
    }

    #[test]
    fn render_casts_every_json_parameter_to_jsonb() {
        let sql = "UPDATE t SET a = ?j, b = ?j WHERE c = ?j AND d = ?";
        assert_eq!(
            render_placeholders(sql),
            "UPDATE t SET a = $1::jsonb, b = $2::jsonb WHERE c = $3::jsonb AND d = $4"
        );
    }
}
