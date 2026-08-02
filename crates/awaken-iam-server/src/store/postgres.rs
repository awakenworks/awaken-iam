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
    AppliedMigration, Dialect as MigrationDialect, LedgerBootstrapAction, LedgerSchema,
    MigrationBundle, MigrationError, check_ledger_version, plan, render as render_ddl,
};

use awaken_iam_core::{RepoError, RepoResult};

use super::migration::{Dialect, IamStore, MigrationExecutor, migration_err};
use super::sql::{SqlConn, SqlParam, SqlRow, SqlStore, SqlWrite};

/// A Postgres connection usable as both a migration executor and a repository
/// backend. Cheap to [`Clone`]: clones share one client.
#[derive(Clone)]
pub struct PostgresBackend {
    client: Arc<PlainThreadOwner<Mutex<Client>>>,
}

/// Own a value whose destructor may start its own async runtime.
///
/// The synchronous `postgres` client does exactly that. Its final `Arc` may be
/// released while an async host is unwinding, so the owner moves destruction
/// to a plain OS thread. This is the one lifecycle boundary for every
/// `PostgresBackend` clone; callers do not need a second wrapper.
struct PlainThreadOwner<T: Send + 'static> {
    value: Option<T>,
}

impl<T: Send + 'static> PlainThreadOwner<T> {
    fn new(value: T) -> Self {
        Self { value: Some(value) }
    }

    fn get(&self) -> &T {
        self.value
            .as_ref()
            .expect("Postgres owner remains live until final drop")
    }
}

impl<T: Send + 'static> Drop for PlainThreadOwner<T> {
    fn drop(&mut self) {
        let Some(value) = self.value.take() else {
            return;
        };
        std::thread::Builder::new()
            .name("awaken-iam-postgres-drop".to_owned())
            .spawn(move || drop(value))
            .expect("spawn PostgreSQL destructor thread")
            .join()
            .expect("PostgreSQL destructor thread panicked");
    }
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
            client: Arc::new(PlainThreadOwner::new(Mutex::new(client))),
        }
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, Client> {
        self.client
            .get()
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
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
/// `?` becomes `$n` and a JSON parameter `?j` becomes `$n::text::jsonb`.
///
/// The double cast is deliberate. Every [`SqlParam`] is bound as a Rust
/// `String`, whose driver `ToSql` only serializes to text-like types. A bare
/// `$n::jsonb` makes PostgreSQL infer the parameter's own type as `jsonb`
/// (the cast target propagates to the placeholder), and the driver then refuses
/// to serialize a `String` as `jsonb` — `error serializing parameter`. Casting
/// through text first (`$n::text::jsonb`) pins the *parameter* type to `text`,
/// which a `String` serializes to cleanly, and PostgreSQL casts the text to the
/// column's `jsonb` type server-side. SQLite has no jsonb type, so it collapses
/// `?j` back to a plain `?`; the two backends store the identical JSON text.
fn render(sql: &str) -> String {
    let mut out = String::with_capacity(sql.len() + 16);
    let mut next = 1usize;
    let bytes = sql.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'?' {
            if i + 1 < bytes.len() && bytes[i + 1] == b'j' {
                out.push_str(&format!("${next}::text::jsonb"));
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
    /// Bootstrap or validate the foundation-owned ledger generation while
    /// holding the namespace lock. IAM owns only the synchronous driver calls;
    /// names, DDL, and the state decision remain authoritative in foundation.
    fn ensure_ledger(client: &mut Client, prefix: &str) -> RepoResult<()> {
        let schema = LedgerSchema::with_prefix(prefix).map_err(migration_err)?;
        let mut tx = client.transaction().map_err(backend_err)?;
        tx.execute(
            "SELECT pg_advisory_xact_lock(hashtext($1), hashtext($2))",
            &[&schema.ledger_table(), &"ledger-bootstrap-v1"],
        )
        .map_err(backend_err)?;
        let presence = tx
            .query_one(
                "SELECT to_regclass($1) IS NOT NULL, to_regclass($2) IS NOT NULL",
                &[&schema.ledger_table(), &schema.meta_table()],
            )
            .map_err(backend_err)?;
        let action = schema
            .bootstrap_action(presence.get(0), presence.get(1))
            .map_err(migration_err)?;
        if action == LedgerBootstrapAction::Create {
            for statement in schema.create_statements(MigrationDialect::Postgres) {
                tx.batch_execute(&statement).map_err(backend_err)?;
            }
        }
        let rows = tx
            .query(
                &format!("SELECT ledger_version FROM {}", schema.meta_table()),
                &[],
            )
            .map_err(backend_err)?;
        if rows.len() != 1 {
            return Err(migration_err(MigrationError::LedgerMetadataRowCount {
                meta_table: schema.meta_table().to_string(),
                found: rows.len(),
            }));
        }
        let found: i64 = rows[0].get(0);
        check_ledger_version(schema.ledger_table(), found).map_err(migration_err)?;
        tx.commit().map_err(backend_err)
    }
}

impl SqlConn for PostgresBackend {
    fn dialect(&self) -> Dialect {
        Dialect::Postgres
    }

    fn execute(&self, sql: &str, params: &[SqlParam]) -> RepoResult<u64> {
        let mut client = self.lock();
        client
            .execute(&render(sql), &refs(params))
            .map_err(backend_err)
    }

    fn query(&self, sql: &str, params: &[SqlParam]) -> RepoResult<Vec<SqlRow>> {
        let mut client = self.lock();
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

    fn execute_transaction(&self, writes: &[SqlWrite]) -> RepoResult<Vec<u64>> {
        let mut client = self.lock();
        let mut tx = client.transaction().map_err(backend_err)?;
        let mut affected = Vec::with_capacity(writes.len());
        for write in writes {
            affected.push(
                tx.execute(&render(&write.sql), &refs(&write.params))
                    .map_err(backend_err)?,
            );
        }
        tx.commit().map_err(backend_err)?;
        Ok(affected)
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
        let schema = LedgerSchema::with_prefix(prefix).map_err(migration_err)?;
        let ledger = schema.ledger_table();
        let mut client = self.lock();
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

            let recorded = read_applied(&mut tx, ledger, bundle.bundle_id())?;
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
        let schema = LedgerSchema::with_prefix(prefix).map_err(migration_err)?;
        let ledger = schema.ledger_table();
        let mut client = self.lock();
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
    use super::{PlainThreadOwner, render as render_placeholders};

    #[tokio::test(flavor = "current_thread")]
    async fn runtime_owning_client_is_destroyed_outside_async_host() {
        // Cause-effect graph: C1=the final shared backend owner is released,
        // C2=the caller is inside an entered Tokio runtime, C3=the owned
        // synchronous client starts its private runtime during Drop. Effects:
        // E1=Drop runs on a distinct plain thread; E2=no nested-runtime panic.
        // Decision rule R1(C1+C2+C3)->E1+E2. Non-final Arc releases and a
        // non-runtime caller cannot create the failure and need no extra path.
        struct RuntimeOwningValue(std::sync::mpsc::Sender<std::thread::ThreadId>);

        impl Drop for RuntimeOwningValue {
            fn drop(&mut self) {
                let _ = self.0.send(std::thread::current().id());
                tokio::runtime::Builder::new_current_thread()
                    .build()
                    .expect("private client runtime")
                    .block_on(async {});
            }
        }

        let caller = std::thread::current().id();
        let (sender, receiver) = std::sync::mpsc::channel();
        let owner = std::sync::Arc::new(PlainThreadOwner::new(RuntimeOwningValue(sender)));
        let clone = std::sync::Arc::clone(&owner);
        drop(owner);
        drop(clone);

        assert_ne!(receiver.recv().expect("destructor thread id"), caller);
    }

    #[test]
    fn render_numbers_plain_and_json_placeholders_in_order() {
        let sql = "INSERT INTO t (a, b, c) VALUES (?, ?j, ?)";
        assert_eq!(
            render_placeholders(sql),
            "INSERT INTO t (a, b, c) VALUES ($1, $2::text::jsonb, $3)"
        );
    }

    #[test]
    fn render_casts_every_json_parameter_through_text_to_jsonb() {
        let sql = "UPDATE t SET a = ?j, b = ?j WHERE c = ?j AND d = ?";
        assert_eq!(
            render_placeholders(sql),
            "UPDATE t SET a = $1::text::jsonb, b = $2::text::jsonb \
             WHERE c = $3::text::jsonb AND d = $4"
        );
    }
}
