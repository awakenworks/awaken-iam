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
//! The client is `!Sync`. A caller-supplied client lives behind a [`Mutex`]; the
//! production constructor builds one checked `r2d2_postgres` slot. Clones share
//! that owner. An operation that observes transport loss fails closed and is
//! never replayed; a later checkout replaces the broken client.

use std::collections::BTreeMap;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use postgres::Client;
use postgres::error::SqlState;
use postgres::types::ToSql;
use postgres_native_tls::MakeTlsConnector;
use r2d2_postgres::PostgresConnectionManager;

use awaken_scoped_migration::{
    AppliedMigration, Dialect as MigrationDialect, LedgerBootstrapAction, LedgerSchema,
    MigrationBundle, MigrationError, check_ledger_version, plan, render as render_ddl,
};

use awaken_iam_core::{RepositoryError, RepositoryResult};

use super::migration::{Dialect, IamStore, MigrationExecutor, migration_err};
use super::sql::{SqlConn, SqlParam, SqlRow, SqlStore, SqlTransaction};

/// Execute a synchronous-driver operation without an entered Tokio runtime.
///
/// The `postgres` client owns a private runtime. Repository repository contracts remain
/// synchronous, so an Axum host cannot safely call the driver on its Tokio
/// worker. A scoped thread preserves the synchronous port and borrowed inputs
/// while keeping runtime ownership inside this adapter. Existing plain-thread
/// callers retain the allocation-free direct path.
fn run_outside_tokio<T: Send>(component: &'static str, operation: impl FnOnce() -> T + Send) -> T {
    if tokio::runtime::Handle::try_current().is_err() {
        return operation();
    }
    std::thread::scope(|scope| {
        let handle = std::thread::Builder::new()
            .name(format!("awaken-iam-postgres-{component}"))
            .spawn_scoped(scope, operation)
            .expect("spawn PostgreSQL operation thread");
        match handle.join() {
            Ok(result) => result,
            Err(payload) => std::panic::resume_unwind(payload),
        }
    })
}

/// A Postgres connection usable as both a migration executor and a repository
/// backend. Cheap to [`Clone`]: clones share one connection owner.
#[derive(Clone)]
pub struct PostgresBackend {
    client: Arc<PlainThreadOwner<ConnectionOwner>>,
}

type PostgresPool = r2d2::Pool<PostgresConnectionManager<MakeTlsConnector>>;

enum ConnectionOwner {
    Direct(Box<Mutex<Client>>),
    Reconnecting(PostgresPool),
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
    ///
    /// This compatibility constructor has no connection parameters with which
    /// to replace a disconnected client. Production hosts should use
    /// [`Self::connect`] to get checked replacement after transport loss.
    pub fn new(client: Client) -> Self {
        Self {
            client: Arc::new(PlainThreadOwner::new(ConnectionOwner::Direct(Box::new(
                Mutex::new(client),
            )))),
        }
    }

    fn with_client<T: Send>(
        &self,
        component: &'static str,
        operation: impl FnOnce(&mut Client) -> RepositoryResult<T> + Send,
    ) -> RepositoryResult<T> {
        run_outside_tokio(component, || match self.client.get() {
            ConnectionOwner::Direct(client) => {
                let mut client = client.lock().map_err(|_| {
                    RepositoryError::Backend("Postgres connection lock is poisoned".into())
                })?;
                operation(&mut client)
            }
            ConnectionOwner::Reconnecting(pool) => {
                let mut client = pool.get().map_err(pool_err)?;
                // Invoke the repository operation exactly once. r2d2 validates
                // before checkout and discards a client that becomes broken,
                // but it never replays SQL after an operation error: COMMIT may
                // have reached Postgres even when its response was lost.
                operation(&mut client)
            }
        })
    }

    /// Connect to Postgres using a libpq-style connection string or URL.
    pub fn connect(params: &str) -> RepositoryResult<Self> {
        let tls = native_tls::TlsConnector::new()
            .map_err(|error| RepositoryError::Backend(error.to_string()))?;
        Self::connect_with_tls(params, MakeTlsConnector::new(tls))
    }

    /// Use the embedding binary's verified TLS policy with the original slot.
    /// Private CA selection belongs to that binary. This constructor adds no
    /// SQL replay, pool, runtime or client-lifetime authority.
    pub fn connect_with_tls(params: &str, tls: MakeTlsConnector) -> RepositoryResult<Self> {
        let config = params
            .parse()
            .map_err(|error: postgres::Error| RepositoryError::Backend(error.to_string()))?;
        let manager = PostgresConnectionManager::new(config, tls);
        let pool = run_outside_tokio("connect", || {
            r2d2::Pool::builder()
                // Preserve the existing one-client serialization and advisory
                // transaction semantics while adding checked replacement.
                .max_size(1)
                .min_idle(Some(1))
                .test_on_check_out(true)
                .connection_timeout(Duration::from_secs(5))
                .build(manager)
        })
        .map_err(pool_err)?;
        Ok(Self {
            client: Arc::new(PlainThreadOwner::new(ConnectionOwner::Reconnecting(pool))),
        })
    }
}

/// Connect, run every IAM migration under `prefix`, and return the repository
/// adapter over the connection.
pub fn migrated_store(params: &str, prefix: &str) -> RepositoryResult<SqlStore<PostgresBackend>> {
    let backend = PostgresBackend::connect(params)?;
    IamStore::with_prefix(backend.clone(), prefix)?.migrate()?;
    SqlStore::with_prefix(backend, prefix)
}

fn backend_err(err: postgres::Error) -> RepositoryError {
    if let Some(db) = err.as_db_error()
        && db.code() == &SqlState::UNIQUE_VIOLATION
    {
        return RepositoryError::Conflict(db.message().to_owned());
    }
    RepositoryError::Backend(err.to_string())
}

fn pool_err(err: r2d2::Error) -> RepositoryError {
    RepositoryError::Backend(err.to_string())
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
    fn ensure_ledger(client: &mut Client, prefix: &str) -> RepositoryResult<()> {
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

    fn execute(&self, sql: &str, params: &[SqlParam]) -> RepositoryResult<u64> {
        self.with_client("execute", |client| {
            client
                .execute(&render(sql), &refs(params))
                .map_err(backend_err)
        })
    }

    fn query(&self, sql: &str, params: &[SqlParam]) -> RepositoryResult<Vec<SqlRow>> {
        self.with_client("query", |client| {
            sql_rows(
                client
                    .query(&render(sql), &refs(params))
                    .map_err(backend_err)?,
            )
        })
    }

    fn with_transaction(
        &self,
        operation: &mut (dyn FnMut(&mut dyn SqlTransaction) -> RepositoryResult<()> + Send),
    ) -> RepositoryResult<()> {
        self.with_client("transaction", |client| {
            let mut transaction = client.transaction().map_err(backend_err)?;
            operation(&mut transaction)?;
            transaction.commit().map_err(backend_err)
        })
    }
}

impl SqlTransaction for postgres::Transaction<'_> {
    fn execute(&mut self, sql: &str, params: &[SqlParam]) -> RepositoryResult<u64> {
        postgres::Transaction::execute(self, &render(sql), &refs(params)).map_err(backend_err)
    }

    fn query(&mut self, sql: &str, params: &[SqlParam]) -> RepositoryResult<Vec<SqlRow>> {
        sql_rows(
            postgres::Transaction::query(self, &render(sql), &refs(params)).map_err(backend_err)?,
        )
    }
}

fn sql_rows(rows: Vec<postgres::Row>) -> RepositoryResult<Vec<SqlRow>> {
    let mut output = Vec::with_capacity(rows.len());
    for row in rows {
        let mut cells = Vec::with_capacity(row.len());
        for index in 0..row.len() {
            cells.push(
                row.try_get::<usize, Option<String>>(index)
                    .map_err(backend_err)?,
            );
        }
        output.push(cells);
    }
    Ok(output)
}

impl MigrationExecutor for PostgresBackend {
    fn dialect(&self) -> Dialect {
        Dialect::Postgres
    }

    fn run_migrations(
        &mut self,
        prefix: &str,
        bundles: &[MigrationBundle],
    ) -> RepositoryResult<Vec<AppliedMigration>> {
        let dialect = Dialect::Postgres;
        let schema = LedgerSchema::with_prefix(prefix).map_err(migration_err)?;
        let ledger = schema.ledger_table();
        self.with_client("migrate", |client| {
            Self::ensure_ledger(client, prefix)?;

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
                let bridge = super::migration_compatibility::atomic_v8_bridge(
                    bundle, &recorded, prefix, dialect,
                )?;
                if let Some(bridge) = &bridge {
                    for sql in &bridge.before {
                        tx.batch_execute(sql).map_err(backend_err)?;
                    }
                }
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
                if let Some(bridge) = &bridge {
                    for sql in &bridge.after {
                        tx.batch_execute(sql).map_err(backend_err)?;
                    }
                }
                tx.commit().map_err(backend_err)?;
            }
            Ok(applied)
        })
    }

    fn applied_versions(
        &self,
        prefix: &str,
        bundle_id: &str,
    ) -> RepositoryResult<BTreeMap<i64, String>> {
        let schema = LedgerSchema::with_prefix(prefix).map_err(migration_err)?;
        let ledger = schema.ledger_table();
        self.with_client("migration-read", |client| {
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
        })
    }
}

/// Read the recorded `(version -> checksum)` map for `bundle_id` inside an open
/// transaction, so the read and the subsequent apply share the advisory guard.
fn read_applied(
    tx: &mut postgres::Transaction<'_>,
    ledger: &str,
    bundle_id: &str,
) -> RepositoryResult<BTreeMap<i64, String>> {
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
    use super::{PlainThreadOwner, render as render_placeholders, run_outside_tokio};

    #[tokio::test(flavor = "current_thread")]
    async fn synchronous_driver_operation_runs_outside_async_host() {
        // Cause/effect graph: C1=an entered Tokio runtime, C2=a synchronous
        // driver operation enters its own private runtime. E1=the adapter uses
        // a distinct scoped thread; E2=the nested runtime completes; E3=the
        // exact result returns to the caller.
        //
        // Decision table: C1+C2 -> E1+E2+E3; !C1+C2 -> direct completion;
        // C1+C2 with a direct call -> forbidden nested-runtime panic. Backend
        // errors use the same chosen boundary and are covered by repository
        // contract tests.
        let caller = std::thread::current().id();
        let (operation, value) = run_outside_tokio("test", || {
            let runtime = tokio::runtime::Builder::new_current_thread()
                .build()
                .expect("private client runtime");
            (
                std::thread::current().id(),
                runtime.block_on(async { 42_u8 }),
            )
        });

        assert_ne!(operation, caller);
        assert_eq!(value, 42);
    }

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
    #[ignore = "requires IAM_TEST_POSTGRES_TLS_URL and IAM_TEST_POSTGRES_CA_CERT"]
    fn verified_tls_reuses_the_original_slot_without_replaying_an_interrupted_write() {
        // Causes: C1 TLS-required endpoint; C2 trusted/untrusted root;
        // C3 matching/wrong peer name; C4 original socket is terminated.
        // Effects: E1 no usable client on trust/identity refusal; E2 a verified
        // encrypted shared slot; E3 later checkout replaces the same slot;
        // E4 an interrupted SQL write has at most one effect, never replay.
        // T1=C1+!C2=>E1; T2=C1+C2+!C3=>E1; T3=C1+C2+C3=>E2;
        // T4=T3+C4=>E3+E4. This opt-in case fails on missing fixture inputs;
        // ordinary plaintext fixtures do not count as TLS evidence.
        use super::{PostgresBackend, SqlConn, backend_err};
        use postgres::config::SslMode;
        use postgres_native_tls::MakeTlsConnector;
        let url = std::env::var("IAM_TEST_POSTGRES_TLS_URL").expect("TLS URL");
        let ca = std::env::var("IAM_TEST_POSTGRES_CA_CERT").expect("private CA path");
        assert_eq!(
            url.parse::<postgres::Config>().unwrap().get_ssl_mode(),
            SslMode::Require,
            "C1"
        );
        let tls = |trusted: bool| {
            let mut builder = native_tls::TlsConnector::builder();
            builder.disable_built_in_roots(true);
            if trusted {
                builder.add_root_certificate(
                    native_tls::Certificate::from_pem(&std::fs::read(&ca).unwrap()).unwrap(),
                );
            }
            MakeTlsConnector::new(builder.build().unwrap())
        };
        assert!(
            PostgresBackend::connect_with_tls(&url, tls(false)).is_err(),
            "T1"
        );
        let mut wrong_peer = url::Url::parse(&url).unwrap();
        wrong_peer.set_host(Some("wrong-peer.invalid")).unwrap();
        wrong_peer
            .query_pairs_mut()
            .append_pair("hostaddr", "127.0.0.1");
        wrong_peer
            .as_str()
            .parse::<postgres::Config>()
            .expect("hostaddr keeps the TCP endpoint while changing TLS peer identity");
        assert!(
            PostgresBackend::connect_with_tls(wrong_peer.as_str(), tls(true)).is_err(),
            "T2"
        );
        let backend = PostgresBackend::connect_with_tls(&url, tls(true)).expect("T3");
        let clone = backend.clone();
        let observe = |store: &PostgresBackend| {
            store.with_client("tls-proof", |client| {
            let row = client.query_one("SELECT pg_backend_pid(), (SELECT ssl FROM pg_stat_ssl WHERE pid=pg_backend_pid())", &[]).map_err(backend_err)?;
            Ok((row.get::<_, i32>(0), row.get::<_, bool>(1)))
        })
        };
        let (original, encrypted) = observe(&backend).unwrap();
        assert!(encrypted, "T3 actual server-side TLS");
        assert_eq!(observe(&clone).unwrap(), (original, true), "T3 one slot");
        let mut admin = url
            .parse::<postgres::Config>()
            .unwrap()
            .connect(tls(true))
            .unwrap();
        let table = format!("iam_tls_reconnect_{}", std::process::id());
        admin
            .batch_execute(&format!("CREATE TABLE {table} (value BIGINT NOT NULL)"))
            .unwrap();
        assert!(
            admin
                .query_one("SELECT pg_terminate_backend($1)", &[&original])
                .unwrap()
                .get::<_, bool>(0)
        );
        let _write_result = backend.execute(&format!("INSERT INTO {table} VALUES (1)"), &[]);
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
        let replacement = loop {
            if let Ok(value) = observe(&clone) {
                break value;
            }
            assert!(
                std::time::Instant::now() < deadline,
                "T4 replacement deadline"
            );
            std::thread::sleep(std::time::Duration::from_millis(25));
        };
        assert_ne!(replacement.0, original, "T4 new connection");
        assert!(replacement.1, "T4 replacement still verifies/encrypts");
        assert_eq!(
            observe(&backend).unwrap(),
            replacement,
            "T4 all clones share it"
        );
        let effects: i64 = admin
            .query_one(&format!("SELECT count(*) FROM {table}"), &[])
            .unwrap()
            .get(0);
        assert!(effects <= 1, "T4 interrupted SQL is never replayed");
        admin.batch_execute(&format!("DROP TABLE {table}")).unwrap();

        // T5 uses this SAME real TLS fixture with the original direct-client
        // constructor. Poison must refuse execute/query/transaction without
        // running a callback; recovering the client would pass SELECT 1 and
        // violate this row. No fake Client or replacement manager is introduced.
        let direct = PostgresBackend::new(postgres::Client::connect(&url, tls(true)).unwrap());
        let poisoned = direct.clone();
        assert!(
            std::thread::spawn(move || {
                if let super::ConnectionOwner::Direct(slot) = poisoned.client.get() {
                    let _guard = slot.lock().unwrap();
                    panic!("injected direct PostgreSQL client poison");
                }
            })
            .join()
            .is_err()
        );
        assert!(matches!(
            direct.execute("SET application_name = 'poison-must-not-run'", &[]),
            Err(awaken_iam_core::RepositoryError::Backend(_))
        ));
        assert!(matches!(
            direct.query("SELECT 1", &[]),
            Err(awaken_iam_core::RepositoryError::Backend(_))
        ));
        let mut called = false;
        assert!(matches!(
            direct.with_transaction(&mut |_| {
                called = true;
                Ok(())
            }),
            Err(awaken_iam_core::RepositoryError::Backend(_))
        ));
        assert!(!called);
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
