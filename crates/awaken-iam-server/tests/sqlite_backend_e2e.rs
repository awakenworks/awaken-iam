//! End-to-end coverage of the SQLite backend adapter's dialect negotiation,
//! ledger ledger-queries, and the non-constraint backend-error branch.
//!
//! The SqlConn and MigrationExecutor traits each expose a `dialect()` method
//! the foundation planner uses to render DDL; both must return `Dialect::Sqlite`
//! so the portable placeholder dialect is rewritten to SQLite's native form.
//! `applied_versions` reads the per-bundle ledger after migrations land; the
//! returned `(version -> checksum)` map is what `plan()` verifies against.
//! `backend_err`'s non-constraint branch surfaces a malformed-SQL backend
//! error, not a domain conflict.

use std::collections::BTreeMap;

use awaken_iam_core::RepoError;
use awaken_iam_server::{
    Dialect, MigrationExecutor, SqlConn, SqliteBackend, bundles, sqlite_migrated_store,
};

#[test]
fn sqlite_backend_dialect_is_reported_by_both_traits() {
    let backend = SqliteBackend::open_in_memory().expect("open");
    // Both SqlConn and MigrationExecutor are implemented for SqliteBackend
    // and must report the same dialect so the planner's DDL rendering
    // matches the driver's expectation.
    let conn: &dyn SqlConn = &backend;
    assert_eq!(conn.dialect(), Dialect::Sqlite);
    let exec: &dyn MigrationExecutor = &backend;
    assert_eq!(exec.dialect(), Dialect::Sqlite);
}

#[test]
fn sqlite_backend_debug_impl_does_not_panic() {
    // The Debug impl deliberately does not expose the inner connection;
    // this guarantees it never deadlocks on the Mutex if anything ever
    // debug-prints a backend while a migration is mid-transaction.
    let backend = SqliteBackend::open_in_memory().expect("open");
    let debug = format!("{backend:?}");
    assert!(debug.contains("SqliteBackend"));
}

#[test]
fn sqlite_backend_applied_versions_returns_empty_ledger_after_run_migrations() {
    // After the canonical bundles run, each bundle's ledger has at least one
    // applied step. An unrecognised bundle id (no migrations ever applied)
    // returns an empty map without error.
    let mut backend = SqliteBackend::open_in_memory().expect("open");
    backend.run_migrations("iam", &bundles()).expect("migrate");
    let exec: &dyn MigrationExecutor = &backend;
    let applied = exec
        .applied_versions("iam", "iam.unrecognised")
        .expect("applied versions");
    assert!(applied.is_empty());
}

#[test]
fn sqlite_backend_applied_versions_reports_each_step_after_running_migrations() {
    // Run the canonical bundles through the SQLite executor and read back
    // the per-bundle ledger: each applied step must show up with the right
    // version and a non-empty checksum.
    let mut backend = SqliteBackend::open_in_memory().expect("open");
    let applied = backend.run_migrations("iam", &bundles()).expect("migrate");
    assert!(
        !applied.is_empty(),
        "the canonical bundle set must apply at least one migration"
    );
    // Group applied steps by bundle for the assertions below.
    let mut by_bundle: BTreeMap<String, Vec<i64>> = BTreeMap::new();
    for step in &applied {
        by_bundle
            .entry(step.bundle_id.clone())
            .or_default()
            .push(step.version);
    }
    for (bundle_id, mut versions) in by_bundle {
        versions.sort_unstable();
        // Versions are monotonically increasing within a bundle.
        for window in versions.windows(2) {
            assert!(window[1] > window[0], "versions must be monotonic");
        }

        // applied_versions agrees with what run_migrations reported.
        let exec: &dyn MigrationExecutor = &backend;
        let ledger = exec
            .applied_versions("iam", &bundle_id)
            .expect("read ledger");
        assert_eq!(ledger.len(), versions.len());
        for v in versions {
            assert!(ledger.contains_key(&v));
            assert!(!ledger[&v].is_empty());
        }
    }
}

#[test]
fn sqlite_backend_query_reports_a_malformed_sql_as_backend_error() {
    // The non-constraint branch of `backend_err`: a SQL syntax error or
    // malformed statement must surface as `RepoError::Backend`, not as a
    // domain `Conflict`. This is the path a deployment hits when its
    // migration rolls forward but a downstream query is malformed.
    let backend = SqliteBackend::open_in_memory().expect("open");
    let conn: &dyn SqlConn = &backend;
    let err = conn
        .execute("THIS IS NOT VALID SQL", &[])
        .expect_err("malformed SQL must error");
    assert!(
        matches!(err, RepoError::Backend(_)),
        "non-constraint errors must be RepoError::Backend, got {err:?}"
    );
}

#[test]
fn sqlite_backend_query_returns_rows_in_select_order() {
    // The shared `SqlConn::query` shape is one nullable string per selected
    // column, in select order. Exercise it against a real SELECT and verify
    // the column order is preserved end-to-end.
    let backend = SqliteBackend::open_in_memory().expect("open");
    let conn: &dyn SqlConn = &backend;
    // Set up a tiny table the query can read from.
    conn.execute(
        "CREATE TABLE t (a TEXT NOT NULL, b TEXT NOT NULL, c TEXT)",
        &[],
    )
    .expect("create");
    conn.execute(
        "INSERT INTO t (a, b, c) VALUES (?1, ?2, ?3)",
        &[Some("1".into()), Some("x".into()), Some("42".into())],
    )
    .expect("insert");
    let rows = conn
        .query("SELECT c, a, b FROM t ORDER BY a", &[])
        .expect("query");
    assert_eq!(rows.len(), 1);
    assert_eq!(
        rows[0],
        vec![Some("42".into()), Some("1".into()), Some("x".into())]
    );
}

#[test]
fn sqlite_backend_with_prefix_validates_the_identifier_in_sqlite_migrated_store() {
    // `sqlite_migrated_store` validates the prefix the same way
    // `SqlStore::with_prefix` does: a value with hyphens or spaces is
    // rejected before any DDL is rendered.
    let backend = SqliteBackend::open_in_memory().expect("open");
    let bad = sqlite_migrated_store(backend.clone(), "iam-bad");
    assert!(matches!(bad, Err(RepoError::Backend(_))));
    let good = sqlite_migrated_store(backend, "iam");
    assert!(good.is_ok());
}
