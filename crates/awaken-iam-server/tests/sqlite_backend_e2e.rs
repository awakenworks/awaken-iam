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

use awaken_iam_contract::{
    AcceptInvitation, AccountId, CreateInvitation, InvitationBinding, InvitationStatus, OrgId,
    PrincipalRef, ScopeRef, Timestamp,
};
use awaken_iam_core::{ActionPattern, Organization, RepoError, RoleDef, RoleId};
use awaken_iam_server::{
    Dialect, MigrationExecutor, PolicyAdminApi, SqlConn, SqliteBackend, bundles,
    sqlite_migrated_store,
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

#[test]
fn sqlite_invitation_acceptance_is_atomic_and_restart_visible() {
    // Cause/effect decision table: R1 pending+matching token+matching verified
    // email -> one transaction changes invitation to Accepted and inserts all
    // role bindings; R2 a new PAP over the same database -> both invitation and
    // binding remain visible. An implementation that commits either half alone
    // fails one of the paired restart assertions.
    let backend = SqliteBackend::open_in_memory().expect("open");
    let store = sqlite_migrated_store(backend, "iam").expect("migrate");
    let now = Timestamp("2026-08-02T00:00:00Z".into());
    let principal = PrincipalRef::Account {
        account_id: AccountId("owner".into()),
    };
    let mut pap = PolicyAdminApi::new(store.clone());
    pap.create_org(
        Organization {
            id: OrgId("acme".into()),
            display_name: None,
            owner: principal.clone(),
            created_at: now.clone(),
            updated_at: now.clone(),
        },
        now.clone(),
    )
    .unwrap();
    pap.define_role(
        RoleDef {
            id: RoleId("member".into()),
            display_name: None,
            action_patterns: vec![ActionPattern("workspace.read".into())],
            created_at: now.clone(),
            updated_at: now.clone(),
        },
        now.clone(),
    )
    .unwrap();
    let issued = pap
        .create_invitation(
            CreateInvitation {
                idempotency_key: "sqlite-restart".into(),
                org_id: OrgId("acme".into()),
                email: "member@example.com".into(),
                bindings: vec![InvitationBinding {
                    role_id: "member".into(),
                    scope: ScopeRef::Org {
                        org_id: OrgId("acme".into()),
                    },
                }],
                invited_by: principal,
                expires_at: Timestamp("2026-08-03T00:00:00Z".into()),
            },
            now.clone(),
        )
        .unwrap();
    pap.accept_invitation(
        &issued.invitation.id,
        AcceptInvitation {
            account_id: AccountId("member".into()),
            verified_email: "member@example.com".into(),
            token: issued.token,
        },
        now,
    )
    .unwrap();
    drop(pap);

    let restarted = PolicyAdminApi::new(store);
    let invitations = restarted.list_invitations(&OrgId("acme".into())).unwrap();
    assert_eq!(invitations[0].status, InvitationStatus::Accepted);
    assert_eq!(
        restarted
            .memberships_for_principal(&PrincipalRef::Account {
                account_id: AccountId("member".into()),
            })
            .unwrap()
            .len(),
        1,
    );
}
