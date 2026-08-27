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
    AcceptInvitation, AccountId, ApiToken, ApiTokenId, ApiTokenPrefix, CreateInvitation,
    EnsureProductSpacePlacement, InvitationBinding, InvitationStatus, OrgId, PrincipalRef,
    ProductSpaceRef, ResourceId, ResourceType, ScopeRef, Timestamp, WorkspaceId, WorkspaceOrgEdge,
};
use awaken_iam_core::{
    ActionPattern, ApiTokenRepository, Grant, GrantId, GrantRepository, GrantSubject, Organization,
    RepositoryError, ResourceEdge, ResourceModelRepository, RoleBinding, RoleBindingRepository,
    RoleDef, RoleId,
};
use awaken_iam_server::{
    Dialect, DirectoryApi, MigrationExecutor, PolicyAdminApi, SqlConn, SqliteBackend, bundles,
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
    // malformed statement must surface as `RepositoryError::Backend`, not as a
    // domain `Conflict`. This is the path a deployment hits when its
    // migration rolls forward but a downstream query is malformed.
    let backend = SqliteBackend::open_in_memory().expect("open");
    let conn: &dyn SqlConn = &backend;
    let err = conn
        .execute("THIS IS NOT VALID SQL", &[])
        .expect_err("malformed SQL must error");
    assert!(
        matches!(err, RepositoryError::Backend(_)),
        "non-constraint errors must be RepositoryError::Backend, got {err:?}"
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
    assert!(matches!(bad, Err(RepositoryError::Backend(_))));
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

#[test]
fn sqlite_organization_privacy_command_erases_scope_closure_and_is_idempotent() {
    // Cause/effect decision table:
    // C1 existing Org with Workspace, descendant Resource, grant, membership
    // Directory placement and Workspace token -> E1 one DELETE command removes the
    // complete IAM-owned closure in one SQL write transaction and advances the
    // PAP fence once; C2 foreign Org state -> E2 retained; C3 exact retry -> E3
    // success with no write and no additional fence advance.
    let backend = SqliteBackend::open_in_memory().expect("open");
    let store = sqlite_migrated_store(backend, "iam").expect("migrate");
    let now = Timestamp("2026-08-02T00:00:00Z".into());
    let principal = PrincipalRef::Account {
        account_id: AccountId("owner".into()),
    };
    let mut pap = PolicyAdminApi::new(store.clone());
    let directory = DirectoryApi::new(store.clone());
    for org in ["org-a", "org-b"] {
        pap.create_org(
            Organization {
                id: OrgId(org.into()),
                display_name: None,
                owner: principal.clone(),
                created_at: now.clone(),
                updated_at: now.clone(),
            },
            now.clone(),
        )
        .unwrap();
    }
    let mut org_a_node = None;
    for suffix in ["a", "b"] {
        let org_id = OrgId(format!("org-{suffix}"));
        let ensured = directory
            .ensure_product_space_placement(
                EnsureProductSpacePlacement {
                    product_space: ProductSpaceRef {
                        product_id: awaken_iam_contract::ProductId::new("agents").unwrap(),
                        space_id: format!("workspace/space-{suffix}"),
                    },
                    org_id,
                    parent_product_space: None,
                    name: format!("Root {suffix}"),
                    preferred_slug: format!("root-{suffix}"),
                    description: None,
                },
                awaken_iam_server::DirectoryCommandContext::new(principal.clone(), now.clone()),
            )
            .unwrap();
        if suffix == "a" {
            org_a_node = Some(ensured.node.id);
        }
    }
    for (workspace, org) in [("ws-a", "org-a"), ("ws-b", "org-b")] {
        pap.assign_workspace_org(
            WorkspaceOrgEdge {
                workspace_id: WorkspaceId(workspace.into()),
                org_id: OrgId(org.into()),
            },
            now.clone(),
        )
        .unwrap();
    }
    let resource = ResourceEdge {
        resource_type: ResourceType("issue".into()),
        resource_id: ResourceId("owned".into()),
        parent: ScopeRef::Workspace {
            workspace_id: WorkspaceId("ws-a".into()),
        },
    };
    ResourceModelRepository::put_edge(&store, resource.clone()).unwrap();
    GrantRepository::put(
        &store,
        Grant {
            id: GrantId("grant-a".into()),
            subject: GrantSubject::Principal(principal.clone()),
            action_pattern: ActionPattern("issue.read".into()),
            scope: ScopeRef::Resource {
                resource_type: resource.resource_type,
                resource_id: resource.resource_id,
            },
            effect: awaken_iam_core::Effect::Allow,
        },
    )
    .unwrap();
    RoleBindingRepository::add(
        &store,
        RoleBinding {
            principal: principal.clone(),
            role: RoleId("member".into()),
            scope: ScopeRef::Workspace {
                workspace_id: WorkspaceId("ws-a".into()),
            },
        },
    )
    .unwrap();
    for (id, workspace) in [("token-a", "ws-a"), ("token-b", "ws-b")] {
        ApiTokenRepository::create(
            &store,
            ApiToken {
                id: ApiTokenId(id.into()),
                prefix: ApiTokenPrefix(format!("prefix-{id}")),
                principal: principal.clone(),
                secret_hash: "hash".into(),
                workspace: WorkspaceId(workspace.into()),
                created_at: now.clone(),
                expires_at: None,
                revoked_at: None,
            },
        )
        .unwrap();
    }

    let deleted_version = pap.delete_org(&OrgId("org-a".into()), now.clone()).unwrap();
    assert_eq!(
        pap.delete_org(&OrgId("org-a".into()), now).unwrap(),
        deleted_version
    );
    assert!(pap.get_org(&OrgId("org-a".into())).unwrap().is_none());
    assert!(pap.get_org(&OrgId("org-b".into())).unwrap().is_some());
    assert!(
        directory
            .node(&org_a_node.expect("org-a placement node"))
            .unwrap()
            .is_none()
    );
    assert!(
        directory
            .product_space_placement(
                &OrgId("org-b".into()),
                &ProductSpaceRef {
                    product_id: awaken_iam_contract::ProductId::new("agents").unwrap(),
                    space_id: "workspace/space-b".into(),
                }
            )
            .unwrap()
            .is_some()
    );
    assert!(GrantRepository::list(&store).unwrap().is_empty());
    assert!(RoleBindingRepository::list(&store).unwrap().is_empty());
    assert!(
        ResourceModelRepository::list_edges(&store)
            .unwrap()
            .is_empty()
    );
    assert!(
        ApiTokenRepository::get(&store, &ApiTokenId("token-a".into()))
            .unwrap()
            .is_none()
    );
    assert!(
        ApiTokenRepository::get(&store, &ApiTokenId("token-b".into()))
            .unwrap()
            .is_some()
    );
}

#[test]
fn sqlite_scoped_role_change_is_atomic_and_restart_visible() {
    // Causes/effects: two incumbent managed bindings at the exact scope plus
    // one unrelated binding -> one replacement transaction; after restart the
    // replacement is the only managed binding and the unrelated binding
    // remains. This covers the SQL adapter's delete+insert transaction, not a
    // sequential PAP fallback.
    let backend = SqliteBackend::open_in_memory().expect("open");
    let store = sqlite_migrated_store(backend, "iam").expect("migrate");
    let now = Timestamp("2026-08-15T00:00:00Z".into());
    let principal = PrincipalRef::Account {
        account_id: AccountId("member".into()),
    };
    let scope = ScopeRef::Workspace {
        workspace_id: awaken_iam_contract::WorkspaceId("workspace-a".into()),
    };
    let mut pap = PolicyAdminApi::new(store.clone());
    for role in ["product:member", "product:admin", "custom:auditor"] {
        pap.grant_membership(
            RoleBinding {
                principal: principal.clone(),
                role: RoleId(role.into()),
                scope: scope.clone(),
            },
            now.clone(),
        )
        .unwrap();
    }
    pap.replace_scoped_memberships(
        principal.clone(),
        scope.clone(),
        vec![
            RoleId("product:member".into()),
            RoleId("product:admin".into()),
        ],
        vec![RoleId("product:member".into())],
        now,
    )
    .unwrap();
    drop(pap);

    let bindings = PolicyAdminApi::new(store)
        .memberships_for_principal(&principal)
        .unwrap();
    assert_eq!(
        bindings
            .iter()
            .filter(|binding| {
                binding.scope == scope
                    && ["product:member", "product:admin"].contains(&binding.role.0.as_str())
            })
            .map(|binding| binding.role.0.as_str())
            .collect::<Vec<_>>(),
        ["product:member"]
    );
    assert!(bindings.iter().any(|binding| {
        binding.scope == scope && binding.role == RoleId("custom:auditor".into())
    }));
}
