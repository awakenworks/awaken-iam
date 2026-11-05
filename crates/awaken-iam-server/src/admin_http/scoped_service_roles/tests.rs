//! Bounded native references stay fresh across requests and tenant cardinality.

use super::*;
use crate::{
    AuthApi, AuthzApi, SqlConn, SqlParam, SqlRow, SqlStore, SqlTransaction, SqliteBackend,
};
use awaken_iam_contract::WorkspaceId;
use awaken_iam_core::{RepositoryError, RepositoryResult};
use std::sync::{
    Arc,
    atomic::{AtomicBool, AtomicUsize, Ordering},
};

#[derive(Clone)]
struct BoundedReferences {
    inner: SqliteBackend,
    armed: Arc<AtomicBool>,
    reads: Arc<AtomicUsize>,
}

impl SqlConn for BoundedReferences {
    fn dialect(&self) -> crate::Dialect {
        self.inner.dialect()
    }

    fn execute(&self, sql: &str, params: &[SqlParam]) -> RepositoryResult<u64> {
        self.inner.execute(sql, params)
    }

    fn query(&self, sql: &str, params: &[SqlParam]) -> RepositoryResult<Vec<SqlRow>> {
        if self.armed.load(Ordering::SeqCst) && sql.contains("_role_bindings") {
            // A shared service may have bindings in many Workspaces. Its scoped
            // PDP/PAP path must never request that whole roster from the driver.
            if !sql.contains("WHERE principal = ?j AND role = ? AND scope = ?j")
                || params.len() != 3
            {
                return Err(RepositoryError::Backend(
                    "cross-tenant role enumeration refused".into(),
                ));
            }
            self.reads.fetch_add(1, Ordering::SeqCst);
        }
        self.inner.query(sql, params)
    }

    fn with_transaction(
        &self,
        operation: &mut (dyn FnMut(&mut dyn SqlTransaction) -> RepositoryResult<()> + Send),
    ) -> RepositoryResult<()> {
        self.inner.with_transaction(operation)
    }
}

fn binding(workspace: &str) -> RoleBinding {
    RoleBinding {
        principal: PrincipalRef::Service {
            service_id: "shared-controller".into(),
        },
        role: RoleId("tenant.workflow:controller".into()),
        scope: ScopeRef::Workspace {
            workspace_id: WorkspaceId(workspace.into()),
        },
    }
}

fn exact_coordinates(store: &impl RoleBindingRepository) {
    let current = binding("w1");
    store.add(current.clone()).unwrap();
    assert!(store.contains_exact(&current).unwrap());
    assert!(!store.contains_exact(&binding("foreign")).unwrap());
    let mut wrong = current.clone();
    wrong.role = RoleId("other-role".into());
    assert!(!store.contains_exact(&wrong).unwrap());
    wrong = current.clone();
    wrong.principal = PrincipalRef::Service {
        service_id: "other-controller".into(),
    };
    assert!(!store.contains_exact(&wrong).unwrap());
    wrong = current.clone();
    wrong.scope = ScopeRef::Global;
    assert!(!store.contains_exact(&wrong).unwrap());
    store.remove(&current).unwrap();
    assert!(!store.contains_exact(&current).unwrap());
}

#[test]
fn native_exact_reference_uses_all_three_coordinates_in_memory_and_sql() {
    exact_coordinates(&crate::InMemoryStore::default());
    exact_coordinates(&crate::sqlite_in_memory_store("exact_references").unwrap());
}

#[test]
fn shared_service_lookup_is_bounded_and_reobserved_on_the_next_request() {
    let backend = SqliteBackend::open_in_memory().unwrap();
    crate::sqlite_migrated_store(backend.clone(), "bounded_references").unwrap();
    let armed = Arc::new(AtomicBool::new(false));
    let reads = Arc::new(AtomicUsize::new(0));
    let store = SqlStore::with_prefix(
        BoundedReferences {
            inner: backend,
            armed: armed.clone(),
            reads: reads.clone(),
        },
        "bounded_references",
    )
    .unwrap();
    let state = DaemonState::with_policy_store(
        AuthzApi::new(),
        super::super::AdminAuthPolicy::deny_all(),
        Arc::new(store.clone()),
        store.clone(),
        AuthApi::new().token_authority(),
    )
    .unwrap();
    // Distinct foreign tenants share the same principal and role. Only the
    // requested exact tuple may cross the SQL driver boundary after arming.
    for index in 0..256 {
        store.add(binding(&format!("foreign-{index}"))).unwrap();
    }
    let current = binding("w1");
    store.add(current.clone()).unwrap();
    let version = state.admin.store_version().unwrap();
    armed.store(true, Ordering::SeqCst);
    let mut request = CurrentServiceRoles::default();
    for _ in 0..3 {
        assert!(
            request
                .contains(&state, &current.principal, &current.role.0, &current.scope)
                .unwrap()
        );
    }
    assert_eq!(reads.load(Ordering::SeqCst), 1);
    store.remove(&current).unwrap();
    assert_eq!(state.admin.store_version().unwrap(), version);
    let mut next = CurrentServiceRoles::default();
    for _ in 0..2 {
        assert!(
            !next
                .contains(&state, &current.principal, &current.role.0, &current.scope)
                .unwrap()
        );
    }
    assert_eq!(reads.load(Ordering::SeqCst), 2);
}
