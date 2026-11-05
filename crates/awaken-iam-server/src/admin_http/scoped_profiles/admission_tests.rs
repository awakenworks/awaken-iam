//! Original credential identity and Workspace remain one native SQL observation.

use super::*;
use crate::{
    AuthApi, AuthzApi, SqlConn, SqlParam, SqlRow, SqlStore, SqlTransaction, SqliteBackend,
};
use awaken_iam_contract::{AccountId, ApiTokenId};
use awaken_iam_core::{
    ActionPattern, ApiTokenDirectory, ApiTokenMinter, Effect, Grant, GrantId, GrantRepository,
    GrantSubject, MintApiToken, OsEntropy, PolicySet, RepositoryError, RepositoryResult, RoleId,
};
use std::sync::atomic::{AtomicUsize, Ordering};

#[derive(Clone)]
struct ObserveCredential {
    inner: SqliteBackend,
    observations: Arc<AtomicUsize>,
    allowed: usize,
}

impl SqlConn for ObserveCredential {
    fn dialect(&self) -> crate::Dialect {
        self.inner.dialect()
    }
    fn execute(&self, sql: &str, params: &[SqlParam]) -> RepositoryResult<u64> {
        self.inner.execute(sql, params)
    }
    fn query(&self, sql: &str, params: &[SqlParam]) -> RepositoryResult<Vec<SqlRow>> {
        if sql.contains("_api_tokens")
            && sql.contains("WHERE prefix = ?")
            && self.observations.fetch_add(1, Ordering::SeqCst) >= self.allowed
        {
            return Err(RepositoryError::Backend(
                "credential observation interrupted".into(),
            ));
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

fn fixture(
    allowed: usize,
    revoked: bool,
) -> (
    DaemonState<SqlStore<ObserveCredential>>,
    HeaderMap,
    Arc<AtomicUsize>,
) {
    let backend = SqliteBackend::open_in_memory().unwrap();
    crate::sqlite_migrated_store(backend.clone(), "credential_observation").unwrap();
    let observations = Arc::new(AtomicUsize::new(0));
    let store = SqlStore::with_prefix(
        ObserveCredential {
            inner: backend,
            observations: observations.clone(),
            allowed,
        },
        "credential_observation",
    )
    .unwrap();
    let principal = PrincipalRef::Service {
        service_id: "scoped-publisher".into(),
    };
    let at = awaken_iam_contract::Timestamp("2026-11-05T00:00:00Z".into());
    let mut issued = ApiTokenMinter::new(OsEntropy)
        .mint_service_account(
            &mut ApiTokenDirectory::new(),
            &mut PolicySet::default(),
            MintApiToken {
                id: ApiTokenId("publication-credential".into()),
                principal: principal.clone(),
                workspace: WorkspaceId("w1".into()),
                role: RoleId("viewer".into()),
                created_at: at.clone(),
                expires_at: Some(awaken_iam_contract::Timestamp(
                    "2099-01-01T00:00:00Z".into(),
                )),
            },
            AccountId("accountable-person".into()),
        )
        .unwrap()
        .issued;
    if revoked {
        issued.token.revoked_at = Some(at);
    }
    ApiTokenRepository::create(&store, issued.token.clone()).unwrap();
    store
        .record_api_token_owner(&issued.token.id, &AccountId("accountable-person".into()))
        .unwrap();
    for workspace in ["w1", "w2"] {
        GrantRepository::put(
            &store,
            Grant {
                id: GrantId(format!("publisher-{workspace}")),
                subject: GrantSubject::Principal(principal.clone()),
                action_pattern: ActionPattern("iam.authorization-profile.publish:tenant.a".into()),
                scope: ScopeRef::Workspace {
                    workspace_id: WorkspaceId(workspace.into()),
                },
                effect: Effect::Allow,
            },
        )
        .unwrap();
    }
    let state = DaemonState::with_policy_store(
        AuthzApi::new(),
        AdminAuthPolicy::deny_all(),
        Arc::new(store.clone()),
        store,
        AuthApi::new().token_authority(),
    )
    .unwrap();
    let mut headers = HeaderMap::new();
    headers.insert(
        "authorization",
        format!("Bearer {}", issued.secret).parse().unwrap(),
    );
    (state, headers, observations)
}

#[test]
fn original_native_credential_discharges_identity_and_workspace_without_a_second_read() {
    let (mut state, headers, observations) = fixture(1, false);
    let principal = admit(&mut state, &headers, "w1", "tenant.a", "publish")
        .expect("the original observed token supplies both identity and Workspace");
    assert_eq!(
        principal,
        PrincipalRef::Service {
            service_id: "scoped-publisher".into()
        }
    );
    assert_eq!(observations.load(Ordering::SeqCst), 1);
}

#[test]
fn another_granted_workspace_cannot_replace_the_original_credentials_workspace() {
    let (mut state, headers, observations) = fixture(1, false);
    let denied = admit(&mut state, &headers, "w2", "tenant.a", "publish").unwrap_err();
    assert_eq!(denied.status(), StatusCode::FORBIDDEN);
    assert_eq!(observations.load(Ordering::SeqCst), 1);
}

#[test]
fn current_revocation_still_refuses_the_first_native_observation() {
    let (mut state, headers, observations) = fixture(1, true);
    assert_eq!(
        admit(&mut state, &headers, "w1", "tenant.a", "publish")
            .unwrap_err()
            .status(),
        StatusCode::UNAUTHORIZED
    );
    assert_eq!(observations.load(Ordering::SeqCst), 1);
}

#[test]
fn a_new_request_reobserves_revocation_without_a_policy_version_change() {
    let (mut state, headers, observations) = fixture(usize::MAX, false);
    admit(&mut state, &headers, "w1", "tenant.a", "publish").unwrap();
    let version = state.admin.store_version().unwrap();
    let store = state.admin.store();
    let mut token = ApiTokenRepository::get(store, &ApiTokenId("publication-credential".into()))
        .unwrap()
        .unwrap();
    token.revoked_at = Some(awaken_iam_contract::Timestamp(
        "2026-11-05T00:00:00Z".into(),
    ));
    ApiTokenRepository::update(store, token).unwrap();
    assert_eq!(state.admin.store_version().unwrap(), version);
    assert_eq!(
        admit(&mut state, &headers, "w1", "tenant.a", "publish")
            .unwrap_err()
            .status(),
        StatusCode::UNAUTHORIZED
    );
    assert_eq!(
        observations.load(Ordering::SeqCst),
        2,
        "each request obtains one current credential observation"
    );
}

#[test]
fn unavailable_original_token_never_falls_back_to_a_policy_grant() {
    let (mut state, headers, observations) = fixture(0, false);
    assert_eq!(
        admit(&mut state, &headers, "w1", "tenant.a", "publish")
            .unwrap_err()
            .status(),
        StatusCode::INTERNAL_SERVER_ERROR
    );
    assert_eq!(observations.load(Ordering::SeqCst), 1);
}
