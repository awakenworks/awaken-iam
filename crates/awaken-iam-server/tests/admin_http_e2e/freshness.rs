//! Native HTTP observations must follow current shared policy and token fences.
use super::*;
use awaken_iam_contract::{
    AUTHORIZATION_FRESHNESS_HEADER, AccountId, ActionKey, AuthorizationDecision,
    AuthorizationRequest, PrincipalRef, ResourceAuthorizationRequest, ScopeRef, Timestamp,
};
use awaken_iam_core::{ActionPattern, Effect, Grant, GrantId, GrantSubject, RoleBinding, RoleId};
use awaken_iam_server::{FenceStore, PolicyAdminApi, SqlConn};

async fn evaluate(router: &Router) -> (AuthorizationOutcome, String) {
    let request = ResourceAuthorizationRequest {
        request: AuthorizationRequest::direct(
            PrincipalRef::Account {
                account_id: AccountId("ada".into()),
            },
            ActionKey("document.read".into()),
            ScopeRef::Global,
        ),
        context: Default::default(),
    };
    let response = router
        .clone()
        .oneshot(authed_json(
            "POST",
            "/v1/authorize/resource",
            serde_json::to_value(request).unwrap(),
        ))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let metadata = response
        .headers()
        .get(AUTHORIZATION_FRESHNESS_HEADER)
        .unwrap()
        .to_str()
        .unwrap()
        .to_owned();
    assert!(metadata.starts_with("iam-fence-v1:"));
    (
        serde_json::from_value(body_json(response).await).unwrap(),
        metadata,
    )
}

async fn exercise_native_freshness<B: SqlConn + Clone + 'static>(store: SqlStore<B>, prefix: &str) {
    let state = Arc::new(Mutex::new(
        DaemonState::with_policy_store(
            AuthzApi::new(),
            AdminAuthPolicy::deny_all(),
            Arc::new(store.clone()),
            store.clone(),
            AuthApi::new().token_authority(),
        )
        .unwrap(),
    ));
    let router = daemon_router(state);
    let mut policy = PolicyAdminApi::new(store.clone());
    let at = Timestamp("2026-11-09T00:00:00Z".into());
    let (initial, zero) = evaluate(&router).await;
    assert_eq!(initial.decision, AuthorizationDecision::Deny);
    assert_eq!(
        evaluate(&router).await.1,
        zero,
        "unchanged native fence is stable"
    );
    policy
        .issue_grant(
            Grant {
                id: GrantId("role-read".into()),
                subject: GrantSubject::Role(RoleId("reader".into())),
                action_pattern: ActionPattern("document.read".into()),
                scope: ScopeRef::Global,
                effect: Effect::Allow,
            },
            at.clone(),
        )
        .unwrap();
    let (without_member, grant) = evaluate(&router).await;
    assert_eq!(without_member.decision, AuthorizationDecision::Deny);
    assert_ne!(grant, zero);
    let binding = RoleBinding {
        principal: PrincipalRef::Account {
            account_id: AccountId("ada".into()),
        },
        role: RoleId("reader".into()),
        scope: ScopeRef::Global,
    };
    policy
        .grant_membership(binding.clone(), at.clone())
        .unwrap();
    let (allowed, member) = evaluate(&router).await;
    assert_eq!(allowed.decision, AuthorizationDecision::Allow);
    assert_ne!(member, grant);
    policy.revoke_membership(&binding, at.clone()).unwrap();
    let (denied, revoked) = evaluate(&router).await;
    assert_eq!(denied.decision, AuthorizationDecision::Deny);
    assert_ne!(revoked, member);
    store.advance_epoch().unwrap();
    let (denied, epoch) = evaluate(&router).await;
    assert_eq!(denied.decision, AuthorizationDecision::Deny);
    assert_ne!(
        epoch, revoked,
        "a token epoch change matters without a policy edit"
    );
    // This is the fixture's own migrated database. An unreadable
    // native fence must produce unavailable, not the previous reasoned answer.
    store
        .backend()
        .execute(&format!("DELETE FROM {prefix}_fence WHERE id=1"), &[])
        .unwrap();
    let response = router.oneshot(authed_json("POST", "/v1/authorize/resource", serde_json::json!({
        "request":{"principal":{"kind":"account","account_id":"ada"},"action":"document.read","scope":{"kind":"global"}},"context":{}
    }))).await.unwrap();
    assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
    assert!(
        response
            .headers()
            .get(AUTHORIZATION_FRESHNESS_HEADER)
            .is_none()
    );
}

#[tokio::test]
async fn native_freshness_tracks_real_membership_policy_epoch_and_dependency_failure() {
    exercise_native_freshness(sqlite_in_memory_store("freshness").unwrap(), "freshness").await;
}
#[tokio::test]
async fn postgres_native_freshness_uses_the_same_owner_contract() {
    let Ok(url) = std::env::var("IAM_TEST_POSTGRES_URL") else {
        return;
    };
    let prefix = format!(
        "freshness_pg_{:x}",
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    );
    let store = awaken_iam_server::postgres_migrated_store(&url, &prefix).unwrap();
    exercise_native_freshness(store, &prefix).await;
}

#[derive(Clone)]
struct EpochRace {
    inner: SqliteBackend,
    remaining: Arc<std::sync::atomic::AtomicUsize>,
}
impl SqlConn for EpochRace {
    fn dialect(&self) -> awaken_iam_server::Dialect {
        self.inner.dialect()
    }
    fn execute(
        &self,
        sql: &str,
        params: &[awaken_iam_server::SqlParam],
    ) -> awaken_iam_core::RepositoryResult<u64> {
        self.inner.execute(sql, params)
    }
    fn query(
        &self,
        sql: &str,
        params: &[awaken_iam_server::SqlParam],
    ) -> awaken_iam_core::RepositoryResult<Vec<awaken_iam_server::SqlRow>> {
        let rows = self.inner.query(sql, params)?;
        if sql.starts_with("SELECT CAST(version AS TEXT), CAST(epoch AS TEXT)") {
            use std::sync::atomic::Ordering::SeqCst;
            if self.remaining.fetch_update(SeqCst, SeqCst, |value| {
                if value > 0 { Some(value - 1) } else { None }
            }) == Ok(1)
            {
                // A real, committed native epoch write after this fence read;
                // no fake PDP result or synthesized observation is involved.
                self.inner
                    .execute("UPDATE epoch_race_fence SET epoch=epoch+1 WHERE id=1", &[])?;
            }
        }
        Ok(rows)
    }
    fn with_transaction(
        &self,
        operation: &mut (
                 dyn FnMut(
            &mut dyn awaken_iam_server::SqlTransaction,
        ) -> awaken_iam_core::RepositoryResult<()>
                     + Send
             ),
    ) -> awaken_iam_core::RepositoryResult<()> {
        self.inner.with_transaction(operation)
    }
}

#[tokio::test]
async fn a_native_epoch_write_during_admission_cannot_qualify_an_allow() {
    let base = sqlite_in_memory_store("epoch_race").unwrap();
    let remaining = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let store = SqlStore::with_prefix(
        EpochRace {
            inner: base.backend().clone(),
            remaining: remaining.clone(),
        },
        "epoch_race",
    )
    .unwrap();
    let mut policy = PolicyAdminApi::new(store.clone());
    policy
        .issue_grant(
            Grant {
                id: GrantId("direct-read".into()),
                subject: GrantSubject::Principal(PrincipalRef::Account {
                    account_id: AccountId("ada".into()),
                }),
                action_pattern: ActionPattern("document.read".into()),
                scope: ScopeRef::Global,
                effect: Effect::Allow,
            },
            Timestamp("2026-11-09T00:00:00Z".into()),
        )
        .unwrap();
    let router = daemon_router(Arc::new(Mutex::new(
        DaemonState::with_policy_store(
            AuthzApi::new(),
            AdminAuthPolicy::deny_all(),
            Arc::new(store.clone()),
            store,
            AuthApi::new().token_authority(),
        )
        .unwrap(),
    )));
    let (first, original) = evaluate(&router).await;
    assert_eq!(first.decision, AuthorizationDecision::Allow);
    // One current-store freshness read precedes capture of the admission's
    // candidate fence. Commit the epoch change immediately after that capture.
    remaining.store(2, std::sync::atomic::Ordering::SeqCst);
    let response = router.clone().oneshot(authed_json("POST", "/v1/authorize/resource", serde_json::json!({
        "request":{"principal":{"kind":"account","account_id":"ada"},"action":"document.read","scope":{"kind":"global"}},"context":{}
    }))).await.unwrap();
    assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
    assert!(
        response
            .headers()
            .get(AUTHORIZATION_FRESHNESS_HEADER)
            .is_none()
    );
    let (current, changed) = evaluate(&router).await;
    assert_eq!(current.decision, AuthorizationDecision::Allow);
    assert_ne!(
        changed, original,
        "a fresh admission observes the committed new epoch"
    );
}
