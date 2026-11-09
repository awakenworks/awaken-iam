use super::*;
use std::sync::atomic::{AtomicU8, Ordering};
#[derive(Clone)]
struct QualificationRace<B> {
    inner: B,
    prefix: String,
    armed: Arc<AtomicU8>,
}
impl<B: SqlConn> SqlConn for QualificationRace<B> {
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
        if sql.contains(&format!("JOIN {}_resource_projection_streams", self.prefix)) {
            let selected = self.armed.swap(0, Ordering::SeqCst);
            let column = match selected {
                1 => Some("epoch"),
                2 => Some("version"),
                _ => None,
            };
            if let Some(column) = column {
                // Commit a real peer write after the original ownership read.
                // The returned SQL rows and PDP outcome are never fabricated.
                self.inner.execute(
                    &format!(
                        "UPDATE {}_fence SET {column}={column}+1 WHERE id=1",
                        self.prefix
                    ),
                    &[],
                )?;
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
async fn race<B: SqlConn + Clone + 'static>(base: SqlStore<B>, prefix: &str) {
    let armed = Arc::new(AtomicU8::new(0));
    let store = SqlStore::with_prefix(
        QualificationRace {
            inner: base.backend().clone(),
            prefix: prefix.into(),
            armed: armed.clone(),
        },
        prefix,
    )
    .unwrap();
    seed(&store);
    store
        .register_product_resource_model(&ProductResourceModelRequest {
            product_id: ProductId::new("awaken").unwrap(),
            resource_model: document().resource_model,
        })
        .unwrap();
    publish(&store, document());
    store.apply_resource_projection(&projection()).unwrap();
    let (base, handle) = serve(store.clone()).await;
    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(5))
        .build()
        .unwrap();
    let original = strict(&client, &base, &question()).await;
    assert_eq!(
        original.evaluation.outcome.decision,
        AuthorizationDecision::Allow
    );
    let mut stamp = original.evaluation.freshness;
    for component in [1, 2] {
        armed.store(component, Ordering::SeqCst);
        let response = client
            .post(format!("{base}/v1/authorize/resource/registered"))
            .json(&question())
            .send()
            .await
            .unwrap();
        assert_eq!(response.status(), 503, "native fence component {component}");
        let body: serde_json::Value = response.json().await.unwrap();
        assert!(body.get("registration").is_none());
        let fresh = strict(&client, &base, &question()).await;
        assert_eq!(
            fresh.evaluation.outcome.decision,
            AuthorizationDecision::Allow
        );
        assert_ne!(fresh.evaluation.freshness, stamp);
        stamp = fresh.evaluation.freshness;
    }
    handle.abort();
    let _ = handle.await;
}
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn sqlite_registration_never_qualifies_an_epoch_or_version_race() {
    race(
        sqlite_in_memory_store("strict_registration_race").unwrap(),
        "strict_registration_race",
    )
    .await;
}
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn postgres_registration_never_qualifies_an_epoch_or_version_race() {
    let Ok(url) = std::env::var("IAM_TEST_POSTGRES_URL") else {
        assert!(
            std::env::var_os("AWAKEN_TEST_REQUIRE_POSTGRES").is_none(),
            "required PostgreSQL fixture missing"
        );
        return;
    };
    let prefix = format!(
        "strict_race_{:x}",
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    );
    race(
        awaken_iam_server::postgres_migrated_store(&url, &prefix).unwrap(),
        &prefix,
    )
    .await;
}
