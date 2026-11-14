//! Account-capable adapter over the original guarded PAP read, with no new state.
use super::*;
use awaken_iam_contract::OrganizationMemberLabelsQuery;
use awaken_iam_core::AccountRepository;

/// Mount the optional account-label capability beside the policy-only router.
pub fn organization_member_labels_router<S>(state: SharedDaemonState<S>) -> Router
where
    S: PolicyStore + AccountRepository + 'static,
{
    Router::new()
        .route(
            "/v1/admin/memberships/organization-labels",
            post(organization_member_labels::<S>),
        )
        .with_state(state)
}

async fn organization_member_labels<S>(
    State(state): State<SharedDaemonState<S>>,
    headers: HeaderMap,
    Json(query): Json<OrganizationMemberLabelsQuery>,
) -> Response
where
    S: PolicyStore + AccountRepository,
{
    read(&state, &headers, |admin| {
        admin.organization_member_labels(&query.org_id)
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use awaken_iam_contract::{Account, AccountId, AccountStatus, ProductId, Timestamp};
    use awaken_iam_core::{RoleBinding, RoleBindingRepository, RoleId};
    use axum::{body::Body, http::Request};
    use tower::ServiceExt;

    #[tokio::test]
    async fn organization_member_labels_use_original_admin_guard_and_pap_projection() {
        // L4 missing/unknown/product credential -> original 401/403; both original
        // admin header forms (Bearer token / canonical prefixed API key) -> admitted.
        // An unprefixed x-api-key is not an original recognized credential.
        // L6 same state/store -> byte-equivalent
        // native PAP projection over HTTP, and selectors outside OrgId -> reject.
        let admin_key = format!("{}member-labels-test", crate::ADMIN_API_KEY_PREFIX);
        let store = crate::sqlite_in_memory_store("member_labels_http").unwrap();
        AccountRepository::upsert(
            &store,
            Account {
                id: AccountId("ada".into()),
                status: AccountStatus::Active,
                display_name: Some("Ada".into()),
                created_at: Timestamp("2026-11-14T00:00:00Z".into()),
                updated_at: Timestamp("2026-11-14T00:00:00Z".into()),
            },
        )
        .unwrap();
        RoleBindingRepository::add(
            &store,
            RoleBinding {
                principal: awaken_iam_contract::PrincipalRef::Account {
                    account_id: AccountId("ada".into()),
                },
                role: RoleId("consumer-owned-role".into()),
                scope: awaken_iam_contract::ScopeRef::Org {
                    org_id: OrgId("acme".into()),
                },
            },
        )
        .unwrap();
        let expected = PolicyAdminApi::new(store.clone())
            .organization_member_labels(&OrgId("acme".into()))
            .unwrap();
        let state = Arc::new(Mutex::new(
            DaemonState::with_policy_store(
                crate::AuthzApi::new(),
                AdminAuthPolicy::new(["admin-test".into(), admin_key.clone()])
                    .with_product_token(ProductId::new("agents").unwrap(), "product-test"),
                Arc::new(store.clone()),
                store,
                crate::AuthApi::new().token_authority(),
            )
            .unwrap(),
        ));
        let router = daemon_router(state.clone()).merge(organization_member_labels_router(state));
        for (header, value, status) in [
            ("authorization", "", StatusCode::UNAUTHORIZED),
            ("authorization", "Bearer unknown", StatusCode::FORBIDDEN),
            (
                "authorization",
                "Bearer product-test",
                StatusCode::FORBIDDEN,
            ),
            ("authorization", "Bearer admin-test", StatusCode::OK),
            ("x-api-key", admin_key.as_str(), StatusCode::OK),
        ] {
            let request = Request::builder()
                .method("POST")
                .uri("/v1/admin/memberships/organization-labels")
                .header("content-type", "application/json")
                .header(header, value)
                .body(Body::from(r#"{"org_id":"acme"}"#))
                .unwrap();
            let response = router.clone().oneshot(request).await.unwrap();
            assert_eq!(response.status(), status);
            if status == StatusCode::OK {
                let bytes = axum::body::to_bytes(response.into_body(), usize::MAX)
                    .await
                    .unwrap();
                assert_eq!(
                    serde_json::from_slice::<serde_json::Value>(&bytes).unwrap(),
                    serde_json::to_value(&expected).unwrap()
                );
            }
        }
        let request = Request::builder()
            .method("POST")
            .uri("/v1/admin/memberships/organization-labels")
            .header("content-type", "application/json")
            .header("authorization", "Bearer admin-test")
            .body(Body::from(r#"{"org_id":"acme","account_ids":["foreign"]}"#))
            .unwrap();
        assert_eq!(
            router.oneshot(request).await.unwrap().status(),
            StatusCode::UNPROCESSABLE_ENTITY
        );
    }
}
