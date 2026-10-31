use super::*;

async fn publication(router: &Router) -> awaken_iam_contract::AuthorizationProfilePublicationState {
    let response = router
        .clone()
        .oneshot(
            Request::builder()
                .uri("/v1/authz/profiles/awaken.runtime/publication")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    serde_json::from_value(body_json(response).await).unwrap()
}

#[tokio::test]
async fn publication_evidence_retains_history_without_pap_privilege_or_writes() {
    // Publication cause/effect table over the actual SQLite-backed HTTP owner:
    // H1 no history; H2 draft; H3 validated-only -> false. H4 active and H5
    // retired -> true, even after active-head/snapshot removal. H6 read-only
    // query -> unchanged policy fence; H7 no admin credential -> no PAP write.
    // Decision reads have the same transport exposure as authorize/snapshot;
    // this projection reveals no documents and creates no policy or grant.
    let router = daemon();
    let before = body_json(
        router
            .clone()
            .oneshot(authed_get("/v1/authz/snapshot"))
            .await
            .unwrap(),
    )
    .await;
    assert!(!publication(&router).await.has_published_revision);
    let after = body_json(
        router
            .clone()
            .oneshot(authed_get("/v1/authz/snapshot"))
            .await
            .unwrap(),
    )
    .await;
    assert_eq!(
        before, after,
        "H6 metadata read must not advance or rewrite policy"
    );
    let denied = router
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/v1/admin/authz/profiles")
                .header("content-type", "application/json")
                .body(Body::from(profile_body("workspace").to_string()))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(denied.status(), StatusCode::UNAUTHORIZED, "H7");
    let draft = router
        .clone()
        .oneshot(authed_post(
            "/v1/admin/authz/profiles",
            profile_body("workspace"),
        ))
        .await
        .unwrap();
    assert_eq!(draft.status(), StatusCode::OK);
    assert!(!publication(&router).await.has_published_revision, "H2");
    let validated = router
        .clone()
        .oneshot(authed_post(
            "/v1/admin/authz/profiles/awaken.runtime/1/validate",
            serde_json::json!({}),
        ))
        .await
        .unwrap();
    assert_eq!(validated.status(), StatusCode::OK);
    assert!(!publication(&router).await.has_published_revision, "H3");
    let active = router
        .clone()
        .oneshot(authed_post(
            "/v1/admin/authz/profiles/awaken.runtime/1/activate",
            serde_json::json!({}),
        ))
        .await
        .unwrap();
    assert_eq!(active.status(), StatusCode::OK);
    let evidence = publication(&router).await;
    assert_eq!(evidence.namespace.0, "awaken.runtime");
    assert!(evidence.has_published_revision, "H4");
    let retired = router
        .clone()
        .oneshot(authed_post(
            "/v1/admin/authz/profiles/awaken.runtime/retire",
            serde_json::json!({"expected_active_revision":1}),
        ))
        .await
        .unwrap();
    assert_eq!(retired.status(), StatusCode::OK);
    assert!(publication(&router).await.has_published_revision, "H5");
    let snapshot = body_json(
        router
            .clone()
            .oneshot(authed_get("/v1/authz/snapshot"))
            .await
            .unwrap(),
    )
    .await;
    assert!(snapshot["active_profiles"].as_array().unwrap().is_empty());
    let no_head = router
        .clone()
        .oneshot(authed_get("/v1/admin/authz/profiles/awaken.runtime/active"))
        .await
        .unwrap();
    assert_eq!(no_head.status(), StatusCode::NOT_FOUND);
}

fn profile_body(scope_kind: &str) -> serde_json::Value {
    let scope = if scope_kind == "resource" {
        serde_json::json!({"kind":"resource","resource_type":"memory"})
    } else {
        serde_json::json!({"kind":scope_kind})
    };
    serde_json::json!({
        "namespace": "awaken.runtime",
        "document": {
            "resource_model": {
                "resource_types": [],
                "actions": ["awaken.runtime::memory.*"],
                "edges": []
            },
            "action_scope_rules": [{
                "action_pattern": "awaken.runtime::memory.*",
                "allowed_scope_kinds": [scope]
            }],
            "grants": [{
                "id": "awaken.runtime:g_memory",
                "subject": {"kind":"principal","principal":{"kind":"service","service_id":"runtime"}},
                "action_pattern": "awaken.runtime::memory.*",
                "scope": {"kind":"global"},
                "effect": "allow"
            }]
        },
        "created_at": "2026-07-20T00:00:00Z"
    })
}

#[tokio::test]
async fn profile_pap_replaces_scope_rules_and_rolls_back_over_http() {
    let router = daemon();
    let created = router
        .clone()
        .oneshot(authed_post(
            "/v1/admin/authz/profiles",
            profile_body("workspace"),
        ))
        .await
        .unwrap();
    assert_eq!(created.status(), StatusCode::OK);
    assert_eq!(body_json(created).await["revision"], 1);

    let validated = router
        .clone()
        .oneshot(authed_post(
            "/v1/admin/authz/profiles/awaken.runtime/1/validate",
            serde_json::json!({}),
        ))
        .await
        .unwrap();
    assert_eq!(validated.status(), StatusCode::OK);
    assert_eq!(body_json(validated).await["valid"], true);

    let activated = router
        .clone()
        .oneshot(authed_post(
            "/v1/admin/authz/profiles/awaken.runtime/1/activate",
            serde_json::json!({}),
        ))
        .await
        .unwrap();
    assert_eq!(activated.status(), StatusCode::OK);

    let allowed = router
        .clone()
        .oneshot(authed_post(
            "/v1/authorize",
            serde_json::json!({
                "principal":{"kind":"service","service_id":"runtime"},
                "action":"awaken.runtime::memory.read",
                "scope":{"kind":"workspace","workspace_id":"ws"}
            }),
        ))
        .await
        .unwrap();
    assert_eq!(body_json(allowed).await["decision"], "allow");

    let denied = router
        .clone()
        .oneshot(authed_post(
            "/v1/authorize",
            serde_json::json!({
                "principal":{"kind":"service","service_id":"runtime"},
                "action":"awaken.runtime::memory.read",
                "scope":{"kind":"project","workspace_id":"ws","project_id":"p"}
            }),
        ))
        .await
        .unwrap();
    let denied = body_json(denied).await;
    assert_eq!(denied["decision"], "deny");
    assert_eq!(denied["reason"], "scope_kind_not_allowed");

    let second = router
        .clone()
        .oneshot(authed_post(
            "/v1/admin/authz/profiles",
            profile_body("project"),
        ))
        .await
        .unwrap();
    assert_eq!(body_json(second).await["revision"], 2);
    router
        .clone()
        .oneshot(authed_post(
            "/v1/admin/authz/profiles/awaken.runtime/2/validate",
            serde_json::json!({}),
        ))
        .await
        .unwrap();
    let replaced = router
        .clone()
        .oneshot(authed_post(
            "/v1/admin/authz/profiles/awaken.runtime/2/activate",
            serde_json::json!({"expected_active_revision":1}),
        ))
        .await
        .unwrap();
    assert_eq!(replaced.status(), StatusCode::OK);

    let rolled_back = router
        .clone()
        .oneshot(authed_post(
            "/v1/admin/authz/profiles/awaken.runtime/1/rollback",
            serde_json::json!({"expected_active_revision":2}),
        ))
        .await
        .unwrap();
    assert_eq!(rolled_back.status(), StatusCode::OK);
    assert_eq!(body_json(rolled_back).await["active_revision"], 1);
}

/// A profile body of `grants` grants, each padded so the JSON exceeds axum's
/// 2 MiB default like a real enterprise profile does.
fn large_profile_body(grants: usize) -> serde_json::Value {
    let mut body = profile_body("workspace");
    let padding = "x".repeat(800);
    body["document"]["grants"] = (0..grants)
        .map(|index| {
            serde_json::json!({
                "id": format!("awaken.runtime:g_{index:05}_{padding}"),
                "subject": {"kind":"principal","principal":{"kind":"service","service_id":"runtime"}},
                "action_pattern": "awaken.runtime::memory.*",
                "scope": {"kind":"global"},
                "effect": "allow"
            })
        })
        .collect();
    body
}

fn daemon_with_profile_limit(bytes: usize) -> Router {
    let state = test_daemon_state(
        AuthzApi::new(),
        AdminAuthPolicy::new([ADMIN_TOKEN.to_owned()]),
    )
    .with_profile_body_limit(bytes);
    daemon_router(Arc::new(Mutex::new(state)))
}

#[tokio::test]
async fn profile_publication_body_limit_is_explicit_and_configurable() {
    // L1 a 2,673-grant profile above 2 MiB -> accepted under the 16 MiB
    // default; L2 the same body over a configured 1 MiB limit -> 413; L3 every
    // other route keeps axum's 2 MiB default (grant batch -> 413).
    let body = large_profile_body(2_673);
    let size = body.to_string().len();
    assert!(size > 2 * 1024 * 1024, "fixture is {size} bytes");
    assert!(size < awaken_iam_server::DEFAULT_PROFILE_BODY_LIMIT);

    let created = daemon()
        .oneshot(authed_post("/v1/admin/authz/profiles", body.clone()))
        .await
        .unwrap();
    assert_eq!(created.status(), StatusCode::OK, "L1");
    assert_eq!(body_json(created).await["revision"], 1, "L1");

    let limited = daemon_with_profile_limit(1024 * 1024)
        .oneshot(authed_post("/v1/admin/authz/profiles", body.clone()))
        .await
        .unwrap();
    assert_eq!(limited.status(), StatusCode::PAYLOAD_TOO_LARGE, "L2");

    let grants = body["document"]["grants"].clone();
    let other_route = daemon()
        .oneshot(authed_post(
            "/v1/admin/grants/batch",
            serde_json::json!({ "grants": grants }),
        ))
        .await
        .unwrap();
    assert_eq!(other_route.status(), StatusCode::PAYLOAD_TOO_LARGE, "L3");
}
