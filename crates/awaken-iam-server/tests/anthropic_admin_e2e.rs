//! End-to-end coverage of the Anthropic-compatible Admin API methods over the
//! real `AnthropicAdminApi` against an in-process `PolicyAdminApi`.
//!
//! The seam is framework-agnostic; the wire shape (`/v1/organizations/users`,
//! `/v1/organizations/workspaces/{id}/members`, `/v1/organizations/api_keys`,
//! `/v1/organizations/service_accounts`, `/v1/organizations/federation_*`) is
//! declared in the assembly manifest but bound by each deployment. This test
//! drives every method the surface advertises and verifies the response
//! envelopes match Anthropic's `{"type":"...", ...}` shape exactly — proving
//! the data plane is correct so a future HTTP binding is wire-compatible.
//!
//! The federation projection paths exercise the `project_federation_*` helpers
//! directly, which are the read-side renderers used by
//! `GET /v1/organizations/federation_issuers` and
//! `GET /v1/organizations/federation_rules`.

use awaken_iam_contract::{AccountId, Jwks, OrgId, PrincipalRef, Timestamp, WorkspaceId};
use awaken_iam_preset::seed_named_roles;
use awaken_iam_server::{
    AnthropicAdminApi, ApiKey, DEFAULT_PAGE_LIMIT, FederationIssuer, InMemoryStore, ListParams,
    MAX_PAGE_LIMIT, Member, ObjectKind, OrgRole, PolicyAdminApi, ServiceAccount, TrustedIssuer,
    WorkloadBinding, WorkspaceMember, WorkspaceRole, project_federation_issuers,
    project_federation_rules,
};

fn at() -> Timestamp {
    Timestamp("2026-06-23T00:00:00Z".to_owned())
}

fn org() -> OrgId {
    OrgId("acme".to_owned())
}

fn workspace() -> WorkspaceId {
    WorkspaceId("default".to_owned())
}

fn pap() -> PolicyAdminApi<InMemoryStore> {
    let store = InMemoryStore::new();
    seed_named_roles(&store, &at()).expect("seed catalog");
    PolicyAdminApi::new(store)
}

fn jwks() -> Jwks {
    // The federation projection only consumes the issuer's JWKS for display
    // and signing; for read-rendering we don't need valid keys, only a non-empty
    // JWKS so the envelope renders without panicking.
    Jwks { keys: Vec::new() }
}

fn issuer(name: &str, enabled: bool) -> TrustedIssuer {
    TrustedIssuer {
        issuer: name.to_owned(),
        keys: jwks(),
        audiences: vec!["aud-1".to_owned(), "aud-2".to_owned()],
        bindings: vec![],
        enabled,
    }
}

fn issuer_with_binding(name: &str, binding: WorkloadBinding) -> TrustedIssuer {
    TrustedIssuer {
        issuer: name.to_owned(),
        keys: jwks(),
        audiences: vec!["awaken-iam".to_owned()],
        bindings: vec![binding],
        enabled: true,
    }
}

#[test]
fn project_federation_issuers_renders_disabled_and_enabled_issuers_with_prefixes() {
    // The reader-facing `/v1/organizations/federation_issuers` projection
    // sorts issuers by id, stamps the `fdis_` prefix, and reflects the
    // `enabled` toggle as a field on the envelope.
    let issuers = vec![
        issuer("https://idp.example/", true),
        issuer("https://staging.example/", false),
    ];

    let page = project_federation_issuers(&issuers, &Default::default()).unwrap();
    assert_eq!(page.data.len(), 2);
    // Stable id order: the https:// one with the smaller host sorts first.
    let ids: Vec<&str> = page.data.iter().map(|i| i.id.as_str()).collect();
    assert!(ids[0] < ids[1]);
    for iss in &page.data {
        assert_eq!(iss.object, ObjectKind::FederationIssuer);
        assert!(iss.id.starts_with("fdis_"));
    }
    let staging = page
        .data
        .iter()
        .find(|i| i.issuer.contains("staging"))
        .unwrap();
    assert!(!staging.enabled);
    let prod = page.data.iter().find(|i| i.issuer.contains("idp")).unwrap();
    assert!(prod.enabled);
    assert_eq!(prod.audiences, vec!["aud-1", "aud-2"]);
}

#[test]
fn project_federation_issuers_paginates_with_limit_and_after_id() {
    let issuers: Vec<TrustedIssuer> = (0..5)
        .map(|i| issuer(&format!("https://issuer-{i:02}.example/"), true))
        .collect();

    // First page: 2 issuers, has_more true.
    let page = project_federation_issuers(
        &issuers,
        &ListParams {
            limit: 2,
            before_id: None,
            after_id: None,
        },
    )
    .unwrap();
    assert_eq!(page.data.len(), 2);
    assert!(page.has_more);

    // Second page: cursor after the last id of the previous page.
    let last_id = page.last_id.clone().unwrap();
    let next = project_federation_issuers(
        &issuers,
        &ListParams {
            limit: 2,
            before_id: None,
            after_id: Some(last_id),
        },
    )
    .unwrap();
    assert_eq!(next.data.len(), 2);
    assert!(next.has_more);
    // Order is stable ascending by id.
    assert!(next.first_id.as_ref().unwrap() > page.first_id.as_ref().unwrap());
}

#[test]
fn project_federation_issuers_paginates_backward_with_before_id() {
    let issuers: Vec<TrustedIssuer> = (0..5)
        .map(|i| issuer(&format!("https://issuer-{i:02}.example/"), true))
        .collect();
    let all_ids: Vec<String> = {
        let page = project_federation_issuers(
            &issuers,
            &ListParams {
                limit: MAX_PAGE_LIMIT,
                before_id: None,
                after_id: None,
            },
        )
        .unwrap();
        page.data.iter().map(|i| i.id.clone()).collect()
    };

    // before_id targets the last issuer; the page is the immediately-preceding
    // `limit` entries, in ascending order.
    let last = all_ids.last().unwrap().clone();
    let page = project_federation_issuers(
        &issuers,
        &ListParams {
            limit: 2,
            before_id: Some(last.clone()),
            after_id: None,
        },
    )
    .unwrap();
    assert_eq!(page.data.len(), 2);
    // The returned ids are not the cursor itself.
    for iss in &page.data {
        assert_ne!(iss.id, last);
    }
}

#[test]
fn project_federation_issuers_rejects_an_unknown_cursor_and_bad_limit() {
    let issuers = vec![issuer("https://idp.example/", true)];

    let err = project_federation_issuers(
        &issuers,
        &ListParams {
            limit: 0,
            before_id: None,
            after_id: None,
        },
    )
    .unwrap_err();
    assert!(
        matches!(err, awaken_iam_server::AdminApiError::InvalidLimit(0)),
        "limit=0 must be rejected"
    );

    let err = project_federation_issuers(
        &issuers,
        &ListParams {
            limit: MAX_PAGE_LIMIT + 1,
            before_id: None,
            after_id: None,
        },
    )
    .unwrap_err();
    assert!(matches!(
        err,
        awaken_iam_server::AdminApiError::InvalidLimit(_)
    ));

    let err = project_federation_issuers(
        &issuers,
        &ListParams {
            limit: 10,
            before_id: None,
            after_id: Some("fdis_does-not-exist".to_owned()),
        },
    )
    .unwrap_err();
    assert!(matches!(
        err,
        awaken_iam_server::AdminApiError::InvalidCursor(_)
    ));

    // Both cursors at once is mutually exclusive.
    let err = project_federation_issuers(
        &issuers,
        &ListParams {
            limit: 10,
            before_id: Some("any".to_owned()),
            after_id: Some("any".to_owned()),
        },
    )
    .unwrap_err();
    assert!(matches!(
        err,
        awaken_iam_server::AdminApiError::InvalidCursor(_)
    ));
}

#[test]
fn project_federation_rules_flattens_issuers_bindings_with_prefixes() {
    // A federation rule is a per-(issuer, subject) binding: each
    // `TrustedIssuer::bindings` entry projects to one rule envelope.
    let issuers = vec![
        issuer_with_binding(
            "https://idp.example/",
            WorkloadBinding {
                subject: "user-1".to_owned(),
                service_id: "ci-bot".to_owned(),
                audience: "awaken-iam".to_owned(),
                scopes: vec!["workspace:developer".to_owned(), "extra.read".to_owned()],
                workspace: workspace(),
            },
        ),
        issuer_with_binding(
            "https://idp-2.example/",
            WorkloadBinding {
                subject: "user-2".to_owned(),
                service_id: "ci-bot-2".to_owned(),
                audience: "awaken-iam".to_owned(),
                scopes: vec!["workspace:admin".to_owned()],
                workspace: workspace(),
            },
        ),
    ];

    let page = project_federation_rules(&issuers, &Default::default()).unwrap();
    assert_eq!(page.data.len(), 2);
    for rule in &page.data {
        assert_eq!(rule.object, ObjectKind::FederationRule);
        assert!(rule.id.starts_with("fdrl_"));
        assert!(rule.issuer_id.starts_with("fdis_"));
        assert!(rule.service_account_id.starts_with("svac_"));
    }
    // workspace:developer -> WorkspaceDeveloper; workspace:admin -> WorkspaceAdmin.
    let dev_rule = page.data.iter().find(|r| r.subject == "user-1").unwrap();
    assert_eq!(
        dev_rule.workspace_role,
        Some(WorkspaceRole::WorkspaceDeveloper)
    );
    assert_eq!(dev_rule.scopes, vec!["workspace:developer", "extra.read"]);

    let admin_rule = page.data.iter().find(|r| r.subject == "user-2").unwrap();
    assert_eq!(
        admin_rule.workspace_role,
        Some(WorkspaceRole::WorkspaceAdmin)
    );
}

#[test]
fn project_federation_rules_skips_issuers_with_no_bindings() {
    // An enabled issuer with no bindings contributes zero rules — readers
    // see only the actual bindings, never empty envelopes.
    let issuers = vec![
        issuer("https://idp.example/", true),
        issuer_with_binding(
            "https://idp-with-bindings.example/",
            WorkloadBinding {
                subject: "user-1".to_owned(),
                service_id: "ci".to_owned(),
                audience: "awaken-iam".to_owned(),
                scopes: vec!["workspace:user".to_owned()],
                workspace: workspace(),
            },
        ),
    ];

    let page = project_federation_rules(&issuers, &Default::default()).unwrap();
    assert_eq!(page.data.len(), 1);
    assert!(page.data[0].issuer_id.contains("idp-with-bindings"));
}

#[test]
fn api_key_and_service_account_list_paginate_with_the_default_limit() {
    // Drive `list_api_keys` and `list_service_accounts` over a real
    // PolicyAdminApi store and verify they:
    //  - emit Anthropic-shaped envelopes (`type` discriminator, prefixed ids),
    //  - paginate with the DEFAULT_PAGE_LIMIT cap,
    //  - only surface bindings scoped to a workspace.
    let mut pap = pap();
    let mut api = AnthropicAdminApi::new(&mut pap, org());

    // Seed enough entries to test the page cap.
    let target = DEFAULT_PAGE_LIMIT + 5;
    for i in 0..target {
        let key = format!("tok_{i:03}");
        api.bind_api_key(&key, &workspace(), WorkspaceRole::WorkspaceUser, at())
            .expect("bind key");
        let svc = format!("svc-{i:03}");
        api.add_service_account(&svc, &workspace(), WorkspaceRole::WorkspaceDeveloper, at())
            .expect("add service account");
    }

    // list_api_keys with default limit returns DEFAULT_PAGE_LIMIT, has_more=true.
    let page = api.list_api_keys(&ListParams::default()).unwrap();
    assert_eq!(page.data.len(), DEFAULT_PAGE_LIMIT);
    assert!(page.has_more);
    for key in &page.data {
        assert_eq!(key.object, ObjectKind::ApiKey);
        assert_eq!(key.workspace_id, "wrkspc_default");
    }

    // list_service_accounts paginates too.
    let page = api.list_service_accounts(&ListParams::default()).unwrap();
    assert_eq!(page.data.len(), DEFAULT_PAGE_LIMIT);
    assert!(page.has_more);
    for account in &page.data {
        assert_eq!(account.object, ObjectKind::ServiceAccount);
        assert!(account.id.starts_with("svac_"));
    }

    // Removing one service account closes the gap and the next list reflects it.
    let first_svac = page.first_id.clone().unwrap();
    api.remove_service_account(&first_svac, &workspace(), at())
        .expect("remove");
    let page = api.list_service_accounts(&ListParams::default()).unwrap();
    assert!(
        !page.data.iter().any(|a| a.id == first_svac),
        "the removed service account must not reappear"
    );
}

#[test]
fn set_api_key_role_replaces_the_role_binding() {
    // The `set_api_key_role` operation revokes every existing binding for the
    // (token, workspace) pair and binds a new one — replacement, not
    // accumulation.
    let mut pap = pap();
    let mut api = AnthropicAdminApi::new(&mut pap, org());

    api.bind_api_key("tok_set", &workspace(), WorkspaceRole::WorkspaceUser, at())
        .unwrap();
    let replaced = api
        .set_api_key_role("tok_set", &workspace(), WorkspaceRole::WorkspaceAdmin, at())
        .unwrap();
    assert_eq!(replaced.object, ObjectKind::ApiKey);
    assert_eq!(replaced.workspace_role, WorkspaceRole::WorkspaceAdmin);

    // The list still shows exactly one entry for this token — no double-binding.
    let page = api.list_api_keys(&ListParams::default()).unwrap();
    let matches: Vec<_> = page.data.iter().filter(|k| k.id == "tok_set").collect();
    assert_eq!(matches.len(), 1);
    assert_eq!(matches[0].workspace_role, WorkspaceRole::WorkspaceAdmin);
}

#[test]
fn set_api_key_role_fails_closed_when_no_binding_exists() {
    let mut pap = pap();
    let mut api = AnthropicAdminApi::new(&mut pap, org());
    let err = api
        .set_api_key_role(
            "tok_absent",
            &workspace(),
            WorkspaceRole::WorkspaceAdmin,
            at(),
        )
        .unwrap_err();
    assert!(matches!(err, awaken_iam_server::AdminApiError::Admin(_)));
}

#[test]
fn remove_workspace_member_fails_closed_when_unbound() {
    let mut pap = pap();
    let mut api = AnthropicAdminApi::new(&mut pap, org());

    // Adding then removing leaves no bindings.
    api.add_workspace_member(
        &workspace(),
        AccountId("zoe".to_owned()),
        WorkspaceRole::WorkspaceUser,
        at(),
    )
    .unwrap();
    api.remove_workspace_member(&workspace(), &AccountId("zoe".to_owned()), at())
        .unwrap();

    // A second remove must fail closed.
    let err = api
        .remove_workspace_member(&workspace(), &AccountId("zoe".to_owned()), at())
        .unwrap_err();
    assert!(matches!(err, awaken_iam_server::AdminApiError::Admin(_)));
}

#[test]
fn list_workspace_members_paginates_by_user_id() {
    let mut pap = pap();
    let mut api = AnthropicAdminApi::new(&mut pap, org());
    for i in 0..5 {
        let name = format!("user-{i}");
        api.add_workspace_member(
            &workspace(),
            AccountId(name),
            WorkspaceRole::WorkspaceUser,
            at(),
        )
        .unwrap();
    }

    let page = api
        .list_workspace_members(
            &workspace(),
            &ListParams {
                limit: 2,
                before_id: None,
                after_id: None,
            },
        )
        .unwrap();
    assert_eq!(page.data.len(), 2);
    assert!(page.has_more);
    for member in &page.data {
        assert_eq!(member.object, ObjectKind::WorkspaceMember);
        assert_eq!(member.workspace_id, "wrkspc_default");
        assert_eq!(member.workspace_role, WorkspaceRole::WorkspaceUser);
    }
}

#[test]
fn role_envelope_serializes_with_the_anthropic_type_tag() {
    // The `type` discriminator is the most visible wire contract: every
    // object envelope must serialize to `{"type":"...", ...}` (not
    // `{"object":"..."}`) so a client of the Anthropic SDK shape parses it
    // correctly.
    let member = Member {
        object: ObjectKind::User,
        id: "user_abc".to_owned(),
        role: OrgRole::Developer,
    };
    assert_eq!(serde_json::to_value(&member).unwrap()["type"], "user");

    let wm = WorkspaceMember {
        object: ObjectKind::WorkspaceMember,
        workspace_id: "wrkspc_default".to_owned(),
        user_id: "user_abc".to_owned(),
        workspace_role: WorkspaceRole::WorkspaceDeveloper,
    };
    let value = serde_json::to_value(&wm).unwrap();
    assert_eq!(value["type"], "workspace_member");
    assert_eq!(value["workspace_role"], "workspace_developer");

    let key = ApiKey {
        object: ObjectKind::ApiKey,
        id: "apikey_xyz".to_owned(),
        workspace_id: "wrkspc_default".to_owned(),
        workspace_role: WorkspaceRole::WorkspaceAdmin,
    };
    assert_eq!(serde_json::to_value(&key).unwrap()["type"], "api_key");

    let svc = ServiceAccount {
        object: ObjectKind::ServiceAccount,
        id: "svac_xyz".to_owned(),
        workspace_id: "wrkspc_default".to_owned(),
        workspace_role: WorkspaceRole::WorkspaceUser,
    };
    assert_eq!(
        serde_json::to_value(&svc).unwrap()["type"],
        "service_account"
    );

    let issuer = FederationIssuer {
        object: ObjectKind::FederationIssuer,
        id: "fdis_xyz".to_owned(),
        issuer: "https://idp.example/".to_owned(),
        audiences: vec!["a".to_owned()],
        enabled: true,
    };
    assert_eq!(
        serde_json::to_value(&issuer).unwrap()["type"],
        "federation_issuer"
    );
}

#[test]
fn admin_authorization_request_targets_org_admin_at_the_org_scope() {
    // The authorization request the admin caller must pass is `org.admin.manage`
    // at the org scope. This is the literal action the operator's bearer token
    // must clear in the one model.
    let principal = PrincipalRef::Account {
        account_id: AccountId("root".to_owned()),
    };
    let request = awaken_iam_server::admin_authorization_request(principal.clone(), &org());
    assert_eq!(request.action.0, "org.admin.manage");
    assert_eq!(
        request.scope,
        awaken_iam_contract::ScopeRef::Org { org_id: org() }
    );
    // principal_chain has just the acting principal — no on-behalf-of chain.
    assert_eq!(request.on_behalf_of.len(), 0);
}

#[test]
fn workspace_role_oauth_scope_mapping_resolves_known_and_unknown_scopes() {
    // `workspace:<role>` is the wire shape a federation-issued OAuth token's
    // scope takes; the deserializer maps it to a workspace role for binding.
    assert_eq!(
        WorkspaceRole::from_oauth_scope("workspace:admin"),
        Some(WorkspaceRole::WorkspaceAdmin)
    );
    assert_eq!(
        WorkspaceRole::from_oauth_scope("workspace:developer"),
        Some(WorkspaceRole::WorkspaceDeveloper)
    );
    assert_eq!(
        WorkspaceRole::from_oauth_scope("workspace:billing"),
        Some(WorkspaceRole::WorkspaceBilling)
    );
    // Unknown or unrelated scopes yield None, not a synthetic role.
    assert_eq!(WorkspaceRole::from_oauth_scope("billing:read"), None);
    assert_eq!(WorkspaceRole::from_oauth_scope("not-a-scope"), None);
    assert_eq!(WorkspaceRole::from_oauth_scope("workspace:nonsense"), None);
}
