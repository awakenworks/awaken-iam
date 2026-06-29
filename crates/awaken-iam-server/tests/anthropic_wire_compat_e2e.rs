//! Wire-compatibility verification against Anthropic's published Admin API
//! contract (platform.claude.com/docs/en/api/admin-api).
//!
//! Each test below pins a shape documented by Anthropic and checks our
//! rendering against it. The intent is to catch drift between our
//! Anthropic-compatible surface and the real platform contract.
//!
//! Documented shapes captured 2026-06-29 from:
//!   - List/Get Users:            /v1/organizations/users[/{user_id}]
//!   - List/Get Workspace Members:/v1/organizations/workspaces/{id}/members
//!   - List/Get API Keys:         /v1/organizations/api_keys[/{id}]
//!
//! Where our surface intentionally or structurally diverges, the test asserts
//! our *current* output and the comment states the divergence explicitly, so
//! the gap is regression-locked and visible rather than silently wrong.

use awaken_iam_server::{
    ApiKey, DEFAULT_PAGE_LIMIT, FederationIssuer, ListParams, MAX_PAGE_LIMIT, Member, ObjectKind,
    OrgRole, ServiceAccount, WorkspaceMember, WorkspaceRole, project_federation_issuers,
};

// ----------------------------------------------------------------------------
// Object `type` discriminators — Anthropic stamps every object with a `type`.
// ----------------------------------------------------------------------------

#[test]
fn object_type_tags_match_anthropic_exact_strings() {
    // Anthropic: User -> "user", WorkspaceMember -> "workspace_member",
    // ApiKey -> "api_key", ServiceAccount -> "service_account",
    // FederationIssuer -> "federation_issuer", FederationRule -> "federation_rule".
    let cases = [
        (ObjectKind::User, "user"),
        (ObjectKind::WorkspaceMember, "workspace_member"),
        (ObjectKind::ApiKey, "api_key"),
        (ObjectKind::ServiceAccount, "service_account"),
        (ObjectKind::FederationIssuer, "federation_issuer"),
        (ObjectKind::FederationRule, "federation_rule"),
    ];
    for (kind, expected) in cases {
        let json = serde_json::to_value(kind).unwrap();
        assert_eq!(
            json, expected,
            "object kind {kind:?} must serialize to {expected}"
        );
    }
}

// ----------------------------------------------------------------------------
// Organization role enum — Anthropic documents exactly these five strings.
// ----------------------------------------------------------------------------

#[test]
fn org_role_enum_matches_anthropic_exact_strings() {
    // Anthropic User.role enum: user, developer, billing, admin, claude_code_user.
    let cases = [
        (OrgRole::User, "user"),
        (OrgRole::Developer, "developer"),
        (OrgRole::Billing, "billing"),
        (OrgRole::Admin, "admin"),
        (OrgRole::ClaudeCodeUser, "claude_code_user"),
    ];
    for (role, expected) in cases {
        assert_eq!(serde_json::to_value(role).unwrap(), expected);
        assert_eq!(role.as_str(), expected);
    }
    // The exact documented set, no more and no fewer.
    let all: std::collections::BTreeSet<&str> = cases.iter().map(|(_, s)| *s).collect();
    assert_eq!(
        all,
        ["admin", "billing", "claude_code_user", "developer", "user"]
            .into_iter()
            .collect()
    );
}

// ----------------------------------------------------------------------------
// Workspace role enum — Anthropic documents exactly these five strings,
// including `workspace_restricted_developer` (NOT `..._limited_...`).
// ----------------------------------------------------------------------------

#[test]
fn workspace_role_enum_matches_anthropic_exact_strings() {
    let cases = [
        (WorkspaceRole::WorkspaceUser, "workspace_user"),
        (WorkspaceRole::WorkspaceDeveloper, "workspace_developer"),
        (
            WorkspaceRole::WorkspaceRestrictedDeveloper,
            "workspace_restricted_developer",
        ),
        (WorkspaceRole::WorkspaceAdmin, "workspace_admin"),
        (WorkspaceRole::WorkspaceBilling, "workspace_billing"),
    ];
    for (role, expected) in cases {
        assert_eq!(
            serde_json::to_value(role).unwrap(),
            expected,
            "workspace role {role:?} must serialize to Anthropic's {expected}"
        );
        assert_eq!(role.as_str(), expected);
        // Round-trips through the catalog id parser.
        assert_eq!(
            WorkspaceRole::from_role_id(&awaken_iam_core::RoleId(expected.to_owned())).unwrap(),
            role
        );
    }
}

#[test]
fn workspace_oauth_scope_maps_restricted_developer() {
    // Federation scope `workspace:restricted_developer` must resolve to the
    // restricted-developer role, matching the renamed Anthropic catalog id.
    assert_eq!(
        WorkspaceRole::from_oauth_scope("workspace:restricted_developer"),
        Some(WorkspaceRole::WorkspaceRestrictedDeveloper)
    );
    // The old (incompatible) name must no longer resolve.
    assert_eq!(
        WorkspaceRole::from_oauth_scope("workspace:limited_developer"),
        None
    );
}

// ----------------------------------------------------------------------------
// Pagination envelope + limit range.
// ----------------------------------------------------------------------------

#[test]
fn pagination_defaults_and_range_match_anthropic() {
    // Anthropic: limit defaults to 20, ranges 1..=1000.
    assert_eq!(
        DEFAULT_PAGE_LIMIT, 20,
        "default page size must match Anthropic"
    );
    assert_eq!(
        MAX_PAGE_LIMIT, 1000,
        "max page size must match Anthropic's 1000"
    );
    assert_eq!(ListParams::default().limit, DEFAULT_PAGE_LIMIT);
}

#[test]
fn page_limit_boundary_accepts_1000_and_rejects_1001_and_0() {
    // A real client may ask for the documented maximum of 1000; our paginator
    // must accept it and reject 0 / 1001.
    let issuers: Vec<awaken_iam_server::TrustedIssuer> = Vec::new();

    // limit = 1000 (the documented max) is accepted.
    assert!(
        project_federation_issuers(
            &issuers,
            &ListParams {
                limit: 1000,
                before_id: None,
                after_id: None
            }
        )
        .is_ok()
    );

    // limit = 1001 is rejected as out of range.
    assert!(matches!(
        project_federation_issuers(
            &issuers,
            &ListParams {
                limit: 1001,
                before_id: None,
                after_id: None
            }
        ),
        Err(awaken_iam_server::AdminApiError::InvalidLimit(1001))
    ));

    // limit = 0 is rejected.
    assert!(matches!(
        project_federation_issuers(
            &issuers,
            &ListParams {
                limit: 0,
                before_id: None,
                after_id: None
            }
        ),
        Err(awaken_iam_server::AdminApiError::InvalidLimit(0))
    ));
}

#[test]
fn list_envelope_uses_anthropic_field_names() {
    // Anthropic list envelope: { data: [...], has_more, first_id, last_id }.
    let issuers: Vec<awaken_iam_server::TrustedIssuer> = vec![awaken_iam_server::TrustedIssuer {
        issuer: "https://idp.example/".to_owned(),
        keys: awaken_iam_contract::Jwks { keys: Vec::new() },
        audiences: vec!["aud".to_owned()],
        bindings: Vec::new(),
        enabled: true,
    }];
    let page = project_federation_issuers(&issuers, &ListParams::default()).unwrap();
    let json = serde_json::to_value(&page).unwrap();
    assert!(json.get("data").is_some(), "must carry `data`");
    assert!(json.get("has_more").is_some(), "must carry `has_more`");
    assert!(json.get("first_id").is_some(), "must carry `first_id`");
    assert!(json.get("last_id").is_some(), "must carry `last_id`");
    assert!(json["data"].is_array());
}

// ----------------------------------------------------------------------------
// WorkspaceMember object — our fields match Anthropic exactly.
// ----------------------------------------------------------------------------

#[test]
fn workspace_member_object_matches_anthropic_field_set() {
    // Anthropic WorkspaceMember: { type, user_id, workspace_id, workspace_role }.
    let wm = WorkspaceMember {
        object: ObjectKind::WorkspaceMember,
        workspace_id: "wrkspc_01JwQvzr7rXLA5AGx3HKfFUJ".to_owned(),
        user_id: "user_01WCz1FkmYMm4gnmykNKUu3Q".to_owned(),
        workspace_role: WorkspaceRole::WorkspaceUser,
    };
    let json = serde_json::to_value(&wm).unwrap();
    assert_eq!(json["type"], "workspace_member");
    assert_eq!(json["user_id"], "user_01WCz1FkmYMm4gnmykNKUu3Q");
    assert_eq!(json["workspace_id"], "wrkspc_01JwQvzr7rXLA5AGx3HKfFUJ");
    assert_eq!(json["workspace_role"], "workspace_user");
    // No extra fields beyond Anthropic's four.
    let obj = json.as_object().unwrap();
    let keys: std::collections::BTreeSet<&str> = obj.keys().map(|s| s.as_str()).collect();
    assert_eq!(
        keys,
        ["type", "user_id", "workspace_id", "workspace_role"]
            .into_iter()
            .collect(),
        "WorkspaceMember must carry exactly Anthropic's four fields"
    );
}

// ----------------------------------------------------------------------------
// Prefixed ids — Anthropic uses wrkspc_/svac_/fdis_ prefixes.
// ----------------------------------------------------------------------------

#[test]
fn workspace_and_service_account_ids_carry_anthropic_prefixes() {
    assert_eq!(awaken_iam_server::WORKSPACE_ID_PREFIX, "wrkspc_");
    assert_eq!(awaken_iam_server::SERVICE_ACCOUNT_ID_PREFIX, "svac_");
    assert_eq!(awaken_iam_server::FEDERATION_ISSUER_ID_PREFIX, "fdis_");
    assert_eq!(awaken_iam_server::FEDERATION_RULE_ID_PREFIX, "fdrl_");

    let svc = ServiceAccount {
        object: ObjectKind::ServiceAccount,
        id: "svac_ci".to_owned(),
        workspace_id: "wrkspc_default".to_owned(),
        workspace_role: WorkspaceRole::WorkspaceDeveloper,
    };
    assert!(
        serde_json::to_value(&svc).unwrap()["id"]
            .as_str()
            .unwrap()
            .starts_with("svac_")
    );

    let iss = FederationIssuer {
        object: ObjectKind::FederationIssuer,
        id: "fdis_x".to_owned(),
        issuer: "https://idp.example/".to_owned(),
        audiences: vec!["a".to_owned()],
        enabled: true,
    };
    assert!(
        serde_json::to_value(&iss).unwrap()["id"]
            .as_str()
            .unwrap()
            .starts_with("fdis_")
    );
}

// ----------------------------------------------------------------------------
// KNOWN DIVERGENCES — pinned so they are visible and regression-locked.
// These document where our surface is NOT yet wire-compatible with Anthropic.
// ----------------------------------------------------------------------------

#[test]
fn divergence_user_object_is_missing_documented_fields() {
    // Anthropic User: { id, added_at, email, name, role, type }.
    // Ours (Member): { type, id, role } — MISSING added_at, email, name.
    //
    // Reason: IAM does not own user profile data (email/name) — that is product
    // runtime data the IAM contract deliberately excludes (AGENTS.md G4). Closing
    // this gap needs a product decision on whether IAM proxies profile fields.
    let member = Member {
        object: ObjectKind::User,
        id: "ada".to_owned(),
        role: OrgRole::Developer,
    };
    let json = serde_json::to_value(&member).unwrap();
    let keys: std::collections::BTreeSet<&str> = json
        .as_object()
        .unwrap()
        .keys()
        .map(|s| s.as_str())
        .collect();
    // Current shape: exactly these three. (When the gap is closed, update this.)
    assert_eq!(keys, ["type", "id", "role"].into_iter().collect());
    assert!(
        json.get("email").is_none(),
        "DIVERGENCE: no email field yet"
    );
    assert!(json.get("name").is_none(), "DIVERGENCE: no name field yet");
    assert!(
        json.get("added_at").is_none(),
        "DIVERGENCE: no added_at field yet"
    );
}

#[test]
fn divergence_api_key_object_shape_differs_from_anthropic() {
    // Anthropic APIKey: { id, created_at, created_by, expires_at, name,
    //   partial_key_hint, status, type, workspace_id }.
    // Ours (ApiKey): { type, id, workspace_id, workspace_role } — it carries a
    // `workspace_role` (authority binding) and omits the credential-lifecycle
    // fields. ADR-0008 sequences the `sk-ant-` key rendering separately; today
    // an API key is modeled purely as a workspace role binding.
    let key = ApiKey {
        object: ObjectKind::ApiKey,
        id: "apikey_01Rj2N8SVvo6BePZj99NhmiT".to_owned(),
        workspace_id: "wrkspc_default".to_owned(),
        workspace_role: WorkspaceRole::WorkspaceDeveloper,
    };
    let json = serde_json::to_value(&key).unwrap();
    assert_eq!(json["type"], "api_key");
    // The binding-authority field we add (not in Anthropic's shape).
    assert_eq!(json["workspace_role"], "workspace_developer");
    // Documented-but-absent credential-lifecycle fields:
    for absent in [
        "created_at",
        "created_by",
        "expires_at",
        "name",
        "partial_key_hint",
        "status",
    ] {
        assert!(
            json.get(absent).is_none(),
            "DIVERGENCE: api_key.{absent} not modeled yet"
        );
    }
}
