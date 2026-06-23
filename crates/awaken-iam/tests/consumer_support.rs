//! Consumer-support contract tests, exercised against the **real** IAM engines
//! (not stand-ins) through the public `awaken-iam` facade.
//!
//! Where `consumer_integration.rs` pins the three *consumption modes* with a fake
//! remote, these tests prove the engines are *sufficient to manage* the three
//! concrete consumer domains named in the goal:
//!
//! - **awaken-next — managed agents:** entitlement + quota gating of agent runs
//!   and model tiers, evaluated by the real `EntitlementEngine`.
//! - **oversight-next — Workspace/Project:** the real authorization engine
//!   governs Workspace- and Project-scoped actions, including Workspace→Project
//!   grant inheritance and cross-workspace isolation, with the caller resolved
//!   through the real session core.
//! - **domain-pack permissions:** the real namespace trust directory owns
//!   namespaces, authorizes publish/read/yank and signer use, and binds/looks up
//!   signer keys, with a separate entitlement plane for private packs.

use awaken_iam::{
    AccountId, ActionKey, ActionPattern, AuthorizationDecision, AuthorizationRequest, AuthzApi,
    Effect, EntitlementCatalog, EntitlementDecision, EntitlementEngine, EntitlementRequest, Grant,
    GrantId, GrantSubject, NamespaceId, NamespaceOwner, NamespaceTrustDirectory, OrgId, Plan,
    PlanId, PlanTier, PrincipalRef, ProjectId, Quota, ScopeRef, Session, SessionDirectory,
    SessionId, SignerKey, SignerKeyAlgorithm, SignerKeyFingerprint, SignerKeyId, SignerKeyStatus,
    Timestamp, WorkspaceId,
};

fn service(id: &str) -> PrincipalRef {
    PrincipalRef::Service {
        service_id: id.into(),
    }
}

fn account(id: &str) -> PrincipalRef {
    PrincipalRef::Account {
        account_id: AccountId(id.into()),
    }
}

fn ts(value: &str) -> Timestamp {
    Timestamp(value.into())
}

// --- awaken-next: managed agents ------------------------------------------

/// awaken-next manages *managed agents* by gating who may run an agent, which
/// model tier they may use, and how many runs their plan allows. All three are
/// the entitlement plane's job; the real engine answers each with a distinct
/// reason, and the runtime capability/credential gating stays in-repo.
#[test]
fn awaken_next_manages_agent_runs_by_entitlement_and_quota() {
    let runner = service("agent:managed-runner");
    let free_runner = service("agent:free-runner");

    let mut catalog = EntitlementCatalog::new();
    catalog.upsert_plan(
        Plan::new(
            PlanId("team".into()),
            PlanTier::Team,
            ["agent.run", "model.strong_access"],
        )
        // The plan defines an inclusive ceiling on concurrent managed-agent runs;
        // awaken-next meters its own usage and supplies the observed count.
        .with_quota("agent.run", Quota::Limited(50)),
    );
    catalog.assign(runner.clone(), PlanId("team".into()));
    let engine = EntitlementEngine::local(catalog);

    let run = |principal: &PrincipalRef, feature: &str| EntitlementRequest {
        principal: principal.clone(),
        entitlement: feature.into(),
        resource: Some("workspace:ws_acme".into()),
    };

    // Who may run: the entitled runner may, with a plan_entitles reason.
    let allowed = engine.evaluate(&run(&runner, "agent.run"));
    assert_eq!(allowed.decision, EntitlementDecision::Allow);
    assert_eq!(allowed.reason.code(), "plan_entitles");

    // Which model tier: the plan entitles strong-model access but not a tier it
    // does not carry — fail closed with a distinct reason.
    assert_eq!(
        engine.check_entitlement(&run(&runner, "model.strong_access")),
        EntitlementDecision::Allow
    );
    let lacks = engine.evaluate(&run(&runner, "model.frontier_access"));
    assert_eq!(lacks.decision, EntitlementDecision::Deny);
    assert_eq!(lacks.reason.code(), "plan_lacks_feature");

    // How many: usage at the inclusive ceiling is allowed; strictly over it is
    // denied as quota_exceeded — IAM defines the ceiling, the caller meters.
    assert_eq!(
        engine.check_quota(&run(&runner, "agent.run"), 50).decision,
        EntitlementDecision::Allow
    );
    let over = engine.check_quota(&run(&runner, "agent.run"), 51);
    assert_eq!(over.decision, EntitlementDecision::Deny);
    assert_eq!(over.reason.code(), "quota_exceeded");

    // No plan: an unassigned runner fails closed (local mode is explicit policy,
    // never a permissive fallback).
    let no_plan = engine.evaluate(&run(&free_runner, "agent.run"));
    assert_eq!(no_plan.decision, EntitlementDecision::Deny);
    assert_eq!(no_plan.reason.code(), "no_plan_assigned");
}

// --- oversight-next: Workspace / Project ----------------------------------

/// oversight-next manages Workspace/Project permissions through the IAM
/// authorization engine: the caller is resolved through the IAM session core,
/// then a Workspace-scoped grant governs every Project beneath that workspace,
/// while a different workspace stays isolated. (Oversight keeps its own *domain*
/// actions like `issue.advance`; the structural Workspace/Project actions are
/// IAM's.)
#[test]
fn oversight_next_manages_workspace_and_project_scopes() {
    // AuthN is delegated to IAM: a live session resolves the acting account.
    let mut sessions = SessionDirectory::new();
    sessions
        .create_session(Session {
            id: SessionId("sess_ada".into()),
            account_id: AccountId("acct_ada".into()),
            token_hash: "hash-of-cookie".into(),
            external_identity_id: None,
            created_at: ts("2026-06-21T00:00:00Z"),
            last_seen_at: ts("2026-06-21T00:00:00Z"),
            expires_at: ts("2026-06-22T00:00:00Z"),
            revoked_at: None,
        })
        .unwrap();
    let authenticated = sessions
        .authenticate_by_token_hash("hash-of-cookie", ts("2026-06-21T06:00:00Z"))
        .unwrap();
    let principal = account(&authenticated.account_id.0);

    let ws_acme = WorkspaceId("ws_acme".into());
    let ws_other = WorkspaceId("ws_other".into());
    let project = |ws: &WorkspaceId, p: &str| ScopeRef::Project {
        workspace_id: ws.clone(),
        project_id: ProjectId(p.into()),
    };

    // A workspace admin holds project.* at the workspace, and workspace.configure
    // at the workspace itself.
    let mut api = AuthzApi::new();
    api.policy_mut().add_grant(Grant {
        id: GrantId("g_ws_projects".into()),
        subject: GrantSubject::Principal(principal.clone()),
        action_pattern: ActionPattern("project.*".into()),
        scope: ScopeRef::Workspace {
            workspace_id: ws_acme.clone(),
        },
        effect: Effect::Allow,
    });
    api.policy_mut().add_grant(Grant {
        id: GrantId("g_ws_configure".into()),
        subject: GrantSubject::Principal(principal.clone()),
        action_pattern: ActionPattern("workspace.configure".into()),
        scope: ScopeRef::Workspace {
            workspace_id: ws_acme.clone(),
        },
        effect: Effect::Allow,
    });

    let authorize = |action: &str, scope: ScopeRef| {
        api.authorize(&AuthorizationRequest::direct(
            principal.clone(),
            ActionKey(action.into()),
            scope,
        ))
    };

    // Workspace-scoped grant inherits onto every Project beneath that workspace.
    let configure = authorize("project.configure", project(&ws_acme, "proj_web"));
    assert_eq!(configure.decision, AuthorizationDecision::Allow);
    assert_eq!(configure.reason, "allowed_by_grant");
    assert_eq!(
        authorize("project.read", project(&ws_acme, "proj_support")).decision,
        AuthorizationDecision::Allow,
    );

    // The workspace-level action resolves at the workspace scope itself.
    assert_eq!(
        authorize(
            "workspace.configure",
            ScopeRef::Workspace {
                workspace_id: ws_acme.clone()
            }
        )
        .decision,
        AuthorizationDecision::Allow,
    );

    // Isolation: a project in a *different* workspace is not covered.
    assert_eq!(
        authorize("project.configure", project(&ws_other, "proj_x")).decision,
        AuthorizationDecision::Deny,
    );

    // No blanket authority: an org-level action the admin was never granted is
    // denied (no superuser wildcard).
    assert_eq!(
        authorize(
            "org.manage",
            ScopeRef::Org {
                org_id: OrgId("org_acme".into())
            }
        )
        .decision,
        AuthorizationDecision::Deny,
    );
}

// --- domain-pack permissions ----------------------------------------------

fn signer_key(ns: &str, id: &str, fingerprint: &str) -> SignerKey {
    SignerKey {
        id: SignerKeyId(id.into()),
        namespace_id: NamespaceId(ns.into()),
        fingerprint: SignerKeyFingerprint(fingerprint.into()),
        algorithm: SignerKeyAlgorithm::Ed25519,
        public_key: "base64-public-key".into(),
        status: SignerKeyStatus::Active,
        label: Some("release".into()),
        registered_at: ts("2026-06-21T00:00:00Z"),
        revoked_at: None,
    }
}

/// domain-pack permission management is the namespace trust directory's job: it
/// owns the namespace, authorizes publish/read/yank and signer use at namespace
/// scope, and binds/looks up the signer key publishing depends on — while a
/// separate entitlement plane gates private/paid packs.
#[test]
fn domain_pack_permissions_are_fully_managed_by_namespace_trust() {
    let acme = NamespaceId("acme".into());
    let publisher = service("pack-hub-publisher");
    let outsider = service("pack-hub-outsider");

    let mut trust = NamespaceTrustDirectory::new();
    trust.set_namespace_owner(NamespaceOwner {
        namespace_id: acme.clone(),
        owner_org_id: OrgId("org_acme".into()),
        created_at: ts("2026-06-21T00:00:00Z"),
    });
    assert!(trust.namespace_owner(&acme).is_some());

    // Publisher role: publish + read + yank + signer use.
    for action in ["pack.publish", "pack.read", "pack.yank", "namespace.signer.use"] {
        trust
            .grant(&acme, publisher.clone(), ActionKey(action.into()))
            .unwrap();
    }
    // Register the signing key bound to the namespace.
    let fingerprint = SignerKeyFingerprint("fp-release".into());
    trust
        .register_signer_key(signer_key("acme", "key_release", "fp-release"))
        .unwrap();

    let ns_scope = ScopeRef::Namespace {
        namespace_id: acme.clone(),
    };
    let may = |who: &PrincipalRef, action: &str| {
        trust.authorize(&AuthorizationRequest::direct(
            who.clone(),
            ActionKey(action.into()),
            ns_scope.clone(),
        )) == AuthorizationDecision::Allow
    };

    // Publish gate: the publisher holds both the publish and signer-use grants,
    // and the signer key resolves at verification time.
    assert!(may(&publisher, "pack.publish"));
    assert!(may(&publisher, "namespace.signer.use"));
    assert!(trust.lookup_signer(&acme, &fingerprint).is_some());
    assert!(trust.is_authorized_signer(&acme, &fingerprint));

    // Read and yank are independently governed by their own grants.
    assert!(may(&publisher, "pack.read"));
    assert!(may(&publisher, "pack.yank"));

    // An outsider with no grants is denied every namespace action — fail closed.
    assert!(!may(&outsider, "pack.publish"));
    assert!(!may(&outsider, "pack.read"));

    // Signer revocation is the trust-root signal: a revoked key no longer signs
    // new versions, so the verification-time lookup yields nothing.
    trust
        .revoke_signer_key(&acme, &SignerKeyId("key_release".into()), ts("2026-06-21T12:00:00Z"))
        .unwrap();
    assert!(trust.lookup_signer(&acme, &fingerprint).is_none());
    assert!(!trust.is_authorized_signer(&acme, &fingerprint));

    // Private/paid packs are a separate plane: entitlement gates read access
    // independently of the authorization grant above.
    let mut catalog = EntitlementCatalog::new();
    catalog.upsert_plan(Plan::new(
        PlanId("pro".into()),
        PlanTier::Pro,
        ["pack.read"],
    ));
    catalog.assign(publisher.clone(), PlanId("pro".into()));
    let entitlements = EntitlementEngine::local(catalog);
    let read_private = |who: &PrincipalRef| EntitlementRequest {
        principal: who.clone(),
        entitlement: "pack.read".into(),
        resource: Some("acme/private-pkg".into()),
    };
    assert_eq!(
        entitlements.check_entitlement(&read_private(&publisher)),
        EntitlementDecision::Allow
    );
    assert_eq!(
        entitlements.check_entitlement(&read_private(&outsider)),
        EntitlementDecision::Deny
    );
}
