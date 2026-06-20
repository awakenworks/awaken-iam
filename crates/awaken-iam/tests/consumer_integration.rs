//! Cross-consumer integration boundary contract tests.
//!
//! These tests pin the three consumption modes defined in
//! `docs/design/consumer-integration.md`, exercised through the public
//! `awaken-iam` facade — the same surface a product service integrates against:
//!
//! - Oversight Next delegates **authN only** and keeps its own authz engine;
//! - Oversight Pack Hub delegates **authorize() + namespace/signer checks**;
//! - Awaken Next delegates **entitlement gating only**, keeping runtime
//!   capability/permission gating and credentials in-repo.

use std::collections::HashSet;

use awaken_iam::{
    AccountId, ActionKey, AuthorizationDecision, AuthorizationRequest, EntitlementCatalog,
    EntitlementDecision, EntitlementEngine, EntitlementRequest, IamClient, IamServer, NamespaceId,
    Plan, PlanId, PlanTier, PrincipalRef, ScopeRef, Session, SessionDirectory, SessionId,
    Timestamp, WorkspaceId,
};

/// A stand-in for a remote IAM deployment used by consumers that delegate the
/// grant plane. It answers `authorize`/`check_entitlement` from an explicit set
/// of grants, so a contract test can model the exact call sequence a consumer
/// makes against the `IamClient` seam, with both allow and deny outcomes.
#[derive(Debug, Default)]
struct FakeRemoteIam {
    grants: HashSet<(PrincipalRef, ActionKey, ScopeRef)>,
    entitlements: HashSet<(PrincipalRef, String)>,
}

impl FakeRemoteIam {
    fn grant(mut self, principal: PrincipalRef, action: &str, scope: ScopeRef) -> Self {
        self.grants
            .insert((principal, ActionKey(action.into()), scope));
        self
    }

    fn entitle(mut self, principal: PrincipalRef, feature: &str) -> Self {
        self.entitlements.insert((principal, feature.into()));
        self
    }
}

impl IamClient for FakeRemoteIam {
    fn authorize(&self, request: AuthorizationRequest) -> AuthorizationDecision {
        if self
            .grants
            .contains(&(request.principal, request.action, request.scope))
        {
            AuthorizationDecision::Allow
        } else {
            AuthorizationDecision::Deny
        }
    }

    fn check_entitlement(&self, request: EntitlementRequest) -> EntitlementDecision {
        if self
            .entitlements
            .contains(&(request.principal, request.entitlement))
        {
            EntitlementDecision::Allow
        } else {
            EntitlementDecision::Deny
        }
    }
}

fn service(id: &str) -> PrincipalRef {
    PrincipalRef::Service {
        service_id: id.into(),
    }
}

/// Oversight Next delegates **authentication only**: it resolves the caller
/// through the IAM session core, then runs its own authorization engine over its
/// own domain. It does not consult the IAM grant plane for domain decisions, so
/// the IAM grant plane denying the same action must not change the outcome.
#[test]
fn oversight_next_delegates_authn_only() {
    // AuthN is delegated to IAM: a live session resolves the caller's account.
    let mut sessions = SessionDirectory::new();
    sessions
        .create_session(Session {
            id: SessionId("sess_1".into()),
            account_id: AccountId("acct_ada".into()),
            token_hash: "hash-of-cookie".into(),
            external_identity_id: None,
            created_at: Timestamp("2026-06-19T00:00:00Z".into()),
            last_seen_at: Timestamp("2026-06-19T00:00:00Z".into()),
            expires_at: Timestamp("2026-06-20T00:00:00Z".into()),
            revoked_at: None,
        })
        .unwrap();
    let authenticated = sessions
        .authenticate_by_token_hash("hash-of-cookie", Timestamp("2026-06-19T06:00:00Z".into()))
        .unwrap();
    let principal = PrincipalRef::Account {
        account_id: authenticated.account_id.clone(),
    };

    // AuthZ is NOT delegated. Oversight owns its domain authorization; the IAM
    // grant plane returns deny for an Oversight domain action because IAM does
    // not own that decision.
    let iam = FakeRemoteIam::default();
    let domain_action = AuthorizationRequest {
        principal: principal.clone(),
        on_behalf_of: Vec::new(),
        action: ActionKey("issue.advance".into()),
        scope: ScopeRef::Project {
            workspace_id: WorkspaceId("ws_acme".into()),
            project_id: awaken_iam::ProjectId("proj_web".into()),
        },
    };
    assert_eq!(
        iam.authorize(domain_action),
        AuthorizationDecision::Deny,
        "IAM must not own Oversight domain authorization"
    );

    // Oversight's own engine decides the same action and allows it for the
    // authenticated principal. This is the boundary: IAM resolves *who*,
    // Oversight decides *what*.
    let product_engine = OversightAuthz::default().allow(&principal, "issue.advance");
    assert!(product_engine.may(&principal, "issue.advance"));
    assert!(!product_engine.may(&service("intruder"), "issue.advance"));
}

/// Oversight Next's in-repo authorization engine. It never calls IAM; it decides
/// purely over product-owned grants. Modeled minimally for the contract test.
#[derive(Debug, Default)]
struct OversightAuthz {
    allowed: HashSet<(PrincipalRef, String)>,
}

impl OversightAuthz {
    fn allow(mut self, principal: &PrincipalRef, action: &str) -> Self {
        self.allowed.insert((principal.clone(), action.into()));
        self
    }

    fn may(&self, principal: &PrincipalRef, action: &str) -> bool {
        self.allowed.contains(&(principal.clone(), action.into()))
    }
}

/// Oversight Pack Hub delegates authorization to IAM. A publish requires both
/// the namespace publish grant and the signer-use grant, plus an entitlement —
/// all against the IAM seam. Missing the signer grant blocks the publish even
/// when `pack.publish` is held.
#[test]
fn oversight_pack_hub_uses_remote_authorize_and_signer_checks() {
    let publisher = service("pack-hub-publisher");
    let namespace = ScopeRef::Namespace {
        namespace_id: NamespaceId("acme".into()),
    };

    let iam = FakeRemoteIam::default()
        .grant(publisher.clone(), "pack.publish", namespace.clone())
        .grant(publisher.clone(), "namespace.signer.use", namespace.clone())
        .entitle(publisher.clone(), "pack.publish");

    assert!(
        pack_hub_can_publish(&iam, &publisher, &namespace),
        "publisher with both grants and entitlement may publish"
    );

    // A principal holding only the publish grant but lacking signer-use cannot
    // sign and publish — proving both authorize() checks are required.
    let unsigned = service("pack-hub-no-signer");
    let iam_no_signer = FakeRemoteIam::default()
        .grant(unsigned.clone(), "pack.publish", namespace.clone())
        .entitle(unsigned.clone(), "pack.publish");
    assert!(
        !pack_hub_can_publish(&iam_no_signer, &unsigned, &namespace),
        "missing namespace.signer.use must block publish"
    );

    // Entitlement is its own plane: grants without the SKU also block.
    let unentitled = service("pack-hub-free-tier");
    let iam_unentitled = FakeRemoteIam::default()
        .grant(unentitled.clone(), "pack.publish", namespace.clone())
        .grant(
            unentitled.clone(),
            "namespace.signer.use",
            namespace.clone(),
        );
    assert!(
        !pack_hub_can_publish(&iam_unentitled, &unentitled, &namespace),
        "missing entitlement must block publish"
    );
}

/// Pack Hub's publish gate: two grant checks plus an entitlement check, all
/// delegated to the IAM seam.
fn pack_hub_can_publish(
    iam: &impl IamClient,
    principal: &PrincipalRef,
    namespace: &ScopeRef,
) -> bool {
    let can_publish = iam.authorize(AuthorizationRequest {
        principal: principal.clone(),
        on_behalf_of: Vec::new(),
        action: ActionKey("pack.publish".into()),
        scope: namespace.clone(),
    }) == AuthorizationDecision::Allow;
    let can_sign = iam.authorize(AuthorizationRequest {
        principal: principal.clone(),
        on_behalf_of: Vec::new(),
        action: ActionKey("namespace.signer.use".into()),
        scope: namespace.clone(),
    }) == AuthorizationDecision::Allow;
    let entitled = iam.check_entitlement(EntitlementRequest {
        principal: principal.clone(),
        entitlement: "pack.publish".into(),
        resource: Some("acme/pkg".into()),
    }) == EntitlementDecision::Allow;
    can_publish && can_sign && entitled
}

/// Awaken Next delegates **entitlement gating only**. A run is gated by
/// `check_entitlement` against a real local entitlement plan; runtime capability
/// gating and credentials stay in-repo. A principal whose plan lacks the feature
/// fails closed.
#[test]
fn awaken_next_uses_entitlement_gating_only() {
    let runner = service("awaken-runner");
    let free_runner = service("awaken-runner-free");

    // IAM owns the plan/SKU plane. The runner's plan entitles strong-model
    // access; the free runner has no plan and fails closed.
    let mut catalog = EntitlementCatalog::new();
    catalog.upsert_plan(Plan::new(
        PlanId("team".into()),
        PlanTier::Team,
        ["model.strong_access"],
    ));
    catalog.assign(runner.clone(), PlanId("team".into()));
    let iam = IamServer::with_entitlements(EntitlementEngine::local(catalog));

    let workspace = ScopeRef::Workspace {
        workspace_id: WorkspaceId("ws_acme".into()),
    };

    // Runtime capability gating + credentials are resolved in-repo and never
    // routed through IAM.
    let runtime = AwakenRuntime::default()
        .with_capability("model.invoke")
        .with_credential("anthropic_api_key");

    assert!(
        awaken_can_run(&iam, &runtime, &runner, &workspace),
        "entitled runner with the local capability and credential may run"
    );

    // Plan lacks the feature -> entitlement plane fails closed -> run blocked.
    assert!(
        !awaken_can_run(&iam, &runtime, &free_runner, &workspace),
        "unentitled runner must be blocked by the entitlement gate"
    );

    // Entitlement passes but the runtime capability is absent -> still blocked,
    // and that decision is made locally, not by IAM.
    let no_capability = AwakenRuntime::default().with_credential("anthropic_api_key");
    assert!(
        !awaken_can_run(&iam, &no_capability, &runner, &workspace),
        "missing in-repo runtime capability must block the run"
    );
}

/// Awaken Next's in-repo runtime: capability/permission gating and product-owned
/// credentials. IAM never sees either.
#[derive(Debug, Default)]
struct AwakenRuntime {
    capabilities: HashSet<String>,
    credentials: HashSet<String>,
}

impl AwakenRuntime {
    fn with_capability(mut self, capability: &str) -> Self {
        self.capabilities.insert(capability.into());
        self
    }

    fn with_credential(mut self, credential: &str) -> Self {
        self.credentials.insert(credential.into());
        self
    }

    fn permits(&self, capability: &str) -> bool {
        self.capabilities.contains(capability)
    }

    fn holds(&self, credential: &str) -> bool {
        self.credentials.contains(credential)
    }
}

/// Awaken Next's run gate: IAM answers entitlement; the runtime answers
/// capability and holds the credential.
fn awaken_can_run(
    iam: &impl IamClient,
    runtime: &AwakenRuntime,
    principal: &PrincipalRef,
    workspace: &ScopeRef,
) -> bool {
    let _ = workspace;
    let entitled = iam.check_entitlement(EntitlementRequest {
        principal: principal.clone(),
        entitlement: "model.strong_access".into(),
        resource: Some("workspace:ws_acme".into()),
    }) == EntitlementDecision::Allow;
    entitled && runtime.permits("model.invoke") && runtime.holds("anthropic_api_key")
}
