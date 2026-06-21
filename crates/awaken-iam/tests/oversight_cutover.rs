//! Oversight reuses the IAM authorization plane — ResourceModel registration and
//! the Strangler-Fig shadow cutover (ADR-0004 #1 and #5).
//!
//! Where `consumer_integration.rs` pins the *historical* baseline (Oversight
//! delegating authN only and keeping its own engine), these tests pin the
//! migration the ADR mandates: Oversight stops carrying its own authorization
//! engine and reuses IAM's full capability.
//!
//! Two pieces make that possible, both proven here against the **real** engines
//! through the public `awaken-iam` facade:
//!
//! - **ResourceModel registration (ADR-0004 #1).** Oversight teaches IAM its
//!   resource types (`issue`, `run`, `thread`, `team`), their action catalogs,
//!   and their per-instance scope parent edges *as data*. IAM then resolves
//!   Oversight's hierarchy (`run -> issue -> project -> workspace`) through the
//!   same scope-graph walk it uses for the well-known scopes — the core never
//!   learns the product. The rich actor taxonomy
//!   (`User`/`Agent`/`ProcessAgent`/`System`/`Team`) resolves down to the shared
//!   shapes (`Account`/`Service`/`Group`) at the call boundary, per the
//!   `consumer-integration` mapping table.
//!
//! - **Strangler shadow cutover (ADR-0004 #5).** The enforcement point runs
//!   Oversight's incumbent engine and IAM in shadow through [`ShadowAuthorizer`].
//!   The incumbent stays authoritative while the IAM candidate is compared but
//!   never enforced. Divergence is burned down to measured parity, then the flag
//!   flips and IAM alone decides — at which point the in-repo engine can be
//!   deleted.

use awaken_iam::{
    AccountId, ActionKey, ActionPattern, AuthorizationDecision, AuthorizationRequest, Effect,
    Grant, GrantId, GrantSubject, IamCore, PrincipalRef, ProjectId, ResourceId, ResourceModel,
    ResourceType, ResourceTypeDef, RoleBinding, RoleId, ScopeRef, ShadowAuthorizer, WorkspaceId,
};

// --- Oversight's product-local vocabulary ---------------------------------
//
// Oversight keeps its rich actor taxonomy and resolves it down to the three
// shared `PrincipalRef` variants at the IAM call boundary. IAM never learns
// these kinds; the `service_id` prefix convention keeps the distinction legible
// in audit traces without leaking a product enum into the contract.

/// Oversight's actor taxonomy. `Team` is intentionally absent: a team is never a
/// principal — it is a membership target (a `Group`), so no request is made "as a
/// Team".
#[derive(Debug, Clone)]
enum Actor {
    /// A human account principal.
    User(String),
    /// A product agent actor.
    Agent(String),
    /// A process / automation actor.
    ProcessAgent(String),
    /// The platform / system actor.
    System(String),
}

impl Actor {
    /// Resolve the rich actor down to the shared `PrincipalRef` at the boundary,
    /// following the `consumer-integration` prefix convention.
    fn to_principal_ref(&self) -> PrincipalRef {
        match self {
            Actor::User(id) => PrincipalRef::Account {
                account_id: AccountId(id.clone()),
            },
            Actor::Agent(id) => PrincipalRef::Service {
                service_id: format!("agent:{id}"),
            },
            Actor::ProcessAgent(id) => PrincipalRef::Service {
                service_id: format!("process:{id}"),
            },
            Actor::System(name) => PrincipalRef::Service {
                service_id: format!("system:{name}"),
            },
        }
    }
}

/// An Oversight domain resource. Each resolves down to a `ScopeRef::Resource`
/// anchored by its registered type and id; its place in the hierarchy comes from
/// the parent edges the resource model registers, never from the ids.
#[derive(Debug, Clone)]
enum Resource {
    Issue(String),
    Run(String),
    Thread(String),
    Team(String),
}

impl Resource {
    fn scope(&self) -> ScopeRef {
        let (resource_type, id) = match self {
            Resource::Issue(id) => ("issue", id),
            Resource::Run(id) => ("run", id),
            Resource::Thread(id) => ("thread", id),
            Resource::Team(id) => ("team", id),
        };
        ScopeRef::Resource {
            resource_type: ResourceType(resource_type.into()),
            resource_id: ResourceId(id.clone()),
        }
    }
}

fn workspace() -> WorkspaceId {
    WorkspaceId("ws_acme".into())
}

fn web_project() -> ScopeRef {
    ScopeRef::Project {
        workspace_id: workspace(),
        project_id: ProjectId("proj_web".into()),
    }
}

/// Build the Oversight resource model: the four resource types with their action
/// catalogs, and the per-instance parent edges that place this scenario's
/// resources in the hierarchy. `include_run_edges` lets a test register the model
/// with the `run -> issue` edges deliberately missing, to drive a divergence the
/// shadow harness then catches.
fn oversight_resource_model(include_run_edges: bool) -> ResourceModel {
    let mut model = ResourceModel::new();
    model
        .register_resource_type(ResourceTypeDef {
            resource_type: ResourceType("issue".into()),
            parent_type: None,
            actions: vec![
                ActionKey("issue.read".into()),
                ActionKey("issue.comment".into()),
                ActionKey("issue.advance".into()),
                ActionKey("issue.close".into()),
            ],
        })
        .register_resource_type(ResourceTypeDef {
            resource_type: ResourceType("run".into()),
            parent_type: Some(ResourceType("issue".into())),
            actions: vec![
                ActionKey("run.read".into()),
                ActionKey("run.start".into()),
                ActionKey("run.cancel".into()),
            ],
        })
        .register_resource_type(ResourceTypeDef {
            resource_type: ResourceType("thread".into()),
            parent_type: Some(ResourceType("issue".into())),
            actions: vec![
                ActionKey("thread.read".into()),
                ActionKey("thread.post".into()),
            ],
        })
        .register_resource_type(ResourceTypeDef {
            resource_type: ResourceType("team".into()),
            parent_type: None,
            actions: vec![
                ActionKey("team.read".into()),
                ActionKey("team.manage".into()),
            ],
        });

    // issue:42 nests under the web project; thread:3 under issue:42; team:triage
    // under the workspace. The team is a roster anchored in the workspace, not an
    // ancestor of issues.
    model
        .register_parent(
            ResourceType("issue".into()),
            ResourceId("iss_42".into()),
            web_project(),
        )
        .register_parent(
            ResourceType("thread".into()),
            ResourceId("thr_3".into()),
            Resource::Issue("iss_42".into()).scope(),
        )
        .register_parent(
            ResourceType("team".into()),
            ResourceId("triage".into()),
            ScopeRef::Workspace {
                workspace_id: workspace(),
            },
        );

    if include_run_edges {
        // run:7 executes against issue:42. Without this edge IAM cannot resolve
        // run:7's place in the hierarchy and a grant inherited from above it
        // cannot reach the run — exactly the divergence the cutover must catch.
        model.register_parent(
            ResourceType("run".into()),
            ResourceId("run_7".into()),
            Resource::Issue("iss_42".into()).scope(),
        );
    }

    model
}

/// The triage team role. Members hold `issue.read` + `thread.read` at the team's
/// operating scope (the web project), so joining the team confers the role's
/// grants. `Team` resolves to a `Group` (the roster); membership is expressed as
/// a role binding per member at the operating scope, which is the inheritance the
/// engine supports today (dynamic `Group`-as-subject resolution lands with its
/// own issue, ADR-0004 #2).
fn triage_role() -> RoleId {
    RoleId("oversight.triage".into())
}

/// Build the IAM authorization core for the Oversight scenario: register the
/// resource model, then load the grants and role bindings the product writes when
/// it provisions workspaces, agents, system automation, and team membership.
fn oversight_iam(include_run_edges: bool) -> IamCore {
    let mut core = IamCore::new();
    let policy = core.policy_mut();
    policy.register_resource_model(&oversight_resource_model(include_run_edges));

    // Ada is a workspace admin: full authority anywhere under the workspace.
    policy.add_grant(Grant {
        id: GrantId("g_ada_admin".into()),
        subject: GrantSubject::Principal(Actor::User("ada".into()).to_principal_ref()),
        action_pattern: ActionPattern("*".into()),
        scope: ScopeRef::Workspace {
            workspace_id: workspace(),
        },
        effect: Effect::Allow,
    });

    // The CI agent may start and manage runs on issue:42, and nothing else.
    policy.add_grant(Grant {
        id: GrantId("g_bot_runs".into()),
        subject: GrantSubject::Principal(Actor::Agent("ci-bot".into()).to_principal_ref()),
        action_pattern: ActionPattern("run.*".into()),
        scope: Resource::Issue("iss_42".into()).scope(),
        effect: Effect::Allow,
    });

    // A process agent may start runs on issue:42 when acting for a user.
    policy.add_grant(Grant {
        id: GrantId("g_proc_runs".into()),
        subject: GrantSubject::Principal(
            Actor::ProcessAgent("scheduler".into()).to_principal_ref(),
        ),
        action_pattern: ActionPattern("run.start".into()),
        scope: Resource::Issue("iss_42".into()).scope(),
        effect: Effect::Allow,
    });

    // System automation advances issues platform-wide.
    policy.add_grant(Grant {
        id: GrantId("g_system_advance".into()),
        subject: GrantSubject::Principal(Actor::System("automation".into()).to_principal_ref()),
        action_pattern: ActionPattern("issue.advance".into()),
        scope: ScopeRef::Global,
        effect: Effect::Allow,
    });

    // The triage role carries read access at the web project; team members are
    // bound to it.
    policy.add_grant(Grant {
        id: GrantId("g_triage_issue_read".into()),
        subject: GrantSubject::Role(triage_role()),
        action_pattern: ActionPattern("issue.read".into()),
        scope: web_project(),
        effect: Effect::Allow,
    });
    policy.add_grant(Grant {
        id: GrantId("g_triage_thread_read".into()),
        subject: GrantSubject::Role(triage_role()),
        action_pattern: ActionPattern("thread.read".into()),
        scope: web_project(),
        effect: Effect::Allow,
    });
    // Lin joined the triage team, so the binding gives Lin the role's grants.
    policy.bind_role(RoleBinding {
        principal: Actor::User("lin".into()).to_principal_ref(),
        role: triage_role(),
        scope: web_project(),
    });

    core
}

// --- Oversight's incumbent engine -----------------------------------------
//
// A compact, *independent* re-implementation of Oversight's in-repo authorization
// engine: it resolves its own product hierarchy over its own grant table. It
// shares no code with IAM, so when both agree on a request battery the agreement
// is meaningful — it proves the IAM mapping is faithful, not tautological. It
// consumes the same shared-shape `AuthorizationRequest` the enforcement point
// already builds (the incumbent adapted through the harness, per the shadow
// design).

#[derive(Debug, Clone)]
enum IncumbentSubject {
    Principal(PrincipalRef),
    Role(RoleId),
}

#[derive(Debug, Clone)]
struct IncumbentGrant {
    subject: IncumbentSubject,
    action_prefix: String,
    scope: ScopeRef,
}

#[derive(Debug, Default)]
struct OversightLegacyAuthz {
    /// child scope -> immediate parent scope.
    parents: std::collections::HashMap<ScopeRef, ScopeRef>,
    grants: Vec<IncumbentGrant>,
    /// principal -> roles the principal holds (membership, already expanded).
    roles: std::collections::HashMap<PrincipalRef, Vec<RoleId>>,
}

impl OversightLegacyAuthz {
    fn link(&mut self, child: ScopeRef, parent: ScopeRef) -> &mut Self {
        self.parents.insert(child, parent);
        self
    }

    fn grant_principal(&mut self, who: PrincipalRef, action_prefix: &str, scope: ScopeRef) {
        self.grants.push(IncumbentGrant {
            subject: IncumbentSubject::Principal(who),
            action_prefix: action_prefix.into(),
            scope,
        });
    }

    fn grant_role(&mut self, role: RoleId, action_prefix: &str, scope: ScopeRef) {
        self.grants.push(IncumbentGrant {
            subject: IncumbentSubject::Role(role),
            action_prefix: action_prefix.into(),
            scope,
        });
    }

    fn add_member(&mut self, who: PrincipalRef, role: RoleId) {
        self.roles.entry(who).or_default().push(role);
    }

    /// Walk a scope and its registered ancestors, nearest first.
    fn ancestry(&self, scope: &ScopeRef) -> Vec<ScopeRef> {
        let mut chain = vec![scope.clone()];
        let mut current = scope.clone();
        while let Some(parent) = self.parents.get(&current) {
            chain.push(parent.clone());
            current = parent.clone();
        }
        chain
    }

    fn prefix_matches(prefix: &str, action: &ActionKey) -> bool {
        if prefix == "*" {
            return true;
        }
        action.0 == prefix || action.0.starts_with(&format!("{prefix}."))
    }

    fn principal_allowed(&self, principal: &PrincipalRef, request: &AuthorizationRequest) -> bool {
        let ancestry = self.ancestry(&request.scope);
        let held_roles = self.roles.get(principal).cloned().unwrap_or_default();
        self.grants.iter().any(|grant| {
            let subject_matches = match &grant.subject {
                IncumbentSubject::Principal(p) => p == principal,
                IncumbentSubject::Role(role) => held_roles.contains(role),
            };
            subject_matches
                && Self::prefix_matches(&grant.action_prefix, &request.action)
                && ancestry.contains(&grant.scope)
        })
    }

    fn decide(&self, request: &AuthorizationRequest) -> AuthorizationDecision {
        // Conjunctive principal chain: every link must be allowed, and an empty
        // chain is denied — no principal ever means deny.
        let chain: Vec<&PrincipalRef> = request.principal_chain().collect();
        if chain.is_empty() {
            return AuthorizationDecision::Deny;
        }
        if chain
            .iter()
            .all(|principal| self.principal_allowed(principal, request))
        {
            AuthorizationDecision::Allow
        } else {
            AuthorizationDecision::Deny
        }
    }
}

/// Build the incumbent engine populated to the *same* intended policy as
/// `oversight_iam`, resolved over its own independent hierarchy. The incumbent
/// always knows `run:7 -> issue:42`; whether IAM does is what the cutover tests.
fn oversight_incumbent() -> OversightLegacyAuthz {
    let mut engine = OversightLegacyAuthz::default();
    let ws = ScopeRef::Workspace {
        workspace_id: workspace(),
    };
    engine
        // The workspace roots under the global scope, so a global grant resolves
        // through the same ancestor walk IAM uses.
        .link(ws.clone(), ScopeRef::Global)
        .link(web_project(), ws.clone())
        .link(Resource::Issue("iss_42".into()).scope(), web_project())
        .link(
            Resource::Run("run_7".into()).scope(),
            Resource::Issue("iss_42".into()).scope(),
        )
        .link(
            Resource::Thread("thr_3".into()).scope(),
            Resource::Issue("iss_42".into()).scope(),
        )
        .link(Resource::Team("triage".into()).scope(), ws);

    engine.grant_principal(
        Actor::User("ada".into()).to_principal_ref(),
        "*",
        web_project_workspace(),
    );
    engine.grant_principal(
        Actor::Agent("ci-bot".into()).to_principal_ref(),
        "run",
        Resource::Issue("iss_42".into()).scope(),
    );
    engine.grant_principal(
        Actor::ProcessAgent("scheduler".into()).to_principal_ref(),
        "run.start",
        Resource::Issue("iss_42".into()).scope(),
    );
    engine.grant_principal(
        Actor::System("automation".into()).to_principal_ref(),
        "issue.advance",
        ScopeRef::Global,
    );
    engine.grant_role(triage_role(), "issue.read", web_project());
    engine.grant_role(triage_role(), "thread.read", web_project());
    engine.add_member(Actor::User("lin".into()).to_principal_ref(), triage_role());
    engine
}

fn web_project_workspace() -> ScopeRef {
    ScopeRef::Workspace {
        workspace_id: workspace(),
    }
}

/// The representative request battery the enforcement point replays through both
/// engines. Each is already in shared-shape form — the product mapped its actor
/// and resource at the boundary.
fn request_battery() -> Vec<AuthorizationRequest> {
    let direct = |actor: Actor, action: &str, resource: Resource| {
        AuthorizationRequest::direct(
            actor.to_principal_ref(),
            ActionKey(action.into()),
            resource.scope(),
        )
    };
    vec![
        // 1. Admin advances an issue under the workspace.
        direct(
            Actor::User("ada".into()),
            "issue.advance",
            Resource::Issue("iss_42".into()),
        ),
        // 2. Admin cancels a run — only reachable through the run -> issue edge.
        direct(
            Actor::User("ada".into()),
            "run.cancel",
            Resource::Run("run_7".into()),
        ),
        // 3. CI agent starts a run — also needs the run -> issue edge.
        direct(
            Actor::Agent("ci-bot".into()),
            "run.start",
            Resource::Run("run_7".into()),
        ),
        // 4. CI agent may not close an issue (no issue grant).
        direct(
            Actor::Agent("ci-bot".into()),
            "issue.close",
            Resource::Issue("iss_42".into()),
        ),
        // 5. Team member reads an issue via the triage role.
        direct(
            Actor::User("lin".into()),
            "issue.read",
            Resource::Issue("iss_42".into()),
        ),
        // 6. Team member reads a thread (thread -> issue -> project) via the role.
        direct(
            Actor::User("lin".into()),
            "thread.read",
            Resource::Thread("thr_3".into()),
        ),
        // 7. Team member may not close an issue (role does not carry it).
        direct(
            Actor::User("lin".into()),
            "issue.close",
            Resource::Issue("iss_42".into()),
        ),
        // 8. System automation advances any issue (global grant).
        direct(
            Actor::System("automation".into()),
            "issue.advance",
            Resource::Issue("iss_42".into()),
        ),
        // 9. An outsider is denied — fail closed.
        direct(
            Actor::User("mallory".into()),
            "issue.read",
            Resource::Issue("iss_42".into()),
        ),
        // 10. Process agent acting on behalf of the admin starts a run (chain).
        AuthorizationRequest {
            principal: Actor::ProcessAgent("scheduler".into()).to_principal_ref(),
            on_behalf_of: vec![Actor::User("ada".into()).to_principal_ref()],
            action: ActionKey("run.start".into()),
            scope: Resource::Run("run_7".into()).scope(),
        },
    ]
}

// --- Tests ----------------------------------------------------------------

/// ADR-0004 #1: registering the Oversight resource model lets IAM resolve the
/// product's `run -> issue -> project -> workspace` hierarchy through the same
/// scope-graph walk it uses for well-known scopes. A workspace-scoped admin grant
/// reaches a deeply-nested run, and the team roster resolves under the workspace.
#[test]
fn registering_the_resource_model_resolves_oversights_hierarchy() {
    let iam = oversight_iam(true);

    // The catalog learned every product action purely from registration.
    let model = oversight_resource_model(true);
    for action in ["issue.advance", "run.start", "thread.read", "team.manage"] {
        assert!(
            model.knows_action(&ActionKey(action.into())),
            "registered action {action} must be in the open catalog"
        );
    }

    // A grant at the workspace covers a run nested four levels down, resolved only
    // through the registered edges.
    assert_eq!(
        iam.authorize(&AuthorizationRequest::direct(
            Actor::User("ada".into()).to_principal_ref(),
            ActionKey("run.cancel".into()),
            Resource::Run("run_7".into()).scope(),
        )),
        AuthorizationDecision::Allow,
    );
}

/// ADR-0004 #1 (boundary mapping): the rich actor taxonomy resolves down to the
/// shared `PrincipalRef` variants, and a `Team` is a `Group`/membership target —
/// never a principal. The product distinction survives only as the `service_id`
/// prefix, legible in audit traces without entering the contract.
#[test]
fn the_actor_taxonomy_resolves_down_to_shared_principals() {
    assert_eq!(
        Actor::User("ada".into()).to_principal_ref(),
        PrincipalRef::Account {
            account_id: AccountId("ada".into())
        },
    );
    assert_eq!(
        Actor::Agent("ci-bot".into()).to_principal_ref(),
        PrincipalRef::Service {
            service_id: "agent:ci-bot".into()
        },
    );
    assert_eq!(
        Actor::ProcessAgent("scheduler".into()).to_principal_ref(),
        PrincipalRef::Service {
            service_id: "process:scheduler".into()
        },
    );
    assert_eq!(
        Actor::System("automation".into()).to_principal_ref(),
        PrincipalRef::Service {
            service_id: "system:automation".into()
        },
    );

    // Team membership is the inheritance path: Lin reads via the triage role,
    // while a non-member is denied the same action.
    let iam = oversight_iam(true);
    assert_eq!(
        iam.authorize(&AuthorizationRequest::direct(
            Actor::User("lin".into()).to_principal_ref(),
            ActionKey("issue.read".into()),
            Resource::Issue("iss_42".into()).scope(),
        )),
        AuthorizationDecision::Allow,
    );
    assert_eq!(
        iam.authorize(&AuthorizationRequest::direct(
            Actor::User("mallory".into()).to_principal_ref(),
            ActionKey("issue.read".into()),
            Resource::Issue("iss_42".into()).scope(),
        )),
        AuthorizationDecision::Deny,
    );
}

/// ADR-0004 #5: the Strangler cutover. With the `run -> issue` edges missing, IAM
/// diverges from the incumbent on every run request; the harness keeps enforcing
/// the incumbent and logs the disagreements, so parity is *not* yet reached. The
/// incumbent stays authoritative throughout — shadowing changes no outcome.
#[test]
fn shadow_run_catches_divergence_before_parity() {
    let incumbent = oversight_incumbent();
    let iam = oversight_iam(false); // run edges deliberately absent

    let mut shadow = ShadowAuthorizer::new(
        |request: &AuthorizationRequest| incumbent.decide(request),
        iam,
    );
    for request in request_battery() {
        let outcome = shadow.run(&request);
        // The enforced decision is always the incumbent's, never the candidate's.
        assert_eq!(outcome.authoritative, incumbent.decide(&request));
    }

    let report = shadow.report();
    assert_eq!(report.observations, 10);
    // Requests 2, 3, and 10 touch run:7, which IAM cannot resolve without the
    // edge: it denies where the incumbent allows.
    assert_eq!(report.divergences, 3);
    assert!(
        !report.at_parity(10),
        "parity must not be declared while diverging"
    );

    // The logged samples carry the exact requests for reconciliation.
    let diverged_actions: Vec<&str> = shadow
        .divergences()
        .map(|divergence| divergence.request.action.0.as_str())
        .collect();
    assert!(diverged_actions.contains(&"run.cancel"));
    assert!(diverged_actions.contains(&"run.start"));
}

/// ADR-0004 #5: once the resource model is complete the candidate reaches
/// measured parity over the full battery, and the flag may flip. After cutover
/// IAM alone decides, and its decisions match what the incumbent produced — so
/// the in-repo engine can be retired.
#[test]
fn shadow_reaches_parity_then_cuts_over_to_iam() {
    let incumbent = oversight_incumbent();
    let iam = oversight_iam(true); // model now complete

    let mut shadow = ShadowAuthorizer::new(
        |request: &AuthorizationRequest| incumbent.decide(request),
        iam,
    );
    for request in request_battery() {
        let outcome = shadow.run(&request);
        assert!(!outcome.diverged, "no request may diverge at parity");
    }

    let report = shadow.report();
    assert_eq!(report.observations, 10);
    assert_eq!(report.divergences, 0);
    assert_eq!(report.divergence_rate(), 0.0);
    assert!(
        report.at_parity(10),
        "zero divergence over the window is parity"
    );

    // Cut over: IAM is now authoritative on its own, and every battery decision
    // matches the incumbent it replaced.
    let iam_after = oversight_iam(true);
    for request in request_battery() {
        assert_eq!(
            iam_after.authorize(&request),
            incumbent.decide(&request),
            "post-cutover IAM decision must match the retired incumbent for {:?}",
            request.action,
        );
    }

    // Spot-check the post-cutover outcomes are the intended policy, not merely
    // mutual agreement on deny.
    assert_eq!(
        iam_after.authorize(&request_battery()[7]),
        AuthorizationDecision::Allow,
        "system automation advances issues after cutover",
    );
    assert_eq!(
        iam_after.authorize(&request_battery()[3]),
        AuthorizationDecision::Deny,
        "the CI agent still cannot close an issue after cutover",
    );
}
