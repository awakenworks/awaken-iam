//! Executable documentation for ADR-0009 (ABAC gap assessment).
//!
//! Each test below pins one of the seven Oversight authorization decision
//! points and shows that the existing engine primitives — action pattern,
//! scope hierarchy, group subjects, three-valued effect, and conjunctive
//! principal chain — cover it **without** any grant `condition` field.
//!
//! **Conclusion recorded here: no gap.** action + scope + group suffices
//! for every identified consumer authorization decision point. The
//! `condition?` placeholder described in the authorization-engine design is
//! explicitly deferred; no current consumer requires it for correctness.

use awaken_iam_contract::{
    AccountId, ActionKey, AuthorizationDecision, AuthorizationRequest, OrgId, PrincipalRef,
    ProjectId, ResourceId, ResourceType, ScopeRef, WorkspaceId,
};
use awaken_iam_core::{
    ActionPattern, DecisionReason, Effect, Grant, GrantId, GrantSubject, GroupId, GroupRoleBinding,
    PolicySet, RoleBinding, RoleId,
};

fn account(id: &str) -> PrincipalRef {
    PrincipalRef::Account {
        account_id: AccountId(id.into()),
    }
}

fn service(id: &str) -> PrincipalRef {
    PrincipalRef::Service {
        service_id: id.into(),
    }
}

fn project(ws: &str, proj: &str) -> ScopeRef {
    ScopeRef::Project {
        workspace_id: WorkspaceId(ws.into()),
        project_id: ProjectId(proj.into()),
    }
}

fn resource(ty: &str, id: &str) -> ScopeRef {
    ScopeRef::Resource {
        resource_type: ResourceType(ty.into()),
        resource_id: ResourceId(id.into()),
    }
}

fn direct(principal: PrincipalRef, action: &str, scope: ScopeRef) -> AuthorizationRequest {
    AuthorizationRequest::direct(principal, ActionKey(action.into()), scope)
}

fn delegated(
    caller: PrincipalRef,
    on_behalf_of: Vec<PrincipalRef>,
    action: &str,
    scope: ScopeRef,
) -> AuthorizationRequest {
    AuthorizationRequest {
        principal: caller,
        on_behalf_of,
        action: ActionKey(action.into()),
        scope,
    }
}

/// Decision point 1 — role-based access to resources.
///
/// A workspace-scoped role grant covers every issue in that workspace
/// through the scope hierarchy: no per-issue grant or condition is needed.
#[test]
fn role_based_read_covers_all_issues_in_workspace() {
    let ws = WorkspaceId("ws_main".into());
    let org = OrgId("acme".into());

    let mut policy = PolicySet::new();
    policy
        .scope_graph_mut()
        .assign_workspace(ws.clone(), org.clone());

    // Register the issue resource hierarchy: issue -> project -> workspace.
    policy.scope_graph_mut().assign_resource_parent(
        ResourceType("issue".into()),
        ResourceId("issue_42".into()),
        project("ws_main", "proj_backend"),
    );
    policy.scope_graph_mut().assign_resource_parent(
        ResourceType("issue".into()),
        ResourceId("issue_99".into()),
        project("ws_main", "proj_backend"),
    );

    // Bind ada to the "viewer" role at workspace scope.
    policy.bind_role(RoleBinding {
        principal: account("ada"),
        role: RoleId("viewer".into()),
        scope: ScopeRef::Workspace {
            workspace_id: ws.clone(),
        },
    });
    // The viewer role grants issue.read across its whole scope.
    policy.add_grant(Grant {
        id: GrantId("g_viewer_read".into()),
        subject: GrantSubject::Role(RoleId("viewer".into())),
        action_pattern: ActionPattern("issue.read".into()),
        scope: ScopeRef::Workspace {
            workspace_id: ws.clone(),
        },
        effect: Effect::Allow,
    });

    // ada may read every issue in the workspace without per-issue grants.
    for issue_id in ["issue_42", "issue_99"] {
        let trace = policy.evaluate(&direct(
            account("ada"),
            "issue.read",
            resource("issue", issue_id),
        ));
        assert_eq!(
            trace.decision,
            AuthorizationDecision::Allow,
            "issue {issue_id}: expected Allow"
        );
    }

    // bob holds no binding at all — default deny.
    let denied = policy.evaluate(&direct(
        account("bob"),
        "issue.read",
        resource("issue", "issue_42"),
    ));
    assert_eq!(denied.decision, AuthorizationDecision::Deny);
    assert_eq!(denied.reason, DecisionReason::DefaultDeny);
}

/// Decision point 2 — team-scoped access via live Group roster.
///
/// A GroupRoleBinding covers a team's members dynamically; joining or
/// leaving the team changes effective permissions immediately.
#[test]
fn team_membership_gates_project_access() {
    let proj = project("ws_main", "proj_backend");

    let mut policy = PolicySet::new();
    policy.set_group_roster(GroupId("backend-team".into()), [account("ada")]);
    policy.bind_group_role(GroupRoleBinding {
        group: GroupId("backend-team".into()),
        role: RoleId("closer".into()),
        scope: proj.clone(),
    });
    policy.add_grant(Grant {
        id: GrantId("g_closer".into()),
        subject: GrantSubject::Role(RoleId("closer".into())),
        action_pattern: ActionPattern("issue.close".into()),
        scope: proj.clone(),
        effect: Effect::Allow,
    });

    // Team member may close issues in the project.
    let member = policy.evaluate(&direct(account("ada"), "issue.close", proj.clone()));
    assert_eq!(member.decision, AuthorizationDecision::Allow);

    // Non-member is denied.
    let outsider = policy.evaluate(&direct(account("bob"), "issue.close", proj.clone()));
    assert_eq!(outsider.decision, AuthorizationDecision::Deny);

    // Joining the team grants the permission on the next evaluation.
    policy.add_group_member(GroupId("backend-team".into()), account("bob"));
    let new_member = policy.evaluate(&direct(account("bob"), "issue.close", proj.clone()));
    assert_eq!(new_member.decision, AuthorizationDecision::Allow);

    // Leaving the team revokes it immediately.
    policy.remove_group_member(&GroupId("backend-team".into()), &account("bob"));
    let former = policy.evaluate(&direct(account("bob"), "issue.close", proj.clone()));
    assert_eq!(former.decision, AuthorizationDecision::Deny);
}

/// Decision point 3 — approval-gated sensitive actions.
///
/// A RequireApproval grant returns an obligations envelope the caller
/// discharges product-side; no condition on the grant is needed.
#[test]
fn delete_requires_approval_and_carries_obligation() {
    let proj = project("ws_main", "proj_backend");

    let mut policy = PolicySet::new();
    policy.add_grant(Grant {
        id: GrantId("g_delete_gate".into()),
        subject: GrantSubject::Principal(account("ada")),
        action_pattern: ActionPattern("issue.delete".into()),
        scope: proj.clone(),
        effect: Effect::RequireApproval,
    });

    let trace = policy.evaluate(&direct(account("ada"), "issue.delete", proj.clone()));
    assert_eq!(trace.decision, AuthorizationDecision::RequireApproval);
    assert_eq!(trace.reason, DecisionReason::NeedsApproval);

    // The obligation envelope names the policy and anchors the authority
    // scope; the product drives the approve/pause/resume loop against it.
    let obligation = trace
        .obligation
        .as_ref()
        .expect("approval carries obligation");
    assert_eq!(obligation.policy_id, "g_delete_gate");
    assert_eq!(obligation.authority.scope, proj);
    assert!(obligation.obligation_id.starts_with("obl_"));
}

/// Decision point 4 — conjunctive principal chain for delegated authorization.
///
/// An AI agent may only close an issue when both the agent itself and the
/// human it acts for each hold that permission. If either is denied the
/// whole chain is denied.
#[test]
fn agent_delegation_requires_both_links_to_be_permitted() {
    let agent = service("agent:run_42");
    let proj = project("ws_main", "proj_backend");

    let mut policy = PolicySet::new();
    // Both principals are allowed.
    policy.add_grant(Grant {
        id: GrantId("g_human".into()),
        subject: GrantSubject::Principal(account("ada")),
        action_pattern: ActionPattern("issue.close".into()),
        scope: proj.clone(),
        effect: Effect::Allow,
    });
    policy.add_grant(Grant {
        id: GrantId("g_agent".into()),
        subject: GrantSubject::Principal(agent.clone()),
        action_pattern: ActionPattern("issue.close".into()),
        scope: proj.clone(),
        effect: Effect::Allow,
    });

    let allowed = policy.evaluate(&delegated(
        agent.clone(),
        vec![account("ada")],
        "issue.close",
        proj.clone(),
    ));
    assert_eq!(allowed.decision, AuthorizationDecision::Allow);

    // Remove the human's grant — the chain now denies.
    let mut policy2 = PolicySet::new();
    policy2.add_grant(Grant {
        id: GrantId("g_agent".into()),
        subject: GrantSubject::Principal(agent.clone()),
        action_pattern: ActionPattern("issue.close".into()),
        scope: proj.clone(),
        effect: Effect::Allow,
    });
    let denied = policy2.evaluate(&delegated(
        agent.clone(),
        vec![account("ada")],
        "issue.close",
        proj.clone(),
    ));
    assert_eq!(denied.decision, AuthorizationDecision::Deny);
    assert_eq!(denied.reason, DecisionReason::DefaultDeny);
}

/// Decision point 5 — per-instance ownership via resource-scoped grant.
///
/// The transactional outbox writes a per-instance grant for the creator at
/// resource creation time. No condition field is needed; `ScopeRef::Resource`
/// anchors the grant exactly at the one issue instance.
#[test]
fn creator_grant_at_resource_scope_models_ownership() {
    let issue_id = ResourceId("issue_42".into());
    let issue_scope = resource("issue", "issue_42");

    let mut policy = PolicySet::new();
    // Written by the transactional outbox when issue_42 is created by ada.
    policy.add_grant(Grant {
        id: GrantId("g_creator_delete".into()),
        subject: GrantSubject::Principal(account("ada")),
        action_pattern: ActionPattern("issue.delete".into()),
        scope: issue_scope.clone(),
        effect: Effect::Allow,
    });

    // ada can delete her own issue.
    let creator = policy.evaluate(&direct(account("ada"), "issue.delete", issue_scope.clone()));
    assert_eq!(creator.decision, AuthorizationDecision::Allow);
    assert_eq!(
        creator.matched_grants,
        vec![GrantId("g_creator_delete".into())]
    );

    // bob cannot — he holds no grant scoped to this resource.
    let other = policy.evaluate(&direct(account("bob"), "issue.delete", issue_scope.clone()));
    assert_eq!(other.decision, AuthorizationDecision::Deny);
    assert_eq!(other.reason, DecisionReason::DefaultDeny);

    // A project-level grant for bob does NOT reach the resource scope unless
    // the resource's parent edge is registered. Without registration the
    // resource roots at itself — the "registered, never inferred" invariant.
    policy.add_grant(Grant {
        id: GrantId("g_project_admin".into()),
        subject: GrantSubject::Principal(account("bob")),
        action_pattern: ActionPattern("issue.*".into()),
        scope: project("ws_main", "proj_backend"),
        effect: Effect::Allow,
    });
    // Still denied: no parent edge registered, resource roots at itself.
    let still_denied =
        policy.evaluate(&direct(account("bob"), "issue.delete", issue_scope.clone()));
    assert_eq!(still_denied.decision, AuthorizationDecision::Deny);

    // After registering the parent edge the project grant covers the resource.
    policy.scope_graph_mut().assign_resource_parent(
        ResourceType("issue".into()),
        issue_id.clone(),
        project("ws_main", "proj_backend"),
    );
    let now_allowed = policy.evaluate(&direct(account("bob"), "issue.delete", issue_scope.clone()));
    assert_eq!(now_allowed.decision, AuthorizationDecision::Allow);
}

/// Decision point 6 — cross-product key authorization via action namespaces.
///
/// A single principal may hold Allow for `agent.*` and RequireApproval for
/// `oversight.*` under the same evaluation, with no per-product config.
#[test]
fn cross_product_key_allow_for_agent_require_approval_for_oversight() {
    let mut policy = PolicySet::new();
    policy.add_grant(Grant {
        id: GrantId("g_agent_allow".into()),
        subject: GrantSubject::Principal(account("svc")),
        action_pattern: ActionPattern("agent.*".into()),
        scope: ScopeRef::Global,
        effect: Effect::Allow,
    });
    policy.add_grant(Grant {
        id: GrantId("g_oversight_gate".into()),
        subject: GrantSubject::Principal(account("svc")),
        action_pattern: ActionPattern("oversight.*".into()),
        scope: ScopeRef::Global,
        effect: Effect::RequireApproval,
    });

    // Agent action is simply allowed.
    let agent_trace = policy.evaluate(&direct(account("svc"), "agent.run", ScopeRef::Global));
    assert_eq!(agent_trace.decision, AuthorizationDecision::Allow);

    // Oversight action requires approval.
    let oversight_trace = policy.evaluate(&direct(
        account("svc"),
        "oversight.approval.grant",
        ScopeRef::Global,
    ));
    assert_eq!(
        oversight_trace.decision,
        AuthorizationDecision::RequireApproval
    );

    // oversight.* is RequireApproval so it carries an obligation; agent.* does not.
    let obl_agent = policy
        .evaluate(&direct(account("svc"), "agent.configure", ScopeRef::Global))
        .obligation;
    let obl_oversight = policy
        .evaluate(&direct(
            account("svc"),
            "oversight.review",
            ScopeRef::Global,
        ))
        .obligation;
    assert!(obl_agent.is_none());
    assert!(obl_oversight.is_some());
}

/// Decision point 7 — list visibility filtering in a single pass.
///
/// `PolicySet::visible` answers "which of these resource scopes may
/// `issue.read`" without one authorize call per row.
#[test]
fn visible_filters_issue_list_to_accessible_scopes() {
    let mut policy = PolicySet::new();
    policy
        .scope_graph_mut()
        .assign_workspace(WorkspaceId("ws_main".into()), OrgId("acme".into()));

    // ada has read access across the whole workspace.
    policy.add_grant(Grant {
        id: GrantId("g_ws_read".into()),
        subject: GrantSubject::Principal(account("ada")),
        action_pattern: ActionPattern("issue.read".into()),
        scope: ScopeRef::Workspace {
            workspace_id: WorkspaceId("ws_main".into()),
        },
        effect: Effect::Allow,
    });

    // bob only has access to proj_a.
    policy.add_grant(Grant {
        id: GrantId("g_bob_proj_a".into()),
        subject: GrantSubject::Principal(account("bob")),
        action_pattern: ActionPattern("issue.read".into()),
        scope: project("ws_main", "proj_a"),
        effect: Effect::Allow,
    });

    let candidates = vec![
        project("ws_main", "proj_a"),
        project("ws_main", "proj_b"),
        project("ws_other", "proj_x"),
    ];

    let ada_visible = policy.visible(
        &account("ada"),
        &ActionKey("issue.read".into()),
        &candidates,
    );
    // ada sees both workspace projects; proj_x is in a different workspace
    // with no registered org edge, so the workspace grant doesn't cover it.
    assert_eq!(
        ada_visible,
        vec![project("ws_main", "proj_a"), project("ws_main", "proj_b")]
    );

    let bob_visible = policy.visible(
        &account("bob"),
        &ActionKey("issue.read".into()),
        &candidates,
    );
    assert_eq!(bob_visible, vec![project("ws_main", "proj_a")]);
}
