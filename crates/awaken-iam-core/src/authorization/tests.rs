use super::*;
use awaken_iam_contract::{NamespaceId, OrgId, ProjectId, WorkspaceId};

fn account(id: &str) -> PrincipalRef {
    PrincipalRef::Account {
        account_id: awaken_iam_contract::AccountId(id.into()),
    }
}

fn request(principal: PrincipalRef, action: &str, scope: ScopeRef) -> AuthorizationRequest {
    AuthorizationRequest::direct(principal, ActionKey(action.into()), scope)
}

fn project_scope(ws: &str, proj: &str) -> ScopeRef {
    ScopeRef::Project {
        workspace_id: WorkspaceId(ws.into()),
        project_id: ProjectId(proj.into()),
    }
}

#[test]
fn empty_policy_denies_by_default() {
    let policy = PolicySet::new();
    let trace = policy.evaluate(&request(account("a"), "pack.read", ScopeRef::Global));
    assert_eq!(trace.decision, AuthorizationDecision::Deny);
    assert_eq!(trace.reason, DecisionReason::DefaultDeny);
    assert!(trace.matched_grants.is_empty());
    assert!(trace.matched_roles.is_empty());
}

#[test]
fn direct_grant_allows_and_traces_the_grant() {
    let mut policy = PolicySet::new();
    policy.add_grant(Grant {
        id: GrantId("g1".into()),
        subject: GrantSubject::Principal(account("ada")),
        action_pattern: ActionPattern("pack.publish".into()),
        scope: ScopeRef::Namespace {
            namespace_id: NamespaceId("acme".into()),
        },
        effect: Effect::Allow,
    });

    let trace = policy.evaluate(&request(
        account("ada"),
        "pack.publish",
        ScopeRef::Namespace {
            namespace_id: NamespaceId("acme".into()),
        },
    ));
    assert_eq!(trace.decision, AuthorizationDecision::Allow);
    assert_eq!(trace.reason, DecisionReason::AllowedByGrant);
    assert_eq!(trace.matched_grants, vec![GrantId("g1".into())]);
    assert!(trace.matched_roles.is_empty());
}

#[test]
fn grant_for_other_principal_does_not_match() {
    let mut policy = PolicySet::new();
    policy.add_grant(Grant {
        id: GrantId("g1".into()),
        subject: GrantSubject::Principal(account("ada")),
        action_pattern: ActionPattern("pack.publish".into()),
        scope: ScopeRef::Global,
        effect: Effect::Allow,
    });

    let trace = policy.evaluate(&request(account("bob"), "pack.publish", ScopeRef::Global));
    assert_eq!(trace.decision, AuthorizationDecision::Deny);
    assert_eq!(trace.reason, DecisionReason::DefaultDeny);
}

#[test]
fn role_binding_expands_into_grant_match() {
    let mut policy = PolicySet::new();
    policy.bind_role(RoleBinding {
        principal: account("ada"),
        role: RoleId("publisher".into()),
        scope: ScopeRef::Namespace {
            namespace_id: NamespaceId("acme".into()),
        },
    });
    policy.add_grant(Grant {
        id: GrantId("g_pub".into()),
        subject: GrantSubject::Role(RoleId("publisher".into())),
        action_pattern: ActionPattern("pack.publish".into()),
        scope: ScopeRef::Namespace {
            namespace_id: NamespaceId("acme".into()),
        },
        effect: Effect::Allow,
    });

    let trace = policy.evaluate(&request(
        account("ada"),
        "pack.publish",
        ScopeRef::Namespace {
            namespace_id: NamespaceId("acme".into()),
        },
    ));
    assert_eq!(trace.decision, AuthorizationDecision::Allow);
    assert_eq!(trace.matched_grants, vec![GrantId("g_pub".into())]);
    assert_eq!(trace.matched_roles, vec![RoleId("publisher".into())]);
}

#[test]
fn role_binding_for_other_principal_is_ignored() {
    let mut policy = PolicySet::new();
    policy.bind_role(RoleBinding {
        principal: account("ada"),
        role: RoleId("publisher".into()),
        scope: ScopeRef::Global,
    });
    policy.add_grant(Grant {
        id: GrantId("g_pub".into()),
        subject: GrantSubject::Role(RoleId("publisher".into())),
        action_pattern: ActionPattern("pack.publish".into()),
        scope: ScopeRef::Global,
        effect: Effect::Allow,
    });

    let trace = policy.evaluate(&request(account("bob"), "pack.publish", ScopeRef::Global));
    assert_eq!(trace.decision, AuthorizationDecision::Deny);
    assert_eq!(trace.reason, DecisionReason::DefaultDeny);
}

#[test]
fn action_wildcard_matches_dotted_actions_but_not_siblings() {
    let pattern = ActionPattern("project.*".into());
    assert!(pattern.matches(&ActionKey("project.read".into())));
    assert!(pattern.matches(&ActionKey("project.configure".into())));
    assert!(pattern.matches(&ActionKey("project".into())));
    assert!(!pattern.matches(&ActionKey("projectile.read".into())));
    assert!(!pattern.matches(&ActionKey("workspace.read".into())));
    assert!(ActionPattern("*".into()).matches(&ActionKey("anything.at.all".into())));
}

#[test]
fn global_grant_covers_nested_project_scope() {
    let mut policy = PolicySet::new();
    policy.add_grant(Grant {
        id: GrantId("g_global".into()),
        subject: GrantSubject::Principal(account("ada")),
        action_pattern: ActionPattern("project.*".into()),
        scope: ScopeRef::Global,
        effect: Effect::Allow,
    });

    let trace = policy.evaluate(&request(
        account("ada"),
        "project.read",
        project_scope("ws_main", "proj_web"),
    ));
    assert_eq!(trace.decision, AuthorizationDecision::Allow);
    assert_eq!(trace.matched_grants, vec![GrantId("g_global".into())]);
}

#[test]
fn workspace_grant_covers_its_project_via_intrinsic_link() {
    let mut policy = PolicySet::new();
    policy.add_grant(Grant {
        id: GrantId("g_ws".into()),
        subject: GrantSubject::Principal(account("ada")),
        action_pattern: ActionPattern("project.read".into()),
        scope: ScopeRef::Workspace {
            workspace_id: WorkspaceId("ws_main".into()),
        },
        effect: Effect::Allow,
    });

    let covered = policy.evaluate(&request(
        account("ada"),
        "project.read",
        project_scope("ws_main", "proj_web"),
    ));
    assert_eq!(covered.decision, AuthorizationDecision::Allow);

    // A project in a different workspace is not covered.
    let other = policy.evaluate(&request(
        account("ada"),
        "project.read",
        project_scope("ws_other", "proj_web"),
    ));
    assert_eq!(other.decision, AuthorizationDecision::Deny);
}

#[test]
fn org_grant_covers_namespace_and_workspace_through_scope_graph() {
    let mut policy = PolicySet::new();
    policy
        .scope_graph_mut()
        .assign_namespace(NamespaceId("acme".into()), OrgId("acme".into()))
        .assign_workspace(WorkspaceId("ws_main".into()), OrgId("acme".into()));
    policy.add_grant(Grant {
        id: GrantId("g_org".into()),
        subject: GrantSubject::Principal(account("ada")),
        action_pattern: ActionPattern("*".into()),
        scope: ScopeRef::Org {
            org_id: OrgId("acme".into()),
        },
        effect: Effect::Allow,
    });

    let ns = policy.evaluate(&request(
        account("ada"),
        "pack.publish",
        ScopeRef::Namespace {
            namespace_id: NamespaceId("acme".into()),
        },
    ));
    assert_eq!(ns.decision, AuthorizationDecision::Allow);

    let project = policy.evaluate(&request(
        account("ada"),
        "project.read",
        project_scope("ws_main", "proj_web"),
    ));
    assert_eq!(project.decision, AuthorizationDecision::Allow);

    // A namespace that is not registered under the org is not covered.
    let unrelated = policy.evaluate(&request(
        account("ada"),
        "pack.publish",
        ScopeRef::Namespace {
            namespace_id: NamespaceId("other".into()),
        },
    ));
    assert_eq!(unrelated.decision, AuthorizationDecision::Deny);
}

#[test]
fn narrow_grant_does_not_cover_broader_request() {
    let mut policy = PolicySet::new();
    policy.add_grant(Grant {
        id: GrantId("g_proj".into()),
        subject: GrantSubject::Principal(account("ada")),
        action_pattern: ActionPattern("project.read".into()),
        scope: project_scope("ws_main", "proj_web"),
        effect: Effect::Allow,
    });

    let trace = policy.evaluate(&request(
        account("ada"),
        "project.read",
        ScopeRef::Workspace {
            workspace_id: WorkspaceId("ws_main".into()),
        },
    ));
    assert_eq!(trace.decision, AuthorizationDecision::Deny);
    assert_eq!(trace.reason, DecisionReason::DefaultDeny);
}

#[test]
fn deny_grant_takes_precedence_over_allow() {
    let mut policy = PolicySet::new();
    policy.add_grant(Grant {
        id: GrantId("g_allow".into()),
        subject: GrantSubject::Principal(account("ada")),
        action_pattern: ActionPattern("pack.*".into()),
        scope: ScopeRef::Global,
        effect: Effect::Allow,
    });
    policy.add_grant(Grant {
        id: GrantId("g_deny".into()),
        subject: GrantSubject::Principal(account("ada")),
        action_pattern: ActionPattern("pack.publish".into()),
        scope: ScopeRef::Namespace {
            namespace_id: NamespaceId("acme".into()),
        },
        effect: Effect::Deny,
    });
    policy
        .scope_graph_mut()
        .assign_namespace(NamespaceId("acme".into()), OrgId("acme".into()));

    let trace = policy.evaluate(&request(
        account("ada"),
        "pack.publish",
        ScopeRef::Namespace {
            namespace_id: NamespaceId("acme".into()),
        },
    ));
    assert_eq!(trace.decision, AuthorizationDecision::Deny);
    assert_eq!(trace.reason, DecisionReason::DeniedByGrant);
    assert_eq!(trace.matched_grants, vec![GrantId("g_deny".into())]);
}

fn resource_scope(resource_type: &str, resource_id: &str) -> ScopeRef {
    ScopeRef::Resource {
        resource_type: awaken_iam_contract::ResourceType(resource_type.into()),
        resource_id: awaken_iam_contract::ResourceId(resource_id.into()),
    }
}

#[test]
fn grant_at_registered_resource_parent_covers_the_resource() {
    let mut policy = PolicySet::new();
    policy.scope_graph_mut().assign_resource_parent(
        awaken_iam_contract::ResourceType("issue".into()),
        awaken_iam_contract::ResourceId("42".into()),
        project_scope("ws_main", "proj_web"),
    );
    policy.add_grant(Grant {
        id: GrantId("g_proj".into()),
        subject: GrantSubject::Principal(account("ada")),
        action_pattern: ActionPattern("issue.*".into()),
        scope: project_scope("ws_main", "proj_web"),
        effect: Effect::Allow,
    });

    let trace = policy.evaluate(&request(
        account("ada"),
        "issue.read",
        resource_scope("issue", "42"),
    ));
    assert_eq!(trace.decision, AuthorizationDecision::Allow);
    assert_eq!(trace.matched_grants, vec![GrantId("g_proj".into())]);
}

#[test]
fn retired_resource_denies_even_an_exact_manual_grant_after_snapshot_reload() {
    let mut policy = PolicySet::new();
    policy.add_grant(Grant {
        id: GrantId("manual".into()),
        subject: GrantSubject::Principal(account("ada")),
        action_pattern: ActionPattern("issue.read".into()),
        scope: resource_scope("issue", "42"),
        effect: Effect::Allow,
    });
    let before = request(account("ada"), "issue.read", resource_scope("issue", "42"));
    assert_eq!(
        policy.evaluate(&before).decision,
        AuthorizationDecision::Allow
    );
    policy
        .scope_graph_mut()
        .retire_resource(ResourceType("issue".into()), ResourceId("42".into()));
    assert_eq!(
        policy.evaluate(&before).decision,
        AuthorizationDecision::Deny
    );
    let restored = PolicySet::from_snapshot(&policy.snapshot(7));
    assert_eq!(
        restored.evaluate(&before).decision,
        AuthorizationDecision::Deny
    );
}

#[test]
fn arbitrarily_deep_resource_chain_resolves_to_root() {
    let mut policy = PolicySet::new();
    // comment:7 -> issue:42 -> project:web -> workspace:ws_main -> org:acme -> global
    policy
        .scope_graph_mut()
        .assign_workspace(WorkspaceId("ws_main".into()), OrgId("acme".into()))
        .assign_resource_parent(
            awaken_iam_contract::ResourceType("issue".into()),
            awaken_iam_contract::ResourceId("42".into()),
            project_scope("ws_main", "proj_web"),
        )
        .assign_resource_parent(
            awaken_iam_contract::ResourceType("comment".into()),
            awaken_iam_contract::ResourceId("7".into()),
            resource_scope("issue", "42"),
        );
    policy.add_grant(Grant {
        id: GrantId("g_org".into()),
        subject: GrantSubject::Principal(account("ada")),
        action_pattern: ActionPattern("comment.delete".into()),
        scope: ScopeRef::Org {
            org_id: OrgId("acme".into()),
        },
        effect: Effect::Allow,
    });

    // A grant at the org root covers a comment five edges below it, and the
    // intermediate resource->resource edge is part of the same walk.
    let trace = policy.evaluate(&request(
        account("ada"),
        "comment.delete",
        resource_scope("comment", "7"),
    ));
    assert_eq!(trace.decision, AuthorizationDecision::Allow);
    assert_eq!(trace.matched_grants, vec![GrantId("g_org".into())]);
}

#[test]
fn unregistered_resource_roots_at_itself() {
    let mut policy = PolicySet::new();
    // A global grant does not reach a resource whose parent edge was never
    // registered: its place in the hierarchy is registered, never inferred.
    policy.add_grant(Grant {
        id: GrantId("g_global".into()),
        subject: GrantSubject::Principal(account("ada")),
        action_pattern: ActionPattern("*".into()),
        scope: ScopeRef::Global,
        effect: Effect::Allow,
    });

    let unreached = policy.evaluate(&request(
        account("ada"),
        "issue.read",
        resource_scope("issue", "orphan"),
    ));
    assert_eq!(unreached.decision, AuthorizationDecision::Deny);
    assert_eq!(unreached.reason, DecisionReason::DefaultDeny);

    // An exactly-anchored grant still covers it.
    policy.add_grant(Grant {
        id: GrantId("g_exact".into()),
        subject: GrantSubject::Principal(account("ada")),
        action_pattern: ActionPattern("issue.read".into()),
        scope: resource_scope("issue", "orphan"),
        effect: Effect::Allow,
    });
    let reached = policy.evaluate(&request(
        account("ada"),
        "issue.read",
        resource_scope("issue", "orphan"),
    ));
    assert_eq!(reached.decision, AuthorizationDecision::Allow);
    assert_eq!(reached.matched_grants, vec![GrantId("g_exact".into())]);
}

#[test]
fn cyclic_resource_edges_do_not_loop_forever() {
    let mut policy = PolicySet::new();
    // Misregistered cycle: a -> b -> a. The walk must terminate.
    policy
        .scope_graph_mut()
        .assign_resource_parent(
            awaken_iam_contract::ResourceType("node".into()),
            awaken_iam_contract::ResourceId("a".into()),
            resource_scope("node", "b"),
        )
        .assign_resource_parent(
            awaken_iam_contract::ResourceType("node".into()),
            awaken_iam_contract::ResourceId("b".into()),
            resource_scope("node", "a"),
        );

    let trace = policy.evaluate(&request(
        account("ada"),
        "node.read",
        resource_scope("node", "a"),
    ));
    assert_eq!(trace.decision, AuthorizationDecision::Deny);
    assert_eq!(trace.reason, DecisionReason::DefaultDeny);
}

#[test]
fn reason_codes_are_stable() {
    assert_eq!(DecisionReason::AllowedByGrant.code(), "allowed_by_grant");
    assert_eq!(DecisionReason::NeedsApproval.code(), "needs_approval");
    assert_eq!(DecisionReason::DeniedByGrant.code(), "denied_by_grant");
    assert_eq!(DecisionReason::DefaultDeny.code(), "default_deny");
    assert_eq!(
        DecisionReason::PrincipalUnresolved.code(),
        "principal_unresolved"
    );
}

fn delegated(
    principal: PrincipalRef,
    on_behalf_of: Vec<PrincipalRef>,
    action: &str,
    scope: ScopeRef,
) -> AuthorizationRequest {
    AuthorizationRequest {
        principal,
        on_behalf_of,
        action: ActionKey(action.into()),
        scope,
    }
}

#[test]
fn require_approval_grant_yields_require_approval_decision() {
    let mut policy = PolicySet::new();
    policy.add_grant(Grant {
        id: GrantId("g_appr".into()),
        subject: GrantSubject::Principal(account("ada")),
        action_pattern: ActionPattern("pack.publish".into()),
        scope: ScopeRef::Global,
        effect: Effect::RequireApproval,
    });

    let trace = policy.evaluate(&request(account("ada"), "pack.publish", ScopeRef::Global));
    assert_eq!(trace.decision, AuthorizationDecision::RequireApproval);
    assert_eq!(trace.reason, DecisionReason::NeedsApproval);
    assert_eq!(trace.matched_grants, vec![GrantId("g_appr".into())]);
}

#[test]
fn deny_outranks_require_approval() {
    let mut policy = PolicySet::new();
    policy.add_grant(Grant {
        id: GrantId("g_appr".into()),
        subject: GrantSubject::Principal(account("ada")),
        action_pattern: ActionPattern("pack.*".into()),
        scope: ScopeRef::Global,
        effect: Effect::RequireApproval,
    });
    policy.add_grant(Grant {
        id: GrantId("g_deny".into()),
        subject: GrantSubject::Principal(account("ada")),
        action_pattern: ActionPattern("pack.publish".into()),
        scope: ScopeRef::Global,
        effect: Effect::Deny,
    });

    let trace = policy.evaluate(&request(account("ada"), "pack.publish", ScopeRef::Global));
    assert_eq!(trace.decision, AuthorizationDecision::Deny);
    assert_eq!(trace.reason, DecisionReason::DeniedByGrant);
    assert_eq!(trace.matched_grants, vec![GrantId("g_deny".into())]);
}

#[test]
fn require_approval_outranks_allow() {
    let mut policy = PolicySet::new();
    policy.add_grant(Grant {
        id: GrantId("g_allow".into()),
        subject: GrantSubject::Principal(account("ada")),
        action_pattern: ActionPattern("pack.*".into()),
        scope: ScopeRef::Global,
        effect: Effect::Allow,
    });
    policy.add_grant(Grant {
        id: GrantId("g_appr".into()),
        subject: GrantSubject::Principal(account("ada")),
        action_pattern: ActionPattern("pack.publish".into()),
        scope: ScopeRef::Global,
        effect: Effect::RequireApproval,
    });

    let trace = policy.evaluate(&request(account("ada"), "pack.publish", ScopeRef::Global));
    assert_eq!(trace.decision, AuthorizationDecision::RequireApproval);
    assert_eq!(trace.matched_grants, vec![GrantId("g_appr".into())]);
}

#[test]
fn require_approval_carries_an_obligation_naming_policy_and_authority() {
    let mut policy = PolicySet::new();
    policy.add_grant(Grant {
        id: GrantId("g_gate".into()),
        subject: GrantSubject::Principal(account("ada")),
        action_pattern: ActionPattern("issue.delete".into()),
        scope: ScopeRef::Namespace {
            namespace_id: NamespaceId("acme".into()),
        },
        effect: Effect::RequireApproval,
    });

    let trace = policy.evaluate(&request(
        account("ada"),
        "issue.delete",
        ScopeRef::Namespace {
            namespace_id: NamespaceId("acme".into()),
        },
    ));
    assert_eq!(trace.decision, AuthorizationDecision::RequireApproval);
    let obligation = trace.obligation.as_ref().expect("approval carries one");
    // The deciding grant names the policy and anchors the approval authority.
    assert_eq!(obligation.policy_id, "g_gate");
    assert_eq!(
        obligation.authority.scope,
        ScopeRef::Namespace {
            namespace_id: NamespaceId("acme".into()),
        }
    );
    assert!(obligation.obligation_id.starts_with("obl_"));
}

#[test]
fn allow_and_deny_carry_no_obligation() {
    let mut policy = PolicySet::new();
    policy.add_grant(Grant {
        id: GrantId("g_allow".into()),
        subject: GrantSubject::Principal(account("ada")),
        action_pattern: ActionPattern("pack.read".into()),
        scope: ScopeRef::Global,
        effect: Effect::Allow,
    });

    let allowed = policy.evaluate(&request(account("ada"), "pack.read", ScopeRef::Global));
    assert_eq!(allowed.decision, AuthorizationDecision::Allow);
    assert!(allowed.obligation.is_none());

    // A bare default-deny on an unmatched action also carries no obligation.
    let denied = policy.evaluate(&request(account("ada"), "pack.delete", ScopeRef::Global));
    assert_eq!(denied.decision, AuthorizationDecision::Deny);
    assert!(denied.obligation.is_none());
}

#[test]
fn obligation_id_is_stable_across_re_queries_and_varies_by_question() {
    let mut policy = PolicySet::new();
    for (id, subject) in [("g_ada", account("ada")), ("g_bob", account("bob"))] {
        policy.add_grant(Grant {
            id: GrantId(id.into()),
            subject: GrantSubject::Principal(subject),
            action_pattern: ActionPattern("issue.*".into()),
            scope: ScopeRef::Global,
            effect: Effect::RequireApproval,
        });
    }

    let first = policy.evaluate(&request(account("ada"), "issue.delete", ScopeRef::Global));
    let again = policy.evaluate(&request(account("ada"), "issue.delete", ScopeRef::Global));
    let other_action = policy.evaluate(&request(account("ada"), "issue.archive", ScopeRef::Global));
    let other_principal =
        policy.evaluate(&request(account("bob"), "issue.delete", ScopeRef::Global));

    let id = |t: &AuthorizationTrace| t.obligation.as_ref().unwrap().obligation_id.clone();
    // Re-querying the same question is idempotent: identical obligation id.
    assert_eq!(id(&first), id(&again));
    // A different action or principal is a different obligation.
    assert_ne!(id(&first), id(&other_action));
    assert_ne!(id(&first), id(&other_principal));
}

#[test]
fn principal_chain_allows_only_when_every_link_is_allowed() {
    let mut policy = PolicySet::new();
    let agent = PrincipalRef::Service {
        service_id: "agent".into(),
    };
    // Both the human and the agent it acts for are allowed.
    for (id, subject) in [("g_human", account("ada")), ("g_agent", agent.clone())] {
        policy.add_grant(Grant {
            id: GrantId(id.into()),
            subject: GrantSubject::Principal(subject),
            action_pattern: ActionPattern("issue.close".into()),
            scope: ScopeRef::Global,
            effect: Effect::Allow,
        });
    }

    let trace = policy.evaluate(&delegated(
        agent.clone(),
        vec![account("ada")],
        "issue.close",
        ScopeRef::Global,
    ));
    assert_eq!(trace.decision, AuthorizationDecision::Allow);
    // The trace unions both links' grants in chain order.
    assert_eq!(
        trace.matched_grants,
        vec![GrantId("g_agent".into()), GrantId("g_human".into())]
    );
}

#[test]
fn principal_chain_denies_when_a_delegate_link_is_unauthorized() {
    let mut policy = PolicySet::new();
    let agent = PrincipalRef::Service {
        service_id: "agent".into(),
    };
    // Only the agent is granted; the human it acts for is not.
    policy.add_grant(Grant {
        id: GrantId("g_agent".into()),
        subject: GrantSubject::Principal(agent.clone()),
        action_pattern: ActionPattern("issue.close".into()),
        scope: ScopeRef::Global,
        effect: Effect::Allow,
    });

    let trace = policy.evaluate(&delegated(
        agent,
        vec![account("ada")],
        "issue.close",
        ScopeRef::Global,
    ));
    assert_eq!(trace.decision, AuthorizationDecision::Deny);
    assert_eq!(trace.reason, DecisionReason::DefaultDeny);
}

#[test]
fn chain_require_approval_when_one_link_needs_it_and_none_denied() {
    let mut policy = PolicySet::new();
    let agent = PrincipalRef::Service {
        service_id: "agent".into(),
    };
    policy.add_grant(Grant {
        id: GrantId("g_human".into()),
        subject: GrantSubject::Principal(account("ada")),
        action_pattern: ActionPattern("issue.close".into()),
        scope: ScopeRef::Global,
        effect: Effect::Allow,
    });
    policy.add_grant(Grant {
        id: GrantId("g_agent".into()),
        subject: GrantSubject::Principal(agent.clone()),
        action_pattern: ActionPattern("issue.close".into()),
        scope: ScopeRef::Global,
        effect: Effect::RequireApproval,
    });

    let trace = policy.evaluate(&delegated(
        agent,
        vec![account("ada")],
        "issue.close",
        ScopeRef::Global,
    ));
    assert_eq!(trace.decision, AuthorizationDecision::RequireApproval);
    assert_eq!(trace.reason, DecisionReason::NeedsApproval);
    assert_eq!(trace.matched_grants, vec![GrantId("g_agent".into())]);
}

#[test]
fn empty_principal_chain_is_unresolved() {
    let policy = PolicySet::new();
    let trace = policy.evaluate_chain(&[], &ActionKey("pack.read".into()), &ScopeRef::Global);
    assert_eq!(trace.decision, AuthorizationDecision::Deny);
    assert_eq!(trace.reason, DecisionReason::PrincipalUnresolved);
}

#[test]
fn visible_filters_candidates_to_allowed_scopes_in_order() {
    let mut policy = PolicySet::new();
    policy
        .scope_graph_mut()
        .assign_workspace(WorkspaceId("ws_main".into()), OrgId("acme".into()));
    // Allowed across everything under the org, plus an unrelated workspace.
    policy.add_grant(Grant {
        id: GrantId("g_org".into()),
        subject: GrantSubject::Principal(account("ada")),
        action_pattern: ActionPattern("project.read".into()),
        scope: ScopeRef::Org {
            org_id: OrgId("acme".into()),
        },
        effect: Effect::Allow,
    });

    let candidates = vec![
        project_scope("ws_main", "proj_web"),
        project_scope("ws_other", "proj_api"),
        ScopeRef::Workspace {
            workspace_id: WorkspaceId("ws_main".into()),
        },
    ];
    let visible = policy.visible(
        &account("ada"),
        &ActionKey("project.read".into()),
        &candidates,
    );
    assert_eq!(
        visible,
        vec![
            project_scope("ws_main", "proj_web"),
            ScopeRef::Workspace {
                workspace_id: WorkspaceId("ws_main".into()),
            },
        ]
    );
}

#[test]
fn visible_excludes_require_approval_scopes() {
    let mut policy = PolicySet::new();
    policy.add_grant(Grant {
        id: GrantId("g_appr".into()),
        subject: GrantSubject::Principal(account("ada")),
        action_pattern: ActionPattern("project.read".into()),
        scope: ScopeRef::Global,
        effect: Effect::RequireApproval,
    });

    let candidates = vec![project_scope("ws_main", "proj_web")];
    let visible = policy.visible(
        &account("ada"),
        &ActionKey("project.read".into()),
        &candidates,
    );
    assert!(visible.is_empty());
}

#[test]
fn group_grant_reaches_members_and_not_outsiders() {
    let mut policy = PolicySet::new();
    policy.set_group_roster(GroupId("eng".into()), [account("ada")]);
    policy.add_grant(Grant {
        id: GrantId("g_eng".into()),
        subject: GrantSubject::Group(GroupId("eng".into())),
        action_pattern: ActionPattern("pack.publish".into()),
        scope: ScopeRef::Global,
        effect: Effect::Allow,
    });

    // A member inherits the group's grant...
    let member = policy.evaluate(&request(account("ada"), "pack.publish", ScopeRef::Global));
    assert_eq!(member.decision, AuthorizationDecision::Allow);
    assert_eq!(member.reason, DecisionReason::AllowedByGrant);
    assert_eq!(member.matched_grants, vec![GrantId("g_eng".into())]);
    // ...the grant carries no role, so the trace records none.
    assert!(member.matched_roles.is_empty());

    // ...an outsider does not.
    let outsider = policy.evaluate(&request(account("bob"), "pack.publish", ScopeRef::Global));
    assert_eq!(outsider.decision, AuthorizationDecision::Deny);
    assert_eq!(outsider.reason, DecisionReason::DefaultDeny);
}

#[test]
fn joining_or_leaving_a_group_changes_permissions_immediately() {
    let mut policy = PolicySet::new();
    policy.add_grant(Grant {
        id: GrantId("g_eng".into()),
        subject: GrantSubject::Group(GroupId("eng".into())),
        action_pattern: ActionPattern("pack.publish".into()),
        scope: ScopeRef::Global,
        effect: Effect::Allow,
    });

    let req = || request(account("ada"), "pack.publish", ScopeRef::Global);
    // Not yet a member: denied.
    assert_eq!(
        policy.evaluate(&req()).decision,
        AuthorizationDecision::Deny
    );

    // Joining the group grants the permission on the next evaluation, with no
    // re-expansion into per-member grants.
    assert!(policy.add_group_member(GroupId("eng".into()), account("ada")));
    assert_eq!(
        policy.evaluate(&req()).decision,
        AuthorizationDecision::Allow
    );

    // Leaving revokes it again immediately.
    assert!(policy.remove_group_member(&GroupId("eng".into()), &account("ada")));
    assert_eq!(
        policy.evaluate(&req()).decision,
        AuthorizationDecision::Deny
    );
}

#[test]
fn group_role_binding_lets_members_use_the_role_grants() {
    let mut policy = PolicySet::new();
    // A Team: a group roster + a scope + a group role binding.
    policy.set_group_roster(GroupId("eng".into()), [account("ada")]);
    policy.bind_group_role(GroupRoleBinding {
        group: GroupId("eng".into()),
        role: RoleId("publisher".into()),
        scope: ScopeRef::Namespace {
            namespace_id: NamespaceId("acme".into()),
        },
    });
    policy.add_grant(Grant {
        id: GrantId("g_pub".into()),
        subject: GrantSubject::Role(RoleId("publisher".into())),
        action_pattern: ActionPattern("pack.publish".into()),
        scope: ScopeRef::Namespace {
            namespace_id: NamespaceId("acme".into()),
        },
        effect: Effect::Allow,
    });

    let trace = policy.evaluate(&request(
        account("ada"),
        "pack.publish",
        ScopeRef::Namespace {
            namespace_id: NamespaceId("acme".into()),
        },
    ));
    assert_eq!(trace.decision, AuthorizationDecision::Allow);
    assert_eq!(trace.matched_grants, vec![GrantId("g_pub".into())]);
    assert_eq!(trace.matched_roles, vec![RoleId("publisher".into())]);

    // Drop the member from the roster: the role and its grant fall away.
    policy.remove_group_member(&GroupId("eng".into()), &account("ada"));
    let revoked = policy.evaluate(&request(
        account("ada"),
        "pack.publish",
        ScopeRef::Namespace {
            namespace_id: NamespaceId("acme".into()),
        },
    ));
    assert_eq!(revoked.decision, AuthorizationDecision::Deny);
}

#[test]
fn group_deny_grant_still_takes_precedence() {
    let mut policy = PolicySet::new();
    policy.set_group_roster(GroupId("eng".into()), [account("ada")]);
    policy.add_grant(Grant {
        id: GrantId("g_allow".into()),
        subject: GrantSubject::Principal(account("ada")),
        action_pattern: ActionPattern("pack.*".into()),
        scope: ScopeRef::Global,
        effect: Effect::Allow,
    });
    policy.add_grant(Grant {
        id: GrantId("g_group_deny".into()),
        subject: GrantSubject::Group(GroupId("eng".into())),
        action_pattern: ActionPattern("pack.publish".into()),
        scope: ScopeRef::Global,
        effect: Effect::Deny,
    });

    let trace = policy.evaluate(&request(account("ada"), "pack.publish", ScopeRef::Global));
    assert_eq!(trace.decision, AuthorizationDecision::Deny);
    assert_eq!(trace.reason, DecisionReason::DeniedByGrant);
    assert_eq!(trace.matched_grants, vec![GrantId("g_group_deny".into())]);
}

#[test]
fn synced_snapshot_resolves_group_membership_identically() {
    let mut policy = PolicySet::new();
    policy.set_group_roster(GroupId("eng".into()), [account("ada")]);
    policy.add_grant(Grant {
        id: GrantId("g_eng".into()),
        subject: GrantSubject::Group(GroupId("eng".into())),
        action_pattern: ActionPattern("pack.*".into()),
        scope: ScopeRef::Global,
        effect: Effect::Allow,
    });
    policy.bind_group_role(GroupRoleBinding {
        group: GroupId("eng".into()),
        role: RoleId("publisher".into()),
        scope: ScopeRef::Global,
    });

    let snapshot = policy.snapshot(3);
    assert_eq!(snapshot.group_rosters.len(), 1);
    assert_eq!(snapshot.group_role_bindings.len(), 1);
    let local = PolicySet::from_snapshot(&snapshot);

    for (principal, action) in [(account("ada"), "pack.read"), (account("bob"), "pack.read")] {
        let req = request(principal, action, ScopeRef::Global);
        // A consumer evaluating from the synced snapshot resolves the live
        // roster exactly as the server does.
        assert_eq!(
            local.evaluate(&req).to_outcome(),
            policy.evaluate(&req).to_outcome()
        );
    }
}
