//! Per-consumer action-namespace convention, exercised end-to-end through the
//! **real** authorization engine via the public `awaken-iam` facade (ADR-0008
//! decision 8).
//!
//! These tests pin the convention's two load-bearing claims:
//!
//! - **Products are action namespaces, not configuration.** A consumer registers
//!   a [`ResourceModel`] whose actions live under its namespace (`agent.*` for
//!   managed agents, `oversight.*`/`issue.*` for Oversight); the
//!   [`ConsumerNamespaces`] convention renders that surface as a grant set and
//!   confirms a registered model stays inside it.
//! - **Reach is a role property, never a partition.** Running the same
//!   `PolicySet::evaluate`, one key spans both products by holding a role whose
//!   grants cross both namespaces, while a workspace-scoped role confines another
//!   key to one — and the cross-product key can still be `Allow` for `agent.*`
//!   and `RequireApproval` for an `oversight.*` action under one evaluation, with
//!   no second config.

use awaken_iam::{
    AccountId, ActionKey, ActionPattern, AuthorizationDecision, AuthorizationRequest,
    ConsumerNamespaces, Effect, Grant, GrantId, GrantSubject, OrgId, PolicySet, PrincipalRef,
    ResourceModel, ResourceType, ResourceTypeDef, RoleBinding, RoleId, ScopeRef, WorkspaceId,
    managed_agents, oversight,
};

fn account(id: &str) -> PrincipalRef {
    PrincipalRef::Account {
        account_id: AccountId(id.into()),
    }
}

/// The managed-agents product surface: an `agent` resource type whose actions all
/// live under the `agent.*` namespace.
fn managed_agents_model() -> ResourceModel {
    let mut model = ResourceModel::new();
    model.register_resource_type(ResourceTypeDef {
        resource_type: ResourceType("agent".into()),
        parent_type: None,
        actions: vec![
            ActionKey("agent.run".into()),
            ActionKey("agent.configure".into()),
        ],
    });
    model
}

/// The Oversight product surface: an `issue` resource type plus the standalone
/// `oversight.*` actions, all inside the Oversight namespaces.
fn oversight_model() -> ResourceModel {
    let mut model = ResourceModel::new();
    model
        .register_resource_type(ResourceTypeDef {
            resource_type: ResourceType("issue".into()),
            parent_type: None,
            actions: vec![
                ActionKey("issue.read".into()),
                ActionKey("issue.advance".into()),
            ],
        })
        .register_action(ActionKey("oversight.read".into()))
        .register_action(ActionKey("oversight.deploy".into()));
    model
}

/// Each consumer's registered model stays inside the namespaces it declares —
/// the product surface is exactly what the model registers, nothing leaks across.
#[test]
fn each_consumer_model_is_confined_to_its_declared_namespaces() {
    assert_eq!(managed_agents().confines(&managed_agents_model()), Ok(()));
    assert_eq!(oversight().confines(&oversight_model()), Ok(()));

    // The boundary is real: neither product's model is confined by the other's
    // declaration, and the offending actions are reported, not silently allowed.
    assert_eq!(
        oversight().confines(&managed_agents_model()),
        Err(vec![
            ActionKey("agent.configure".into()),
            ActionKey("agent.run".into()),
        ])
    );
    assert!(managed_agents().confines(&oversight_model()).is_err());
}

/// Grants carried by `role` for every glob pattern of `consumer`, with `effect`.
fn namespace_grants(role: &RoleId, consumer: &ConsumerNamespaces, effect: Effect) -> Vec<Grant> {
    consumer
        .glob_patterns()
        .into_iter()
        .enumerate()
        .map(|(index, pattern)| Grant {
            id: GrantId(format!("g_{}_{}_{index}", role.0, pattern.0)),
            subject: GrantSubject::Role(role.clone()),
            action_pattern: pattern,
            scope: ScopeRef::Org {
                org_id: OrgId("org_acme".into()),
            },
            effect,
        })
        .collect()
}

/// One key spans both products because the role it holds carries grants crossing
/// both namespaces — and the same key is `Allow` for `agent.*` yet
/// `RequireApproval` for a gated `oversight.*` action, all under one evaluation
/// with no per-product wiring. A second key, holding a workspace-scoped role that
/// carries only Oversight's namespaces, is confined to that product.
#[test]
fn one_role_spans_both_products_and_a_narrower_one_confines() {
    let org = OrgId("org_acme".into());
    let workspace = WorkspaceId("ws_acme".into());

    let mut policy = PolicySet::new();
    // Both products teach the engine their resource models; the workspace nests
    // under the org so an org-scoped binding reaches workspace-scoped requests.
    policy.register_resource_model(&managed_agents_model());
    policy.register_resource_model(&oversight_model());
    policy
        .scope_graph_mut()
        .assign_workspace(workspace.clone(), org.clone());

    // The cross-product role: Allow over both products' namespaces, plus a single
    // RequireApproval grant gating one Oversight action (deny/approval beats the
    // namespace-wide allow under the effect lattice).
    let operator = RoleId("platform_operator".into());
    for grant in namespace_grants(&operator, &managed_agents(), Effect::Allow) {
        policy.add_grant(grant);
    }
    for grant in namespace_grants(&operator, &oversight(), Effect::Allow) {
        policy.add_grant(grant);
    }
    policy.add_grant(Grant {
        id: GrantId("g_operator_deploy_gate".into()),
        subject: GrantSubject::Role(operator.clone()),
        action_pattern: ActionPattern("oversight.deploy".into()),
        scope: ScopeRef::Org {
            org_id: org.clone(),
        },
        effect: Effect::RequireApproval,
    });

    // The Oversight-only role carries just the Oversight glob set.
    let triage = RoleId("oversight_triage".into());
    for grant in namespace_grants(&triage, &oversight(), Effect::Allow) {
        policy.add_grant(grant);
    }

    // One key holds the cross-product role at the org; the other holds the
    // confined role only at the workspace.
    let crossing_key = account("acct_operator");
    let confined_key = account("acct_triage");
    policy.bind_role(RoleBinding {
        principal: crossing_key.clone(),
        role: operator,
        scope: ScopeRef::Org {
            org_id: org.clone(),
        },
    });
    policy.bind_role(RoleBinding {
        principal: confined_key.clone(),
        role: triage,
        scope: ScopeRef::Workspace {
            workspace_id: workspace.clone(),
        },
    });

    let at_workspace = |who: &PrincipalRef, action: &str| {
        policy
            .evaluate(&AuthorizationRequest::direct(
                who.clone(),
                ActionKey(action.into()),
                ScopeRef::Workspace {
                    workspace_id: workspace.clone(),
                },
            ))
            .decision
    };

    // The cross-product key reaches both products with one binding...
    assert_eq!(
        at_workspace(&crossing_key, "agent.run"),
        AuthorizationDecision::Allow
    );
    assert_eq!(
        at_workspace(&crossing_key, "issue.advance"),
        AuthorizationDecision::Allow
    );
    assert_eq!(
        at_workspace(&crossing_key, "oversight.read"),
        AuthorizationDecision::Allow
    );
    // ...yet the gated Oversight action resolves to RequireApproval for the *same*
    // key under the same evaluation — the Allow/approval split is per action.
    assert_eq!(
        at_workspace(&crossing_key, "oversight.deploy"),
        AuthorizationDecision::RequireApproval
    );

    // The confined key reaches Oversight but not managed agents: nothing binds it
    // to the agent namespace, so default-deny holds (a binding choice, not a
    // per-product config).
    assert_eq!(
        at_workspace(&confined_key, "issue.advance"),
        AuthorizationDecision::Allow
    );
    assert_eq!(
        at_workspace(&confined_key, "agent.run"),
        AuthorizationDecision::Deny
    );

    // And an unbound key reaches neither — no key is bound to a product.
    let stranger = account("acct_stranger");
    assert_eq!(
        at_workspace(&stranger, "agent.run"),
        AuthorizationDecision::Deny
    );
    assert_eq!(
        at_workspace(&stranger, "issue.read"),
        AuthorizationDecision::Deny
    );
}
