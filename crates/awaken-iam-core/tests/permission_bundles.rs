use std::collections::BTreeSet;

use awaken_iam_contract::{
    AccountId, ActionKey, ActionScopeRule, AuthorizationAccess, AuthorizationAmount,
    AuthorizationAmountRange, AuthorizationContext, AuthorizationDataScope, AuthorizationDecision,
    AuthorizationProfile, AuthorizationProfileDocument, AuthorizationRequest, GrantConstraint,
    GrantEffect, GrantSnapshot, GrantSubjectRef, GroupRoleBindingSnapshot, NamespaceId,
    PermissionBundleMetadata, PrincipalRef, ProfileLifecycle, ProjectId,
    ResourceAuthorizationRequest, ResourceModelRegistration, RoleBindingLimit, RoleBindingSnapshot,
    ScopeKind, ScopeRef, Timestamp, WorkspaceId,
};
use awaken_iam_core::{GroupId, PolicySet};

const ROLE: &str = "operations.business:role:sales";
const TEAM: &str = "awaken.flow:team:sales";

fn account(id: &str) -> PrincipalRef {
    PrincipalRef::Account {
        account_id: AccountId(id.into()),
    }
}

fn workspace(id: &str) -> ScopeRef {
    ScopeRef::Workspace {
        workspace_id: WorkspaceId(id.into()),
    }
}

fn project(id: &str) -> ScopeRef {
    ScopeRef::Project {
        workspace_id: WorkspaceId("wa".into()),
        project_id: ProjectId(id.into()),
    }
}

fn grant(id: &str, action: &str, effect: GrantEffect) -> GrantSnapshot {
    GrantSnapshot {
        id: format!("operations.business:{id}"),
        subject: GrantSubjectRef::Role {
            role_id: ROLE.into(),
        },
        action_pattern: format!("operations.business::{action}"),
        scope: ScopeRef::Global,
        effect,
    }
}

fn constraint(id: &str, data_scope: AuthorizationDataScope) -> GrantConstraint {
    GrantConstraint {
        grant_id: format!("operations.business:{id}"),
        data_scope,
        readable_fields: None,
        writable_fields: None,
        amount_range: None,
        prohibit_initiator: false,
    }
}

fn document(
    grants: Vec<GrantSnapshot>,
    constraints: Vec<GrantConstraint>,
) -> AuthorizationProfileDocument {
    let actions = grants
        .iter()
        .map(|grant| grant.action_pattern.clone())
        .collect::<BTreeSet<_>>();
    AuthorizationProfileDocument {
        resource_model: ResourceModelRegistration {
            actions: actions.iter().cloned().map(ActionKey).collect(),
            ..Default::default()
        },
        action_scope_rules: actions
            .into_iter()
            .map(|action_pattern| ActionScopeRule {
                action_pattern,
                allowed_scope_kinds: vec![ScopeKind::Workspace, ScopeKind::Project],
            })
            .collect(),
        grants,
        grant_constraints: constraints,
        role_bindings: vec![RoleBindingSnapshot {
            principal: account("alice"),
            role_id: ROLE.into(),
            scope: project("p1"),
        }],
        permission_bundles: vec![PermissionBundleMetadata {
            role_id: ROLE.into(),
            key: "sales".into(),
            name: "Sales operations".into(),
            owner_scope: workspace("wa"),
            source_id: "example/sales".into(),
            source_revision: "1".into(),
            source_digest: format!("sha256:{}", "a".repeat(64)),
        }],
        ..Default::default()
    }
}

fn policy(document: AuthorizationProfileDocument) -> PolicySet {
    PolicySet::from_profile(&AuthorizationProfile {
        namespace: NamespaceId("operations.business".into()),
        revision: 1,
        lifecycle: ProfileLifecycle::Active,
        document,
        checksum: "test".into(),
        created_at: Timestamp("2026-10-12T00:00:00Z".into()),
    })
}

fn request(action: &str, owner: &str) -> ResourceAuthorizationRequest {
    ResourceAuthorizationRequest {
        request: AuthorizationRequest::direct(
            account("alice"),
            ActionKey(format!("operations.business::{action}")),
            project("p1"),
        ),
        context: AuthorizationContext {
            evaluated_at: Some(100),
            resource_id: Some("customer-1".into()),
            owner: Some(account(owner)),
            access: AuthorizationAccess::Read,
            fields: Some(vec!["name".into()]),
            groups: Some(vec![TEAM.into()]),
            ..Default::default()
        },
    }
}

#[test]
fn ownership_is_checked_on_the_exact_action_and_requires_trusted_facts() {
    let policy = policy(document(
        vec![grant("edit", "customer.update", GrantEffect::Allow)],
        vec![constraint("edit", AuthorizationDataScope::Owner)],
    ));
    let own = request("customer.update", "alice");
    assert_eq!(
        policy.evaluate_resource(&own).decision,
        AuthorizationDecision::Allow
    );
    assert_eq!(
        policy
            .evaluate_resource(&request("customer.update", "bob"))
            .decision,
        AuthorizationDecision::Deny
    );
    assert_eq!(
        policy.evaluate(&own.request).decision,
        AuthorizationDecision::Deny
    );
    let mut missing = own;
    missing.context.owner = None;
    assert_eq!(
        policy.evaluate_resource(&missing).decision,
        AuthorizationDecision::Deny
    );
}

#[test]
fn broad_read_cannot_expand_an_owned_write_and_project_binding_stays_narrow() {
    let policy = policy(document(
        vec![
            grant("read", "customer.read", GrantEffect::Allow),
            grant("edit", "customer.update", GrantEffect::Allow),
        ],
        vec![
            constraint("read", AuthorizationDataScope::AuthorizedScope),
            constraint("edit", AuthorizationDataScope::Owner),
        ],
    ));
    assert_eq!(
        policy
            .evaluate_resource(&request("customer.read", "bob"))
            .decision,
        AuthorizationDecision::Allow
    );
    assert_eq!(
        policy
            .evaluate_resource(&request("customer.update", "bob"))
            .decision,
        AuthorizationDecision::Deny
    );
    let mut sibling = request("customer.read", "alice");
    sibling.request.scope = project("p2");
    assert_eq!(
        policy.evaluate_resource(&sibling).decision,
        AuthorizationDecision::Deny
    );
}

#[test]
fn live_team_role_requires_the_same_target_team_and_leaving_revokes_next_evaluation() {
    let mut document = document(
        vec![grant("read", "customer.read", GrantEffect::Allow)],
        vec![constraint("read", AuthorizationDataScope::BindingGroup)],
    );
    document.role_bindings.clear();
    document.group_role_bindings.push(GroupRoleBindingSnapshot {
        group_id: TEAM.into(),
        role_id: ROLE.into(),
        scope: project("p1"),
    });
    let mut policy = policy(document);
    let request = request("customer.read", "alice");
    assert_eq!(
        policy.evaluate_resource(&request).decision,
        AuthorizationDecision::Deny
    );
    policy.add_group_member(GroupId(TEAM.into()), account("alice"));
    assert_eq!(
        policy.evaluate_resource(&request).decision,
        AuthorizationDecision::Allow
    );
    let mut another_team = request.clone();
    another_team.context.groups = Some(vec!["awaken.flow:team:other".into()]);
    assert_eq!(
        policy.evaluate_resource(&another_team).decision,
        AuthorizationDecision::Deny
    );
    policy.remove_group_member(&GroupId(TEAM.into()), &account("alice"));
    assert_eq!(
        policy.evaluate_resource(&request).decision,
        AuthorizationDecision::Deny
    );
}

#[test]
fn field_limits_require_exact_demands_and_do_not_transfer_between_read_and_write() {
    let mut read = constraint("read", AuthorizationDataScope::Owner);
    read.readable_fields = Some(vec!["name".into()]);
    read.writable_fields = Some(vec![]);
    let policy = policy(document(
        vec![grant("read", "customer.read", GrantEffect::Allow)],
        vec![read],
    ));
    let mut request = request("customer.read", "alice");
    assert_eq!(
        policy.evaluate_resource(&request).decision,
        AuthorizationDecision::Allow
    );
    request.context.fields = Some(vec!["profit".into()]);
    assert_eq!(
        policy.evaluate_resource(&request).decision,
        AuthorizationDecision::Deny
    );
    request.context.fields = None;
    assert_eq!(
        policy.evaluate_resource(&request).decision,
        AuthorizationDecision::Deny
    );
    request.context.fields = Some(vec!["name".into()]);
    request.context.access = AuthorizationAccess::Write;
    assert_eq!(
        policy.evaluate_resource(&request).decision,
        AuthorizationDecision::Deny
    );
    request.context.access = AuthorizationAccess::Operate;
    assert_eq!(
        policy.evaluate_resource(&request).decision,
        AuthorizationDecision::Deny
    );
}

#[test]
fn explicit_field_denial_wins_without_removing_other_fields_or_authorized_row_counts() {
    let mut deny = constraint("deny-bank", AuthorizationDataScope::AuthorizedScope);
    deny.readable_fields = Some(vec!["bank_account".into()]);
    let policy = policy(document(
        vec![
            grant("read", "customer.read", GrantEffect::Allow),
            grant("deny-bank", "customer.read", GrantEffect::Deny),
        ],
        vec![
            constraint("read", AuthorizationDataScope::AuthorizedScope),
            deny,
        ],
    ));
    let mut request = request("customer.read", "alice");
    assert_eq!(
        policy.evaluate_resource(&request).decision,
        AuthorizationDecision::Allow
    );
    request.context.fields = Some(vec!["bank_account".into()]);
    assert_eq!(
        policy.evaluate_resource(&request).decision,
        AuthorizationDecision::Deny
    );
    request.context.fields = Some(vec![]);
    assert_eq!(
        policy.evaluate_resource(&request).decision,
        AuthorizationDecision::Allow
    );
}

#[test]
fn amount_approval_cannot_be_bypassed_by_plain_allow_or_missing_currency() {
    let mut approval = constraint("approval", AuthorizationDataScope::AuthorizedScope);
    approval.amount_range = Some(AuthorizationAmountRange {
        currency: "CNY".into(),
        minimum: Some(100_001),
        maximum: None,
    });
    let policy = policy(document(
        vec![
            grant("pay", "payment.execute", GrantEffect::Allow),
            grant("approval", "payment.execute", GrantEffect::RequireApproval),
        ],
        vec![
            constraint("pay", AuthorizationDataScope::AuthorizedScope),
            approval,
        ],
    ));
    let mut request = request("payment.execute", "alice");
    assert_eq!(
        policy.evaluate_resource(&request).reason.code(),
        "required_facts_unavailable"
    );
    request.context.amount = Some(AuthorizationAmount {
        minor_units: 100_000,
        currency: "CNY".into(),
    });
    assert_eq!(
        policy.evaluate_resource(&request).decision,
        AuthorizationDecision::Allow
    );
    request.context.amount.as_mut().unwrap().minor_units = 100_001;
    assert_eq!(
        policy.evaluate_resource(&request).decision,
        AuthorizationDecision::RequireApproval
    );
    request.context.amount.as_mut().unwrap().currency = "USD".into();
    assert_eq!(
        policy.evaluate_resource(&request).decision,
        AuthorizationDecision::Deny
    );
}

#[test]
fn expiry_and_exact_target_limit_narrow_a_native_binding() {
    let mut document = document(
        vec![grant("read", "customer.read", GrantEffect::Allow)],
        vec![constraint("read", AuthorizationDataScope::AuthorizedScope)],
    );
    document.binding_limits.push(RoleBindingLimit {
        subject: GrantSubjectRef::Principal {
            principal: account("alice"),
        },
        role_id: ROLE.into(),
        scope: project("p1"),
        expires_at: Some(200),
        resource_ids: Some(vec!["customer-1".into()]),
    });
    let policy = policy(document);
    let mut request = request("customer.read", "alice");
    assert_eq!(
        policy.evaluate_resource(&request).decision,
        AuthorizationDecision::Allow
    );
    request.context.resource_id = Some("customer-2".into());
    assert_eq!(
        policy.evaluate_resource(&request).decision,
        AuthorizationDecision::Deny
    );
    request.context.resource_id = Some("customer-1".into());
    request.context.evaluated_at = Some(200);
    assert_eq!(
        policy.evaluate_resource(&request).decision,
        AuthorizationDecision::Deny
    );
    request.context.evaluated_at = None;
    assert_eq!(
        policy.evaluate_resource(&request).decision,
        AuthorizationDecision::Deny
    );
}

#[test]
fn an_overbroad_binding_cannot_move_a_bundle_outside_its_owner_workspace() {
    let mut document = document(
        vec![grant("read", "customer.read", GrantEffect::Allow)],
        vec![constraint("read", AuthorizationDataScope::AuthorizedScope)],
    );
    document.role_bindings[0].scope = ScopeRef::Global;
    let policy = policy(document);
    let mut request = request("customer.read", "alice");
    request.request.scope = workspace("other");
    assert_eq!(
        policy.evaluate_resource(&request).decision,
        AuthorizationDecision::Deny
    );
}

#[test]
fn delegated_agent_needs_its_own_grant_and_preserves_the_humans_ownership_limit() {
    let agent = PrincipalRef::Service {
        service_id: "agent".into(),
    };
    let mut document = document(
        vec![grant("read", "customer.read", GrantEffect::Allow)],
        vec![constraint("read", AuthorizationDataScope::Owner)],
    );
    let mut policy_without_agent = policy(document.clone());
    let mut request = request("customer.read", "alice");
    request.request.on_behalf_of.push(agent.clone());
    assert_eq!(
        policy_without_agent.evaluate_resource(&request).decision,
        AuthorizationDecision::Deny
    );
    document.grants.push(GrantSnapshot {
        id: "operations.business:agent-read".into(),
        subject: GrantSubjectRef::Principal { principal: agent },
        action_pattern: "operations.business::customer.read".into(),
        scope: project("p1"),
        effect: GrantEffect::Allow,
    });
    policy_without_agent = policy(document);
    assert_eq!(
        policy_without_agent.evaluate_resource(&request).decision,
        AuthorizationDecision::Allow
    );
    request.context.owner = Some(account("bob"));
    assert_eq!(
        policy_without_agent.evaluate_resource(&request).decision,
        AuthorizationDecision::Deny
    );
}

#[test]
fn responsible_person_and_separation_of_duties_use_actual_principals() {
    let mut rule = constraint("review", AuthorizationDataScope::Responsible);
    rule.prohibit_initiator = true;
    let policy = policy(document(
        vec![grant("review", "contract.review", GrantEffect::Allow)],
        vec![rule],
    ));
    let mut request = request("contract.review", "alice");
    request.context.responsible = Some(account("alice"));
    request.context.initiator = Some(account("bob"));
    assert_eq!(
        policy.evaluate_resource(&request).decision,
        AuthorizationDecision::Allow
    );
    request.context.initiator = Some(account("alice"));
    assert_eq!(
        policy.evaluate_resource(&request).decision,
        AuthorizationDecision::Deny
    );
    request.context.initiator = None;
    assert_eq!(
        policy.evaluate_resource(&request).decision,
        AuthorizationDecision::Deny
    );
}
