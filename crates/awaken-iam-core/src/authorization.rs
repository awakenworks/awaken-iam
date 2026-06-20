//! Authorization evaluation engine.
//!
//! Implements the `Principal + Action + Scope -> Decision` shape described in
//! the IAM model and the authorization-engine design. Evaluation is
//! default-deny: a request is allowed only when at least one matching grant
//! (held directly by the principal or through a role binding) permits it.
//!
//! A request carries a conjunctive principal *chain* (length one for a direct
//! caller, longer for on-behalf-of dispatch such as `[human, agent]`): every
//! link must be permitted. The decision is three-valued —
//! `Allow | Deny | RequireApproval` — under the precedence
//! `deny > require_approval > allow > default-deny`. An empty chain is denied as
//! `principal_unresolved`; no principal ever means allow.
//!
//! The evaluator resolves the scope graph
//! (`global -> org -> namespace/workspace -> project`) so a grant issued at a
//! broader scope covers requests at narrower scopes underneath it. Parent links
//! that are not derivable from a [`ScopeRef`] alone (org membership of
//! namespaces and workspaces) are recorded in the [`ScopeGraph`]; the
//! `workspace -> project` link is intrinsic to `ScopeRef::Project`.
//!
//! Every evaluation returns an [`AuthorizationTrace`] carrying the decision, a
//! stable reason code, and the ids of the grants and roles that produced it, so
//! audit and debug surfaces can explain why a request was allowed or denied.

use std::collections::HashMap;
use std::collections::HashSet;

use awaken_iam_contract::{
    ActionKey, AuthorizationDecision, AuthorizationRequest, NamespaceId, OrgId, PrincipalRef,
    ResourceId, ResourceType, ScopeRef, WorkspaceId,
};

/// Identifier of a role (a reusable bundle of grants).
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct RoleId(pub String);

/// Identifier of an individual grant.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct GrantId(pub String);

/// Effect of a grant.
///
/// v1 policy is expected to issue [`Effect::Allow`] and
/// [`Effect::RequireApproval`]; introducing deny grants in stored policy
/// requires a future ADR. The evaluator still models [`Effect::Deny`] so the
/// precedence seam (deny overrides everything) exists from the start and does
/// not need to be retrofitted.
///
/// Precedence among matching grants is `Deny > RequireApproval > Allow`,
/// mirroring the three-valued decision lattice.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Effect {
    /// Permit the action.
    Allow,
    /// Permit the action only after the caller completes an approval step.
    RequireApproval,
    /// Forbid the action, overriding any matching allow or approval grant.
    Deny,
}

/// Pattern matched against a requested [`ActionKey`].
///
/// Supported forms:
///
/// - `*` matches every action;
/// - a dotted prefix wildcard such as `project.*` matches `project` and any
///   action under it (`project.read`, `project.configure`, ...);
/// - any other value matches a single action key exactly.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct ActionPattern(pub String);

impl ActionPattern {
    /// Returns whether this pattern matches `action`.
    pub fn matches(&self, action: &ActionKey) -> bool {
        let pattern = self.0.as_str();
        if pattern == "*" {
            return true;
        }
        if let Some(prefix) = pattern.strip_suffix(".*") {
            let value = action.0.as_str();
            return value == prefix
                || value
                    .strip_prefix(prefix)
                    .is_some_and(|rest| rest.starts_with('.'));
        }
        pattern == action.0
    }
}

/// Subject a grant applies to: a concrete principal or a role.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum GrantSubject {
    /// A grant attached directly to a principal.
    Principal(PrincipalRef),
    /// A grant carried by a role; it applies to any principal bound to the role
    /// at a covering scope.
    Role(RoleId),
}

/// A single grant: it permits (or denies) an action pattern at a scope for a
/// subject.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Grant {
    /// Stable grant id surfaced in the decision trace.
    pub id: GrantId,
    /// Principal or role the grant applies to.
    pub subject: GrantSubject,
    /// Action pattern the grant covers.
    pub action_pattern: ActionPattern,
    /// Scope at which the grant is issued; it covers this scope and everything
    /// beneath it in the scope graph.
    pub scope: ScopeRef,
    /// Whether the grant allows, requires approval, or denies.
    pub effect: Effect,
}

/// Binds a principal to a role at a scope.
///
/// The binding lets the principal use every grant carried by the role for
/// requests at the binding scope and anything beneath it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RoleBinding {
    /// Principal that holds the role.
    pub principal: PrincipalRef,
    /// Role being granted to the principal.
    pub role: RoleId,
    /// Scope at which the binding applies.
    pub scope: ScopeRef,
}

/// Stable reason code explaining an authorization decision.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DecisionReason {
    /// Every principal in the chain was allowed and none required approval.
    AllowedByGrant,
    /// At least one principal matched a require-approval grant and none was
    /// denied; the caller must complete the approval before proceeding.
    NeedsApproval,
    /// A deny grant matched a principal and took precedence over any allow or
    /// approval grant.
    DeniedByGrant,
    /// At least one principal in the chain had no matching grant; the
    /// default-deny rule applied.
    DefaultDeny,
    /// The request carried no resolvable principal; no principal ever means
    /// allow, so the chain is denied before any grant is consulted.
    PrincipalUnresolved,
}

impl DecisionReason {
    /// Returns a stable snake_case code suitable for audit logs and UIs.
    pub fn code(&self) -> &'static str {
        match self {
            DecisionReason::AllowedByGrant => "allowed_by_grant",
            DecisionReason::NeedsApproval => "needs_approval",
            DecisionReason::DeniedByGrant => "denied_by_grant",
            DecisionReason::DefaultDeny => "default_deny",
            DecisionReason::PrincipalUnresolved => "principal_unresolved",
        }
    }
}

/// Decision plus the trace explaining how it was reached.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuthorizationTrace {
    /// The three-valued outcome (allow, deny, or require-approval).
    pub decision: AuthorizationDecision,
    /// Reason code for the outcome.
    pub reason: DecisionReason,
    /// Ids of the grants that produced the deciding effect, in policy order.
    pub matched_grants: Vec<GrantId>,
    /// Ids of the roles whose grants contributed to the deciding effect, in
    /// policy order.
    pub matched_roles: Vec<RoleId>,
}

/// Records scope-graph parent links that cannot be derived from a [`ScopeRef`]
/// on its own.
///
/// `ScopeRef::Project` already carries its `workspace_id`, so the
/// `workspace -> project` edge is intrinsic. The `org -> namespace` and
/// `org -> workspace` edges are not encoded in the ids, so they are registered
/// here to complete the `global -> org -> namespace/workspace -> project`
/// hierarchy.
///
/// Open [`ScopeRef::Resource`] scopes are product data: where a resource sits in
/// the hierarchy is never inferred from its ids. Each resource instance's parent
/// edge is registered with [`ScopeGraph::assign_resource_parent`] (typically by
/// applying a [`ResourceModel`]). Because a resource's parent may itself be a
/// resource, the walk follows these edges iteratively, so arbitrarily deep
/// product hierarchies (`issue:42 -> project:web -> workspace:ws -> org:acme ->
/// global`) resolve through the same ancestor walk. A resource with no
/// registered parent roots at itself: nothing outside an exactly-matching grant
/// covers it.
#[derive(Debug, Default, Clone)]
pub struct ScopeGraph {
    namespace_org: HashMap<NamespaceId, OrgId>,
    workspace_org: HashMap<WorkspaceId, OrgId>,
    resource_parent: HashMap<(ResourceType, ResourceId), ScopeRef>,
}

impl ScopeGraph {
    /// Create an empty scope graph.
    pub fn new() -> Self {
        Self::default()
    }

    /// Record that `namespace` belongs to `org`.
    pub fn assign_namespace(&mut self, namespace: NamespaceId, org: OrgId) -> &mut Self {
        self.namespace_org.insert(namespace, org);
        self
    }

    /// Record that `workspace` belongs to `org`.
    pub fn assign_workspace(&mut self, workspace: WorkspaceId, org: OrgId) -> &mut Self {
        self.workspace_org.insert(workspace, org);
        self
    }

    /// Record the parent scope of an open product resource.
    ///
    /// `parent` may be any [`ScopeRef`], including another
    /// [`ScopeRef::Resource`], which is what lets the walk follow an
    /// arbitrarily deep product hierarchy up to its root.
    pub fn assign_resource_parent(
        &mut self,
        resource_type: ResourceType,
        resource_id: ResourceId,
        parent: ScopeRef,
    ) -> &mut Self {
        self.resource_parent
            .insert((resource_type, resource_id), parent);
        self
    }

    /// Returns the direct parent of `scope`, or `None` when `scope` is a root.
    ///
    /// `Global` is the well-known root. An open resource is a root when no
    /// parent edge has been registered for it.
    fn parent_of(&self, scope: &ScopeRef) -> Option<ScopeRef> {
        match scope {
            ScopeRef::Global => None,
            ScopeRef::Org { .. } => Some(ScopeRef::Global),
            ScopeRef::Namespace { namespace_id } => Some(
                self.namespace_org
                    .get(namespace_id)
                    .map(|org_id| ScopeRef::Org {
                        org_id: org_id.clone(),
                    })
                    .unwrap_or(ScopeRef::Global),
            ),
            ScopeRef::Workspace { workspace_id } => Some(
                self.workspace_org
                    .get(workspace_id)
                    .map(|org_id| ScopeRef::Org {
                        org_id: org_id.clone(),
                    })
                    .unwrap_or(ScopeRef::Global),
            ),
            ScopeRef::Project { workspace_id, .. } => Some(ScopeRef::Workspace {
                workspace_id: workspace_id.clone(),
            }),
            ScopeRef::Resource {
                resource_type,
                resource_id,
            } => self
                .resource_parent
                .get(&(resource_type.clone(), resource_id.clone()))
                .cloned(),
        }
    }

    /// Returns the inclusive ancestors of `scope`, ordered most specific first
    /// and ending at the scope's root.
    ///
    /// The walk follows [`ScopeGraph::parent_of`] edges, so it resolves
    /// arbitrarily deep open-resource hierarchies. A `seen` set guards against
    /// cycles accidentally introduced by misregistered parent edges, keeping
    /// evaluation terminating regardless of registration order.
    fn ancestors(&self, scope: &ScopeRef) -> Vec<ScopeRef> {
        let mut chain = vec![scope.clone()];
        let mut seen: HashSet<ScopeRef> = HashSet::new();
        seen.insert(scope.clone());
        let mut current = scope.clone();
        while let Some(parent) = self.parent_of(&current) {
            if !seen.insert(parent.clone()) {
                break;
            }
            chain.push(parent.clone());
            current = parent;
        }
        chain
    }

    /// Returns whether a grant issued at `grant_scope` covers a request at
    /// `request_scope`, i.e. `grant_scope` is `request_scope` or one of its
    /// ancestors.
    pub fn covers(&self, grant_scope: &ScopeRef, request_scope: &ScopeRef) -> bool {
        self.ancestors(request_scope)
            .iter()
            .any(|ancestor| ancestor == grant_scope)
    }
}

/// The grants, role bindings, and scope graph evaluated against a request.
#[derive(Debug, Default)]
pub struct PolicySet {
    grants: Vec<Grant>,
    role_bindings: Vec<RoleBinding>,
    scope_graph: ScopeGraph,
}

impl PolicySet {
    /// Create an empty policy set. An empty policy denies every request.
    pub fn new() -> Self {
        Self::default()
    }

    /// Add a grant to the policy.
    pub fn add_grant(&mut self, grant: Grant) -> &mut Self {
        self.grants.push(grant);
        self
    }

    /// Bind a principal to a role at a scope.
    pub fn bind_role(&mut self, binding: RoleBinding) -> &mut Self {
        self.role_bindings.push(binding);
        self
    }

    /// Mutable access to the scope graph for registering parent links.
    pub fn scope_graph_mut(&mut self) -> &mut ScopeGraph {
        &mut self.scope_graph
    }

    /// Register a product's [`ResourceModel`](crate::ResourceModel) so the
    /// evaluator resolves its open resource scopes.
    ///
    /// This folds the model's per-instance parent edges into the scope graph;
    /// afterwards a grant anchored at any registered ancestor covers requests on
    /// the product's resources through the same ancestor walk used for the
    /// well-known scopes.
    pub fn register_resource_model(&mut self, model: &crate::ResourceModel) -> &mut Self {
        model.apply_to(&mut self.scope_graph);
        self
    }

    /// Read-only access to the scope graph.
    pub fn scope_graph(&self) -> &ScopeGraph {
        &self.scope_graph
    }

    /// Roles held by `principal` for a request at `scope`, in policy order with
    /// duplicates removed.
    fn held_roles(&self, principal: &PrincipalRef, scope: &ScopeRef) -> Vec<RoleId> {
        let mut roles: Vec<RoleId> = Vec::new();
        for binding in &self.role_bindings {
            if &binding.principal != principal {
                continue;
            }
            if !self.scope_graph.covers(&binding.scope, scope) {
                continue;
            }
            if !roles.contains(&binding.role) {
                roles.push(binding.role.clone());
            }
        }
        roles
    }

    /// Grants matching one principal at `scope` for `action`, partitioned by
    /// effect in policy order with duplicate role ids removed.
    fn link_matches(
        &self,
        principal: &PrincipalRef,
        action: &ActionKey,
        scope: &ScopeRef,
    ) -> LinkMatches {
        let held_roles = self.held_roles(principal, scope);
        let mut matches = LinkMatches::default();

        for grant in &self.grants {
            let via_role = match &grant.subject {
                GrantSubject::Principal(grant_principal) => {
                    if grant_principal != principal {
                        continue;
                    }
                    None
                }
                GrantSubject::Role(role) => {
                    if !held_roles.contains(role) {
                        continue;
                    }
                    Some(role)
                }
            };
            if !grant.action_pattern.matches(action) {
                continue;
            }
            if !self.scope_graph.covers(&grant.scope, scope) {
                continue;
            }

            let (grants, roles) = match grant.effect {
                Effect::Allow => (&mut matches.allow_grants, &mut matches.allow_roles),
                Effect::RequireApproval => {
                    (&mut matches.approval_grants, &mut matches.approval_roles)
                }
                Effect::Deny => (&mut matches.deny_grants, &mut matches.deny_roles),
            };
            grants.push(grant.id.clone());
            if let Some(role) = via_role
                && !roles.contains(role)
            {
                roles.push(role.clone());
            }
        }

        matches
    }

    /// Evaluate `request` against the policy and return the decision trace.
    ///
    /// The request's principal chain is evaluated conjunctively: every link must
    /// be permitted, and the chain's outcome is the strongest effect any link
    /// contributes under the `deny > require_approval > allow > default-deny`
    /// lattice. An empty chain is [`DecisionReason::PrincipalUnresolved`].
    pub fn evaluate(&self, request: &AuthorizationRequest) -> AuthorizationTrace {
        let chain: Vec<&PrincipalRef> = request.principal_chain().collect();
        self.evaluate_chain(&chain, &request.action, &request.scope)
    }

    /// Evaluate an explicit principal `chain` for `action` at `scope`.
    ///
    /// This is the conjunctive core behind [`PolicySet::evaluate`]: it is shared
    /// by the request path and by callers that hold a chain directly. An empty
    /// chain denies with [`DecisionReason::PrincipalUnresolved`] — no principal
    /// never means allow.
    pub fn evaluate_chain(
        &self,
        chain: &[&PrincipalRef],
        action: &ActionKey,
        scope: &ScopeRef,
    ) -> AuthorizationTrace {
        if chain.is_empty() {
            return AuthorizationTrace {
                decision: AuthorizationDecision::Deny,
                reason: DecisionReason::PrincipalUnresolved,
                matched_grants: Vec::new(),
                matched_roles: Vec::new(),
            };
        }

        let mut deny_grants: Vec<GrantId> = Vec::new();
        let mut deny_roles: Vec<RoleId> = Vec::new();
        let mut approval_grants: Vec<GrantId> = Vec::new();
        let mut approval_roles: Vec<RoleId> = Vec::new();
        let mut allow_grants: Vec<GrantId> = Vec::new();
        let mut allow_roles: Vec<RoleId> = Vec::new();
        let mut any_unmatched = false;

        for principal in chain {
            let link = self.link_matches(principal, action, scope);
            if !link.is_permitted() {
                any_unmatched = true;
            }
            extend_unique(&mut deny_grants, link.deny_grants);
            extend_unique(&mut deny_roles, link.deny_roles);
            extend_unique(&mut approval_grants, link.approval_grants);
            extend_unique(&mut approval_roles, link.approval_roles);
            extend_unique(&mut allow_grants, link.allow_grants);
            extend_unique(&mut allow_roles, link.allow_roles);
        }

        // An explicit deny on any link is the strongest, most informative
        // outcome, so it is reported ahead of a bare default-deny.
        if !deny_grants.is_empty() {
            return AuthorizationTrace {
                decision: AuthorizationDecision::Deny,
                reason: DecisionReason::DeniedByGrant,
                matched_grants: deny_grants,
                matched_roles: deny_roles,
            };
        }
        // Conjunction: a link with no matching grant is not permitted, so the
        // whole chain defaults to deny even if other links would allow.
        if any_unmatched {
            return AuthorizationTrace {
                decision: AuthorizationDecision::Deny,
                reason: DecisionReason::DefaultDeny,
                matched_grants: Vec::new(),
                matched_roles: Vec::new(),
            };
        }
        if !approval_grants.is_empty() {
            return AuthorizationTrace {
                decision: AuthorizationDecision::RequireApproval,
                reason: DecisionReason::NeedsApproval,
                matched_grants: approval_grants,
                matched_roles: approval_roles,
            };
        }
        AuthorizationTrace {
            decision: AuthorizationDecision::Allow,
            reason: DecisionReason::AllowedByGrant,
            matched_grants: allow_grants,
            matched_roles: allow_roles,
        }
    }

    /// Filter `candidates` to the scopes on which `principal` may perform
    /// `action`, in input order.
    ///
    /// This answers a list endpoint's "which of these rows can the caller act
    /// on" in a single pass instead of one [`PolicySet::evaluate`] call per row.
    /// Only scopes that resolve to [`AuthorizationDecision::Allow`] are
    /// returned; `RequireApproval` is not yet permitted and is excluded.
    pub fn visible(
        &self,
        principal: &PrincipalRef,
        action: &ActionKey,
        candidates: &[ScopeRef],
    ) -> Vec<ScopeRef> {
        let chain = [principal];
        candidates
            .iter()
            .filter(|scope| {
                self.evaluate_chain(&chain, action, scope).decision == AuthorizationDecision::Allow
            })
            .cloned()
            .collect()
    }
}

/// Grants matching a single principal link, partitioned by effect.
#[derive(Debug, Default)]
struct LinkMatches {
    allow_grants: Vec<GrantId>,
    allow_roles: Vec<RoleId>,
    approval_grants: Vec<GrantId>,
    approval_roles: Vec<RoleId>,
    deny_grants: Vec<GrantId>,
    deny_roles: Vec<RoleId>,
}

impl LinkMatches {
    /// Whether this link matched at least one allow or require-approval grant
    /// (deny is handled separately because it overrides everything).
    fn is_permitted(&self) -> bool {
        !self.allow_grants.is_empty() || !self.approval_grants.is_empty()
    }
}

/// Append `extra` onto `target`, skipping values already present so the merged
/// trace preserves policy order without duplicates.
fn extend_unique<T: PartialEq>(target: &mut Vec<T>, extra: Vec<T>) {
    for value in extra {
        if !target.contains(&value) {
            target.push(value);
        }
    }
}

#[cfg(test)]
mod tests {
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
}
