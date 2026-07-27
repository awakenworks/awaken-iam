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
    ActionKey, ApprovalAuthority, ApprovalObligation, AuthorizationDecision, AuthorizationOutcome,
    AuthorizationProfile, AuthorizationRequest, GrantEffect, GrantSnapshot, GrantSubjectRef,
    GroupRoleBindingSnapshot, GroupRosterSnapshot, NamespaceId, NamespaceOrgEdge, OrgId,
    PolicySnapshot, PrincipalRef, ResourceId, ResourceParentEdge, ResourceType,
    RoleBindingSnapshot, ScopeGraphSnapshot, ScopeKind, ScopeRef, WorkspaceId, WorkspaceOrgEdge,
};

use crate::GroupId;

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

/// Subject a grant applies to: a concrete principal, a role, or a group.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum GrantSubject {
    /// A grant attached directly to a principal.
    Principal(PrincipalRef),
    /// A grant carried by a role; it applies to any principal bound to the role
    /// at a covering scope.
    Role(RoleId),
    /// A grant carried by a group; it applies to any principal in the group's
    /// **live roster** at evaluation. Membership is the single source of truth,
    /// so a principal joining or leaving the group gains or loses the grant
    /// immediately, with no re-expansion. A group is never a principal — the
    /// grant reaches the group's members, never "the group" itself.
    Group(GroupId),
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

/// Binds a group's live roster to a role at a scope.
///
/// Every principal in the group's roster holds the role for requests at the
/// binding scope and anything beneath it, resolved dynamically at evaluation — a
/// roster change takes effect immediately. This binding is the kernel of a
/// product **Team**: a [`Group`](crate::Group) roster plus a container scope plus
/// this binding.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GroupRoleBinding {
    /// Group whose roster holds the role.
    pub group: GroupId,
    /// Role being granted to the group's members.
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
    /// The active authorization profile does not permit this action on the
    /// submitted structural scope kind.
    ScopeKindNotAllowed,
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
            DecisionReason::ScopeKindNotAllowed => "scope_kind_not_allowed",
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
    /// Approval obligation the caller must discharge, present iff `decision` is
    /// [`AuthorizationDecision::RequireApproval`]. It is the engine's hand-off
    /// seam: the approval is discharged against its `obligation_id` product-side
    /// or as a capability token, never by re-querying authorize.
    pub obligation: Option<ApprovalObligation>,
}

impl AuthorizationTrace {
    /// Project the trace onto the [`AuthorizationOutcome`] wire DTO, flattening
    /// the reason to its stable code and the matched ids to plain strings. The
    /// approval obligation, when present, is carried through unchanged.
    pub fn to_outcome(&self) -> AuthorizationOutcome {
        AuthorizationOutcome {
            decision: self.decision,
            reason: self.reason.code().to_owned(),
            matched_grants: self.matched_grants.iter().map(|id| id.0.clone()).collect(),
            matched_roles: self.matched_roles.iter().map(|id| id.0.clone()).collect(),
            obligation: self.obligation.clone(),
        }
    }
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

    /// Capture the scope graph's parent edges as a [`ScopeGraphSnapshot`].
    ///
    /// Edges are sorted by their keys so the snapshot is deterministic
    /// regardless of map iteration order.
    fn to_snapshot(&self) -> ScopeGraphSnapshot {
        let mut namespace_orgs: Vec<NamespaceOrgEdge> = self
            .namespace_org
            .iter()
            .map(|(namespace_id, org_id)| NamespaceOrgEdge {
                namespace_id: namespace_id.clone(),
                org_id: org_id.clone(),
            })
            .collect();
        namespace_orgs.sort_by(|left, right| left.namespace_id.0.cmp(&right.namespace_id.0));

        let mut workspace_orgs: Vec<WorkspaceOrgEdge> = self
            .workspace_org
            .iter()
            .map(|(workspace_id, org_id)| WorkspaceOrgEdge {
                workspace_id: workspace_id.clone(),
                org_id: org_id.clone(),
            })
            .collect();
        workspace_orgs.sort_by(|left, right| left.workspace_id.0.cmp(&right.workspace_id.0));

        let mut resource_parents: Vec<ResourceParentEdge> = self
            .resource_parent
            .iter()
            .map(
                |((resource_type, resource_id), parent)| ResourceParentEdge {
                    resource_type: resource_type.clone(),
                    resource_id: resource_id.clone(),
                    parent: parent.clone(),
                },
            )
            .collect();
        resource_parents.sort_by(|left, right| {
            (left.resource_type.0.as_str(), left.resource_id.0.as_str())
                .cmp(&(right.resource_type.0.as_str(), right.resource_id.0.as_str()))
        });

        ScopeGraphSnapshot {
            namespace_orgs,
            workspace_orgs,
            resource_parents,
        }
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

/// The grants, role bindings, group rosters, and scope graph evaluated against a
/// request.
#[derive(Debug, Default)]
pub struct PolicySet {
    grants: Vec<Grant>,
    role_bindings: Vec<RoleBinding>,
    group_rosters: HashMap<GroupId, Vec<PrincipalRef>>,
    group_role_bindings: Vec<GroupRoleBinding>,
    scope_graph: ScopeGraph,
    active_profiles: Vec<AuthorizationProfile>,
    action_scope_rules: Vec<(ActionPattern, HashSet<ScopeKind>)>,
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

    /// Replace a group's live roster with `members`, deduplicated in insertion
    /// order. This is the single source of truth a [`GrantSubject::Group`] grant
    /// and a [`GroupRoleBinding`] resolve against at evaluation.
    pub fn set_group_roster(
        &mut self,
        group: GroupId,
        members: impl IntoIterator<Item = PrincipalRef>,
    ) -> &mut Self {
        let mut roster: Vec<PrincipalRef> = Vec::new();
        for member in members {
            if !roster.contains(&member) {
                roster.push(member);
            }
        }
        self.group_rosters.insert(group, roster);
        self
    }

    /// Add `principal` to a group's roster, returning whether it was newly added.
    ///
    /// The principal gains every grant and group role binding the group holds
    /// immediately — membership is resolved live, never expanded into per-member
    /// grants.
    pub fn add_group_member(&mut self, group: GroupId, principal: PrincipalRef) -> bool {
        let roster = self.group_rosters.entry(group).or_default();
        if roster.contains(&principal) {
            return false;
        }
        roster.push(principal);
        true
    }

    /// Remove `principal` from a group's roster, returning whether it was present.
    ///
    /// The principal loses every grant and group role binding the group holds
    /// immediately on the next evaluation.
    pub fn remove_group_member(&mut self, group: &GroupId, principal: &PrincipalRef) -> bool {
        let Some(roster) = self.group_rosters.get_mut(group) else {
            return false;
        };
        let before = roster.len();
        roster.retain(|member| member != principal);
        roster.len() != before
    }

    /// Bind a group's roster to a role at a scope.
    pub fn bind_group_role(&mut self, binding: GroupRoleBinding) -> &mut Self {
        self.group_role_bindings.push(binding);
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

    /// Whether `principal` is in `group`'s live roster.
    fn group_contains(&self, group: &GroupId, principal: &PrincipalRef) -> bool {
        self.group_rosters
            .get(group)
            .is_some_and(|roster| roster.contains(principal))
    }

    /// Roles held by `principal` for a request at `scope`, in policy order with
    /// duplicates removed.
    ///
    /// A principal holds a role both through a direct [`RoleBinding`] and through
    /// any [`GroupRoleBinding`] whose group lists the principal in its live
    /// roster, so a group membership change is reflected on the next evaluation.
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
        for binding in &self.group_role_bindings {
            if !self.group_contains(&binding.group, principal) {
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
                GrantSubject::Group(group) => {
                    // The grant reaches every principal in the group's live
                    // roster; it carries no role, so it contributes only its
                    // grant id to the trace.
                    if !self.group_contains(group, principal) {
                        continue;
                    }
                    None
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
                    // Anchor the obligation at the first approval grant's scope,
                    // matching `approval_grants[0]` so authority and policy id
                    // describe the same deciding grant.
                    if matches.approval_anchor.is_none() {
                        matches.approval_anchor = Some(grant.scope.clone());
                    }
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
        if self.profile_governs(action) && !self.scope_kind_allowed(action, scope) {
            return AuthorizationTrace {
                decision: AuthorizationDecision::Deny,
                reason: DecisionReason::ScopeKindNotAllowed,
                matched_grants: Vec::new(),
                matched_roles: Vec::new(),
                obligation: None,
            };
        }
        if chain.is_empty() {
            return AuthorizationTrace {
                decision: AuthorizationDecision::Deny,
                reason: DecisionReason::PrincipalUnresolved,
                matched_grants: Vec::new(),
                matched_roles: Vec::new(),
                obligation: None,
            };
        }

        let mut deny_grants: Vec<GrantId> = Vec::new();
        let mut deny_roles: Vec<RoleId> = Vec::new();
        let mut approval_grants: Vec<GrantId> = Vec::new();
        let mut approval_roles: Vec<RoleId> = Vec::new();
        let mut approval_anchor: Option<ScopeRef> = None;
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
            if approval_grants.is_empty() {
                // First link contributing an approval grant fixes the anchor,
                // keeping it aligned with the eventual `approval_grants[0]`.
                approval_anchor = approval_anchor.or(link.approval_anchor);
            }
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
                obligation: None,
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
                obligation: None,
            };
        }
        if !approval_grants.is_empty() {
            // The deciding grant (first in policy order) names the policy and its
            // anchor scope; the obligation id is content-addressed so re-querying
            // authorize is idempotent against the recorded/token-bound approval.
            let policy_id = approval_grants[0].0.clone();
            let authority = ApprovalAuthority {
                scope: approval_anchor.unwrap_or_else(|| scope.clone()),
            };
            let obligation = ApprovalObligation {
                obligation_id: obligation_id(chain, action, scope, &policy_id),
                policy_id,
                authority,
            };
            return AuthorizationTrace {
                decision: AuthorizationDecision::RequireApproval,
                reason: DecisionReason::NeedsApproval,
                matched_grants: approval_grants,
                matched_roles: approval_roles,
                obligation: Some(obligation),
            };
        }
        AuthorizationTrace {
            decision: AuthorizationDecision::Allow,
            reason: DecisionReason::AllowedByGrant,
            matched_grants: allow_grants,
            matched_roles: allow_roles,
            obligation: None,
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

    /// Capture this policy as a versioned [`PolicySnapshot`] for local-mode sync.
    ///
    /// Grants and role bindings keep policy order; scope-graph edges are sorted
    /// by their keys so the snapshot is deterministic regardless of map
    /// iteration order. The result is authorization-only — entitlement is a
    /// separate plane and is never bundled here.
    pub fn snapshot(&self, version: u64) -> PolicySnapshot {
        let grants = self
            .grants
            .iter()
            .map(|grant| GrantSnapshot {
                id: grant.id.0.clone(),
                subject: match &grant.subject {
                    GrantSubject::Principal(principal) => GrantSubjectRef::Principal {
                        principal: principal.clone(),
                    },
                    GrantSubject::Role(role) => GrantSubjectRef::Role {
                        role_id: role.0.clone(),
                    },
                    GrantSubject::Group(group) => GrantSubjectRef::Group {
                        group_id: group.0.clone(),
                    },
                },
                action_pattern: grant.action_pattern.0.clone(),
                scope: grant.scope.clone(),
                effect: effect_to_wire(grant.effect),
            })
            .collect();
        let role_bindings = self
            .role_bindings
            .iter()
            .map(|binding| RoleBindingSnapshot {
                principal: binding.principal.clone(),
                role_id: binding.role.0.clone(),
                scope: binding.scope.clone(),
            })
            .collect();
        // Group rosters are sorted by id so the snapshot is deterministic
        // regardless of map iteration order; member order within a roster is
        // preserved.
        let mut group_rosters: Vec<GroupRosterSnapshot> = self
            .group_rosters
            .iter()
            .map(|(group, members)| GroupRosterSnapshot {
                group_id: group.0.clone(),
                members: members.clone(),
            })
            .collect();
        group_rosters.sort_by(|left, right| left.group_id.cmp(&right.group_id));
        let group_role_bindings = self
            .group_role_bindings
            .iter()
            .map(|binding| GroupRoleBindingSnapshot {
                group_id: binding.group.0.clone(),
                role_id: binding.role.0.clone(),
                scope: binding.scope.clone(),
            })
            .collect();
        PolicySnapshot {
            version,
            grants,
            role_bindings,
            group_rosters,
            group_role_bindings,
            scope_graph: self.scope_graph.to_snapshot(),
            active_profiles: self.active_profiles.clone(),
        }
    }

    /// Rebuild a policy set from a [`PolicySnapshot`].
    ///
    /// This is the local-mode counterpart to [`PolicySet::snapshot`]: a consumer
    /// that syncs the snapshot rebuilds the policy and evaluates in-process, so
    /// its decisions are byte-identical to the server's remote `authorize`
    /// answers. The snapshot `version` is metadata for the caller's freshness
    /// fence and is not retained in the rebuilt policy.
    pub fn from_snapshot(snapshot: &PolicySnapshot) -> Self {
        let mut policy = Self::new();
        for grant in &snapshot.grants {
            policy.add_grant(Grant {
                id: GrantId(grant.id.clone()),
                subject: match &grant.subject {
                    GrantSubjectRef::Principal { principal } => {
                        GrantSubject::Principal(principal.clone())
                    }
                    GrantSubjectRef::Role { role_id } => {
                        GrantSubject::Role(RoleId(role_id.clone()))
                    }
                    GrantSubjectRef::Group { group_id } => {
                        GrantSubject::Group(GroupId(group_id.clone()))
                    }
                },
                action_pattern: ActionPattern(grant.action_pattern.clone()),
                scope: grant.scope.clone(),
                effect: effect_from_wire(grant.effect),
            });
        }
        for binding in &snapshot.role_bindings {
            policy.bind_role(RoleBinding {
                principal: binding.principal.clone(),
                role: RoleId(binding.role_id.clone()),
                scope: binding.scope.clone(),
            });
        }
        for roster in &snapshot.group_rosters {
            policy.set_group_roster(
                GroupId(roster.group_id.clone()),
                roster.members.iter().cloned(),
            );
        }
        for binding in &snapshot.group_role_bindings {
            policy.bind_group_role(GroupRoleBinding {
                group: GroupId(binding.group_id.clone()),
                role: RoleId(binding.role_id.clone()),
                scope: binding.scope.clone(),
            });
        }
        let graph = policy.scope_graph_mut();
        for edge in &snapshot.scope_graph.namespace_orgs {
            graph.assign_namespace(edge.namespace_id.clone(), edge.org_id.clone());
        }
        for edge in &snapshot.scope_graph.workspace_orgs {
            graph.assign_workspace(edge.workspace_id.clone(), edge.org_id.clone());
        }
        for edge in &snapshot.scope_graph.resource_parents {
            graph.assign_resource_parent(
                edge.resource_type.clone(),
                edge.resource_id.clone(),
                edge.parent.clone(),
            );
        }
        for profile in &snapshot.active_profiles {
            policy.install_profile_rules(profile);
        }
        policy
    }

    fn install_profile_rules(&mut self, profile: &AuthorizationProfile) {
        self.active_profiles
            .retain(|active| active.namespace != profile.namespace);
        self.active_profiles.push(profile.clone());
        self.action_scope_rules.clear();
        for active in &self.active_profiles {
            for rule in &active.document.action_scope_rules {
                if let Some((_, allowed)) = self
                    .action_scope_rules
                    .iter_mut()
                    .find(|(pattern, _)| pattern.0 == rule.action_pattern)
                {
                    allowed.extend(rule.allowed_scope_kinds.iter().cloned());
                } else {
                    self.action_scope_rules.push((
                        ActionPattern(rule.action_pattern.clone()),
                        rule.allowed_scope_kinds.iter().cloned().collect(),
                    ));
                }
            }
        }
    }

    fn scope_kind_allowed(&self, action: &ActionKey, scope: &ScopeRef) -> bool {
        self.action_scope_rules.iter().any(|(pattern, allowed)| {
            pattern.matches(action) && allowed.iter().any(|kind| scope_matches_kind(scope, kind))
        })
    }

    fn profile_governs(&self, action: &ActionKey) -> bool {
        self.active_profiles.iter().any(|profile| {
            action
                .0
                .strip_prefix(&profile.namespace.0)
                .is_some_and(|suffix| suffix.starts_with("::"))
        })
    }
}

fn scope_matches_kind(scope: &ScopeRef, kind: &ScopeKind) -> bool {
    match (scope, kind) {
        (ScopeRef::Global, ScopeKind::Global)
        | (ScopeRef::Org { .. }, ScopeKind::Org)
        | (ScopeRef::Namespace { .. }, ScopeKind::Namespace)
        | (ScopeRef::Workspace { .. }, ScopeKind::Workspace)
        | (ScopeRef::Project { .. }, ScopeKind::Project) => true,
        (
            ScopeRef::Resource { resource_type, .. },
            ScopeKind::Resource {
                resource_type: allowed,
            },
        ) => resource_type == allowed,
        _ => false,
    }
}

/// Map a core [`Effect`] onto its wire [`GrantEffect`].
fn effect_to_wire(effect: Effect) -> GrantEffect {
    match effect {
        Effect::Allow => GrantEffect::Allow,
        Effect::RequireApproval => GrantEffect::RequireApproval,
        Effect::Deny => GrantEffect::Deny,
    }
}

/// Map a wire [`GrantEffect`] back onto its core [`Effect`].
fn effect_from_wire(effect: GrantEffect) -> Effect {
    match effect {
        GrantEffect::Allow => Effect::Allow,
        GrantEffect::RequireApproval => Effect::RequireApproval,
        GrantEffect::Deny => Effect::Deny,
    }
}

/// Grants matching a single principal link, partitioned by effect.
#[derive(Debug, Default)]
struct LinkMatches {
    allow_grants: Vec<GrantId>,
    allow_roles: Vec<RoleId>,
    approval_grants: Vec<GrantId>,
    approval_roles: Vec<RoleId>,
    /// Scope of the first require-approval grant matched on this link, in policy
    /// order. It is the scope the obligation's approval authority is anchored at.
    approval_anchor: Option<ScopeRef>,
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

/// Derive the content-addressed id of a require-approval obligation.
///
/// The id is a SHA-256 digest over the canonical principal chain, action, scope,
/// and deciding `policy_id`. It is therefore deterministic and identical whether
/// computed by the server or by a consumer evaluating a synced snapshot, so an
/// approval recorded (or a capability token minted) against it is idempotent and
/// re-querying authorize for the same question never invents a new obligation.
fn obligation_id(
    chain: &[&PrincipalRef],
    action: &ActionKey,
    scope: &ScopeRef,
    policy_id: &str,
) -> String {
    use sha2::{Digest, Sha256};

    let mut hasher = Sha256::new();
    hasher.update(b"awaken-iam.obligation.v1");
    hasher.update(b"\x00policy\x00");
    hasher.update(policy_id.as_bytes());
    hasher.update(b"\x00action\x00");
    hasher.update(action.0.as_bytes());
    hasher.update(b"\x00scope\x00");
    hasher.update(canonical_json(scope).as_bytes());
    hasher.update(b"\x00chain\x00");
    for principal in chain {
        hasher.update(canonical_json(principal).as_bytes());
        hasher.update(b"\x1e");
    }
    let digest = hasher.finalize();

    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut id = String::with_capacity(4 + 32);
    id.push_str("obl_");
    for byte in &digest[..16] {
        id.push(HEX[(byte >> 4) as usize] as char);
        id.push(HEX[(byte & 0x0f) as usize] as char);
    }
    id
}

/// Serialize a contract DTO to its canonical JSON string for hashing.
///
/// Serde emits struct and enum fields in declaration order, so this is stable
/// across processes; the rare serialization failure degrades to an empty string
/// rather than panicking in the evaluation hot path.
fn canonical_json<T: serde::Serialize>(value: &T) -> String {
    serde_json::to_string(value).unwrap_or_default()
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
        let other_action =
            policy.evaluate(&request(account("ada"), "issue.archive", ScopeRef::Global));
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
}
