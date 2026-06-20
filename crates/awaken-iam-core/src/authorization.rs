//! Authorization evaluation engine.
//!
//! Implements the `Principal + Action + Scope -> Decision` shape described in
//! the IAM model and the authorization-engine design. Evaluation is
//! default-deny: a request is allowed only when at least one matching grant
//! (held directly by the principal or through a role binding) permits it, and
//! deny effects take precedence over allow.
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
/// v1 policy is expected to issue only [`Effect::Allow`]; introducing deny
/// grants in stored policy requires a future ADR. The evaluator still models
/// [`Effect::Deny`] so the precedence seam (deny overrides allow) exists from
/// the start and does not need to be retrofitted.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Effect {
    /// Permit the action.
    Allow,
    /// Forbid the action, overriding any matching allow.
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
    /// Whether the grant allows or denies.
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
    /// At least one allow grant matched and no deny grant overrode it.
    AllowedByGrant,
    /// A deny grant matched and took precedence over any allow.
    DeniedByGrant,
    /// No grant matched the request; the default-deny rule applied.
    DefaultDeny,
}

impl DecisionReason {
    /// Returns a stable snake_case code suitable for audit logs and UIs.
    pub fn code(&self) -> &'static str {
        match self {
            DecisionReason::AllowedByGrant => "allowed_by_grant",
            DecisionReason::DeniedByGrant => "denied_by_grant",
            DecisionReason::DefaultDeny => "default_deny",
        }
    }
}

/// Decision plus the trace explaining how it was reached.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuthorizationTrace {
    /// The allow/deny outcome.
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

    /// Evaluate `request` against the policy and return the decision trace.
    pub fn evaluate(&self, request: &AuthorizationRequest) -> AuthorizationTrace {
        let held_roles = self.held_roles(&request.principal, &request.scope);

        let mut allow_grants: Vec<GrantId> = Vec::new();
        let mut allow_roles: Vec<RoleId> = Vec::new();
        let mut deny_grants: Vec<GrantId> = Vec::new();
        let mut deny_roles: Vec<RoleId> = Vec::new();

        for grant in &self.grants {
            let via_role = match &grant.subject {
                GrantSubject::Principal(principal) => {
                    if principal != &request.principal {
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
            if !grant.action_pattern.matches(&request.action) {
                continue;
            }
            if !self.scope_graph.covers(&grant.scope, &request.scope) {
                continue;
            }

            match grant.effect {
                Effect::Allow => {
                    allow_grants.push(grant.id.clone());
                    if let Some(role) = via_role
                        && !allow_roles.contains(role)
                    {
                        allow_roles.push(role.clone());
                    }
                }
                Effect::Deny => {
                    deny_grants.push(grant.id.clone());
                    if let Some(role) = via_role
                        && !deny_roles.contains(role)
                    {
                        deny_roles.push(role.clone());
                    }
                }
            }
        }

        if !deny_grants.is_empty() {
            return AuthorizationTrace {
                decision: AuthorizationDecision::Deny,
                reason: DecisionReason::DeniedByGrant,
                matched_grants: deny_grants,
                matched_roles: deny_roles,
            };
        }
        if !allow_grants.is_empty() {
            return AuthorizationTrace {
                decision: AuthorizationDecision::Allow,
                reason: DecisionReason::AllowedByGrant,
                matched_grants: allow_grants,
                matched_roles: allow_roles,
            };
        }
        AuthorizationTrace {
            decision: AuthorizationDecision::Deny,
            reason: DecisionReason::DefaultDeny,
            matched_grants: Vec::new(),
            matched_roles: Vec::new(),
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
        AuthorizationRequest {
            principal,
            action: ActionKey(action.into()),
            scope,
        }
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
        assert_eq!(DecisionReason::DeniedByGrant.code(), "denied_by_grant");
        assert_eq!(DecisionReason::DefaultDeny.code(), "default_deny");
    }
}
