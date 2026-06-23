//! Open resource-model registry — the genericity seam.
//!
//! A product teaches IAM its hierarchy and vocabulary **as data**, never by
//! changing the core. A [`ResourceModel`] holds three open registries:
//!
//! - **resource types** — the kinds of [`ScopeRef::Resource`] a product anchors
//!   grants at, with an optional declared parent type that documents the shape;
//! - **an open action catalog** — [`ActionKey`]s are open strings, so a product
//!   adds an action by registering it, with no schema change;
//! - **scope edges** — per-instance parent links registered into a
//!   [`ScopeGraph`], so the evaluator resolves arbitrarily deep product
//!   hierarchies (leaf resource -> ... -> tenant root) through the same ancestor
//!   walk that handles the well-known scopes.
//!
//! Nothing here is inferred: a resource's place in the hierarchy and the set of
//! known actions are exactly what a product registers, matching the
//! "registered, never inferred" invariant on the resource-model aggregate.

use std::collections::HashMap;
use std::collections::HashSet;

use awaken_iam_contract::{ActionKey, ResourceId, ResourceType, ScopeRef};

use crate::authorization::ScopeGraph;

/// Declared shape of one product resource type.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResourceTypeDef {
    /// The resource type this definition describes.
    pub resource_type: ResourceType,
    /// The resource type this one nests under, if any.
    ///
    /// This documents the intended hierarchy shape; the concrete per-instance
    /// parent scope is still registered as an edge, because a leaf instance may
    /// nest under a well-known scope (e.g. a project) rather than another
    /// resource.
    pub parent_type: Option<ResourceType>,
    /// Actions defined on this resource type. Folded into the open action
    /// catalog when the type is registered.
    pub actions: Vec<ActionKey>,
}

/// A single registered per-instance parent edge.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResourceEdge {
    /// Type of the child resource.
    pub resource_type: ResourceType,
    /// Id of the child resource instance.
    pub resource_id: ResourceId,
    /// Scope the child nests directly under.
    pub parent: ScopeRef,
}

/// A product's registered resource types, action catalog, and scope edges.
///
/// Apply it to a [`ScopeGraph`] (or a [`PolicySet`](crate::PolicySet) via
/// `register_resource_model`) to make the evaluator resolve the product's
/// hierarchy.
#[derive(Debug, Default, Clone)]
pub struct ResourceModel {
    types: HashMap<ResourceType, ResourceTypeDef>,
    actions: HashSet<ActionKey>,
    edges: Vec<ResourceEdge>,
}

impl ResourceModel {
    /// Create an empty resource model.
    pub fn new() -> Self {
        Self::default()
    }

    /// Register a resource type, folding its actions into the catalog.
    ///
    /// Re-registering a type replaces its definition; its actions remain in the
    /// catalog.
    pub fn register_resource_type(&mut self, def: ResourceTypeDef) -> &mut Self {
        for action in &def.actions {
            self.actions.insert(action.clone());
        }
        self.types.insert(def.resource_type.clone(), def);
        self
    }

    /// Register a standalone action in the open catalog.
    pub fn register_action(&mut self, action: ActionKey) -> &mut Self {
        self.actions.insert(action);
        self
    }

    /// Register the parent scope of a single resource instance.
    ///
    /// `parent` may be any [`ScopeRef`], including another
    /// [`ScopeRef::Resource`]; chained edges are what let the ancestor walk span
    /// an arbitrarily deep product hierarchy.
    pub fn register_parent(
        &mut self,
        resource_type: ResourceType,
        resource_id: ResourceId,
        parent: ScopeRef,
    ) -> &mut Self {
        self.edges.push(ResourceEdge {
            resource_type,
            resource_id,
            parent,
        });
        self
    }

    /// Look up a registered resource type definition.
    pub fn resource_type(&self, resource_type: &ResourceType) -> Option<&ResourceTypeDef> {
        self.types.get(resource_type)
    }

    /// Returns whether `action` is registered in the open catalog.
    pub fn knows_action(&self, action: &ActionKey) -> bool {
        self.actions.contains(action)
    }

    /// The open action catalog, sorted for a stable iteration order.
    pub fn actions(&self) -> Vec<ActionKey> {
        let mut actions: Vec<ActionKey> = self.actions.iter().cloned().collect();
        actions.sort_by(|left, right| left.0.cmp(&right.0));
        actions
    }

    /// The registered per-instance parent edges, in registration order.
    pub fn edges(&self) -> &[ResourceEdge] {
        &self.edges
    }

    /// Register every parent edge held by this model into `graph`.
    ///
    /// After applying, the evaluator resolves the product's resources through
    /// the same scope-graph walk it uses for the well-known scopes.
    pub fn apply_to(&self, graph: &mut ScopeGraph) {
        for edge in &self.edges {
            graph.assign_resource_parent(
                edge.resource_type.clone(),
                edge.resource_id.clone(),
                edge.parent.clone(),
            );
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        ActionPattern, AuthorizationDecision, Effect, Grant, GrantId, GrantSubject, PolicySet,
    };
    use awaken_iam_contract::{
        AccountId, AuthorizationRequest, PrincipalRef, ProjectId, WorkspaceId,
    };

    fn issue_type() -> ResourceTypeDef {
        ResourceTypeDef {
            resource_type: ResourceType("issue".into()),
            parent_type: None,
            actions: vec![
                ActionKey("issue.read".into()),
                ActionKey("issue.close".into()),
            ],
        }
    }

    #[test]
    fn registering_a_type_folds_its_actions_into_the_catalog() {
        let mut model = ResourceModel::new();
        model.register_resource_type(issue_type());
        model.register_action(ActionKey("issue.assign".into()));

        assert!(model.knows_action(&ActionKey("issue.read".into())));
        assert!(model.knows_action(&ActionKey("issue.close".into())));
        assert!(model.knows_action(&ActionKey("issue.assign".into())));
        assert!(!model.knows_action(&ActionKey("issue.delete".into())));

        assert_eq!(
            model.actions(),
            vec![
                ActionKey("issue.assign".into()),
                ActionKey("issue.close".into()),
                ActionKey("issue.read".into()),
            ]
        );
        assert_eq!(
            model.resource_type(&ResourceType("issue".into())),
            Some(&issue_type())
        );
    }

    #[test]
    fn applying_a_model_lets_the_engine_resolve_product_resources() {
        let mut model = ResourceModel::new();
        model.register_resource_type(issue_type()).register_parent(
            ResourceType("issue".into()),
            ResourceId("42".into()),
            ScopeRef::Project {
                workspace_id: WorkspaceId("ws_main".into()),
                project_id: ProjectId("proj_web".into()),
            },
        );

        let mut policy = PolicySet::new();
        policy.register_resource_model(&model);
        policy.add_grant(Grant {
            id: GrantId("g_proj".into()),
            subject: GrantSubject::Principal(PrincipalRef::Account {
                account_id: AccountId("ada".into()),
            }),
            action_pattern: ActionPattern("issue.*".into()),
            scope: ScopeRef::Project {
                workspace_id: WorkspaceId("ws_main".into()),
                project_id: ProjectId("proj_web".into()),
            },
            effect: Effect::Allow,
        });

        let trace = policy.evaluate(&AuthorizationRequest {
            principal: PrincipalRef::Account {
                account_id: AccountId("ada".into()),
            },
            on_behalf_of: Vec::new(),
            action: ActionKey("issue.close".into()),
            scope: ScopeRef::Resource {
                resource_type: ResourceType("issue".into()),
                resource_id: ResourceId("42".into()),
            },
        });
        assert_eq!(trace.decision, AuthorizationDecision::Allow);
        assert_eq!(trace.matched_grants, vec![GrantId("g_proj".into())]);
    }

    #[test]
    fn a_registered_model_resolves_a_chained_resource_hierarchy() {
        // A product teaches IAM a two-hop hierarchy entirely as data:
        // comment:7 -> issue:42 -> project:web. A grant anchored at the project
        // must cover the comment through both registered resource edges, proving
        // the registry's `apply_to` feeds the same arbitrary-depth ancestor walk
        // the well-known scopes use — not just a single resource->scope hop.
        let mut model = ResourceModel::new();
        model
            .register_resource_type(issue_type())
            .register_resource_type(ResourceTypeDef {
                resource_type: ResourceType("comment".into()),
                parent_type: Some(ResourceType("issue".into())),
                actions: vec![ActionKey("comment.delete".into())],
            })
            .register_parent(
                ResourceType("issue".into()),
                ResourceId("42".into()),
                ScopeRef::Project {
                    workspace_id: WorkspaceId("ws_main".into()),
                    project_id: ProjectId("proj_web".into()),
                },
            )
            .register_parent(
                ResourceType("comment".into()),
                ResourceId("7".into()),
                ScopeRef::Resource {
                    resource_type: ResourceType("issue".into()),
                    resource_id: ResourceId("42".into()),
                },
            );

        let mut policy = PolicySet::new();
        policy.register_resource_model(&model);
        policy.add_grant(Grant {
            id: GrantId("g_proj".into()),
            subject: GrantSubject::Principal(PrincipalRef::Account {
                account_id: AccountId("ada".into()),
            }),
            action_pattern: ActionPattern("comment.*".into()),
            scope: ScopeRef::Project {
                workspace_id: WorkspaceId("ws_main".into()),
                project_id: ProjectId("proj_web".into()),
            },
            effect: Effect::Allow,
        });

        let trace = policy.evaluate(&AuthorizationRequest {
            principal: PrincipalRef::Account {
                account_id: AccountId("ada".into()),
            },
            on_behalf_of: Vec::new(),
            action: ActionKey("comment.delete".into()),
            scope: ScopeRef::Resource {
                resource_type: ResourceType("comment".into()),
                resource_id: ResourceId("7".into()),
            },
        });
        assert_eq!(trace.decision, AuthorizationDecision::Allow);
        assert_eq!(trace.matched_grants, vec![GrantId("g_proj".into())]);
    }

    #[test]
    fn edges_are_recorded_in_registration_order() {
        let mut model = ResourceModel::new();
        model
            .register_parent(
                ResourceType("comment".into()),
                ResourceId("7".into()),
                ScopeRef::Resource {
                    resource_type: ResourceType("issue".into()),
                    resource_id: ResourceId("42".into()),
                },
            )
            .register_parent(
                ResourceType("issue".into()),
                ResourceId("42".into()),
                ScopeRef::Global,
            );

        let edges = model.edges();
        assert_eq!(edges.len(), 2);
        assert_eq!(edges[0].resource_type, ResourceType("comment".into()));
        assert_eq!(edges[1].resource_type, ResourceType("issue".into()));
    }
}
