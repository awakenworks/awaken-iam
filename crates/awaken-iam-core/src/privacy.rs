//! Organization privacy scope closure.
//!
//! IAM stores authorization scopes as contract value objects.  Organization
//! erasure therefore resolves the owned scope graph once here instead of
//! teaching every storage adapter a different ownership rule.

use std::collections::BTreeSet;

use awaken_iam_contract::{OrgId, ScopeRef, WorkspaceOrgEdge};

use crate::ResourceEdge;

/// Exact IAM scopes owned by one organization.
#[derive(Debug, Clone)]
pub struct OrganizationPrivacyScope {
    org_id: OrgId,
    workspace_ids: BTreeSet<String>,
    resource_ids: BTreeSet<(String, String)>,
}

impl OrganizationPrivacyScope {
    /// Resolve the transitive scope closure from the authoritative Workspace →
    /// Org projection and the registered resource-parent graph.
    #[must_use]
    pub fn resolve(
        org_id: &OrgId,
        workspace_edges: &[WorkspaceOrgEdge],
        resource_edges: &[ResourceEdge],
    ) -> Self {
        let workspace_ids = workspace_edges
            .iter()
            .filter(|edge| &edge.org_id == org_id)
            .map(|edge| edge.workspace_id.0.clone())
            .collect();
        let mut scope = Self {
            org_id: org_id.clone(),
            workspace_ids,
            resource_ids: BTreeSet::new(),
        };
        loop {
            let before = scope.resource_ids.len();
            for edge in resource_edges {
                if scope.contains(&edge.parent) {
                    scope
                        .resource_ids
                        .insert((edge.resource_type.0.clone(), edge.resource_id.0.clone()));
                }
            }
            if scope.resource_ids.len() == before {
                break;
            }
        }
        scope
    }

    /// Whether `candidate` belongs to the organization closure.
    #[must_use]
    pub fn contains(&self, candidate: &ScopeRef) -> bool {
        match candidate {
            ScopeRef::Org { org_id } => org_id == &self.org_id,
            ScopeRef::Workspace { workspace_id } => self.workspace_ids.contains(&workspace_id.0),
            ScopeRef::Project { workspace_id, .. } => self.workspace_ids.contains(&workspace_id.0),
            ScopeRef::Resource {
                resource_type,
                resource_id,
            } => self
                .resource_ids
                .contains(&(resource_type.0.clone(), resource_id.0.clone())),
            ScopeRef::Global | ScopeRef::Namespace { .. } => false,
        }
    }

    /// Whether a Workspace is owned by the organization.
    #[must_use]
    pub fn contains_workspace(&self, workspace_id: &str) -> bool {
        self.workspace_ids.contains(workspace_id)
    }
}

#[cfg(test)]
mod tests {
    use awaken_iam_contract::{ProjectId, ResourceId, ResourceType, WorkspaceId};

    use super::*;

    #[test]
    fn resolves_only_the_owned_transitive_scope_graph() {
        // Cause/effect decision table:
        // R1 exact Org -> owned; R2 owned Workspace/Project -> owned;
        // R3 Resource whose parent is owned, including a recursive child ->
        // owned; R4 foreign Workspace/Resource, Global or Namespace -> not
        // owned.  This table is the one ownership rule reused by every store.
        let org = OrgId("org-a".into());
        let workspaces = vec![
            WorkspaceOrgEdge {
                workspace_id: WorkspaceId("ws-a".into()),
                org_id: org.clone(),
            },
            WorkspaceOrgEdge {
                workspace_id: WorkspaceId("ws-b".into()),
                org_id: OrgId("org-b".into()),
            },
        ];
        let resources = vec![
            ResourceEdge {
                resource_type: ResourceType("issue".into()),
                resource_id: ResourceId("one".into()),
                parent: ScopeRef::Workspace {
                    workspace_id: WorkspaceId("ws-a".into()),
                },
            },
            ResourceEdge {
                resource_type: ResourceType("comment".into()),
                resource_id: ResourceId("two".into()),
                parent: ScopeRef::Resource {
                    resource_type: ResourceType("issue".into()),
                    resource_id: ResourceId("one".into()),
                },
            },
            ResourceEdge {
                resource_type: ResourceType("issue".into()),
                resource_id: ResourceId("foreign".into()),
                parent: ScopeRef::Workspace {
                    workspace_id: WorkspaceId("ws-b".into()),
                },
            },
        ];
        let scope = OrganizationPrivacyScope::resolve(&org, &workspaces, &resources);

        assert!(scope.contains(&ScopeRef::Org { org_id: org }));
        assert!(scope.contains(&ScopeRef::Project {
            workspace_id: WorkspaceId("ws-a".into()),
            project_id: ProjectId("project-a".into()),
        }));
        assert!(scope.contains(&ScopeRef::Resource {
            resource_type: ResourceType("comment".into()),
            resource_id: ResourceId("two".into()),
        }));
        assert!(!scope.contains(&ScopeRef::Resource {
            resource_type: ResourceType("issue".into()),
            resource_id: ResourceId("foreign".into()),
        }));
        assert!(!scope.contains(&ScopeRef::Global));
    }
}
