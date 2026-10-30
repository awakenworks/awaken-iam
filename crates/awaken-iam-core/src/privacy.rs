//! Organization privacy scope closure.
//!
//! IAM stores authorization scopes as contract value objects.  Organization
//! erasure therefore resolves the owned scope graph once here instead of
//! teaching every storage adapter a different ownership rule.

use std::collections::BTreeSet;

use awaken_iam_contract::{OrgId, ScopeRef, WorkspaceOrgEdge};

use crate::ResourceEdge;

/// Exact IAM scopes owned by one organization.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
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
        Self::resolve_with_owned_resources(
            org_id,
            workspace_edges,
            resource_edges,
            &BTreeSet::new(),
        )
    }

    /// Include resource identities whose ORIGINAL projection owner or retirement
    /// fact proves this Org even after its active parent edge was removed. The
    /// adapter supplies those positive facts under the same mutation lock.
    #[must_use]
    pub fn resolve_with_owned_resources(
        org_id: &OrgId,
        workspace_edges: &[WorkspaceOrgEdge],
        resource_edges: &[ResourceEdge],
        owned_resources: &BTreeSet<(String, String)>,
    ) -> Self {
        let workspace_ids = workspace_edges
            .iter()
            .filter(|edge| &edge.org_id == org_id)
            .map(|edge| edge.workspace_id.0.clone())
            .collect();
        let mut scope = Self {
            org_id: org_id.clone(),
            workspace_ids,
            resource_ids: owned_resources.clone(),
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

    /// Keep only legacy negative resource keys which have no existing product
    /// projection owner. The projection ownership/tombstone tables remain the
    /// canonical authority for their keys, rather than duplicating them here.
    pub fn without_projected_resources(mut self, projected: &BTreeSet<(String, String)>) -> Self {
        self.resource_ids.retain(|key| !projected.contains(key));
        self
    }

    /// Whether a Workspace is owned by the organization.
    #[must_use]
    pub fn contains_workspace(&self, workspace_id: &str) -> bool {
        self.workspace_ids.contains(workspace_id)
    }
}

/// Material-free terminal facts retained in the ORIGINAL organization row.
/// This is not another organization directory or a projection epoch authority.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct OrgPrivacyTerminal {
    pub scope: OrganizationPrivacyScope,
    pub group_ids: BTreeSet<String>,
    pub erasure_version: u64,
    /// False for a never-known or historically removed identity: negative
    /// admission is still published, but cannot certify historical erasure.
    pub confirmed_organization: bool,
}

/// One publication decision shared by SQL and memory; adapters own their
/// atomic persistence boundary, never an independent replay/version policy.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum OrgPrivacyCommitPlan {
    Replay(awaken_iam_contract::OrgPrivacyCommitReceipt),
    Publish {
        erasure_version: u64,
        confirmed_organization: bool,
    },
}

pub fn plan_org_privacy_commit(
    org: &OrgId,
    terminal: Option<&OrgPrivacyTerminal>,
    known_organization: bool,
    observed_policy_version: u64,
) -> crate::RepositoryResult<OrgPrivacyCommitPlan> {
    if org.0.trim().is_empty() || observed_policy_version == 0 {
        return Err(crate::RepositoryError::Conflict(
            "invalid organization privacy admission coordinate".into(),
        ));
    }
    if let Some(terminal) = terminal {
        if !terminal.scope.contains(&ScopeRef::Org {
            org_id: org.clone(),
        }) {
            return Err(crate::RepositoryError::Conflict(
                "terminal organization identity differs".into(),
            ));
        }
        return Ok(OrgPrivacyCommitPlan::Replay(terminal.receipt(
            observed_policy_version,
            false,
            false,
        )?));
    }
    let next = observed_policy_version
        .checked_add(1)
        .filter(|value| *value <= i64::MAX as u64)
        .ok_or_else(|| crate::RepositoryError::Backend("IAM policy version exhausted".into()))?;
    Ok(OrgPrivacyCommitPlan::Publish {
        erasure_version: next,
        confirmed_organization: known_organization,
    })
}

impl OrgPrivacyTerminal {
    pub fn receipt(
        &self,
        observed_policy_version: u64,
        changed: bool,
        admission_changed: bool,
    ) -> crate::RepositoryResult<awaken_iam_contract::OrgPrivacyCommitReceipt> {
        let receipt = awaken_iam_contract::OrgPrivacyCommitReceipt {
            receipt_version: awaken_iam_contract::ORG_PRIVACY_RECEIPT_VERSION,
            org_id: self.scope.org_id.clone(),
            changed,
            admission_changed,
            confirmed_organization: self.confirmed_organization,
            erasure_version: self.erasure_version,
            observed_policy_version,
        };
        receipt
            .validate_for(&self.scope.org_id)
            .map_err(|error| crate::RepositoryError::Backend(error.to_string()))?;
        Ok(receipt)
    }

    /// One source of truth for negative legacy scopes and removed Group ids.
    /// Adapters derive prior+proposed subjects under their SAME mutation lock.
    pub fn ensure_admitted(
        &self,
        scopes: &[ScopeRef],
        groups: &[String],
    ) -> crate::RepositoryResult<()> {
        if scopes.iter().any(|scope| self.scope.contains(scope))
            || groups.iter().any(|group| self.group_ids.contains(group))
        {
            return Err(crate::RepositoryError::Conflict(
                "organization admission is terminal".into(),
            ));
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use awaken_iam_contract::{ProjectId, ResourceId, ResourceType, WorkspaceId};

    use super::*;

    #[test]
    fn one_publication_plan_distinguishes_new_negative_admission_from_exact_replay() {
        // CF2 rows K1 absent/new negative -> one publication, unconfirmed;
        // K2 known/new -> one publication, confirmed; K3 old receipt/current
        // newer global policy -> replay stores old erasure but returns CURRENT;
        // K4 foreign subject/overflow -> refuse before any persistence effects.
        let org = OrgId("org".into());
        assert_eq!(
            plan_org_privacy_commit(&org, None, false, 1).unwrap(),
            OrgPrivacyCommitPlan::Publish {
                erasure_version: 2,
                confirmed_organization: false
            }
        );
        assert_eq!(
            plan_org_privacy_commit(&org, None, true, 1).unwrap(),
            OrgPrivacyCommitPlan::Publish {
                erasure_version: 2,
                confirmed_organization: true
            }
        );
        let terminal = OrgPrivacyTerminal {
            scope: OrganizationPrivacyScope::resolve(&org, &[], &[]),
            group_ids: BTreeSet::new(),
            erasure_version: 2,
            confirmed_organization: true,
        };
        let OrgPrivacyCommitPlan::Replay(receipt) =
            plan_org_privacy_commit(&org, Some(&terminal), false, 7).unwrap()
        else {
            panic!("K3 replay");
        };
        assert_eq!(
            (receipt.erasure_version, receipt.observed_policy_version),
            (2, 7)
        );
        assert!(!receipt.changed && !receipt.admission_changed);
        assert!(
            plan_org_privacy_commit(&OrgId("foreign".into()), Some(&terminal), false, 7).is_err()
        );
        assert!(plan_org_privacy_commit(&org, None, true, i64::MAX as u64).is_err());
        assert!(plan_org_privacy_commit(&org, None, true, 0).is_err());
    }

    #[test]
    fn proven_retired_resource_seeds_reuse_the_same_scope_closure() {
        // EA06/07: positive original owner/tombstone survives active-edge loss
        // -> include its Resource and current descendants; unknown/foreign
        // resource is NOT inferred from absence. Legacy resolve has no seeds.
        use awaken_iam_contract::{ResourceId, ResourceType};
        let org = OrgId("org".into());
        let retired = ScopeRef::Resource {
            resource_type: ResourceType("kind".into()),
            resource_id: ResourceId("retired".into()),
        };
        let child = ResourceEdge {
            resource_type: ResourceType("kind".into()),
            resource_id: ResourceId("child".into()),
            parent: retired.clone(),
        };
        let keys = BTreeSet::from([("kind".into(), "retired".into())]);
        let scope =
            OrganizationPrivacyScope::resolve_with_owned_resources(&org, &[], &[child], &keys);
        assert!(scope.contains(&retired));
        assert!(scope.contains(&ScopeRef::Resource {
            resource_type: ResourceType("kind".into()),
            resource_id: ResourceId("child".into())
        }));
        assert!(!OrganizationPrivacyScope::resolve(&org, &[], &[]).contains(&retired));
        let negative = scope.without_projected_resources(&keys);
        assert!(
            !negative.contains(&retired),
            "original tombstone stays canonical; no duplicated projected refusal key"
        );
        assert!(
            negative.contains(&ScopeRef::Resource {
                resource_type: ResourceType("kind".into()),
                resource_id: ResourceId("child".into())
            }),
            "legacy descendant needs its minimal original Org refusal key"
        );
    }

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
