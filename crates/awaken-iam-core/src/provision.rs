//! Idempotent application of a resource-create provision into IAM.
//!
//! This is the IAM side of the resource-create consistency contract
//! ([ADR-0004](../../../docs/adr/0004-consumers-reuse-iam-authz.md) #4). A
//! consumer that creates a domain object propagates a
//! [`ResourceProvision`] — the grants and scope edges that make the new resource
//! authorizable — and IAM applies it here:
//!
//! - **Remote** consumers send the payload over the wire after draining their
//!   transactional outbox; the relay is at-least-once, so the same payload may
//!   arrive more than once.
//! - **Embedded** consumers call this directly inside their single shared-database
//!   transaction, alongside the domain write.
//!
//! Either way application is **idempotent**: grants upsert by their own id
//! through [`GrantRepo::put`] and each scope edge upserts by its
//! `(resource_type, resource_id)` key through [`ResourceModelRepo::put_edge`], so
//! re-applying an identical provision overwrites like with like and changes
//! nothing. Edges are written before grants so a grant anchored at the new
//! resource always resolves its ancestor scope the moment it lands — never a
//! grant referencing an edge that is not yet present.

use awaken_iam_contract::{GrantEffect, GrantSubjectRef, ResourceProvision};

use crate::GroupId;
use crate::authorization::{ActionPattern, Effect, Grant, GrantId, GrantSubject, RoleId};
use crate::ports::{GrantRepo, RepoResult, ResourceModelRepo};
use crate::resource_model::ResourceEdge;

/// Apply one [`ResourceProvision`] to the IAM authorization plane idempotently.
///
/// Scope edges are upserted first, then grants, so the scope graph that a grant
/// depends on is in place before the grant itself. Re-applying the same payload
/// is a no-op because both writes are keyed upserts; this is what makes the
/// at-least-once outbox relay safe with no two-phase commit. The `epoch` carried
/// by the provision is left for the caller's `version`/`epoch` fence and is not
/// interpreted here.
pub fn apply_resource_provision(
    provision: &ResourceProvision,
    grants: &dyn GrantRepo,
    edges: &dyn ResourceModelRepo,
) -> RepoResult<()> {
    for edge in &provision.scope_edges {
        edges.put_edge(ResourceEdge {
            resource_type: edge.resource_type.clone(),
            resource_id: edge.resource_id.clone(),
            parent: edge.parent.clone(),
        })?;
    }
    for grant in &provision.grants {
        grants.put(Grant {
            id: GrantId(grant.id.clone()),
            subject: match &grant.subject {
                GrantSubjectRef::Principal { principal } => {
                    GrantSubject::Principal(principal.clone())
                }
                GrantSubjectRef::Role { role_id } => GrantSubject::Role(RoleId(role_id.clone())),
                GrantSubjectRef::Group { group_id } => {
                    GrantSubject::Group(GroupId(group_id.clone()))
                }
            },
            action_pattern: ActionPattern(grant.action_pattern.clone()),
            scope: grant.scope.clone(),
            effect: match grant.effect {
                GrantEffect::Allow => Effect::Allow,
                GrantEffect::RequireApproval => Effect::RequireApproval,
                GrantEffect::Deny => Effect::Deny,
            },
        })?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ports::{RepoError, RepoResult};
    use awaken_iam_contract::{
        AccountId, GrantSnapshot, PrincipalRef, ResourceId, ResourceParentEdge, ResourceType,
        ScopeRef,
    };
    use std::sync::Mutex;

    #[derive(Default)]
    struct FakeAuthz {
        grants: Mutex<Vec<Grant>>,
        edges: Mutex<Vec<ResourceEdge>>,
    }

    impl GrantRepo for FakeAuthz {
        fn put(&self, grant: Grant) -> RepoResult<()> {
            let mut grants = self.grants.lock().unwrap();
            if let Some(existing) = grants.iter_mut().find(|g| g.id == grant.id) {
                *existing = grant;
            } else {
                grants.push(grant);
            }
            Ok(())
        }
        fn get(&self, id: &GrantId) -> RepoResult<Option<Grant>> {
            Ok(self
                .grants
                .lock()
                .unwrap()
                .iter()
                .find(|g| &g.id == id)
                .cloned())
        }
        fn list(&self) -> RepoResult<Vec<Grant>> {
            Ok(self.grants.lock().unwrap().clone())
        }
        fn remove(&self, id: &GrantId) -> RepoResult<()> {
            let mut grants = self.grants.lock().unwrap();
            let before = grants.len();
            grants.retain(|g| &g.id != id);
            if grants.len() == before {
                return Err(RepoError::NotFound(format!("grant {}", id.0)));
            }
            Ok(())
        }
    }

    impl ResourceModelRepo for FakeAuthz {
        fn put_edge(&self, edge: ResourceEdge) -> RepoResult<()> {
            let mut edges = self.edges.lock().unwrap();
            if let Some(existing) = edges.iter_mut().find(|e| {
                e.resource_type == edge.resource_type && e.resource_id == edge.resource_id
            }) {
                *existing = edge;
            } else {
                edges.push(edge);
            }
            Ok(())
        }
        fn list_edges(&self) -> RepoResult<Vec<ResourceEdge>> {
            Ok(self.edges.lock().unwrap().clone())
        }
    }

    fn provision() -> ResourceProvision {
        ResourceProvision {
            idempotency_key: "issue:42".into(),
            epoch: 3,
            grants: vec![GrantSnapshot {
                id: "g_issue_42_owner".into(),
                subject: GrantSubjectRef::Principal {
                    principal: PrincipalRef::Account {
                        account_id: AccountId("ada".into()),
                    },
                },
                action_pattern: "issue.*".into(),
                scope: ScopeRef::Resource {
                    resource_type: ResourceType("issue".into()),
                    resource_id: ResourceId("42".into()),
                },
                effect: GrantEffect::Allow,
            }],
            scope_edges: vec![ResourceParentEdge {
                resource_type: ResourceType("issue".into()),
                resource_id: ResourceId("42".into()),
                parent: ScopeRef::Global,
            }],
        }
    }

    #[test]
    fn apply_writes_grants_and_edges() {
        let authz = FakeAuthz::default();
        apply_resource_provision(&provision(), &authz, &authz).unwrap();
        assert_eq!(authz.list().unwrap().len(), 1);
        assert_eq!(authz.list_edges().unwrap().len(), 1);
        assert_eq!(
            authz.list().unwrap()[0].id,
            GrantId("g_issue_42_owner".into())
        );
    }

    #[test]
    fn re_applying_an_identical_provision_is_a_no_op() {
        // The at-least-once relay can deliver the same payload more than once; a
        // redelivery must not duplicate the grant or its edge.
        let authz = FakeAuthz::default();
        apply_resource_provision(&provision(), &authz, &authz).unwrap();
        apply_resource_provision(&provision(), &authz, &authz).unwrap();
        apply_resource_provision(&provision(), &authz, &authz).unwrap();
        assert_eq!(authz.list().unwrap().len(), 1);
        assert_eq!(authz.list_edges().unwrap().len(), 1);
    }

    #[test]
    fn fake_authz_get_returns_seeded_grants_and_remove_yields_not_found() {
        // The fake port's get/remove round-trip the same shape a real
        // GrantRepo exposes: get returns Some/None by id, remove yields
        // NotFound for an unknown id and Ok(()) for a known one.
        let authz = FakeAuthz::default();
        apply_resource_provision(&provision(), &authz, &authz).unwrap();

        let id = GrantId("g_issue_42_owner".into());
        assert!(authz.get(&id).unwrap().is_some());

        // Removing twice: first succeeds, second yields NotFound.
        authz.remove(&id).unwrap();
        assert!(authz.get(&id).unwrap().is_none());
        assert!(matches!(authz.remove(&id), Err(RepoError::NotFound(_))));
    }
}
