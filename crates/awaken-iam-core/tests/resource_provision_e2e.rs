//! End-to-end coverage of the resource-create provision contract.
//!
//! `apply_resource_provision` is the IAM side of the at-least-once outbox
//! relay (ADR-0004 decision 4): a consumer propagates a `ResourceProvision`
//! with grants and scope edges, and IAM applies it idempotently. Real
//! consumers cover all `GrantSubjectRef` variants (Principal, Role, Group)
//! and all `GrantEffect` values (Allow, RequireApproval, Deny); each must
//! round-trip through the real `Grant`/`ResourceEdge` aggregates without
//! dropping a field.
//!
//! These tests use real `GrantRepo` / `ResourceModelRepo` ports from
//! `awaken_iam_core` (not mocks) so any divergence between the wire shape
//! and the core aggregate is caught here.

use awaken_iam_contract::{
    AccountId, GrantEffect, GrantSubjectRef, PrincipalRef, ResourceId, ResourceParentEdge,
    ResourceProvision, ResourceType, ScopeRef,
};
use awaken_iam_core::{GrantRepo, ResourceModelRepo, apply_resource_provision};
use std::sync::Mutex;

/// A real `GrantRepo` and `ResourceModelRepo` backed by in-memory vectors.
/// Implements both ports so the provision can be applied through the same
/// seam the SqlStore / InMemoryStore adapters expose in production.
#[derive(Default)]
struct FakePort {
    grants: Mutex<Vec<awaken_iam_core::Grant>>,
    edges: Mutex<Vec<awaken_iam_core::ResourceEdge>>,
}

impl awaken_iam_core::GrantRepo for FakePort {
    fn put(&self, grant: awaken_iam_core::Grant) -> awaken_iam_core::RepoResult<()> {
        let mut grants = self.grants.lock().unwrap();
        if let Some(existing) = grants.iter_mut().find(|g| g.id == grant.id) {
            *existing = grant;
        } else {
            grants.push(grant);
        }
        Ok(())
    }
    fn get(
        &self,
        id: &awaken_iam_core::GrantId,
    ) -> awaken_iam_core::RepoResult<Option<awaken_iam_core::Grant>> {
        Ok(self
            .grants
            .lock()
            .unwrap()
            .iter()
            .find(|g| &g.id == id)
            .cloned())
    }
    fn list(&self) -> awaken_iam_core::RepoResult<Vec<awaken_iam_core::Grant>> {
        Ok(self.grants.lock().unwrap().clone())
    }
    fn remove(&self, id: &awaken_iam_core::GrantId) -> awaken_iam_core::RepoResult<()> {
        let mut grants = self.grants.lock().unwrap();
        let before = grants.len();
        grants.retain(|g| &g.id != id);
        if grants.len() == before {
            return Err(awaken_iam_core::RepoError::NotFound(format!(
                "grant {}",
                id.0
            )));
        }
        Ok(())
    }
}

impl awaken_iam_core::ResourceModelRepo for FakePort {
    fn put_edge(&self, edge: awaken_iam_core::ResourceEdge) -> awaken_iam_core::RepoResult<()> {
        let mut edges = self.edges.lock().unwrap();
        if let Some(existing) = edges
            .iter_mut()
            .find(|e| e.resource_type == edge.resource_type && e.resource_id == edge.resource_id)
        {
            *existing = edge;
        } else {
            edges.push(edge);
        }
        Ok(())
    }
    fn list_edges(&self) -> awaken_iam_core::RepoResult<Vec<awaken_iam_core::ResourceEdge>> {
        Ok(self.edges.lock().unwrap().clone())
    }
}

fn provision_with_subject(subject: GrantSubjectRef) -> ResourceProvision {
    ResourceProvision {
        idempotency_key: "issue:42".into(),
        epoch: 3,
        grants: vec![awaken_iam_contract::GrantSnapshot {
            id: "g_issue_42".into(),
            subject,
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
fn provision_anchors_a_grant_at_a_principal_subject() {
    // The most common consumer shape: the user who created the resource is
    // granted ownership of it.
    let port = FakePort::default();
    let provision = provision_with_subject(GrantSubjectRef::Principal {
        principal: PrincipalRef::Account {
            account_id: AccountId("ada".into()),
        },
    });
    apply_resource_provision(&provision, &port, &port).unwrap();

    let grants = port.list().unwrap();
    assert_eq!(grants.len(), 1);
    let grant = &grants[0];
    assert_eq!(grant.id.0, "g_issue_42");
    assert_eq!(
        grant.subject,
        awaken_iam_core::GrantSubject::Principal(PrincipalRef::Account {
            account_id: AccountId("ada".into()),
        })
    );
    assert_eq!(grant.action_pattern.0, "issue.*");
    assert!(matches!(grant.scope, ScopeRef::Resource { .. }));
}

#[test]
fn provision_anchors_a_grant_at_a_role_subject() {
    // A role-anchored grant: every principal holding that role at the grant's
    // scope inherits the action. Used for cross-resource patterns like
    // "every publisher can read every issue in their org".
    let port = FakePort::default();
    let provision = provision_with_subject(GrantSubjectRef::Role {
        role_id: "publisher".into(),
    });
    apply_resource_provision(&provision, &port, &port).unwrap();

    let grants = port.list().unwrap();
    assert_eq!(
        grants[0].subject,
        awaken_iam_core::GrantSubject::Role(awaken_iam_core::RoleId("publisher".into()),)
    );
}

#[test]
fn provision_anchors_a_grant_at_a_group_subject() {
    let port = FakePort::default();
    let provision = provision_with_subject(GrantSubjectRef::Group {
        group_id: "eng".into(),
    });
    apply_resource_provision(&provision, &port, &port).unwrap();

    let grants = port.list().unwrap();
    assert_eq!(
        grants[0].subject,
        awaken_iam_core::GrantSubject::Group(awaken_iam_core::GroupId("eng".into()),)
    );
}

#[test]
fn provision_round_trips_each_grant_effect() {
    // Allow, RequireApproval, Deny — every effect variant on the wire must
    // map onto the matching core aggregate, not collapse to one default.
    for effect in [
        GrantEffect::Allow,
        GrantEffect::RequireApproval,
        GrantEffect::Deny,
    ] {
        let port = FakePort::default();
        let mut provision = provision_with_subject(GrantSubjectRef::Principal {
            principal: PrincipalRef::Account {
                account_id: AccountId("ada".into()),
            },
        });
        provision.grants[0].effect = effect;
        apply_resource_provision(&provision, &port, &port).unwrap();
        let grants = port.list().unwrap();
        let expected = match effect {
            GrantEffect::Allow => awaken_iam_core::Effect::Allow,
            GrantEffect::RequireApproval => awaken_iam_core::Effect::RequireApproval,
            GrantEffect::Deny => awaken_iam_core::Effect::Deny,
        };
        assert_eq!(grants[0].effect, expected, "effect round-trip");
    }
}

#[test]
fn provision_upserts_scope_edges_idempotently() {
    // Two applications of the same provision must not duplicate the edge.
    // The scope graph that a grant depends on must be present exactly once.
    let port = FakePort::default();
    let provision = provision_with_subject(GrantSubjectRef::Principal {
        principal: PrincipalRef::Account {
            account_id: AccountId("ada".into()),
        },
    });

    apply_resource_provision(&provision, &port, &port).unwrap();
    apply_resource_provision(&provision, &port, &port).unwrap();
    apply_resource_provision(&provision, &port, &port).unwrap();

    assert_eq!(port.list().unwrap().len(), 1, "grant upsert is idempotent");
    assert_eq!(
        port.list_edges().unwrap().len(),
        1,
        "edge upsert is idempotent"
    );
}

#[test]
fn provision_writes_edges_before_grants_so_evaluation_resolves_immediately() {
    // Order matters: edges must be in the store *before* the grant they
    // anchor is written, so the first evaluation of the grant can walk the
    // scope graph immediately. A consumer cannot tolerate a transient window
    // where the grant references an edge that doesn't yet exist.
    //
    // We instrument the port to capture insert order and assert edges come
    // before grants.
    use std::sync::Mutex as StdMutex;
    #[derive(Default)]
    struct OrderedPort {
        order: StdMutex<Vec<&'static str>>,
        grants: StdMutex<Vec<awaken_iam_core::Grant>>,
        edges: StdMutex<Vec<awaken_iam_core::ResourceEdge>>,
    }
    impl awaken_iam_core::GrantRepo for OrderedPort {
        fn put(&self, g: awaken_iam_core::Grant) -> awaken_iam_core::RepoResult<()> {
            self.order.lock().unwrap().push("grant");
            self.grants.lock().unwrap().push(g);
            Ok(())
        }
        fn get(
            &self,
            _: &awaken_iam_core::GrantId,
        ) -> awaken_iam_core::RepoResult<Option<awaken_iam_core::Grant>> {
            Ok(None)
        }
        fn list(&self) -> awaken_iam_core::RepoResult<Vec<awaken_iam_core::Grant>> {
            Ok(self.grants.lock().unwrap().clone())
        }
        fn remove(&self, _: &awaken_iam_core::GrantId) -> awaken_iam_core::RepoResult<()> {
            Ok(())
        }
    }
    impl awaken_iam_core::ResourceModelRepo for OrderedPort {
        fn put_edge(&self, e: awaken_iam_core::ResourceEdge) -> awaken_iam_core::RepoResult<()> {
            self.order.lock().unwrap().push("edge");
            self.edges.lock().unwrap().push(e);
            Ok(())
        }
        fn list_edges(&self) -> awaken_iam_core::RepoResult<Vec<awaken_iam_core::ResourceEdge>> {
            Ok(self.edges.lock().unwrap().clone())
        }
    }

    let port = OrderedPort::default();
    let provision = provision_with_subject(GrantSubjectRef::Principal {
        principal: PrincipalRef::Account {
            account_id: AccountId("ada".into()),
        },
    });
    apply_resource_provision(&provision, &port, &port).unwrap();
    let order = port.order.lock().unwrap().clone();
    assert_eq!(order, vec!["edge", "grant"]);
}

#[test]
fn provision_with_multiple_grants_writes_each_one() {
    // A consumer may bundle several grants per resource (the creator gets
    // owner, the team gets read, etc.). Each grant round-trips independently.
    let port = FakePort::default();
    let provision = ResourceProvision {
        idempotency_key: "issue:99".into(),
        epoch: 7,
        grants: vec![
            awaken_iam_contract::GrantSnapshot {
                id: "g_owner".into(),
                subject: GrantSubjectRef::Principal {
                    principal: PrincipalRef::Account {
                        account_id: AccountId("ada".into()),
                    },
                },
                action_pattern: "issue.*".into(),
                scope: ScopeRef::Resource {
                    resource_type: ResourceType("issue".into()),
                    resource_id: ResourceId("99".into()),
                },
                effect: GrantEffect::Allow,
            },
            awaken_iam_contract::GrantSnapshot {
                id: "g_team_read".into(),
                subject: GrantSubjectRef::Group {
                    group_id: "eng".into(),
                },
                action_pattern: "issue.read".into(),
                scope: ScopeRef::Resource {
                    resource_type: ResourceType("issue".into()),
                    resource_id: ResourceId("99".into()),
                },
                effect: GrantEffect::Allow,
            },
        ],
        // A single resource anchors exactly one parent edge. The provision
        // carries the same edge a second time would be a no-op replacement,
        // not duplication.
        scope_edges: vec![ResourceParentEdge {
            resource_type: ResourceType("issue".into()),
            resource_id: ResourceId("99".into()),
            parent: ScopeRef::Global,
        }],
    };
    apply_resource_provision(&provision, &port, &port).unwrap();

    let grants = port.list().unwrap();
    assert_eq!(grants.len(), 2);
    assert!(grants.iter().any(|g| g.id.0 == "g_owner"));
    assert!(grants.iter().any(|g| g.id.0 == "g_team_read"));
    assert_eq!(port.list_edges().unwrap().len(), 1);
}
