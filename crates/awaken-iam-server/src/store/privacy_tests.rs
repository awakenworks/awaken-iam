//! Shared participant receipt tests; production authority remains Core + stores.
use super::{FenceStore, InMemoryStore, SqlConn, SqlParam, SqlRow, SqlStore, SqlTransaction};
use crate::admin_api::ResourceProvisioningStore;
use awaken_iam_contract::{
    AccountId, ApiToken, ApiTokenId, ApiTokenPrefix, InvitationId, InvitationStatus, OrgId,
    PrincipalRef, ResourceProvision, ScopeRef, Timestamp, WorkspaceId, WorkspaceOrgEdge,
};
use awaken_iam_core::{
    ActionPattern, ApiTokenRepository, AuditEvent, AuditSink, Effect, Grant, GrantId,
    GrantRepository, GrantSubject, Group, GroupId, GroupRepository, Invitation,
    InvitationRepository, OrgPrivacyRepository, OrgRepository, Organization, RepositoryError,
    RepositoryResult, ResourceEdge, ResourceModelRepository, RoleBinding, RoleBindingRepository,
    RoleId,
};

fn org(id: &str) -> Organization {
    Organization {
        id: OrgId(id.into()),
        display_name: Some("private name".into()),
        owner: PrincipalRef::Service {
            service_id: "private-owner".into(),
        },
        created_at: Timestamp("2026-10-30T00:00:00Z".into()),
        updated_at: Timestamp("2026-10-30T00:00:00Z".into()),
    }
}
fn audit(id: &OrgId) -> AuditEvent {
    crate::admin_api::organization_erasure_audit(id, Timestamp("2026-10-30T01:00:00Z".into()))
}

fn receipt_cases<S: OrgRepository + OrgPrivacyRepository + FenceStore + AuditSink>(store: &S) {
    // CF2 cause/effect graph: known live identity + first command -> payload
    // cleanup + exact terminal receipt + audit/global fence ONE commit;
    // repeat/lost reply -> stored erasure coordinate + CURRENT policy, no write;
    // Never/legacy-deleted -> new negative admission publishes once despite
    // changed=false, but confirmed=false forbids a new erasure certificate.
    // Foreign Org remains live; larger global version never rewrites the receipt.
    // Decision rows P1 Known, P2 Replay, P3 UnrelatedAdvance, P4 Never,
    // P5 LegacyUnknown, P6 CompatibilityBool, P7 TerminalRecreate.
    OrgRepository::upsert(store, org("known")).unwrap();
    OrgRepository::upsert(store, org("foreign")).unwrap();
    let before = store.fence().unwrap().version;
    let audit_before = AuditSink::events(store).unwrap().len();
    let known = OrgId("known".into());
    let first = store
        .erase_org_privacy_with_audit(&known, audit(&known))
        .unwrap();
    assert!(
        first.changed && first.admission_changed && first.confirmed_organization,
        "P1"
    );
    assert_eq!(first.erasure_version, before + 1, "P1");
    assert_eq!(first.observed_policy_version, first.erasure_version, "P1");
    assert_eq!(
        AuditSink::events(store).unwrap().len(),
        audit_before + 1,
        "P1"
    );
    let replay = store
        .erase_org_privacy_with_audit(&known, audit(&known))
        .unwrap();
    assert!(!replay.changed && !replay.admission_changed, "P2");
    assert_eq!(replay.erasure_version, first.erasure_version, "P2");
    assert_eq!(store.fence().unwrap().version, first.erasure_version, "P2");
    let newer = store.advance_version().unwrap();
    let replay = store
        .erase_org_privacy_with_audit(&known, audit(&known))
        .unwrap();
    assert_eq!(
        replay.erasure_version, first.erasure_version,
        "P3 historical coordinate"
    );
    assert_eq!(
        replay.observed_policy_version, newer,
        "P3 current coordinate"
    );
    assert_eq!(
        AuditSink::events(store).unwrap().len(),
        audit_before + 1,
        "P2/P3 no extra audit"
    );
    let never = OrgId("never".into());
    let absent = store
        .erase_org_privacy_with_audit(&never, audit(&never))
        .unwrap();
    assert!(
        !absent.changed && absent.admission_changed && !absent.confirmed_organization,
        "P4"
    );
    assert_eq!(
        absent.erasure_version,
        newer + 1,
        "P4 negative fact IS policy change"
    );
    OrgRepository::upsert(store, org("legacy")).unwrap();
    OrgRepository::remove(store, &OrgId("legacy".into())).unwrap();
    let legacy = OrgId("legacy".into());
    let unknown = store
        .erase_org_privacy_with_audit(&legacy, audit(&legacy))
        .unwrap();
    assert!(
        !unknown.confirmed_organization,
        "P5 no invented historical identity"
    );
    let before_bool = store.fence().unwrap().version;
    assert!(
        !store
            .erase_org_privacy(&OrgId("legacy-bool".into()))
            .unwrap(),
        "P6 payload law"
    );
    assert_eq!(
        store.fence().unwrap().version,
        before_bool + 1,
        "P6 same atomic publication"
    );
    assert!(
        !store
            .erase_org_privacy(&OrgId("legacy-bool".into()))
            .unwrap(),
        "P6 exact retry"
    );
    assert_eq!(
        store.fence().unwrap().version,
        before_bool + 1,
        "P6 no repeat publication"
    );
    assert!(
        OrgRepository::upsert(store, org("known")).is_err(),
        "P7 no resurrection"
    );
    assert!(
        OrgRepository::remove(store, &known).is_err(),
        "P7 terminal cannot be deleted"
    );
    assert_eq!(
        OrgRepository::get(store, &OrgId("foreign".into())).unwrap(),
        Some(org("foreign")),
        "foreign whole record retained"
    );
}

use std::sync::atomic::{AtomicBool, Ordering};

#[derive(Clone, Copy, PartialEq, Eq)]
enum PrivacyFault {
    AuditWrite,
    FinalFenceWrite,
    CommitReply,
}
struct FailPrivacy<B> {
    inner: B,
    cut: PrivacyFault,
    fired: AtomicBool,
}
impl<B> FailPrivacy<B> {
    fn new(inner: B, cut: PrivacyFault) -> Self {
        Self {
            inner,
            cut,
            fired: AtomicBool::new(false),
        }
    }
}
impl<B: SqlConn> SqlConn for FailPrivacy<B> {
    fn dialect(&self) -> super::migration::Dialect {
        self.inner.dialect()
    }
    fn execute(&self, sql: &str, params: &[SqlParam]) -> RepositoryResult<u64> {
        self.inner.execute(sql, params)
    }
    fn query(&self, sql: &str, params: &[SqlParam]) -> RepositoryResult<Vec<SqlRow>> {
        self.inner.query(sql, params)
    }
    fn with_transaction(
        &self,
        operation: &mut (dyn FnMut(&mut dyn SqlTransaction) -> RepositoryResult<()> + Send),
    ) -> RepositoryResult<()> {
        self.inner.with_transaction(&mut |transaction| {
            operation(&mut FailPrivacyTransaction {
                inner: transaction,
                cut: self.cut,
                fired: &self.fired,
                audit_written: false,
            })
        })?;
        // Protocol fault injection AFTER the actual original native commit.
        // This is not a simulated transaction, fake receipt or real network cut.
        if self.cut == PrivacyFault::CommitReply && !self.fired.swap(true, Ordering::SeqCst) {
            return Err(RepositoryError::Backend(
                "injected reply loss after native commit".into(),
            ));
        }
        Ok(())
    }
}
struct FailPrivacyTransaction<'a> {
    inner: &'a mut dyn SqlTransaction,
    cut: PrivacyFault,
    fired: &'a AtomicBool,
    audit_written: bool,
}
impl SqlTransaction for FailPrivacyTransaction<'_> {
    fn execute(&mut self, sql: &str, params: &[SqlParam]) -> RepositoryResult<u64> {
        let audit_write = sql.contains("_audit_events");
        let final_fence =
            self.audit_written && sql.contains("_fence") && sql.contains(" SET version=");
        if ((self.cut == PrivacyFault::AuditWrite && audit_write)
            || (self.cut == PrivacyFault::FinalFenceWrite && final_fence))
            && !self.fired.swap(true, Ordering::SeqCst)
        {
            return Err(RepositoryError::Backend(
                "injected original privacy write failure".into(),
            ));
        }
        let affected = self.inner.execute(sql, params)?;
        self.audit_written |= audit_write;
        Ok(affected)
    }
    fn query(&mut self, sql: &str, params: &[SqlParam]) -> RepositoryResult<Vec<SqlRow>> {
        self.inner.query(sql, params)
    }
}
fn seed_owned_closure<S>(store: &S) -> (PrincipalRef, ResourceEdge)
where
    S: OrgRepository
        + GroupRepository
        + GrantRepository
        + RoleBindingRepository
        + ApiTokenRepository
        + ResourceModelRepository,
{
    let owner = PrincipalRef::Account {
        account_id: AccountId("owner".into()),
    };
    for id in ["org-a", "org-b"] {
        OrgRepository::upsert(
            store,
            Organization {
                id: OrgId(id.into()),
                display_name: None,
                owner: owner.clone(),
                created_at: Timestamp("2026-06-19T00:00:00Z".into()),
                updated_at: Timestamp("2026-06-19T00:00:00Z".into()),
            },
        )
        .unwrap();
    }
    GroupRepository::upsert(
        store,
        Group {
            id: GroupId("group-a".into()),
            org: OrgId("org-a".into()),
            display_name: None,
            members: vec![owner.clone()],
            created_at: Timestamp("2026-06-19T00:00:00Z".into()),
            updated_at: Timestamp("2026-06-19T00:00:00Z".into()),
        },
    )
    .unwrap();
    for (workspace, org) in [("ws-a", "org-a"), ("ws-b", "org-b")] {
        ResourceModelRepository::put_workspace_org(
            store,
            WorkspaceOrgEdge {
                workspace_id: WorkspaceId(workspace.into()),
                org_id: OrgId(org.into()),
            },
        )
        .unwrap();
    }
    let owned_resource = ResourceEdge {
        resource_type: awaken_iam_contract::ResourceType("issue".into()),
        resource_id: awaken_iam_contract::ResourceId("owned".into()),
        parent: ScopeRef::Project {
            workspace_id: WorkspaceId("ws-a".into()),
            project_id: awaken_iam_contract::ProjectId("project-a".into()),
        },
    };
    ResourceModelRepository::put_edge(store, owned_resource.clone()).unwrap();
    GrantRepository::put(
        store,
        Grant {
            id: GrantId("owned-grant".into()),
            subject: GrantSubject::Group(GroupId("group-a".into())),
            action_pattern: ActionPattern("issue.read".into()),
            scope: ScopeRef::Resource {
                resource_type: owned_resource.resource_type.clone(),
                resource_id: owned_resource.resource_id.clone(),
            },
            effect: Effect::Allow,
        },
    )
    .unwrap();
    RoleBindingRepository::add(
        store,
        RoleBinding {
            principal: owner.clone(),
            role: RoleId("member".into()),
            scope: ScopeRef::Workspace {
                workspace_id: WorkspaceId("ws-a".into()),
            },
        },
    )
    .unwrap();
    for (id, workspace) in [("token-a", "ws-a"), ("token-b", "ws-b")] {
        ApiTokenRepository::create(
            store,
            ApiToken {
                id: ApiTokenId(id.into()),
                prefix: ApiTokenPrefix(format!("prefix-{id}")),
                principal: owner.clone(),
                secret_hash: "hash".into(),
                workspace: WorkspaceId(workspace.into()),
                created_at: Timestamp("2026-06-19T00:00:00Z".into()),
                expires_at: None,
                revoked_at: None,
            },
        )
        .unwrap();
    }

    (owner, owned_resource)
}

fn seed_invitation<S: InvitationRepository>(
    store: &S,
    owner: &PrincipalRef,
    scope: &ScopeRef,
) -> Invitation {
    let invitation = Invitation {
        id: InvitationId("invite-a".into()),
        idempotency_key: "invite-key".into(),
        org_id: OrgId("org-a".into()),
        email: "owner@example.test".into(),
        bindings: vec![awaken_iam_contract::InvitationBinding {
            role_id: "member".into(),
            scope: scope.clone(),
        }],
        invited_by: owner.clone(),
        token_hash: "claim-hash".into(),
        status: InvitationStatus::Pending,
        expires_at: Timestamp("2026-12-01T00:00:00Z".into()),
        created_at: Timestamp("2026-06-19T00:00:00Z".into()),
        updated_at: Timestamp("2026-06-19T00:00:00Z".into()),
        accepted_by_account_id: None,
    };
    InvitationRepository::create_invitation(store, invitation.clone()).unwrap();
    invitation
}

fn seed_raw_provision<S: ResourceProvisioningStore>(
    store: &S,
    owned_resource: &ResourceEdge,
) -> (
    ResourceProvision,
    awaken_iam_contract::ResourceProvisionReceipt,
) {
    let provision = ResourceProvision {
        product_id: awaken_iam_contract::ProductId::new("tutor").unwrap(),
        org_id: OrgId("org-a".into()),
        idempotency_key: "captured-provision".into(),
        epoch: 1,
        grants: vec![],
        scope_edges: vec![awaken_iam_contract::ResourceParentEdge {
            resource_type: owned_resource.resource_type.clone(),
            resource_id: owned_resource.resource_id.clone(),
            parent: owned_resource.parent.clone(),
        }],
        retirements: vec![],
    };
    let original_receipt = store
        .provision_resource(
            &provision,
            "captured",
            AuditEvent {
                at: Timestamp("2026-06-19T00:00:00Z".into()),
                actor: None,
                action: "test.provision".into(),
                detail: "captured".into(),
            },
        )
        .unwrap();
    (provision, original_receipt)
}

fn assert_owned_closure_erased<S>(store: &S)
where
    S: OrgRepository
        + GroupRepository
        + GrantRepository
        + RoleBindingRepository
        + ApiTokenRepository
        + ResourceModelRepository,
{
    assert!(
        OrgRepository::get(store, &OrgId("org-a".into()))
            .unwrap()
            .is_none()
    );
    assert!(
        OrgRepository::get(store, &OrgId("org-b".into()))
            .unwrap()
            .is_some()
    );
    assert!(GroupRepository::list(store).unwrap().is_empty());
    assert!(GrantRepository::list(store).unwrap().is_empty());
    assert!(RoleBindingRepository::list(store).unwrap().is_empty());
    assert!(
        ResourceModelRepository::list_edges(store)
            .unwrap()
            .is_empty()
    );
    assert!(
        ApiTokenRepository::get(store, &ApiTokenId("token-a".into()))
            .unwrap()
            .is_none()
    );
    assert!(
        ApiTokenRepository::get(store, &ApiTokenId("token-b".into()))
            .unwrap()
            .is_some()
    );
}

pub(super) fn closure_and_late_writer_cases<S>(store: &S)
where
    S: OrgRepository
        + OrgPrivacyRepository
        + GroupRepository
        + GrantRepository
        + RoleBindingRepository
        + ApiTokenRepository
        + ResourceModelRepository
        + InvitationRepository
        + ResourceProvisioningStore
        + FenceStore
        + AuditSink,
{
    // Cause/effect decision table:
    // C1 row is the Org, its group/invitation, owned Workspace, Project or
    // recursive Resource scope or Directory placement -> E1 remove; C2 API
    // token is bound to an owned Workspace -> E2 remove; C3 row belongs to
    // a foreign Org -> E3 retain; C4 exact retry after E1/E2 -> E4 false
    // with no new effect.
    let (owner, owned_resource) = seed_owned_closure(store);

    // EA05/06/07/08: capture real candidate values BEFORE erasure, then
    // resume each existing writer after the same atomic terminal commit.
    let stale_org = OrgRepository::get(store, &OrgId("org-a".into()))
        .unwrap()
        .unwrap();
    let stale_group = GroupRepository::get(store, &GroupId("group-a".into()))
        .unwrap()
        .unwrap();
    let stale_grant = GrantRepository::get(store, &GrantId("owned-grant".into()))
        .unwrap()
        .unwrap();
    let stale_binding = RoleBindingRepository::list(store).unwrap().remove(0);
    let stale_token = ApiTokenRepository::get(store, &ApiTokenId("token-a".into()))
        .unwrap()
        .unwrap();
    let foreign_token = ApiTokenRepository::get(store, &ApiTokenId("token-b".into()))
        .unwrap()
        .unwrap();
    let invitation = seed_invitation(store, &owner, &stale_binding.scope);
    let (provision, original_receipt) = seed_raw_provision(store, &owned_resource);
    assert!(store.erase_org_privacy(&OrgId("org-a".into())).unwrap());
    assert!(!store.erase_org_privacy(&OrgId("org-a".into())).unwrap());
    assert_owned_closure_erased(store);

    // EA05–08 effects: terminal admission applies even when the live owner
    // graph is now absent. Prior AND proposed identities are checked under
    // authz; token mutation keeps authz -> identity through the effect.
    let before_fence = store.fence().unwrap();
    let before_audit = AuditSink::events(store).unwrap();
    assert!(OrgRepository::upsert(store, stale_org).is_err());
    assert!(GroupRepository::upsert(store, stale_group).is_err());
    assert!(GrantRepository::put(store, stale_grant.clone()).is_err());
    let group_only = Grant {
        id: GrantId("group-only".into()),
        scope: ScopeRef::Global,
        ..stale_grant
    };
    assert!(
        GrantRepository::put(store, group_only).is_err(),
        "EA06 Group-subject negative key"
    );
    assert!(RoleBindingRepository::add(store, stale_binding.clone()).is_err());
    assert!(
        RoleBindingRepository::replace_scoped(
            store,
            &owner,
            &stale_binding.scope,
            &[RoleId("member".into())],
            &[RoleId("member".into())]
        )
        .is_err()
    );
    assert!(ApiTokenRepository::create(store, stale_token.clone()).is_err());
    assert!(ApiTokenRepository::update(store, stale_token).is_err());
    assert!(ResourceModelRepository::put_edge(store, owned_resource.clone()).is_err());
    let mut reparented = owned_resource.clone();
    reparented.parent = ScopeRef::Org {
        org_id: OrgId("org-b".into()),
    };
    assert!(
        ResourceModelRepository::put_edge(store, reparented).is_err(),
        "EA06 prior Resource identity cannot be reattached elsewhere"
    );
    assert!(
        ResourceModelRepository::put_workspace_org(
            store,
            WorkspaceOrgEdge {
                workspace_id: WorkspaceId("ws-a".into()),
                org_id: OrgId("org-b".into())
            }
        )
        .is_err(),
        "EA06 prior Workspace identity"
    );
    assert!(InvitationRepository::create_invitation(store, invitation.clone()).is_err());
    assert!(
        InvitationRepository::replace_pending_invitation(store, invitation.clone(), "claim-hash")
            .is_err()
    );
    assert!(
        InvitationRepository::accept_pending_invitation(
            store,
            &invitation.id,
            "claim-hash",
            &AccountId("late-account".into()),
            &Timestamp("2026-10-30T00:00:00Z".into())
        )
        .is_err()
    );
    assert!(
        store
            .resource_provision_replay(&provision, "captured")
            .is_err(),
        "EA07 old receipt is not live admission"
    );
    let mut newer = provision;
    newer.epoch = original_receipt.epoch + 1;
    newer.idempotency_key = "newer-provision".into();
    assert!(
        store
            .provision_resource(
                &newer,
                "newer",
                AuditEvent {
                    at: Timestamp("2026-10-30T00:00:00Z".into()),
                    actor: None,
                    action: "test.provision".into(),
                    detail: "newer".into()
                }
            )
            .is_err(),
        "EA07 larger epoch cannot revive Org"
    );
    assert_eq!(
        store.fence().unwrap(),
        before_fence,
        "EA05–08 zero policy effect"
    );
    assert_eq!(
        AuditSink::events(store).unwrap(),
        before_audit,
        "EA05–08 zero audit effect"
    );
    assert!(GroupRepository::list(store).unwrap().is_empty());
    assert!(GrantRepository::list(store).unwrap().is_empty());
    assert!(RoleBindingRepository::list(store).unwrap().is_empty());
    assert!(
        ResourceModelRepository::list_edges(store)
            .unwrap()
            .is_empty()
    );
    assert!(
        InvitationRepository::list_invitations_for_org(store, &OrgId("org-a".into()))
            .unwrap()
            .is_empty()
    );
    assert_eq!(
        ApiTokenRepository::get(store, &ApiTokenId("token-b".into())).unwrap(),
        Some(foreign_token),
        "foreign whole token retained"
    );
}

fn seed_projected_closure<B: SqlConn + Clone>(
    store: &SqlStore<B>,
    id: &OrgId,
) -> awaken_iam_contract::ResourceProjectionBatch {
    use awaken_iam_contract::{
        ActionKey, GrantEffect, GrantSnapshot, GrantSubjectRef, ProductId,
        ProductResourceModelRequest, ResourceId, ResourceModelRegistration, ResourceParentEdge,
        ResourceProjectionBatch, ResourceType, ResourceTypeRegistration, ScopeRef, WorkspaceId,
        WorkspaceOrgEdge,
    };
    use awaken_iam_core::ResourceModelRepository;
    let id = id.clone();
    OrgRepository::upsert(store, org(&id.0)).unwrap();
    ResourceModelRepository::put_workspace_org(
        store,
        WorkspaceOrgEdge {
            workspace_id: WorkspaceId("projected-workspace".into()),
            org_id: id.clone(),
        },
    )
    .unwrap();
    let product = ProductId::new("tutor").unwrap();
    let kind = ResourceType("tutor.private".into());
    store
        .register_product_resource_model(&ProductResourceModelRequest {
            product_id: product.clone(),
            resource_model: ResourceModelRegistration {
                resource_types: vec![ResourceTypeRegistration {
                    resource_type: kind.clone(),
                    parent_type: None,
                    actions: vec![ActionKey("tutor.private.read".into())],
                }],
                actions: vec![],
                edges: vec![],
            },
        })
        .unwrap();
    let scope = ScopeRef::Resource {
        resource_type: kind.clone(),
        resource_id: ResourceId("private-one".into()),
    };
    let captured = ResourceProjectionBatch {
        product_id: product,
        org_id: id.clone(),
        projection_id: "private-stream".into(),
        idempotency_key: "private-key-2".into(),
        epoch: 2,
        grants: vec![GrantSnapshot {
            id: "private-grant".into(),
            subject: GrantSubjectRef::Principal {
                principal: PrincipalRef::Service {
                    service_id: "private-owner".into(),
                },
            },
            action_pattern: "tutor.private.read".into(),
            scope,
            effect: GrantEffect::Allow,
        }],
        scope_edges: vec![ResourceParentEdge {
            resource_type: kind,
            resource_id: ResourceId("private-one".into()),
            parent: ScopeRef::Workspace {
                workspace_id: WorkspaceId("projected-workspace".into()),
            },
        }],
        retirements: vec![],
    };
    // EA07/EA10 actual original projection owner, SAME fixture on real SQLite
    // and configured PG: exact/older/newer/foreign candidates captured before
    // terminal commit must all refuse; source stream/owner/epoch stays canonical.
    store.apply_resource_projection(&captured).unwrap();
    captured
}

fn projection_cases<B: SqlConn + Clone>(store: &SqlStore<B>, prefix: &str) {
    let id = OrgId("projected".into());
    let captured = seed_projected_closure(store, &id);
    assert_eq!(
        store
            .apply_resource_projection(&captured)
            .unwrap()
            .disposition,
        awaken_iam_contract::ResourceProjectionDisposition::Replayed
    );
    store.erase_org_privacy_with_audit(&id, audit(&id)).unwrap();
    let before_fence = store.fence().unwrap();
    let before_audit = AuditSink::events(store).unwrap();
    let query = format!(
        "SELECT CAST(epoch AS TEXT),payload_digest,idempotency_key,CAST(version AS TEXT),CAST(grant_ids AS TEXT),CAST(edge_keys AS TEXT) FROM {prefix}_resource_projection_streams WHERE org_id=? ORDER BY projection_id"
    );
    let before = store
        .backend()
        .query(&query, &[Some(id.0.clone())])
        .unwrap();
    let mut older = captured.clone();
    older.epoch = 1;
    older.idempotency_key = "private-key-1".into();
    let mut newer = captured.clone();
    newer.epoch = 3;
    newer.idempotency_key = "private-key-3".into();
    let mut foreign = newer.clone();
    foreign.org_id = OrgId("foreign".into());
    for candidate in [&captured, &older, &newer, &foreign] {
        assert!(
            store.apply_resource_projection(candidate).is_err(),
            "EA07 no receipt-based terminal bypass"
        );
        assert_eq!(store.fence().unwrap(), before_fence, "EA07 no publication");
        assert_eq!(
            AuditSink::events(store).unwrap(),
            before_audit,
            "EA07 no audit"
        );
        assert_eq!(
            store
                .backend()
                .query(&query, &[Some(id.0.clone())])
                .unwrap(),
            before,
            "EA07 whole stream unchanged"
        );
    }
}

fn retired_projection_owner_cases<B: SqlConn + Clone>(store: &SqlStore<B>, prefix: &str) {
    use awaken_iam_contract::{
        GrantEffect, GrantSnapshot, GrantSubjectRef, ProductId, ResourceId, ResourceParentEdge,
        ResourceProjectionBatch, ResourceRetirement, ResourceType, WorkspaceId, WorkspaceOrgEdge,
    };
    let org_id = OrgId("retired-root".into());
    let kind = ResourceType("tutor.private".into());
    let resource = ResourceId("retired-owned".into());
    OrgRepository::upsert(store, org("retired-root")).unwrap();
    ResourceModelRepository::put_workspace_org(
        store,
        WorkspaceOrgEdge {
            workspace_id: WorkspaceId("retired-workspace".into()),
            org_id: org_id.clone(),
        },
    )
    .unwrap();
    let target = ScopeRef::Resource {
        resource_type: kind.clone(),
        resource_id: resource.clone(),
    };
    let body = ResourceProjectionBatch {
        product_id: ProductId::new("tutor").unwrap(),
        org_id: org_id.clone(),
        projection_id: "retirement-stream".into(),
        idempotency_key: "retirement-key-2".into(),
        epoch: 2,
        grants: vec![GrantSnapshot {
            id: "owned-retirement-grant".into(),
            subject: GrantSubjectRef::Principal {
                principal: PrincipalRef::Service {
                    service_id: "owner".into(),
                },
            },
            action_pattern: "tutor.private.read".into(),
            scope: target.clone(),
            effect: GrantEffect::Allow,
        }],
        scope_edges: vec![ResourceParentEdge {
            resource_type: kind.clone(),
            resource_id: resource.clone(),
            parent: ScopeRef::Workspace {
                workspace_id: WorkspaceId("retired-workspace".into()),
            },
        }],
        retirements: vec![],
    };
    store.apply_resource_projection(&body).unwrap();
    let edge = ResourceEdge {
        resource_type: kind.clone(),
        resource_id: resource.clone(),
        parent: body.scope_edges[0].parent.clone(),
    };
    // EA07 owner consolidation: the original projection owner forbids raw
    // overwrite/delete/higher-epoch legacy provisioning, not only ON CONFLICT
    // UPDATE. After retirement its SAME tombstone forbids INSERT resurrection.
    assert!(ResourceModelRepository::put_edge(store, edge.clone()).is_err());
    assert!(ResourceModelRepository::remove_edge(store, &kind, &resource).is_err());
    let raw = ResourceProvision {
        product_id: body.product_id.clone(),
        org_id: org_id.clone(),
        idempotency_key: "raw-owner-attempt".into(),
        epoch: 9,
        grants: vec![],
        scope_edges: body.scope_edges.clone(),
        retirements: vec![],
    };
    assert!(
        store
            .provision_resource(&raw, "raw-owner", audit(&org_id))
            .is_err()
    );
    // A legitimate independent admin grant/binding exists BEFORE retirement.
    // It is not an owned-stream grant; retirement makes the resource deny, but
    // privacy still must remove these payload rows using the POSITIVE original
    // tombstone, even though the active parent edge no longer exists.
    let manual = Grant {
        id: GrantId("manual-retired-grant".into()),
        subject: GrantSubject::Principal(PrincipalRef::Service {
            service_id: "manual".into(),
        }),
        action_pattern: ActionPattern("tutor.private.read".into()),
        scope: target.clone(),
        effect: Effect::Allow,
    };
    GrantRepository::put(store, manual.clone()).unwrap();
    RoleBindingRepository::add(
        store,
        RoleBinding {
            principal: PrincipalRef::Service {
                service_id: "manual".into(),
            },
            role: RoleId("member".into()),
            scope: target.clone(),
        },
    )
    .unwrap();
    let mut retired = body.clone();
    retired.epoch = 3;
    retired.idempotency_key = "retirement-key-3".into();
    retired.grants.clear();
    retired.scope_edges.clear();
    retired.retirements = vec![ResourceRetirement {
        resource_type: kind.clone(),
        resource_id: resource.clone(),
        grant_ids: vec!["owned-retirement-grant".into()],
    }];
    store.apply_resource_projection(&retired).unwrap();
    assert!(
        GrantRepository::get(store, &manual.id).unwrap().is_some(),
        "positive tombstone seed required for later privacy cleanup"
    );
    let before = store.fence().unwrap();
    let audits = AuditSink::events(store).unwrap();
    assert!(
        ResourceModelRepository::put_edge(store, edge).is_err(),
        "retired resource INSERT refused"
    );
    assert!(
        GrantRepository::put(store, manual.clone()).is_err(),
        "retired scoped grant effect refused"
    );
    assert!(
        RoleBindingRepository::add(
            store,
            RoleBinding {
                principal: PrincipalRef::Service {
                    service_id: "late-manual".into()
                },
                role: RoleId("member".into()),
                scope: target.clone()
            }
        )
        .is_err(),
        "retired scoped membership effect refused"
    );
    let child = ResourceEdge {
        resource_type: kind.clone(),
        resource_id: ResourceId("child-of-retired".into()),
        parent: target.clone(),
    };
    assert!(
        ResourceModelRepository::put_edge(store, child).is_err(),
        "retired parent cannot admit a raw child"
    );
    assert!(
        store
            .provision_resource(&raw, "raw-owner", audit(&org_id))
            .is_err(),
        "higher epoch does not override original retirement"
    );
    assert_eq!(
        store.fence().unwrap(),
        before,
        "raw refusals do not publish"
    );
    assert_eq!(
        AuditSink::events(store).unwrap(),
        audits,
        "raw refusals do not audit"
    );
    let erased = store
        .erase_org_privacy_with_audit(&org_id, audit(&org_id))
        .unwrap();
    assert!(erased.confirmed_organization);
    assert!(
        GrantRepository::get(store, &manual.id).unwrap().is_none(),
        "retired owned Resource grant is erased"
    );
    assert!(
        !RoleBindingRepository::list(store)
            .unwrap()
            .iter()
            .any(|binding| binding.scope == target),
        "retired owned Resource binding is erased"
    );
    assert!(
        ResourceModelRepository::list_retired_resources(store)
            .unwrap()
            .iter()
            .any(|key| key.resource_type == kind && key.resource_id == resource),
        "original retirement remains canonical"
    );
    let rows = store
        .backend()
        .query(
            &format!("SELECT CAST(erased_scope AS TEXT) FROM {prefix}_orgs WHERE id=?"),
            &[Some(org_id.0)],
        )
        .unwrap();
    let legacy_scope: awaken_iam_core::OrganizationPrivacyScope =
        serde_json::from_str(rows[0][0].as_deref().unwrap()).unwrap();
    assert!(
        !legacy_scope.contains(&target),
        "no duplicate projected identity in Org legacy negative keys"
    );
    // EA13 a pre-cohort legacy raw INSERT could attach this foreign RETIRED
    // identity beneath another Org. Seed that historical contradiction through
    // a DB fixture, never through a permitted current writer. Positive original
    // ownership must fail closed; do not guess lineage or erase foreign facts.
    let ambiguous = OrgId("ambiguous-root".into());
    OrgRepository::upsert(store, org("ambiguous-root")).unwrap();
    let parent = serde_json::to_string(&ScopeRef::Org {
        org_id: ambiguous.clone(),
    })
    .unwrap();
    store.backend().execute(&format!("INSERT INTO {prefix}_resource_edges (resource_type,resource_id,parent) VALUES (?,?,?j)"),&[Some(kind.0.clone()),Some(resource.0.clone()),Some(parent)]).unwrap();
    let before = store.fence().unwrap();
    let audits = AuditSink::events(store).unwrap();
    let edges = ResourceModelRepository::list_edges(store).unwrap();
    assert!(
        store
            .erase_org_privacy_with_audit(&ambiguous, audit(&ambiguous))
            .is_err(),
        "EA13 conflicting positive owner refuses"
    );
    assert_eq!(
        OrgRepository::get(store, &ambiguous).unwrap(),
        Some(org("ambiguous-root")),
        "EA13 no invented terminal identity"
    );
    assert_eq!(
        ResourceModelRepository::list_edges(store).unwrap(),
        edges,
        "EA13 no foreign payload removal"
    );
    assert_eq!(store.fence().unwrap(), before);
    assert_eq!(AuditSink::events(store).unwrap(), audits);
    // Remove only this test-injected impossible legacy edge; the canonical
    // original retirement row remains intact for the rest of the shared suite.
    store
        .backend()
        .execute(
            &format!("DELETE FROM {prefix}_resource_edges WHERE resource_type=? AND resource_id=?"),
            &[Some(kind.0), Some(resource.0)],
        )
        .unwrap();
}

fn ordered_writer_races<S>(authority: &S, peer: &S)
where
    S: OrgRepository
        + OrgPrivacyRepository
        + ResourceModelRepository
        + GrantRepository
        + FenceStore
        + AuditSink
        + Sync,
{
    use awaken_iam_contract::{ResourceId, ResourceType, WorkspaceId, WorkspaceOrgEdge};
    use std::sync::mpsc;
    use std::time::Duration;
    // EA04/05/11 decision table uses actual owners/connections, no sleeps:
    // R1 candidate reads live membership, erasure commits, candidate resumes ->
    // refusal and whole audit/version unchanged. R2 writer+grant commits first,
    // erasure then reads its closure -> both new payload rows removed. The same
    // fixture runs on the original memory mutex and TWO native SQL connections.
    for erase_first in [true, false] {
        let name = if erase_first {
            "race-erase-first"
        } else {
            "race-writer-first"
        };
        let id = OrgId(name.into());
        let workspace = WorkspaceId(format!("{name}-workspace"));
        OrgRepository::upsert(authority, org(name)).unwrap();
        ResourceModelRepository::put_workspace_org(
            authority,
            WorkspaceOrgEdge {
                workspace_id: workspace.clone(),
                org_id: id.clone(),
            },
        )
        .unwrap();
        let (ready_tx, ready_rx) = mpsc::channel();
        let (release_tx, release_rx) = mpsc::channel();
        let mut expected_fence = None;
        let mut expected_audit = None;
        std::thread::scope(|scope| {
            let worker = scope.spawn(move || {
                let observed = ResourceModelRepository::workspace_org(peer, &workspace)
                    .unwrap()
                    .unwrap();
                let candidate = ResourceEdge {
                    resource_type: ResourceType("legacy.race".into()),
                    resource_id: ResourceId(name.into()),
                    parent: ScopeRef::Workspace {
                        workspace_id: observed.workspace_id,
                    },
                };
                if erase_first {
                    ready_tx.send(()).unwrap();
                    release_rx.recv_timeout(Duration::from_secs(30)).unwrap();
                }
                let result = ResourceModelRepository::put_edge(peer, candidate);
                if !erase_first {
                    result.as_ref().unwrap();
                    GrantRepository::put(
                        peer,
                        Grant {
                            id: GrantId(format!("{name}-grant")),
                            subject: GrantSubject::Principal(PrincipalRef::Service {
                                service_id: "race-owner".into(),
                            }),
                            action_pattern: ActionPattern("legacy.read".into()),
                            scope: ScopeRef::Resource {
                                resource_type: ResourceType("legacy.race".into()),
                                resource_id: ResourceId(name.into()),
                            },
                            effect: Effect::Allow,
                        },
                    )
                    .unwrap();
                    ready_tx.send(()).unwrap();
                }
                result
            });
            ready_rx.recv_timeout(Duration::from_secs(30)).unwrap();
            authority
                .erase_org_privacy_with_audit(&id, audit(&id))
                .unwrap();
            if erase_first {
                expected_fence = Some(authority.fence().unwrap());
                expected_audit = Some(AuditSink::events(authority).unwrap());
                release_tx.send(()).unwrap();
            }
            let result = worker.join().unwrap();
            assert_eq!(
                result.is_err(),
                erase_first,
                "EA04/05 original lock chooses the legal order"
            );
        });
        assert!(
            !ResourceModelRepository::list_edges(authority)
                .unwrap()
                .iter()
                .any(|edge| edge.resource_id.0 == name),
            "EA04/05 no orphaned accepted candidate"
        );
        assert!(
            GrantRepository::get(authority, &GrantId(format!("{name}-grant")))
                .unwrap()
                .is_none(),
            "EA04 writer-first grant included in closure"
        );
        if let Some(fence) = expected_fence {
            assert_eq!(
                authority.fence().unwrap(),
                fence,
                "EA05 refusal leaves policy unchanged"
            );
        }
        if let Some(audits) = expected_audit {
            assert_eq!(
                AuditSink::events(authority).unwrap(),
                audits,
                "EA05 refusal leaves audit unchanged"
            );
        }
    }
}

fn seed_directory_closure<B: SqlConn + Clone>(
    store: &SqlStore<B>,
    id: &OrgId,
) -> (
    awaken_iam_core::DirectoryNode,
    awaken_iam_contract::ProductSpacePlacement,
    Timestamp,
    PrincipalRef,
) {
    use awaken_iam_contract::{
        DirectoryNodeId, ProductId, ProductSpacePlacement, ProductSpacePlacementStatus,
        ProductSpaceRef,
    };
    use awaken_iam_core::{DirectoryNode, DirectoryRepository};
    let id = id.clone();
    OrgRepository::upsert(store, org(&id.0)).unwrap();
    let at = Timestamp("2026-10-30T02:00:00Z".into());
    let node = DirectoryNode {
        id: DirectoryNodeId("erasure-node".into()),
        org_id: id.clone(),
        parent_id: None,
        name: "Private node".into(),
        slug: "private-node".into(),
        description: None,
        archived: false,
        created_at: at.clone(),
        updated_at: at.clone(),
    };
    let placement = ProductSpacePlacement {
        product_space: ProductSpaceRef {
            product_id: ProductId::new("agents").unwrap(),
            space_id: "private-space".into(),
        },
        org_id: id.clone(),
        node_id: node.id.clone(),
        status: ProductSpacePlacementStatus::Active,
    };
    let actor = PrincipalRef::Service {
        service_id: "directory-erasure-test".into(),
    };
    DirectoryRepository::create_directory_node(
        store,
        node.clone(),
        Some(placement.clone()),
        &actor,
    )
    .unwrap();
    (node, placement, at, actor)
}

fn directory_cases<B: SqlConn + Clone>(store: &SqlStore<B>) {
    use awaken_iam_contract::ProductSpacePlacementStatus;
    use awaken_iam_core::DirectoryRepository;
    let id = OrgId("directory-erasure".into());
    let (node, placement, at, actor) = seed_directory_closure(store, &id);
    // EA09 actual Directory owner: capture candidates before erase; terminal
    // create/restore/activate/update/move cannot recreate an empty Org fence or
    // a node/placement. Independent Directory revision retains its own law.
    store.erase_org_privacy_with_audit(&id, audit(&id)).unwrap();
    let before = store.fence().unwrap();
    let audits = AuditSink::events(store).unwrap();
    let directory_revision = DirectoryRepository::directory_revision(store, &id).unwrap();
    assert!(
        DirectoryRepository::create_directory_node(
            store,
            node.clone(),
            Some(placement.clone()),
            &actor
        )
        .is_err()
    );
    assert!(DirectoryRepository::restore_directory_node(store, &node.id, &at, &actor).is_err());
    assert!(DirectoryRepository::archive_directory_node(store, &node.id, &at, &actor).is_err());
    assert!(DirectoryRepository::move_directory_node(store, &node.id, None, &at, &actor).is_err());
    assert!(
        DirectoryRepository::update_directory_node(
            store, &node.id, "late", "late", None, &at, &actor
        )
        .is_err()
    );
    assert!(
        DirectoryRepository::set_product_space_placement_status(
            store,
            &id,
            &placement.product_space,
            ProductSpacePlacementStatus::Active,
            &at,
            &actor
        )
        .is_err()
    );
    assert!(
        DirectoryRepository::directory_node(store, &node.id)
            .unwrap()
            .is_none()
    );
    assert!(
        DirectoryRepository::product_space_placement(store, &id, &placement.product_space)
            .unwrap()
            .is_none()
    );
    assert_eq!(
        DirectoryRepository::directory_revision(store, &id).unwrap(),
        directory_revision,
        "EA09 no fence reset/advance"
    );
    assert_eq!(store.fence().unwrap(), before, "EA09 no policy effect");
    assert_eq!(
        AuditSink::events(store).unwrap(),
        audits,
        "EA09 no audit effect"
    );
}

// Logical rows of the SAME migrated schema affected by privacy, plus retained
// provenance/foreign facts. Every column is cast by the existing portable SQL
// dialect; this observer neither mutates nor grants business receipt authority.
fn privacy_rows<B: SqlConn>(store: &SqlStore<B>, prefix: &str) -> Vec<(&'static str, Vec<SqlRow>)> {
    [
        ("orgs", "id,display_name,owner,created_at,updated_at,erasure_version,erasure_confirmed,erased_scope,erased_groups"),
        ("groups", "id,org_id,display_name,members,created_at,updated_at"),
        ("grants", "id,subject,action_pattern,scope,effect"),
        ("role_bindings", "principal,role,scope"),
        ("workspace_org_edges", "workspace_id,org_id"),
        ("resource_edges", "resource_type,resource_id,parent"),
        ("api_tokens", "id,prefix,principal,secret_hash,workspace,created_at,expires_at,revoked_at,owner"),
        ("invitations", "id,idempotency_key,org_id,email,bindings,invited_by,token_hash,status,expires_at,created_at,updated_at,accepted_by_account_id"),
        ("directory_nodes", "id,org_id,parent_id,name,slug,description,archived,created_at,updated_at"),
        ("product_space_bindings", "product,space_id,org_id,node_id,status"),
        ("directory_fence", "org_id,revision"),
        ("resource_projection_streams", "product_id,org_id,projection_id,idempotency_key,epoch,payload_digest,version,grant_ids,edge_keys"),
        ("resource_projection_keys", "product_id,org_id,idempotency_key,projection_id,epoch,payload_digest,version"),
        ("resource_projection_grant_owners", "grant_id,product_id,org_id,projection_id"),
        ("resource_projection_edge_owners", "resource_type,resource_id,product_id,org_id,projection_id"),
        ("resource_projection_tombstones", "resource_type,resource_id,product_id,org_id,projection_id,epoch"),
        ("resource_provisions", "idempotency_key,epoch,fingerprint,version,applied_at"),
        ("resource_epochs", "resource_type,resource_id,epoch"),
        ("product_resource_types", "product_id,resource_type,parent_type,actions"),
        ("product_actions", "product_id,action_key"),
        ("fence", "id,version,epoch,updated_at"),
        ("audit_events", "seq,at,actor,action,detail"),
    ].into_iter().map(|(table, columns)| {
        let columns = columns.split(',').collect::<Vec<_>>();
        let selected = columns.iter().map(|column| format!("CAST({column} AS TEXT)")).collect::<Vec<_>>().join(",");
        let order = (1..=columns.len()).map(|index| index.to_string()).collect::<Vec<_>>().join(",");
        let rows = store.backend().query(&format!("SELECT {selected} FROM {prefix}_{table} ORDER BY {order}"), &[]).unwrap();
        (table,rows)
    }).collect()
}

fn commit_fault_cases<B: SqlConn + Clone>(store: &SqlStore<B>, prefix: &str) {
    use awaken_iam_core::DirectoryRepository;
    // Cause/effect graph: C1 complete original Org/raw/projection/Directory
    // closure; C2 fault after cleanup+terminal+audit but before final policy
    // publication; C3 actual native COMMIT succeeds but its caller reply is lost;
    // C4 exact retry after unrelated global policy progress.
    // P9=C1+C2 -> Backend Err/no receipt and WHOLE logical rows unchanged,
    // including payload, terminal, independent Directory fence, audit/version.
    // P10=C1+C3 -> first caller Err/no receipt, yet original cleanup+terminal+
    // audit/version committed once; P11=C4 -> original erasure/current observed
    // coordinate, no new effect. Constraint: post-COMMIT loss is protocol fault
    // injection AFTER the real inner commit, NOT a real network fault or fake
    // transaction/receipt. Original P8 and T1-T3 remain independent coverage.
    let (owner, resource) = seed_owned_closure(store);
    let id = OrgId("org-a".into());
    seed_invitation(
        store,
        &owner,
        &ScopeRef::Workspace {
            workspace_id: WorkspaceId("ws-a".into()),
        },
    );
    seed_raw_provision(store, &resource);
    seed_projected_closure(store, &id);
    let (node, placement, _, _) = seed_directory_closure(store, &id);
    let foreign_org = OrgRepository::get(store, &OrgId("org-b".into())).unwrap();
    let foreign_token = ApiTokenRepository::get(store, &ApiTokenId("token-b".into())).unwrap();
    let before = privacy_rows(store, prefix);
    let before_fence = store.fence().unwrap();
    let audits = AuditSink::events(store).unwrap();
    let failing = SqlStore::with_prefix(
        FailPrivacy::new(store.backend().clone(), PrivacyFault::FinalFenceWrite),
        prefix,
    )
    .unwrap();
    assert!(
        matches!(
            failing.erase_org_privacy_with_audit(&id, audit(&id)),
            Err(RepositoryError::Backend(_))
        ),
        "P9 no receipt"
    );
    assert!(
        failing.backend().fired.load(Ordering::SeqCst),
        "P9 reached FINAL fence after actual audit write"
    );
    assert_eq!(
        privacy_rows(store, prefix),
        before,
        "P9 whole closure/terminal/Directory/provenance/audit/version rollback"
    );
    assert_eq!(
        store.fence().unwrap(),
        before_fence,
        "P9 no policy publication"
    );
    assert_eq!(AuditSink::events(store).unwrap(), audits, "P9 no audit");

    let lost_reply = SqlStore::with_prefix(
        FailPrivacy::new(store.backend().clone(), PrivacyFault::CommitReply),
        prefix,
    )
    .unwrap();
    assert!(
        matches!(
            lost_reply.erase_org_privacy_with_audit(&id, audit(&id)),
            Err(RepositoryError::Backend(_))
        ),
        "P10 caller received no receipt"
    );
    assert!(
        lost_reply.backend().fired.load(Ordering::SeqCst),
        "P10 failure was AFTER actual native commit"
    );
    let committed_version = before_fence.version + 1;
    assert_eq!(
        store.fence().unwrap().version,
        committed_version,
        "P10 one original publication"
    );
    assert_eq!(
        AuditSink::events(store).unwrap().len(),
        audits.len() + 1,
        "P10 one original audit"
    );
    let terminal = store.backend().query(&format!("SELECT CAST(erasure_version AS TEXT),CAST(erasure_confirmed AS TEXT),display_name,CAST(owner AS TEXT),created_at,updated_at FROM {prefix}_orgs WHERE id=?"),&[Some(id.0.clone())]).unwrap();
    assert_eq!(
        terminal,
        vec![vec![
            Some(committed_version.to_string()),
            Some("1".into()),
            None,
            None,
            None,
            None
        ]],
        "P10 original confirmed material-free terminal already stored before retry"
    );
    assert_owned_closure_erased(store);
    assert!(
        InvitationRepository::list_invitations_for_org(store, &id)
            .unwrap()
            .is_empty(),
        "P10 invitation payload gone"
    );
    assert!(
        DirectoryRepository::directory_node(store, &node.id)
            .unwrap()
            .is_none(),
        "P10 Directory payload gone"
    );
    assert!(
        DirectoryRepository::product_space_placement(store, &id, &placement.product_space)
            .unwrap()
            .is_none(),
        "P10 placement payload gone"
    );
    let streams = store.backend().query(&format!("SELECT CAST(grant_ids AS TEXT),CAST(edge_keys AS TEXT) FROM {prefix}_resource_projection_streams WHERE org_id=?"),&[Some(id.0.clone())]).unwrap();
    assert_eq!(
        streams,
        vec![vec![Some("[]".into()), Some("[]".into())]],
        "P10 original stream payload lists redacted"
    );
    assert_eq!(
        OrgRepository::get(store, &OrgId("org-b".into())).unwrap(),
        foreign_org,
        "P10 whole foreign Org unchanged"
    );
    assert_eq!(
        ApiTokenRepository::get(store, &ApiTokenId("token-b".into())).unwrap(),
        foreign_token,
        "P10 whole foreign token unchanged"
    );
    let after = privacy_rows(store, prefix);
    for retained in [
        "resource_projection_keys",
        "resource_projection_grant_owners",
        "resource_projection_edge_owners",
        "resource_projection_tombstones",
        "resource_provisions",
        "resource_epochs",
        "product_resource_types",
        "product_actions",
    ] {
        assert_eq!(
            after.iter().find(|(name, _)| *name == retained),
            before.iter().find(|(name, _)| *name == retained),
            "P10 original provenance/catalog stays canonical: {retained}"
        );
    }
    let current_version = store.advance_version().unwrap();
    let before_replay = privacy_rows(store, prefix);
    for _ in 0..2 {
        let receipt = lost_reply
            .erase_org_privacy_with_audit(&id, audit(&id))
            .unwrap();
        assert_eq!(receipt.org_id, id, "P11 exact original subject");
        assert!(
            receipt.confirmed_organization && !receipt.changed && !receipt.admission_changed,
            "P11 replay, no new admission/payload effect"
        );
        assert_eq!(
            (receipt.erasure_version, receipt.observed_policy_version),
            (committed_version, current_version),
            "P11 original erasure/current observed policy"
        );
        assert_eq!(
            privacy_rows(store, prefix),
            before_replay,
            "P11 whole state stutter, no repeated cleanup/audit/publication"
        );
    }
}

fn raw_epoch_fences_share_one_native_write<B: SqlConn + Clone>(store: &SqlStore<B>, prefix: &str) {
    use awaken_iam_contract::{ResourceId, ResourceParentEdge, ResourceRetirement, ResourceType};
    // Cause/effect graph: E1 valid live Org + unprojected resource; E2 create
    // versus retire; E3 proposed epoch below/equal/above the stored head.
    // RE1 absent + create(2) -> insert; RE2/3 both kinds + <=head -> conflict
    // and WHOLE22table stutter; RE4 create(3) -> update exactly once;
    // RE5 retire(4) -> remove edge and advance SAME epoch; RE6 repeated stale
    // retirement -> conflict/stutter. SQLite and configured PostgreSQL run the
    // same original production transaction. This catches target/excluded SQL
    // ambiguity on both paths; it does not infer success from a SQL string.
    let id = OrgId("epoch-owner".into());
    OrgRepository::upsert(store, org(&id.0)).unwrap();
    let edge = ResourceParentEdge {
        resource_type: ResourceType("epoch.resource".into()),
        resource_id: ResourceId("epoch-child".into()),
        parent: ScopeRef::Org { org_id: id.clone() },
    };
    let provision = |epoch, retire, key: &str| ResourceProvision {
        product_id: awaken_iam_contract::ProductId::new("epoch-tests").unwrap(),
        org_id: id.clone(),
        idempotency_key: key.into(),
        epoch,
        grants: vec![],
        scope_edges: if retire { vec![] } else { vec![edge.clone()] },
        retirements: if retire {
            vec![ResourceRetirement {
                resource_type: edge.resource_type.clone(),
                resource_id: edge.resource_id.clone(),
                grant_ids: vec![],
            }]
        } else {
            vec![]
        },
    };
    let before = store.fence().unwrap().version;
    store
        .provision_resource(
            &provision(2, false, "epoch-create"),
            "epoch-create",
            audit(&id),
        )
        .unwrap();
    assert_eq!(store.fence().unwrap().version, before + 1, "RE1");
    for (head, kinds) in [(2, vec![false, true]), (4, vec![true])] {
        for retire in kinds {
            for epoch in [head - 1, head] {
                let key = format!("epoch-reject-{head}-{retire}-{epoch}");
                let before = privacy_rows(store, prefix);
                assert!(
                    matches!(
                        store.provision_resource(&provision(epoch, retire, &key), &key, audit(&id)),
                        Err(RepositoryError::Conflict(_))
                    ),
                    "RE2/3/6 head={head} retire={retire} epoch={epoch}"
                );
                assert_eq!(
                    privacy_rows(store, prefix),
                    before,
                    "RE2/3/6 no row/audit/version/receipt effect"
                );
            }
        }
        if head == 2 {
            for (epoch, retire) in [(3, false), (4, true)] {
                let key = format!("epoch-advance-{epoch}");
                let before = store.fence().unwrap().version;
                store
                    .provision_resource(&provision(epoch, retire, &key), &key, audit(&id))
                    .unwrap();
                assert_eq!(store.fence().unwrap().version, before + 1, "RE4/5");
                let rows = store.backend().query(&format!("SELECT CAST(epoch AS TEXT) FROM {prefix}_resource_epochs WHERE resource_type=? AND resource_id=?"), &[Some(edge.resource_type.0.clone()), Some(edge.resource_id.0.clone())]).unwrap();
                assert_eq!(
                    rows,
                    vec![vec![Some(epoch.to_string())]],
                    "RE4/5 same epoch owner"
                );
            }
            assert!(
                !ResourceModelRepository::list_edges(store)
                    .unwrap()
                    .iter()
                    .any(|current| current.resource_type == edge.resource_type
                        && current.resource_id == edge.resource_id),
                "RE5 edge removed"
            );
        }
    }
    // RE7 out-of-range positive input (first impossible and u64::MAX), with
    // and without an epoch-head write -> Backend error before ANY SQL effect;
    // receipt-only input is covered too. This is the native BIGINT storage
    // boundary, not a new limit on the independent in-memory domain model.
    for epoch in [i64::MAX as u64 + 1, u64::MAX] {
        for empty in [false, true] {
            let key = format!("epoch-overflow-{epoch}-{empty}");
            let mut invalid = provision(epoch, false, &key);
            if empty {
                invalid.scope_edges.clear();
            }
            let before = privacy_rows(store, prefix);
            assert!(
                matches!(store.provision_resource(&invalid, &key, audit(&id)), Err(RepositoryError::Backend(message)) if message == "resource epoch exceeds the native storage integer range"),
                "RE7"
            );
            assert_eq!(
                privacy_rows(store, prefix),
                before,
                "RE7 no clamp, receipt, audit or policy effect"
            );
        }
    }
    // RE8 the LAST representable epoch must preserve exact bytes in BOTH head
    // and receipt, then exact replay stutters. This detects silent SQLite
    // saturation as well as PostgreSQL's text-to-BIGINT parameter mismatch.
    let mut maximum = provision(i64::MAX as u64, false, "epoch-maximum");
    maximum.scope_edges[0].resource_id = ResourceId("epoch-max-child".into());
    let receipt = store
        .provision_resource(&maximum, "epoch-maximum", audit(&id))
        .unwrap();
    assert_eq!(receipt.epoch, i64::MAX as u64, "RE8 returned exact");
    let head = store.backend().query(&format!("SELECT CAST(epoch AS TEXT) FROM {prefix}_resource_epochs WHERE resource_type=? AND resource_id=?"), &[Some(edge.resource_type.0.clone()), Some("epoch-max-child".into())]).unwrap();
    assert_eq!(
        head,
        vec![vec![Some(i64::MAX.to_string())]],
        "RE8 persisted exact"
    );
    let before = privacy_rows(store, prefix);
    let replay = store
        .provision_resource(&maximum, "epoch-maximum", audit(&id))
        .unwrap();
    assert_eq!(
        (replay.epoch, replay.version),
        (receipt.epoch, receipt.version),
        "RE8 exact receipt"
    );
    assert_eq!(
        privacy_rows(store, prefix),
        before,
        "RE8 replay whole state stutter"
    );
    // Reuse the original erasure owner to leave no live fixture edge for the
    // subsequent shared native closure tests; original epoch provenance stays.
    assert!(store.erase_org_privacy(&id).unwrap());
}

fn sql_cases<B: SqlConn + Clone>(store: &SqlStore<B>, prefix: &str) {
    raw_epoch_fences_share_one_native_write(store, prefix);
    receipt_cases(store);
    projection_cases(store, prefix);
    retired_projection_owner_cases(store, prefix);
    closure_and_late_writer_cases(store);
    directory_cases(store);
    // P0 SQL CHECK uses explicit non-null alternatives: SQL UNKNOWN is not
    // enough to reject a partial terminal row. Both native backends refuse it.
    assert!(
        store
            .backend()
            .execute(
                &format!("INSERT INTO {prefix}_orgs (id) VALUES (?)"),
                &[Some("partial-terminal".into())]
            )
            .is_err(),
        "P0 partial identity row refused"
    );
    // P0b a structurally present row is not silently promoted past the original
    // canonical Org decoder. Invalid legacy domain payload is a read error,
    // not Never or confirmed erasure; all participant facts remain unchanged.
    let invalid_id = OrgId("invalid-owner-fixture".into());
    store
        .backend()
        .execute(
            &format!(
                "INSERT INTO {prefix}_orgs (id,owner,created_at,updated_at) VALUES (?,?j,?,?)"
            ),
            &[
                Some(invalid_id.0.clone()),
                Some("null".into()),
                Some("2026-10-30T00:00:00Z".into()),
                Some("2026-10-30T00:00:00Z".into()),
            ],
        )
        .unwrap();
    let invalid_fence = store.fence().unwrap();
    let invalid_audit = AuditSink::events(store).unwrap();
    assert!(
        store
            .erase_org_privacy_with_audit(&invalid_id, audit(&invalid_id))
            .is_err(),
        "P0b canonical read error cannot certify"
    );
    assert_eq!(store.fence().unwrap(), invalid_fence);
    assert_eq!(AuditSink::events(store).unwrap(), invalid_audit);
    store
        .backend()
        .execute(
            &format!("DELETE FROM {prefix}_orgs WHERE id=?"),
            &[Some(invalid_id.0)],
        )
        .unwrap();
    // P8 actual native transaction: cleanup/terminal writes succeeded, then
    // original AuditEvent write fails -> ALL roll back, no terminal receipt or
    // global publication escapes. This wrapper injects only failure, not policy.
    OrgRepository::upsert(store, org("rollback")).unwrap();
    let before = store.fence().unwrap();
    let audits = AuditSink::events(store).unwrap();
    let failing = SqlStore::with_prefix(
        FailPrivacy::new(store.backend().clone(), PrivacyFault::AuditWrite),
        prefix,
    )
    .unwrap();
    let id = OrgId("rollback".into());
    assert!(
        failing
            .erase_org_privacy_with_audit(&id, audit(&id))
            .is_err(),
        "P8"
    );
    assert_eq!(
        OrgRepository::get(store, &id).unwrap(),
        Some(org("rollback")),
        "P8 whole Org restored"
    );
    assert_eq!(store.fence().unwrap(), before, "P8 no publication");
    assert_eq!(
        AuditSink::events(store).unwrap(),
        audits,
        "P8 no extra audit"
    );
    let receipt = store.erase_org_privacy_with_audit(&id, audit(&id)).unwrap();
    assert!(
        receipt.confirmed_organization && receipt.admission_changed,
        "P8 retry remains live"
    );
    let rows = store.backend().query(&format!("SELECT display_name,CAST(owner AS TEXT),created_at,updated_at FROM {prefix}_orgs WHERE id=?"), &[Some(id.0)]).unwrap();
    assert_eq!(
        rows,
        vec![vec![None, None, None, None]],
        "P1/P8 original row retains no Org payload"
    );
}
#[test]
fn memory_terminal_receipts_preserve_exact_publication_laws() {
    let store = InMemoryStore::new();
    receipt_cases(&store);
    ordered_writer_races(&store, &store.clone());
}
#[test]
fn sqlite_terminal_receipts_and_audit_failure_are_atomic() {
    sql_cases(&super::sqlite::in_memory_store("iam").unwrap(), "iam");
}
#[test]
fn sqlite_two_connections_serialize_erasure_and_captured_writer_candidates() {
    struct OwnedDatabaseFile(std::path::PathBuf);
    impl Drop for OwnedDatabaseFile {
        fn drop(&mut self) {
            let _ = std::fs::remove_file(&self.0);
        }
    }
    let path = std::env::temp_dir().join(format!(
        "awaken-iam-erasure-{}-{}.sqlite",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    let owned_file = OwnedDatabaseFile(path.clone());
    let authority =
        super::sqlite::migrated_store(super::SqliteBackend::open_path(&path).unwrap(), "iam")
            .unwrap();
    let peer =
        super::sqlite::migrated_store(super::SqliteBackend::open_path(&path).unwrap(), "iam")
            .unwrap();
    ordered_writer_races(&authority, &peer);
    drop(peer);
    drop(authority);
    drop(owned_file);
}

#[test]
fn postgres_terminal_receipts_and_audit_failure_are_atomic_when_configured() {
    let Ok(url) = std::env::var("IAM_TEST_POSTGRES_URL") else {
        return;
    };
    // Original migration owner creates the inventory under a distinct validated
    // prefix; the SAME helper and native rollback cases run for both backends.
    let prefix = format!(
        "pv_{:x}_{:x}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    );
    let store = super::postgres::migrated_store(&url, &prefix).unwrap();
    sql_cases(&store, &prefix);
    let peer = super::postgres::migrated_store(&url, &prefix).unwrap();
    ordered_writer_races(&store, &peer);
}

#[test]
fn sqlite_final_fence_failure_and_post_commit_reply_loss_preserve_privacy() {
    // P9-P11 use the original migrated native SQLite factory and same shared
    // fault/closure helper as configured Postgres, with no alternate authority.
    commit_fault_cases(&super::sqlite::in_memory_store("iam").unwrap(), "iam");
}

#[test]
fn postgres_final_fence_failure_and_post_commit_reply_loss_when_configured() {
    let Ok(url) = std::env::var("IAM_TEST_POSTGRES_URL") else {
        return;
    };
    // This optional source fixture is UNVERIFIED unless the original native
    // qualification supplies a controlled URL and executes every P9-P11 row.
    let prefix = format!(
        "p8_{:x}_{:x}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    );
    let store = super::postgres::migrated_store(&url, &prefix).unwrap();
    commit_fault_cases(&store, &prefix);
}
