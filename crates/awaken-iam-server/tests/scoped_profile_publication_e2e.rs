//! Native PAP/store recovery evidence. HTTP capability and product source
//! admission have separate tests; these cases do not claim deployed SaaS.
use awaken_iam_contract::*;
use awaken_iam_core::AuthorizationProfileRepository;
use awaken_iam_server::{
    AuthorizationProfileAdmin, AuthzApi, InMemoryStore, SqliteBackend, sqlite_in_memory_store,
    sqlite_migrated_store,
};
use std::sync::{Arc, Barrier};
#[path = "scoped_profile_publication_e2e/postgres.rs"]
mod postgres;

fn erased_organization_admission<S>(store: S)
where
    S: AuthorizationProfileRepository
        + awaken_iam_core::OrgRepository
        + awaken_iam_core::ResourceModelRepository
        + awaken_iam_core::OrgPrivacyRepository
        + Clone
        + 'static,
{
    use awaken_iam_core::{
        OrgPrivacyRepository, OrgRepository, Organization, ResourceModelRepository,
    };
    let org = OrgId("erased".into());
    OrgRepository::upsert(
        &store,
        Organization {
            id: org.clone(),
            display_name: None,
            owner: publisher(),
            created_at: Timestamp("2026-11-05T00:00:00Z".into()),
            updated_at: Timestamp("2026-11-05T00:00:00Z".into()),
        },
    )
    .unwrap();
    ResourceModelRepository::put_workspace_org(
        &store,
        WorkspaceOrgEdge {
            workspace_id: WorkspaceId("workspace-a".into()),
            org_id: org.clone(),
        },
    )
    .unwrap();
    let admin = AuthorizationProfileAdmin::new(Arc::new(store.clone()));
    let mut empty = request("tenant.empty", "workspace-a", "before-erasure", None);
    empty.profile.document = AuthorizationProfileDocument::default();
    admin
        .prepare_scoped_publication(empty, publisher())
        .unwrap();
    assert!(OrgPrivacyRepository::erase_org_privacy(&store, &org).unwrap());
    assert!(
        admin
            .activate_scoped_publication(
                &mut AuthzApi::new(),
                &PolicySnapshot::default(),
                &NamespaceId("tenant.empty".into()),
                "before-erasure"
            )
            .is_err(),
        "an empty prepared profile still belongs to its explicit erased Workspace"
    );
    assert!(
        admin
            .prepare_scoped_publication(
                request("tenant.new", "workspace-a", "late-write", None),
                publisher()
            )
            .is_err(),
        "a late publisher cannot insert a scoped draft after native Org erasure"
    );
}

#[test]
fn scoped_publication_reuses_native_erased_organization_admission() {
    erased_organization_admission(InMemoryStore::new());
    erased_organization_admission(sqlite_in_memory_store("iam_scoped_erased").unwrap());
}

fn publisher() -> PrincipalRef {
    PrincipalRef::Service {
        service_id: "tenant-publisher".into(),
    }
}
fn request(
    namespace: &str,
    workspace: &str,
    key: &str,
    head: Option<u64>,
) -> PrepareScopedAuthorizationProfile {
    let action = format!("{namespace}::invoice.read");
    let mut document = AuthorizationProfileDocument::default();
    document
        .resource_model
        .actions
        .push(ActionKey(action.clone()));
    document.action_scope_rules.push(ActionScopeRule {
        action_pattern: action.clone(),
        allowed_scope_kinds: vec![ScopeKind::Workspace],
    });
    document.grants.push(GrantSnapshot {
        id: format!("{namespace}:read"),
        subject: GrantSubjectRef::Principal {
            principal: publisher(),
        },
        action_pattern: action,
        scope: ScopeRef::Workspace {
            workspace_id: WorkspaceId(workspace.into()),
        },
        effect: GrantEffect::Allow,
    });
    PrepareScopedAuthorizationProfile {
        request_key: key.into(),
        workspace_id: WorkspaceId(workspace.into()),
        profile: CreateAuthorizationProfile {
            namespace: NamespaceId(namespace.into()),
            document,
            created_at: Timestamp("2026-11-05T00:00:00Z".into()),
        },
        expected_active_revision: head,
    }
}

fn history(repository: Arc<dyn AuthorizationProfileRepository>) {
    let admin = AuthorizationProfileAdmin::new(repository.clone());
    let base = PolicySnapshot::default();
    let mut authz = AuthzApi::new();
    let first = request("tenant.a", "workspace-a", "original", None);
    let baseline = admin
        .scoped_publication_baseline(&first.profile.namespace, &first.workspace_id)
        .unwrap();
    assert!(baseline.active.is_none());
    assert!(!baseline.has_published_revision);
    let original = admin
        .prepare_scoped_publication(first.clone(), publisher())
        .unwrap();
    assert_eq!(original.revision, 1);
    assert_eq!(
        admin
            .prepare_scoped_publication(first.clone(), publisher())
            .unwrap(),
        original
    );
    assert_eq!(
        repository
            .list_profiles(&first.profile.namespace)
            .unwrap()
            .len(),
        1
    );
    let mut different = first.clone();
    different.profile.document.grants[0].effect = GrantEffect::Deny;
    assert!(
        admin
            .prepare_scoped_publication(different, publisher())
            .is_err()
    );
    assert!(
        admin
            .prepare_scoped_publication(
                request("tenant.a", "workspace-b", "foreign", None),
                publisher()
            )
            .is_err()
    );
    assert_eq!(
        repository
            .list_profiles(&first.profile.namespace)
            .unwrap()
            .len(),
        1
    );

    let competitor = admin
        .prepare_scoped_publication(
            request("tenant.a", "workspace-a", "competitor", None),
            publisher(),
        )
        .unwrap();
    let active = admin
        .activate_scoped_publication(&mut authz, &base, &first.profile.namespace, "original")
        .unwrap();
    assert_eq!(active.status, ScopedAuthorizationProfileStatus::Active);
    assert_eq!(active.current_active_revision, Some(original.revision));
    assert!(
        admin
            .scoped_publication_baseline(
                &first.profile.namespace,
                &WorkspaceId("workspace-b".into())
            )
            .is_err()
    );
    assert!(
        admin
            .activate_scoped_publication(
                &mut authz,
                &base,
                &first.profile.namespace,
                &competitor.request_key
            )
            .is_err()
    );

    let mut replacement = request(
        "tenant.a",
        "workspace-a",
        "replacement",
        Some(original.revision),
    );
    replacement.profile.document.grants[0].effect = GrantEffect::Deny;
    let replacement = admin
        .prepare_scoped_publication(replacement, publisher())
        .unwrap();
    let current = admin
        .activate_scoped_publication(&mut authz, &base, &first.profile.namespace, "replacement")
        .unwrap();
    assert_eq!(current.current_active_revision, Some(replacement.revision));
    let recovered = admin
        .activate_scoped_publication(&mut authz, &base, &first.profile.namespace, "original")
        .unwrap();
    assert_eq!(
        recovered.status,
        ScopedAuthorizationProfileStatus::Superseded
    );
    assert_eq!(recovered.intent, original);
    assert_eq!(
        recovered.current_active_revision,
        Some(replacement.revision)
    );
    assert_eq!(
        admin
            .prepare_scoped_publication(first.clone(), publisher())
            .unwrap(),
        original
    );
    admin
        .retire(
            &mut authz,
            &base,
            &first.profile.namespace,
            replacement.revision,
        )
        .unwrap();
    let retired = admin
        .activate_scoped_publication(&mut authz, &base, &first.profile.namespace, "replacement")
        .unwrap();
    assert_eq!(retired.status, ScopedAuthorizationProfileStatus::Retired);
    assert_eq!(retired.current_active_revision, None);
    let baseline = admin
        .scoped_publication_baseline(&first.profile.namespace, &first.workspace_id)
        .unwrap();
    assert!(baseline.active.is_none());
    assert!(
        baseline.has_published_revision,
        "retirement is not initial absence"
    );
    assert!(
        admin
            .activate_scoped_publication(&mut authz, &base, &first.profile.namespace, "competitor")
            .is_err(),
        "an unactivated original draft cannot survive active-to-retired head ABA"
    );
    assert!(
        admin
            .prepare_scoped_publication(
                request("tenant.a", "workspace-a", "after-retirement", None),
                publisher()
            )
            .is_err(),
        "retired head is not initial publication"
    );
    assert_eq!(
        repository
            .list_profiles(&first.profile.namespace)
            .unwrap()
            .len(),
        3
    );
}

#[test]
fn original_intent_history_conforms_in_memory_and_sqlite() {
    history(Arc::new(InMemoryStore::new()));
    history(Arc::new(sqlite_in_memory_store("iam").unwrap()));
}

#[test]
fn concurrent_preparation_reserves_one_immutable_sql_revision() {
    let repository = Arc::new(sqlite_in_memory_store("iam").unwrap());
    let admin = Arc::new(AuthorizationProfileAdmin::new(repository.clone()));
    let barrier = Arc::new(Barrier::new(4));
    let threads = (0..4)
        .map(|_| {
            let admin = admin.clone();
            let barrier = barrier.clone();
            std::thread::spawn(move || {
                barrier.wait();
                admin
                    .prepare_scoped_publication(
                        request("tenant.a", "workspace-a", "same-intent", None),
                        publisher(),
                    )
                    .unwrap()
            })
        })
        .collect::<Vec<_>>();
    let receipts = threads
        .into_iter()
        .map(|thread| thread.join().unwrap())
        .collect::<Vec<_>>();
    assert!(receipts.iter().all(|receipt| receipt == &receipts[0]));
    assert_eq!(
        repository
            .list_profiles(&NamespaceId("tenant.a".into()))
            .unwrap()
            .len(),
        1
    );
}

#[test]
fn original_profile_and_scope_survive_database_reopen() {
    let directory = tempfile::tempdir().unwrap();
    let file = directory.path().join("iam.db");
    let candidate = request("tenant.a", "workspace-a", "persisted", None);
    let original = {
        let repository = Arc::new(
            sqlite_migrated_store(SqliteBackend::open_path(&file).unwrap(), "iam").unwrap(),
        );
        let admin = AuthorizationProfileAdmin::new(repository);
        let original = admin
            .prepare_scoped_publication(candidate.clone(), publisher())
            .unwrap();
        admin
            .activate_scoped_publication(
                &mut AuthzApi::new(),
                &PolicySnapshot::default(),
                &candidate.profile.namespace,
                "persisted",
            )
            .unwrap();
        original
    };
    let repository =
        Arc::new(sqlite_migrated_store(SqliteBackend::open_path(&file).unwrap(), "iam").unwrap());
    let admin = AuthorizationProfileAdmin::new(repository);
    assert_eq!(
        admin
            .prepare_scoped_publication(candidate.clone(), publisher())
            .unwrap(),
        original
    );
    assert_eq!(
        admin
            .scoped_publication_receipt(&candidate.profile.namespace, "persisted")
            .unwrap()
            .status,
        ScopedAuthorizationProfileStatus::Active
    );
    assert!(
        admin
            .prepare_scoped_publication(
                request(
                    "tenant.a",
                    "workspace-b",
                    "new-key",
                    Some(original.revision)
                ),
                publisher()
            )
            .is_err()
    );
}

#[test]
fn malformed_scope_and_namespace_do_not_create_any_intent() {
    let repository = Arc::new(sqlite_in_memory_store("iam").unwrap());
    let admin = AuthorizationProfileAdmin::new(repository.clone());
    let mut candidate = request("tenant.a", "workspace-a", "invalid", None);
    candidate.profile.document.grants[0].scope = ScopeRef::Global;
    assert!(
        admin
            .prepare_scoped_publication(candidate.clone(), publisher())
            .is_err()
    );
    candidate.profile.document.grants[0].scope = ScopeRef::Workspace {
        workspace_id: WorkspaceId("workspace-a".into()),
    };
    candidate.profile.document.grants[0].action_pattern = "iam::permission.manage".into();
    assert!(
        admin
            .prepare_scoped_publication(candidate.clone(), publisher())
            .is_err()
    );
    assert!(
        repository
            .list_profiles(&candidate.profile.namespace)
            .unwrap()
            .is_empty()
    );
    assert!(
        repository
            .profile_publication(&candidate.profile.namespace, "invalid")
            .unwrap()
            .is_none()
    );
}
