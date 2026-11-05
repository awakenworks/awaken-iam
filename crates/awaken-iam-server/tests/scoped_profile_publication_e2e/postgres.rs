//! PostgreSQL evidence uses independent native connections, not shared locks.
use super::*;
use awaken_iam_server::postgres_migrated_store;

fn database() -> Option<(String, String)> {
    let url = std::env::var("IAM_TEST_POSTGRES_URL").ok()?;
    let prefix = format!(
        "spg_{:x}",
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    );
    Some((url, prefix))
}

#[test]
fn postgres_exact_runtime_reference_is_current_across_native_connections() {
    use awaken_iam_contract::{ScopeRef, WorkspaceId};
    use awaken_iam_core::{RoleBinding, RoleBindingRepository, RoleId};

    let Some((url, prefix)) = database() else {
        return;
    };
    let first = postgres_migrated_store(&url, &prefix).unwrap();
    let second = postgres_migrated_store(&url, &prefix).unwrap();
    let binding = RoleBinding {
        principal: PrincipalRef::Service {
            service_id: "shared-runtime-controller".into(),
        },
        role: RoleId("tenant.pg:controller".into()),
        scope: ScopeRef::Workspace {
            workspace_id: WorkspaceId("workspace-a".into()),
        },
    };
    RoleBindingRepository::add(&first, binding.clone()).unwrap();
    assert!(first.contains_exact(&binding).unwrap());
    assert!(second.contains_exact(&binding).unwrap());
    let mut foreign = binding.clone();
    foreign.scope = ScopeRef::Workspace {
        workspace_id: WorkspaceId("workspace-b".into()),
    };
    assert!(!second.contains_exact(&foreign).unwrap());
    foreign = binding.clone();
    foreign.role = RoleId("tenant.pg:other-role".into());
    assert!(!second.contains_exact(&foreign).unwrap());
    foreign = binding.clone();
    foreign.principal = publisher();
    assert!(!second.contains_exact(&foreign).unwrap());
    RoleBindingRepository::remove(&second, &binding).unwrap();
    assert!(!first.contains_exact(&binding).unwrap());
    assert!(!second.contains_exact(&binding).unwrap());
}

#[test]
fn postgres_original_intent_and_erasure_use_native_transactions() {
    let Some((url, prefix)) = database() else {
        return;
    };
    let store = postgres_migrated_store(&url, &prefix).unwrap();
    history(Arc::new(store.clone()));
    erased_organization_admission(store);
}

#[test]
fn postgres_replica_preparation_and_activation_keep_one_original_and_one_cas_winner() {
    let Some((url, prefix)) = database() else {
        return;
    };
    let first = postgres_migrated_store(&url, &prefix).unwrap();
    let second = postgres_migrated_store(&url, &prefix).unwrap();
    let barrier = Arc::new(Barrier::new(2));
    let threads = [first.clone(), second.clone()]
        .into_iter()
        .map(|store| {
            let barrier = barrier.clone();
            std::thread::spawn(move || {
                let admin = AuthorizationProfileAdmin::new(Arc::new(store));
                barrier.wait();
                admin
                    .prepare_scoped_publication(
                        request("tenant.pg", "workspace-a", "original", None),
                        publisher(),
                    )
                    .unwrap()
            })
        })
        .collect::<Vec<_>>();
    let prepared = threads
        .into_iter()
        .map(|thread| thread.join().unwrap())
        .collect::<Vec<_>>();
    assert_eq!(prepared[0], prepared[1]);
    let namespace = NamespaceId("tenant.pg".into());
    assert_eq!(first.list_profiles(&namespace).unwrap().len(), 1);
    let competitor = AuthorizationProfileAdmin::new(Arc::new(first.clone()))
        .prepare_scoped_publication(
            request("tenant.pg", "workspace-a", "competitor", None),
            publisher(),
        )
        .unwrap();
    let barrier = Arc::new(Barrier::new(2));
    let threads = [(first.clone(), "original"), (second.clone(), "competitor")]
        .into_iter()
        .map(|(store, key)| {
            let barrier = barrier.clone();
            let namespace = namespace.clone();
            std::thread::spawn(move || {
                let admin = AuthorizationProfileAdmin::new(Arc::new(store));
                barrier.wait();
                admin.activate_scoped_publication(
                    &mut AuthzApi::new(),
                    &PolicySnapshot::default(),
                    &namespace,
                    key,
                )
            })
        })
        .collect::<Vec<_>>();
    let results = threads
        .into_iter()
        .map(|thread| thread.join().unwrap())
        .collect::<Vec<_>>();
    assert_eq!(results.iter().filter(|result| result.is_ok()).count(), 1);
    let active = second.active_profile(&namespace).unwrap().unwrap();
    assert!([prepared[0].revision, competitor.revision].contains(&active.revision));
    let reopened = postgres_migrated_store(&url, &prefix).unwrap();
    assert_eq!(
        reopened.active_profile(&namespace).unwrap().unwrap(),
        active
    );
    assert_eq!(
        AuthorizationProfileAdmin::new(Arc::new(reopened))
            .prepare_scoped_publication(
                request("tenant.pg", "workspace-a", "original", None),
                publisher()
            )
            .unwrap(),
        prepared[0]
    );
}
