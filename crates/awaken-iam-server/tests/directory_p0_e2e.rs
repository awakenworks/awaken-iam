//! P0 acceptance for the organization-scoped Directory authority.

use std::sync::{Arc, Barrier};
use std::thread;

use awaken_iam_contract::{
    CreateDirectoryNode, EnsureProductSpacePlacement, MoveDirectoryNode, OrgId, PrincipalRef,
    ProductId, ProductSpaceRef, Timestamp,
};
use awaken_iam_core::{AuditSink, OrgRepository, Organization};
use awaken_iam_server::{DirectoryApi, DirectoryCommandContext, sqlite_in_memory_store};

fn at(second: u8) -> Timestamp {
    Timestamp(format!("2026-08-27T00:00:{second:02}Z"))
}

fn owner() -> PrincipalRef {
    PrincipalRef::Service {
        service_id: "directory-p0-test".into(),
    }
}

fn product(id: &str) -> ProductId {
    ProductId::new(id).unwrap()
}

fn space() -> ProductSpaceRef {
    ProductSpaceRef {
        product_id: product("agents"),
        space_id: "workspace/shared-id".into(),
    }
}

fn create_org(store: &impl OrgRepository, id: &str) {
    OrgRepository::upsert(
        store,
        Organization {
            id: OrgId(id.into()),
            display_name: Some(id.into()),
            owner: owner(),
            created_at: at(0),
            updated_at: at(0),
        },
    )
    .unwrap();
}

fn ensure(org_id: &str) -> EnsureProductSpacePlacement {
    EnsureProductSpacePlacement {
        product_space: space(),
        org_id: OrgId(org_id.into()),
        parent_product_space: None,
        name: "Shared workspace".into(),
        preferred_slug: "shared-workspace".into(),
        description: None,
    }
}

fn context(second: u8) -> DirectoryCommandContext {
    DirectoryCommandContext::product_service(product("agents"), "agents", at(second))
}

#[test]
fn organizations_own_independent_product_identity_and_revision() {
    // Cause-effect decision table:
    // R1 same product/space in different Orgs -> two placements and distinct
    // node ids; R2 mutate Org A only -> A revision advances and B stays fenced;
    // R3 read empty/non-empty children -> one atomic response carries the Org's
    // own revision. These rules prove Org is the Directory aggregate boundary.
    let store = sqlite_in_memory_store("directory_org_partition").unwrap();
    create_org(&store, "org-a");
    create_org(&store, "org-b");
    let directory = DirectoryApi::new(store);

    let a = directory
        .ensure_product_space_placement(ensure("org-a"), context(1))
        .unwrap();
    let b = directory
        .ensure_product_space_placement(ensure("org-b"), context(2))
        .unwrap();
    assert_eq!(a.revision, 2, "R1");
    assert_eq!(b.revision, 2, "R1");
    assert_ne!(a.node.id, b.node.id, "R1");

    directory
        .update_node(
            &a.node.id,
            awaken_iam_contract::UpdateDirectoryNode {
                name: "Org A workspace".into(),
                slug: "org-a-workspace".into(),
                description: None,
            },
            context(3),
        )
        .unwrap();
    assert_eq!(directory.revision(&OrgId("org-a".into())).unwrap(), 3, "R2");
    assert_eq!(directory.revision(&OrgId("org-b".into())).unwrap(), 2, "R2");

    let b_roots = directory.children(&OrgId("org-b".into()), None).unwrap();
    assert_eq!(b_roots.revision, 2, "R3");
    assert_eq!(b_roots.nodes, vec![b.node], "R3");
    assert!(
        directory
            .product_space_placement(&OrgId("org-b".into()), &space())
            .unwrap()
            .is_some(),
        "R1"
    );
}

#[test]
fn parent_resolution_is_org_scoped_and_requires_an_active_parent() {
    // Cause-effect decision table: R1=unknown parent in the same Org -> reject
    // without revision/audit effects; R2=parent exists only in another Org ->
    // reject identically, so node ids cannot cross the aggregate boundary;
    // R3=archived parent in the same Org -> reject without another revision.
    let store = sqlite_in_memory_store("directory_parent_scope").unwrap();
    create_org(&store, "org-a");
    create_org(&store, "org-b");
    let directory = DirectoryApi::new(store.clone());
    let parent_space = ProductSpaceRef {
        product_id: product("agents"),
        space_id: "workspace/parent".into(),
    };
    let parent = directory
        .ensure_product_space_placement(
            EnsureProductSpacePlacement {
                product_space: parent_space.clone(),
                org_id: OrgId("org-a".into()),
                parent_product_space: None,
                name: "Parent".into(),
                preferred_slug: "parent".into(),
                description: None,
            },
            context(1),
        )
        .unwrap();

    let child = |org_id: &str, parent_product_space: ProductSpaceRef| EnsureProductSpacePlacement {
        product_space: ProductSpaceRef {
            product_id: product("agents"),
            space_id: format!("workspace/child-{org_id}"),
        },
        org_id: OrgId(org_id.into()),
        parent_product_space: Some(parent_product_space),
        name: "Child".into(),
        preferred_slug: "child".into(),
        description: None,
    };
    let missing = ProductSpaceRef {
        product_id: product("agents"),
        space_id: "workspace/missing".into(),
    };
    assert!(
        directory
            .ensure_product_space_placement(child("org-a", missing), context(2))
            .is_err(),
        "R1"
    );
    assert_eq!(directory.revision(&OrgId("org-a".into())).unwrap(), 2, "R1");
    assert!(
        directory
            .ensure_product_space_placement(child("org-b", parent_space.clone()), context(3))
            .is_err(),
        "R2"
    );
    assert_eq!(directory.revision(&OrgId("org-b".into())).unwrap(), 1, "R2");

    directory.archive_node(&parent.node.id, context(4)).unwrap();
    assert!(
        directory
            .ensure_product_space_placement(child("org-a", parent_space), context(5))
            .is_err(),
        "R3"
    );
    assert_eq!(directory.revision(&OrgId("org-a".into())).unwrap(), 3, "R3");
    assert_eq!(
        AuditSink::events(&store)
            .unwrap()
            .iter()
            .filter(|event| event.action.starts_with("directory."))
            .count(),
        2,
        "only create and archive produce effects"
    );
}

#[test]
fn concurrent_exact_ensure_converges_on_one_placement() {
    // Cause-effect decision table: R1 eight callers start the same canonical
    // ensure concurrently -> exactly one create, seven idempotent replays, one
    // node/placement/audit effect and revision 2; R2 every returned result ->
    // the same node identity. The barrier exposes the unique-winner retry path.
    let store = sqlite_in_memory_store("directory_concurrent_ensure").unwrap();
    create_org(&store, "acme");
    let barrier = Arc::new(Barrier::new(8));
    let handles = (0..8)
        .map(|index| {
            let directory = DirectoryApi::new(store.clone());
            let barrier = barrier.clone();
            thread::spawn(move || {
                barrier.wait();
                directory
                    .ensure_product_space_placement(ensure("acme"), context(index as u8))
                    .unwrap()
            })
        })
        .collect::<Vec<_>>();
    let results = handles
        .into_iter()
        .map(|handle| handle.join().unwrap())
        .collect::<Vec<_>>();

    assert_eq!(
        results.iter().filter(|result| result.created).count(),
        1,
        "R1"
    );
    assert!(results.iter().all(|result| result.revision == 2), "R1");
    assert!(
        results
            .iter()
            .all(|result| result.node.id == results[0].node.id),
        "R2"
    );
    let roots = DirectoryApi::new(store.clone())
        .children(&OrgId("acme".into()), None)
        .unwrap();
    assert_eq!(roots.revision, 2, "R1");
    assert_eq!(roots.nodes.len(), 1, "R1");
    assert_eq!(
        AuditSink::events(&store)
            .unwrap()
            .iter()
            .filter(|event| event.action == "directory.node.create")
            .count(),
        1,
        "R1"
    );
}

#[test]
fn concurrent_inverse_moves_cannot_commit_a_cycle() {
    // Cause-effect decision table: R1=two roots exist, R2=A->B and B->A begin
    // together -> serialization permits exactly one move and rejects the move
    // that would close the cycle; R3=one successful mutation advances the Org
    // revision once and the persisted graph remains acyclic.
    let store = sqlite_in_memory_store("directory_concurrent_move").unwrap();
    create_org(&store, "acme");
    let directory = DirectoryApi::new(store.clone());
    let a = directory
        .create_node(
            CreateDirectoryNode {
                org_id: OrgId("acme".into()),
                parent_id: None,
                name: "A".into(),
                preferred_slug: "a".into(),
                description: None,
            },
            DirectoryCommandContext::service("test", at(1)),
        )
        .unwrap()
        .node;
    let b = directory
        .create_node(
            CreateDirectoryNode {
                org_id: OrgId("acme".into()),
                parent_id: None,
                name: "B".into(),
                preferred_slug: "b".into(),
                description: None,
            },
            DirectoryCommandContext::service("test", at(2)),
        )
        .unwrap()
        .node;
    let barrier = Arc::new(Barrier::new(2));
    let attempts = [(a.id.clone(), b.id.clone()), (b.id.clone(), a.id.clone())]
        .into_iter()
        .enumerate()
        .map(|(index, (node_id, parent_id))| {
            let directory = DirectoryApi::new(store.clone());
            let barrier = barrier.clone();
            thread::spawn(move || {
                barrier.wait();
                directory.move_node(
                    &node_id,
                    MoveDirectoryNode {
                        parent_id: Some(parent_id),
                    },
                    DirectoryCommandContext::service("test", at(index as u8 + 3)),
                )
            })
        })
        .collect::<Vec<_>>();
    let results = attempts
        .into_iter()
        .map(|attempt| attempt.join().unwrap())
        .collect::<Vec<_>>();
    assert_eq!(
        results.iter().filter(|result| result.is_ok()).count(),
        1,
        "R2"
    );
    assert_eq!(
        results.iter().filter(|result| result.is_err()).count(),
        1,
        "R2"
    );

    let stored_a = directory.node(&a.id).unwrap().unwrap();
    let stored_b = directory.node(&b.id).unwrap().unwrap();
    assert!(
        (stored_a.parent_id.as_ref() == Some(&b.id) && stored_b.parent_id.is_none())
            || (stored_b.parent_id.as_ref() == Some(&a.id) && stored_a.parent_id.is_none()),
        "R3"
    );
    assert_eq!(directory.revision(&OrgId("acme".into())).unwrap(), 4, "R3");
}
