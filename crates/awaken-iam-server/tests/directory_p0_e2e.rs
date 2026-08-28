//! P0 acceptance for the organization-scoped Directory authority.

use std::sync::{Arc, Barrier};
use std::thread;

use awaken_iam_contract::{
    CreateDirectoryNode, EnsureProductSpacePlacement, MoveDirectoryNode, OrgId, PrincipalRef,
    ProductId, ProductSpacePlacementStatus, ProductSpaceRef, RetireProductSpacePlacement,
    Timestamp, UpdateDirectoryNode,
};
use awaken_iam_core::{AuditSink, OrgRepository, Organization};
use awaken_iam_server::{
    DirectoryApi, DirectoryCommandContext, PolicyAdminApi, sqlite_in_memory_store,
};

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

fn product_space(product_id: &str, kind: &str, id: &str) -> ProductSpaceRef {
    ProductSpaceRef {
        product_id: product(product_id),
        space_id: format!("{kind}/{id}"),
    }
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
fn agents_objects_and_workforce_share_placement_without_sharing_policy() {
    // Cause/effect decision table:
    // R1 three open product ids in one Org, each parented beneath another
    // product -> one arbitrary cross-product Directory tree; R2 move the middle
    // Objects node beneath a user folder -> only Directory parentage/revision
    // changes while every ProductSpaceRef binding stays stable; R3 all Directory
    // mutations -> IAM policy version remains unchanged. Constraints: Org is the
    // immutable partition, product ids are not an enum, and no product business
    // parent or permission edge is inferred from Directory parent_id.
    let store = sqlite_in_memory_store("directory_three_products").unwrap();
    create_org(&store, "acme");
    let directory = DirectoryApi::new(store.clone());
    let policy = PolicyAdminApi::new(store);
    let policy_version = policy.store_version().unwrap();

    let agents = product_space("agents", "workspace", "agent-ws");
    let objects = product_space("objects", "object-space", "customer-data");
    let workforce = product_space("workforce", "project", "delivery");
    let ensure = |space: ProductSpaceRef,
                  parent_product_space: Option<ProductSpaceRef>,
                  name: &str,
                  second: u8| {
        directory
            .ensure_product_space_placement(
                EnsureProductSpacePlacement {
                    product_space: space,
                    org_id: OrgId("acme".into()),
                    parent_product_space,
                    name: name.into(),
                    preferred_slug: name.into(),
                    description: None,
                },
                DirectoryCommandContext::product_service(product(name), name, at(second)),
            )
            .unwrap()
    };

    let agents_node = ensure(agents.clone(), None, "agents", 1).node;
    let objects_node = ensure(objects.clone(), Some(agents.clone()), "objects", 2).node;
    let workforce_node = ensure(workforce.clone(), Some(objects.clone()), "workforce", 3).node;
    assert_eq!(objects_node.parent_id, Some(agents_node.id));
    assert_eq!(workforce_node.parent_id, Some(objects_node.id.clone()));

    let folder = directory
        .create_node(
            CreateDirectoryNode {
                org_id: OrgId("acme".into()),
                parent_id: None,
                name: "Customer Success".into(),
                preferred_slug: "customer-success".into(),
                description: None,
            },
            DirectoryCommandContext::service("directory-admin", at(4)),
        )
        .unwrap()
        .node;
    directory
        .move_node(
            &objects_node.id,
            MoveDirectoryNode {
                parent_id: Some(folder.id),
            },
            DirectoryCommandContext::service("directory-admin", at(5)),
        )
        .unwrap();

    for space in [&agents, &objects, &workforce] {
        assert!(
            directory
                .product_space_placement(&OrgId("acme".into()), space)
                .unwrap()
                .is_some(),
            "R2: moving presentation preserves stable product binding"
        );
    }
    assert_eq!(policy.store_version().unwrap(), policy_version, "R3");
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

#[test]
fn product_retirement_is_independent_from_user_node_lifecycle() {
    // Cause/effect decision table:
    // | placement | node/children | command | effect |
    // | active | live with a live child | retire | binding becomes retired once; node and child stay live |
    // | retired | unchanged | retire retry | no revision or audit advance |
    // | retired parent | any | create a new child | reject because product parent is unavailable |
    // | retired | user metadata unchanged | ensure | reactivate the same node once |
    // Constraints: retirement never deletes/moves/archives user structure and
    // never advances authorization policy; ProductSpaceRef remains stable.
    let store = sqlite_in_memory_store("directory_product_lifecycle").unwrap();
    create_org(&store, "acme");
    let directory = DirectoryApi::new(store.clone());
    let policy = PolicyAdminApi::new(store);
    let policy_version = policy.store_version().unwrap();
    let parent_space = product_space("workforce", "workspace", "parent");
    let child_space = product_space("workforce", "project", "child");
    let parent = directory
        .ensure_product_space_placement(
            EnsureProductSpacePlacement {
                product_space: parent_space.clone(),
                org_id: OrgId("acme".into()),
                parent_product_space: None,
                name: "Parent".into(),
                preferred_slug: "parent".into(),
                description: Some("preserved".into()),
            },
            DirectoryCommandContext::product_service(product("workforce"), "workforce", at(1)),
        )
        .unwrap();
    let child = directory
        .ensure_product_space_placement(
            EnsureProductSpacePlacement {
                product_space: child_space,
                org_id: OrgId("acme".into()),
                parent_product_space: Some(parent_space.clone()),
                name: "Child".into(),
                preferred_slug: "child".into(),
                description: None,
            },
            DirectoryCommandContext::product_service(product("workforce"), "workforce", at(2)),
        )
        .unwrap();
    let retired = directory
        .retire_product_space_placement(
            RetireProductSpacePlacement {
                product_space: parent_space.clone(),
                org_id: OrgId("acme".into()),
            },
            DirectoryCommandContext::product_service(product("workforce"), "workforce", at(3)),
        )
        .unwrap();
    assert!(retired.changed);
    assert_eq!(
        retired.placement.status,
        ProductSpacePlacementStatus::Retired
    );
    assert!(!retired.node.archived);
    assert_eq!(
        directory.node(&child.node.id).unwrap().unwrap().parent_id,
        Some(parent.node.id.clone())
    );
    let retired_revision = retired.revision;
    let retry = directory
        .retire_product_space_placement(
            RetireProductSpacePlacement {
                product_space: parent_space.clone(),
                org_id: OrgId("acme".into()),
            },
            DirectoryCommandContext::product_service(product("workforce"), "workforce", at(4)),
        )
        .unwrap();
    assert!(!retry.changed);
    assert_eq!(retry.revision, retired_revision);
    assert!(
        directory
            .ensure_product_space_placement(
                EnsureProductSpacePlacement {
                    product_space: product_space("workforce", "project", "new-child"),
                    org_id: OrgId("acme".into()),
                    parent_product_space: Some(parent_space.clone()),
                    name: "New child".into(),
                    preferred_slug: "new-child".into(),
                    description: None,
                },
                DirectoryCommandContext::product_service(product("workforce"), "workforce", at(5),),
            )
            .is_err()
    );
    let reactivated = directory
        .ensure_product_space_placement(
            EnsureProductSpacePlacement {
                product_space: parent_space,
                org_id: OrgId("acme".into()),
                parent_product_space: None,
                name: "Ignored replacement".into(),
                preferred_slug: "ignored-replacement".into(),
                description: None,
            },
            DirectoryCommandContext::product_service(product("workforce"), "workforce", at(6)),
        )
        .unwrap();
    assert!(!reactivated.created);
    assert_eq!(
        reactivated.placement.status,
        ProductSpacePlacementStatus::Active
    );
    assert_eq!(reactivated.node.id, parent.node.id);
    assert_eq!(reactivated.node.name, "Parent");
    assert_eq!(reactivated.node.description.as_deref(), Some("preserved"));
    assert_eq!(policy.store_version().unwrap(), policy_version);
}

#[test]
fn concurrent_exact_retirement_converges_without_duplicate_effects() {
    // Cause-effect decision table: C1 one active placement, C2 eight exact
    // retire commands race behind one start barrier. C1+C2 -> every call
    // succeeds with retired durable truth, exactly one revision/audit effect,
    // and the user node remains live. This covers the checked-row loser path,
    // not merely sequential idempotent replay.
    let store = sqlite_in_memory_store("directory_concurrent_retire").unwrap();
    create_org(&store, "acme");
    let created = DirectoryApi::new(store.clone())
        .ensure_product_space_placement(ensure("acme"), context(1))
        .unwrap();
    let barrier = Arc::new(Barrier::new(8));
    let handles = (0..8)
        .map(|index| {
            let directory = DirectoryApi::new(store.clone());
            let barrier = barrier.clone();
            thread::spawn(move || {
                barrier.wait();
                directory.retire_product_space_placement(
                    RetireProductSpacePlacement {
                        product_space: space(),
                        org_id: OrgId("acme".into()),
                    },
                    context(index as u8 + 2),
                )
            })
        })
        .collect::<Vec<_>>();
    let results = handles
        .into_iter()
        .map(|handle| handle.join().unwrap().unwrap())
        .collect::<Vec<_>>();
    assert!(results.iter().all(|result| {
        result.placement.status == ProductSpacePlacementStatus::Retired && result.revision == 3
    }));
    assert!(!directory_node(&store, &created.node.id).archived);
    assert_eq!(
        AuditSink::events(&store)
            .unwrap()
            .iter()
            .filter(|event| event.action == "directory.product-space.retire")
            .count(),
        1
    );
}

fn directory_node(
    store: &impl awaken_iam_core::DirectoryRepository,
    id: &awaken_iam_contract::DirectoryNodeId,
) -> awaken_iam_core::DirectoryNode {
    awaken_iam_core::DirectoryRepository::directory_node(store, id)
        .unwrap()
        .unwrap()
}

#[test]
fn rejected_directory_boundaries_have_no_partial_effects() {
    // Cause/effect decision table for repository-dependent invariants:
    // | cause | command | effect |
    // | target parent belongs to another Org | move | reject, both Org revisions and audit unchanged |
    // | target parent is archived | move | reject, revision and audit unchanged |
    // | parent remains archived | restore child | reject, child remains archived |
    // | live sibling already owns slug | update | reject, metadata unchanged |
    // These are the P1 negative combinations that pure aggregate validation
    // cannot decide. Every rejection must occur before an audit/fence effect.
    let store = sqlite_in_memory_store("directory_rejected_boundaries").unwrap();
    create_org(&store, "org-a");
    create_org(&store, "org-b");
    let directory = DirectoryApi::new(store.clone());
    let create = |org: &str, parent_id, name: &str, slug: &str, second| {
        directory
            .create_node(
                CreateDirectoryNode {
                    org_id: OrgId(org.into()),
                    parent_id,
                    name: name.into(),
                    preferred_slug: slug.into(),
                    description: None,
                },
                DirectoryCommandContext::service("directory-boundary-test", at(second)),
            )
            .unwrap()
            .node
    };
    let a_root = create("org-a", None, "A root", "a-root", 1);
    let a_child = create("org-a", Some(a_root.id.clone()), "A child", "child", 2);
    let b_root = create("org-b", None, "B root", "b-root", 3);

    let a_revision = directory.revision(&OrgId("org-a".into())).unwrap();
    let b_revision = directory.revision(&OrgId("org-b".into())).unwrap();
    let audit_count = AuditSink::events(&store).unwrap().len();
    assert!(
        directory
            .move_node(
                &a_child.id,
                MoveDirectoryNode {
                    parent_id: Some(b_root.id),
                },
                DirectoryCommandContext::service("directory-boundary-test", at(4)),
            )
            .is_err(),
        "cross-Org move"
    );
    assert_eq!(
        directory.revision(&OrgId("org-a".into())).unwrap(),
        a_revision
    );
    assert_eq!(
        directory.revision(&OrgId("org-b".into())).unwrap(),
        b_revision
    );
    assert_eq!(AuditSink::events(&store).unwrap().len(), audit_count);

    let archived_target = create("org-a", None, "Archived target", "archived", 5);
    directory
        .archive_node(
            &archived_target.id,
            DirectoryCommandContext::service("directory-boundary-test", at(6)),
        )
        .unwrap();
    let revision = directory.revision(&OrgId("org-a".into())).unwrap();
    let audit_count = AuditSink::events(&store).unwrap().len();
    assert!(
        directory
            .move_node(
                &a_child.id,
                MoveDirectoryNode {
                    parent_id: Some(archived_target.id),
                },
                DirectoryCommandContext::service("directory-boundary-test", at(7)),
            )
            .is_err(),
        "archived parent move"
    );
    assert_eq!(
        directory.revision(&OrgId("org-a".into())).unwrap(),
        revision
    );
    assert_eq!(AuditSink::events(&store).unwrap().len(), audit_count);

    directory
        .archive_node(
            &a_child.id,
            DirectoryCommandContext::service("directory-boundary-test", at(8)),
        )
        .unwrap();
    directory
        .archive_node(
            &a_root.id,
            DirectoryCommandContext::service("directory-boundary-test", at(9)),
        )
        .unwrap();
    let revision = directory.revision(&OrgId("org-a".into())).unwrap();
    let audit_count = AuditSink::events(&store).unwrap().len();
    assert!(
        directory
            .restore_node(
                &a_child.id,
                DirectoryCommandContext::service("directory-boundary-test", at(10)),
            )
            .is_err(),
        "archived parent restore"
    );
    assert!(directory.node(&a_child.id).unwrap().unwrap().archived);
    assert_eq!(
        directory.revision(&OrgId("org-a".into())).unwrap(),
        revision
    );
    assert_eq!(AuditSink::events(&store).unwrap().len(), audit_count);

    let first = create("org-a", None, "First", "first", 11);
    let second = create("org-a", None, "Second", "second", 12);
    let revision = directory.revision(&OrgId("org-a".into())).unwrap();
    let audit_count = AuditSink::events(&store).unwrap().len();
    assert!(
        directory
            .update_node(
                &second.id,
                UpdateDirectoryNode {
                    name: "Conflicting".into(),
                    slug: first.slug.clone(),
                    description: Some("must not persist".into()),
                },
                DirectoryCommandContext::service("directory-boundary-test", at(13)),
            )
            .is_err(),
        "sibling slug conflict"
    );
    assert_eq!(directory.node(&second.id).unwrap().unwrap().name, "Second");
    assert_eq!(
        directory.revision(&OrgId("org-a".into())).unwrap(),
        revision
    );
    assert_eq!(AuditSink::events(&store).unwrap().len(), audit_count);
}
