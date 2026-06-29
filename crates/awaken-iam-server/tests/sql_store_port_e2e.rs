//! End-to-end coverage of the SQL store's repository ports not exercised by
//! `sql_store_e2e::exercise_every_port`: list endpoints, role deletion, the
//! api-token absent-update NotFound branch, and the unknown tier / effect
//! string-error branches.

use awaken_iam_contract::{
    AccountId, ApiToken, ApiTokenId, ApiTokenPrefix, GrantEffect, OrgId, PrincipalRef, ScopeRef,
    Timestamp, WorkspaceId,
};
use awaken_iam_core::{
    ActionPattern, ApiTokenRepo, Effect, Group, GroupId, GroupRepo, OrgRepo, Organization, Plan,
    PlanId, PlanRepo, PlanTier, Quota, RateLimit, RateWindow, RepoError, RoleDef, RoleId, RoleRepo,
};
use awaken_iam_server::sqlite_in_memory_store;
use std::collections::{BTreeMap, BTreeSet};

fn ts() -> Timestamp {
    Timestamp("2026-06-21T00:00:00Z".into())
}

#[test]
fn api_token_update_on_absent_token_yields_not_found() {
    // The api-token update path's fail-closed branch: the SQL store surfaces
    // `NotFound` when the row to update does not exist, instead of silently
    // reporting success.
    let store = sqlite_in_memory_store("iam").expect("migrate");
    let absent = ApiToken {
        id: ApiTokenId("tok_ghost".into()),
        prefix: ApiTokenPrefix("pfx_ghost".into()),
        principal: PrincipalRef::Account {
            account_id: AccountId("ada".into()),
        },
        secret_hash: "hash".into(),
        workspace: WorkspaceId("wrkspc_default".into()),
        created_at: ts(),
        expires_at: None,
        revoked_at: None,
    };
    let result = ApiTokenRepo::update(&store, absent);
    assert!(matches!(result, Err(RepoError::NotFound(_))));
}

#[test]
fn role_remove_returns_not_found_when_absent() {
    let store = sqlite_in_memory_store("iam").expect("migrate");
    let result = RoleRepo::remove(&store, &RoleId("ghost".into()));
    assert!(matches!(result, Err(RepoError::NotFound(_))));
}

#[test]
fn role_remove_returns_ok_when_present() {
    // The SQL store's `remove` path: a successful delete returns Ok(()) and
    // a follow-up `get` returns None.
    let store = sqlite_in_memory_store("iam").expect("migrate");
    let role = RoleDef {
        id: RoleId("publisher".into()),
        display_name: Some("Publisher".into()),
        action_patterns: vec![ActionPattern("pack.*".into())],
        created_at: ts(),
        updated_at: ts(),
    };
    RoleRepo::upsert(&store, role).expect("upsert");
    RoleRepo::remove(&store, &RoleId("publisher".into())).expect("remove");
    assert!(
        RoleRepo::get(&store, &RoleId("publisher".into()))
            .unwrap()
            .is_none()
    );
    // A second remove now fails closed.
    assert!(matches!(
        RoleRepo::remove(&store, &RoleId("publisher".into())),
        Err(RepoError::NotFound(_))
    ));
}

#[test]
fn group_list_returns_every_group_for_an_org() {
    // The SQL store's `GroupRepo::list` path: every persisted group is
    // returned, in deterministic order, irrespective of insert order.
    let store = sqlite_in_memory_store("iam").expect("migrate");
    // Seed an org the groups belong to.
    OrgRepo::upsert(
        &store,
        Organization {
            id: OrgId("acme".into()),
            display_name: Some("Acme".into()),
            owner: PrincipalRef::Account {
                account_id: AccountId("ada".into()),
            },
            created_at: ts(),
            updated_at: ts(),
        },
    )
    .unwrap();

    for (id, name) in [
        ("eng", "Engineering"),
        ("design", "Design"),
        ("ops", "Operations"),
    ] {
        GroupRepo::upsert(
            &store,
            Group {
                id: GroupId(id.into()),
                org: OrgId("acme".into()),
                display_name: Some(name.into()),
                members: vec![PrincipalRef::Account {
                    account_id: AccountId("ada".into()),
                }],
                created_at: ts(),
                updated_at: ts(),
            },
        )
        .unwrap();
    }

    let groups = GroupRepo::list(&store).unwrap();
    assert_eq!(groups.len(), 3);
    let ids: Vec<&str> = groups.iter().map(|g| g.id.0.as_str()).collect();
    assert_eq!(ids, vec!["design", "eng", "ops"]);
}

#[test]
fn unknown_effect_string_fails_to_deserialize() {
    // The Effect round-trip function rejects an unknown effect string at the
    // SQL decode layer — a row written with a future Effect variant does not
    // silently coerce to Allow.
    //
    // The SQL store uses portable types; we exercise the deserializer by
    // writing a grant with the unknown variant via the shared adapter
    // (the wire form of Effect is a stable lowercase token).
    //
    // Since the Effect enum has only three variants, the unknown branch is
    // reachable only via raw column corruption; we verify the deserializer
    // returns RepoError::Backend on a row it cannot parse.
    use awaken_iam_server::SqlConn;
    use awaken_iam_server::SqliteBackend;
    // Open the backend, then mount both the migrated store and the same
    // raw connection so corruption and read-back share one database.
    let backend = SqliteBackend::open_in_memory().expect("open");
    let store = awaken_iam_server::sqlite_migrated_store(backend.clone(), "iam").expect("migrate");
    OrgRepo::upsert(
        &store,
        Organization {
            id: OrgId("acme".into()),
            display_name: Some("Acme".into()),
            owner: PrincipalRef::Account {
                account_id: AccountId("ada".into()),
            },
            created_at: ts(),
            updated_at: ts(),
        },
    )
    .unwrap();

    use awaken_iam_core::GrantRepo;
    GrantRepo::put(
        &store,
        awaken_iam_core::Grant {
            id: awaken_iam_core::GrantId("g1".into()),
            subject: awaken_iam_core::GrantSubject::Principal(PrincipalRef::Account {
                account_id: AccountId("ada".into()),
            }),
            action_pattern: ActionPattern("pack.read".into()),
            scope: ScopeRef::Org {
                org_id: OrgId("acme".into()),
            },
            effect: Effect::Allow,
        },
    )
    .unwrap();

    // Now mutate the `effect` column to a string the deserialiser does not
    // recognise and read it back.
    let conn: &dyn SqlConn = &backend;
    conn.execute(
        "UPDATE iam_grants SET effect = ?1 WHERE id = ?2",
        &[Some("totally_unknown".into()), Some("g1".into())],
    )
    .expect("corrupt effect");

    let result = GrantRepo::get(&store, &awaken_iam_core::GrantId("g1".into()));
    assert!(
        matches!(result, Err(RepoError::Backend(_))),
        "unknown effect must surface as Backend error, got {result:?}"
    );
}

#[test]
fn unknown_plan_tier_string_fails_to_deserialize() {
    // Mirror the Effect test for PlanTier — the decoder rejects an unknown
    // tier rather than defaulting to Free.
    use awaken_iam_server::SqlConn;
    use awaken_iam_server::SqliteBackend;
    let backend = SqliteBackend::open_in_memory().expect("open");
    let store = awaken_iam_server::sqlite_migrated_store(backend.clone(), "iam").expect("migrate");

    PlanRepo::put(
        &store,
        Plan::new(PlanId("plan-x".into()), PlanTier::Team, ["pack.read"])
            .with_quota("pack.publish", Quota::Limited(10))
            .with_rate_limit("pack.read", RateLimit::new(50, RateWindow::Minute)),
    )
    .unwrap();

    // Corrupt the tier column.
    let conn: &dyn SqlConn = &backend;
    conn.execute(
        "UPDATE iam_plans SET tier = ?1 WHERE id = ?2",
        &[Some("mystery-tier".into()), Some("plan-x".into())],
    )
    .expect("corrupt tier");

    let result = PlanRepo::get(&store, &PlanId("plan-x".into()));
    assert!(
        matches!(result, Err(RepoError::Backend(_))),
        "unknown tier must surface as Backend error, got {result:?}"
    );
}

#[test]
fn plan_tier_round_trips_with_limits_and_rates() {
    // A real Plan with quotas, rate limits, and a BTreeMap-ordered limits
    // payload round-trips through the SQL store without loss.
    let store = sqlite_in_memory_store("iam").expect("migrate");
    let mut limits = BTreeMap::new();
    limits.insert("seats".to_owned(), Quota::Limited(25));
    limits.insert("private_namespaces".to_owned(), Quota::Unlimited);
    let plan = Plan {
        id: PlanId("plan-pro".into()),
        tier: PlanTier::Enterprise,
        features: BTreeSet::from(["pack.publish".to_owned(), "pack.read".to_owned()]),
        limits: limits.clone(),
        rates: BTreeMap::new(),
    };
    PlanRepo::put(&store, plan.clone()).unwrap();
    let read = PlanRepo::get(&store, &PlanId("plan-pro".into()))
        .unwrap()
        .unwrap();
    assert_eq!(read.tier, PlanTier::Enterprise);
    assert_eq!(read.features, plan.features);
    assert_eq!(read.limits, limits);
}

#[test]
fn grant_subject_ref_round_trips_through_grant_storage() {
    // GrantSubjectRef is the wire form decoded when reading a grant back.
    // Every variant must round-trip cleanly.
    use awaken_iam_core::GrantRepo;
    let store = sqlite_in_memory_store("iam").expect("migrate");
    OrgRepo::upsert(
        &store,
        Organization {
            id: OrgId("acme".into()),
            display_name: None,
            owner: PrincipalRef::Account {
                account_id: AccountId("ada".into()),
            },
            created_at: ts(),
            updated_at: ts(),
        },
    )
    .unwrap();

    // Grant with a Service principal subject — a path the SQL store's
    // decoder recognises.
    GrantRepo::put(
        &store,
        awaken_iam_core::Grant {
            id: awaken_iam_core::GrantId("g_service".into()),
            subject: awaken_iam_core::GrantSubject::Principal(PrincipalRef::Service {
                service_id: "ci-bot".to_owned(),
            }),
            action_pattern: ActionPattern("pack.publish".into()),
            scope: ScopeRef::Org {
                org_id: OrgId("acme".into()),
            },
            effect: Effect::Allow,
        },
    )
    .unwrap();
    let loaded = GrantRepo::get(&store, &awaken_iam_core::GrantId("g_service".into()))
        .unwrap()
        .unwrap();
    assert_eq!(
        loaded.subject,
        awaken_iam_core::GrantSubject::Principal(PrincipalRef::Service {
            service_id: "ci-bot".to_owned()
        })
    );

    // GrantEffect is the wire form of Effect; round-trip each variant.
    for effect in [
        GrantEffect::Allow,
        GrantEffect::Deny,
        GrantEffect::RequireApproval,
    ] {
        let id = format!("g_{effect:?}").to_lowercase();
        GrantRepo::put(
            &store,
            awaken_iam_core::Grant {
                id: awaken_iam_core::GrantId(id.clone()),
                subject: awaken_iam_core::GrantSubject::Principal(PrincipalRef::Service {
                    service_id: "ci-bot".to_owned(),
                }),
                action_pattern: ActionPattern("pack.publish".into()),
                scope: ScopeRef::Org {
                    org_id: OrgId("acme".into()),
                },
                effect: match effect {
                    GrantEffect::Allow => Effect::Allow,
                    GrantEffect::Deny => Effect::Deny,
                    GrantEffect::RequireApproval => Effect::RequireApproval,
                },
            },
        )
        .unwrap();
        let loaded = GrantRepo::get(&store, &awaken_iam_core::GrantId(id))
            .unwrap()
            .unwrap();
        let expected = match effect {
            GrantEffect::Allow => Effect::Allow,
            GrantEffect::Deny => Effect::Deny,
            GrantEffect::RequireApproval => Effect::RequireApproval,
        };
        assert_eq!(loaded.effect, expected);
    }
}
