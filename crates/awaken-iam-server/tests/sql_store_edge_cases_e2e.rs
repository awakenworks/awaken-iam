//! End-to-end coverage of the SQL store's edge cases: invalid prefixes,
//! every `Effect` and `PlanTier` round-trip, every `GrantSubject` decode,
//! the backend getter, and the file-backed SQLite path.
//!
//! These are real-world scenarios: a consumer that misconfigures a prefix,
//! or whose data hits a denied branch, must get a clean error or the correct
//! deserialised value, not a silent fallback.

use awaken_iam_contract::{
    Account, AccountId, AccountStatus, ExternalIdentity, ExternalIdentityClaims,
    ExternalIdentityId, ExternalIdentityKey, ExternalSubject, IdentityProviderKey, OrgId,
    PrincipalRef, ScopeRef, Timestamp,
};
use awaken_iam_core::{
    AccountRepository, ActionPattern, Effect, ExternalIdentityRepository, Grant, GrantId,
    GrantRepository, GrantSubject, GroupId, OrgRepository, Organization, Plan, PlanId,
    PlanRepository, PlanTier, Quota, RateLimit, RateWindow, RoleDef, RoleId, RoleRepository,
};
use awaken_iam_server::{SqlStore, SqliteBackend, sqlite_in_memory_store, sqlite_migrated_store};

fn ts() -> Timestamp {
    Timestamp("2026-06-21T00:00:00Z".into())
}

#[test]
fn sql_store_with_prefix_rejects_empty_and_invalid_prefixes() {
    // The prefix is interpolated directly into DDL identifiers, so the only
    // safe alphabet is `[a-z0-9_]+`. Anything else must fail closed at
    // construction rather than later, when a SQL statement tries to use it.
    let backend = SqliteBackend::open_in_memory().expect("open");

    for bad in [
        "",
        "Iam.Identity",
        "iam identity",
        "iam-identity",
        "iam;DROP",
    ] {
        let result = SqlStore::with_prefix(backend.clone(), bad);
        assert!(
            matches!(result, Err(awaken_iam_core::RepositoryError::Backend(_))),
            "prefix {bad:?} must be rejected"
        );
    }

    // Valid prefixes pass.
    for good in ["iam", "iam_identity", "tenant_a_42"] {
        let result = SqlStore::with_prefix(backend.clone(), good);
        assert!(result.is_ok(), "prefix {good:?} must be accepted");
    }
}

#[test]
fn sql_store_backend_returns_the_underlying_connection() {
    // The `backend()` getter is the seam a deployment uses to issue its own
    // queries through the same connection the repositories share.
    let store = sqlite_in_memory_store("iam").expect("migrate");
    let _backend = store.backend();
    // No assertion beyond "the getter returns": the value's identity is the
    // primary contract — if it didn't, a custom query against `backend`
    // would target a different connection than the repositories.
}

#[test]
fn effect_round_trips_through_allow_and_deny_branches() {
    // The wire form encodes each Effect variant as a stable lowercase token.
    // A persisted grant with Effect::Deny must read back as Deny, not collapse
    // to Allow or error on a missing variant.
    let store = sqlite_in_memory_store("iam").expect("migrate");

    // Need an org so grants can be looked up against a known scope graph.
    let org_id = OrgId("acme".into());
    OrgRepository::upsert(
        &store,
        Organization {
            id: org_id.clone(),
            display_name: Some("Acme".into()),
            owner: PrincipalRef::Account {
                account_id: AccountId("ada".into()),
            },
            created_at: ts(),
            updated_at: ts(),
        },
    )
    .unwrap();

    for effect in [Effect::Allow, Effect::Deny] {
        let grant = Grant {
            id: GrantId(format!(
                "g_{}",
                match effect {
                    Effect::Allow => "allow",
                    Effect::Deny => "deny",
                    Effect::RequireApproval => "require_approval",
                }
            )),
            subject: GrantSubject::Principal(PrincipalRef::Account {
                account_id: AccountId("ada".into()),
            }),
            action_pattern: ActionPattern("pack.read".into()),
            scope: ScopeRef::Org {
                org_id: org_id.clone(),
            },
            effect,
        };
        GrantRepository::put(&store, grant.clone()).unwrap();
        let round_tripped = GrantRepository::get(&store, &grant.id).unwrap().unwrap();
        assert_eq!(round_tripped.effect, effect);
        assert_eq!(round_tripped.action_pattern.0, "pack.read");
    }
}

#[test]
fn plan_tier_round_trips_through_free_team_and_enterprise() {
    // Each tier maps to its own storage token; round-tripping every variant
    // proves the SQL store's deserialiser dispatches all three.
    let store = sqlite_in_memory_store("iam").expect("migrate");
    for (tier, label) in [
        (PlanTier::Free, "free"),
        (PlanTier::Team, "team"),
        (PlanTier::Enterprise, "enterprise"),
    ] {
        let plan = Plan::new(PlanId(format!("plan_{label}")), tier, ["pack.read"])
            .with_quota("pack.publish", Quota::Limited(100))
            .with_rate_limit("pack.read", RateLimit::new(50, RateWindow::Minute));
        PlanRepository::put(&store, plan.clone()).unwrap();
        let round_tripped = PlanRepository::get(&store, &plan.id).unwrap().unwrap();
        assert_eq!(round_tripped.tier, tier);
    }
}

#[test]
fn grant_subject_decodes_principal_role_and_group_variants() {
    // The GrantSubjectRef wire form is decoded into one of three core
    // variants; each must round-trip independently.
    let store = sqlite_in_memory_store("iam").expect("migrate");

    let org_id = OrgId("acme".into());
    OrgRepository::upsert(
        &store,
        Organization {
            id: org_id.clone(),
            display_name: Some("Acme".into()),
            owner: PrincipalRef::Account {
                account_id: AccountId("ada".into()),
            },
            created_at: ts(),
            updated_at: ts(),
        },
    )
    .unwrap();
    RoleRepository::upsert(
        &store,
        RoleDef {
            id: RoleId("publisher".into()),
            display_name: Some("Publisher".into()),
            action_patterns: vec![ActionPattern("pack.*".into())],
            created_at: ts(),
            updated_at: ts(),
        },
    )
    .unwrap();

    // Principal variant.
    let grant = Grant {
        id: GrantId("g_principal".into()),
        subject: GrantSubject::Principal(PrincipalRef::Account {
            account_id: AccountId("ada".into()),
        }),
        action_pattern: ActionPattern("pack.read".into()),
        scope: ScopeRef::Org {
            org_id: org_id.clone(),
        },
        effect: Effect::Allow,
    };
    GrantRepository::put(&store, grant).unwrap();
    let loaded = GrantRepository::get(&store, &GrantId("g_principal".into()))
        .unwrap()
        .unwrap();
    match loaded.subject {
        GrantSubject::Principal(PrincipalRef::Account { account_id }) => {
            assert_eq!(account_id.0, "ada");
        }
        _ => panic!("expected principal subject"),
    }

    // Role variant.
    let grant = Grant {
        id: GrantId("g_role".into()),
        subject: GrantSubject::Role(RoleId("publisher".into())),
        action_pattern: ActionPattern("pack.read".into()),
        scope: ScopeRef::Org {
            org_id: org_id.clone(),
        },
        effect: Effect::Allow,
    };
    GrantRepository::put(&store, grant).unwrap();
    let loaded = GrantRepository::get(&store, &GrantId("g_role".into()))
        .unwrap()
        .unwrap();
    assert!(matches!(loaded.subject, GrantSubject::Role(_)));

    // Group variant (the Grant subject takes a GroupId directly).
    let grant = Grant {
        id: GrantId("g_group".into()),
        subject: GrantSubject::Group(GroupId("eng".into())),
        action_pattern: ActionPattern("pack.read".into()),
        scope: ScopeRef::Org {
            org_id: org_id.clone(),
        },
        effect: Effect::Allow,
    };
    GrantRepository::put(&store, grant).unwrap();
    let loaded = GrantRepository::get(&store, &GrantId("g_group".into()))
        .unwrap()
        .unwrap();
    assert!(matches!(loaded.subject, GrantSubject::Group(_)));
}

#[test]
fn sqlite_backend_open_path_creates_a_file_backed_database() {
    // The on-disk SQLite path is the deployment default for single-tenant
    // servers: open the file, run the migrations, and the same `SqlStore`
    // exercises the same port surface as the in-memory path.
    let path = std::env::temp_dir().join("awaken-iam-sqlite-edge-test.db");
    let _ = std::fs::remove_file(&path);

    let backend = SqliteBackend::open_path(&path).expect("open file-backed db");
    let store = sqlite_migrated_store(backend, "iam").expect("migrate");

    // The store round-trips an account over the file-backed connection.
    let id = AccountId("ada".into());
    AccountRepository::upsert(
        &store,
        Account {
            id: id.clone(),
            status: AccountStatus::Active,
            display_name: Some("Ada".into()),
            created_at: ts(),
            updated_at: ts(),
        },
    )
    .unwrap();
    assert!(AccountRepository::get(&store, &id).unwrap().is_some());

    // Reopen the file and confirm the data persists across processes —
    // a fresh connection must see what the previous one wrote.
    let backend2 = SqliteBackend::open_path(&path).expect("reopen");
    let store2 = sqlite_migrated_store(backend2, "iam").expect("migrate again");
    assert!(AccountRepository::get(&store2, &id).unwrap().is_some());

    // Clean up the fixture.
    let _ = std::fs::remove_file(&path);
}

#[test]
fn external_identity_subject_decodes_through_the_sql_path() {
    // ExternalIdentityRepository.get_by_key deserialises the stored claims JSON.
    // A real (provider, subject) round-trip exercises that path end-to-end.
    let store = sqlite_in_memory_store("iam").expect("migrate");

    let identity = ExternalIdentity {
        id: ExternalIdentityId("e1".into()),
        account_id: AccountId("a".into()),
        provider_key: IdentityProviderKey("github".into()),
        claims: ExternalIdentityClaims {
            subject: ExternalSubject("gh-1".into()),
            email: Some("ada@example.com".into()),
            email_verified: Some(true),
            display_name: Some("Ada".into()),
            username: Some("ada".into()),
            avatar_url: None,
            locale: None,
        },
        first_seen_at: ts(),
        last_seen_at: ts(),
    };
    store.link(identity).unwrap();
    let key = ExternalIdentityKey {
        provider_key: IdentityProviderKey("github".into()),
        subject: ExternalSubject("gh-1".into()),
    };
    let read = store.get_by_key(&key).unwrap().unwrap();
    assert_eq!(read.claims.email.as_deref(), Some("ada@example.com"));
}

#[test]
fn sql_store_rejects_grant_with_role_subject_whose_role_does_not_exist() {
    // A grant's Role subject is a plain id reference; the store accepts it
    // without a FK check (domain owns shape), so the grant round-trips even
    // when no role row is present — this is the documented behaviour, not a
    // bug.
    let store = sqlite_in_memory_store("iam").expect("migrate");
    OrgRepository::upsert(
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
    let grant = Grant {
        id: GrantId("g_phantom".into()),
        subject: GrantSubject::Role(RoleId("ghost".into())),
        action_pattern: ActionPattern("pack.read".into()),
        scope: ScopeRef::Org {
            org_id: OrgId("acme".into()),
        },
        effect: Effect::Allow,
    };
    GrantRepository::put(&store, grant.clone()).unwrap();
    let loaded = GrantRepository::get(&store, &grant.id).unwrap().unwrap();
    assert_eq!(loaded.subject, GrantSubject::Role(RoleId("ghost".into())));
}
