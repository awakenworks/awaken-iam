//! End-to-end proof that the real database adapters are switchable behind the
//! repository contracts (ADR-0003).
//!
//! One harness, [`exercise_every_repository`], drives every IAM repository contract through
//! its success, failure, and guardrail paths against an [`SqlStore`] without
//! naming a backend. It runs unconditionally against SQLite (a migrated
//! in-memory database) and, when `IAM_TEST_POSTGRES_URL` is set, against a real
//! Postgres instance — the same assertions passing on both is the switchability
//! the ADR promises. Selecting the backend is configuration, not a code fork.

use awaken_iam_contract::{
    Account, AccountId, AccountStatus, ApiToken, ApiTokenId, ApiTokenPrefix, AuthorizationProfile,
    AuthorizationProfileDocument, CreateDirectoryNode, DirectoryNodeId,
    EnsureProductSpacePlacement, ExternalIdentity, ExternalIdentityClaims, ExternalIdentityId,
    ExternalIdentityKey, ExternalSubject, IdentityProviderKey, MoveDirectoryNode, NamespaceId,
    OAuthLoginState, OAuthLoginStateId, OrgId, PrincipalRef, ProductId, ProductSpacePlacement,
    ProductSpaceRef, ProfileLifecycle, ResourceId, ResourceType, ScopeRef, Session, SessionId,
    Timestamp, WorkspaceId, WorkspaceOrgEdge,
};
use awaken_iam_core::{
    AccountIdentityRepository, AccountRepository, ActionPattern, ApiTokenRepository, AuditEvent,
    AuditSink, AuthCodeRepository, AuthorizationProfileRepository, DirectoryNode,
    DirectoryRepository, Effect, ExternalIdentityRepository, Grant, GrantId, GrantRepository,
    GrantSubject, Group, GroupId, GroupRepository, LoginFlowRepository, OAuthClientRepository,
    OrgRepository, Organization, Plan, PlanId, PlanRepository, PlanTier, Quota, RateLimit,
    RateWindow, RegisteredClient, RepositoryError, ResourceEdge, ResourceModelRepository,
    RoleBinding, RoleBindingRepository, RoleDef, RoleId, RoleRepository, SessionRepository,
    StoredAuthorizationCode,
};
use awaken_iam_server::{
    DirectoryApi, DirectoryCommandContext, FenceStore, PostgresBackend, SqlConn, SqlStore,
    postgres_migrated_store, sqlite_in_memory_store,
};
use std::sync::{Arc, Barrier};
use std::thread;

fn ts(value: &str) -> Timestamp {
    Timestamp(value.into())
}

struct IsolatedPostgresSchema {
    base_url: String,
    schema: String,
    url: String,
}

impl IsolatedPostgresSchema {
    fn create(base_url: &str, prefix: &str) -> Self {
        let schema = format!(
            "{}_{}_{}",
            prefix,
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .expect("wall clock")
                .as_nanos()
        );
        let create_url = base_url.to_owned();
        let create_schema = schema.clone();
        std::thread::spawn(move || {
            let mut client = postgres::Client::connect(&create_url, postgres::NoTls)
                .expect("connect PostgreSQL");
            client
                .batch_execute(&format!("CREATE SCHEMA {create_schema}"))
                .expect("create isolated IAM schema");
        })
        .join()
        .expect("isolated IAM schema thread");
        let separator = if base_url.contains('?') { '&' } else { '?' };
        let url = format!("{base_url}{separator}options=-csearch_path%3D{schema}");
        Self {
            base_url: base_url.into(),
            schema,
            url,
        }
    }
}

impl Drop for IsolatedPostgresSchema {
    fn drop(&mut self) {
        let base_url = self.base_url.clone();
        let schema = self.schema.clone();
        let _ = std::thread::spawn(move || {
            if let Ok(mut client) = postgres::Client::connect(&base_url, postgres::NoTls) {
                let _ = client.batch_execute(&format!("DROP SCHEMA {schema} CASCADE"));
            }
        })
        .join();
    }
}

fn account(id: &str) -> Account {
    Account {
        id: AccountId(id.into()),
        status: AccountStatus::Active,
        display_name: Some("Display".into()),
        created_at: ts("2026-06-19T00:00:00Z"),
        updated_at: ts("2026-06-19T00:00:00Z"),
    }
}

fn external(id: &str, account_id: &str, subject: &str) -> ExternalIdentity {
    ExternalIdentity {
        id: ExternalIdentityId(id.into()),
        account_id: AccountId(account_id.into()),
        provider_key: IdentityProviderKey("github".into()),
        claims: ExternalIdentityClaims {
            subject: ExternalSubject(subject.into()),
            email: Some("ada@example.com".into()),
            email_verified: Some(true),
            display_name: Some("Ada".into()),
            username: Some("ada".into()),
            avatar_url: None,
            locale: None,
        },
        first_seen_at: ts("2026-06-19T00:00:00Z"),
        last_seen_at: ts("2026-06-19T00:00:00Z"),
    }
}

fn service(name: &str) -> PrincipalRef {
    PrincipalRef::Service {
        service_id: name.into(),
    }
}

/// Drive every repository through its success, failure, and guardrail paths.
fn exercise_every_repository<B: SqlConn>(store: &SqlStore<B>) {
    // --- accounts: upsert is idempotent replace; list is ordered ---
    assert_eq!(
        AccountRepository::get(store, &AccountId("a".into())).unwrap(),
        None
    );
    AccountRepository::upsert(store, account("a")).unwrap();
    AccountRepository::upsert(store, account("b")).unwrap();
    let mut replaced = account("a");
    replaced.display_name = Some("Renamed".into());
    AccountRepository::upsert(store, replaced).unwrap();
    let accounts = AccountRepository::list(store).unwrap();
    assert_eq!(accounts.len(), 2);
    assert_eq!(accounts[0].id.0, "a");
    assert_eq!(accounts[0].display_name.as_deref(), Some("Renamed"));

    // --- external identities: unique by (provider, subject); claims refresh ---
    store.link(external("e1", "a", "sub-1")).unwrap();
    let dup = store.link(external("e2", "a", "sub-1"));
    assert!(
        matches!(dup, Err(RepositoryError::Conflict(_))),
        "duplicate subject must conflict"
    );
    let key = ExternalIdentityKey {
        provider_key: IdentityProviderKey("github".into()),
        subject: ExternalSubject("sub-1".into()),
    };
    assert_eq!(store.get_by_key(&key).unwrap().unwrap().id.0, "e1");
    let mut refreshed = external("e1", "a", "sub-1");
    refreshed.claims.email = Some("ada@new.example".into());
    refreshed.last_seen_at = ts("2026-06-20T00:00:00Z");
    store.update_claims(refreshed).unwrap();
    assert_eq!(
        store
            .get_by_key(&key)
            .unwrap()
            .unwrap()
            .claims
            .email
            .as_deref(),
        Some("ada@new.example")
    );
    assert!(matches!(
        store.update_claims(external("e9", "a", "absent")),
        Err(RepositoryError::NotFound(_))
    ));
    assert_eq!(
        store
            .list_for_account(&AccountId("a".into()))
            .unwrap()
            .len(),
        1
    );

    // Cause/effect decision table for the Account aggregate command:
    // R1 new account + new provider subject -> both rows commit atomically.
    // R2 new account + occupied provider subject -> neither row commits.
    // R3 account with two identities -> exact owned unlink succeeds.
    // R4 account with one identity -> unlink fails and preserves login access.
    AccountIdentityRepository::provision(store, account("c"), external("e3", "c", "sub-3"))
        .unwrap();
    assert!(
        AccountRepository::get(store, &AccountId("c".into()))
            .unwrap()
            .is_some()
    );
    assert!(matches!(
        AccountIdentityRepository::provision(
            store,
            account("orphan"),
            external("e4", "orphan", "sub-3")
        ),
        Err(RepositoryError::Conflict(_))
    ));
    assert_eq!(
        AccountRepository::get(store, &AccountId("orphan".into())).unwrap(),
        None
    );
    ExternalIdentityRepository::link(store, external("e5", "c", "sub-5")).unwrap();
    let key_5 = ExternalIdentityKey {
        provider_key: IdentityProviderKey("github".into()),
        subject: ExternalSubject("sub-5".into()),
    };
    AccountIdentityRepository::unlink(store, &key_5, &AccountId("c".into())).unwrap();
    let key_3 = ExternalIdentityKey {
        provider_key: IdentityProviderKey("github".into()),
        subject: ExternalSubject("sub-3".into()),
    };
    assert!(matches!(
        AccountIdentityRepository::unlink(store, &key_3, &AccountId("c".into())),
        Err(RepositoryError::Conflict(_))
    ));
    assert!(
        ExternalIdentityRepository::get_by_key(store, &key_3)
            .unwrap()
            .is_some()
    );

    // --- sessions: id + token-hash lookup, conflict, in-place revoke ---
    let session = Session {
        id: SessionId("s1".into()),
        account_id: AccountId("a".into()),
        token_hash: "hash-1".into(),
        external_identity_id: Some(ExternalIdentityId("e1".into())),
        created_at: ts("2026-06-19T00:00:00Z"),
        last_seen_at: ts("2026-06-19T00:00:00Z"),
        expires_at: ts("2026-06-20T00:00:00Z"),
        revoked_at: None,
    };
    SessionRepository::create(store, session.clone()).unwrap();
    assert!(matches!(
        SessionRepository::create(store, session.clone()),
        Err(RepositoryError::Conflict(_))
    ));
    assert_eq!(
        store.get_by_token_hash("hash-1").unwrap().unwrap().id.0,
        "s1"
    );
    let mut revoked = session;
    revoked.revoked_at = Some(ts("2026-06-19T01:00:00Z"));
    SessionRepository::update(store, revoked).unwrap();
    assert!(
        SessionRepository::get(store, &SessionId("s1".into()))
            .unwrap()
            .unwrap()
            .revoked_at
            .is_some()
    );
    let mut ghost = Session {
        id: SessionId("missing".into()),
        account_id: AccountId("a".into()),
        token_hash: "x".into(),
        external_identity_id: None,
        created_at: ts("2026-06-19T00:00:00Z"),
        last_seen_at: ts("2026-06-19T00:00:00Z"),
        expires_at: ts("2026-06-20T00:00:00Z"),
        revoked_at: None,
    };
    ghost.token_hash = "y".into();
    assert!(matches!(
        SessionRepository::update(store, ghost),
        Err(RepositoryError::NotFound(_))
    ));

    // --- login flows: start once, consume at most once ---
    let flow = OAuthLoginState {
        id: OAuthLoginStateId("l1".into()),
        provider_key: IdentityProviderKey("github".into()),
        state_hash: "state".into(),
        nonce_hash: Some("nonce".into()),
        pkce_verifier_hash: None,
        return_to: Some("/after".into()),
        created_at: ts("2026-06-19T00:00:00Z"),
        expires_at: ts("2026-06-19T00:10:00Z"),
        consumed_at: None,
    };
    store.start(flow.clone()).unwrap();
    assert!(matches!(
        store.start(flow),
        Err(RepositoryError::Conflict(_))
    ));
    assert_eq!(
        LoginFlowRepository::get(store, &OAuthLoginStateId("l1".into()))
            .unwrap()
            .unwrap()
            .return_to
            .as_deref(),
        Some("/after")
    );
    store
        .mark_consumed(&OAuthLoginStateId("l1".into()), ts("2026-06-19T00:05:00Z"))
        .unwrap();
    assert!(matches!(
        store.mark_consumed(&OAuthLoginStateId("l1".into()), ts("2026-06-19T00:06:00Z")),
        Err(RepositoryError::Conflict(_))
    ));
    assert!(matches!(
        store.mark_consumed(
            &OAuthLoginStateId("absent".into()),
            ts("2026-06-19T00:06:00Z")
        ),
        Err(RepositoryError::NotFound(_))
    ));

    // --- downstream OAuth: shared clients + atomic live code consumption ---
    // Cause/effect rules: R1(upsert client)->read/list round-trip; R2(live,
    // unconsumed code)->one successful CAS; R3(consumed or expired)->false and
    // no second state transition. The same harness runs on SQLite and optional
    // Postgres, proving one backend-neutral repository contract.
    let client = RegisteredClient::public(
        "awaken-runtime",
        vec!["https://awaken.example/callback".into()],
        ["openid", "email"],
    );
    OAuthClientRepository::upsert(store, client.clone()).unwrap();
    assert_eq!(
        OAuthClientRepository::get(store, "awaken-runtime").unwrap(),
        Some(client)
    );
    assert_eq!(OAuthClientRepository::list(store).unwrap().len(), 1);
    let code = StoredAuthorizationCode {
        code_hash: "code-hash-live".into(),
        client_id: "awaken-runtime".into(),
        redirect_uri: "https://awaken.example/callback".into(),
        account_id: AccountId("a".into()),
        scopes: vec!["openid".into()],
        code_challenge: Some("challenge".into()),
        nonce: Some("nonce".into()),
        expires_at: ts("2026-06-19T00:10:00Z"),
        consumed_at: None,
    };
    AuthCodeRepository::create(store, code.clone()).unwrap();
    assert_eq!(
        AuthCodeRepository::get(store, "code-hash-live").unwrap(),
        Some(code)
    );
    assert!(
        AuthCodeRepository::consume_if_live(store, "code-hash-live", &ts("2026-06-19T00:05:00Z"))
            .unwrap()
    );
    assert!(
        !AuthCodeRepository::consume_if_live(store, "code-hash-live", &ts("2026-06-19T00:06:00Z"))
            .unwrap()
    );
    let expired = StoredAuthorizationCode {
        code_hash: "code-hash-expired".into(),
        expires_at: ts("2026-06-19T00:04:00Z"),
        consumed_at: None,
        ..AuthCodeRepository::get(store, "code-hash-live")
            .unwrap()
            .unwrap()
    };
    AuthCodeRepository::create(store, expired).unwrap();
    assert!(
        !AuthCodeRepository::consume_if_live(
            store,
            "code-hash-expired",
            &ts("2026-06-19T00:05:00Z")
        )
        .unwrap()
    );
    OAuthClientRepository::remove(store, "awaken-runtime").unwrap();

    // --- api tokens: unique id + prefix, prefix lookup, in-place revoke ---
    let token = ApiToken {
        id: ApiTokenId("tok_1".into()),
        prefix: ApiTokenPrefix("pfx_1".into()),
        principal: service("ci"),
        secret_hash: "$argon2id$hash".into(),
        workspace: WorkspaceId("wrkspc_default".into()),
        created_at: ts("2026-06-19T00:00:00Z"),
        expires_at: None,
        revoked_at: None,
    };
    ApiTokenRepository::create(store, token.clone()).unwrap();
    assert!(matches!(
        ApiTokenRepository::create(store, token.clone()),
        Err(RepositoryError::Conflict(_))
    ));
    let mut dup_prefix = token.clone();
    dup_prefix.id = ApiTokenId("tok_2".into());
    assert!(
        matches!(
            ApiTokenRepository::create(store, dup_prefix),
            Err(RepositoryError::Conflict(_))
        ),
        "duplicate prefix must conflict"
    );
    assert_eq!(
        store
            .get_by_prefix(&ApiTokenPrefix("pfx_1".into()))
            .unwrap()
            .unwrap()
            .workspace,
        WorkspaceId("wrkspc_default".into())
    );
    assert_eq!(
        ApiTokenRepository::list_for_principal(store, &service("ci"))
            .unwrap()
            .len(),
        1
    );
    let mut revoked = token;
    revoked.revoked_at = Some(ts("2026-06-19T02:00:00Z"));
    ApiTokenRepository::update(store, revoked).unwrap();
    assert!(
        ApiTokenRepository::get(store, &ApiTokenId("tok_1".into()))
            .unwrap()
            .unwrap()
            .revoked_at
            .is_some()
    );

    // --- directory: orgs, groups, roles round-trip and remove fail-closed ---
    let org = Organization {
        id: OrgId("acme".into()),
        display_name: Some("Acme".into()),
        owner: PrincipalRef::Account {
            account_id: AccountId("a".into()),
        },
        created_at: ts("2026-06-21T00:00:00Z"),
        updated_at: ts("2026-06-21T00:00:00Z"),
    };
    OrgRepository::upsert(store, org.clone()).unwrap();
    assert_eq!(
        OrgRepository::get(store, &OrgId("acme".into())).unwrap(),
        Some(org)
    );
    assert_eq!(OrgRepository::list(store).unwrap().len(), 1);
    assert!(matches!(
        OrgRepository::remove(store, &OrgId("ghost".into())),
        Err(RepositoryError::NotFound(_))
    ));

    let group = Group {
        id: GroupId("eng".into()),
        org: OrgId("acme".into()),
        display_name: None,
        members: vec![
            service("ci"),
            PrincipalRef::Account {
                account_id: AccountId("a".into()),
            },
        ],
        created_at: ts("2026-06-21T00:00:00Z"),
        updated_at: ts("2026-06-21T00:00:00Z"),
    };
    GroupRepository::upsert(store, group.clone()).unwrap();
    assert_eq!(GroupRepository::get(store, &group.id).unwrap(), Some(group));
    GroupRepository::remove(store, &GroupId("eng".into())).unwrap();
    assert!(matches!(
        GroupRepository::remove(store, &GroupId("eng".into())),
        Err(RepositoryError::NotFound(_))
    ));

    let role = RoleDef {
        id: RoleId("publisher".into()),
        display_name: Some("Publisher".into()),
        action_patterns: vec![
            ActionPattern("pack.*".into()),
            ActionPattern("pack.read".into()),
        ],
        created_at: ts("2026-06-21T00:00:00Z"),
        updated_at: ts("2026-06-21T00:00:00Z"),
    };
    RoleRepository::upsert(store, role.clone()).unwrap();
    assert_eq!(RoleRepository::get(store, &role.id).unwrap(), Some(role));
    assert_eq!(RoleRepository::list(store).unwrap().len(), 1);

    // Cause-effect decision table for the cross-backend Directory authority:
    // R1 valid root + qualified product space -> node, binding, audit and one
    // revision advance commit together; R2 arbitrary live child -> accepted;
    // R3 retire/activate binding -> status and revision commit while the live
    // node remains unchanged; R4 ancestor moved below its descendant -> conflict
    // with no revision advance; R5 parent with live child -> archive conflict;
    // R6 leaf -> archive commits and disappears from live children. The same
    // rules execute through this harness for SQLite and required Postgres,
    // proving one SQL path.
    let directory_node = |id: &str, parent: Option<&str>| DirectoryNode {
        id: DirectoryNodeId(id.into()),
        org_id: OrgId("acme".into()),
        parent_id: parent.map(|value| DirectoryNodeId(value.into())),
        name: id.into(),
        slug: id.into(),
        description: None,
        archived: false,
        created_at: ts("2026-06-21T00:00:00Z"),
        updated_at: ts("2026-06-21T00:00:00Z"),
    };
    let directory_actor = PrincipalRef::Service {
        service_id: "sql-conformance".into(),
    };
    assert_eq!(
        DirectoryRepository::create_directory_node(
            store,
            directory_node("root", None),
            Some(ProductSpacePlacement {
                product_space: ProductSpaceRef {
                    product_id: awaken_iam_contract::ProductId::new("agents").unwrap(),
                    space_id: "space-a".into(),
                },
                org_id: OrgId("acme".into()),
                node_id: DirectoryNodeId("root".into()),
                status: awaken_iam_contract::ProductSpacePlacementStatus::Active,
            }),
            &directory_actor,
        )
        .unwrap(),
        2
    );
    DirectoryRepository::create_directory_node(
        store,
        directory_node("team", Some("root")),
        None,
        &directory_actor,
    )
    .unwrap();
    assert_eq!(
        DirectoryRepository::product_space_placement(
            store,
            &OrgId("acme".into()),
            &ProductSpaceRef {
                product_id: awaken_iam_contract::ProductId::new("agents").unwrap(),
                space_id: "space-a".into(),
            }
        )
        .unwrap()
        .unwrap()
        .node_id,
        DirectoryNodeId("root".into())
    );
    let product_space = ProductSpaceRef {
        product_id: awaken_iam_contract::ProductId::new("agents").unwrap(),
        space_id: "space-a".into(),
    };
    let before_retire =
        DirectoryRepository::directory_revision(store, &OrgId("acme".into())).unwrap();
    assert_eq!(
        DirectoryRepository::set_product_space_placement_status(
            store,
            &OrgId("acme".into()),
            &product_space,
            awaken_iam_contract::ProductSpacePlacementStatus::Retired,
            &ts("2026-06-21T00:30:00Z"),
            &directory_actor,
        )
        .unwrap(),
        before_retire + 1,
        "R3"
    );
    assert_eq!(
        DirectoryRepository::product_space_placement(store, &OrgId("acme".into()), &product_space)
            .unwrap()
            .unwrap()
            .status,
        awaken_iam_contract::ProductSpacePlacementStatus::Retired,
        "R3"
    );
    assert!(
        !DirectoryRepository::directory_node(store, &DirectoryNodeId("root".into()))
            .unwrap()
            .unwrap()
            .archived
    );
    DirectoryRepository::set_product_space_placement_status(
        store,
        &OrgId("acme".into()),
        &product_space,
        awaken_iam_contract::ProductSpacePlacementStatus::Active,
        &ts("2026-06-21T00:31:00Z"),
        &directory_actor,
    )
    .unwrap();
    let before_rejection =
        DirectoryRepository::directory_revision(store, &OrgId("acme".into())).unwrap();
    assert!(matches!(
        DirectoryRepository::move_directory_node(
            store,
            &DirectoryNodeId("root".into()),
            Some(&DirectoryNodeId("team".into())),
            &ts("2026-06-21T01:00:00Z"),
            &directory_actor,
        ),
        Err(RepositoryError::Conflict(_))
    ));
    assert_eq!(
        DirectoryRepository::directory_revision(store, &OrgId("acme".into())).unwrap(),
        before_rejection
    );
    DirectoryRepository::update_directory_node(
        store,
        &DirectoryNodeId("team".into()),
        "Platform team",
        "platform-team",
        Some("renamed without moving"),
        &ts("2026-06-21T01:30:00Z"),
        &directory_actor,
    )
    .unwrap();
    let renamed = DirectoryRepository::directory_node(store, &DirectoryNodeId("team".into()))
        .unwrap()
        .unwrap();
    assert_eq!(renamed.slug, "platform-team");
    assert_eq!(renamed.parent_id, Some(DirectoryNodeId("root".into())));
    assert!(matches!(
        DirectoryRepository::archive_directory_node(
            store,
            &DirectoryNodeId("root".into()),
            &ts("2026-06-21T02:00:00Z"),
            &directory_actor,
        ),
        Err(RepositoryError::Conflict(_))
    ));
    DirectoryRepository::archive_directory_node(
        store,
        &DirectoryNodeId("team".into()),
        &ts("2026-06-21T02:00:00Z"),
        &directory_actor,
    )
    .unwrap();
    assert!(
        DirectoryRepository::directory_children(
            store,
            &OrgId("acme".into()),
            Some(&DirectoryNodeId("root".into()))
        )
        .unwrap()
        .1
        .is_empty()
    );

    // --- grants: put/get/list/remove, with a require-approval effect ---
    let grant = Grant {
        id: GrantId("g1".into()),
        subject: GrantSubject::Role(RoleId("publisher".into())),
        action_pattern: ActionPattern("pack.publish".into()),
        scope: ScopeRef::Org {
            org_id: OrgId("acme".into()),
        },
        effect: Effect::RequireApproval,
    };
    GrantRepository::put(store, grant.clone()).unwrap();
    assert_eq!(
        GrantRepository::get(store, &GrantId("g1".into())).unwrap(),
        Some(grant)
    );
    assert_eq!(GrantRepository::list(store).unwrap().len(), 1);
    GrantRepository::remove(store, &GrantId("g1".into())).unwrap();
    assert!(matches!(
        GrantRepository::remove(store, &GrantId("g1".into())),
        Err(RepositoryError::NotFound(_))
    ));

    // --- role bindings: idempotent add, filter, exact remove ---
    let binding = RoleBinding {
        principal: PrincipalRef::Account {
            account_id: AccountId("a".into()),
        },
        role: RoleId("publisher".into()),
        scope: ScopeRef::Global,
    };
    store.add(binding.clone()).unwrap();
    store.add(binding.clone()).unwrap(); // idempotent
    assert_eq!(RoleBindingRepository::list(store).unwrap().len(), 1);
    assert_eq!(
        RoleBindingRepository::list_for_principal(store, &binding.principal)
            .unwrap()
            .len(),
        1
    );
    RoleBindingRepository::remove(store, &binding).unwrap();
    assert!(matches!(
        RoleBindingRepository::remove(store, &binding),
        Err(RepositoryError::NotFound(_))
    ));

    // --- resource edges: upsert and list ---
    store
        .put_edge(ResourceEdge {
            resource_type: ResourceType("issue".into()),
            resource_id: ResourceId("42".into()),
            parent: ScopeRef::Org {
                org_id: OrgId("acme".into()),
            },
        })
        .unwrap();
    assert_eq!(store.list_edges().unwrap().len(), 1);

    let workspace_edge = WorkspaceOrgEdge {
        workspace_id: WorkspaceId("ws_flow".into()),
        org_id: OrgId("acme".into()),
    };
    store.put_workspace_org(workspace_edge.clone()).unwrap();
    store.put_workspace_org(workspace_edge.clone()).unwrap();
    assert_eq!(
        store.workspace_org(&WorkspaceId("ws_flow".into())).unwrap(),
        Some(workspace_edge.clone())
    );
    assert_eq!(store.list_workspace_orgs().unwrap(), vec![workspace_edge]);

    // --- plans + subscriptions: quota and rate-limit JSON round-trip ---
    let plan = Plan::new(
        PlanId("pro".into()),
        PlanTier::Pro,
        ["pack.read", "pack.publish"],
    )
    .with_quota("pack.publish", Quota::Limited(100))
    .with_quota("seats", Quota::Unlimited)
    .with_rate_limit("pack.read", RateLimit::new(50, RateWindow::Minute));
    PlanRepository::put(store, plan.clone()).unwrap();
    assert_eq!(
        PlanRepository::get(store, &PlanId("pro".into())).unwrap(),
        Some(plan)
    );
    assert_eq!(PlanRepository::list(store).unwrap().len(), 1);
    let principal = PrincipalRef::Account {
        account_id: AccountId("a".into()),
    };
    assert_eq!(store.subscription(&principal).unwrap(), None);
    store
        .subscribe(principal.clone(), PlanId("pro".into()))
        .unwrap();
    store
        .subscribe(principal.clone(), PlanId("pro".into()))
        .unwrap(); // replace
    assert_eq!(
        store.subscription(&principal).unwrap(),
        Some(PlanId("pro".into()))
    );

    // --- audit: append-only, read back in append order ---
    AuditSink::record(
        store,
        AuditEvent {
            at: ts("2026-06-19T00:00:00Z"),
            actor: Some(service("ci")),
            action: "grant.put".into(),
            detail: "first".into(),
        },
    )
    .unwrap();
    AuditSink::record(
        store,
        AuditEvent {
            at: ts("2026-06-19T00:01:00Z"),
            actor: None,
            action: "grant.revoke".into(),
            detail: "second".into(),
        },
    )
    .unwrap();
    let events = AuditSink::events(store).unwrap();
    assert_eq!(
        events
            .iter()
            .filter(|event| event.action.starts_with("directory."))
            .count(),
        6,
        "node create/update/archive plus product retire/activate are audited"
    );
    let tail = &events[events.len() - 2..];
    assert_eq!(tail[0].detail, "first");
    assert_eq!(tail[0].actor, Some(service("ci")));
    assert_eq!(tail[1].detail, "second");
    assert_eq!(tail[1].actor, None);
}

#[test]
fn sqlite_backend_serves_every_repository() {
    let store = sqlite_in_memory_store("iam").expect("migrate sqlite");
    exercise_every_repository(&store);
}

#[test]
fn sqlite_isolates_a_sibling_by_prefix_in_one_database() {
    // Two prefixes over the same connection are independent schemas: the same
    // assembly deploys embedded next to siblings purely by prefix.
    let backend = awaken_iam_server::SqliteBackend::open_in_memory().expect("open");
    let iam = awaken_iam_server::sqlite_migrated_store(backend.clone(), "iam").expect("iam");
    let other = awaken_iam_server::sqlite_migrated_store(backend, "iamx").expect("iamx");
    AccountRepository::upsert(&iam, account("only-in-iam")).unwrap();
    assert_eq!(AccountRepository::list(&iam).unwrap().len(), 1);
    assert_eq!(AccountRepository::list(&other).unwrap().len(), 0);
}

#[test]
fn postgres_profile_head_and_policy_version_commit_together_when_configured() {
    let Ok(url) = std::env::var("IAM_TEST_POSTGRES_URL") else {
        return;
    };
    let schema = IsolatedPostgresSchema::create(&url, "iam_profile_fence");
    let writer = postgres_migrated_store(&schema.url, "iam").expect("migrate profile schema");
    let reader = postgres_migrated_store(&schema.url, "iam").expect("open second store handle");
    let namespace = NamespaceId("awaken.runtime".into());
    for revision in 1..=2 {
        writer
            .create_profile(AuthorizationProfile {
                namespace: namespace.clone(),
                revision,
                lifecycle: ProfileLifecycle::Validated,
                document: AuthorizationProfileDocument::default(),
                checksum: format!("revision-{revision}"),
                created_at: ts("2026-10-01T00:00:00Z"),
            })
            .expect("create validated profile");
    }
    assert_eq!(reader.fence().unwrap().version, 1);
    assert_eq!(
        writer.activate_profile(&namespace, 1, None).unwrap(),
        (None, 2)
    );
    assert_eq!(reader.fence().unwrap().version, 2);
    assert_eq!(
        reader.active_profile(&namespace).unwrap().unwrap().revision,
        1
    );

    assert!(matches!(
        writer.activate_profile(&namespace, 2, None),
        Err(RepositoryError::Conflict(_))
    ));
    assert_eq!(reader.fence().unwrap().version, 2);
    assert_eq!(
        writer.activate_profile(&namespace, 2, Some(1)).unwrap(),
        (Some(1), 3)
    );
    assert_eq!(reader.fence().unwrap().version, 3);
    assert_eq!(
        reader.active_profile(&namespace).unwrap().unwrap().revision,
        2
    );

    assert!(matches!(
        writer.retire_active_profile(&namespace, 1),
        Err(RepositoryError::Conflict(_))
    ));
    assert_eq!(reader.fence().unwrap().version, 3);
    assert_eq!(
        reader.active_profile(&namespace).unwrap().unwrap().revision,
        2
    );
    let (retired, version) = writer.retire_active_profile(&namespace, 2).unwrap();
    assert_eq!(retired.revision, 2);
    assert_eq!(version, 4);
    assert_eq!(reader.fence().unwrap().version, 4);
    assert!(reader.active_profile(&namespace).unwrap().is_none());
}

#[test]
fn postgres_product_projection_is_atomic_and_fenced_when_configured() {
    let Ok(url) = std::env::var("IAM_TEST_POSTGRES_URL") else {
        return;
    };
    let schema = IsolatedPostgresSchema::create(&url, "iam_projection");
    let store = postgres_migrated_store(&schema.url, "iam").expect("migrate projection schema");
    OrgRepository::upsert(
        &store,
        Organization {
            id: OrgId("org-a".into()),
            display_name: None,
            owner: PrincipalRef::Service {
                service_id: "owner".into(),
            },
            created_at: ts("2026-01-01T00:00:00Z"),
            updated_at: ts("2026-01-01T00:00:00Z"),
        },
    )
    .unwrap();
    ResourceModelRepository::put_workspace_org(
        &store,
        WorkspaceOrgEdge {
            workspace_id: WorkspaceId("workspace-a".into()),
            org_id: OrgId("org-a".into()),
        },
    )
    .unwrap();
    let model: awaken_iam_contract::ProductResourceModelRequest = serde_json::from_value(serde_json::json!({
        "product_id": "tutor",
        "resource_model": {
            "resource_types": [{"resource_type": "tutor.campus", "actions": ["tutor.campus.manage"]}],
            "actions": [], "edges": []
        }
    })).unwrap();
    store.register_product_resource_model(&model).unwrap();
    let created: awaken_iam_contract::ResourceProjectionBatch = serde_json::from_value(serde_json::json!({
        "product_id":"tutor", "org_id":"org-a", "projection_id":"campus:1",
        "idempotency_key":"campus:1:1", "epoch":1,
        "grants":[{"id":"campus-1-manage","subject":{"kind":"principal","principal":{"kind":"service","service_id":"owner"}},
            "action_pattern":"tutor.campus.manage", "scope":{"kind":"resource","resource_type":"tutor.campus","resource_id":"1"},"effect":"allow"}],
        "scope_edges":[{"resource_type":"tutor.campus","resource_id":"1","parent":{"kind":"workspace","workspace_id":"workspace-a"}}],
        "retirements":[]
    })).unwrap();
    let first = store.apply_resource_projection(&created).unwrap();
    assert_eq!(
        first.disposition,
        awaken_iam_contract::ResourceProjectionDisposition::Applied
    );
    assert_eq!(GrantRepository::list(&store).unwrap().len(), 1);
    let mut retired = created.clone();
    retired.epoch = 2;
    retired.idempotency_key = "campus:1:2".into();
    retired.grants.clear();
    retired.scope_edges.clear();
    retired.retirements = vec![awaken_iam_contract::ResourceRetirement {
        resource_type: ResourceType("tutor.campus".into()),
        resource_id: ResourceId("1".into()),
        grant_ids: vec!["campus-1-manage".into()],
    }];
    let second = store.apply_resource_projection(&retired).unwrap();
    assert_eq!(second.version, first.version + 1);
    assert!(GrantRepository::list(&store).unwrap().is_empty());
    assert_eq!(
        store
            .apply_resource_projection(&created)
            .unwrap()
            .disposition,
        awaken_iam_contract::ResourceProjectionDisposition::Stale
    );
    let start = Arc::new(Barrier::new(2));
    let mut joins = Vec::new();
    for suffix in ["2", "3"] {
        let mut next = created.clone();
        next.projection_id = format!("campus:{suffix}");
        next.idempotency_key = format!("campus:{suffix}:1");
        next.grants[0].id = format!("campus-{suffix}-manage");
        next.grants[0].scope = ScopeRef::Resource {
            resource_type: ResourceType("tutor.campus".into()),
            resource_id: ResourceId(suffix.into()),
        };
        next.scope_edges[0].resource_id = ResourceId(suffix.into());
        let sibling = store.clone();
        let start = start.clone();
        joins.push(thread::spawn(move || {
            start.wait();
            sibling.apply_resource_projection(&next).unwrap()
        }));
    }
    let versions = joins
        .into_iter()
        .map(|join| join.join().unwrap().version)
        .collect::<Vec<_>>();
    assert_eq!(versions.len(), 2);
    assert_ne!(versions[0], versions[1]);
    assert_eq!(GrantRepository::list(&store).unwrap().len(), 2);
    let mut exact = created.clone();
    exact.projection_id = "campus:4".into();
    exact.idempotency_key = "campus:4:1".into();
    exact.grants[0].id = "campus-4-manage".into();
    exact.grants[0].scope = ScopeRef::Resource {
        resource_type: ResourceType("tutor.campus".into()),
        resource_id: ResourceId("4".into()),
    };
    exact.scope_edges[0].resource_id = ResourceId("4".into());
    let start = Arc::new(Barrier::new(2));
    let mut joins = Vec::new();
    for _ in 0..2 {
        let sibling = store.clone();
        let duplicate = exact.clone();
        let start = start.clone();
        joins.push(thread::spawn(move || {
            start.wait();
            sibling.apply_resource_projection(&duplicate).unwrap()
        }));
    }
    let receipts = joins
        .into_iter()
        .map(|join| join.join().unwrap())
        .collect::<Vec<_>>();
    assert_eq!(receipts[0].version, receipts[1].version);
    assert!(receipts.iter().any(|receipt| receipt.disposition
        == awaken_iam_contract::ResourceProjectionDisposition::Applied));
    assert!(receipts.iter().any(|receipt| receipt.disposition
        == awaken_iam_contract::ResourceProjectionDisposition::Replayed));
}

#[tokio::test]
async fn postgres_backend_serves_every_repository_when_configured() {
    // Cause/effect graph: C1=the complete Postgres port suite runs inside an
    // entered Tokio host, C2=connect/query/transaction/migration use the
    // synchronous driver. E1=every call crosses the adapter-owned plain-thread
    // boundary; E2=all repository effects match the shared backend contract;
    // E3=no nested-runtime panic occurs.
    //
    // Decision table: configured+C1+C2 -> E1+E2+E3; unconfigured -> explicit
    // skip; configured+plain caller is covered by the same shared port harness
    // through production migration callers and does not select this regression
    // branch. Backend errors remain fail-closed through the existing assertions.
    let Ok(url) = std::env::var("IAM_TEST_POSTGRES_URL") else {
        eprintln!("skipping: set IAM_TEST_POSTGRES_URL to run the Postgres backend e2e");
        return;
    };
    // The migration bundle remains the only table inventory. An isolated schema
    // gives this harness a repeatable empty authority without duplicating that
    // inventory in test cleanup or colliding with another PostgreSQL test.
    let schema = IsolatedPostgresSchema::create(&url, "iam_store_e2e");
    let store = postgres_migrated_store(&schema.url, "iam").expect("migrate postgres");
    exercise_every_repository(&store);

    // Cause/effect graph: C1=multiple processes may issue the same canonical
    // ensure against PostgreSQL, C2=the Org fence and unique key serialize the
    // race. E1=one placement wins, E2=all callers observe one node/revision,
    // E3=only one root is durable. Decision rule C1+C2 -> E1+E2+E3 proves the
    // production backend, not only SQLite, enforces idempotency.
    let org_id = OrgId("postgres-directory-race".into());
    OrgRepository::upsert(
        &store,
        Organization {
            id: org_id.clone(),
            display_name: Some("Postgres directory race".into()),
            owner: service("postgres-directory-test"),
            created_at: ts("2026-08-27T00:00:00Z"),
            updated_at: ts("2026-08-27T00:00:00Z"),
        },
    )
    .unwrap();
    let product_id = ProductId::new("agents").unwrap();
    let barrier = Arc::new(Barrier::new(8));
    let handles = (0..8)
        .map(|_| {
            let directory = DirectoryApi::new(store.clone());
            let barrier = barrier.clone();
            let org_id = org_id.clone();
            let product_id = product_id.clone();
            thread::spawn(move || {
                barrier.wait();
                directory
                    .ensure_product_space_placement(
                        EnsureProductSpacePlacement {
                            product_space: ProductSpaceRef {
                                product_id: product_id.clone(),
                                space_id: "workspace/shared-race".into(),
                            },
                            org_id,
                            parent_product_space: None,
                            name: "Shared race".into(),
                            preferred_slug: "shared-race".into(),
                            description: None,
                        },
                        DirectoryCommandContext::product_service(
                            product_id,
                            "postgres-directory-test",
                            ts("2026-08-27T00:00:01Z"),
                        ),
                    )
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
        "E1"
    );
    assert!(results.iter().all(|result| result.revision == 2), "E2");
    assert!(
        results
            .iter()
            .all(|result| result.node.id == results[0].node.id),
        "E2"
    );
    let roots = DirectoryApi::new(store.clone())
        .children(&OrgId("postgres-directory-race".into()), None)
        .unwrap();
    assert_eq!(roots.nodes.len(), 1, "E3");
    assert_eq!(roots.revision, 2, "E3");

    // Cause/effect graph: C1 two cloned PostgreSQL store handles load the same
    // two roots, C2 inverse moves start together, C3 the backend serializes each
    // transaction through the Org revision fence before ancestry validation.
    // E1 exactly one move commits, E2 the other observes the new ancestry and
    // rejects a cycle, E3 one revision/audit mutation is durable.
    //
    // Decision table:
    // | A parent | B parent | concurrent commands | effect |
    // | root | root | A->B and B->A | one success, one cycle refusal |
    // | B | root | replay A->B | no second cycle-producing mutation |
    // Constraint: this is the production PostgreSQL adapter; the SQLite P0
    // test covers the same domain rule but cannot prove row-lock serialization.
    let cycle_org = OrgId("postgres-directory-cycle".into());
    OrgRepository::upsert(
        &store,
        Organization {
            id: cycle_org.clone(),
            display_name: Some("Postgres directory cycle".into()),
            owner: service("postgres-directory-test"),
            created_at: ts("2026-08-27T00:01:00Z"),
            updated_at: ts("2026-08-27T00:01:00Z"),
        },
    )
    .unwrap();
    let directory = DirectoryApi::new(store.clone());
    let create = |name: &str| {
        directory
            .create_node(
                CreateDirectoryNode {
                    org_id: cycle_org.clone(),
                    parent_id: None,
                    name: name.into(),
                    preferred_slug: name.to_ascii_lowercase(),
                    description: None,
                },
                DirectoryCommandContext::service(
                    "postgres-directory-test",
                    ts("2026-08-27T00:01:01Z"),
                ),
            )
            .unwrap()
            .node
    };
    let a = create("A");
    let b = create("B");
    let barrier = Arc::new(Barrier::new(2));
    let attempts = [(a.id.clone(), b.id.clone()), (b.id.clone(), a.id.clone())]
        .into_iter()
        .map(|(node_id, parent_id)| {
            let directory = DirectoryApi::new(store.clone());
            let barrier = barrier.clone();
            thread::spawn(move || {
                barrier.wait();
                directory.move_node(
                    &node_id,
                    MoveDirectoryNode {
                        parent_id: Some(parent_id),
                    },
                    DirectoryCommandContext::service(
                        "postgres-directory-test",
                        ts("2026-08-27T00:01:02Z"),
                    ),
                )
            })
        })
        .collect::<Vec<_>>();
    let outcomes = attempts
        .into_iter()
        .map(|attempt| attempt.join().unwrap())
        .collect::<Vec<_>>();
    assert_eq!(
        outcomes.iter().filter(|result| result.is_ok()).count(),
        1,
        "E1"
    );
    assert_eq!(
        outcomes.iter().filter(|result| result.is_err()).count(),
        1,
        "E2"
    );
    let stored_a = directory.node(&a.id).unwrap().unwrap();
    let stored_b = directory.node(&b.id).unwrap().unwrap();
    assert!(
        (stored_a.parent_id.as_ref() == Some(&b.id) && stored_b.parent_id.is_none())
            || (stored_b.parent_id.as_ref() == Some(&a.id) && stored_a.parent_id.is_none()),
        "E2: the committed PostgreSQL graph remains acyclic"
    );
    assert_eq!(directory.revision(&cycle_org).unwrap(), 4, "E3");
}

#[test]
fn postgres_backend_clones_recover_after_transport_loss_when_configured() {
    // Cause/effect graph:
    // C1=all repository adapters clone one PostgresBackend connection pool;
    // C2=Postgres terminates its sole slot after startup;
    // C3=checkout validation either detects the stale slot before SQL or the
    //    operation itself observes the transport loss;
    // C4=a replacement connection is available to a subsequent checkout.
    // E1=the write closure runs at most once (zero or one durable effect);
    // E2=the pool discards the broken client;
    // E3=both clones use one replacement connection with a different PID.
    //
    // Decision table:
    // | stale known at checkout | replacement | write outcome | effects    |
    // | yes                     | available   | success       | E1+E2+E3   |
    // | no; fails during SQL    | later avail | error         | E1+E2+E3*  |
    // | yes                     | unavailable | pool error    | E2, no SQL |
    // `*` is the unavoidable response-loss/COMMIT ambiguity. The adapter must
    // never replay that write; callers reconcile from durable state under their
    // own idempotency fence. This test admits the ambiguity but rejects a second
    // effect and proves a subsequent read recovers the sole shared slot.
    let Ok(url) = std::env::var("IAM_TEST_POSTGRES_URL") else {
        eprintln!("skipping: set IAM_TEST_POSTGRES_URL to run the reconnect e2e");
        return;
    };

    let backend = PostgresBackend::connect(&url).expect("connect shared backend");
    let clone = backend.clone();
    let initial_pid = backend
        .query("SELECT pg_backend_pid()::text", &[])
        .expect("read initial PID")[0][0]
        .as_deref()
        .expect("PID cell")
        .parse::<i32>()
        .expect("PID integer");
    let clone_pid = clone
        .query("SELECT pg_backend_pid()::text", &[])
        .expect("clone reads PID")[0][0]
        .as_deref()
        .expect("clone PID cell")
        .parse::<i32>()
        .expect("clone PID integer");
    assert_eq!(clone_pid, initial_pid, "clones share one connection slot");

    let mut admin = postgres::Client::connect(&url, postgres::NoTls).expect("admin connection");
    let table = format!(
        "iam_reconnect_{}_{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("wall clock")
            .as_nanos()
    );
    admin
        .batch_execute(&format!("CREATE TABLE {table} (value BIGINT NOT NULL)"))
        .expect("create reconnect fixture");
    assert!(
        admin
            .query_one("SELECT pg_terminate_backend($1)", &[&initial_pid])
            .expect("terminate initial backend")
            .get::<_, bool>(0),
        "initial backend must be terminated"
    );

    let _write_result = backend.execute(&format!("INSERT INTO {table} VALUES (1)"), &[]);

    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
    let replacement_pid = loop {
        if let Ok(rows) = clone.query("SELECT pg_backend_pid()::text", &[])
            && let Some(Some(value)) = rows.first().and_then(|row| row.first())
        {
            break value.parse::<i32>().expect("replacement PID integer");
        }
        assert!(
            std::time::Instant::now() < deadline,
            "shared connection slot did not recover before deadline"
        );
        std::thread::sleep(std::time::Duration::from_millis(100));
    };
    assert_ne!(replacement_pid, initial_pid);
    assert_eq!(
        backend
            .query("SELECT pg_backend_pid()::text", &[])
            .expect("original handle uses replacement")[0][0]
            .as_deref()
            .expect("replacement PID cell")
            .parse::<i32>()
            .expect("replacement PID integer"),
        replacement_pid,
        "every clone must observe the one replacement connection"
    );

    let effects: i64 = admin
        .query_one(&format!("SELECT count(*) FROM {table}"), &[])
        .expect("count durable effects")
        .get(0);
    assert!(effects <= 1, "an interrupted write must never be replayed");
    admin
        .batch_execute(&format!("DROP TABLE {table}"))
        .expect("drop reconnect fixture");
}
