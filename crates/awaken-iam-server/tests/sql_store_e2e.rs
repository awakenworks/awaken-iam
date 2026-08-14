//! End-to-end proof that the real database adapters are switchable behind the
//! repository ports (ADR-0003).
//!
//! One harness, [`exercise_every_port`], drives every IAM repository port through
//! its success, failure, and guardrail paths against an [`SqlStore`] without
//! naming a backend. It runs unconditionally against SQLite (a migrated
//! in-memory database) and, when `IAM_TEST_POSTGRES_URL` is set, against a real
//! Postgres instance — the same assertions passing on both is the switchability
//! the ADR promises. Selecting the backend is configuration, not a code fork.

use awaken_iam_contract::{
    Account, AccountId, AccountStatus, ApiToken, ApiTokenId, ApiTokenPrefix, ExternalIdentity,
    ExternalIdentityClaims, ExternalIdentityId, ExternalIdentityKey, ExternalSubject,
    IdentityProviderKey, OAuthLoginState, OAuthLoginStateId, OrgId, PrincipalRef, ResourceId,
    ResourceType, ScopeRef, Session, SessionId, Timestamp, WorkspaceId, WorkspaceOrgEdge,
};
use awaken_iam_core::{
    AccountIdentityRepo, AccountRepo, ActionPattern, ApiTokenRepo, AuditEvent, AuditSink,
    AuthCodeRepo, Effect, ExternalIdentityRepo, Grant, GrantId, GrantRepo, GrantSubject, Group,
    GroupId, GroupRepo, LoginFlowRepo, OAuthClientRepo, OrgRepo, Organization, Plan, PlanId,
    PlanRepo, PlanTier, Quota, RateLimit, RateWindow, RegisteredClient, RepoError, ResourceEdge,
    ResourceModelRepo, RoleBinding, RoleBindingRepo, RoleDef, RoleId, RoleRepo, SessionRepo,
    StoredAuthorizationCode,
};
use awaken_iam_server::{
    PostgresBackend, SqlConn, SqlStore, postgres_migrated_store, sqlite_in_memory_store,
};

fn ts(value: &str) -> Timestamp {
    Timestamp(value.into())
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

/// Drive every repository port through its success, failure, and guardrail paths.
fn exercise_every_port<B: SqlConn>(store: &SqlStore<B>) {
    // --- accounts: upsert is idempotent replace; list is ordered ---
    assert_eq!(
        AccountRepo::get(store, &AccountId("a".into())).unwrap(),
        None
    );
    AccountRepo::upsert(store, account("a")).unwrap();
    AccountRepo::upsert(store, account("b")).unwrap();
    let mut replaced = account("a");
    replaced.display_name = Some("Renamed".into());
    AccountRepo::upsert(store, replaced).unwrap();
    let accounts = AccountRepo::list(store).unwrap();
    assert_eq!(accounts.len(), 2);
    assert_eq!(accounts[0].id.0, "a");
    assert_eq!(accounts[0].display_name.as_deref(), Some("Renamed"));

    // --- external identities: unique by (provider, subject); claims refresh ---
    store.link(external("e1", "a", "sub-1")).unwrap();
    let dup = store.link(external("e2", "a", "sub-1"));
    assert!(
        matches!(dup, Err(RepoError::Conflict(_))),
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
        Err(RepoError::NotFound(_))
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
    AccountIdentityRepo::provision(store, account("c"), external("e3", "c", "sub-3")).unwrap();
    assert!(
        AccountRepo::get(store, &AccountId("c".into()))
            .unwrap()
            .is_some()
    );
    assert!(matches!(
        AccountIdentityRepo::provision(store, account("orphan"), external("e4", "orphan", "sub-3")),
        Err(RepoError::Conflict(_))
    ));
    assert_eq!(
        AccountRepo::get(store, &AccountId("orphan".into())).unwrap(),
        None
    );
    ExternalIdentityRepo::link(store, external("e5", "c", "sub-5")).unwrap();
    let key_5 = ExternalIdentityKey {
        provider_key: IdentityProviderKey("github".into()),
        subject: ExternalSubject("sub-5".into()),
    };
    AccountIdentityRepo::unlink(store, &key_5, &AccountId("c".into())).unwrap();
    let key_3 = ExternalIdentityKey {
        provider_key: IdentityProviderKey("github".into()),
        subject: ExternalSubject("sub-3".into()),
    };
    assert!(matches!(
        AccountIdentityRepo::unlink(store, &key_3, &AccountId("c".into())),
        Err(RepoError::Conflict(_))
    ));
    assert!(
        ExternalIdentityRepo::get_by_key(store, &key_3)
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
    SessionRepo::create(store, session.clone()).unwrap();
    assert!(matches!(
        SessionRepo::create(store, session.clone()),
        Err(RepoError::Conflict(_))
    ));
    assert_eq!(
        store.get_by_token_hash("hash-1").unwrap().unwrap().id.0,
        "s1"
    );
    let mut revoked = session;
    revoked.revoked_at = Some(ts("2026-06-19T01:00:00Z"));
    SessionRepo::update(store, revoked).unwrap();
    assert!(
        SessionRepo::get(store, &SessionId("s1".into()))
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
        SessionRepo::update(store, ghost),
        Err(RepoError::NotFound(_))
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
    assert!(matches!(store.start(flow), Err(RepoError::Conflict(_))));
    assert_eq!(
        LoginFlowRepo::get(store, &OAuthLoginStateId("l1".into()))
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
        Err(RepoError::Conflict(_))
    ));
    assert!(matches!(
        store.mark_consumed(
            &OAuthLoginStateId("absent".into()),
            ts("2026-06-19T00:06:00Z")
        ),
        Err(RepoError::NotFound(_))
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
    OAuthClientRepo::upsert(store, client.clone()).unwrap();
    assert_eq!(
        OAuthClientRepo::get(store, "awaken-runtime").unwrap(),
        Some(client)
    );
    assert_eq!(OAuthClientRepo::list(store).unwrap().len(), 1);
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
    AuthCodeRepo::create(store, code.clone()).unwrap();
    assert_eq!(
        AuthCodeRepo::get(store, "code-hash-live").unwrap(),
        Some(code)
    );
    assert!(
        AuthCodeRepo::consume_if_live(store, "code-hash-live", &ts("2026-06-19T00:05:00Z"))
            .unwrap()
    );
    assert!(
        !AuthCodeRepo::consume_if_live(store, "code-hash-live", &ts("2026-06-19T00:06:00Z"))
            .unwrap()
    );
    let expired = StoredAuthorizationCode {
        code_hash: "code-hash-expired".into(),
        expires_at: ts("2026-06-19T00:04:00Z"),
        consumed_at: None,
        ..AuthCodeRepo::get(store, "code-hash-live").unwrap().unwrap()
    };
    AuthCodeRepo::create(store, expired).unwrap();
    assert!(
        !AuthCodeRepo::consume_if_live(store, "code-hash-expired", &ts("2026-06-19T00:05:00Z"))
            .unwrap()
    );
    OAuthClientRepo::remove(store, "awaken-runtime").unwrap();

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
    ApiTokenRepo::create(store, token.clone()).unwrap();
    assert!(matches!(
        ApiTokenRepo::create(store, token.clone()),
        Err(RepoError::Conflict(_))
    ));
    let mut dup_prefix = token.clone();
    dup_prefix.id = ApiTokenId("tok_2".into());
    assert!(
        matches!(
            ApiTokenRepo::create(store, dup_prefix),
            Err(RepoError::Conflict(_))
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
        ApiTokenRepo::list_for_principal(store, &service("ci"))
            .unwrap()
            .len(),
        1
    );
    let mut revoked = token;
    revoked.revoked_at = Some(ts("2026-06-19T02:00:00Z"));
    ApiTokenRepo::update(store, revoked).unwrap();
    assert!(
        ApiTokenRepo::get(store, &ApiTokenId("tok_1".into()))
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
    OrgRepo::upsert(store, org.clone()).unwrap();
    assert_eq!(
        OrgRepo::get(store, &OrgId("acme".into())).unwrap(),
        Some(org)
    );
    assert_eq!(OrgRepo::list(store).unwrap().len(), 1);
    assert!(matches!(
        OrgRepo::remove(store, &OrgId("ghost".into())),
        Err(RepoError::NotFound(_))
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
    GroupRepo::upsert(store, group.clone()).unwrap();
    assert_eq!(GroupRepo::get(store, &group.id).unwrap(), Some(group));
    GroupRepo::remove(store, &GroupId("eng".into())).unwrap();
    assert!(matches!(
        GroupRepo::remove(store, &GroupId("eng".into())),
        Err(RepoError::NotFound(_))
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
    RoleRepo::upsert(store, role.clone()).unwrap();
    assert_eq!(RoleRepo::get(store, &role.id).unwrap(), Some(role));
    assert_eq!(RoleRepo::list(store).unwrap().len(), 1);

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
    GrantRepo::put(store, grant.clone()).unwrap();
    assert_eq!(
        GrantRepo::get(store, &GrantId("g1".into())).unwrap(),
        Some(grant)
    );
    assert_eq!(GrantRepo::list(store).unwrap().len(), 1);
    GrantRepo::remove(store, &GrantId("g1".into())).unwrap();
    assert!(matches!(
        GrantRepo::remove(store, &GrantId("g1".into())),
        Err(RepoError::NotFound(_))
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
    assert_eq!(RoleBindingRepo::list(store).unwrap().len(), 1);
    assert_eq!(
        RoleBindingRepo::list_for_principal(store, &binding.principal)
            .unwrap()
            .len(),
        1
    );
    RoleBindingRepo::remove(store, &binding).unwrap();
    assert!(matches!(
        RoleBindingRepo::remove(store, &binding),
        Err(RepoError::NotFound(_))
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
    PlanRepo::put(store, plan.clone()).unwrap();
    assert_eq!(
        PlanRepo::get(store, &PlanId("pro".into())).unwrap(),
        Some(plan)
    );
    assert_eq!(PlanRepo::list(store).unwrap().len(), 1);
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
    assert_eq!(events.len(), 2);
    assert_eq!(events[0].detail, "first");
    assert_eq!(events[0].actor, Some(service("ci")));
    assert_eq!(events[1].detail, "second");
    assert_eq!(events[1].actor, None);
}

#[test]
fn sqlite_backend_serves_every_port() {
    let store = sqlite_in_memory_store("iam").expect("migrate sqlite");
    exercise_every_port(&store);
}

#[test]
fn sqlite_isolates_a_sibling_by_prefix_in_one_database() {
    // Two prefixes over the same connection are independent schemas: the same
    // assembly deploys embedded next to siblings purely by prefix.
    let backend = awaken_iam_server::SqliteBackend::open_in_memory().expect("open");
    let iam = awaken_iam_server::sqlite_migrated_store(backend.clone(), "iam").expect("iam");
    let other = awaken_iam_server::sqlite_migrated_store(backend, "iamx").expect("iamx");
    AccountRepo::upsert(&iam, account("only-in-iam")).unwrap();
    assert_eq!(AccountRepo::list(&iam).unwrap().len(), 1);
    assert_eq!(AccountRepo::list(&other).unwrap().len(), 0);
}

#[tokio::test]
async fn postgres_backend_serves_every_port_when_configured() {
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
    // Start from a clean slate so the shared harness's count assertions hold.
    let backend = PostgresBackend::connect(&url).expect("connect");
    for table in [
        "accounts",
        "external_identities",
        "sessions",
        "login_flows",
        "api_tokens",
        "orgs",
        "groups",
        "roles",
        "grants",
        "role_bindings",
        "resource_edges",
        "workspace_org_edges",
        "plans",
        "subscriptions",
        "audit_events",
        "schema_migrations",
    ] {
        backend
            .execute(&format!("DROP TABLE IF EXISTS iam_{table} CASCADE"), &[])
            .expect("drop");
    }
    let store = postgres_migrated_store(&url, "iam").expect("migrate postgres");
    exercise_every_port(&store);
}
