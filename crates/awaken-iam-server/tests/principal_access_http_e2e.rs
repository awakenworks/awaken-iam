//! Real HTTP proof for fenced team access replacement (ADR-0018).
//!
//! Credential rules C1-C5 and fence rules F1-F5 are named in
//! `admin_http/principal_access.rs` and `admin_api/principal_access.rs`. Two
//! daemons share one SQLite store, as replicas do in production.

use std::sync::{Arc, Mutex};
use std::time::Duration;

use awaken_iam_contract::{
    AccessFence, AccountId, ActionKey, AuthorizationDecision, AuthorizationOutcome,
    AuthorizationRequest, NamespaceId, OrgId, PrincipalRef, ScopeRef, TeamAccessReceipt,
    TeamAccessReplacement, Timestamp, WorkspaceId, WorkspaceOrgEdge,
};
use awaken_iam_core::{
    ActionPattern, ApiTokenDirectory, ApiTokenMinter, ApiTokenOwnerRepository, ApiTokenRepository,
    AuthorizationProfileRepository, Effect, Grant, GrantId, GrantRepository, GrantSubject, Group,
    GroupId, GroupRepository, MintApiToken, OrgRepository, Organization, OsEntropy, PolicySet,
    ResourceModelRepository, RoleId,
};
use awaken_iam_server::{
    ACTION_AUTHZ_PROFILE_READ, ACTION_PRINCIPAL_ACCESS_REPLACE, AdminAuthPolicy, AuthApi, AuthzApi,
    DaemonState, SqlStore, SqliteBackend, daemon_router, http, principal_access_router,
    sqlite_in_memory_store,
};

const NAMESPACE: &str = "awaken.flow.business.w1";

fn at() -> Timestamp {
    Timestamp("2026-10-31T00:00:00Z".into())
}

fn alice() -> PrincipalRef {
    PrincipalRef::Account {
        account_id: AccountId("alice".into()),
    }
}

fn service(id: &str) -> PrincipalRef {
    PrincipalRef::Service {
        service_id: id.into(),
    }
}

fn workspace() -> ScopeRef {
    ScopeRef::Workspace {
        workspace_id: WorkspaceId("w1".into()),
    }
}

fn allow(id: &str, principal: PrincipalRef, action: &str, scope: ScopeRef) -> Grant {
    Grant {
        id: GrantId(id.into()),
        subject: GrantSubject::Principal(principal),
        action_pattern: ActionPattern(action.into()),
        scope,
        effect: Effect::Allow,
    }
}

/// Mint a token into the durable store; `owned` uses the accountable
/// service-account path, otherwise the generic mint records no owner.
fn mint(store: &SqlStore<SqliteBackend>, id: &str, principal: PrincipalRef, owned: bool) -> String {
    let mut directory = ApiTokenDirectory::new();
    let mut policy = PolicySet::default();
    let request = MintApiToken {
        id: awaken_iam_contract::ApiTokenId(id.into()),
        principal,
        workspace: WorkspaceId("w1".into()),
        role: RoleId("viewer".into()),
        created_at: at(),
        expires_at: Some(Timestamp("2099-01-01T00:00:00Z".into())),
    };
    let mut minter = ApiTokenMinter::new(OsEntropy);
    let issued = if owned {
        minter
            .mint_service_account(
                &mut directory,
                &mut policy,
                request,
                AccountId("owner".into()),
            )
            .unwrap()
            .issued
    } else {
        minter.mint(&mut directory, &mut policy, request).unwrap()
    };
    ApiTokenRepository::create(store, issued.token.clone()).unwrap();
    if owned {
        store
            .record_api_token_owner(&issued.token.id, &AccountId("owner".into()))
            .unwrap();
    }
    issued.secret
}

struct Tokens {
    flow: String,
    unowned: String,
    ungranted: String,
    account: String,
}

fn seed(store: &SqlStore<SqliteBackend>) -> Tokens {
    OrgRepository::upsert(
        store,
        Organization {
            id: OrgId("o1".into()),
            display_name: Some("o1".into()),
            owner: alice(),
            created_at: at(),
            updated_at: at(),
        },
    )
    .unwrap();
    ResourceModelRepository::put_workspace_org(
        store,
        WorkspaceOrgEdge {
            workspace_id: WorkspaceId("w1".into()),
            org_id: OrgId("o1".into()),
        },
    )
    .unwrap();
    GroupRepository::upsert(
        store,
        Group {
            id: GroupId("awaken.flow:sales".into()),
            org: OrgId("o1".into()),
            display_name: Some("Sales".into()),
            members: vec![PrincipalRef::Account {
                account_id: AccountId("bob".into()),
            }],
            created_at: at(),
            updated_at: at(),
        },
    )
    .unwrap();
    for grant in [
        allow(
            "flow-replace",
            service("flow-personnel"),
            ACTION_PRINCIPAL_ACCESS_REPLACE,
            workspace(),
        ),
        allow(
            "flow-profile",
            service("flow-personnel"),
            ACTION_AUTHZ_PROFILE_READ,
            ScopeRef::Namespace {
                namespace_id: NamespaceId(NAMESPACE.into()),
            },
        ),
        allow(
            "unowned-replace",
            service("unowned"),
            ACTION_PRINCIPAL_ACCESS_REPLACE,
            workspace(),
        ),
        allow(
            "account-replace",
            alice(),
            ACTION_PRINCIPAL_ACCESS_REPLACE,
            workspace(),
        ),
        allow("alice-work", alice(), "issue.write", workspace()),
    ] {
        GrantRepository::put(store, grant).unwrap();
    }
    Tokens {
        flow: mint(store, "tok-flow", service("flow-personnel"), true),
        unowned: mint(store, "tok-unowned", service("unowned"), false),
        ungranted: mint(store, "tok-ungranted", service("other"), true),
        account: mint(store, "tok-account", alice(), false),
    }
}

async fn serve(store: SqlStore<SqliteBackend>) -> String {
    let profiles: Arc<dyn AuthorizationProfileRepository> = Arc::new(store.clone());
    let state = Arc::new(Mutex::new(
        DaemonState::with_policy_store(
            AuthzApi::new(),
            AdminAuthPolicy::new(["admin-key".to_owned()]),
            profiles,
            store,
            AuthApi::new().token_authority(),
        )
        .unwrap(),
    ));
    let router = daemon_router(state.clone()).merge(principal_access_router(state));
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move { http::serve(listener, router).await.unwrap() });
    format!("http://{addr}")
}

fn command(teams: &[&str], suspended: bool, generation: u64, plan: &str) -> TeamAccessReplacement {
    TeamAccessReplacement {
        workspace_id: WorkspaceId("w1".into()),
        principal: alice(),
        managed: vec!["awaken.flow:sales".into(), "awaken.flow:support".into()],
        teams: teams
            .iter()
            .map(|team| format!("awaken.flow:{team}"))
            .collect(),
        suspended,
        fence: AccessFence {
            generation,
            plan_id: plan.into(),
        },
    }
}

async fn replace(
    client: &reqwest::Client,
    base: &str,
    token: Option<&str>,
    body: &TeamAccessReplacement,
) -> (u16, serde_json::Value) {
    let mut request = client
        .post(format!(
            "{base}/v1/admin/principal-access/team-replacements"
        ))
        .json(body);
    if let Some(token) = token {
        request = request.bearer_auth(token);
    }
    let response = request.send().await.unwrap();
    let status = response.status().as_u16();
    (
        status,
        response.json().await.unwrap_or(serde_json::Value::Null),
    )
}

async fn alice_may_work(client: &reqwest::Client, base: &str) -> bool {
    client
        .post(format!("{base}/v1/authorize"))
        .json(&AuthorizationRequest::direct(
            alice(),
            ActionKey("issue.write".into()),
            workspace(),
        ))
        .send()
        .await
        .unwrap()
        .json::<AuthorizationOutcome>()
        .await
        .unwrap()
        .decision
        == AuthorizationDecision::Allow
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn fenced_team_access_replacement_over_two_replicas() {
    let store = sqlite_in_memory_store("iam_principal_access").unwrap();
    let tokens = seed(&store);
    let first = serve(store.clone()).await;
    let second = serve(store.clone()).await;
    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(10))
        .build()
        .unwrap();
    let plan = command(&["sales"], false, 1, "record-1:join");

    assert_eq!(
        replace(&client, &first, None, &plan).await.0,
        401,
        "C3 none"
    );
    assert_eq!(
        replace(&client, &first, Some("awk_garbage"), &plan).await.0,
        401,
        "C3 unknown"
    );
    for (token, rule) in [
        (&tokens.unowned, "C4 unowned"),
        (&tokens.ungranted, "C4 ungranted"),
        (&tokens.account, "C4 account"),
    ] {
        assert_eq!(
            replace(&client, &first, Some(token), &plan).await.0,
            403,
            "{rule}"
        );
    }

    let (status, body) = replace(&client, &first, Some(&tokens.flow), &plan).await;
    assert_eq!(status, 200, "C2/F1 {body}");
    let receipt: TeamAccessReceipt = serde_json::from_value(body).unwrap();
    assert_eq!(receipt.teams, ["awaken.flow:sales"]);
    let sales = GroupRepository::get(&store, &GroupId("awaken.flow:sales".into()))
        .unwrap()
        .unwrap();
    assert_eq!(sales.members.len(), 2, "other members are kept: {sales:?}");
    assert!(alice_may_work(&client, &second).await, "no deny after join");

    // F3: the same plan through the other replica (a resumed host).
    let (status, body) = replace(&client, &second, Some(&tokens.flow), &plan).await;
    assert_eq!(status, 200, "F3 {body}");

    // F2: a newer departure plan suspends and removes the roster.
    let departure = command(&[], true, 2, "record-1:leave");
    let (status, body) = replace(&client, &second, Some("admin-key"), &departure).await;
    assert_eq!(status, 200, "C1/F2 {body}");
    assert!(
        !alice_may_work(&client, &first).await,
        "deny is live on the other replica"
    );

    // F5/F4: the superseded and a competing plan change nothing.
    for (stale, rule) in [
        (command(&["sales"], false, 1, "record-1:join"), "F5"),
        (command(&["support"], false, 2, "record-1:other"), "F4"),
    ] {
        let (status, body) = replace(&client, &first, Some(&tokens.flow), &stale).await;
        assert_eq!(status, 409, "{rule} {body}");
        assert_eq!(body["error"], "stale_access_fence", "{rule}");
    }
    let sales = GroupRepository::get(&store, &GroupId("awaken.flow:sales".into()))
        .unwrap()
        .unwrap();
    assert!(
        !sales.members.contains(&alice()),
        "stale plan did not re-add"
    );
    assert!(
        !alice_may_work(&client, &first).await,
        "stale plan did not lift the deny"
    );

    // The business profile read: the granted namespace answers (no profile
    // yet), another namespace is refused.
    let read = |namespace: &str, token: &str| {
        client
            .get(format!(
                "{first}/v1/admin/principal-access/profiles/{namespace}"
            ))
            .bearer_auth(token.to_owned())
            .send()
    };
    let absent = read(NAMESPACE, &tokens.flow).await.unwrap();
    assert_eq!(absent.status(), 404);
    assert_eq!(
        absent.json::<serde_json::Value>().await.unwrap()["error"],
        "no_active_profile"
    );
    assert_eq!(
        read("other.namespace", &tokens.flow)
            .await
            .unwrap()
            .status(),
        403
    );
}
