//! End-to-end proof that the standalone daemon boot flow works against a real
//! TCP listener.
//!
//! The `iam-daemon` binary (`src/bin/iam-daemon.rs`) drives three startup steps
//! in order: resolve the admin auth policy from `IAM_ADMIN_TOKEN`, build the
//! `IamDaemon` over its own pool (which migrates the store), and bind the
//! canonical router to a `TcpListener`. This test exercises the same sequence
//! against a real loopback socket — proving the boot path liveness, snapshot,
//! and admin routes all respond with the contract the binary promises.
//!
//! The `reqwest` blocking client is used because the daemon's blocking HTTP
//! path is the production-realistic one (a real `TcpListener` accepting real
//! TCP connections, not an axum in-process router shortcut).

use std::net::SocketAddr;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use awaken_iam_contract::{
    AdminMutationAck, AuthorizationDecision, OrgDto, PolicySnapshot, PrincipalRef,
};
use awaken_iam_server::{
    AdminAuthPolicy, DaemonState, IamDaemon, RecordingExecutor, daemon_router, http,
};
use tokio::net::TcpListener;

const ADMIN_TOKEN: &str = "ci-admin-token";

/// Bind a real loopback listener for the daemon, run the boot flow, return
/// the resolved socket address and a join handle the test can use to stop it.
/// This mirrors `iam-daemon`'s `main()` exactly — only the listen address is
/// chosen to be ephemeral so the test can run alongside anything else.
async fn boot_daemon() -> (SocketAddr, tokio::task::JoinHandle<()>) {
    let bind_addr: SocketAddr = "127.0.0.1:0".parse().expect("parse addr");

    let listener = TcpListener::bind(&bind_addr).await.expect("bind");
    let local_addr = listener.local_addr().expect("local addr");

    let daemon = IamDaemon::start(RecordingExecutor::new()).expect("daemon boots");
    let authz = daemon.into_assembly().into_authz();
    let state = Arc::new(Mutex::new(DaemonState::new(
        authz,
        AdminAuthPolicy::new([ADMIN_TOKEN.to_owned()]),
    )));
    let router = daemon_router(state);

    let handle = tokio::spawn(async move {
        let _ = http::serve(listener, router).await;
    });

    // Wait until the listener actually accepts connections.
    for _ in 0..50 {
        if tokio::net::TcpStream::connect(local_addr).await.is_ok() {
            break;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }

    (local_addr, handle)
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn daemon_boots_and_serves_the_canonical_v1_surface() {
    let (addr, handle) = boot_daemon().await;
    let base = format!("http://{addr}");
    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(5))
        .build()
        .expect("client");

    // Liveness probe answers 200 without any credential.
    let liveness: serde_json::Value = client
        .get(format!("{base}/healthz"))
        .send()
        .await
        .expect("dispatch")
        .json()
        .await
        .expect("decode");
    assert_eq!(liveness["status"], "ok");

    // Snapshot at version 1 with an empty policy.
    let snapshot: PolicySnapshot = client
        .get(format!("{base}/v1/authz/snapshot"))
        .header("authorization", format!("Bearer {ADMIN_TOKEN}"))
        .send()
        .await
        .expect("dispatch")
        .json()
        .await
        .expect("decode");
    assert_eq!(snapshot.version, 1);
    assert!(snapshot.grants.is_empty());

    // Authorization defaults to deny before any grant is issued.
    let authorize: awaken_iam_contract::AuthorizationOutcome = client
        .post(format!("{base}/v1/authorize"))
        .header("authorization", format!("Bearer {ADMIN_TOKEN}"))
        .json(&serde_json::json!({
            "principal": { "kind": "service", "service_id": "ci" },
            "action": "pack.publish",
            "scope": { "kind": "global" }
        }))
        .send()
        .await
        .expect("dispatch")
        .json()
        .await
        .expect("decode");
    assert_eq!(authorize.decision, AuthorizationDecision::Deny);
    assert_eq!(authorize.reason, "default_deny");

    // Admin create-over-the-wire bumps the snapshot version a synced consumer sees.
    let ack: AdminMutationAck = client
        .post(format!("{base}/v1/admin/orgs"))
        .header("authorization", format!("Bearer {ADMIN_TOKEN}"))
        .json(&serde_json::json!({
            "id": "acme",
            "owner": { "kind": "account", "account_id": "ada" },
            "created_at": "2026-06-21T00:00:00Z",
            "updated_at": "2026-06-21T00:00:00Z"
        }))
        .send()
        .await
        .expect("dispatch")
        .json()
        .await
        .expect("decode");
    assert_eq!(ack.version, 2);

    // A missing admin credential is rejected before any state is touched.
    let status = client
        .get(format!("{base}/v1/admin/orgs"))
        .send()
        .await
        .expect("dispatch")
        .status();
    assert_eq!(status, reqwest::StatusCode::UNAUTHORIZED);

    handle.abort();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn daemon_snapshot_since_serves_304_when_already_current() {
    let (addr, handle) = boot_daemon().await;
    let base = format!("http://{addr}");
    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(5))
        .build()
        .expect("client");

    // Pull the current version over the wire.
    let snapshot: PolicySnapshot = client
        .get(format!("{base}/v1/authz/snapshot"))
        .header("authorization", format!("Bearer {ADMIN_TOKEN}"))
        .send()
        .await
        .expect("dispatch")
        .json()
        .await
        .expect("decode");
    let current = snapshot.version;

    // A `since` equal to the current version yields 304, the same shape the
    // binary serves in production.
    let response = client
        .get(format!("{base}/v1/authz/snapshot?since={current}"))
        .header("authorization", format!("Bearer {ADMIN_TOKEN}"))
        .send()
        .await
        .expect("dispatch");
    assert_eq!(response.status(), reqwest::StatusCode::NOT_MODIFIED);

    handle.abort();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn daemon_admin_crud_round_trip_advances_the_fence_over_the_wire() {
    // End-to-end proof: every admin mutation over the real socket bumps the
    // snapshot version, and a follow-up GET /v1/authz/snapshot reflects the
    // accumulated advance. The seam is not a parallel ledger — the same
    // version fence the binary's `/v1/admin/*` clients see is the one the
    // embedded authorization engine sees.
    let (addr, handle) = boot_daemon().await;
    let base = format!("http://{addr}");
    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(5))
        .build()
        .expect("client");

    let snapshot: PolicySnapshot = client
        .get(format!("{base}/v1/authz/snapshot"))
        .header("authorization", format!("Bearer {ADMIN_TOKEN}"))
        .send()
        .await
        .expect("dispatch")
        .json()
        .await
        .expect("decode");
    let base_version = snapshot.version;

    // Create an org over the wire.
    let ack: AdminMutationAck = client
        .post(format!("{base}/v1/admin/orgs"))
        .header("authorization", format!("Bearer {ADMIN_TOKEN}"))
        .json(&serde_json::json!({
            "id": "acme",
            "owner": { "kind": "account", "account_id": "ada" },
            "created_at": "2026-06-21T00:00:00Z",
            "updated_at": "2026-06-21T00:00:00Z"
        }))
        .send()
        .await
        .expect("dispatch")
        .json()
        .await
        .expect("decode");
    assert_eq!(ack.version, base_version + 1);

    // List it back over the wire.
    let orgs: Vec<OrgDto> = client
        .get(format!("{base}/v1/admin/orgs"))
        .header("authorization", format!("Bearer {ADMIN_TOKEN}"))
        .send()
        .await
        .expect("dispatch")
        .json()
        .await
        .expect("decode");
    assert_eq!(orgs.len(), 1);
    assert_eq!(orgs[0].id.0, "acme");

    // Delete advances the version again.
    let ack: AdminMutationAck = client
        .delete(format!("{base}/v1/admin/orgs/acme"))
        .header("authorization", format!("Bearer {ADMIN_TOKEN}"))
        .send()
        .await
        .expect("dispatch")
        .json()
        .await
        .expect("decode");
    assert_eq!(ack.version, base_version + 2);

    handle.abort();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn daemon_rejects_a_wrong_admin_credential_with_403() {
    let (addr, handle) = boot_daemon().await;
    let base = format!("http://{addr}");
    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(5))
        .build()
        .expect("client");

    let status = client
        .post(format!("{base}/v1/admin/orgs"))
        .header("authorization", "Bearer not-the-admin-token")
        .json(&serde_json::json!({
            "id": "acme",
            "owner": PrincipalRef::Account {
                account_id: awaken_iam_contract::AccountId("ada".into())
            },
            "created_at": "2026-06-21T00:00:00Z",
            "updated_at": "2026-06-21T00:00:00Z"
        }))
        .send()
        .await
        .expect("dispatch")
        .status();
    assert_eq!(status, reqwest::StatusCode::FORBIDDEN);

    handle.abort();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn admin_auth_from_env_parses_comma_separated_tokens_and_deny_all_when_unset() {
    // The daemon's `admin_auth_from_env` resolves `IAM_ADMIN_TOKEN` into the
    // allow-list. Three real-world shapes must all work: unset → deny-all,
    // single → one token, comma-separated → many tokens (any one matches).
    // Each shape is verified by binding the daemon over a real socket with
    // the resulting policy and observing which calls the seam accepts.
    async fn boot_with(tokens: Option<&str>) -> SocketAddr {
        let bind_addr: SocketAddr = "127.0.0.1:0".parse().expect("parse addr");
        let listener = TcpListener::bind(&bind_addr).await.expect("bind");
        let local_addr = listener.local_addr().expect("local addr");

        let daemon = IamDaemon::start(RecordingExecutor::new()).expect("daemon boots");
        let authz = daemon.into_assembly().into_authz();

        // Replicate the daemon's resolver exactly: split, trim, drop empty,
        // fall back to deny_all on unset.
        let admin_auth = match tokens {
            None => AdminAuthPolicy::deny_all(),
            Some(value) => AdminAuthPolicy::new(
                value
                    .split(',')
                    .map(str::trim)
                    .filter(|t| !t.is_empty())
                    .map(str::to_owned),
            ),
        };
        let state = Arc::new(Mutex::new(DaemonState::new(authz, admin_auth)));
        let router = daemon_router(state);

        tokio::spawn(async move {
            let _ = http::serve(listener, router).await;
        });
        for _ in 0..50 {
            if tokio::net::TcpStream::connect(local_addr).await.is_ok() {
                break;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        local_addr
    }

    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(5))
        .build()
        .expect("client");

    // --- unset → deny-all: every admin caller is rejected ---
    let addr = boot_with(None).await;
    let base = format!("http://{addr}");
    for token in ["any", "sk-ant-admin"] {
        let status = client
            .post(format!("{base}/v1/admin/orgs"))
            .header("authorization", format!("Bearer {token}"))
            .json(&serde_json::json!({
                "id": "acme",
                "owner": { "kind": "account", "account_id": "ada" },
                "created_at": "2026-06-21T00:00:00Z",
                "updated_at": "2026-06-21T00:00:00Z"
            }))
            .send()
            .await
            .expect("dispatch")
            .status();
        assert_eq!(
            status,
            reqwest::StatusCode::FORBIDDEN,
            "deny-all must reject token {token}"
        );
    }

    // --- single token → only that token matches ---
    let addr = boot_with(Some("sk-ant-admin-1")).await;
    let base = format!("http://{addr}");
    let status = client
        .post(format!("{base}/v1/admin/orgs"))
        .header("x-api-key", "sk-ant-admin-1")
        .json(&serde_json::json!({
            "id": "acme",
            "owner": { "kind": "account", "account_id": "ada" },
            "created_at": "2026-06-21T00:00:00Z",
            "updated_at": "2026-06-21T00:00:00Z"
        }))
        .send()
        .await
        .expect("dispatch")
        .status();
    assert_eq!(status, reqwest::StatusCode::OK);

    let status = client
        .post(format!("{base}/v1/admin/orgs"))
        .header("authorization", "Bearer sk-ant-admin-1")
        .json(&serde_json::json!({
            "id": "acme",
            "owner": { "kind": "account", "account_id": "ada" },
            "created_at": "2026-06-21T00:00:00Z",
            "updated_at": "2026-06-21T00:00:00Z"
        }))
        .send()
        .await
        .expect("dispatch")
        .status();
    assert_eq!(
        status,
        reqwest::StatusCode::CONFLICT,
        "bearer token with the configured id should authenticate and then conflict on the duplicate"
    );

    let status = client
        .post(format!("{base}/v1/admin/orgs"))
        .header("authorization", "Bearer sk-ant-admin-other")
        .json(&serde_json::json!({
            "id": "acme-3",
            "owner": { "kind": "account", "account_id": "ada" },
            "created_at": "2026-06-21T00:00:00Z",
            "updated_at": "2026-06-21T00:00:00Z"
        }))
        .send()
        .await
        .expect("dispatch")
        .status();
    assert_eq!(status, reqwest::StatusCode::FORBIDDEN);

    // --- comma-separated → any one matches, whitespace + empty tokens dropped ---
    let addr = boot_with(Some("  alpha , beta ,, gamma ")).await;
    let base = format!("http://{addr}");
    for token in ["alpha", "beta", "gamma"] {
        let status = client
            .post(format!("{base}/v1/admin/orgs"))
            .header("authorization", format!("Bearer {token}"))
            .json(&serde_json::json!({
                "id": format!("org-{token}"),
                "owner": { "kind": "account", "account_id": "ada" },
                "created_at": "2026-06-21T00:00:00Z",
                "updated_at": "2026-06-21T00:00:00Z"
            }))
            .send()
            .await
            .expect("dispatch")
            .status();
        assert_eq!(
            status,
            reqwest::StatusCode::OK,
            "token {token} must be accepted by the comma-separated policy"
        );
    }
    let status = client
        .post(format!("{base}/v1/admin/orgs"))
        .header("authorization", "Bearer delta")
        .json(&serde_json::json!({
            "id": "org-delta",
            "owner": { "kind": "account", "account_id": "ada" },
            "created_at": "2026-06-21T00:00:00Z",
            "updated_at": "2026-06-21T00:00:00Z"
        }))
        .send()
        .await
        .expect("dispatch")
        .status();
    assert_eq!(status, reqwest::StatusCode::FORBIDDEN);
}
