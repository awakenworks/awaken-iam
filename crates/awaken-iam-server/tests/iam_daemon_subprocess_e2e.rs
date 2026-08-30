//! End-to-end proof that the `iam-daemon` binary boots, binds a real
//! TCP socket, and serves the canonical `/v1` surface over the wire.
//!
//! The daemon's `main()` is the production boot path: it reads
//! `IAM_BIND_ADDR`, runs the assembly over its own pool, resolves the admin
//! auth policy from `IAM_ADMIN_TOKEN`, and binds the canonical router. To
//! cover `main()` from the same test suite that covers the rest of the
//! surface, this test launches the compiled `iam-daemon` binary as a child
//! process, talks to it with `reqwest`, and asserts the wire contract the
//! binary promises.

use std::net::SocketAddr;
use std::process::{Child, Command, Stdio};
use std::time::Duration;

async fn wait_until_ready(child: &mut Child, client: &reqwest::Client, base: &str) {
    // Causal test design: readiness is proved by the production liveness
    // endpoint, not by elapsed startup time. A bounded deadline tolerates a
    // contended CI host while an early child exit still fails immediately.
    let deadline = tokio::time::Instant::now() + Duration::from_secs(15);
    loop {
        if client.get(format!("{base}/healthz")).send().await.is_ok() {
            return;
        }
        if let Some(status) = child.try_wait().expect("inspect iam-daemon") {
            panic!("iam-daemon exited before readiness: {status}");
        }
        assert!(
            tokio::time::Instant::now() < deadline,
            "iam-daemon must accept connections within 15s"
        );
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
}

fn test_database(label: &str) -> std::path::PathBuf {
    let nonce = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("clock")
        .as_nanos();
    let dir = std::env::temp_dir().join(format!(
        "awaken-iam-daemon-{label}-{}-{nonce}",
        std::process::id()
    ));
    std::fs::create_dir_all(&dir).expect("create daemon test directory");
    dir.join("iam.sqlite")
}

fn locate_daemon_binary() -> Option<std::path::PathBuf> {
    // 1. CARGO_BIN_EXE_iam-daemon (set by Cargo when running integration tests
    //    for the same crate, including the instrumented binary when run
    //    through `cargo llvm-cov`).
    if let Ok(path) = std::env::var("CARGO_BIN_EXE_iam-daemon") {
        let path = std::path::PathBuf::from(path);
        if path.exists() {
            return Some(path);
        }
    }
    // 2. Walk up from CARGO_MANIFEST_DIR / OUT_DIR to find target/debug/iam-daemon.
    let mut dir = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    loop {
        let candidate = dir.join("target/debug/iam-daemon");
        if candidate.exists() {
            return Some(candidate);
        }
        if !dir.pop() {
            break;
        }
    }
    // 3. LLVM-COV's instrumented target dir.
    if let Ok(target) = std::env::var("CARGO_TARGET_DIR") {
        let candidate = std::path::PathBuf::from(&target).join("llvm-cov-target/debug/iam-daemon");
        if candidate.exists() {
            return Some(candidate);
        }
    }
    // 4. The shared llvm-cov-target cache.
    let mut dir = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    loop {
        let candidate = dir.join("target/llvm-cov-target/debug/iam-daemon");
        if candidate.exists() {
            return Some(candidate);
        }
        if !dir.pop() {
            break;
        }
    }
    None
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn iam_daemon_binary_boots_and_serves_healthz_and_snapshot() {
    let Some(binary) = locate_daemon_binary() else {
        eprintln!("skipping: iam-daemon binary not built yet");
        return;
    };

    // Bind to an ephemeral loopback port; the binary reads IAM_BIND_ADDR.
    let bind_addr: SocketAddr = "127.0.0.1:0".parse().expect("parse addr");
    // Use std::net to allocate the port, then hand it to the binary so it
    // binds exactly the same socket.
    let listener = std::net::TcpListener::bind(bind_addr).expect("bind");
    let port = listener.local_addr().expect("local_addr").port();
    // Drop our reservation; the binary will re-bind the same port.
    drop(listener);

    let admin_cred = "ci-subprocess-token";
    let database = test_database("boot");
    let mut cmd = Command::new(&binary);
    cmd.env("IAM_BIND_ADDR", format!("127.0.0.1:{port}"))
        .env("IAM_ADMIN_TOKEN", admin_cred)
        .env("IAM_DATABASE_PATH", &database)
        .stdout(Stdio::null())
        .stderr(Stdio::null());
    // Forward the LLVM profile env so the instrumented binary writes its
    // coverage data to the same target dir `cargo llvm-cov` aggregates.
    for (key, value) in std::env::vars() {
        if key == "LLVM_PROFILE_FILE" {
            cmd.env(key, value);
        }
    }
    let mut child = cmd.spawn().expect("spawn iam-daemon");

    // Wait until the binary is ready to accept connections.
    let base = format!("http://127.0.0.1:{port}");
    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(5))
        .build()
        .expect("client");
    wait_until_ready(&mut child, &client, &base).await;

    // Liveness probe — proves main() bound the router.
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
    let snapshot: awaken_iam_contract::PolicySnapshot = client
        .get(format!("{base}/v1/authz/snapshot"))
        .header("authorization", format!("Bearer {admin_cred}"))
        .send()
        .await
        .expect("dispatch")
        .json()
        .await
        .expect("decode");
    assert_eq!(snapshot.version, 1);
    assert!(snapshot.grants.is_empty());

    // Default-deny authorization — proves the engine and the seam are wired.
    let authorize: awaken_iam_contract::AuthorizationOutcome = client
        .post(format!("{base}/v1/authorize"))
        .header("authorization", format!("Bearer {admin_cred}"))
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
    assert_eq!(
        authorize.decision,
        awaken_iam_contract::AuthorizationDecision::Deny
    );

    // A missing admin credential is rejected before any state is touched.
    let status = client
        .get(format!("{base}/v1/admin/orgs"))
        .send()
        .await
        .expect("dispatch")
        .status();
    assert_eq!(status, reqwest::StatusCode::UNAUTHORIZED);

    // Clean up: kill the binary and give it a moment to flush its
    // coverage profile before reaping, so the .profraw file is fully written.
    let _ = child.kill();
    std::thread::sleep(std::time::Duration::from_millis(200));
    let _ = child.wait();
    std::fs::remove_dir_all(database.parent().unwrap()).expect("remove daemon test directory");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn iam_daemon_binary_rejects_unknown_admin_token_with_403() {
    let Some(binary) = locate_daemon_binary() else {
        eprintln!("skipping: iam-daemon binary not built yet");
        return;
    };

    let bind_addr: SocketAddr = "127.0.0.1:0".parse().expect("parse addr");
    let listener = std::net::TcpListener::bind(bind_addr).expect("bind");
    let port = listener.local_addr().expect("local_addr").port();
    drop(listener);

    let database = test_database("auth");
    let mut cmd = Command::new(&binary);
    cmd.env("IAM_BIND_ADDR", format!("127.0.0.1:{port}"))
        .env("IAM_ADMIN_TOKEN", "the-real-token")
        .env("IAM_DATABASE_PATH", &database)
        .stdout(Stdio::null())
        .stderr(Stdio::null());
    for (key, value) in std::env::vars() {
        if key == "LLVM_PROFILE_FILE" {
            cmd.env(key, value);
        }
    }
    let mut child = cmd.spawn().expect("spawn iam-daemon");

    let base = format!("http://127.0.0.1:{port}");
    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(5))
        .build()
        .expect("client");
    wait_until_ready(&mut child, &client, &base).await;

    let status = client
        .post(format!("{base}/v1/admin/orgs"))
        .header("authorization", "Bearer not-the-real-token")
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
    assert_eq!(status, reqwest::StatusCode::FORBIDDEN);

    let _ = child.kill();
    // Give the binary a moment to flush its coverage profile before
    // reaping, so the .profraw file is fully written.
    std::thread::sleep(std::time::Duration::from_millis(200));
    let _ = child.wait();
    std::fs::remove_dir_all(database.parent().unwrap()).expect("remove daemon test directory");
}
