//! The standalone `iam-daemon` process.
//!
//! Assembles IAM in [`Deployment::Standalone`](awaken_iam_server::Deployment),
//! runs the `iam.*` migration bundles against the daemon's own pool, then binds
//! the canonical `/v1` authorization protocol to an axum/hyper server (see
//! [deployment](../../../../docs/design/deployment.md)). Remote consumers reach
//! it through the remote
//! [`IamClient`](awaken_iam_client::RemoteIamClient).
//!
//! The MVP daemon runs over the in-process migration executor — the only
//! [`MigrationExecutor`](awaken_iam_server::MigrationExecutor) shipped today; a
//! Postgres-backed pool slots in here unchanged once its adapter lands.
//!
//! Configuration is environment-driven:
//!
//! - `IAM_BIND_ADDR` — socket address to listen on (default `127.0.0.1:8080`).
//! - `IAM_ADMIN_TOKEN` — comma-separated admin credential(s) the `/v1/admin/*`
//!   policy-administration seam accepts (the `x-api-key` admin key or
//!   `Authorization: Bearer` value the remote console presents). Unset means the
//!   admin seam is still served but fails closed — every admin call is rejected —
//!   so the daemon never exposes an unauthenticated control plane by default.

use std::sync::{Arc, Mutex};

use awaken_iam_server::{
    AdminAuthPolicy, DaemonState, IamDaemon, RecordingExecutor, daemon_router, http,
};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let bind_addr = std::env::var("IAM_BIND_ADDR").unwrap_or_else(|_| "127.0.0.1:8080".to_owned());

    // Assemble standalone and migrate before binding the socket, so the process
    // fails fast on a drifted ledger instead of serving a half-migrated schema.
    let daemon = IamDaemon::start(RecordingExecutor::new())?;
    let authz = daemon.into_assembly().into_authz();

    // The standalone daemon additionally serves the policy-administration seam:
    // the remote console administers orgs/groups/roles/grants/memberships over
    // `/v1/admin/*`, guarded by the configured admin credential(s).
    let admin_auth = admin_auth_from_env();
    let state = Arc::new(Mutex::new(DaemonState::new(authz, admin_auth)));
    let router = daemon_router(state);

    let listener = tokio::net::TcpListener::bind(&bind_addr).await?;
    eprintln!("iam-daemon: serving /v1 (incl. /v1/admin/*) on http://{bind_addr}");
    http::serve(listener, router).await?;
    Ok(())
}

/// Resolve the admin auth allow-list from `IAM_ADMIN_TOKEN`; an unset or empty
/// value denies every admin caller (fail closed).
fn admin_auth_from_env() -> AdminAuthPolicy {
    match std::env::var("IAM_ADMIN_TOKEN") {
        Ok(value) => AdminAuthPolicy::new(
            value
                .split(',')
                .map(str::trim)
                .filter(|token| !token.is_empty())
                .map(str::to_owned),
        ),
        Err(_) => AdminAuthPolicy::deny_all(),
    }
}
