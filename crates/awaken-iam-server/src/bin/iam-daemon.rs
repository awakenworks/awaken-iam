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

use std::sync::Arc;

use awaken_iam_server::{IamDaemon, RecordingExecutor, http};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let bind_addr = std::env::var("IAM_BIND_ADDR").unwrap_or_else(|_| "127.0.0.1:8080".to_owned());

    // Assemble standalone and migrate before binding the socket, so the process
    // fails fast on a drifted ledger instead of serving a half-migrated schema.
    let daemon = IamDaemon::start(RecordingExecutor::new())?;
    let authz = Arc::new(daemon.into_assembly().into_authz());
    let router = http::authz_router(authz);

    let listener = tokio::net::TcpListener::bind(&bind_addr).await?;
    eprintln!("iam-daemon: serving /v1 on http://{bind_addr}");
    http::serve(listener, router).await?;
    Ok(())
}
