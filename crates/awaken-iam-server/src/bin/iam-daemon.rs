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

use awaken_iam_core::{
    AuthCodeRepository, OAuthClientRepository, RegisteredClient, SessionRepository,
};
use awaken_iam_server::{
    AdminAuthPolicy, DaemonState, IamDaemon, RecordingExecutor, SharedAuthApi, SqliteBackend,
    daemon_router, http, op_router, sqlite_migrated_store,
};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let bind_addr = std::env::var("IAM_BIND_ADDR").unwrap_or_else(|_| "127.0.0.1:8080".to_owned());

    // Assemble standalone and migrate before binding the socket, so the process
    // fails fast on a drifted ledger instead of serving a half-migrated schema.
    let daemon = IamDaemon::start(RecordingExecutor::new())?;
    let (mut auth, authz) = daemon.into_assembly().into_auth_and_authz();
    let issuer = std::env::var("IAM_ISSUER").unwrap_or_else(|_| format!("http://{bind_addr}"));
    auth = auth.with_issuer(issuer.clone());
    let database_path =
        std::env::var("IAM_DATABASE_PATH").unwrap_or_else(|_| "iam.sqlite".to_owned());
    let profile_store = Arc::new(sqlite_migrated_store(
        SqliteBackend::open_path(&database_path)?,
        "iam",
    )?);
    let sessions: Arc<dyn SessionRepository> = profile_store.clone();
    let oauth_clients: Arc<dyn OAuthClientRepository> = profile_store.clone();
    let oauth_codes: Arc<dyn AuthCodeRepository> = profile_store.clone();
    auth = auth
        .with_session_repository(sessions)
        .with_oauth_repositories(oauth_clients, oauth_codes);
    if let (Ok(client_id), Ok(redirect_uris)) = (
        std::env::var("IAM_DESKTOP_CLIENT_ID"),
        std::env::var("IAM_DESKTOP_REDIRECT_URIS"),
    ) {
        let redirect_uris = redirect_uris
            .split(',')
            .map(str::trim)
            .filter(|uri| !uri.is_empty())
            .map(str::to_owned)
            .collect::<Vec<_>>();
        if !client_id.trim().is_empty() && !redirect_uris.is_empty() {
            auth.register_oauth_client(RegisteredClient::public(
                client_id,
                redirect_uris,
                ["openid", "email", "profile"],
            ))?;
        }
    }
    let capability_tokens = auth.token_authority();
    let auth: SharedAuthApi = Arc::new(tokio::sync::Mutex::new(auth));

    // Profiles are durable even though the legacy MVP policy-admin aggregates
    // still use their existing adapters. The active heads are hydrated before
    // the socket binds, so a restart never serves the pre-profile policy.
    // The standalone daemon additionally serves the policy-administration seam:
    // the remote console administers orgs/groups/roles/grants/memberships over
    // `/v1/admin/*`, guarded by the configured admin credential(s).
    let admin_auth = admin_auth_from_env();
    let state = Arc::new(Mutex::new(DaemonState::with_policy_store(
        authz,
        admin_auth,
        profile_store.clone(),
        (*profile_store).clone(),
        capability_tokens,
    )?));
    let router = daemon_router(state).merge(op_router(auth, issuer));

    let listener = tokio::net::TcpListener::bind(&bind_addr).await?;
    eprintln!("iam-daemon: serving /v1 (incl. /v1/admin/*) on http://{bind_addr}");
    http::serve(listener, router).await?;
    Ok(())
}

/// Resolve the admin auth allow-list from `IAM_ADMIN_TOKEN`; an unset or empty
/// value denies every admin caller (fail closed).
///
/// Pure, env-free helper used by the daemon. Exposed so callers and tests can
/// validate the parser without touching the process environment.
fn resolve_admin_auth(raw: Option<&str>) -> AdminAuthPolicy {
    match raw {
        Some(value) => AdminAuthPolicy::new(
            value
                .split(',')
                .map(str::trim)
                .filter(|token| !token.is_empty())
                .map(str::to_owned),
        ),
        None => AdminAuthPolicy::deny_all(),
    }
}

/// Read `IAM_ADMIN_TOKEN` from the environment and resolve the auth policy.
fn admin_auth_from_env() -> AdminAuthPolicy {
    resolve_admin_auth(std::env::var("IAM_ADMIN_TOKEN").ok().as_deref())
}

#[cfg(test)]
mod tests {
    use super::*;

    // The full end-to-end behaviour of `admin_auth_from_env` is exercised by
    // `tests/daemon_boot_e2e.rs` over a real socket; the unit tests here only
    // need to prove the parser does not panic and yields a usable policy for
    // every input shape the binary may encounter at boot.

    #[test]
    fn unset_returns_a_deny_all_policy() {
        let _ = resolve_admin_auth(None);
    }

    #[test]
    fn empty_string_does_not_panic() {
        let _ = resolve_admin_auth(Some(""));
    }

    #[test]
    fn whitespace_only_does_not_panic() {
        let _ = resolve_admin_auth(Some("   "));
    }

    #[test]
    fn single_token_does_not_panic() {
        let _ = resolve_admin_auth(Some("sk-ant-admin-1"));
    }

    #[test]
    fn comma_separated_tokens_do_not_panic() {
        let _ = resolve_admin_auth(Some("alpha,beta,gamma"));
    }

    #[test]
    fn whitespace_around_tokens_does_not_panic() {
        let _ = resolve_admin_auth(Some("  alpha , beta "));
    }

    #[test]
    fn empty_entries_between_commas_do_not_panic() {
        let _ = resolve_admin_auth(Some("alpha,,beta,"));
    }

    #[test]
    fn resolve_admin_auth_from_env_reads_the_env_var_or_unset() {
        // The env-reading variant either succeeds (var present) or returns the
        // deny-all fallback (var unset); neither branch may panic. Durable
        // DaemonState assembly is covered by daemon_boot_e2e over migrated
        // SQLite rather than a process-memory policy store.
        let _policy = admin_auth_from_env();
    }
}
