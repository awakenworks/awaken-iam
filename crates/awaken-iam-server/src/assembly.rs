//! Two deployments from one assembly.
//!
//! `awaken-iam` ships embedded and standalone from a single codebase; the
//! deployment choice is *which pool and router host IAM*, not a code fork (see
//! [deployment](../../../../docs/design/deployment.md)). This module is that one
//! assembly seam:
//!
//! ```text
//! embedded:   host builds the shared pool (Postgres) or opens a SQLite connection
//!             -> IamStore::with_prefix(pool, "iam"); store.migrate()  (runs iam.* bundles)
//!             -> mount IAM /v1 routes onto the host router
//!             -> in-process callers use the local IamClient (no network hop)
//!
//! standalone: iam-daemon builds its own pool (Postgres for cloud/HA)
//!             -> IamStore::with_prefix(pool, "iam"); store.migrate()
//!             -> serve the canonical /v1 API
//!             -> remote callers use the remote IamClient
//! ```
//!
//! [`IamAssembly`] is the shared body both modes reuse. The only differences are
//! the [`Deployment`] tag (which the host inspects to wire the client SDK's
//! `local | remote` mode to match) and which pool it was handed; the migration
//! bundles, the table prefix, and the mounted [`routes`](IamAssembly::routes) are
//! identical. [`IamDaemon`] is the thin standalone wrapper the `iam-daemon`
//! process is: it owns its pool's assembly and serves the canonical `/v1` API.

use awaken_iam_core::{EntitlementEngine, RepoResult};

use crate::{AuthApi, AuthzApi, IamStore, MigrateReport, MigrationExecutor};

/// IAM's canonical table prefix inside whichever database hosts it.
///
/// The distinct `iam` prefix and IAM's own `iam_schema_migrations` ledger isolate
/// it inside a shared (embedded) database next to siblings, and are equally the
/// prefix in its own (standalone) database — identical code, different pool.
pub const IAM_TABLE_PREFIX: &str = "iam";

/// Which of the two deployments an [`IamAssembly`] was built for.
///
/// The shared body is the same in both; this tag only records *how* IAM is
/// hosted so the host can mirror it onto the client SDK's `local | remote` mode
/// (embedded → local, standalone → remote).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Deployment {
    /// A library co-located in a host process, sharing that host's database and
    /// router. In-process callers use the local [`IamClient`](crate::IamClient).
    Embedded,
    /// The `iam-daemon` process with its own database, serving the canonical
    /// `/v1` API. Callers reach it through the remote
    /// [`IamClient`](crate::IamClient).
    Standalone,
}

impl Deployment {
    /// Whether the client SDK should run in `local` mode for this deployment.
    ///
    /// Embedded resolves in-process (local); standalone resolves over the wire
    /// (remote). The mapping is total and mirrors the deployment exactly.
    pub const fn is_local_client(self) -> bool {
        matches!(self, Deployment::Embedded)
    }
}

/// HTTP method of a mounted [`RouteSpec`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum HttpMethod {
    /// `GET`.
    Get,
    /// `POST`.
    Post,
    /// `DELETE`.
    Delete,
}

/// One canonical route the assembly mounts onto the host (embedded) or serves
/// directly (standalone).
///
/// The assembly exposes the framework-agnostic *manifest* of routes; a
/// deployment maps each entry onto its router of choice and dispatches to the
/// matching [`AuthApi`]/[`AuthzApi`] method. Both modes mount the identical set.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct RouteSpec {
    /// HTTP method the route answers.
    pub method: HttpMethod,
    /// Canonical path, including `/v1` or the well-known discovery prefix.
    pub path: &'static str,
}

impl RouteSpec {
    const fn get(path: &'static str) -> Self {
        Self {
            method: HttpMethod::Get,
            path,
        }
    }

    const fn post(path: &'static str) -> Self {
        Self {
            method: HttpMethod::Post,
            path,
        }
    }

    const fn delete(path: &'static str) -> Self {
        Self {
            method: HttpMethod::Delete,
            path,
        }
    }
}

/// The browser-facing authentication routes ([`AuthApi`]).
const AUTH_ROUTES: &[RouteSpec] = &[
    RouteSpec::get("/.well-known/openid-configuration"),
    RouteSpec::get("/v1/auth/providers"),
    RouteSpec::get("/v1/auth/login/{provider}"),
    RouteSpec::get("/v1/auth/callback/{provider}"),
    RouteSpec::get("/v1/session"),
    RouteSpec::delete("/v1/session"),
    RouteSpec::post("/v1/oauth/token"),
    RouteSpec::get("/v1/oauth/userinfo"),
    RouteSpec::get("/v1/account/identities"),
    RouteSpec::post("/v1/account/identities"),
    RouteSpec::delete("/v1/account/identities/{provider}/{subject}"),
];

/// The authorization/entitlement protocol routes ([`AuthzApi`]).
const AUTHZ_ROUTES: &[RouteSpec] = &[
    RouteSpec::post("/v1/authorize"),
    RouteSpec::post("/v1/authorize/batch"),
    RouteSpec::post("/v1/entitlements/check"),
    RouteSpec::get("/v1/authz/snapshot"),
];

/// The shared assembly both deployments reuse.
///
/// It owns the migrated [`IamStore`] for the host-supplied `Pool`, the
/// authentication surface ([`AuthApi`]), and the authorization/entitlement
/// surface ([`AuthzApi`]). Constructing it runs IAM's `iam.*` migration bundles
/// against the pool under the [`IAM_TABLE_PREFIX`]; the resulting handle exposes
/// the route manifest to mount and, in embedded mode, the local in-process
/// [`IamClient`](crate::IamClient).
pub struct IamAssembly<Pool> {
    deployment: Deployment,
    store: IamStore<Pool>,
    migrate_report: MigrateReport,
    auth: AuthApi,
    authz: AuthzApi,
}

impl<Pool: MigrationExecutor> IamAssembly<Pool> {
    /// Build the embedded assembly over a host-supplied pool.
    ///
    /// The host owns the pool's lifecycle; IAM owns its *schema within* the
    /// shared database, isolated by the `iam` prefix and its own ledger. Runs the
    /// `iam.*` bundles before returning.
    pub fn embedded(pool: Pool) -> RepoResult<Self> {
        Self::assemble(
            Deployment::Embedded,
            pool,
            EntitlementEngine::default_allow(),
        )
    }

    /// Build the standalone assembly over the daemon's own pool.
    ///
    /// Identical code to [`embedded`](Self::embedded); only the pool (a distinct
    /// database) and the [`Deployment`] tag differ.
    pub fn standalone(pool: Pool) -> RepoResult<Self> {
        Self::assemble(
            Deployment::Standalone,
            pool,
            EntitlementEngine::default_allow(),
        )
    }

    /// Build an assembly for an explicit deployment and entitlement engine.
    ///
    /// The general constructor [`embedded`](Self::embedded) and
    /// [`standalone`](Self::standalone) delegate to; a deployment that ships a
    /// configured plan catalog supplies its own [`EntitlementEngine`] here.
    pub fn with_entitlements(
        deployment: Deployment,
        pool: Pool,
        entitlements: EntitlementEngine,
    ) -> RepoResult<Self> {
        Self::assemble(deployment, pool, entitlements)
    }

    fn assemble(
        deployment: Deployment,
        pool: Pool,
        entitlements: EntitlementEngine,
    ) -> RepoResult<Self> {
        let mut store = IamStore::with_prefix(pool, IAM_TABLE_PREFIX)?;
        let migrate_report = store.migrate()?;
        Ok(Self {
            deployment,
            store,
            migrate_report,
            auth: AuthApi::new(),
            authz: AuthzApi::with_entitlements(entitlements),
        })
    }

    /// Which deployment this assembly was built for.
    pub fn deployment(&self) -> Deployment {
        self.deployment
    }

    /// The configured table prefix (always [`IAM_TABLE_PREFIX`]).
    pub fn prefix(&self) -> &str {
        self.store.prefix()
    }

    /// The result of the `iam.*` migration run performed at construction.
    pub fn migrate_report(&self) -> MigrateReport {
        self.migrate_report
    }

    /// The migrated store owning IAM's schema for this pool.
    pub fn store(&self) -> &IamStore<Pool> {
        &self.store
    }

    /// The authentication API to mount the auth half of `/v1` onto.
    pub fn auth(&self) -> &AuthApi {
        &self.auth
    }

    /// Mutable authentication API, e.g. to register identity providers.
    pub fn auth_mut(&mut self) -> &mut AuthApi {
        &mut self.auth
    }

    /// The authorization/entitlement API to mount the authz half of `/v1` onto.
    ///
    /// In embedded mode this same value is the local in-process
    /// [`IamClient`](crate::IamClient) (see [`local_client`](Self::local_client)).
    pub fn authz(&self) -> &AuthzApi {
        &self.authz
    }

    /// Mutable authorization/entitlement API, e.g. to edit the grant policy.
    pub fn authz_mut(&mut self) -> &mut AuthzApi {
        &mut self.authz
    }

    /// The local in-process [`IamClient`](crate::IamClient) for embedded callers.
    ///
    /// Returns the [`AuthzApi`] that backs the mounted routes — calling it
    /// resolves decisions with no network hop, byte-identical to a remote
    /// `POST /v1/authorize` against the same policy. Available in both modes, but
    /// it is the embedded deployment's client path; standalone callers reach the
    /// same engine through the remote client instead.
    pub fn local_client(&self) -> &AuthzApi {
        &self.authz
    }

    /// Consume the assembly and yield its owned [`AuthzApi`].
    ///
    /// Migrations have already run by the time an assembly exists, and the
    /// authorization plane evaluates from its in-memory policy rather than the
    /// store; a deployment that only serves the authorization half of `/v1` (the
    /// standalone [`http`](crate::http) router) takes the engine this way to
    /// share it read-only across connections.
    pub fn into_authz(self) -> AuthzApi {
        self.authz
    }

    /// The canonical `/v1` routes this assembly mounts (auth then authz).
    ///
    /// Both deployments mount the identical manifest; embedded mounts it onto the
    /// host router, standalone serves it directly.
    pub fn routes(&self) -> Vec<RouteSpec> {
        AUTH_ROUTES
            .iter()
            .chain(AUTHZ_ROUTES.iter())
            .copied()
            .collect()
    }
}

/// The standalone `iam-daemon`: an [`IamAssembly`] over the daemon's own pool.
///
/// The daemon builds its own pool (its own database), assembles IAM in
/// [`Deployment::Standalone`], and serves the canonical `/v1` API. Remote callers
/// reach it through the remote [`IamClient`](crate::IamClient); the wrapper itself
/// only owns and exposes the assembly so the process can dispatch its routes.
pub struct IamDaemon<Pool> {
    assembly: IamAssembly<Pool>,
}

impl<Pool: MigrationExecutor> IamDaemon<Pool> {
    /// Start the daemon over its own pool: assemble standalone and migrate.
    pub fn start(pool: Pool) -> RepoResult<Self> {
        Ok(Self {
            assembly: IamAssembly::standalone(pool)?,
        })
    }

    /// Start the daemon with an explicit entitlement engine.
    pub fn with_entitlements(pool: Pool, entitlements: EntitlementEngine) -> RepoResult<Self> {
        Ok(Self {
            assembly: IamAssembly::with_entitlements(Deployment::Standalone, pool, entitlements)?,
        })
    }

    /// The underlying standalone assembly.
    pub fn assembly(&self) -> &IamAssembly<Pool> {
        &self.assembly
    }

    /// Mutable access to the underlying assembly.
    pub fn assembly_mut(&mut self) -> &mut IamAssembly<Pool> {
        &mut self.assembly
    }

    /// Consume the daemon and yield its underlying standalone assembly.
    ///
    /// The standalone process uses this to take ownership of the assembly after
    /// `start` has migrated, then serve its authorization engine over HTTP.
    pub fn into_assembly(self) -> IamAssembly<Pool> {
        self.assembly
    }

    /// The canonical `/v1` routes the daemon serves.
    pub fn routes(&self) -> Vec<RouteSpec> {
        self.assembly.routes()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::RecordingExecutor;
    use awaken_iam_client::IamClient;
    use awaken_iam_contract::{
        ActionKey, AuthorizationDecision, AuthorizationRequest, PrincipalRef, ScopeRef,
    };
    use awaken_iam_core::{ActionPattern, Effect, Grant, GrantId, GrantSubject};

    fn service(id: &str) -> PrincipalRef {
        PrincipalRef::Service {
            service_id: id.into(),
        }
    }

    /// Resolve through the [`IamClient`] trait rather than `AuthzApi`'s inherent
    /// `authorize`, exercising the actual local-client path embedded callers use.
    fn via_client(client: &impl IamClient, request: AuthorizationRequest) -> AuthorizationDecision {
        client.authorize(request)
    }

    #[test]
    fn embedded_runs_iam_bundles_under_the_iam_prefix() {
        let assembly = IamAssembly::embedded(RecordingExecutor::new()).expect("assemble embedded");
        assert_eq!(assembly.deployment(), Deployment::Embedded);
        assert_eq!(assembly.prefix(), IAM_TABLE_PREFIX);
        // Every shipped bundle migration was applied exactly once.
        let plan_len = assembly.store().plan().len();
        assert_eq!(assembly.migrate_report().applied, plan_len);
        assert_eq!(assembly.migrate_report().skipped, 0);
        // The executed DDL targets iam_* tables and the iam ledger.
        let executed = &assembly.store().pool().executed;
        assert!(executed.iter().any(|s| s.contains("iam_accounts")));
        assert!(executed.iter().any(|s| s.contains("iam_grants")));
        assert!(executed.iter().any(|s| s.contains("iam_schema_migrations")));
    }

    #[test]
    fn standalone_assembles_identically_to_embedded() {
        let embedded = IamAssembly::embedded(RecordingExecutor::new()).expect("embedded");
        let daemon = IamDaemon::start(RecordingExecutor::new()).expect("daemon");
        assert_eq!(daemon.assembly().deployment(), Deployment::Standalone);
        // Same prefix, same bundle plan, same mounted routes — only the pool and
        // the deployment tag differ.
        assert_eq!(daemon.assembly().prefix(), embedded.prefix());
        assert_eq!(
            daemon.assembly().store().plan(),
            embedded.store().plan(),
            "both deployments render the identical iam.* plan"
        );
        assert_eq!(daemon.routes(), embedded.routes());
    }

    #[test]
    fn deployment_maps_to_the_client_sdk_mode() {
        assert!(Deployment::Embedded.is_local_client());
        assert!(!Deployment::Standalone.is_local_client());
    }

    #[test]
    fn routes_are_the_canonical_v1_tree() {
        let routes = IamAssembly::embedded(RecordingExecutor::new())
            .expect("assemble")
            .routes();
        assert_eq!(routes.len(), AUTH_ROUTES.len() + AUTHZ_ROUTES.len());
        // Both halves of /v1 are mounted from one assembly.
        assert!(routes.contains(&RouteSpec::get("/v1/session")));
        assert!(routes.contains(&RouteSpec::post("/v1/authorize")));
        assert!(routes.contains(&RouteSpec::get("/v1/authz/snapshot")));
        // No path leaks an unrendered template token or omits its version prefix.
        assert!(
            routes
                .iter()
                .all(|r| r.path.starts_with("/v1/") || r.path.starts_with("/."))
        );
    }

    #[test]
    fn embedded_local_client_resolves_in_process() {
        let mut assembly = IamAssembly::embedded(RecordingExecutor::new()).expect("assemble");
        let request = || {
            AuthorizationRequest::direct(
                service("svc"),
                ActionKey("pack.publish".into()),
                ScopeRef::Global,
            )
        };
        // Default-deny before any grant, resolved without a network hop.
        assert_eq!(
            via_client(assembly.local_client(), request()),
            AuthorizationDecision::Deny
        );
        assembly.authz_mut().policy_mut().add_grant(Grant {
            id: GrantId("g1".into()),
            subject: GrantSubject::Principal(service("svc")),
            action_pattern: ActionPattern("pack.publish".into()),
            scope: ScopeRef::Global,
            effect: Effect::Allow,
        });
        assert_eq!(
            via_client(assembly.local_client(), request()),
            AuthorizationDecision::Allow
        );
    }

    #[test]
    fn assembling_over_a_drifted_ledger_fails_closed() {
        let mut executor = RecordingExecutor::new();
        executor.force_checksum("iam.identity", "0001_identity", "deadbeef");
        let result = IamAssembly::embedded(executor);
        assert!(result.is_err(), "drift must abort assembly, not be skipped");
    }
}
