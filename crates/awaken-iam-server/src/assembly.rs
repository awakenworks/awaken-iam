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
//! [`IamAssembly`] is the shared body both modes reuse. The differences are the
//! [`Deployment`] tag (which the host inspects to wire the client SDK's
//! `local | remote` mode to match), which pool it was handed, and whether the
//! policy-administration management seam is mounted: the migration bundles, the
//! table prefix, and the shared `/v1` surface are identical, while the
//! standalone daemon additionally serves the `/v1/admin/*` routes the remote
//! control plane administers policy through (an embedded host uses the in-process
//! [`PolicyAdminApi`](crate::PolicyAdminApi) instead). [`IamDaemon`] is the thin
//! standalone wrapper the `iam-daemon` process is: it owns its pool's assembly
//! and serves the canonical `/v1` API.

use awaken_iam_contract::Timestamp;
use awaken_iam_core::{EntitlementEngine, EntitlementProvider, RepoResult};

use crate::{
    AuthApi, AuthzApi, IamStore, LicenseConfig, LicenseStatus, Liveness, MigrateReport,
    MigrationExecutor, Readiness,
};

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
    /// `PUT`.
    Put,
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

    const fn put(path: &'static str) -> Self {
        Self {
            method: HttpMethod::Put,
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
    RouteSpec::get("/.well-known/jwks.json"),
    RouteSpec::get("/v1/auth/providers"),
    RouteSpec::get("/v1/auth/login/{provider}"),
    RouteSpec::get("/v1/auth/callback/{provider}"),
    RouteSpec::get("/v1/session"),
    RouteSpec::delete("/v1/session"),
    RouteSpec::get("/v1/oauth/authorize"),
    RouteSpec::post("/v1/oauth/token"),
    RouteSpec::post("/v1/oauth/revoke"),
    RouteSpec::get("/v1/oauth/userinfo"),
    RouteSpec::get("/v1/account/identities"),
    RouteSpec::post("/v1/account/identities"),
    RouteSpec::delete("/v1/account/identities/{provider}/{subject}"),
];

/// The authorization/entitlement protocol routes ([`AuthzApi`]).
///
/// `GET /v1/namespaces/{namespace_id}/signers` is the namespace trust-root
/// lookup a registry consumer (Pack Hub) reads to obtain a namespace's active
/// signer set under the snapshot version fence.
const AUTHZ_ROUTES: &[RouteSpec] = &[
    RouteSpec::post("/v1/authorize"),
    RouteSpec::post("/v1/authorize/batch"),
    RouteSpec::post("/v1/entitlements/check"),
    RouteSpec::get("/v1/namespaces/{namespace_id}/signers"),
    RouteSpec::post("/v1/authz/resource-model"),
    RouteSpec::get("/v1/authz/snapshot"),
    RouteSpec::post("/v1/capabilities/introspect"),
];

/// The policy-administration routes ([`PolicyAdminApi`](crate::PolicyAdminApi)).
///
/// This is the console <-> remote-daemon management seam: a remote control plane
/// (cloud-console) administers the authorization model — organizations, groups,
/// roles, grants, and memberships — over the wire against the standalone daemon.
/// It is *not* an IAM-as-a-product surface; an embedded host administers the same
/// model through the in-process [`PolicyAdminApi`](crate::PolicyAdminApi) with no
/// network hop, so [`routes`](IamAssembly::routes) mounts this surface only in the
/// [`Standalone`](Deployment::Standalone) deployment.
const ADMIN_ROUTES: &[RouteSpec] = &[
    RouteSpec::post("/v1/admin/orgs"),
    RouteSpec::put("/v1/admin/orgs/{id}"),
    RouteSpec::delete("/v1/admin/orgs/{id}"),
    RouteSpec::get("/v1/admin/orgs"),
    RouteSpec::post("/v1/admin/groups"),
    RouteSpec::put("/v1/admin/groups/{id}"),
    RouteSpec::delete("/v1/admin/groups/{id}"),
    RouteSpec::post("/v1/admin/roles"),
    RouteSpec::put("/v1/admin/roles/{id}"),
    RouteSpec::delete("/v1/admin/roles/{id}"),
    RouteSpec::post("/v1/admin/grants"),
    RouteSpec::delete("/v1/admin/grants/{id}"),
    RouteSpec::post("/v1/admin/capabilities"),
    RouteSpec::post("/v1/admin/memberships"),
    RouteSpec::delete("/v1/admin/memberships"),
    RouteSpec::put("/v1/admin/memberships/scoped"),
    RouteSpec::post("/v1/admin/memberships/query"),
    RouteSpec::post("/v1/admin/scope/workspace-orgs"),
    RouteSpec::post("/v1/admin/authz/profiles"),
    RouteSpec::get("/v1/admin/authz/profiles/{namespace}"),
    RouteSpec::get("/v1/admin/authz/profiles/{namespace}/active"),
    RouteSpec::get("/v1/admin/authz/profiles/{namespace}/{revision}"),
    RouteSpec::post("/v1/admin/authz/profiles/{namespace}/{revision}/validate"),
    RouteSpec::post("/v1/admin/authz/profiles/{namespace}/{revision}/activate"),
    RouteSpec::post("/v1/admin/authz/profiles/{namespace}/{revision}/rollback"),
];

/// The Anthropic-compatible Admin API surface (ADR-0008 decision 6).
///
/// These render the same one model the `/v1/admin/*` routes administer, but in
/// the Anthropic Claude platform's shape: `/v1/organizations/...` paths and
/// verbs, `x-api-key` / `Bearer org:admin` auth, typed object envelopes, cursor
/// pagination, and prefixed ids. Member / workspace-member / API-key /
/// service-account operations are [`RoleBinding`](crate::AnthropicAdminApi) edits
/// over the policy PAP; federation issuers/rules project the trusted-issuer
/// token-exchange model. Like [`ADMIN_ROUTES`] it is the console <-> daemon
/// management seam, mounted only in the [`Standalone`](Deployment::Standalone)
/// deployment.
const ORG_ADMIN_ROUTES: &[RouteSpec] = &[
    RouteSpec::get("/v1/organizations/users"),
    RouteSpec::get("/v1/organizations/users/{user_id}"),
    RouteSpec::post("/v1/organizations/users/{user_id}"),
    RouteSpec::delete("/v1/organizations/users/{user_id}"),
    RouteSpec::get("/v1/organizations/workspaces/{workspace_id}/members"),
    RouteSpec::post("/v1/organizations/workspaces/{workspace_id}/members"),
    RouteSpec::get("/v1/organizations/workspaces/{workspace_id}/members/{user_id}"),
    RouteSpec::delete("/v1/organizations/workspaces/{workspace_id}/members/{user_id}"),
    RouteSpec::get("/v1/organizations/api_keys"),
    RouteSpec::post("/v1/organizations/api_keys/{api_key_id}"),
    RouteSpec::get("/v1/organizations/service_accounts"),
    RouteSpec::post("/v1/organizations/service_accounts"),
    RouteSpec::delete("/v1/organizations/service_accounts/{service_account_id}"),
    RouteSpec::get("/v1/organizations/federation_issuers"),
    RouteSpec::get("/v1/organizations/federation_rules"),
];

/// The operational health probes the load balancer and orchestrator route on.
///
/// Unversioned by convention (`/healthz`, `/readyz`) so probes are stable across
/// `/v1` revisions. `/healthz` is liveness ([`IamAssembly::healthz`]); `/readyz`
/// is readiness ([`IamAssembly::readyz`]). See
/// [high availability](../../../../docs/design/high-availability.md).
const OPS_ROUTES: &[RouteSpec] = &[RouteSpec::get("/healthz"), RouteSpec::get("/readyz")];

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
        Self::assemble(Deployment::Embedded, pool, EntitlementEngine::unlicensed())
    }

    /// Build the standalone assembly over the daemon's own pool.
    ///
    /// Identical code to [`embedded`](Self::embedded); only the pool (a distinct
    /// database) and the [`Deployment`] tag differ.
    pub fn standalone(pool: Pool) -> RepoResult<Self> {
        Self::assemble(
            Deployment::Standalone,
            pool,
            EntitlementEngine::unlicensed(),
        )
    }

    /// Build an assembly for an explicit deployment and entitlement provider.
    ///
    /// The general constructor [`embedded`](Self::embedded) and
    /// [`standalone`](Self::standalone) delegate to; a deployment that ships a
    /// configured plan catalog or a closed, licensed provider supplies its own
    /// [`EntitlementProvider`] here.
    pub fn with_entitlements(
        deployment: Deployment,
        pool: Pool,
        entitlements: impl EntitlementProvider + 'static,
    ) -> RepoResult<Self> {
        Self::assemble(deployment, pool, entitlements)
    }

    /// Build an assembly whose entitlement plane is resolved from a license
    /// config at instant `now`.
    ///
    /// Verifies the configured claim offline and installs the resolved provider
    /// through the same injection point as [`with_entitlements`](Self::with_entitlements):
    /// a claim that verifies installs the licensed provider, while a missing or
    /// rejected claim installs the fail-closed unlicensed provider. Open product
    /// functionality remains outside commercial checks. The returned
    /// [`LicenseStatus`] explains the outcome
    /// (and carries the claim's `not_after` for the re-verify cadence — re-call
    /// [`resolve`](crate::LicenseConfig::resolve) and
    /// [`set_entitlements`](Self::set_entitlements) before it).
    pub fn with_license(
        deployment: Deployment,
        pool: Pool,
        license: &LicenseConfig,
        now: &Timestamp,
    ) -> RepoResult<(Self, LicenseStatus)> {
        let resolved = license.resolve(now);
        let assembly = Self::assemble(deployment, pool, resolved.provider)?;
        Ok((assembly, resolved.status))
    }

    /// Replace the installed entitlement provider in place.
    ///
    /// The re-verify cadence seam: a host re-resolves its [`LicenseConfig`] with
    /// the current time (claims expire at their `not_after`) and swaps the
    /// resolved provider here without rebuilding the assembly.
    pub fn set_entitlements(&mut self, entitlements: impl EntitlementProvider + 'static) {
        self.authz.set_entitlements(entitlements);
    }

    fn assemble(
        deployment: Deployment,
        pool: Pool,
        entitlements: impl EntitlementProvider + 'static,
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

    /// Consume the assembly and yield the authentication and authorization
    /// runtimes together so a standalone host cannot accidentally discard the
    /// declared OP surface while mounting only the PDP routes.
    pub fn into_auth_and_authz(self) -> (AuthApi, AuthzApi) {
        (self.auth, self.authz)
    }

    /// The canonical routes this assembly mounts: the `/v1` surface (auth then
    /// authz), the standalone-only policy-administration seam, then the
    /// operational health probes.
    ///
    /// Both deployments mount the shared `/v1` surface — embedded onto the host
    /// router, standalone directly. The policy-administration routes
    /// ([`ADMIN_ROUTES`]) are the console <-> remote-daemon management seam and
    /// are mounted only in the [`Standalone`](Deployment::Standalone) deployment;
    /// an embedded host administers the same model through the in-process
    /// [`PolicyAdminApi`](crate::PolicyAdminApi) rather than over HTTP.
    pub fn routes(&self) -> Vec<RouteSpec> {
        let mut routes: Vec<RouteSpec> = AUTH_ROUTES
            .iter()
            .chain(AUTHZ_ROUTES.iter())
            .copied()
            .collect();
        if self.deployment == Deployment::Standalone {
            routes.extend(ADMIN_ROUTES.iter().copied());
            routes.extend(ORG_ADMIN_ROUTES.iter().copied());
        }
        routes.extend(OPS_ROUTES.iter().copied());
        routes
    }

    /// Liveness probe (`/healthz`): the process is up.
    ///
    /// Deliberately store-independent so a transient store outage does not
    /// trigger a needless restart — that is what readiness is for. Always
    /// [`Liveness::Up`] for a running process.
    pub fn healthz(&self) -> Liveness {
        Liveness::Up
    }

    /// Readiness probe (`/readyz`): the store is reachable and this node's
    /// migrations are applied.
    ///
    /// Reads the ledger to confirm every planned migration is recorded; that read
    /// doubles as the store-reachability check. Fails closed — a pending/drifted
    /// migration or an unreadable store reports *not ready*, so the balancer
    /// drains the node rather than route to one that cannot evaluate fresh.
    pub fn readyz(&self) -> Readiness {
        match self.store.migrations_applied() {
            Ok(true) => Readiness::ready(),
            Ok(false) => Readiness::not_ready("migrations not fully applied"),
            Err(err) => Readiness::not_ready(format!("store unreachable: {err}")),
        }
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

    /// Start the daemon with an explicit entitlement provider.
    pub fn with_entitlements(
        pool: Pool,
        entitlements: impl EntitlementProvider + 'static,
    ) -> RepoResult<Self> {
        Ok(Self {
            assembly: IamAssembly::with_entitlements(Deployment::Standalone, pool, entitlements)?,
        })
    }

    /// Start the daemon with its entitlement plane resolved from a license config
    /// at instant `now`.
    ///
    /// Delegates to [`IamAssembly::with_license`]; the returned [`LicenseStatus`]
    /// explains whether a license was installed and, if so, when it expires.
    pub fn with_license(
        pool: Pool,
        license: &LicenseConfig,
        now: &Timestamp,
    ) -> RepoResult<(Self, LicenseStatus)> {
        let (assembly, status) =
            IamAssembly::with_license(Deployment::Standalone, pool, license, now)?;
        Ok((Self { assembly }, status))
    }

    /// Replace the daemon's installed entitlement provider in place (re-verify
    /// cadence seam). See [`IamAssembly::set_entitlements`].
    pub fn set_entitlements(&mut self, entitlements: impl EntitlementProvider + 'static) {
        self.assembly.set_entitlements(entitlements);
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
    /// The canonical routes the daemon serves (the `/v1` surface plus probes).
    pub fn routes(&self) -> Vec<RouteSpec> {
        self.assembly.routes()
    }

    /// Liveness probe (`/healthz`) the orchestrator restarts a wedged node on.
    pub fn healthz(&self) -> Liveness {
        self.assembly.healthz()
    }

    /// Readiness probe (`/readyz`) the load balancer routes ready nodes on.
    pub fn readyz(&self) -> Readiness {
        self.assembly.readyz()
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
        // Same prefix, same bundle plan — only the pool and the deployment tag
        // differ. The shared `/v1` surface is identical; the standalone daemon
        // additionally mounts the policy-administration management seam.
        assert_eq!(daemon.assembly().prefix(), embedded.prefix());
        assert_eq!(
            daemon.assembly().store().plan(),
            embedded.store().plan(),
            "both deployments render the identical iam.* plan"
        );
        // The daemon's manifest is the embedded surface plus the admin and the
        // Anthropic-compatible org-admin routes.
        assert_eq!(
            daemon.routes().len(),
            embedded.routes().len() + ADMIN_ROUTES.len() + ORG_ADMIN_ROUTES.len()
        );
        for spec in embedded.routes() {
            assert!(
                daemon.routes().contains(&spec),
                "standalone must also mount the shared route {}",
                spec.path
            );
        }
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
        assert_eq!(
            routes.len(),
            AUTH_ROUTES.len() + AUTHZ_ROUTES.len() + OPS_ROUTES.len()
        );
        // Both halves of /v1 are mounted from one assembly.
        assert!(routes.contains(&RouteSpec::get("/v1/session")));
        assert!(routes.contains(&RouteSpec::post("/v1/authorize")));
        assert!(routes.contains(&RouteSpec::get("/v1/authz/snapshot")));
        // The well-known discovery surface mounts both the OIDC metadata and the
        // JWKS so third parties can verify IAM-signed access tokens.
        assert!(routes.contains(&RouteSpec::get("/.well-known/openid-configuration")));
        assert!(routes.contains(&RouteSpec::get("/.well-known/jwks.json")));
        // The downstream OpenID Provider endpoints are mounted alongside.
        assert!(routes.contains(&RouteSpec::get("/v1/oauth/authorize")));
        assert!(routes.contains(&RouteSpec::post("/v1/oauth/token")));
        assert!(routes.contains(&RouteSpec::post("/v1/oauth/revoke")));
        // The namespace trust-root lookup is mounted alongside the authz routes.
        assert!(routes.contains(&RouteSpec::get("/v1/namespaces/{namespace_id}/signers")));
        // No path leaks an unrendered template token or omits its version prefix.
        // The operational probes are mounted alongside the /v1 surface.
        assert!(routes.contains(&RouteSpec::get("/healthz")));
        assert!(routes.contains(&RouteSpec::get("/readyz")));
        // No path leaks an unrendered template token; every path is either the
        // versioned surface, the well-known discovery prefix, or a health probe.
        assert!(routes.iter().all(|r| {
            r.path.starts_with("/v1/")
                || r.path.starts_with("/.")
                || r.path == "/healthz"
                || r.path == "/readyz"
        }));
    }

    #[test]
    fn standalone_mounts_the_admin_seam_but_embedded_does_not() {
        let embedded = IamAssembly::embedded(RecordingExecutor::new()).expect("embedded");
        let daemon = IamDaemon::start(RecordingExecutor::new()).expect("daemon");

        // The policy-administration surface is the console <-> remote-daemon seam:
        // the standalone daemon serves every /v1/admin/* route over the wire.
        let standalone = daemon.routes();
        assert!(standalone.contains(&RouteSpec::post("/v1/admin/orgs")));
        assert!(standalone.contains(&RouteSpec::put("/v1/admin/orgs/{id}")));
        assert!(standalone.contains(&RouteSpec::delete("/v1/admin/orgs/{id}")));
        assert!(standalone.contains(&RouteSpec::get("/v1/admin/orgs")));
        assert!(standalone.contains(&RouteSpec::post("/v1/admin/groups")));
        assert!(standalone.contains(&RouteSpec::put("/v1/admin/groups/{id}")));
        assert!(standalone.contains(&RouteSpec::delete("/v1/admin/groups/{id}")));
        assert!(standalone.contains(&RouteSpec::post("/v1/admin/roles")));
        assert!(standalone.contains(&RouteSpec::put("/v1/admin/roles/{id}")));
        assert!(standalone.contains(&RouteSpec::delete("/v1/admin/roles/{id}")));
        assert!(standalone.contains(&RouteSpec::post("/v1/admin/grants")));
        assert!(standalone.contains(&RouteSpec::delete("/v1/admin/grants/{id}")));
        assert!(standalone.contains(&RouteSpec::post("/v1/admin/memberships")));
        assert!(standalone.contains(&RouteSpec::delete("/v1/admin/memberships")));
        assert!(standalone.contains(&RouteSpec::post("/v1/admin/authz/profiles")));
        assert!(standalone.contains(&RouteSpec::post(
            "/v1/admin/authz/profiles/{namespace}/{revision}/activate"
        )));
        assert_eq!(
            standalone
                .iter()
                .filter(|r| r.path.starts_with("/v1/admin"))
                .count(),
            ADMIN_ROUTES.len()
        );

        // An embedded host administers the model in-process and does not expose
        // the admin routes on the host router.
        assert!(
            embedded
                .routes()
                .iter()
                .all(|r| !r.path.starts_with("/v1/admin")),
            "embedded must not mount the admin seam over HTTP"
        );
    }

    #[test]
    fn standalone_mounts_the_anthropic_org_admin_surface() {
        let embedded = IamAssembly::embedded(RecordingExecutor::new()).expect("embedded");
        let daemon = IamDaemon::start(RecordingExecutor::new()).expect("daemon");
        let standalone = daemon.routes();

        // The Anthropic-compatible surface lives under /v1/organizations and is
        // served only by the standalone daemon.
        assert!(standalone.contains(&RouteSpec::get("/v1/organizations/users")));
        assert!(standalone.contains(&RouteSpec::delete("/v1/organizations/users/{user_id}")));
        assert!(standalone.contains(&RouteSpec::get(
            "/v1/organizations/workspaces/{workspace_id}/members"
        )));
        assert!(standalone.contains(&RouteSpec::get("/v1/organizations/api_keys")));
        assert!(standalone.contains(&RouteSpec::post("/v1/organizations/service_accounts")));
        assert!(standalone.contains(&RouteSpec::get("/v1/organizations/federation_issuers")));
        assert!(standalone.contains(&RouteSpec::get("/v1/organizations/federation_rules")));
        assert_eq!(
            standalone
                .iter()
                .filter(|r| r.path.starts_with("/v1/organizations"))
                .count(),
            ORG_ADMIN_ROUTES.len()
        );

        assert!(
            embedded
                .routes()
                .iter()
                .all(|r| !r.path.starts_with("/v1/organizations")),
            "embedded must not mount the org-admin surface over HTTP"
        );
    }

    #[test]
    fn healthz_is_live_and_readyz_is_ready_after_migration() {
        let assembly = IamAssembly::embedded(RecordingExecutor::new()).expect("assemble");
        // Liveness is up for a running process and never touches the store.
        assert!(assembly.healthz().is_live());
        // Readiness is green because assembly migrated the store before returning.
        assert!(assembly.readyz().is_ready());
    }

    #[test]
    fn readyz_fails_closed_when_migrations_are_not_applied() {
        // A store that was never migrated has an incomplete ledger, so readiness
        // must report not-ready and drain the node rather than serve traffic.
        let store = IamStore::with_prefix(RecordingExecutor::new(), IAM_TABLE_PREFIX)
            .expect("valid prefix");
        assert!(
            !store.migrations_applied().expect("probe ledger"),
            "an un-migrated store must not report ready"
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
        executor.force_checksum("iam.identity", 1, "deadbeef");
        let result = IamAssembly::embedded(executor);
        assert!(result.is_err(), "drift must abort assembly, not be skipped");
    }

    #[test]
    fn explicit_entitlement_engine_flows_through_both_constructors() {
        use awaken_iam_core::EntitlementEngine;

        // The assembly constructor accepts a deployment-supplied engine.
        let mut assembly = IamAssembly::with_entitlements(
            Deployment::Embedded,
            RecordingExecutor::new(),
            EntitlementEngine::default_allow(),
        )
        .expect("assemble with entitlements");
        assert_eq!(assembly.deployment(), Deployment::Embedded);

        // The auth and authz surfaces are reachable by shared and mutable borrow.
        let _ = assembly.auth();
        let _ = assembly.auth_mut();
        let _ = assembly.authz();
        let _ = assembly.authz_mut();

        // The daemon wrapper takes the same explicit engine and exposes its
        // assembly mutably.
        let mut daemon = IamDaemon::with_entitlements(
            RecordingExecutor::new(),
            EntitlementEngine::default_allow(),
        )
        .expect("daemon with entitlements");
        assert_eq!(daemon.assembly().deployment(), Deployment::Standalone);
        let _ = daemon.assembly_mut().authz_mut();
    }

    #[test]
    fn license_config_wires_through_with_license_and_set_entitlements() {
        use crate::{LicenseConfig, LicenseSource, LicenseStatus};
        use awaken_iam_contract::{
            AccountId, EntitlementDecision, EntitlementRequest, JsonWebKey, Jwks, LicenseClaim,
            LicenseSignature, PrincipalRef, Timestamp,
        };
        use base64::Engine;
        use base64::engine::general_purpose::URL_SAFE_NO_PAD;
        use ed25519_dalek::{Signer, SigningKey};

        let key = SigningKey::from_bytes(&[7u8; 32]);
        let jwks = Jwks {
            keys: vec![JsonWebKey {
                kty: "OKP".into(),
                crv: "Ed25519".into(),
                x: URL_SAFE_NO_PAD.encode(key.verifying_key().to_bytes()),
                kid: "lic-1".into(),
                key_use: "sig".into(),
                alg: "EdDSA".into(),
            }],
        };
        let mut claim = LicenseClaim {
            features: vec!["pack.publish".into()],
            limits: Default::default(),
            issued_at: Timestamp("2026-06-01T00:00:00Z".into()),
            not_after: Timestamp("2026-12-01T00:00:00Z".into()),
            epoch: 1,
            sig: LicenseSignature {
                kid: "lic-1".into(),
                value: String::new(),
            },
        };
        claim.sig.value = URL_SAFE_NO_PAD.encode(key.sign(&claim.signing_input()).to_bytes());

        let config = LicenseConfig::new(
            jwks,
            0,
            LicenseSource::Inline(serde_json::to_string(&claim).unwrap()),
        );
        let now = Timestamp("2026-07-01T00:00:00Z".into());
        let entitled = |feature: &str| EntitlementRequest {
            principal: PrincipalRef::Account {
                account_id: AccountId("acct_1".into()),
            },
            entitlement: feature.into(),
            resource: None,
        };

        // A verifying claim installs a licensed provider through with_license.
        let (mut assembly, status) = IamAssembly::with_license(
            Deployment::Embedded,
            RecordingExecutor::new(),
            &config,
            &now,
        )
        .expect("assemble with license");
        assert!(status.is_licensed());
        assert_eq!(
            assembly
                .authz()
                .check_entitlement(&entitled("pack.publish"))
                .decision,
            EntitlementDecision::Allow
        );
        assert_eq!(
            assembly
                .authz()
                .check_entitlement(&entitled("model.strong_access"))
                .decision,
            EntitlementDecision::Deny
        );

        // The re-verify cadence seam swaps the provider in place; an unlicensed
        // resolution denies commercial checks without rebuilding the assembly.
        let unlicensed = LicenseConfig::unlicensed().resolve(&now);
        assert_eq!(unlicensed.status, LicenseStatus::Unlicensed);
        assembly.set_entitlements(unlicensed.provider);
        assert_eq!(
            assembly
                .authz()
                .check_entitlement(&entitled("model.strong_access"))
                .decision,
            EntitlementDecision::Deny
        );
    }
}
