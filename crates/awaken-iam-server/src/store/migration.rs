//! Scope-partitioned, self-contained schema migration bundles.
//!
//! IAM owns its schema as append-only, checksum-verified migration bundles, one
//! per subdomain scope. The bundle/checksum/plan **mechanism** is the shared
//! [`awaken-scoped-migration`](awaken_scoped_migration) foundation crate; this
//! module only declares IAM's bundles and the thin per-backend glue that drives
//! the crate's pure core against IAM's own database drivers. Two rules keep the
//! bundles split-or-aggregate safe (see
//! [deployment](../../../../docs/design/deployment.md)):
//!
//! 1. No bundle hard-couples to another bundle; bundles version independently.
//! 2. No cross-component foreign key. References *between* IAM subdomains are by
//!    id resolved in the domain, never a DB-level FK across bundles.
//!
//! Both are enforced by [`awaken_scoped_migration::lint`] over [`bundles`] (see
//! the test below), not by hand.
//!
//! The store is constructed with a table prefix —
//! [`IamStore::with_prefix`]`(pool, "iam")` yields `iam_accounts`,
//! `iam_grants`, … and the ledger `iam_schema_migrations`. The same DDL renders
//! against any prefix, which is what lets IAM deploy embedded (sharing a host's
//! database next to siblings using their own prefixes) or standalone (its own
//! database) from one codebase. The pool itself is supplied by the host through
//! a [`MigrationExecutor`]; this module is pool-agnostic so the core stays
//! storage-free and each backend executor (Postgres, SQLite) is a thin edge
//! adapter over the foundation crate's [`plan`](awaken_scoped_migration::plan).
//!
//! DDL is authored **dialect-neutral** using the foundation crate's portable
//! token vocabulary (`{prefix}`, `{json}`, `{timestamptz}`, `{now}`, `{blob}`,
//! `{pk_autoinc}`), which each backend renders to its dialect via
//! [`awaken_scoped_migration::render`] alongside the prefix. See
//! [ADR-0003](../../../../docs/adr/0003-storage-backends.md).
//!
//! ## Why the foundation crate's *core* and not its runner shells
//!
//! `awaken-scoped-migration` ships optional `postgres` (async `sqlx`) and
//! `sqlite` (`rusqlite` 0.32) runner shells. IAM's backends use the *synchronous*
//! `postgres` client and `rusqlite` 0.40 — different driver generations — so IAM
//! depends on the crate with **default features** (the driver-agnostic pure core)
//! and writes its own thin shells here, exactly mirroring the pattern the crate's
//! own shells follow.

use std::collections::BTreeMap;

use awaken_iam_core::{RepoError, RepoResult};

pub use awaken_scoped_migration::{
    AppliedMigration, Dialect, Migration, MigrationBundle, MigrationError,
};
use awaken_scoped_migration::{plan as plan_bundle, render, sql_identifier};

/// Map a foundation [`MigrationError`] onto the IAM repository error taxonomy.
///
/// The whole migration mechanism reports through one error type; at the IAM edge
/// every variant is an opaque backend failure (a drifted checksum, an unreachable
/// ledger, an invalid prefix), surfaced verbatim so the cause is preserved.
pub(crate) fn migration_err(err: MigrationError) -> RepoError {
    RepoError::Backend(err.to_string())
}

/// Component-scope partition a migration bundle belongs to.
///
/// The scope decides *where the tables live* (which bundle owns them), distinct
/// from tenant scope which decides *whose rows they hold*. A bundle never
/// references a table owned by another scope.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum BundleScope {
    /// `iam.identity` — accounts, external identities, sessions, login flows.
    Identity,
    /// `iam.authz` — directory (orgs, groups, roles), grants, role memberships,
    /// resource-model registry.
    Authz,
    /// `iam.entitlement` — plans and subscriptions.
    Entitlement,
    /// `iam.audit` — the append-only audit event log.
    Audit,
}

impl BundleScope {
    /// Stable dotted bundle id recorded in the ledger.
    pub const fn id(self) -> &'static str {
        match self {
            BundleScope::Identity => "iam.identity",
            BundleScope::Authz => "iam.authz",
            BundleScope::Entitlement => "iam.entitlement",
            BundleScope::Audit => "iam.audit",
        }
    }

    /// Every scope, in canonical apply order.
    pub const fn all() -> [BundleScope; 4] {
        [
            BundleScope::Identity,
            BundleScope::Authz,
            BundleScope::Entitlement,
            BundleScope::Audit,
        ]
    }
}

/// The canonical IAM migration bundles, one per subdomain scope, built on the
/// shared [`MigrationBundle`] value type.
///
/// Each bundle's migrations are versioned `1, 2, …` within the bundle (the
/// foundation crate renders the readable `V0001` label and checksums over it).
/// The bundle ids are the [`BundleScope`] dotted ids. The DDL bodies are static
/// and tested by the [`lint`](awaken_scoped_migration::lint) check below, so the
/// per-`Migration` construction cannot fail in practice; an `expect` keeps the
/// public signature infallible.
pub fn bundles() -> Vec<MigrationBundle> {
    vec![
        bundle(
            BundleScope::Identity,
            vec![
                (1, "identity", IDENTITY_0001),
                (2, "api_tokens", IDENTITY_0002),
                (3, "oauth_clients", IDENTITY_0003),
                (4, "api_token_workspace", IDENTITY_0004),
            ],
        ),
        bundle(
            BundleScope::Authz,
            vec![
                (1, "authz", AUTHZ_0001),
                (2, "directory", AUTHZ_0002),
                (3, "fence", AUTHZ_0003),
            ],
        ),
        bundle(
            BundleScope::Entitlement,
            vec![(1, "entitlement", ENTITLEMENT_0001)],
        ),
        bundle(BundleScope::Audit, vec![(1, "audit", AUDIT_0001)]),
    ]
}

/// Assemble one scope's bundle from `(version, description, ddl)` triples.
fn bundle(scope: BundleScope, steps: Vec<(i64, &'static str, &'static str)>) -> MigrationBundle {
    let migrations = steps
        .into_iter()
        .map(|(version, description, sql)| {
            Migration::new(version, description, sql)
                .unwrap_or_else(|err| panic!("invalid {} migration: {err}", scope.id()))
        })
        .collect();
    MigrationBundle::new(scope.id(), migrations)
        .unwrap_or_else(|err| panic!("invalid {} bundle: {err}", scope.id()))
}

/// A migration rendered for a concrete table prefix and dialect, ready to apply.
///
/// The flattened, ordered view of [`bundles`] a store exposes for inspection
/// (the readiness plan length, deployment-parity equality). The `checksum` is the
/// foundation-template identity, stable across dialects for a portable migration.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PlannedMigration {
    /// Owning bundle id (e.g. `iam.identity`).
    pub bundle: String,
    /// Migration version within the bundle.
    pub version: i64,
    /// Checksum of the canonical template under the active dialect.
    pub checksum: String,
    /// Prefix- and dialect-rendered DDL to execute for the active backend.
    pub sql: String,
}

/// Summary of an [`IamStore::migrate`] run.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MigrateReport {
    /// Steps applied this run.
    pub applied: usize,
    /// Steps skipped because they were already recorded.
    pub skipped: usize,
}

/// Executor seam a deployment provides to apply IAM's bundles and read its
/// ledger.
///
/// The Postgres and SQLite backends implement this over their own driver; tests
/// use the in-memory [`RecordingExecutor`]. Each implementation owns the
/// backend-specific apply transaction and single-applier guard, delegating the
/// *decision* of what to apply to [`awaken_scoped_migration::plan`] — so the
/// shared mechanism (ordering, checksums, drift detection, the ledger fence) is
/// identical across backends and only the driver edge differs.
pub trait MigrationExecutor {
    /// The SQL backend this executor applies and checksums migrations under.
    fn dialect(&self) -> Dialect;

    /// Apply every pending migration across `bundles` under `prefix`, in order,
    /// idempotently, under the backend's single-applier guard.
    ///
    /// Already-applied steps whose recorded checksum matches are skipped; a step
    /// whose recorded checksum differs is a drift error (bundles are append-only).
    /// Returns the steps applied this run.
    fn run_migrations(
        &mut self,
        prefix: &str,
        bundles: &[MigrationBundle],
    ) -> RepoResult<Vec<AppliedMigration>>;

    /// Read the recorded `(version -> checksum)` map for `bundle_id` under
    /// `prefix`, the input [`awaken_scoped_migration::plan`] verifies against.
    fn applied_versions(&self, prefix: &str, bundle_id: &str) -> RepoResult<BTreeMap<i64, String>>;
}

/// Storage adapter that owns IAM's schema for a given table prefix.
///
/// `Pool` is the host-supplied migration executor (a [`PostgresBackend`] /
/// [`SqliteBackend`] in real deployments, the [`RecordingExecutor`] in tests).
/// The store never opens or owns the pool's lifecycle in embedded mode — it owns
/// its *schema within* the shared database, isolated by the distinct prefix and
/// its own ledger.
///
/// [`PostgresBackend`]: super::PostgresBackend
/// [`SqliteBackend`]: super::SqliteBackend
#[derive(Debug, Clone)]
pub struct IamStore<Pool> {
    prefix: String,
    pool: Pool,
}

impl<Pool> IamStore<Pool> {
    /// Construct a store over `pool`, isolating IAM's tables behind `prefix`.
    ///
    /// `prefix` is validated by [`awaken_scoped_migration::sql_identifier`]
    /// (leading ASCII letter, then `[A-Za-z0-9_]`); it is concatenated into table
    /// names, so anything else is rejected to keep the rendered DDL injection-free.
    pub fn with_prefix(pool: Pool, prefix: impl Into<String>) -> RepoResult<Self> {
        let prefix = sql_identifier(&prefix.into()).map_err(migration_err)?;
        Ok(Self { prefix, pool })
    }

    /// The configured table prefix.
    pub fn prefix(&self) -> &str {
        &self.prefix
    }

    /// Borrow the underlying pool/executor handle.
    pub fn pool(&self) -> &Pool {
        &self.pool
    }

    /// Mutably borrow the underlying pool/executor handle.
    pub fn pool_mut(&mut self) -> &mut Pool {
        &mut self.pool
    }

    /// The ledger table name: `<prefix>_schema_migrations`.
    ///
    /// Each component keeps its own ledger so siblings sharing a database never
    /// contend on a single migration table.
    pub fn ledger_table(&self) -> String {
        format!("{}_schema_migrations", self.prefix)
    }
}

impl<Pool: MigrationExecutor> IamStore<Pool> {
    /// The full ordered set of migrations rendered for this prefix and the
    /// executor's backend [`Dialect`].
    ///
    /// The `checksum` is the neutral-template identity, so it is stable across
    /// dialects even though the rendered `sql` differs.
    pub fn plan(&self) -> Vec<PlannedMigration> {
        let dialect = self.pool.dialect();
        let mut planned = Vec::new();
        for bundle in bundles() {
            for migration in bundle.migrations() {
                planned.push(PlannedMigration {
                    bundle: bundle.bundle_id().to_owned(),
                    version: migration.version(),
                    checksum: migration.checksum_for(dialect),
                    sql: render(migration.sql_for(dialect), dialect, &self.prefix),
                });
            }
        }
        planned
    }

    /// Apply every pending migration in order, verifying already-applied steps.
    ///
    /// Idempotent and fail-closed: delegates the apply to the executor, which runs
    /// the foundation crate's plan under its single-applier guard so concurrent
    /// node startup is safe and a drifted step aborts the run.
    pub fn migrate(&mut self) -> RepoResult<MigrateReport> {
        let bundles = bundles();
        let total: usize = bundles.iter().map(|b| b.migrations().len()).sum();
        let applied = self.pool.run_migrations(&self.prefix, &bundles)?;
        Ok(MigrateReport {
            applied: applied.len(),
            skipped: total - applied.len(),
        })
    }

    /// Whether every planned migration is recorded with a matching checksum.
    ///
    /// The readiness ([`/readyz`](crate::Readiness)) probe behind it: it both
    /// confirms the node's own migrations are applied and, because it reads the
    /// ledger, proves the store is reachable. A pending step, a drifted checksum,
    /// or an unreadable ledger all report *not applied* — readiness fails closed.
    pub fn migrations_applied(&self) -> RepoResult<bool> {
        let dialect = self.pool.dialect();
        for bundle in bundles() {
            // An unreadable ledger errors here → not ready (fail closed).
            let applied = self
                .pool
                .applied_versions(&self.prefix, bundle.bundle_id())?;
            // A pending step (non-empty plan) or a drift/unknown-version error
            // (Err) both mean this node is not fully migrated.
            match plan_bundle(&bundle, &applied, dialect) {
                Ok(pending) if pending.is_empty() => {}
                _ => return Ok(false),
            }
        }
        Ok(true)
    }
}

/// In-memory [`MigrationExecutor`] for tests and the local adapter.
///
/// It drives the same foundation [`plan`](awaken_scoped_migration::plan) the real
/// backends do over an in-memory ledger, recording the rendered DDL it was asked
/// to run, so tests can assert ordering, idempotence, and drift handling without
/// a live database.
#[derive(Debug, Clone)]
pub struct RecordingExecutor {
    /// Recorded ledger rows keyed by `(bundle_id, version)` to their checksum.
    ledger: BTreeMap<(String, i64), String>,
    /// Backend dialect the plan is rendered and checksummed against.
    dialect: Dialect,
    /// DDL statements executed in order (the ledger DDL, then each applied body).
    pub executed: Vec<String>,
    /// Whether the ledger DDL has been recorded this executor's lifetime.
    ledger_created: bool,
}

impl Default for RecordingExecutor {
    fn default() -> Self {
        Self::new()
    }
}

impl RecordingExecutor {
    /// A fresh executor with an empty ledger, rendering for the
    /// [`Dialect::Postgres`] backend.
    pub fn new() -> Self {
        Self::with_dialect(Dialect::Postgres)
    }

    /// A fresh executor that renders the plan for a specific backend dialect.
    pub fn with_dialect(dialect: Dialect) -> Self {
        Self {
            ledger: BTreeMap::new(),
            dialect,
            executed: Vec::new(),
            ledger_created: false,
        }
    }

    /// Overwrite a ledger row's checksum to simulate a drifted prior apply.
    pub fn force_checksum(&mut self, bundle_id: &str, version: i64, checksum: &str) {
        self.ledger
            .insert((bundle_id.to_owned(), version), checksum.to_owned());
    }
}

impl MigrationExecutor for RecordingExecutor {
    fn dialect(&self) -> Dialect {
        self.dialect
    }

    fn run_migrations(
        &mut self,
        prefix: &str,
        bundles: &[MigrationBundle],
    ) -> RepoResult<Vec<AppliedMigration>> {
        if !self.ledger_created {
            self.executed.push(format!(
                "CREATE TABLE IF NOT EXISTS {prefix}_schema_migrations (...)"
            ));
            self.ledger_created = true;
        }
        let dialect = self.dialect;
        let mut applied = Vec::new();
        for bundle in bundles {
            let recorded = self.applied_versions(prefix, bundle.bundle_id())?;
            let pending = plan_bundle(bundle, &recorded, dialect).map_err(migration_err)?;
            for migration in pending {
                self.executed
                    .push(render(migration.sql_for(dialect), dialect, prefix));
                let checksum = migration.checksum_for(dialect);
                self.ledger.insert(
                    (bundle.bundle_id().to_owned(), migration.version()),
                    checksum.clone(),
                );
                applied.push(AppliedMigration {
                    bundle_id: bundle.bundle_id().to_owned(),
                    version: migration.version(),
                    checksum,
                    description: migration.ledger_description(),
                });
            }
        }
        Ok(applied)
    }

    fn applied_versions(
        &self,
        _prefix: &str,
        bundle_id: &str,
    ) -> RepoResult<BTreeMap<i64, String>> {
        Ok(self
            .ledger
            .iter()
            .filter(|((bundle, _), _)| bundle == bundle_id)
            .map(|((_, version), checksum)| (*version, checksum.clone()))
            .collect())
    }
}

// --- iam.identity DDL ------------------------------------------------------
//
// Accounts, external identities, sessions, and in-flight login flows. The
// external-identity natural key is (provider_key, subject); email is a mutable
// claim and never a key. `account_id` columns reference accounts by id resolved
// in the domain — deliberately no FK, so this bundle can deploy without the
// others present.
const IDENTITY_0001: &str = "\
CREATE TABLE IF NOT EXISTS {prefix}_accounts (\
 id TEXT PRIMARY KEY, \
 status TEXT NOT NULL, \
 display_name TEXT, \
 created_at TEXT NOT NULL, \
 updated_at TEXT NOT NULL);\n\
CREATE TABLE IF NOT EXISTS {prefix}_external_identities (\
 id TEXT PRIMARY KEY, \
 account_id TEXT NOT NULL, \
 provider_key TEXT NOT NULL, \
 subject TEXT NOT NULL, \
 claims {json} NOT NULL, \
 first_seen_at TEXT NOT NULL, \
 last_seen_at TEXT NOT NULL, \
 UNIQUE (provider_key, subject));\n\
CREATE INDEX IF NOT EXISTS {prefix}_external_identities_account_idx \
 ON {prefix}_external_identities (account_id);\n\
CREATE TABLE IF NOT EXISTS {prefix}_sessions (\
 id TEXT PRIMARY KEY, \
 account_id TEXT NOT NULL, \
 token_hash TEXT NOT NULL UNIQUE, \
 external_identity_id TEXT, \
 created_at TEXT NOT NULL, \
 last_seen_at TEXT NOT NULL, \
 expires_at TEXT NOT NULL, \
 revoked_at TEXT);\n\
CREATE TABLE IF NOT EXISTS {prefix}_login_flows (\
 id TEXT PRIMARY KEY, \
 provider_key TEXT NOT NULL, \
 state_hash TEXT NOT NULL, \
 nonce_hash TEXT, \
 pkce_verifier_hash TEXT, \
 return_to TEXT, \
 created_at TEXT NOT NULL, \
 expires_at TEXT NOT NULL, \
 consumed_at TEXT);";

// Long-lived, principal-scoped API tokens. Stored as the public lookup prefix
// plus the argon2id hash of the secret half — never the cleartext token. The
// scope is the JSON-encoded ActionKey set the token may exercise; `principal`
// is the JSON contract form, resolved in the domain with no FK into another
// bundle. An optional `expires_at` and a `revoked_at` stamp carry liveness.
const IDENTITY_0002: &str = "\
CREATE TABLE IF NOT EXISTS {prefix}_api_tokens (\
 id TEXT PRIMARY KEY, \
 prefix TEXT NOT NULL UNIQUE, \
 principal {json} NOT NULL, \
 secret_hash TEXT NOT NULL, \
 scope {json} NOT NULL, \
 created_at TEXT NOT NULL, \
 expires_at TEXT, \
 revoked_at TEXT);\n\
CREATE INDEX IF NOT EXISTS {prefix}_api_tokens_principal_idx \
 ON {prefix}_api_tokens (principal);";

// Downstream OAuth provider clients: the product clients allowed to integrate
// against IAM as an authorization server. The natural key is the public
// `client_id`. Redirect URIs and allowed scopes are the JSON contract form so
// the domain owns their shape; `secret_hash` is the hash of a confidential
// client's secret and is NULL for a public (PKCE-only) client — the cleartext
// secret is never stored.
const IDENTITY_0003: &str = "\
CREATE TABLE IF NOT EXISTS {prefix}_oauth_clients (\
 client_id TEXT PRIMARY KEY, \
 redirect_uris {json} NOT NULL, \
 allowed_scopes {json} NOT NULL, \
 secret_hash TEXT);";

// Collapse API-token authorization onto the policy engine (ADR-0008 decision 3):
// a key no longer carries a per-key `scope` ActionKey set; it is bound to one
// `workspace` for credential attribution (usage and rate-limit accounting) and
// draws its authority from the principal's role bindings. Drop the `scope`
// column and add the `workspace` binding. The default backfills any pre-existing
// row; every mint thereafter supplies the workspace explicitly.
const IDENTITY_0004: &str = "\
ALTER TABLE {prefix}_api_tokens DROP COLUMN scope;\n\
ALTER TABLE {prefix}_api_tokens ADD COLUMN workspace TEXT NOT NULL DEFAULT '';";

// --- iam.authz DDL ---------------------------------------------------------
//
// Grants, role memberships, and the resource-model registry. Subjects and
// scopes are stored as their JSON contract form so the domain owns their
// shape; no FK crosses into iam.identity or iam.entitlement.
const AUTHZ_0001: &str = "\
CREATE TABLE IF NOT EXISTS {prefix}_grants (\
 id TEXT PRIMARY KEY, \
 subject {json} NOT NULL, \
 action_pattern TEXT NOT NULL, \
 scope {json} NOT NULL, \
 effect TEXT NOT NULL);\n\
CREATE TABLE IF NOT EXISTS {prefix}_role_bindings (\
 principal {json} NOT NULL, \
 role TEXT NOT NULL, \
 scope {json} NOT NULL, \
 PRIMARY KEY (principal, role, scope));\n\
CREATE TABLE IF NOT EXISTS {prefix}_resource_edges (\
 resource_type TEXT NOT NULL, \
 resource_id TEXT NOT NULL, \
 parent {json} NOT NULL, \
 PRIMARY KEY (resource_type, resource_id));";

// The directory: organizations, groups, and reusable role definitions. Owners
// and members are stored as their JSON principal form so the domain owns their
// shape; an org/group reference is by id resolved in the domain, never a DB-level
// FK across rows. Appended as a second authz step, leaving 0001 untouched so its
// recorded identity never drifts.
const AUTHZ_0002: &str = "\
CREATE TABLE IF NOT EXISTS {prefix}_orgs (\
 id TEXT PRIMARY KEY, \
 display_name TEXT, \
 owner {json} NOT NULL, \
 created_at TEXT NOT NULL, \
 updated_at TEXT NOT NULL);\n\
CREATE TABLE IF NOT EXISTS {prefix}_groups (\
 id TEXT PRIMARY KEY, \
 org_id TEXT NOT NULL, \
 display_name TEXT, \
 members {json} NOT NULL, \
 created_at TEXT NOT NULL, \
 updated_at TEXT NOT NULL);\n\
CREATE INDEX IF NOT EXISTS {prefix}_groups_org_idx \
 ON {prefix}_groups (org_id);\n\
CREATE TABLE IF NOT EXISTS {prefix}_roles (\
 id TEXT PRIMARY KEY, \
 display_name TEXT, \
 action_patterns {json} NOT NULL, \
 created_at TEXT NOT NULL, \
 updated_at TEXT NOT NULL);";

// The shared-store freshness fence: the policy `version` and token `epoch` that
// HA advances in the store (rule 3) instead of per-node memory, so a bump on one
// node is visible to every node on the next read. A single pinned row (id = 1)
// holds both counters; a grant/role/membership change bumps `version` and a
// revoke bumps `epoch`, each in the same transaction as the write it fences. No
// FK crosses into another bundle. See high-availability.md.
const AUTHZ_0003: &str = "\
CREATE TABLE IF NOT EXISTS {prefix}_fence (\
 id INTEGER PRIMARY KEY, \
 version BIGINT NOT NULL DEFAULT 1, \
 epoch BIGINT NOT NULL DEFAULT 0, \
 updated_at {timestamptz} NOT NULL DEFAULT {now});";

// --- iam.entitlement DDL ---------------------------------------------------
//
// Plans and the per-principal subscription assignment. A subscription names a
// plan by id resolved in the domain — no FK to the plans table, keeping the
// bundle aggregate-safe with the rest.
const ENTITLEMENT_0001: &str = "\
CREATE TABLE IF NOT EXISTS {prefix}_plans (\
 id TEXT PRIMARY KEY, \
 tier TEXT NOT NULL, \
 features {json} NOT NULL, \
 limits {json} NOT NULL, \
 rates {json} NOT NULL);\n\
CREATE TABLE IF NOT EXISTS {prefix}_subscriptions (\
 principal {json} NOT NULL PRIMARY KEY, \
 plan_id TEXT NOT NULL);";

// --- iam.audit DDL ---------------------------------------------------------
//
// The append-only audit event log. `seq` is a backend-assigned autoincrement
// surrogate so events read back in exact append order on either dialect; the
// actor is the optional JSON principal form, absent when no principal is
// attributable. Audit references nothing by FK — it is a flat, write-once log.
const AUDIT_0001: &str = "\
CREATE TABLE IF NOT EXISTS {prefix}_audit_events (\
 seq {pk_autoinc}, \
 at TEXT NOT NULL, \
 actor {json}, \
 action TEXT NOT NULL, \
 detail TEXT NOT NULL);";

#[cfg(test)]
mod tests {
    use super::*;

    fn store(prefix: &str) -> IamStore<RecordingExecutor> {
        IamStore::with_prefix(RecordingExecutor::new(), prefix).expect("valid prefix")
    }

    #[test]
    fn bundles_partition_by_the_subdomain_scopes() {
        let all = bundles();
        let scopes: Vec<&str> = all.iter().map(|b| b.bundle_id()).collect();
        assert_eq!(
            scopes,
            ["iam.identity", "iam.authz", "iam.entitlement", "iam.audit"]
        );
    }

    #[test]
    fn bundles_pass_the_foundation_lint() {
        // The append-only ordering, distinct bundle ids, and bundle-independence
        // (no migration references a table another bundle owns) are enforced by
        // the shared crate's lint over the whole set, not by hand.
        awaken_scoped_migration::lint(&bundles()).expect("iam bundles must lint clean");
    }

    #[test]
    fn with_prefix_renders_table_and_ledger_names() {
        let store = store("iam");
        assert_eq!(store.ledger_table(), "iam_schema_migrations");
        let plan = store.plan();
        assert!(plan.iter().any(|m| m.sql.contains("iam_accounts")));
        assert!(plan.iter().any(|m| m.sql.contains("iam_api_tokens")));
        assert!(plan.iter().any(|m| m.sql.contains("iam_oauth_clients")));
        assert!(plan.iter().any(|m| m.sql.contains("iam_grants")));
        assert!(plan.iter().any(|m| m.sql.contains("iam_plans")));
        // No unrendered template tokens leak into the executed SQL.
        assert!(plan.iter().all(|m| !m.sql.contains('{')));
    }

    #[test]
    fn renders_postgres_and_sqlite_type_tokens_distinctly() {
        let pg = IamStore::with_prefix(RecordingExecutor::with_dialect(Dialect::Postgres), "iam")
            .expect("valid prefix");
        let lite = IamStore::with_prefix(RecordingExecutor::with_dialect(Dialect::Sqlite), "iam")
            .expect("valid prefix");

        let pg_sql: String = pg.plan().iter().map(|m| m.sql.clone()).collect();
        let lite_sql: String = lite.plan().iter().map(|m| m.sql.clone()).collect();

        // Postgres keeps JSONB; SQLite renders the portable TEXT form and never
        // emits a Postgres-only type.
        assert!(pg_sql.contains("claims JSONB"));
        assert!(!lite_sql.contains("JSONB"));
        assert!(lite_sql.contains("claims TEXT"));
    }

    #[test]
    fn checksum_is_dialect_independent_but_rendered_sql_is_not() {
        // The migration's recorded identity is the neutral template, so the
        // checksum is the same on either backend even though the rendered SQL is
        // dialect-specific.
        let pg = IamStore::with_prefix(RecordingExecutor::with_dialect(Dialect::Postgres), "iam")
            .expect("valid prefix");
        let lite = IamStore::with_prefix(RecordingExecutor::with_dialect(Dialect::Sqlite), "iam")
            .expect("valid prefix");
        let (pg_plan, lite_plan) = (pg.plan(), lite.plan());
        assert_eq!(pg_plan.len(), lite_plan.len());
        let mut any_diverged = false;
        for (a, b) in pg_plan.iter().zip(lite_plan.iter()) {
            assert_eq!(
                a.checksum, b.checksum,
                "{}::{} identity drifted",
                a.bundle, a.version
            );
            any_diverged |= a.sql != b.sql;
        }
        assert!(
            any_diverged,
            "no migration rendered dialect-specifically; type-token rendering is inert"
        );
    }

    #[test]
    fn both_dialects_migrate_cleanly_and_idempotently() {
        for dialect in [Dialect::Postgres, Dialect::Sqlite] {
            let mut store = IamStore::with_prefix(RecordingExecutor::with_dialect(dialect), "iam")
                .expect("valid prefix");
            let first = store.migrate().expect("first migrate");
            assert_eq!(first.applied, store.plan().len());
            assert_eq!(first.skipped, 0);
            let second = store.migrate().expect("second migrate");
            assert_eq!(second.applied, 0);
            assert_eq!(second.skipped, store.plan().len());
        }
    }

    #[test]
    fn a_different_prefix_isolates_a_sibling_in_the_same_database() {
        let store = store("iamx");
        assert_eq!(store.ledger_table(), "iamx_schema_migrations");
        assert!(store.plan().iter().all(|m| m.sql.contains("iamx_")));
    }

    #[test]
    fn invalid_prefixes_are_rejected() {
        // Empty, a leading digit, and an injection attempt are all rejected by the
        // shared identifier validation.
        assert!(IamStore::with_prefix(RecordingExecutor::new(), "").is_err());
        assert!(IamStore::with_prefix(RecordingExecutor::new(), "iam_accounts; DROP").is_err());
        assert!(IamStore::with_prefix(RecordingExecutor::new(), "1iam").is_err());
        // A bare lowercase identifier is accepted.
        assert!(IamStore::with_prefix(RecordingExecutor::new(), "iam").is_ok());
    }

    #[test]
    fn migrate_applies_every_step_once_then_is_idempotent() {
        let mut store = store("iam");
        let first = store.migrate().expect("first migrate");
        assert_eq!(first.applied, store.plan().len());
        assert_eq!(first.skipped, 0);

        let second = store.migrate().expect("second migrate");
        assert_eq!(second.applied, 0);
        assert_eq!(second.skipped, store.plan().len());

        // The ledger DDL ran exactly once.
        let ledger_runs = store
            .pool()
            .executed
            .iter()
            .filter(|s| s.contains("schema_migrations"))
            .count();
        assert_eq!(ledger_runs, 1);
    }

    #[test]
    fn migrate_detects_checksum_drift_in_an_applied_step() {
        let mut executor = RecordingExecutor::new();
        executor.force_checksum("iam.identity", 1, "deadbeef");
        let mut store = IamStore::with_prefix(executor, "iam").expect("valid prefix");
        let err = store.migrate().expect_err("drift must fail closed");
        assert!(matches!(err, RepoError::Backend(msg) if msg.contains("checksum mismatch")));
    }

    #[test]
    fn migrations_applied_is_false_before_and_true_after_migrate() {
        let mut store = store("iam");
        // Readiness fences on this: an un-migrated store is not applied.
        assert!(!store.migrations_applied().expect("probe"));
        store.migrate().expect("migrate");
        assert!(store.migrations_applied().expect("probe"));
    }

    #[test]
    fn migrations_applied_is_false_when_a_recorded_step_drifts() {
        let mut store = store("iam");
        store.migrate().expect("migrate");
        // Corrupt one recorded checksum: readiness must report not-applied, never
        // a hopeful ready over a ledger it can no longer trust.
        store.pool_mut().force_checksum("iam.authz", 3, "deadbeef");
        assert!(!store.migrations_applied().expect("probe"));
    }

    #[test]
    fn checksums_are_stable_and_per_migration() {
        let plan = store("iam").plan();
        // Stable across renders/prefixes.
        let again = store("other").plan();
        for (a, b) in plan.iter().zip(again.iter()) {
            assert_eq!(a.checksum, b.checksum);
        }
        // Distinct migrations have distinct checksums.
        let mut sums: Vec<&str> = plan.iter().map(|m| m.checksum.as_str()).collect();
        sums.sort_unstable();
        sums.dedup();
        assert_eq!(sums.len(), plan.len());
    }
}
