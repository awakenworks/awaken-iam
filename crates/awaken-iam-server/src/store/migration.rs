//! Scope-partitioned, self-contained schema migration bundles.
//!
//! IAM owns its schema as append-only, checksum-verified migration bundles, one
//! per subdomain scope, adopting the `awaken-sql-migration` pattern. Two rules
//! keep the bundles split-or-aggregate safe (see
//! [deployment](../../../../docs/design/deployment.md)):
//!
//! 1. No bundle hard-couples to another bundle; bundles version independently.
//! 2. No cross-component foreign key. References *between* IAM subdomains are by
//!    id resolved in the domain, never a DB-level FK across bundles.
//!
//! The store is constructed with a table prefix —
//! [`IamStore::with_prefix`]`(pool, "iam")` yields `iam_accounts`,
//! `iam_grants`, … and the ledger `iam_schema_migrations`. The same DDL renders
//! against any prefix, which is what lets IAM deploy embedded (sharing a host's
//! database next to siblings using their own prefixes) or standalone (its own
//! database) from one codebase. The pool itself is supplied by the host through
//! a [`MigrationExecutor`]; this module is pool-agnostic so the core stays
//! storage-free and each backend executor (Postgres, SQLite) is a thin edge
//! adapter over the plan.
//!
//! DDL is authored **dialect-neutral**: a step's template uses the prefix token
//! and a small portable type-token vocabulary (e.g. `{json}`, `{timestamptz}`,
//! `{blob}`), which the backend executor renders to that dialect alongside the
//! prefix; a step that cannot be expressed neutrally may carry a per-dialect
//! override. See [ADR-0003](../../../../docs/adr/0003-storage-backends.md).

use sha2::{Digest, Sha256};

use awaken_iam_core::{RepoError, RepoResult};

/// The token every bundle's DDL uses where the configured table prefix belongs.
const PREFIX_TOKEN: &str = "{prefix}";

/// Portable type-token vocabulary (ADR-0003).
///
/// Each row is `(token, postgres, sqlite)`. A bundle's DDL is authored
/// dialect-neutral using these tokens wherever a backend-specific column type or
/// function belongs; the active backend's [`Dialect`] renders each to its
/// concrete form alongside the table prefix. Only tokens actually used by the
/// shipped bundles need a row, but the set is kept small and stable so adding a
/// backend is a column in this table, not a schema rewrite.
const TYPE_TOKENS: &[(&str, &str, &str)] = &[
    ("{json}", "JSONB", "TEXT"),
    ("{timestamptz}", "TIMESTAMPTZ", "TEXT"),
    ("{now}", "now()", "CURRENT_TIMESTAMP"),
    ("{blob}", "BYTEA", "BLOB"),
    (
        "{pk_autoinc}",
        "BIGSERIAL PRIMARY KEY",
        "INTEGER PRIMARY KEY AUTOINCREMENT",
    ),
];

/// Ledger DDL template, rendered per dialect like any bundle step.
const LEDGER_TEMPLATE: &str = "\
CREATE TABLE IF NOT EXISTS {prefix}_schema_migrations (\
 bundle TEXT NOT NULL, \
 id TEXT NOT NULL, \
 checksum TEXT NOT NULL, \
 applied_at {timestamptz} NOT NULL DEFAULT {now}, \
 PRIMARY KEY (bundle, id))";

/// SQL backend a deployment renders and applies the migration plan against.
///
/// The backend choice is configuration, not a code fork (see
/// [ADR-0003](../../../../docs/adr/0003-storage-backends.md)): the same bundles,
/// ledger discipline, and `MigrationExecutor` seam drive either, and only the
/// dialect-token rendering and the single-applier guard differ.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum Dialect {
    /// PostgreSQL — the standalone / cloud / multi-node HA backend.
    #[default]
    Postgres,
    /// SQLite — the embedded / local / single-node backend.
    Sqlite,
}

impl Dialect {
    /// Render a single type token to this dialect's concrete form.
    fn render_token(self, postgres: &'static str, sqlite: &'static str) -> &'static str {
        match self {
            Dialect::Postgres => postgres,
            Dialect::Sqlite => sqlite,
        }
    }
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
    /// `iam.authz` — grants, role memberships, resource-model registry.
    Authz,
    /// `iam.entitlement` — plans and subscriptions.
    Entitlement,
}

impl BundleScope {
    /// Stable dotted bundle id recorded in the ledger.
    pub const fn id(self) -> &'static str {
        match self {
            BundleScope::Identity => "iam.identity",
            BundleScope::Authz => "iam.authz",
            BundleScope::Entitlement => "iam.entitlement",
        }
    }

    /// Every scope, in canonical apply order.
    pub const fn all() -> [BundleScope; 3] {
        [
            BundleScope::Identity,
            BundleScope::Authz,
            BundleScope::Entitlement,
        ]
    }
}

/// A single append-only DDL step within a bundle.
///
/// `up_sql` is a dialect-neutral DDL template that uses the [`PREFIX_TOKEN`]
/// wherever a table name is built, and portable type tokens (e.g. `{json}`,
/// `{timestamptz}`, `{blob}`) wherever a backend-specific column type belongs, so
/// the same statement renders against any prefix and either backend (see
/// [ADR-0003](../../../../docs/adr/0003-storage-backends.md)).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Migration {
    /// Stable, ordered id unique within the owning bundle (e.g. `0001_init`).
    pub id: &'static str,
    /// Prefix- and type-token-templated DDL applied for this step.
    pub up_sql: &'static str,
}

impl Migration {
    /// Content checksum over the canonical (un-prefixed) DDL template.
    ///
    /// The checksum is taken over the template, not the rendered SQL, so the
    /// recorded identity of a migration is stable across deployments that use
    /// different prefixes. Drift in an already-applied step is detected by
    /// comparing this value against the ledger.
    pub fn checksum(&self) -> String {
        let mut hasher = Sha256::new();
        hasher.update(self.id.as_bytes());
        hasher.update([0u8]);
        hasher.update(self.up_sql.as_bytes());
        let digest = hasher.finalize();
        let mut hex = String::with_capacity(digest.len() * 2);
        for byte in digest {
            hex.push_str(&format!("{byte:02x}"));
        }
        hex
    }
}

/// An append-only, checksum-verified sequence of migrations for one scope.
#[derive(Debug, Clone)]
pub struct MigrationBundle {
    /// Component scope this bundle owns.
    pub scope: BundleScope,
    /// Ordered migrations; never reordered or edited in place once shipped.
    pub migrations: Vec<Migration>,
}

/// A migration rendered for a concrete table prefix, ready to apply.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PlannedMigration {
    /// Owning bundle id (e.g. `iam.identity`).
    pub bundle: &'static str,
    /// Migration id within the bundle.
    pub id: &'static str,
    /// Checksum of the canonical template.
    pub checksum: String,
    /// Prefix- and dialect-rendered DDL to execute for the active backend.
    pub sql: String,
}

/// Storage adapter that owns IAM's schema for a given table prefix.
///
/// `Pool` is the host-supplied connection handle (a `PgPool` in the Postgres
/// deployment, a SQLite connection in the single-node deployment, the recording
/// executor in tests). The store never opens or owns
/// the pool's lifecycle in embedded mode — it owns its *schema within* the
/// shared database, isolated by the distinct prefix and its own ledger.
#[derive(Debug, Clone)]
pub struct IamStore<Pool> {
    prefix: String,
    pool: Pool,
}

impl<Pool> IamStore<Pool> {
    /// Construct a store over `pool`, isolating IAM's tables behind `prefix`.
    ///
    /// `prefix` must be a bare identifier fragment (lowercase letters, digits,
    /// and underscore); it is concatenated into table names, so anything else
    /// is rejected to keep the rendered DDL injection-free.
    pub fn with_prefix(pool: Pool, prefix: impl Into<String>) -> RepoResult<Self> {
        let prefix = prefix.into();
        if prefix.is_empty()
            || !prefix
                .bytes()
                .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'_')
        {
            return Err(RepoError::Backend(format!(
                "invalid table prefix {prefix:?}: expected [a-z0-9_]+"
            )));
        }
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

    /// The ledger table name: `<prefix>_schema_migrations`.
    ///
    /// Each component keeps its own ledger so siblings sharing a database never
    /// contend on a single migration table. The name carries only the prefix —
    /// no type tokens — so it is dialect-independent.
    pub fn ledger_table(&self) -> String {
        format!("{PREFIX_TOKEN}_schema_migrations").replace(PREFIX_TOKEN, &self.prefix)
    }

    /// Render a DDL template for `dialect`: substitute the table prefix, then
    /// every [`TYPE_TOKENS`] entry to its dialect-specific form.
    fn render_ddl(&self, template: &str, dialect: Dialect) -> String {
        let mut sql = template.replace(PREFIX_TOKEN, &self.prefix);
        for (token, postgres, sqlite) in TYPE_TOKENS {
            sql = sql.replace(token, dialect.render_token(postgres, sqlite));
        }
        sql
    }
}

impl<Pool: MigrationExecutor> IamStore<Pool> {
    /// DDL that creates this store's ledger if it does not already exist,
    /// rendered for the executor's backend [`Dialect`].
    pub fn ledger_ddl(&self) -> String {
        self.render_ddl(LEDGER_TEMPLATE, self.pool.dialect())
    }

    /// The full ordered set of migrations rendered for this prefix and the
    /// executor's backend [`Dialect`]. The `checksum` is the neutral-template
    /// identity (ADR-0003 decision 5), so it is stable across dialects even
    /// though the rendered `sql` differs.
    pub fn plan(&self) -> Vec<PlannedMigration> {
        let dialect = self.pool.dialect();
        let mut planned = Vec::new();
        for bundle in bundles() {
            for migration in &bundle.migrations {
                planned.push(PlannedMigration {
                    bundle: bundle.scope.id(),
                    id: migration.id,
                    checksum: migration.checksum(),
                    sql: self.render_ddl(migration.up_sql, dialect),
                });
            }
        }
        planned
    }

    /// Apply every pending migration in order, verifying already-applied steps.
    ///
    /// Idempotent: a step whose ledger checksum matches is skipped. A step whose
    /// recorded checksum differs from the shipped template is a drift error —
    /// bundles are append-only, so an applied step must never change.
    pub fn migrate(&mut self) -> RepoResult<MigrateReport> {
        let ledger = self.ledger_table();
        let ledger_ddl = self.ledger_ddl();
        self.pool.ensure_ledger(&ledger_ddl)?;

        let mut applied = 0usize;
        let mut skipped = 0usize;
        for step in self.plan() {
            match self.pool.recorded_checksum(&ledger, step.bundle, step.id)? {
                Some(existing) if existing == step.checksum => {
                    skipped += 1;
                }
                Some(existing) => {
                    return Err(RepoError::Backend(format!(
                        "migration {}::{} drifted: ledger checksum {existing} != shipped {}",
                        step.bundle, step.id, step.checksum
                    )));
                }
                None => {
                    self.pool.apply(&ledger, &step)?;
                    applied += 1;
                }
            }
        }
        Ok(MigrateReport { applied, skipped })
    }
}

/// Summary of a [`IamStore::migrate`] run.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MigrateReport {
    /// Steps applied this run.
    pub applied: usize,
    /// Steps skipped because they were already recorded.
    pub skipped: usize,
}

/// Executor seam a deployment provides to apply the rendered plan.
///
/// The Postgres deployment implements this over a `PgPool`; tests use the
/// in-memory [`RecordingExecutor`]. Keeping the seam here lets the same plan and
/// ledger discipline drive embedded and standalone identically.
pub trait MigrationExecutor {
    /// The SQL backend this executor applies against.
    ///
    /// Drives dialect-token rendering of the plan. Defaults to
    /// [`Dialect::Postgres`] so existing executors need no change; a SQLite
    /// executor overrides it.
    fn dialect(&self) -> Dialect {
        Dialect::Postgres
    }

    /// Create the ledger table if absent.
    fn ensure_ledger(&mut self, ledger_ddl: &str) -> RepoResult<()>;
    /// Return the recorded checksum for an applied `(bundle, id)`, if any.
    fn recorded_checksum(&self, ledger: &str, bundle: &str, id: &str)
    -> RepoResult<Option<String>>;
    /// Execute a migration's DDL and record it in the ledger atomically.
    fn apply(&mut self, ledger: &str, migration: &PlannedMigration) -> RepoResult<()>;
}

/// In-memory [`MigrationExecutor`] for tests and the local adapter.
///
/// It records the rendered DDL it was asked to run and the ledger rows it
/// wrote, so tests can assert ordering, idempotence, and drift handling without
/// a live database.
#[derive(Debug, Default, Clone)]
pub struct RecordingExecutor {
    ledger_created: bool,
    /// Ledger rows keyed by `(bundle, id)` to their recorded checksum.
    ledger: Vec<(String, String, String)>,
    /// Backend dialect the plan is rendered against.
    dialect: Dialect,
    /// DDL statements executed in order.
    pub executed: Vec<String>,
}

impl RecordingExecutor {
    /// A fresh executor with an empty ledger, rendering for the default
    /// ([`Dialect::Postgres`]) backend.
    pub fn new() -> Self {
        Self::default()
    }

    /// A fresh executor that renders the plan for a specific backend dialect.
    pub fn with_dialect(dialect: Dialect) -> Self {
        Self {
            dialect,
            ..Self::default()
        }
    }

    /// Overwrite a ledger row's checksum to simulate a drifted prior apply.
    pub fn force_checksum(&mut self, bundle: &str, id: &str, checksum: &str) {
        if let Some(row) = self
            .ledger
            .iter_mut()
            .find(|(b, i, _)| b == bundle && i == id)
        {
            row.2 = checksum.to_owned();
        } else {
            self.ledger
                .push((bundle.to_owned(), id.to_owned(), checksum.to_owned()));
        }
    }
}

impl MigrationExecutor for RecordingExecutor {
    fn dialect(&self) -> Dialect {
        self.dialect
    }

    fn ensure_ledger(&mut self, ledger_ddl: &str) -> RepoResult<()> {
        if !self.ledger_created {
            self.executed.push(ledger_ddl.to_owned());
            self.ledger_created = true;
        }
        Ok(())
    }

    fn recorded_checksum(
        &self,
        _ledger: &str,
        bundle: &str,
        id: &str,
    ) -> RepoResult<Option<String>> {
        Ok(self
            .ledger
            .iter()
            .find(|(b, i, _)| b == bundle && i == id)
            .map(|(_, _, checksum)| checksum.clone()))
    }

    fn apply(&mut self, _ledger: &str, migration: &PlannedMigration) -> RepoResult<()> {
        self.executed.push(migration.sql.clone());
        self.ledger.push((
            migration.bundle.to_owned(),
            migration.id.to_owned(),
            migration.checksum.clone(),
        ));
        Ok(())
    }
}

/// The canonical IAM migration bundles, one per subdomain scope.
pub fn bundles() -> Vec<MigrationBundle> {
    vec![
        MigrationBundle {
            scope: BundleScope::Identity,
            migrations: vec![
                Migration {
                    id: "0001_identity",
                    up_sql: IDENTITY_0001,
                },
                Migration {
                    id: "0002_api_tokens",
                    up_sql: IDENTITY_0002,
                },
            ],
        },
        MigrationBundle {
            scope: BundleScope::Authz,
            migrations: vec![Migration {
                id: "0001_authz",
                up_sql: AUTHZ_0001,
            }],
        },
        MigrationBundle {
            scope: BundleScope::Entitlement,
            migrations: vec![Migration {
                id: "0001_entitlement",
                up_sql: ENTITLEMENT_0001,
            }],
        },
    ]
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

#[cfg(test)]
mod tests {
    use super::*;

    fn store(prefix: &str) -> IamStore<RecordingExecutor> {
        IamStore::with_prefix(RecordingExecutor::new(), prefix).expect("valid prefix")
    }

    #[test]
    fn bundles_partition_by_the_three_subdomain_scopes() {
        let scopes: Vec<&str> = bundles().iter().map(|b| b.scope.id()).collect();
        assert_eq!(scopes, ["iam.identity", "iam.authz", "iam.entitlement"]);
    }

    #[test]
    fn with_prefix_renders_table_and_ledger_names() {
        let store = store("iam");
        assert_eq!(store.ledger_table(), "iam_schema_migrations");
        let plan = store.plan();
        assert!(plan.iter().any(|m| m.sql.contains("iam_accounts")));
        assert!(plan.iter().any(|m| m.sql.contains("iam_api_tokens")));
        assert!(plan.iter().any(|m| m.sql.contains("iam_grants")));
        assert!(plan.iter().any(|m| m.sql.contains("iam_plans")));
        // No unrendered template tokens leak into the executed SQL — neither the
        // prefix token nor any type token.
        assert!(plan.iter().all(|m| !m.sql.contains(PREFIX_TOKEN)));
        for (token, _, _) in TYPE_TOKENS {
            assert!(
                plan.iter().all(|m| !m.sql.contains(token)),
                "type token {token} leaked into rendered SQL"
            );
        }
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

        // The ledger timestamp default differs per dialect.
        assert!(pg.ledger_ddl().contains("TIMESTAMPTZ"));
        assert!(pg.ledger_ddl().contains("now()"));
        assert!(lite.ledger_ddl().contains("CURRENT_TIMESTAMP"));
        assert!(!lite.ledger_ddl().contains("TIMESTAMPTZ"));
    }

    #[test]
    fn checksum_is_dialect_independent_but_rendered_sql_is_not() {
        // ADR-0003 decision 5: the migration's recorded identity is the neutral
        // template, so the checksum is the same on either backend even though
        // the rendered SQL is dialect-specific.
        let pg = IamStore::with_prefix(RecordingExecutor::with_dialect(Dialect::Postgres), "iam")
            .expect("valid prefix");
        let lite = IamStore::with_prefix(RecordingExecutor::with_dialect(Dialect::Sqlite), "iam")
            .expect("valid prefix");
        let (pg_plan, lite_plan) = (pg.plan(), lite.plan());
        assert_eq!(pg_plan.len(), lite_plan.len());
        for (a, b) in pg_plan.iter().zip(lite_plan.iter()) {
            assert_eq!(
                a.checksum, b.checksum,
                "{}::{} identity drifted",
                a.bundle, a.id
            );
            assert_ne!(a.sql, b.sql, "{}::{} rendered identically", a.bundle, a.id);
        }
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
        assert!(IamStore::with_prefix(RecordingExecutor::new(), "").is_err());
        assert!(IamStore::with_prefix(RecordingExecutor::new(), "iam_accounts; DROP").is_err());
        assert!(IamStore::with_prefix(RecordingExecutor::new(), "IAM").is_err());
    }

    #[test]
    fn no_bundle_declares_a_cross_component_foreign_key() {
        // The whole point of the bundles: references between subdomains are by
        // id resolved in the domain, never a DB-level FK. Assert the DDL never
        // declares one.
        for bundle in bundles() {
            for migration in &bundle.migrations {
                let sql = migration.up_sql.to_uppercase();
                assert!(
                    !sql.contains("FOREIGN KEY") && !sql.contains("REFERENCES"),
                    "{}::{} declares a foreign key",
                    bundle.scope.id(),
                    migration.id
                );
            }
        }
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

    #[test]
    fn migrate_applies_every_step_once_then_is_idempotent() {
        let mut store = store("iam");
        let first = store.migrate().expect("first migrate");
        assert_eq!(first.applied, store.plan().len());
        assert_eq!(first.skipped, 0);

        let second = store.migrate().expect("second migrate");
        assert_eq!(second.applied, 0);
        assert_eq!(second.skipped, store.plan().len());

        // Ledger DDL ran exactly once; every bundle's DDL ran exactly once.
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
        executor.force_checksum("iam.identity", "0001_identity", "deadbeef");
        let mut store = IamStore::with_prefix(executor, "iam").expect("valid prefix");
        let err = store.migrate().expect_err("drift must fail closed");
        assert!(matches!(err, RepoError::Backend(msg) if msg.contains("drifted")));
    }
}
