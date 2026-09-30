//! The canonical IAM migration bundles: IAM's schema, as scope-partitioned,
//! append-only [`MigrationBundle`] values.
//!
//! This module is deliberately separate from the migration *mechanism*
//! ([`super::migration`]): it only *constructs* migrations (the DDL bodies and
//! their bundle/version layout), so the portable `check_migrations.py` hook
//! auto-discovers and best-practice-checks it, while the store/executor machinery
//! next door (which it would otherwise mistake for the crate's own
//! implementation) stays out of scope.
//!
//! Two rules keep the bundles split-or-aggregate safe (see
//! [deployment](../../../../docs/design/deployment.md)) and are enforced by
//! [`awaken_scoped_migration::lint`] over [`bundles`], not by hand:
//!
//! 1. No bundle hard-couples to another bundle; bundles version independently.
//! 2. No cross-component foreign key. References *between* IAM subdomains are by
//!    id resolved in the domain, never a DB-level FK across bundles.
//!
//! DDL is authored **dialect-neutral** using the foundation crate's portable
//! brace-wrapped token vocabulary (the table prefix plus the JSON, timestamp,
//! blob, and primary-key type tokens), which each backend renders to its
//! dialect via [`awaken_scoped_migration::render`]. Statements are
//! unconditional: the ledger guarantees each runs exactly once, so a bare
//! `CREATE TABLE` (not the conditional form) fails loudly on drift instead of
//! masking it.

use awaken_scoped_migration::{Migration, MigrationBundle};

// reviewed: migration-allow-edit — append the next Directory step while preserving
// every shipped body byte-for-byte; only rustfmt changed the registry shape.

/// Component-scope partition a migration bundle belongs to.
///
/// The scope decides *where the tables live* (which bundle owns them), distinct
/// from tenant scope which decides *whose rows they hold*. A bundle never
/// references a table owned by another scope.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum BundleScope {
    /// `iam.identity` — accounts, external identities, sessions, login flows.
    Identity,
    /// `iam.authz` — organizations, groups, roles, grants, role memberships,
    /// and the resource-model registry.
    Authz,
    /// `iam.directory` — user-visible hierarchy and product-space placement.
    Directory,
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
            BundleScope::Directory => "iam.directory",
            BundleScope::Entitlement => "iam.entitlement",
            BundleScope::Audit => "iam.audit",
        }
    }

    /// Every scope, in canonical apply order.
    pub const fn all() -> [BundleScope; 5] {
        [
            BundleScope::Identity,
            BundleScope::Authz,
            BundleScope::Directory,
            BundleScope::Entitlement,
            BundleScope::Audit,
        ]
    }
}

/// The canonical IAM migration bundles, one per subdomain scope, built on the
/// shared [`MigrationBundle`] value type.
///
/// Each bundle's migrations are versioned `1, 2, …` within the bundle (the
/// foundation crate renders the readable zero-padded label and checksums over it).
/// The bundle ids are the [`BundleScope`] dotted ids. The DDL bodies are static
/// and tested by the [`lint`](awaken_scoped_migration::lint) check below, so the
/// per-`Migration` construction cannot fail in practice; an `expect` keeps the
/// public signature infallible.
pub fn bundles() -> Vec<MigrationBundle> {
    vec![
        bundle(
            BundleScope::Identity,
            vec![
                (
                    1,
                    "accounts, external identities, sessions, login flows",
                    IDENTITY_0001,
                ),
                (2, "long-lived principal-scoped API tokens", IDENTITY_0002),
                (3, "downstream OAuth provider clients", IDENTITY_0003),
                (
                    4,
                    "bind API tokens to a workspace; drop per-token scope",
                    IDENTITY_0004,
                ),
                (
                    5,
                    "single-use downstream OAuth authorization codes",
                    IDENTITY_0005,
                ),
            ],
        ),
        bundle(
            BundleScope::Authz,
            vec![
                (1, "grants, role bindings, resource model edges", AUTHZ_0001),
                (
                    2,
                    "organizations, groups, reusable role definitions",
                    AUTHZ_0002,
                ),
                (
                    3,
                    "shared-store freshness fence for HA policy/epoch versioning",
                    AUTHZ_0003,
                ),
                (
                    4,
                    "immutable authorization profiles and atomic active heads",
                    AUTHZ_0004,
                ),
                (5, "initialize the singleton freshness fence", AUTHZ_0005),
                (6, "persist Workspace to Org scope projections", AUTHZ_0006),
                (7, "organization invitation lifecycle", AUTHZ_0007),
                (
                    8,
                    "product projection ownership and resource tombstones",
                    AUTHZ_0008,
                ),
            ],
        ),
        bundle(
            BundleScope::Directory,
            vec![
                (
                    1,
                    "arbitrary directory nodes and stable product-space placement",
                    DIRECTORY_0001,
                ),
                (
                    2,
                    "enforce one product-space placement per Directory node",
                    DIRECTORY_0002,
                ),
                (
                    3,
                    "partition product-space identity and revision by organization",
                    DIRECTORY_0003,
                ),
                (
                    4,
                    "separate product-space lifecycle from node presentation",
                    DIRECTORY_0004,
                ),
            ],
        ),
        bundle(
            BundleScope::Entitlement,
            vec![(
                1,
                "plans and per-principal subscription assignments",
                ENTITLEMENT_0001,
            )],
        ),
        bundle(
            BundleScope::Audit,
            vec![(1, "append-only audit event log", AUDIT_0001)],
        ),
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

// --- iam.identity DDL ------------------------------------------------------
//
// Accounts, external identities, sessions, and in-flight login flows. The
// external-identity natural key is (provider_key, subject); email is a mutable
// claim and never a key. `account_id` columns reference accounts by id resolved
// in the domain — deliberately no FK, so this bundle can deploy without the
// others present.
const IDENTITY_0001: &str = "\
CREATE TABLE {prefix}_accounts (\
 id TEXT PRIMARY KEY, \
 status TEXT NOT NULL, \
 display_name TEXT, \
 created_at TEXT NOT NULL, \
 updated_at TEXT NOT NULL);\n\
CREATE TABLE {prefix}_external_identities (\
 id TEXT PRIMARY KEY, \
 account_id TEXT NOT NULL, \
 provider_key TEXT NOT NULL, \
 subject TEXT NOT NULL, \
 claims {json} NOT NULL, \
 first_seen_at TEXT NOT NULL, \
 last_seen_at TEXT NOT NULL, \
 UNIQUE (provider_key, subject));\n\
CREATE INDEX {prefix}_external_identities_account_idx \
 ON {prefix}_external_identities (account_id);\n\
CREATE TABLE {prefix}_sessions (\
 id TEXT PRIMARY KEY, \
 account_id TEXT NOT NULL, \
 token_hash TEXT NOT NULL UNIQUE, \
 external_identity_id TEXT, \
 created_at TEXT NOT NULL, \
 last_seen_at TEXT NOT NULL, \
 expires_at TEXT NOT NULL, \
 revoked_at TEXT);\n\
CREATE TABLE {prefix}_login_flows (\
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
CREATE TABLE {prefix}_api_tokens (\
 id TEXT PRIMARY KEY, \
 prefix TEXT NOT NULL UNIQUE, \
 principal {json} NOT NULL, \
 secret_hash TEXT NOT NULL, \
 scope {json} NOT NULL, \
 created_at TEXT NOT NULL, \
 expires_at TEXT, \
 revoked_at TEXT);\n\
CREATE INDEX {prefix}_api_tokens_principal_idx \
 ON {prefix}_api_tokens (principal);";

// Downstream OAuth provider clients: the product clients allowed to integrate
// against IAM as an authorization server. The natural key is the public
// `client_id`. Redirect URIs and allowed scopes are the JSON contract form so
// the domain owns their shape; `secret_hash` is the hash of a confidential
// client's secret and is NULL for a public (PKCE-only) client — the cleartext
// secret is never stored.
const IDENTITY_0003: &str = "\
CREATE TABLE {prefix}_oauth_clients (\
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
//
// This deliberately drops a column. The check-migrations hook flags destructive
// ops by default; the column carried no authorization state worth preserving
// (authority now derives from role bindings), so the drop is intentional and
// reviewed: migration-allow-destructive
const IDENTITY_0004: &str = "\
ALTER TABLE {prefix}_api_tokens DROP COLUMN scope;\n\
ALTER TABLE {prefix}_api_tokens ADD COLUMN workspace TEXT NOT NULL DEFAULT '';";

// Hashed downstream authorization codes. The conditional update over
// `consumed_at IS NULL AND expires_at > now` is the shared multi-replica replay
// fence; no cleartext browser code is persisted.
const IDENTITY_0005: &str = "\
CREATE TABLE {prefix}_oauth_authorization_codes (\
 code_hash TEXT PRIMARY KEY, \
 client_id TEXT NOT NULL, \
 redirect_uri TEXT NOT NULL, \
 account_id TEXT NOT NULL, \
 scopes {json} NOT NULL, \
 code_challenge TEXT, \
 nonce TEXT, \
 expires_at TEXT NOT NULL, \
 consumed_at TEXT);\n\
CREATE INDEX {prefix}_oauth_authorization_codes_expiry_idx \
 ON {prefix}_oauth_authorization_codes (expires_at);";

// --- iam.authz DDL ---------------------------------------------------------
//
// Grants, role memberships, and the resource-model registry. Subjects and
// scopes are stored as their JSON contract form so the domain owns their
// shape; no FK crosses into iam.identity or iam.entitlement.
const AUTHZ_0001: &str = "\
CREATE TABLE {prefix}_grants (\
 id TEXT PRIMARY KEY, \
 subject {json} NOT NULL, \
 action_pattern TEXT NOT NULL, \
 scope {json} NOT NULL, \
 effect TEXT NOT NULL);\n\
CREATE TABLE {prefix}_role_bindings (\
 principal {json} NOT NULL, \
 role TEXT NOT NULL, \
 scope {json} NOT NULL, \
 PRIMARY KEY (principal, role, scope));\n\
CREATE TABLE {prefix}_resource_edges (\
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
CREATE TABLE {prefix}_orgs (\
 id TEXT PRIMARY KEY, \
 display_name TEXT, \
 owner {json} NOT NULL, \
 created_at TEXT NOT NULL, \
 updated_at TEXT NOT NULL);\n\
CREATE TABLE {prefix}_groups (\
 id TEXT PRIMARY KEY, \
 org_id TEXT NOT NULL, \
 display_name TEXT, \
 members {json} NOT NULL, \
 created_at TEXT NOT NULL, \
 updated_at TEXT NOT NULL);\n\
CREATE INDEX {prefix}_groups_org_idx \
 ON {prefix}_groups (org_id);\n\
CREATE TABLE {prefix}_roles (\
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
CREATE TABLE {prefix}_fence (\
 id INTEGER PRIMARY KEY, \
 version BIGINT NOT NULL DEFAULT 1, \
 epoch BIGINT NOT NULL DEFAULT 0, \
 updated_at TEXT NOT NULL);";

// Immutable documents are separate from the one-row namespace head. Profile
// activation is consequently a single compare-and-set on the head row.
const AUTHZ_0004: &str = "\
CREATE TABLE {prefix}_authorization_profiles (\
 namespace TEXT NOT NULL, \
 revision TEXT NOT NULL, \
 lifecycle TEXT NOT NULL, \
 document {json} NOT NULL, \
 checksum TEXT NOT NULL, \
 created_at TEXT NOT NULL, \
 PRIMARY KEY (namespace, revision));\n\
CREATE TABLE {prefix}_authorization_profile_heads (\
 namespace TEXT PRIMARY KEY, \
 active_revision TEXT NOT NULL);";

const AUTHZ_0005: &str = "\
INSERT INTO {prefix}_fence (id, version, epoch, updated_at) \
VALUES (1, 1, 0, '1970-01-01T00:00:00Z');";

const AUTHZ_0006: &str = "\
CREATE TABLE {prefix}_workspace_org_edges (\
 workspace_id TEXT PRIMARY KEY, \
 org_id TEXT NOT NULL);\
CREATE INDEX {prefix}_workspace_org_edges_org_idx \
 ON {prefix}_workspace_org_edges (org_id);";

// Invitation is IAM authorization intent, stored beside role bindings. Only a
// SHA-256 claim-token hash is persisted; delivery remains a Cloud adapter.
const AUTHZ_0007: &str = "\
CREATE TABLE {prefix}_invitations (\
 id TEXT PRIMARY KEY, \
 idempotency_key TEXT NOT NULL, \
 org_id TEXT NOT NULL, \
 email TEXT NOT NULL, \
 bindings {json} NOT NULL, \
 invited_by {json} NOT NULL, \
 token_hash TEXT NOT NULL, \
 status TEXT NOT NULL, \
 expires_at TEXT NOT NULL, \
 created_at TEXT NOT NULL, \
 updated_at TEXT NOT NULL, \
 accepted_by_account_id TEXT, \
 UNIQUE (org_id, idempotency_key));\n\
CREATE INDEX {prefix}_invitations_org_idx \
 ON {prefix}_invitations (org_id, created_at);";

// Stream coordinates and ownership are durable so retries after a daemon
// restart cannot restore an older grant. The owner tables also fence a product
// projection from replacing another stream's grant or resource edge.
const AUTHZ_0008: &str = "\
CREATE TABLE {prefix}_resource_projection_streams (\
 product_id TEXT NOT NULL, \
 org_id TEXT NOT NULL, \
 projection_id TEXT NOT NULL, \
 idempotency_key TEXT NOT NULL, \
 epoch BIGINT NOT NULL, \
 payload_digest TEXT NOT NULL, \
 version BIGINT NOT NULL, \
 grant_ids {json} NOT NULL, \
 edge_keys {json} NOT NULL, \
 PRIMARY KEY (product_id, org_id, projection_id));\n\
CREATE TABLE {prefix}_resource_projection_keys (\
 product_id TEXT NOT NULL, \
 org_id TEXT NOT NULL, \
 idempotency_key TEXT NOT NULL, \
 projection_id TEXT NOT NULL, \
 epoch BIGINT NOT NULL, \
 payload_digest TEXT NOT NULL, \
 version BIGINT NOT NULL, \
 PRIMARY KEY (product_id, org_id, idempotency_key));\n\
CREATE TABLE {prefix}_resource_projection_grant_owners (\
 grant_id TEXT PRIMARY KEY, \
 product_id TEXT NOT NULL, \
 org_id TEXT NOT NULL, \
 projection_id TEXT NOT NULL);\n\
CREATE TABLE {prefix}_resource_projection_edge_owners (\
 resource_type TEXT NOT NULL, \
 resource_id TEXT NOT NULL, \
 product_id TEXT NOT NULL, \
 org_id TEXT NOT NULL, \
 projection_id TEXT NOT NULL, \
 PRIMARY KEY (resource_type, resource_id));\n\
CREATE TABLE {prefix}_resource_projection_tombstones (\
 resource_type TEXT NOT NULL, \
 resource_id TEXT NOT NULL, \
 product_id TEXT NOT NULL, \
 org_id TEXT NOT NULL, \
 projection_id TEXT NOT NULL, \
 epoch BIGINT NOT NULL, \
 PRIMARY KEY (resource_type, resource_id));\n\
CREATE TABLE {prefix}_product_resource_types (\
 product_id TEXT NOT NULL, \
 resource_type TEXT NOT NULL, \
 parent_type TEXT, \
 actions {json} NOT NULL, \
 PRIMARY KEY (product_id, resource_type));\n\
CREATE TABLE {prefix}_product_actions (\
 product_id TEXT NOT NULL, \
 action_key TEXT NOT NULL, \
 PRIMARY KEY (product_id, action_key));";

// User-visible placement is independent from both the fixed compatibility
// ScopeRef shapes and product business tables. An empty `parent_id` is the
// portable SQL root sentinel, allowing any number of roots inside one immutable
// Org partition. Product-space
// identity is open and qualified by product; moving a node updates only this
// bundle and its independent revision fence.
const DIRECTORY_0001: &str = "\
CREATE TABLE {prefix}_directory_nodes (\
 id TEXT PRIMARY KEY, \
 org_id TEXT NOT NULL, \
 parent_id TEXT NOT NULL, \
 name TEXT NOT NULL, \
 slug TEXT NOT NULL, \
 description TEXT, \
 archived BIGINT NOT NULL, \
 created_at TEXT NOT NULL, \
 updated_at TEXT NOT NULL, \
 UNIQUE (org_id, parent_id, slug));\n\
CREATE INDEX {prefix}_directory_nodes_parent_idx \
 ON {prefix}_directory_nodes (org_id, parent_id, archived, slug);\n\
CREATE TABLE {prefix}_product_space_bindings (\
 product TEXT NOT NULL, \
 space_id TEXT NOT NULL, \
 org_id TEXT NOT NULL, \
 node_id TEXT NOT NULL, \
 PRIMARY KEY (product, space_id));\n\
CREATE INDEX {prefix}_product_space_bindings_node_idx \
 ON {prefix}_product_space_bindings (org_id, node_id);\n\
CREATE TABLE {prefix}_directory_fence (\
 id INTEGER PRIMARY KEY, \
 revision BIGINT NOT NULL);\n\
INSERT INTO {prefix}_directory_fence (id, revision) VALUES (1, 1);";

// A Directory node represents either one user folder or one product space. A
// second product identity cannot share the same node and silently couple their
// moves, archive state, or presentation metadata. The physical V0001 table name
// remains append-only migration history; the published language calls rows
// ProductSpacePlacement.
const DIRECTORY_0002: &str = "\
CREATE UNIQUE INDEX {prefix}_product_space_bindings_node_key \
 ON {prefix}_product_space_bindings (node_id);";

// reviewed: migration-allow-destructive — the third Directory step atomically rebuilds two
// authority tables because SQLite cannot alter their primary keys in place.
// The Directory aggregate is one organization partition, not one global tree.
// Rebuild the two small authority tables portably because SQLite cannot alter a
// primary key in place. Existing organizations with Directory nodes inherit the
// previous global revision; an empty organization initializes revision 1 on its
// first Directory command.
const DIRECTORY_0003: &str = "\
CREATE TABLE {prefix}_product_space_bindings_v2 (\
 product TEXT NOT NULL, \
 space_id TEXT NOT NULL, \
 org_id TEXT NOT NULL, \
 node_id TEXT NOT NULL, \
 PRIMARY KEY (org_id, product, space_id));\n\
INSERT INTO {prefix}_product_space_bindings_v2 (product, space_id, org_id, node_id) \
 SELECT product, space_id, org_id, node_id FROM {prefix}_product_space_bindings;\n\
DROP TABLE {prefix}_product_space_bindings;\n\
ALTER TABLE {prefix}_product_space_bindings_v2 RENAME TO {prefix}_product_space_bindings;\n\
CREATE INDEX {prefix}_product_space_bindings_node_idx \
 ON {prefix}_product_space_bindings (org_id, node_id);\n\
CREATE UNIQUE INDEX {prefix}_product_space_bindings_node_key \
 ON {prefix}_product_space_bindings (node_id);\n\
CREATE TABLE {prefix}_directory_fence_v2 (\
 org_id TEXT PRIMARY KEY, \
 revision BIGINT NOT NULL);\n\
INSERT INTO {prefix}_directory_fence_v2 (org_id, revision) \
 SELECT DISTINCT node.org_id, fence.revision \
 FROM {prefix}_directory_nodes node CROSS JOIN {prefix}_directory_fence fence;\n\
DROP TABLE {prefix}_directory_fence;\n\
ALTER TABLE {prefix}_directory_fence_v2 RENAME TO {prefix}_directory_fence;";

// Existing placements were active by definition. Product retirement is stored
// on the binding rather than overloading the user-managed node archive flag.
const DIRECTORY_0004: &str = "\
ALTER TABLE {prefix}_product_space_bindings \
 ADD COLUMN status TEXT NOT NULL DEFAULT 'active' \
 CHECK (status IN ('active', 'retired'));";

// --- iam.entitlement DDL ---------------------------------------------------
//
// Plans and the per-principal subscription assignment. A subscription names a
// plan by id resolved in the domain — no FK to the plans table, keeping the
// bundle aggregate-safe with the rest.
const ENTITLEMENT_0001: &str = "\
CREATE TABLE {prefix}_plans (\
 id TEXT PRIMARY KEY, \
 tier TEXT NOT NULL, \
 features {json} NOT NULL, \
 limits {json} NOT NULL, \
 rates {json} NOT NULL);\n\
CREATE TABLE {prefix}_subscriptions (\
 principal {json} NOT NULL PRIMARY KEY, \
 plan_id TEXT NOT NULL);";

// --- iam.audit DDL ---------------------------------------------------------
//
// The append-only audit event log. `seq` is a backend-assigned auto-incrementing
// surrogate so events read back in exact append order on either dialect; the
// actor is the optional JSON principal form, absent when no principal is
// attributable. Audit references nothing by FK — it is a flat, write-once log.
const AUDIT_0001: &str = "\
CREATE TABLE {prefix}_audit_events (\
 seq {pk_autoinc}, \
 at TEXT NOT NULL, \
 actor {json}, \
 action TEXT NOT NULL, \
 detail TEXT NOT NULL);";

#[cfg(test)]
mod tests {
    use super::*;
    use crate::store::{SqlConn, SqliteBackend, sqlite_in_memory_store};

    #[test]
    fn projection_migration_applies_and_fences_cross_stream_ownership() {
        let store = sqlite_in_memory_store("iam").expect("migrate all IAM bundles");
        let backend = store.backend();
        backend
            .execute(
                "INSERT INTO iam_resource_projection_grant_owners \
             (grant_id, product_id, org_id, projection_id) VALUES (?, ?, ?, ?)",
                &[
                    Some("grant-1".into()),
                    Some("tutor".into()),
                    Some("org-a".into()),
                    Some("campus:1".into()),
                ],
            )
            .expect("first owner");
        assert!(
            backend
                .execute(
                    "INSERT INTO iam_resource_projection_grant_owners \
             (grant_id, product_id, org_id, projection_id) VALUES (?, ?, ?, ?)",
                    &[
                        Some("grant-1".into()),
                        Some("tutor".into()),
                        Some("org-b".into()),
                        Some("staff:2".into())
                    ],
                )
                .is_err()
        );
        backend
            .execute(
                "INSERT INTO iam_resource_projection_keys \
             (product_id, org_id, idempotency_key, projection_id, epoch, payload_digest, version) \
             VALUES (?, ?, ?, ?, ?, ?, ?)",
                &[
                    Some("tutor".into()),
                    Some("org-a".into()),
                    Some("event-1".into()),
                    Some("campus:1".into()),
                    Some("1".into()),
                    Some("digest-a".into()),
                    Some("2".into()),
                ],
            )
            .expect("first idempotency key");
        assert!(
            backend
                .execute(
                    "INSERT INTO iam_resource_projection_keys \
             (product_id, org_id, idempotency_key, projection_id, epoch, payload_digest, version) \
             VALUES (?, ?, ?, ?, ?, ?, ?)",
                    &[
                        Some("tutor".into()),
                        Some("org-a".into()),
                        Some("event-1".into()),
                        Some("staff:2".into()),
                        Some("2".into()),
                        Some("digest-b".into()),
                        Some("3".into())
                    ],
                )
                .is_err()
        );
        backend
            .execute(
                "INSERT INTO iam_resource_projection_tombstones \
             (resource_type, resource_id, product_id, org_id, projection_id, epoch) \
             VALUES (?, ?, ?, ?, ?, ?)",
                &[
                    Some("tutor.campus".into()),
                    Some("1".into()),
                    Some("tutor".into()),
                    Some("org-a".into()),
                    Some("campus:1".into()),
                    Some("2".into()),
                ],
            )
            .expect("retirement survives in migrated schema");
    }

    #[test]
    fn directory_v3_preserves_rows_and_scopes_identity_and_revision_by_org() {
        // Cause/effect graph: C1=the first two versions contain one placement and
        // one global revision, C2=the third rebuilds both authority tables. E1=the existing row
        // remains queryable, E2=its Org receives the old revision, E3=another
        // Org may reuse the same product-space identity. Decision rule
        // C1+C2 -> E1+E2+E3 guards the only supported upgrade path.
        let backend = SqliteBackend::open_in_memory().expect("open sqlite");
        for statement in [
            "CREATE TABLE iam_directory_nodes (id TEXT PRIMARY KEY, org_id TEXT NOT NULL, parent_id TEXT NOT NULL, name TEXT NOT NULL, slug TEXT NOT NULL, description TEXT, archived BIGINT NOT NULL, created_at TEXT NOT NULL, updated_at TEXT NOT NULL, UNIQUE (org_id, parent_id, slug))",
            "CREATE TABLE iam_product_space_bindings (product TEXT NOT NULL, space_id TEXT NOT NULL, org_id TEXT NOT NULL, node_id TEXT NOT NULL, PRIMARY KEY (product, space_id))",
            "CREATE UNIQUE INDEX iam_product_space_bindings_node_key ON iam_product_space_bindings (node_id)",
            "CREATE TABLE iam_directory_fence (id INTEGER PRIMARY KEY, revision BIGINT NOT NULL)",
            "INSERT INTO iam_directory_nodes (id, org_id, parent_id, name, slug, description, archived, created_at, updated_at) VALUES ('node-a', 'org-a', '', 'A', 'a', NULL, 0, 't', 't')",
            "INSERT INTO iam_product_space_bindings (product, space_id, org_id, node_id) VALUES ('agents', 'workspace/shared', 'org-a', 'node-a')",
            "INSERT INTO iam_directory_fence (id, revision) VALUES (1, 7)",
        ] {
            backend
                .execute(statement, &[])
                .expect("seed version-two schema");
        }

        for statement in DIRECTORY_0003.replace("{prefix}", "iam").split(';') {
            let statement = statement.trim();
            if !statement.is_empty() {
                backend
                    .execute(statement, &[])
                    .expect("apply third-version statement");
            }
        }

        let placement = backend
            .query(
                "SELECT org_id, node_id FROM iam_product_space_bindings WHERE product = ? AND space_id = ?",
                &[Some("agents".into()), Some("workspace/shared".into())],
            )
            .expect("read migrated placement");
        assert_eq!(
            placement,
            vec![vec![Some("org-a".into()), Some("node-a".into())]],
            "E1"
        );
        assert_eq!(
            backend
                .query(
                    "SELECT CAST(revision AS TEXT) FROM iam_directory_fence WHERE org_id = ?",
                    &[Some("org-a".into())],
                )
                .expect("read migrated revision"),
            vec![vec![Some("7".into())]],
            "E2"
        );

        backend
            .execute(
                "INSERT INTO iam_directory_nodes (id, org_id, parent_id, name, slug, description, archived, created_at, updated_at) VALUES ('node-b', 'org-b', '', 'B', 'b', NULL, 0, 't', 't')",
                &[],
            )
            .expect("seed second Org node");
        backend
            .execute(
                "INSERT INTO iam_product_space_bindings (product, space_id, org_id, node_id) VALUES (?, ?, ?, ?)",
                &[
                    Some("agents".into()),
                    Some("workspace/shared".into()),
                    Some("org-b".into()),
                    Some("node-b".into()),
                ],
            )
            .expect("same product space is valid in another Org");
        assert_eq!(
            backend
                .query(
                    "SELECT CAST(COUNT(*) AS TEXT) FROM iam_product_space_bindings",
                    &[],
                )
                .expect("count placements"),
            vec![vec![Some("2".into())]],
            "E3"
        );
    }

    #[test]
    fn directory_v4_preserves_existing_placements_as_active() {
        // Cause/effect decision table: R1 a version-three placement plus the
        // version-four migration ->
        // the row remains active; R2 active -> retired update round-trips; R3 an
        // unknown lifecycle value -> database constraint refusal. This guards
        // the only supported lifecycle upgrade without rebuilding node state.
        let backend = SqliteBackend::open_in_memory().expect("open sqlite");
        backend
            .execute(
                "CREATE TABLE iam_product_space_bindings (product TEXT NOT NULL, space_id TEXT NOT NULL, org_id TEXT NOT NULL, node_id TEXT NOT NULL, PRIMARY KEY (org_id, product, space_id))",
                &[],
            )
            .expect("seed version-three schema");
        backend
            .execute(
                "INSERT INTO iam_product_space_bindings (product, space_id, org_id, node_id) VALUES ('agents', 'workspace/a', 'org-a', 'node-a')",
                &[],
            )
            .expect("seed version-three placement");
        backend
            .execute(&DIRECTORY_0004.replace("{prefix}", "iam"), &[])
            .expect("apply version four");
        assert_eq!(
            backend
                .query(
                    "SELECT status FROM iam_product_space_bindings WHERE org_id = ? AND product = ? AND space_id = ?",
                    &[
                        Some("org-a".into()),
                        Some("agents".into()),
                        Some("workspace/a".into()),
                    ],
                )
                .expect("read migrated lifecycle"),
            vec![vec![Some("active".into())]],
            "R1"
        );
        backend
            .execute(
                "UPDATE iam_product_space_bindings SET status = 'retired' WHERE org_id = 'org-a'",
                &[],
            )
            .expect("retire placement");
        assert!(
            backend
                .execute(
                    "UPDATE iam_product_space_bindings SET status = 'unknown' WHERE org_id = 'org-a'",
                    &[],
                )
                .is_err(),
            "R3"
        );
    }

    #[test]
    fn bundles_partition_by_the_subdomain_scopes() {
        let all = bundles();
        let scopes: Vec<&str> = all.iter().map(|b| b.bundle_id()).collect();
        assert_eq!(
            scopes,
            [
                "iam.identity",
                "iam.authz",
                "iam.directory",
                "iam.entitlement",
                "iam.audit"
            ]
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
    fn bundle_scope_id_is_the_stable_dotted_handle() {
        assert_eq!(BundleScope::Identity.id(), "iam.identity");
        assert_eq!(BundleScope::Authz.id(), "iam.authz");
        assert_eq!(BundleScope::Directory.id(), "iam.directory");
        assert_eq!(BundleScope::Entitlement.id(), "iam.entitlement");
        assert_eq!(BundleScope::Audit.id(), "iam.audit");
    }

    #[test]
    fn bundle_scope_all_lists_every_scope_in_apply_order() {
        // Apply order is significant: a bundle must never depend on a table
        // owned by a later bundle.
        let all = BundleScope::all();
        assert_eq!(
            all,
            [
                BundleScope::Identity,
                BundleScope::Authz,
                BundleScope::Directory,
                BundleScope::Entitlement,
                BundleScope::Audit,
            ]
        );
        let ids: Vec<&str> = all.iter().map(|s| s.id()).collect();
        assert_eq!(
            ids,
            [
                "iam.identity",
                "iam.authz",
                "iam.directory",
                "iam.entitlement",
                "iam.audit"
            ]
        );
    }

    #[test]
    fn every_bundle_has_a_unique_dotted_id_and_at_least_one_migration() {
        // Dependency-revision compatibility design:
        // C1 = Foundation still accepts every canonical IAM bundle; C2 = bundle
        // ids remain unique and non-empty. E1 = the upgraded shared planner can
        // consume the complete IAM schema without a product-local compatibility
        // path. This test covers R1(C1 && C2 -> E1); planner rejection or duplicate
        // identity fails the single rule directly.
        // The lint already enforces this; restated here so the invariant is
        // explicit at the API surface too.
        let all = bundles();
        let mut seen = std::collections::HashSet::new();
        for bundle in &all {
            assert!(
                seen.insert(bundle.bundle_id().to_owned()),
                "duplicate bundle id {}",
                bundle.bundle_id()
            );
            assert!(
                !bundle.migrations().is_empty(),
                "bundle {} has no migrations",
                bundle.bundle_id()
            );
        }
    }
}
