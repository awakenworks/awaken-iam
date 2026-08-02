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
    fn bundle_scope_id_is_the_stable_dotted_handle() {
        assert_eq!(BundleScope::Identity.id(), "iam.identity");
        assert_eq!(BundleScope::Authz.id(), "iam.authz");
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
                BundleScope::Entitlement,
                BundleScope::Audit,
            ]
        );
        let ids: Vec<&str> = all.iter().map(|s| s.id()).collect();
        assert_eq!(
            ids,
            ["iam.identity", "iam.authz", "iam.entitlement", "iam.audit"]
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
