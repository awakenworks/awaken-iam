//! Reconcile the two exact IAM authz-v8 histories inside the migration transaction.
//!
//! Foundation still verifies the receipt and owns planning. This IAM-owned bridge
//! supplies only the DDL/data operations for its known consumed schema. It never
//! edits a receipt or permits arbitrary drift, and drivers hold their ordinary
//! single-applier transaction across preparation, migration 9 and restoration.

use std::collections::BTreeMap;

use awaken_iam_core::{RepositoryError, RepositoryResult};
use awaken_scoped_migration::{Dialect, MigrationBundle, render};

pub(super) const CONSUMED_AUTHZ_V8_CHECKSUM: &str =
    "d3bc84e133894919b0e6e7a1d5bdfd81a85af2a75215fe1bd00f2a6d2d502d75";

pub(super) struct AtomicV8Bridge {
    pub before: Vec<String>,
    pub after: Vec<String>,
}

pub(super) fn atomic_v8_bridge(
    bundle: &MigrationBundle,
    recorded: &BTreeMap<i64, String>,
    prefix: &str,
    dialect: Dialect,
) -> RepositoryResult<Option<AtomicV8Bridge>> {
    if bundle.bundle_id() != "iam.authz"
        || recorded.get(&8).map(String::as_str) != Some(CONSUMED_AUTHZ_V8_CHECKSUM)
        || recorded.contains_key(&9)
    {
        return Ok(None);
    }
    let Some(convergence) = bundle
        .migrations()
        .iter()
        .find(|migration| migration.version() == 9)
    else {
        // A historical fixture/installer requesting only v8 must remain v8.
        return Ok(None);
    };
    if convergence.checksum_for(dialect)
        != "78e57875d160a22fba013f2b627242f8013ca797ef40573512a79dd2a8922cf0"
    {
        return Err(RepositoryError::Backend(
            "authz migration 9 does not match the validated v8 convergence bridge".into(),
        ));
    }
    let projection = bundle
        .migrations()
        .iter()
        .find(|migration| migration.version() == 8)
        .ok_or_else(|| RepositoryError::Backend("authz v8 migration is missing".into()))?;
    let tables = [
        (
            "resource_provisions",
            "idempotency_key, epoch, fingerprint, version, applied_at",
        ),
        ("resource_epochs", "resource_type, resource_id, epoch"),
    ];
    let mut before = Vec::new();
    let mut after = Vec::new();
    for (table, columns) in tables {
        let old = format!("{prefix}_{table}");
        let saved = format!("{prefix}_atomic_v8_{table}");
        before.push(format!("ALTER TABLE {old} RENAME TO {saved}"));
        after.push(format!(
            "INSERT INTO {old} ({columns}) SELECT {columns} FROM {saved}"
        ));
        after.push(format!("DROP TABLE {saved}"));
    }
    // Public v8's canonical body is pinned by its published-legacy checksum.
    // Its tables are absent on the consumed track; no conditional DDL is used.
    before.push(render(projection.sql_for(dialect), dialect, prefix));
    Ok(Some(AtomicV8Bridge { before, after }))
}
