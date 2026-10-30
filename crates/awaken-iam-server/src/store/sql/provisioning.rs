//! Atomic, backend-neutral control-plane provisioning commands.

use awaken_iam_contract::{
    GrantEffect, ResourceProvision, ResourceProvisionDisposition, ResourceProvisionReceipt,
};
use awaken_iam_core::{AuditEvent, Organization, RepositoryError, RepositoryResult, RoleBinding};

use super::{SqlConn, SqlStore, SqlTransaction, SqlWrite, json_encode, p};
use crate::admin_api::{OrganizationProvisioningStore, ResourceProvisioningStore};

impl<B: SqlConn> OrganizationProvisioningStore for SqlStore<B> {
    fn provision_organization(
        &self,
        organization: Organization,
        owner_binding: RoleBinding,
        audit: AuditEvent,
    ) -> RepositoryResult<u64> {
        self.with_policy_transaction(|transaction, version| {
            self.ensure_scope_admission(
                transaction,
                &[
                    awaken_iam_contract::ScopeRef::Org {
                        org_id: organization.id.clone(),
                    },
                    owner_binding.scope.clone(),
                ],
                &[],
            )?;
            let next_version = version
                .checked_add(1)
                .filter(|value| *value <= i64::MAX as u64)
                .ok_or_else(|| RepositoryError::Backend("IAM policy version exhausted".into()))?;

            let owner = json_encode(&organization.owner, "organization owner")?;
            let principal = json_encode(&owner_binding.principal, "binding principal")?;
            let scope = json_encode(&owner_binding.scope, "binding scope")?;
            let audit_actor = audit
                .actor
                .as_ref()
                .map(|actor| json_encode(actor, "audit actor"))
                .transpose()?;
            let writes = [
                SqlWrite {
                    sql: format!(
                        "INSERT INTO {} (id, display_name, owner, created_at, updated_at) \
                     VALUES (?, ?, ?j, ?, ?)",
                        self.table("orgs")
                    ),
                    params: vec![
                        p(organization.id.0),
                        organization.display_name,
                        p(owner),
                        p(organization.created_at.0),
                        p(organization.updated_at.0),
                    ],
                },
                SqlWrite {
                    sql: format!(
                        "INSERT INTO {} (principal, role, scope) \
                     SELECT ?j, id, ?j FROM {} WHERE id = ?",
                        self.table("role_bindings"),
                        self.table("roles")
                    ),
                    params: vec![p(principal), p(scope), p(owner_binding.role.0)],
                },
                SqlWrite {
                    sql: format!(
                        "INSERT INTO {} (at, actor, action, detail) VALUES (?, ?j, ?, ?)",
                        self.table("audit_events")
                    ),
                    params: vec![
                        p(audit.at.0.clone()),
                        audit_actor,
                        p(audit.action),
                        p(audit.detail),
                    ],
                },
                SqlWrite {
                    sql: format!(
                        "UPDATE {} SET version = version + 1, updated_at = ? WHERE id = 1",
                        self.table("fence")
                    ),
                    params: vec![p(audit.at.0)],
                },
            ];
            transaction.execute_checked(&writes, &[(0, 1), (1, 1), (2, 1), (3, 1)])?;
            Ok(next_version)
        })
    }
}

impl<B: SqlConn> ResourceProvisioningStore for SqlStore<B> {
    fn resource_provision_replay(
        &self,
        provision: &ResourceProvision,
        fingerprint: &str,
    ) -> RepositoryResult<Option<ResourceProvisionReceipt>> {
        self.with_policy_transaction(|transaction, _| {
            self.provision_admission(transaction, provision)?;
            self.resource_provision_receipt(transaction, provision, fingerprint)
        })
    }

    fn provision_resource(
        &self,
        provision: &ResourceProvision,
        fingerprint: &str,
        audit: AuditEvent,
    ) -> RepositoryResult<ResourceProvisionReceipt> {
        // SqlParam binds text. Both native stores persist BIGINT epochs;
        // refuse an unrepresentable input before SQLite can clamp a cast or
        // any write/replay receipt can publish a different coordinate.
        if provision.epoch > i64::MAX as u64 {
            return Err(RepositoryError::Backend(
                "resource epoch exceeds the native storage integer range".into(),
            ));
        }
        let result = self.with_policy_transaction(|transaction,version| {
            self.provision_admission(transaction,provision)?;

        if let Some(receipt) = self.resource_provision_receipt(transaction,provision, fingerprint)? {
            return Ok(receipt);
        }
            // Historical exact receipt is already handled above. Only NEW
            // effects must also respect the canonical projection ownership and
            // retirement owner; legacy writes cannot open a parallel lifecycle.
            self.require_raw_provision_effect(transaction,provision)?;
            let next_version = version.checked_add(1).filter(|value| *value <= i64::MAX as u64).ok_or_else(|| RepositoryError::Backend("IAM policy version exhausted".into()))?;
        let mut writes = Vec::new();
        let mut required = Vec::new();
        for edge in &provision.scope_edges {
            let head_index = writes.len();
            writes.push(self.resource_epoch_write(
                &edge.resource_type.0,
                &edge.resource_id.0,
                provision.epoch,
            ));
            required.push((head_index, 1));
            let parent = json_encode(&edge.parent, "resource parent")?;
            writes.push(SqlWrite {
                sql: format!(
                    "INSERT INTO {} (resource_type, resource_id, parent) VALUES (?, ?, ?j) \
                     ON CONFLICT (resource_type, resource_id) DO UPDATE SET parent = excluded.parent",
                    self.table("resource_edges")
                ),
                params: vec![
                    p(edge.resource_type.0.clone()),
                    p(edge.resource_id.0.clone()),
                    p(parent),
                ],
            });
        }
        for resource in &provision.retirements {
            let head_index = writes.len();
            writes.push(self.resource_epoch_write(
                &resource.resource_type.0,
                &resource.resource_id.0,
                provision.epoch,
            ));
            required.push((head_index, 1));
            writes.push(SqlWrite {
                sql: format!(
                    "DELETE FROM {} WHERE resource_type = ? AND resource_id = ?",
                    self.table("resource_edges")
                ),
                params: vec![
                    p(resource.resource_type.0.clone()),
                    p(resource.resource_id.0.clone()),
                ],
            });
            for grant_id in &resource.grant_ids {
                writes.push(SqlWrite {
                    sql: format!("DELETE FROM {} WHERE id = ?", self.table("grants")),
                    params: vec![p(grant_id.clone())],
                });
            }
        }
        for grant in &provision.grants {
            writes.push(SqlWrite {
                sql: format!(
                    "INSERT INTO {} (id, subject, action_pattern, scope, effect) \
                     VALUES (?, ?j, ?, ?j, ?) ON CONFLICT (id) DO UPDATE SET \
                     subject = excluded.subject, action_pattern = excluded.action_pattern, \
                     scope = excluded.scope, effect = excluded.effect",
                    self.table("grants")
                ),
                params: vec![
                    p(grant.id.clone()),
                    p(json_encode(&grant.subject, "grant subject")?),
                    p(grant.action_pattern.clone()),
                    p(json_encode(&grant.scope, "grant scope")?),
                    p(match grant.effect {
                        GrantEffect::Allow => "allow",
                        GrantEffect::RequireApproval => "require_approval",
                        GrantEffect::Deny => "deny",
                    }),
                ],
            });
        }
        let audit_actor = audit
            .actor
            .as_ref()
            .map(|actor| json_encode(actor, "audit actor"))
            .transpose()?;
        writes.push(SqlWrite {
            sql: format!(
                "INSERT INTO {} (at, actor, action, detail) VALUES (?, ?j, ?, ?)",
                self.table("audit_events")
            ),
            params: vec![
                p(audit.at.0.clone()),
                audit_actor,
                p(audit.action),
                p(audit.detail),
            ],
        });
        let fence_index = writes.len();
        writes.push(SqlWrite {
            sql: format!(
                "UPDATE {} SET version = version + 1, updated_at = ? WHERE id = 1",
                self.table("fence")
            ),
            params: vec![p(audit.at.0.clone())],
        });
        required.push((fence_index, 1));
        let receipt_index = writes.len();
        writes.push(SqlWrite {
            sql: format!(
                "INSERT INTO {} (idempotency_key, epoch, fingerprint, version, applied_at) \
                 VALUES (?, CAST(CAST(? AS TEXT) AS BIGINT), ?, 0, ?)",
                self.table("resource_provisions")
            ),
            params: vec![
                p(provision.idempotency_key.clone()),
                p(provision.epoch.to_string()),
                p(fingerprint),
                p(audit.at.0),
            ],
        });
        required.push((receipt_index, 1));
        let version_index = writes.len();
        writes.push(SqlWrite {
            sql: format!(
                "UPDATE {} SET version = (SELECT version FROM {} WHERE id = 1) \
                 WHERE idempotency_key = ?",
                self.table("resource_provisions"),
                self.table("fence")
            ),
            params: vec![p(provision.idempotency_key.clone())],
        });
        required.push((version_index, 1));

        transaction.execute_checked(&writes,&required)?;
        Ok(ResourceProvisionReceipt {
            idempotency_key: provision.idempotency_key.clone(), epoch: provision.epoch,
            version: next_version, disposition: ResourceProvisionDisposition::Applied,
        })

        });
        match result {
            Err(RepositoryError::Conflict(_)) => self.with_policy_transaction(|transaction, _| {
                self.provision_admission(transaction, provision)?;
                self.resource_provision_receipt(transaction, provision, fingerprint)?
                    .ok_or_else(|| RepositoryError::Conflict("stale resource epoch".into()))
            }),
            other => other,
        }
    }
}

impl<B: SqlConn> SqlStore<B> {
    // Both insertion and retirement use the SAME monotone epoch write. Qualify
    // the target column: PostgreSQL also exposes excluded.epoch in this scope.
    fn resource_epoch_write(&self, resource_type: &str, resource_id: &str, epoch: u64) -> SqlWrite {
        SqlWrite {
            sql: format!(
                "INSERT INTO {epochs} (resource_type, resource_id, epoch) VALUES (?, ?, CAST(CAST(? AS TEXT) AS BIGINT)) \
                 ON CONFLICT (resource_type, resource_id) DO UPDATE SET epoch = excluded.epoch \
                 WHERE {epochs}.epoch < excluded.epoch",
                epochs = self.table("resource_epochs"),
            ),
            params: vec![p(resource_type), p(resource_id), p(epoch.to_string())],
        }
    }

    fn resource_provision_receipt(
        &self,
        transaction: &mut dyn SqlTransaction,
        provision: &ResourceProvision,
        fingerprint: &str,
    ) -> RepositoryResult<Option<ResourceProvisionReceipt>> {
        let sql = format!(
            "SELECT CAST(epoch AS TEXT), fingerprint, CAST(version AS TEXT) FROM {} \
             WHERE idempotency_key = ?",
            self.table("resource_provisions")
        );
        let rows = transaction.query(&sql, &[p(provision.idempotency_key.clone())])?;
        let Some(row) = rows.first() else {
            return Ok(None);
        };
        let epoch = row[0]
            .as_deref()
            .ok_or_else(|| RepositoryError::Backend("resource provision epoch is null".into()))?
            .parse::<u64>()
            .map_err(|error| RepositoryError::Backend(error.to_string()))?;
        let stored_fingerprint = row[1].as_deref().unwrap_or_default();
        if epoch != provision.epoch || stored_fingerprint != fingerprint {
            return Err(RepositoryError::Conflict(
                "idempotency key belongs to another resource provision".into(),
            ));
        }
        let version = row[2]
            .as_deref()
            .ok_or_else(|| RepositoryError::Backend("resource provision version is null".into()))?
            .parse::<u64>()
            .map_err(|error| RepositoryError::Backend(error.to_string()))?;
        Ok(Some(ResourceProvisionReceipt {
            idempotency_key: provision.idempotency_key.clone(),
            epoch,
            version,
            disposition: ResourceProvisionDisposition::Replayed,
        }))
    }
}
