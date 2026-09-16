//! Atomic, backend-neutral control-plane provisioning commands.

use awaken_iam_contract::{
    GrantEffect, ResourceProvision, ResourceProvisionDisposition, ResourceProvisionReceipt,
};
use awaken_iam_core::{AuditEvent, Organization, RepositoryError, RepositoryResult, RoleBinding};

use super::{SqlConn, SqlStore, SqlWrite, json_encode, p};
use crate::admin_api::{OrganizationProvisioningStore, ResourceProvisioningStore};
use crate::store::FenceStore;

impl<B: SqlConn> OrganizationProvisioningStore for SqlStore<B> {
    fn provision_organization(
        &self,
        organization: Organization,
        owner_binding: RoleBinding,
        audit: AuditEvent,
    ) -> RepositoryResult<u64> {
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
        self.backend
            .execute_transaction_checked(&writes, &[(0, 1), (1, 1), (2, 1), (3, 1)])?;
        self.fence().map(|fence| fence.version)
    }
}

impl<B: SqlConn> ResourceProvisioningStore for SqlStore<B> {
    fn provision_resource(
        &self,
        provision: &ResourceProvision,
        fingerprint: &str,
        audit: AuditEvent,
    ) -> RepositoryResult<ResourceProvisionReceipt> {
        if let Some(receipt) = self.resource_provision_receipt(provision, fingerprint)? {
            return Ok(receipt);
        }
        let mut writes = Vec::new();
        let mut required = Vec::new();
        for edge in &provision.scope_edges {
            let head_index = writes.len();
            writes.push(SqlWrite {
                sql: format!(
                    "INSERT INTO {} (resource_type, resource_id, epoch) VALUES (?, ?, ?) \
                     ON CONFLICT (resource_type, resource_id) DO UPDATE SET epoch = excluded.epoch \
                     WHERE epoch < excluded.epoch",
                    self.table("resource_epochs")
                ),
                params: vec![
                    p(edge.resource_type.0.clone()),
                    p(edge.resource_id.0.clone()),
                    p(provision.epoch.to_string()),
                ],
            });
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
                 VALUES (?, ?, ?, 0, ?)",
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

        match self.backend.execute_transaction_checked(&writes, &required) {
            Ok(_) => {
                let version = self.fence()?.version;
                Ok(ResourceProvisionReceipt {
                    idempotency_key: provision.idempotency_key.clone(),
                    epoch: provision.epoch,
                    version,
                    disposition: ResourceProvisionDisposition::Applied,
                })
            }
            Err(RepositoryError::Conflict(_)) => self
                .resource_provision_receipt(provision, fingerprint)?
                .ok_or_else(|| RepositoryError::Conflict("stale resource epoch".into())),
            Err(error) => Err(error),
        }
    }
}

impl<B: SqlConn> SqlStore<B> {
    fn resource_provision_receipt(
        &self,
        provision: &ResourceProvision,
        fingerprint: &str,
    ) -> RepositoryResult<Option<ResourceProvisionReceipt>> {
        let sql = format!(
            "SELECT CAST(epoch AS TEXT), fingerprint, CAST(version AS TEXT) FROM {} \
             WHERE idempotency_key = ?",
            self.table("resource_provisions")
        );
        let rows = self
            .backend
            .query(&sql, &[p(provision.idempotency_key.clone())])?;
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
