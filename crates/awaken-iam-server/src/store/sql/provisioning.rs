//! Atomic, backend-neutral control-plane provisioning commands.

use awaken_iam_core::{AuditEvent, Organization, RepositoryResult, RoleBinding};

use super::{SqlConn, SqlStore, SqlWrite, json_encode, p};
use crate::admin_api::OrganizationProvisioningStore;
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
