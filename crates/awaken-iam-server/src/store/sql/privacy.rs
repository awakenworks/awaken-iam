//! Organization privacy lifecycle over the shared SQL adapter.

use std::collections::BTreeSet;

use awaken_iam_contract::{OrgId, ScopeRef};
use awaken_iam_core::{
    GrantRepository, GrantSubject, GroupRepository, OrgPrivacyRepository, OrganizationPrivacyScope,
    RepositoryResult, ResourceModelRepository, RoleBindingRepository,
};

use super::{SqlConn, SqlStore, SqlWrite, json_encode, p, req};

impl<B: SqlConn> OrgPrivacyRepository for SqlStore<B> {
    fn erase_org_privacy(&self, id: &OrgId) -> RepositoryResult<bool> {
        let workspace_edges = ResourceModelRepository::list_workspace_orgs(self)?;
        let resource_edges = ResourceModelRepository::list_edges(self)?;
        let privacy = OrganizationPrivacyScope::resolve(id, &workspace_edges, &resource_edges);
        let groups = GroupRepository::list(self)?;
        let group_ids = groups
            .iter()
            .filter(|group| &group.org == id)
            .map(|group| group.id.0.clone())
            .collect::<BTreeSet<_>>();
        let grants = GrantRepository::list(self)?;
        let bindings = RoleBindingRepository::list(self)?;

        let token_rows = self.backend.query(
            &format!(
                "SELECT id, workspace FROM {} ORDER BY id",
                self.table("api_tokens")
            ),
            &[],
        )?;
        let mut writes = vec![
            SqlWrite {
                // Directory creation/move/archive uses the same row as its
                // command mutex. Privacy deletion must serialize with those
                // commands or a node could outlive its tenant partition.
                sql: format!(
                    "UPDATE {} SET revision = revision WHERE org_id = ?",
                    self.table("directory_fence")
                ),
                params: vec![p(id.0.clone())],
            },
            SqlWrite {
                // Advance the independent Directory fence only when this Org
                // actually owns placement state; exact privacy retries remain
                // revision-idempotent.
                sql: format!(
                    "UPDATE {} SET revision = revision + 1 \
                     WHERE org_id = ? AND EXISTS (SELECT 1 FROM {} WHERE org_id = ?)",
                    self.table("directory_fence"),
                    self.table("directory_nodes")
                ),
                params: vec![p(id.0.clone()), p(id.0.clone())],
            },
        ];
        for row in token_rows {
            let token_id = req(&row, 0, "api token id")?;
            let workspace_id = req(&row, 1, "api token workspace")?;
            if privacy.contains_workspace(&workspace_id) {
                writes.push(SqlWrite {
                    sql: format!("DELETE FROM {} WHERE id = ?", self.table("api_tokens")),
                    params: vec![p(token_id)],
                });
            }
        }
        for grant in grants {
            let group_owned = matches!(
                &grant.subject,
                GrantSubject::Group(group) if group_ids.contains(&group.0)
            );
            if privacy.contains(&grant.scope) || group_owned {
                writes.push(SqlWrite {
                    sql: format!("DELETE FROM {} WHERE id = ?", self.table("grants")),
                    params: vec![p(grant.id.0)],
                });
            }
        }
        for binding in bindings {
            if privacy.contains(&binding.scope) {
                writes.push(SqlWrite {
                    sql: format!(
                        "DELETE FROM {} WHERE principal = ?j AND role = ? AND scope = ?j",
                        self.table("role_bindings")
                    ),
                    params: vec![
                        p(json_encode(&binding.principal, "principal")?),
                        p(binding.role.0),
                        p(json_encode(&binding.scope, "binding scope")?),
                    ],
                });
            }
        }
        for edge in resource_edges {
            let child = ScopeRef::Resource {
                resource_type: edge.resource_type.clone(),
                resource_id: edge.resource_id.clone(),
            };
            if privacy.contains(&edge.parent) || privacy.contains(&child) {
                writes.push(SqlWrite {
                    sql: format!(
                        "DELETE FROM {} WHERE resource_type = ? AND resource_id = ?",
                        self.table("resource_edges")
                    ),
                    params: vec![p(edge.resource_type.0), p(edge.resource_id.0)],
                });
            }
        }
        for (table, column) in [
            ("product_space_bindings", "org_id"),
            ("directory_nodes", "org_id"),
            ("directory_fence", "org_id"),
            ("invitations", "org_id"),
            ("groups", "org_id"),
            ("workspace_org_edges", "org_id"),
            ("orgs", "id"),
        ] {
            writes.push(SqlWrite {
                sql: format!("DELETE FROM {} WHERE {column} = ?", self.table(table)),
                params: vec![p(id.0.clone())],
            });
        }

        Ok(self
            .backend
            .execute_transaction(&writes)?
            .into_iter()
            .skip(2)
            .any(|affected| affected != 0))
    }
}
