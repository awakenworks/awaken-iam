//! Organization privacy lifecycle over the shared SQL adapter.

use std::collections::BTreeSet;

use awaken_iam_contract::{OrgId, ScopeRef};
use awaken_iam_core::{
    GrantRepo, GrantSubject, GroupRepo, OrgPrivacyRepo, OrganizationPrivacyScope, RepoResult,
    ResourceModelRepo, RoleBindingRepo,
};

use super::{SqlConn, SqlStore, SqlWrite, json_encode, p, req};

impl<B: SqlConn> OrgPrivacyRepo for SqlStore<B> {
    fn erase_org_privacy(&self, id: &OrgId) -> RepoResult<bool> {
        let workspace_edges = ResourceModelRepo::list_workspace_orgs(self)?;
        let resource_edges = ResourceModelRepo::list_edges(self)?;
        let privacy = OrganizationPrivacyScope::resolve(id, &workspace_edges, &resource_edges);
        let groups = GroupRepo::list(self)?;
        let group_ids = groups
            .iter()
            .filter(|group| &group.org == id)
            .map(|group| group.id.0.clone())
            .collect::<BTreeSet<_>>();
        let grants = GrantRepo::list(self)?;
        let bindings = RoleBindingRepo::list(self)?;

        let token_rows = self.backend.query(
            &format!(
                "SELECT id, workspace FROM {} ORDER BY id",
                self.table("api_tokens")
            ),
            &[],
        )?;
        let mut writes = Vec::new();
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
            .any(|affected| affected != 0))
    }
}
