//! Fenced team access replacement in one policy transaction (ADR-0018).

use std::collections::BTreeMap;

use awaken_iam_contract::{
    AccessFence, ScopeRef, TeamAccessReceipt, TeamAccessReplacement, Timestamp,
};
use awaken_iam_core::{AuditEvent, GroupId, RepositoryError, RepositoryResult};

use super::{
    SqlConn, SqlStore, SqlWrite, encode_effect, encode_grant_subject, json_encode, p, req,
};
use crate::PrincipalAccessStore;
use crate::admin_api::{
    TeamAccessCurrent, fence_key, plan_team_access, suspension_grant, team_access_receipt,
    workspace_scope,
};

impl<B: SqlConn> PrincipalAccessStore for SqlStore<B> {
    fn replace_team_access(
        &self,
        command: &TeamAccessReplacement,
        at: &Timestamp,
        audit: AuditEvent,
    ) -> RepositoryResult<TeamAccessReceipt> {
        let key = fence_key(command)?;
        let deny = suspension_grant(command)?;
        self.with_policy_transaction(|transaction, version| {
            let next_version = version
                .checked_add(1)
                .filter(|value| *value <= i64::MAX as u64)
                .ok_or_else(|| RepositoryError::Backend("IAM policy version exhausted".into()))?;
            let fence = transaction
                .query(
                    &format!(
                        "SELECT CAST(generation AS TEXT), plan_id FROM {} WHERE fence_key = ?",
                        self.table("principal_access_fences")
                    ),
                    &[p(key.clone())],
                )?
                .first()
                .map(|row| {
                    Ok::<_, RepositoryError>(AccessFence {
                        generation: req(row, 0, "fence generation")?
                            .parse()
                            .map_err(|_| RepositoryError::Backend("malformed fence".into()))?,
                        plan_id: req(row, 1, "fence plan")?,
                    })
                })
                .transpose()?;
            let mut groups = BTreeMap::new();
            for id in &command.managed {
                let group = self.read_group_with(&GroupId(id.clone()), |sql, params| {
                    transaction.query(sql, params)
                })?;
                groups.insert(id.clone(), group);
            }
            let workspace_org = self
                .read_workspace_org_with(&command.workspace_id, |sql, params| {
                    transaction.query(sql, params)
                })?
                .map(|edge| edge.org_id);
            let suspended = !transaction
                .query(
                    &format!("SELECT id FROM {} WHERE id = ?", self.table("grants")),
                    &[p(deny.id.0.clone())],
                )?
                .is_empty();
            let mut scopes = vec![workspace_scope(command)];
            scopes.extend(workspace_org.clone().map(|org_id| ScopeRef::Org { org_id }));
            let existing: Vec<String> = groups
                .iter()
                .filter(|(_, group)| group.is_some())
                .map(|(id, _)| id.clone())
                .collect();
            self.ensure_scope_admission(transaction, &scopes, &existing)?;
            let plan = plan_team_access(
                command,
                &TeamAccessCurrent {
                    groups,
                    suspended,
                    fence,
                    workspace_org,
                },
                at,
            )?;
            if plan.suspension.is_some() {
                self.grant_admission(
                    transaction,
                    std::slice::from_ref(&deny.id.0),
                    std::slice::from_ref(&deny.scope),
                    &[],
                )?;
                self.require_raw_grant_effect(transaction, &deny.id.0, &deny.scope)?;
            }
            let mut writes = Vec::new();
            let mut required = Vec::new();
            for group in &plan.groups {
                writes.push(SqlWrite {
                    sql: format!(
                        "INSERT INTO {t} (id, org_id, display_name, members, created_at, updated_at) \
                         VALUES (?, ?, ?, ?j, ?, ?) \
                         ON CONFLICT (id) DO UPDATE SET members = excluded.members, \
                         updated_at = excluded.updated_at",
                        t = self.table("groups")
                    ),
                    params: vec![
                        p(group.id.0.clone()),
                        p(group.org.0.clone()),
                        group.display_name.clone(),
                        p(json_encode(&group.members, "group members")?),
                        p(group.created_at.0.clone()),
                        p(group.updated_at.0.clone()),
                    ],
                });
                required.push((writes.len() - 1, 1));
            }
            match plan.suspension {
                Some(true) => {
                    writes.push(SqlWrite {
                        sql: format!(
                            "INSERT INTO {} (id, subject, action_pattern, scope, effect) \
                             VALUES (?, ?j, ?, ?j, ?)",
                            self.table("grants")
                        ),
                        params: vec![
                            p(deny.id.0.clone()),
                            p(encode_grant_subject(&deny.subject)?),
                            p(deny.action_pattern.0.clone()),
                            p(json_encode(&deny.scope, "grant scope")?),
                            p(encode_effect(deny.effect)),
                        ],
                    });
                    required.push((writes.len() - 1, 1));
                }
                Some(false) => {
                    writes.push(SqlWrite {
                        sql: format!("DELETE FROM {} WHERE id = ?", self.table("grants")),
                        params: vec![p(deny.id.0.clone())],
                    });
                    required.push((writes.len() - 1, 1));
                }
                None => {}
            }
            // The guard repeats the fence rule, so the row never moves back
            // even if the planner were bypassed.
            writes.push(SqlWrite {
                sql: format!(
                    "INSERT INTO {f} (fence_key, generation, plan_id) \
                     VALUES (?, CAST(CAST(? AS TEXT) AS BIGINT), ?) \
                     ON CONFLICT (fence_key) DO UPDATE SET generation = excluded.generation, \
                     plan_id = excluded.plan_id \
                     WHERE {f}.generation < excluded.generation \
                     OR ({f}.generation = excluded.generation AND {f}.plan_id = excluded.plan_id)",
                    f = self.table("principal_access_fences")
                ),
                params: vec![
                    p(key.clone()),
                    p(command.fence.generation.to_string()),
                    p(command.fence.plan_id.clone()),
                ],
            });
            required.push((writes.len() - 1, 1));
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
                    p(audit.action.clone()),
                    p(audit.detail.clone()),
                ],
            });
            writes.push(SqlWrite {
                sql: format!(
                    "UPDATE {} SET version = version + 1, updated_at = ? WHERE id = 1",
                    self.table("fence")
                ),
                params: vec![p(audit.at.0.clone())],
            });
            required.push((writes.len() - 1, 1));
            transaction.execute_checked(&writes, &required)?;
            Ok(team_access_receipt(command, &plan, next_version))
        })
    }
}
