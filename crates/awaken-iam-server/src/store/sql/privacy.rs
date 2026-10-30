//! Organization privacy lifecycle over the shared SQL adapter.

use super::{
    SqlConn, SqlRow, SqlStore, decode_grant, decode_role_binding, decode_workspace_org,
    json_decode, json_encode, p, parse_fence_value, req,
};
use awaken_iam_contract::{OrgId, OrgPrivacyCommitReceipt, ScopeRef};
use awaken_iam_core::{
    AuditEvent, GrantSubject, OrgPrivacyCommitPlan, OrgPrivacyRepository, OrgPrivacyTerminal,
    OrganizationPrivacyScope, RepositoryError, RepositoryResult, plan_org_privacy_commit,
};
use std::collections::BTreeSet;

pub(super) fn decode_terminal(
    row: &SqlRow,
    id: &OrgId,
) -> RepositoryResult<Option<OrgPrivacyTerminal>> {
    let Some(version) = row.first().and_then(Option::as_ref) else {
        return Ok(None);
    };
    let terminal = OrgPrivacyTerminal {
        scope: json_decode(&req(row, 2, "erased scope")?, "erased scope")?,
        group_ids: json_decode(&req(row, 3, "erased groups")?, "erased groups")?,
        erasure_version: version.parse().map_err(|error| {
            RepositoryError::Backend(format!("invalid erasure version: {error}"))
        })?,
        confirmed_organization: match req(row, 1, "erasure confirmation")?.as_str() {
            "1" => true,
            "0" => false,
            _ => {
                return Err(RepositoryError::Backend(
                    "invalid erasure confirmation".into(),
                ));
            }
        },
    };
    if !terminal
        .scope
        .contains(&ScopeRef::Org { org_id: id.clone() })
    {
        return Err(RepositoryError::Backend(
            "terminal organization identity differs".into(),
        ));
    }
    Ok(Some(terminal))
}

impl<B: SqlConn> OrgPrivacyRepository for SqlStore<B> {
    fn erase_org_privacy(&self, id: &OrgId) -> RepositoryResult<bool> {
        self.erase_org_privacy_with_audit(
            id,
            crate::admin_api::organization_erasure_audit(id, crate::clock::now_timestamp()),
        )
        .map(|receipt| receipt.changed)
    }

    fn erase_org_privacy_with_audit(
        &self,
        id: &OrgId,
        audit: AuditEvent,
    ) -> RepositoryResult<OrgPrivacyCommitReceipt> {
        if id.0.trim().is_empty() {
            return Err(RepositoryError::Conflict(
                "empty organization identity".into(),
            ));
        }
        let mut committed = None;
        self.backend.with_transaction(&mut |transaction| {
            // SAME ordering required of scoped writers: shared policy mutex,
            // then Directory mutex, THEN closure/current-identity reads. Never
            // use the outer connection while this callback holds its owner.
            let version = self.lock_policy(transaction)?;
            transaction.execute(&format!("UPDATE {} SET revision=revision WHERE org_id=?", self.table("directory_fence")), &[p(id.0.clone())])?;
            let orgs = transaction.query(&format!("SELECT CAST(erasure_version AS TEXT), CAST(erasure_confirmed AS TEXT), CAST(erased_scope AS TEXT), CAST(erased_groups AS TEXT) FROM {} WHERE id=?", self.table("orgs")), &[p(id.0.clone())])?;
            let terminal = orgs.first().map(|row| decode_terminal(row, id)).transpose()?.flatten();
            let known = self.read_org_with(id,|sql,params| transaction.query(sql,params))?.is_some();
            let (next, confirmed) = match plan_org_privacy_commit(id, terminal.as_ref(), known, version)? {
                OrgPrivacyCommitPlan::Replay(receipt) => { committed = Some(receipt); return Ok(()); }
                OrgPrivacyCommitPlan::Publish { erasure_version, confirmed_organization } => (erasure_version, confirmed_organization),
            };
            let workspace_edges = transaction.query(&format!("SELECT workspace_id,org_id FROM {} ORDER BY workspace_id", self.table("workspace_org_edges")), &[])?.iter().map(decode_workspace_org).collect::<RepositoryResult<Vec<_>>>()?;
            let resource_edges = self.read_edges_with(|sql,params| transaction.query(sql,params))?;
            let projection_ownership = self.projection_resource_ownership(transaction)?;
            let projected_keys = projection_ownership.iter().filter(|(_,_,org)| org == id).map(|(kind,key,_)| (kind.clone(),key.clone())).collect::<BTreeSet<_>>();
            let privacy = OrganizationPrivacyScope::resolve_with_owned_resources(id, &workspace_edges, &resource_edges, &projected_keys);
            let group_ids = transaction.query(&format!("SELECT id FROM {} WHERE org_id=? ORDER BY id", self.table("groups")), &[p(id.0.clone())])?.iter().map(|row| req(row,0,"group id")).collect::<RepositoryResult<BTreeSet<_>>>()?;
            let grants = transaction.query(&format!("SELECT id,CAST(subject AS TEXT),action_pattern,CAST(scope AS TEXT),effect FROM {} ORDER BY id", self.table("grants")), &[])?.iter().map(decode_grant).collect::<RepositoryResult<Vec<_>>>()?;
            let bindings = transaction.query(&format!("SELECT CAST(principal AS TEXT),role,CAST(scope AS TEXT) FROM {} ORDER BY principal,role,scope", self.table("role_bindings")), &[])?.iter().map(decode_role_binding).collect::<RepositoryResult<Vec<_>>>()?;
            let tokens = transaction.query(&format!("SELECT id,workspace FROM {} ORDER BY id", self.table("api_tokens")), &[])?;
            for (kind,key,org) in projection_ownership {
                if privacy.contains(&ScopeRef::Resource { resource_type: awaken_iam_contract::ResourceType(kind), resource_id: awaken_iam_contract::ResourceId(key) }) && &org != id {
                    return Err(RepositoryError::Conflict("privacy scope crosses another projection owner".into()));
                }
            }
            let mut changed = confirmed;
            for row in tokens {
                if privacy.contains_workspace(&req(&row,1,"token workspace")?) {
                    changed |= transaction.execute(&format!("DELETE FROM {} WHERE id=?", self.table("api_tokens")), &[p(req(&row,0,"token id")?)])? != 0;
                }
            }
            for grant in grants {
                let owned_group = matches!(&grant.subject, GrantSubject::Group(group) if group_ids.contains(&group.0));
                if privacy.contains(&grant.scope) || owned_group {
                    changed |= transaction.execute(&format!("DELETE FROM {} WHERE id=?", self.table("grants")), &[p(grant.id.0)])? != 0;
                }
            }
            for binding in bindings {
                if privacy.contains(&binding.scope) {
                    changed |= transaction.execute(&format!("DELETE FROM {} WHERE principal=?j AND role=? AND scope=?j", self.table("role_bindings")), &[p(json_encode(&binding.principal,"principal")?),p(binding.role.0),p(json_encode(&binding.scope,"binding scope")?)])? != 0;
                }
            }
            for edge in resource_edges {
                let child = ScopeRef::Resource { resource_type: edge.resource_type.clone(), resource_id: edge.resource_id.clone() };
                if privacy.contains(&edge.parent) || privacy.contains(&child) {
                    changed |= transaction.execute(&format!("DELETE FROM {} WHERE resource_type=? AND resource_id=?", self.table("resource_edges")), &[p(edge.resource_type.0),p(edge.resource_id.0)])? != 0;
                }
            }
            // Keep projection ownership/tombstone/epoch coordinates canonical.
            // Only their payload lists are redacted; terminal admission denies
            // replay before an old stream receipt can recreate any payload.
            changed |= transaction.execute(&format!("UPDATE {} SET grant_ids=?j,edge_keys=?j WHERE org_id=? AND (CAST(grant_ids AS TEXT) <> '[]' OR CAST(edge_keys AS TEXT) <> '[]')", self.table("resource_projection_streams")), &[p("[]"),p("[]"),p(id.0.clone())])? != 0;
            let directory = transaction.query(&format!("SELECT CAST(revision AS TEXT) FROM {} WHERE org_id=? AND EXISTS (SELECT 1 FROM {} WHERE org_id=?)", self.table("directory_fence"), self.table("directory_nodes")), &[p(id.0.clone()),p(id.0.clone())])?;
            if let Some(row) = directory.first() {
                let revision = parse_fence_value(row.first(), "directory revision")?;
                let next_revision = revision.checked_add(1).filter(|value| *value <= i64::MAX as u64).ok_or_else(|| RepositoryError::Backend("Directory revision exhausted".into()))?;
                transaction.execute(&format!("UPDATE {} SET revision=CAST(CAST(? AS TEXT) AS BIGINT) WHERE org_id=?", self.table("directory_fence")), &[p(next_revision.to_string()),p(id.0.clone())])?;
            }
            for (table,column) in [("product_space_bindings","org_id"),("directory_nodes","org_id"),("invitations","org_id"),("groups","org_id"),("workspace_org_edges","org_id")] {
                changed |= transaction.execute(&format!("DELETE FROM {} WHERE {column}=?", self.table(table)), &[p(id.0.clone())])? != 0;
            }
            let terminal = OrgPrivacyTerminal { scope: privacy.without_projected_resources(&projected_keys), group_ids, erasure_version: next, confirmed_organization: confirmed };
            let scope = json_encode(&terminal.scope,"erased scope")?; let groups = json_encode(&terminal.group_ids,"erased groups")?;
            let stored = transaction.execute(&format!("INSERT INTO {orgs} (id,erasure_version,erasure_confirmed,erased_scope,erased_groups) VALUES (?,CAST(CAST(? AS TEXT) AS BIGINT),CAST(CAST(? AS TEXT) AS BIGINT),?j,?j) ON CONFLICT(id) DO UPDATE SET display_name=NULL,owner=NULL,created_at=NULL,updated_at=NULL,erasure_version=excluded.erasure_version,erasure_confirmed=excluded.erasure_confirmed,erased_scope=excluded.erased_scope,erased_groups=excluded.erased_groups", orgs=self.table("orgs")), &[p(id.0.clone()),p(next.to_string()),p(if confirmed { "1" } else { "0" }),p(scope),p(groups)])?;
            if stored != 1 { return Err(RepositoryError::Conflict("organization terminal commit lost identity".into())); }
            let actor = audit.actor.as_ref().map(|actor| json_encode(actor,"audit actor")).transpose()?;
            transaction.execute(&format!("INSERT INTO {} (at,actor,action,detail) VALUES (?,?j,?,?)", self.table("audit_events")), &[p(audit.at.0.clone()),actor,p(audit.action.clone()),p(audit.detail.clone())])?;
            if transaction.execute(&format!("UPDATE {} SET version=CAST(CAST(? AS TEXT) AS BIGINT),updated_at=? WHERE id=1 AND version=CAST(CAST(? AS TEXT) AS BIGINT)", self.table("fence")), &[p(next.to_string()),p(audit.at.0.clone()),p(version.to_string())])? != 1 { return Err(RepositoryError::Conflict("privacy policy publication conflict".into())); }
            committed = Some(terminal.receipt(next, changed, true)?);
            Ok(())
        })?;
        committed.ok_or_else(|| {
            RepositoryError::Backend("privacy transaction returned no receipt".into())
        })
    }
}
