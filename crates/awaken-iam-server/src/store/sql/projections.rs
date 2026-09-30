//! Atomic, versioned product projection writes over the shared SQL seam.

use super::*;
use awaken_iam_contract::{
    GrantEffect, ProductResourceModelRequest, ResourceModelRegistered, ResourceProjectionBatch,
    ResourceProjectionDisposition, ResourceProjectionReceipt, ScopeRef,
};
use sha2::{Digest, Sha256};

type EdgeKey = (String, String);

struct StreamHead {
    epoch: u64,
    digest: String,
    key: String,
    version: u64,
    grants: Vec<String>,
    edges: Vec<EdgeKey>,
}

impl<B: SqlConn> SqlStore<B> {
    /// Persist one product's additive type/action catalog under the policy fence.
    pub fn register_product_resource_model(
        &self,
        request: &ProductResourceModelRequest,
    ) -> RepositoryResult<ResourceModelRegistered> {
        if !request.resource_model.edges.is_empty() {
            return Err(RepositoryError::Conflict(
                "instance edges must be submitted through a versioned projection".into(),
            ));
        }
        let product = request.product_id.as_str();
        let mut actions = BTreeSet::new();
        for resource in &request.resource_model.resource_types {
            if resource.resource_type.0.trim().is_empty() {
                return Err(RepositoryError::Conflict(
                    "resource type is required".into(),
                ));
            }
            for action in &resource.actions {
                actions.insert(action.0.as_str());
            }
        }
        for action in &request.resource_model.actions {
            actions.insert(action.0.as_str());
        }
        if request.resource_model.resource_types.is_empty() && actions.is_empty() {
            return Err(RepositoryError::Conflict("resource model is empty".into()));
        }
        let namespace = format!("{product}.");
        if actions
            .iter()
            .any(|action| !action.starts_with(&namespace) || action.contains('*'))
        {
            return Err(RepositoryError::Conflict(
                "action must use its product namespace without a wildcard".into(),
            ));
        }
        let fence = FenceStore::fence(self)?.version;
        let version = fence
            .checked_add(1)
            .ok_or_else(|| RepositoryError::Backend("policy version exhausted".into()))?;
        let mut writes = vec![SqlWrite {
            sql: format!(
                "UPDATE {} SET version = version + 1 WHERE id = 1 AND CAST(version AS TEXT) = ?",
                self.table("fence")
            ),
            params: vec![p(fence.to_string())],
        }];
        for resource in &request.resource_model.resource_types {
            writes.push(SqlWrite {
                sql: format!(
                    "INSERT INTO {} (product_id, resource_type, parent_type, actions) \
                    VALUES (?, ?, ?, ?j) ON CONFLICT (product_id, resource_type) DO UPDATE SET \
                    parent_type = excluded.parent_type, actions = excluded.actions",
                    self.table("product_resource_types")
                ),
                params: vec![
                    p(product),
                    p(&resource.resource_type.0),
                    resource.parent_type.as_ref().map(|parent| parent.0.clone()),
                    p(json_encode(&resource.actions, "resource type actions")?),
                ],
            });
        }
        for action in actions {
            writes.push(SqlWrite {
                sql: format!(
                    "INSERT INTO {} (product_id, action_key) VALUES (?, ?) \
                    ON CONFLICT (product_id, action_key) DO NOTHING",
                    self.table("product_actions")
                ),
                params: vec![p(product), p(action)],
            });
        }
        writes.push(SqlWrite {
            sql: format!(
                "INSERT INTO {} (at, actor, action, detail) VALUES (?, NULL, ?, ?)",
                self.table("audit_events")
            ),
            params: vec![
                p(time::OffsetDateTime::now_utc().to_string()),
                p("resource_model.register"),
                p(product),
            ],
        });
        self.backend
            .execute_transaction_checked(&writes, &[(0, 1)])?;
        Ok(ResourceModelRegistered { version })
    }

    /// Replace one product-owned grant/edge snapshot under a persisted epoch.
    /// The caller authenticates the product credential before reaching this seam.
    pub fn apply_resource_projection(
        &self,
        batch: &ResourceProjectionBatch,
    ) -> RepositoryResult<ResourceProjectionReceipt> {
        for _ in 0..5 {
            match self.apply_resource_projection_once(batch) {
                Ok(receipt) => return Ok(receipt),
                Err(RepositoryError::Conflict(detail)) => {
                    // A concurrent identical delivery may win the INSERT after our
                    // initial read. Resolve it from the committed stream head.
                    if let Some(head) = self.projection_head(batch)? {
                        if head.epoch > batch.epoch {
                            return Ok(projection_receipt(
                                batch,
                                head.version,
                                ResourceProjectionDisposition::Stale,
                            ));
                        }
                        if head.epoch == batch.epoch && head.key == batch.idempotency_key {
                            let digest = format!(
                                "{:x}",
                                Sha256::digest(serde_json::to_vec(batch).map_err(|error| {
                                    RepositoryError::Backend(error.to_string())
                                })?)
                            );
                            if digest == head.digest {
                                return Ok(projection_receipt(
                                    batch,
                                    head.version,
                                    ResourceProjectionDisposition::Replayed,
                                ));
                            }
                        }
                    }
                    if detail.starts_with("transaction write 0 affected 0 rows")
                        || detail.starts_with("transaction write 1 affected 0 rows")
                    {
                        continue;
                    }
                    return Err(RepositoryError::Conflict(detail));
                }
                Err(error) => return Err(error),
            }
        }
        Err(RepositoryError::Conflict(
            "projection policy fence remained busy".into(),
        ))
    }

    fn apply_resource_projection_once(
        &self,
        batch: &ResourceProjectionBatch,
    ) -> RepositoryResult<ResourceProjectionReceipt> {
        if batch.projection_id.trim().is_empty()
            || batch.projection_id.len() > 160
            || batch.idempotency_key.trim().is_empty()
            || batch.idempotency_key.len() > 160
            || batch.epoch == 0
        {
            return Err(RepositoryError::Conflict(
                "projection coordinates are required".into(),
            ));
        }
        if OrgRepository::get(self, &batch.org_id)?.is_none() {
            return Err(RepositoryError::NotFound(format!(
                "organization {}",
                batch.org_id.0
            )));
        }
        let digest = format!(
            "{:x}",
            Sha256::digest(
                serde_json::to_vec(batch).map_err(|e| RepositoryError::Backend(e.to_string()))?
            )
        );
        let head = self.projection_head(batch)?;
        if let Some(current) = &head {
            if batch.epoch < current.epoch {
                return Ok(projection_receipt(
                    batch,
                    current.version,
                    ResourceProjectionDisposition::Stale,
                ));
            }
            if batch.epoch == current.epoch {
                if digest == current.digest && batch.idempotency_key == current.key {
                    return Ok(projection_receipt(
                        batch,
                        current.version,
                        ResourceProjectionDisposition::Replayed,
                    ));
                }
                return Err(RepositoryError::Conflict(
                    "projection epoch was reused with different content".into(),
                ));
            }
        }
        self.validate_projection(batch, head.as_ref())?;
        let grant_ids: Vec<String> = batch.grants.iter().map(|grant| grant.id.clone()).collect();
        let edge_keys: Vec<EdgeKey> = batch
            .scope_edges
            .iter()
            .map(|edge| (edge.resource_type.0.clone(), edge.resource_id.0.clone()))
            .collect();
        let old_grants = head
            .as_ref()
            .map_or(&[][..], |current| current.grants.as_slice());
        let old_edges = head
            .as_ref()
            .map_or(&[][..], |current| current.edges.as_slice());
        let fence = FenceStore::fence(self)?.version;
        let version = fence
            .checked_add(1)
            .ok_or_else(|| RepositoryError::Backend("policy version exhausted".into()))?;
        let mut writes = vec![SqlWrite {
            sql: format!(
                "UPDATE {} SET version = version + 1 WHERE id = 1 AND CAST(version AS TEXT) = ?",
                self.table("fence")
            ),
            params: vec![p(fence.to_string())],
        }];
        let mut required = vec![(0, 1)];
        let stream_index = writes.len();
        if let Some(current) = &head {
            writes.push(SqlWrite {
                sql: format!("UPDATE {} SET epoch = CAST(CAST(? AS TEXT) AS BIGINT), payload_digest = ?, idempotency_key = ?, \
                    version = CAST(CAST(? AS TEXT) AS BIGINT), grant_ids = ?j, edge_keys = ?j WHERE product_id = ? AND org_id = ? \
                    AND projection_id = ? AND CAST(epoch AS TEXT) = ? AND payload_digest = ?", self.table("resource_projection_streams")),
                params: vec![p(batch.epoch.to_string()), p(&digest), p(&batch.idempotency_key),
                    p(version.to_string()), p(json_encode(&grant_ids, "projection grant IDs")?),
                    p(json_encode(&edge_keys, "projection edge keys")?), p(batch.product_id.as_str()),
                    p(&batch.org_id.0), p(&batch.projection_id), p(current.epoch.to_string()), p(&current.digest)],
            });
        } else {
            writes.push(SqlWrite {
                sql: format!("INSERT INTO {} (product_id, org_id, projection_id, idempotency_key, \
                    epoch, payload_digest, version, grant_ids, edge_keys) VALUES (?, ?, ?, ?, CAST(CAST(? AS TEXT) AS BIGINT), ?, CAST(CAST(? AS TEXT) AS BIGINT), ?j, ?j)",
                    self.table("resource_projection_streams")),
                params: vec![p(batch.product_id.as_str()), p(&batch.org_id.0), p(&batch.projection_id),
                    p(&batch.idempotency_key), p(batch.epoch.to_string()), p(&digest), p(version.to_string()),
                    p(json_encode(&grant_ids, "projection grant IDs")?),
                    p(json_encode(&edge_keys, "projection edge keys")?)],
            });
        }
        required.push((stream_index, 1));
        for id in old_grants {
            writes.push(SqlWrite {
                sql: format!("DELETE FROM {} WHERE id = ?", self.table("grants")),
                params: vec![p(id)],
            });
            writes.push(SqlWrite {
                sql: format!(
                    "DELETE FROM {} WHERE grant_id = ?",
                    self.table("resource_projection_grant_owners")
                ),
                params: vec![p(id)],
            });
        }
        for (kind, id) in old_edges {
            writes.push(SqlWrite {
                sql: format!(
                    "DELETE FROM {} WHERE resource_type = ? AND resource_id = ?",
                    self.table("resource_edges")
                ),
                params: vec![p(kind), p(id)],
            });
            writes.push(SqlWrite {
                sql: format!(
                    "DELETE FROM {} WHERE resource_type = ? AND resource_id = ?",
                    self.table("resource_projection_edge_owners")
                ),
                params: vec![p(kind), p(id)],
            });
        }
        for grant in &batch.grants {
            writes.push(SqlWrite {
                sql: format!("INSERT INTO {} (grant_id, product_id, org_id, projection_id) VALUES (?, ?, ?, ?)", self.table("resource_projection_grant_owners")),
                params: vec![p(&grant.id), p(batch.product_id.as_str()), p(&batch.org_id.0), p(&batch.projection_id)],
            });
            writes.push(SqlWrite {
                sql: format!("INSERT INTO {} (id, subject, action_pattern, scope, effect) VALUES (?, ?j, ?, ?j, ?)", self.table("grants")),
                params: vec![p(&grant.id), p(json_encode(&grant.subject, "projection subject")?),
                    p(&grant.action_pattern), p(json_encode(&grant.scope, "projection scope")?),
                    p(match grant.effect { GrantEffect::Allow => "allow", GrantEffect::Deny => "deny",
                        GrantEffect::RequireApproval => "require_approval" })],
            });
        }
        for edge in &batch.scope_edges {
            writes.push(SqlWrite {
                sql: format!("INSERT INTO {} (resource_type, resource_id, product_id, org_id, projection_id) \
                    VALUES (?, ?, ?, ?, ?)", self.table("resource_projection_edge_owners")),
                params: vec![p(&edge.resource_type.0), p(&edge.resource_id.0), p(batch.product_id.as_str()),
                    p(&batch.org_id.0), p(&batch.projection_id)],
            });
            writes.push(SqlWrite {
                sql: format!(
                    "INSERT INTO {} (resource_type, resource_id, parent) VALUES (?, ?, ?j)",
                    self.table("resource_edges")
                ),
                params: vec![
                    p(&edge.resource_type.0),
                    p(&edge.resource_id.0),
                    p(json_encode(&edge.parent, "projection parent")?),
                ],
            });
        }
        for retired in &batch.retirements {
            writes.push(SqlWrite {
                sql: format!("INSERT INTO {} (resource_type, resource_id, product_id, org_id, projection_id, epoch) \
                    VALUES (?, ?, ?, ?, ?, CAST(CAST(? AS TEXT) AS BIGINT))", self.table("resource_projection_tombstones")),
                params: vec![p(&retired.resource_type.0), p(&retired.resource_id.0),
                    p(batch.product_id.as_str()), p(&batch.org_id.0), p(&batch.projection_id), p(batch.epoch.to_string())],
            });
        }
        writes.push(SqlWrite {
            sql: format!(
                "INSERT INTO {} (product_id, org_id, idempotency_key, projection_id, epoch, \
                payload_digest, version) VALUES (?, ?, ?, ?, CAST(CAST(? AS TEXT) AS BIGINT), ?, CAST(CAST(? AS TEXT) AS BIGINT))",
                self.table("resource_projection_keys")
            ),
            params: vec![
                p(batch.product_id.as_str()),
                p(&batch.org_id.0),
                p(&batch.idempotency_key),
                p(&batch.projection_id),
                p(batch.epoch.to_string()),
                p(&digest),
                p(version.to_string()),
            ],
        });
        writes.push(SqlWrite {
            sql: format!(
                "INSERT INTO {} (at, actor, action, detail) VALUES (?, NULL, ?, ?)",
                self.table("audit_events")
            ),
            params: vec![
                p(time::OffsetDateTime::now_utc().to_string()),
                p("resource_projection.apply"),
                p(format!(
                    "{}:{}:{}:{}",
                    batch.product_id.as_str(),
                    batch.org_id.0,
                    batch.projection_id,
                    batch.epoch
                )),
            ],
        });
        self.backend
            .execute_transaction_checked(&writes, &required)?;
        Ok(projection_receipt(
            batch,
            version,
            ResourceProjectionDisposition::Applied,
        ))
    }

    fn projection_head(
        &self,
        batch: &ResourceProjectionBatch,
    ) -> RepositoryResult<Option<StreamHead>> {
        let rows = self.backend.query(
            &format!(
                "SELECT CAST(epoch AS TEXT), payload_digest, idempotency_key, \
            CAST(version AS TEXT), CAST(grant_ids AS TEXT), CAST(edge_keys AS TEXT) FROM {} \
            WHERE product_id = ? AND org_id = ? AND projection_id = ?",
                self.table("resource_projection_streams")
            ),
            &[
                p(batch.product_id.as_str()),
                p(&batch.org_id.0),
                p(&batch.projection_id),
            ],
        )?;
        rows.first()
            .map(|row| {
                Ok(StreamHead {
                    epoch: req(row, 0, "stream epoch")?
                        .parse()
                        .map_err(|e| RepositoryError::Backend(format!("stream epoch: {e}")))?,
                    digest: req(row, 1, "stream digest")?,
                    key: req(row, 2, "stream key")?,
                    version: req(row, 3, "stream version")?
                        .parse()
                        .map_err(|e| RepositoryError::Backend(format!("stream version: {e}")))?,
                    grants: json_decode(&req(row, 4, "stream grants")?, "stream grants")?,
                    edges: json_decode(&req(row, 5, "stream edges")?, "stream edges")?,
                })
            })
            .transpose()
    }

    fn validate_projection(
        &self,
        batch: &ResourceProjectionBatch,
        head: Option<&StreamHead>,
    ) -> RepositoryResult<()> {
        let old_grants: BTreeSet<&str> = head
            .into_iter()
            .flat_map(|h| h.grants.iter().map(String::as_str))
            .collect();
        let old_edges: BTreeSet<(&str, &str)> = head
            .into_iter()
            .flat_map(|h| h.edges.iter().map(|(a, b)| (a.as_str(), b.as_str())))
            .collect();
        let mut grant_ids = BTreeSet::new();
        let mut edge_keys = BTreeSet::new();
        for edge in &batch.scope_edges {
            let key = (edge.resource_type.0.as_str(), edge.resource_id.0.as_str());
            if !edge_keys.insert(key) {
                return Err(RepositoryError::Conflict("duplicate projected edge".into()));
            }
            if matches!(&edge.parent, ScopeRef::Resource { resource_type, resource_id }
                if resource_type.0 == key.0 && resource_id.0 == key.1)
            {
                return Err(RepositoryError::Conflict(
                    "resource cannot be its own parent".into(),
                ));
            }
            self.ensure_not_retired(key)?;
            self.ensure_model_type(batch.product_id.as_str(), key.0)?;
            self.ensure_parent_owner(batch, &edge.parent, &edge_keys)?;
            if old_edges.contains(&key) {
                let existing =
                    ResourceModelRepository::list_edges(self)?
                        .into_iter()
                        .find(|candidate| {
                            candidate.resource_type.0 == key.0 && candidate.resource_id.0 == key.1
                        });
                if existing.is_none_or(|existing| existing.parent != edge.parent) {
                    return Err(RepositoryError::Conflict(
                        "projection cannot silently reparent a resource".into(),
                    ));
                }
            } else {
                self.ensure_edge_unowned(key)?;
            }
        }
        for grant in &batch.grants {
            if !grant_ids.insert(grant.id.as_str()) {
                return Err(RepositoryError::Conflict(
                    "duplicate projected grant".into(),
                ));
            }
            self.ensure_action(batch.product_id.as_str(), &grant.action_pattern)?;
            self.ensure_scope_owner(batch, &grant.scope, &edge_keys)?;
            if !old_grants.contains(grant.id.as_str()) {
                self.ensure_grant_unowned(&grant.id)?;
            }
        }
        let mut retirement_keys = BTreeSet::new();
        for retired in &batch.retirements {
            let key = (
                retired.resource_type.0.as_str(),
                retired.resource_id.0.as_str(),
            );
            if !retirement_keys.insert(key) {
                return Err(RepositoryError::Conflict("duplicate retirement".into()));
            }
            if !old_edges.contains(&key) {
                return Err(RepositoryError::Conflict(
                    "only the owning stream may retire a resource".into(),
                ));
            }
            if edge_keys.contains(&key) {
                return Err(RepositoryError::Conflict(
                    "retired resource remains in desired edges".into(),
                ));
            }
            if batch.grants.iter().any(|grant| matches!(&grant.scope, ScopeRef::Resource { resource_type, resource_id } if resource_type.0 == key.0 && resource_id.0 == key.1)) {
                return Err(RepositoryError::Conflict("retired resource remains in desired grants".into()));
            }
            if self.resource_tombstone(key)?.is_some() {
                return Err(RepositoryError::Conflict("resource already retired".into()));
            }
            if ResourceModelRepository::list_edges(self)?
                .iter()
                .any(|edge| {
                    matches!(&edge.parent, ScopeRef::Resource { resource_type, resource_id }
                    if resource_type.0 == key.0 && resource_id.0 == key.1)
                })
            {
                return Err(RepositoryError::Conflict(
                    "retire child resources before their parent".into(),
                ));
            }
            if retired
                .grant_ids
                .iter()
                .any(|id| !old_grants.contains(id.as_str()))
            {
                return Err(RepositoryError::Conflict(
                    "retirement names a grant outside its owning stream".into(),
                ));
            }
        }
        if old_edges
            .iter()
            .any(|key| !edge_keys.contains(key) && !retirement_keys.contains(key))
        {
            return Err(RepositoryError::Conflict(
                "removed resource edge requires retirement".into(),
            ));
        }
        let keys = self.backend.query(&format!("SELECT projection_id FROM {} WHERE product_id = ? AND org_id = ? AND idempotency_key = ?", self.table("resource_projection_keys")),
            &[p(batch.product_id.as_str()), p(&batch.org_id.0), p(&batch.idempotency_key)])?;
        if !keys.is_empty() {
            return Err(RepositoryError::Conflict(
                "idempotency key already used".into(),
            ));
        }
        Ok(())
    }

    fn ensure_model_type(&self, product: &str, kind: &str) -> RepositoryResult<()> {
        if self
            .backend
            .query(
                &format!(
                    "SELECT resource_type FROM {} WHERE product_id = ? AND resource_type = ?",
                    self.table("product_resource_types")
                ),
                &[p(product), p(kind)],
            )?
            .is_empty()
        {
            return Err(RepositoryError::Conflict(
                "resource type is not registered for product".into(),
            ));
        }
        Ok(())
    }

    fn ensure_action(&self, product: &str, action: &str) -> RepositoryResult<()> {
        if action.contains('*')
            || self
                .backend
                .query(
                    &format!(
                        "SELECT action_key FROM {} WHERE product_id = ? AND action_key = ?",
                        self.table("product_actions")
                    ),
                    &[p(product), p(action)],
                )?
                .is_empty()
        {
            return Err(RepositoryError::Conflict(
                "action is not registered for product".into(),
            ));
        }
        Ok(())
    }

    fn ensure_parent_owner(
        &self,
        batch: &ResourceProjectionBatch,
        parent: &ScopeRef,
        pending: &BTreeSet<(&str, &str)>,
    ) -> RepositoryResult<()> {
        self.ensure_scope_owner(batch, parent, pending)
    }

    fn ensure_scope_owner(
        &self,
        batch: &ResourceProjectionBatch,
        scope: &ScopeRef,
        pending: &BTreeSet<(&str, &str)>,
    ) -> RepositoryResult<()> {
        match scope {
            ScopeRef::Org { org_id } if org_id == &batch.org_id => Ok(()),
            ScopeRef::Workspace { workspace_id } => {
                let owner = ResourceModelRepository::workspace_org(self, workspace_id)?;
                if owner.is_some_and(|edge| edge.org_id == batch.org_id) {
                    Ok(())
                } else {
                    Err(RepositoryError::Conflict(
                        "workspace belongs to another organization".into(),
                    ))
                }
            }
            ScopeRef::Resource {
                resource_type,
                resource_id,
            } => {
                let key = (resource_type.0.as_str(), resource_id.0.as_str());
                self.ensure_not_retired(key)?;
                if pending.contains(&key) {
                    return Ok(());
                }
                let owner = self.backend.query(&format!("SELECT product_id, org_id FROM {} WHERE resource_type = ? AND resource_id = ?", self.table("resource_projection_edge_owners")), &[p(key.0), p(key.1)])?;
                if owner.first().is_some_and(|row| {
                    row.first().and_then(Option::as_deref) == Some(batch.product_id.as_str())
                        && row.get(1).and_then(Option::as_deref) == Some(batch.org_id.0.as_str())
                }) {
                    Ok(())
                } else {
                    Err(RepositoryError::Conflict(
                        "resource belongs to another product or organization".into(),
                    ))
                }
            }
            _ => Err(RepositoryError::Conflict(
                "scope is outside the projected organization".into(),
            )),
        }
    }

    fn resource_tombstone(&self, key: (&str, &str)) -> RepositoryResult<Option<SqlRow>> {
        Ok(self
            .backend
            .query(
                &format!(
                    "SELECT product_id, org_id FROM {} WHERE resource_type = ? AND resource_id = ?",
                    self.table("resource_projection_tombstones")
                ),
                &[p(key.0), p(key.1)],
            )?
            .into_iter()
            .next())
    }

    fn ensure_not_retired(&self, key: (&str, &str)) -> RepositoryResult<()> {
        if self.resource_tombstone(key)?.is_some() {
            Err(RepositoryError::Conflict("resource is retired".into()))
        } else {
            Ok(())
        }
    }

    fn ensure_edge_unowned(&self, key: (&str, &str)) -> RepositoryResult<()> {
        for table in ["resource_projection_edge_owners", "resource_edges"] {
            if !self
                .backend
                .query(
                    &format!(
                        "SELECT resource_id FROM {} WHERE resource_type = ? AND resource_id = ?",
                        self.table(table)
                    ),
                    &[p(key.0), p(key.1)],
                )?
                .is_empty()
            {
                return Err(RepositoryError::Conflict(
                    "resource edge is owned by another writer".into(),
                ));
            }
        }
        Ok(())
    }

    fn ensure_grant_unowned(&self, id: &str) -> RepositoryResult<()> {
        for (table, column) in [
            ("resource_projection_grant_owners", "grant_id"),
            ("grants", "id"),
        ] {
            if !self
                .backend
                .query(
                    &format!(
                        "SELECT {column} FROM {} WHERE {column} = ?",
                        self.table(table)
                    ),
                    &[p(id)],
                )?
                .is_empty()
            {
                return Err(RepositoryError::Conflict(
                    "grant is owned by another writer".into(),
                ));
            }
        }
        Ok(())
    }
}

impl<B: SqlConn> crate::store::ResourceProjectionStore for SqlStore<B> {
    fn apply_projection(
        &self,
        batch: &ResourceProjectionBatch,
    ) -> RepositoryResult<ResourceProjectionReceipt> {
        self.apply_resource_projection(batch)
    }

    fn register_product_model(
        &self,
        request: &ProductResourceModelRequest,
    ) -> RepositoryResult<ResourceModelRegistered> {
        self.register_product_resource_model(request)
    }
}

fn projection_receipt(
    batch: &ResourceProjectionBatch,
    version: u64,
    disposition: ResourceProjectionDisposition,
) -> ResourceProjectionReceipt {
    ResourceProjectionReceipt {
        idempotency_key: batch.idempotency_key.clone(),
        epoch: batch.epoch,
        version,
        disposition,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::store::sqlite_in_memory_store;
    use awaken_iam_contract::{
        AccountId, ActionKey, GrantSnapshot, GrantSubjectRef, PrincipalRef, ProductId, ResourceId,
        ResourceModelRegistration, ResourceParentEdge, ResourceRetirement, ResourceType,
        ResourceTypeRegistration, WorkspaceId, WorkspaceOrgEdge,
    };

    fn setup() -> SqlStore<crate::store::SqliteBackend> {
        let store = sqlite_in_memory_store("iam").unwrap();
        store
            .backend()
            .execute(
                "INSERT INTO iam_orgs (id, display_name, owner, created_at, updated_at) \
             VALUES (?, ?, ?j, ?, ?)",
                &[
                    p("org-a"),
                    p("Org A"),
                    p(r#"{"kind":"account","account_id":"owner"}"#),
                    p("2026-01-01T00:00:00Z"),
                    p("2026-01-01T00:00:00Z"),
                ],
            )
            .unwrap();
        ResourceModelRepository::put_workspace_org(
            &store,
            WorkspaceOrgEdge {
                workspace_id: WorkspaceId("workspace-a".into()),
                org_id: OrgId("org-a".into()),
            },
        )
        .unwrap();
        store.backend().execute(
            "INSERT INTO iam_product_resource_types (product_id, resource_type, parent_type, actions) \
             VALUES (?, ?, ?, ?j)",
            &[p("tutor"), p("tutor.campus"), None, p("[]")],
        ).unwrap();
        for action in ["tutor.campus.manage", "tutor.campus.read"] {
            store
                .backend()
                .execute(
                    "INSERT INTO iam_product_actions (product_id, action_key) VALUES (?, ?)",
                    &[p("tutor"), p(action)],
                )
                .unwrap();
        }
        store
    }

    fn create_batch() -> ResourceProjectionBatch {
        let kind = ResourceType("tutor.campus".into());
        let id = ResourceId("campus-1".into());
        ResourceProjectionBatch {
            product_id: ProductId::new("tutor").unwrap(),
            org_id: OrgId("org-a".into()),
            projection_id: "campus:campus-1".into(),
            idempotency_key: "campus:campus-1:1".into(),
            epoch: 1,
            grants: vec![GrantSnapshot {
                id: "campus-1-creator-manage".into(),
                subject: GrantSubjectRef::Principal {
                    principal: PrincipalRef::Account {
                        account_id: AccountId("owner".into()),
                    },
                },
                action_pattern: "tutor.campus.manage".into(),
                scope: ScopeRef::Resource {
                    resource_type: kind.clone(),
                    resource_id: id.clone(),
                },
                effect: GrantEffect::Allow,
            }],
            scope_edges: vec![ResourceParentEdge {
                resource_type: kind,
                resource_id: id,
                parent: ScopeRef::Workspace {
                    workspace_id: WorkspaceId("workspace-a".into()),
                },
            }],
            retirements: vec![],
        }
    }

    #[test]
    fn product_model_registration_persists_catalog_and_rejects_cross_product_action() {
        let store = sqlite_in_memory_store("iam").unwrap();
        let request = ProductResourceModelRequest {
            product_id: ProductId::new("tutor").unwrap(),
            resource_model: ResourceModelRegistration {
                resource_types: vec![ResourceTypeRegistration {
                    resource_type: ResourceType("tutor.campus".into()),
                    parent_type: None,
                    actions: vec![ActionKey("tutor.campus.manage".into())],
                }],
                actions: vec![ActionKey("tutor.settings.read".into())],
                edges: vec![],
            },
        };
        assert_eq!(
            store
                .register_product_resource_model(&request)
                .unwrap()
                .version,
            2
        );
        assert!(store.ensure_action("tutor", "tutor.settings.read").is_ok());
        assert!(store.ensure_model_type("tutor", "tutor.campus").is_ok());
        let mut invalid = request;
        invalid.resource_model.actions = vec![ActionKey("other.admin".into())];
        assert!(matches!(
            store.register_product_resource_model(&invalid),
            Err(RepositoryError::Conflict(_))
        ));
        assert_eq!(FenceStore::fence(&store).unwrap().version, 2);
    }

    #[test]
    fn create_replay_retire_and_stale_replay_are_fenced_in_sqlite() {
        let store = setup();
        let create = create_batch();
        let first = store.apply_resource_projection(&create).unwrap();
        assert_eq!(first.disposition, ResourceProjectionDisposition::Applied);
        assert_eq!(first.version, 2);
        let replay = store.apply_resource_projection(&create).unwrap();
        assert_eq!(replay.disposition, ResourceProjectionDisposition::Replayed);
        assert_eq!(replay.version, 2);
        let mut changed_same_epoch = create.clone();
        changed_same_epoch.grants[0].action_pattern = "tutor.campus.read".into();
        assert!(matches!(
            store.apply_resource_projection(&changed_same_epoch),
            Err(RepositoryError::Conflict(_))
        ));

        let mut retire = create.clone();
        retire.epoch = 2;
        retire.idempotency_key = "campus:campus-1:2".into();
        retire.grants.clear();
        retire.scope_edges.clear();
        retire.retirements = vec![ResourceRetirement {
            resource_type: ResourceType("tutor.campus".into()),
            resource_id: ResourceId("campus-1".into()),
            grant_ids: vec!["campus-1-creator-manage".into()],
        }];
        let retired = store.apply_resource_projection(&retire).unwrap();
        assert_eq!(retired.disposition, ResourceProjectionDisposition::Applied);
        assert_eq!(retired.version, 3);
        assert!(GrantRepository::list(&store).unwrap().is_empty());
        assert!(
            ResourceModelRepository::list_edges(&store)
                .unwrap()
                .is_empty()
        );
        assert_eq!(
            ResourceModelRepository::list_retired_resources(&store).unwrap(),
            vec![awaken_iam_contract::RetiredResource {
                resource_type: ResourceType("tutor.campus".into()),
                resource_id: ResourceId("campus-1".into()),
            }]
        );
        let stale = store.apply_resource_projection(&create).unwrap();
        assert_eq!(stale.disposition, ResourceProjectionDisposition::Stale);
        assert_eq!(stale.version, 3);
        let mut resurrection = create;
        resurrection.epoch = 3;
        resurrection.idempotency_key = "campus:campus-1:3".into();
        assert!(matches!(
            store.apply_resource_projection(&resurrection),
            Err(RepositoryError::Conflict(_))
        ));
        assert_eq!(FenceStore::fence(&store).unwrap().version, 3);
    }

    #[test]
    fn another_projection_cannot_replace_owned_grant_or_resource() {
        let store = setup();
        let first = create_batch();
        store.apply_resource_projection(&first).unwrap();
        let grant = GrantRepository::get(&store, &GrantId(first.grants[0].id.clone()))
            .unwrap()
            .unwrap();
        assert!(matches!(
            GrantRepository::put(&store, grant),
            Err(RepositoryError::Conflict(_))
        ));
        let edge = ResourceModelRepository::list_edges(&store)
            .unwrap()
            .remove(0);
        assert!(matches!(
            ResourceModelRepository::put_edge(&store, edge),
            Err(RepositoryError::Conflict(_))
        ));
        let mut other = first.clone();
        other.projection_id = "campus:campus-2".into();
        other.idempotency_key = "campus:campus-2:1".into();
        assert!(matches!(
            store.apply_resource_projection(&other),
            Err(RepositoryError::Conflict(_))
        ));
        assert_eq!(FenceStore::fence(&store).unwrap().version, 2);
    }
}
