//! The same physical projection owner, edge, stream and retirement records.
use super::*;
use crate::store::ResourceProjectionObservation;

impl<B: SqlConn> SqlStore<B> {
    pub(super) fn registered_resource_action(
        &self,
        product: &ProductId,
        resource_type: &ResourceType,
        action: &awaken_iam_contract::ActionKey,
    ) -> RepositoryResult<bool> {
        let rows=self.backend.query(&format!(
            "SELECT CAST(t.actions AS TEXT) FROM {types} t WHERE t.product_id=? AND t.resource_type=? \
             AND EXISTS (SELECT 1 FROM {actions} a WHERE a.product_id=t.product_id AND a.action_key=?)",
            types=self.table("product_resource_types"),actions=self.table("product_actions")),
            &[p(product.as_str()),p(&resource_type.0),p(&action.0)])?;
        let Some(row) = rows.first() else {
            return Ok(false);
        };
        let declared: Vec<awaken_iam_contract::ActionKey> =
            json_decode(&req(row, 0, "product actions")?, "product actions")?;
        Ok(declared.contains(action))
    }

    pub(super) fn ensure_profile_resource_product(
        &self,
        tx: &mut dyn SqlTransaction,
        namespace: &NamespaceId,
        proposed: Option<&ProductId>,
    ) -> RepositoryResult<()> {
        let rows = tx.query(
            &format!(
                "SELECT CAST(document AS TEXT) FROM {} WHERE namespace=?",
                self.table("authorization_profiles")
            ),
            &[p(&namespace.0)],
        )?;
        let documents = rows
            .iter()
            .map(|row| {
                json_decode::<AuthorizationProfileDocument>(
                    &req(row, 0, "profile history")?,
                    "profile history",
                )
            })
            .collect::<RepositoryResult<Vec<_>>>()?;
        crate::profile_resource_product::ensure_owner(&documents, proposed)
    }

    pub(super) fn registered_resource_projection(
        &self,
        resource_type: &ResourceType,
        resource_id: &ResourceId,
    ) -> RepositoryResult<Option<ResourceProjectionObservation>> {
        let rows = self.backend.query(&format!(
            "SELECT o.product_id,o.org_id,o.projection_id,CAST(s.epoch AS TEXT),CAST(e.parent AS TEXT) \
             FROM {owners} o JOIN {streams} s ON o.product_id=s.product_id \
             AND o.org_id=s.org_id AND o.projection_id=s.projection_id \
             JOIN {edges} e ON o.resource_type=e.resource_type AND o.resource_id=e.resource_id \
             WHERE o.resource_type=? AND o.resource_id=? \
             AND NOT EXISTS (SELECT 1 FROM {retired} r WHERE r.resource_type=o.resource_type \
             AND r.resource_id=o.resource_id)",
            owners=self.table("resource_projection_edge_owners"),
            streams=self.table("resource_projection_streams"),
            edges=self.table("resource_edges"),
            retired=self.table("resource_projection_tombstones")),
            &[p(&resource_type.0),p(&resource_id.0)])?;
        let Some(row) = rows.first() else {
            return Ok(None);
        };
        if rows.len() != 1 {
            return Err(RepositoryError::Backend(
                "ambiguous resource ownership".into(),
            ));
        }
        Ok(Some(ResourceProjectionObservation {
            product_id: ProductId::new(req(row, 0, "resource product")?)
                .map_err(|_| RepositoryError::Backend("invalid resource product".into()))?,
            org_id: OrgId(req(row, 1, "resource organization")?),
            projection_id: req(row, 2, "resource projection")?,
            epoch: req(row, 3, "resource projection epoch")?
                .parse()
                .map_err(|_| {
                    RepositoryError::Backend("invalid resource projection epoch".into())
                })?,
            parent: json_decode(&req(row, 4, "resource parent")?, "resource parent")?,
        }))
    }
}
