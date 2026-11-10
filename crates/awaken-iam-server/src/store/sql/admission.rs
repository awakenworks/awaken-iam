//! Scoped mutations reuse the original SQL transaction and policy fence.
//! No cache, registry or second lifecycle; every fact is borrowed from this tx.
use super::*;
use awaken_iam_contract::ScopeRef;

impl<B: SqlConn> SqlStore<B> {
    /// A native authorization-source write and its observation epoch publish
    /// under the same original transaction/commit ACK. PAP event versions are
    /// still owned by their existing application commands.
    pub(super) fn with_authorization_change<T: Send>(
        &self,
        operation: impl FnOnce(&mut dyn SqlTransaction) -> RepositoryResult<T> + Send,
    ) -> RepositoryResult<T> {
        self.with_policy_transaction(|transaction, _| {
            let value = operation(transaction)?;
            self.advance_authorization_epoch(transaction)?;
            Ok(value)
        })
    }

    pub(super) fn advance_authorization_epoch(
        &self,
        transaction: &mut dyn SqlTransaction,
    ) -> RepositoryResult<()> {
        let rows = transaction.query(
                &format!(
                    "UPDATE {} SET epoch=epoch+1 WHERE id=1 AND epoch>=0 AND epoch<9223372036854775807 RETURNING CAST(epoch AS TEXT)",
                    self.table("fence")
                ),
                &[],
            )?;
        parse_fence_value(rows.first().and_then(|row| row.first()), "epoch")?;
        Ok(())
    }

    pub(super) fn lock_policy(
        &self,
        transaction: &mut dyn SqlTransaction,
    ) -> RepositoryResult<u64> {
        if transaction.execute(
            &format!(
                "UPDATE {} SET version=version WHERE id=1",
                self.table("fence")
            ),
            &[],
        )? != 1
        {
            return Err(RepositoryError::Backend(
                "IAM freshness fence is missing".into(),
            ));
        }
        let rows = transaction.query(
            &format!(
                "SELECT CAST(version AS TEXT) FROM {} WHERE id=1",
                self.table("fence")
            ),
            &[],
        )?;
        parse_fence_value(rows.first().and_then(|row| row.first()), "version")
    }

    pub(super) fn with_policy_transaction<T: Send>(
        &self,
        operation: impl FnOnce(&mut dyn SqlTransaction, u64) -> RepositoryResult<T> + Send,
    ) -> RepositoryResult<T> {
        let mut operation = Some(operation);
        let mut result = None;
        self.backend.with_transaction(&mut |transaction| {
            let version = self.lock_policy(transaction)?;
            let operation = operation.take().ok_or_else(|| {
                RepositoryError::Backend("policy callback invoked more than once".into())
            })?;
            result = Some(operation(transaction, version)?);
            Ok(())
        })?;
        // A captured value is not publishable before the ORIGINAL commit ACK.
        result.ok_or_else(|| {
            RepositoryError::Backend("policy callback did not return a result".into())
        })
    }

    pub(super) fn ensure_scope_admission(
        &self,
        transaction: &mut dyn SqlTransaction,
        scopes: &[ScopeRef],
        groups: &[String],
    ) -> RepositoryResult<()> {
        let mut scopes = scopes.to_vec();
        for group in groups {
            for row in transaction.query(
                &format!("SELECT org_id FROM {} WHERE id=?", self.table("groups")),
                &[p(group)],
            )? {
                scopes.push(ScopeRef::Org {
                    org_id: OrgId(req(&row, 0, "group organization")?),
                });
            }
        }
        for scope in scopes.clone() {
            if let ScopeRef::Resource {
                resource_type,
                resource_id,
            } = scope
            {
                // Existing ownership/tombstones remain canonical. The terminal
                // Org row retains ONLY legacy keys not represented here.
                for row in [
                    self.resource_projection_owner(
                        transaction,
                        (&resource_type.0, &resource_id.0),
                    )?,
                    self.resource_tombstone(transaction, (&resource_type.0, &resource_id.0))?,
                ]
                .into_iter()
                .flatten()
                {
                    scopes.push(ScopeRef::Org {
                        org_id: OrgId(req(&row, 1, "resource organization")?),
                    });
                }
            }
        }
        let rows = transaction.query(&format!("SELECT CAST(erasure_version AS TEXT),CAST(erasure_confirmed AS TEXT),CAST(erased_scope AS TEXT),CAST(erased_groups AS TEXT),id FROM {} WHERE erasure_version IS NOT NULL ORDER BY id", self.table("orgs")), &[])?;
        for row in rows {
            let terminal =
                privacy::decode_terminal(&row, &OrgId(req(&row, 4, "terminal organization")?))?
                    .ok_or_else(|| {
                        RepositoryError::Backend("terminal organization receipt is missing".into())
                    })?;
            terminal.ensure_admitted(&scopes, groups)?;
        }
        Ok(())
    }

    pub(super) fn edge_admission(
        &self,
        transaction: &mut dyn SqlTransaction,
        edge: &ResourceEdge,
    ) -> RepositoryResult<()> {
        let mut scopes = vec![
            edge.parent.clone(),
            ScopeRef::Resource {
                resource_type: edge.resource_type.clone(),
                resource_id: edge.resource_id.clone(),
            },
        ];
        let edges = self.read_edges_with(|sql, params| transaction.query(sql, params))?;
        if let Some(previous) = edges.iter().find(|old| {
            old.resource_type == edge.resource_type && old.resource_id == edge.resource_id
        }) {
            scopes.push(previous.parent.clone());
        }
        self.ensure_scope_admission(transaction, &scopes, &[])
    }

    pub(super) fn invitation_admission(
        &self,
        transaction: &mut dyn SqlTransaction,
        candidate: &Invitation,
    ) -> RepositoryResult<()> {
        let mut scopes = vec![ScopeRef::Org {
            org_id: candidate.org_id.clone(),
        }];
        scopes.extend(
            candidate
                .bindings
                .iter()
                .map(|binding| binding.scope.clone()),
        );
        if let Some(previous) =
            self.read_invitation_with(&candidate.id, |sql, params| transaction.query(sql, params))?
        {
            scopes.push(ScopeRef::Org {
                org_id: previous.org_id,
            });
            scopes.extend(previous.bindings.into_iter().map(|binding| binding.scope));
        }
        self.ensure_scope_admission(transaction, &scopes, &[])
    }

    pub(super) fn grant_admission(
        &self,
        transaction: &mut dyn SqlTransaction,
        ids: &[String],
        proposed_scopes: &[ScopeRef],
        proposed_groups: &[String],
    ) -> RepositoryResult<()> {
        let mut scopes = proposed_scopes.to_vec();
        let mut groups = proposed_groups.to_vec();
        for id in ids {
            if let Some(previous) = self.read_grant_with(&GrantId(id.clone()), |sql, params| {
                transaction.query(sql, params)
            })? {
                scopes.push(previous.scope);
                if let GrantSubject::Group(group) = previous.subject {
                    groups.push(group.0);
                }
            }
            // A removed projected payload does not erase its original owner.
            // An old ID cannot be laundered with a different proposed scope.
            if let Some(row) = self.grant_projection_owner(transaction, id)? {
                scopes.push(ScopeRef::Org {
                    org_id: OrgId(req(&row, 1, "grant organization")?),
                });
            }
        }
        self.ensure_scope_admission(transaction, &scopes, &groups)
    }

    pub(super) fn provision_admission(
        &self,
        transaction: &mut dyn SqlTransaction,
        provision: &awaken_iam_contract::ResourceProvision,
    ) -> RepositoryResult<()> {
        let mut scopes = vec![ScopeRef::Org {
            org_id: provision.org_id.clone(),
        }];
        let mut groups = Vec::new();
        let mut grants = Vec::new();
        for edge in &provision.scope_edges {
            self.edge_admission(
                transaction,
                &ResourceEdge {
                    resource_type: edge.resource_type.clone(),
                    resource_id: edge.resource_id.clone(),
                    parent: edge.parent.clone(),
                },
            )?;
        }
        for grant in &provision.grants {
            grants.push(grant.id.clone());
            scopes.push(grant.scope.clone());
            if let GrantSubjectRef::Group { group_id } = &grant.subject {
                groups.push(group_id.clone());
            }
        }
        let edges = self.read_edges_with(|sql, params| transaction.query(sql, params))?;
        for retired in &provision.retirements {
            scopes.push(ScopeRef::Resource {
                resource_type: retired.resource_type.clone(),
                resource_id: retired.resource_id.clone(),
            });
            if let Some(previous) = edges.iter().find(|edge| {
                edge.resource_type == retired.resource_type
                    && edge.resource_id == retired.resource_id
            }) {
                scopes.push(previous.parent.clone());
            }
            grants.extend(retired.grant_ids.iter().cloned());
        }
        self.grant_admission(transaction, &grants, &scopes, &groups)
    }

    pub(super) fn require_unprojected_resource(
        &self,
        transaction: &mut dyn SqlTransaction,
        kind: &str,
        id: &str,
    ) -> RepositoryResult<()> {
        self.ensure_not_retired(transaction, (kind, id))?;
        if self
            .resource_projection_owner(transaction, (kind, id))?
            .is_some()
        {
            return Err(RepositoryError::Conflict(
                "resource edge belongs to a product projection".into(),
            ));
        }
        Ok(())
    }

    pub(super) fn require_raw_edge_effect(
        &self,
        transaction: &mut dyn SqlTransaction,
        edge: &ResourceEdge,
    ) -> RepositoryResult<()> {
        self.require_unprojected_resource(transaction, &edge.resource_type.0, &edge.resource_id.0)?;
        if let ScopeRef::Resource {
            resource_type,
            resource_id,
        } = &edge.parent
        {
            self.ensure_not_retired(transaction, (&resource_type.0, &resource_id.0))?;
        }
        Ok(())
    }

    pub(super) fn require_live_effect_scopes(
        &self,
        transaction: &mut dyn SqlTransaction,
        scopes: &[ScopeRef],
    ) -> RepositoryResult<()> {
        for scope in scopes {
            if let ScopeRef::Resource {
                resource_type,
                resource_id,
            } = scope
            {
                self.ensure_not_retired(transaction, (&resource_type.0, &resource_id.0))?;
            }
        }
        Ok(())
    }

    pub(super) fn require_raw_grant_effect(
        &self,
        transaction: &mut dyn SqlTransaction,
        id: &str,
        scope: &ScopeRef,
    ) -> RepositoryResult<()> {
        if self.grant_projection_owner(transaction, id)?.is_some() {
            return Err(RepositoryError::Conflict(
                "grant belongs to a product projection".into(),
            ));
        }
        self.require_live_effect_scopes(transaction, &[scope.clone()])
    }

    pub(super) fn require_raw_provision_effect(
        &self,
        transaction: &mut dyn SqlTransaction,
        provision: &awaken_iam_contract::ResourceProvision,
    ) -> RepositoryResult<()> {
        for edge in &provision.scope_edges {
            self.require_raw_edge_effect(
                transaction,
                &ResourceEdge {
                    resource_type: edge.resource_type.clone(),
                    resource_id: edge.resource_id.clone(),
                    parent: edge.parent.clone(),
                },
            )?;
        }
        for retired in &provision.retirements {
            self.require_unprojected_resource(
                transaction,
                &retired.resource_type.0,
                &retired.resource_id.0,
            )?;
            for id in &retired.grant_ids {
                if self.grant_projection_owner(transaction, id)?.is_some() {
                    return Err(RepositoryError::Conflict(
                        "grant belongs to a product projection".into(),
                    ));
                }
            }
        }
        for grant in &provision.grants {
            self.require_raw_grant_effect(transaction, &grant.id, &grant.scope)?;
        }
        Ok(())
    }
}
