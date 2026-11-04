//! Authorization-profile persistence for this backend.

use super::*;

impl<B: SqlConn> AuthorizationProfileRepository for SqlStore<B> {
    fn profile_publication_workspace(
        &self,
        namespace: &NamespaceId,
    ) -> RepositoryResult<Option<WorkspaceId>> {
        let rows = self.backend.query(
            &format!(
                "SELECT workspace_id FROM {} WHERE namespace=? LIMIT 1",
                self.table("authorization_profile_publications")
            ),
            &[p(namespace.0.clone())],
        )?;
        rows.first()
            .map(|row| req(row, 0, "profile Workspace owner").map(WorkspaceId))
            .transpose()
    }
    fn prepare_profile_publication(
        &self,
        request: awaken_iam_contract::PrepareScopedAuthorizationProfile,
        publisher: PrincipalRef,
        request_digest: String,
        checksum: String,
    ) -> RepositoryResult<awaken_iam_contract::ScopedAuthorizationProfileIntent> {
        use awaken_iam_contract::ScopedAuthorizationProfileIntent;
        let publications = self.table("authorization_profile_publications");
        let profiles = self.table("authorization_profiles");
        let heads = self.table("authorization_profile_heads");
        let namespace = request.profile.namespace.0.clone();
        let mut result = None;
        self.backend.with_transaction(&mut |tx| {
            // Reuse the native policy serialization row. Draft preparation
            // acquires its lock but does not change the active policy version.
            if tx.execute(&format!("UPDATE {} SET version=version WHERE id=1",self.table("fence")), &[])? != 1 {
                return Err(RepositoryError::Backend("profile publication fence is unavailable".into()));
            }
            let original = tx.query(&format!("SELECT CAST(descriptor AS TEXT) FROM {publications} WHERE namespace=? AND request_key=?"),
                &[p(namespace.clone()),p(request.request_key.clone())])?;
            if let Some(row) = original.first() {
                let original: ScopedAuthorizationProfileIntent = serde_json::from_str(&req(row,0,"profile publication intent")?)
                    .map_err(|error| RepositoryError::Backend(error.to_string()))?;
                if original.request_digest != request_digest || original.publisher != publisher || original.workspace_id != request.workspace_id
                    || original.namespace.0 != namespace || original.request_key != request.request_key {
                    return Err(RepositoryError::Conflict("original profile publication has different content".into()));
                }
                result=Some(original);return Ok(());
            }
            self.ensure_scope_admission(tx, &[ScopeRef::Workspace {workspace_id: request.workspace_id.clone()}], &[])?;
            let owner = tx.query(&format!("SELECT workspace_id FROM {publications} WHERE namespace=? LIMIT 1"), &[p(namespace.clone())])?;
            if owner.first().is_some_and(|row| row.first().and_then(Option::as_deref) != Some(request.workspace_id.0.as_str())) {
                return Err(RepositoryError::Conflict("profile namespace belongs to another Workspace".into()));
            }
            let head = tx.query(&format!("SELECT active_revision FROM {heads} WHERE namespace=?"), &[p(namespace.clone())])?;
            let active = head.first().map(|row|req(row,0,"active profile revision").and_then(|value|parse_revision(&value))).transpose()?;
            if active != request.expected_active_revision {
                return Err(RepositoryError::Conflict("active profile revision changed".into()));
            }
            if active.is_none() && !tx.query(&format!("SELECT namespace FROM {profiles} WHERE namespace=? AND lifecycle IN ('active','retired') LIMIT 1"), &[p(namespace.clone())])?.is_empty() {
                return Err(RepositoryError::Conflict("retired namespace requires explicit administrative recovery".into()));
            }
            let rows = tx.query(&format!("SELECT MAX(revision) FROM {profiles} WHERE namespace=?"), &[p(namespace.clone())])?;
            let previous = rows.first().and_then(|row|row.first()).and_then(Option::as_deref).map(parse_revision).transpose()?.unwrap_or(0);
            let revision = previous.checked_add(1).ok_or_else(|| RepositoryError::Backend("profile revision exhausted".into()))?;
            let intent = ScopedAuthorizationProfileIntent {
                namespace:request.profile.namespace.clone(),workspace_id:request.workspace_id.clone(),request_key:request.request_key.clone(),
                request_digest:request_digest.clone(),publisher:publisher.clone(),revision,checksum:checksum.clone(),
                expected_active_revision:request.expected_active_revision,created_at:request.profile.created_at.clone(),
            };
            tx.execute(&format!("INSERT INTO {profiles} (namespace,revision,lifecycle,document,checksum,created_at) VALUES (?,?,'validated',?j,?,?)"),
                &[p(namespace.clone()),p(revision_key(revision)),p(json_encode(&request.profile.document,"profile document")?),p(checksum.clone()),p(request.profile.created_at.0.clone())])?;
            tx.execute(&format!("INSERT INTO {publications} (namespace,request_key,workspace_id,descriptor) VALUES (?,?,?,?j)"),
                &[p(namespace.clone()),p(request.request_key.clone()),p(request.workspace_id.0.clone()),p(json_encode(&intent,"profile publication intent")?)])?;
            result=Some(intent);Ok(())
        })?;
        result.ok_or_else(|| {
            RepositoryError::Backend("profile publication returned no intent".into())
        })
    }

    fn profile_publication(
        &self,
        namespace: &NamespaceId,
        request_key: &str,
    ) -> RepositoryResult<Option<awaken_iam_contract::ScopedAuthorizationProfileIntent>> {
        let rows = self.backend.query(
            &format!(
                "SELECT CAST(descriptor AS TEXT) FROM {} WHERE namespace=? AND request_key=?",
                self.table("authorization_profile_publications")
            ),
            &[p(namespace.0.clone()), p(request_key.to_owned())],
        )?;
        rows.first()
            .map(|row| {
                let intent: awaken_iam_contract::ScopedAuthorizationProfileIntent =
                    serde_json::from_str(&req(row, 0, "profile publication intent")?)
                        .map_err(|error| RepositoryError::Backend(error.to_string()))?;
                if intent.namespace != *namespace || intent.request_key != request_key {
                    return Err(RepositoryError::Backend(
                        "profile publication identity mismatch".into(),
                    ));
                }
                Ok(intent)
            })
            .transpose()
    }
    fn create_profile(&self, profile: AuthorizationProfile) -> RepositoryResult<()> {
        let document = json_encode(&profile.document, "authorization profile document")?;
        let sql = format!(
            "INSERT INTO {} (namespace, revision, lifecycle, document, checksum, created_at) \
             VALUES (?, ?, ?, ?j, ?, ?)",
            self.table("authorization_profiles")
        );
        self.backend.execute(
            &sql,
            &[
                p(profile.namespace.0),
                p(revision_key(profile.revision)),
                p(lifecycle_name(profile.lifecycle)),
                p(document),
                p(profile.checksum),
                p(profile.created_at.0),
            ],
        )?;
        Ok(())
    }

    fn get_profile(
        &self,
        namespace: &NamespaceId,
        revision: u64,
    ) -> RepositoryResult<Option<AuthorizationProfile>> {
        let sql = format!(
            "SELECT namespace, revision, lifecycle, CAST(document AS TEXT), checksum, created_at \
             FROM {} WHERE namespace = ? AND revision = ?",
            self.table("authorization_profiles")
        );
        let rows = self
            .backend
            .query(&sql, &[p(namespace.0.clone()), p(revision_key(revision))])?;
        let mut profile = rows.first().map(decode_profile).transpose()?;
        if let Some(profile) = &mut profile
            && self.active_revision(namespace)? == Some(revision)
        {
            profile.lifecycle = ProfileLifecycle::Active;
        }
        Ok(profile)
    }

    fn list_profiles(
        &self,
        namespace: &NamespaceId,
    ) -> RepositoryResult<Vec<AuthorizationProfile>> {
        let sql = format!(
            "SELECT namespace, revision, lifecycle, CAST(document AS TEXT), checksum, created_at \
             FROM {} WHERE namespace = ? ORDER BY revision",
            self.table("authorization_profiles")
        );
        let active = self.active_revision(namespace)?;
        self.backend
            .query(&sql, &[p(namespace.0.clone())])?
            .iter()
            .map(|row| {
                let mut profile = decode_profile(row)?;
                if active == Some(profile.revision) {
                    profile.lifecycle = ProfileLifecycle::Active;
                }
                Ok(profile)
            })
            .collect()
    }

    fn set_profile_lifecycle(
        &self,
        namespace: &NamespaceId,
        revision: u64,
        lifecycle: ProfileLifecycle,
    ) -> RepositoryResult<()> {
        let sql = format!(
            "UPDATE {} SET lifecycle = ? WHERE namespace = ? AND revision = ?",
            self.table("authorization_profiles")
        );
        let affected = self.backend.execute(
            &sql,
            &[
                p(lifecycle_name(lifecycle)),
                p(namespace.0.clone()),
                p(revision_key(revision)),
            ],
        )?;
        if affected == 0 {
            return Err(RepositoryError::NotFound(
                "profile revision not found".into(),
            ));
        }
        Ok(())
    }

    fn activate_profile(
        &self,
        namespace: &NamespaceId,
        revision: u64,
        expected_active_revision: Option<u64>,
    ) -> RepositoryResult<(Option<u64>, u64)> {
        self.activate_profile_head(namespace, revision, expected_active_revision, false)
    }
    fn activate_scoped_profile(
        &self,
        namespace: &NamespaceId,
        revision: u64,
        expected_active_revision: Option<u64>,
    ) -> RepositoryResult<(Option<u64>, u64)> {
        self.activate_profile_head(namespace, revision, expected_active_revision, true)
    }

    fn retire_active_profile(
        &self,
        namespace: &NamespaceId,
        expected_active_revision: u64,
    ) -> RepositoryResult<(AuthorizationProfile, u64)> {
        let mut profile = self
            .get_profile(namespace, expected_active_revision)?
            .ok_or_else(|| RepositoryError::NotFound("profile revision not found".into()))?;
        let previous_version = FenceStore::fence(self)?.version;
        let policy_version = previous_version
            .checked_add(1)
            .ok_or_else(|| RepositoryError::Backend("IAM policy version exhausted".into()))?;
        let profiles = self.table("authorization_profiles");
        let heads = self.table("authorization_profile_heads");
        self.backend.execute_transaction_checked(&[
            SqlWrite {
                sql: format!(
                    "UPDATE {profiles} SET lifecycle = 'retired' \
                     WHERE namespace = ? AND revision = ? \
                       AND EXISTS (SELECT 1 FROM {heads} \
                                   WHERE namespace = ? AND active_revision = ?)"
                ),
                params: vec![
                    p(namespace.0.clone()),
                    p(revision_key(expected_active_revision)),
                    p(namespace.0.clone()),
                    p(revision_key(expected_active_revision)),
                ],
            },
            SqlWrite {
                sql: format!(
                    "DELETE FROM {heads} WHERE namespace = ? AND active_revision = ? \
                     AND EXISTS (SELECT 1 FROM {profiles} \
                                 WHERE namespace = ? AND revision = ? AND lifecycle = 'retired')"
                ),
                params: vec![
                    p(namespace.0.clone()),
                    p(revision_key(expected_active_revision)),
                    p(namespace.0.clone()),
                    p(revision_key(expected_active_revision)),
                ],
            },
            SqlWrite {
                sql: format!(
                    "UPDATE {} SET version = version + 1 WHERE id = 1 AND CAST(version AS TEXT) = ?",
                    self.table("fence")
                ),
                params: vec![p(previous_version.to_string())],
            },
        ], &[(0, 1), (1, 1), (2, 1)])?;
        profile.lifecycle = ProfileLifecycle::Retired;
        Ok((profile, policy_version))
    }

    fn active_profile(
        &self,
        namespace: &NamespaceId,
    ) -> RepositoryResult<Option<AuthorizationProfile>> {
        let Some(revision) = self.active_revision(namespace)? else {
            return Ok(None);
        };
        self.get_profile(namespace, revision)
    }

    fn active_profiles(&self) -> RepositoryResult<Vec<AuthorizationProfile>> {
        let sql = format!(
            "SELECT p.namespace, p.revision, p.lifecycle, CAST(p.document AS TEXT), \
                    p.checksum, p.created_at \
             FROM {profiles} p JOIN {heads} h \
               ON p.namespace = h.namespace AND p.revision = h.active_revision \
             ORDER BY p.namespace",
            profiles = self.table("authorization_profiles"),
            heads = self.table("authorization_profile_heads")
        );
        self.backend
            .query(&sql, &[])?
            .iter()
            .map(|row| {
                let mut profile = decode_profile(row)?;
                profile.lifecycle = ProfileLifecycle::Active;
                Ok(profile)
            })
            .collect()
    }
}

impl<B: SqlConn> SqlStore<B> {
    fn activate_profile_head(
        &self,
        namespace: &NamespaceId,
        revision: u64,
        expected_active_revision: Option<u64>,
        reject_retired_initial: bool,
    ) -> RepositoryResult<(Option<u64>, u64)> {
        let target = self
            .get_profile(namespace, revision)?
            .ok_or_else(|| RepositoryError::NotFound("profile revision not found".into()))?;
        if target.lifecycle == ProfileLifecycle::Draft {
            return Err(RepositoryError::Conflict(
                "profile revision is not validated".into(),
            ));
        }
        let previous = self.active_revision(namespace)?;
        if previous != expected_active_revision {
            return Err(RepositoryError::Conflict(
                "active profile revision changed".into(),
            ));
        }
        let previous_version = FenceStore::fence(self)?.version;
        if reject_retired_initial {
            let workspace = self
                .profile_publication_workspace(namespace)?
                .ok_or_else(|| {
                    RepositoryError::NotFound("scoped publication intent is unavailable".into())
                })?;
            // Read after the version marker. Any concurrent privacy admission
            // advances that same fence, so the final native CAS rolls back.
            self.backend.with_transaction(&mut |tx| {
                self.ensure_scope_admission(
                    tx,
                    &[ScopeRef::Workspace {
                        workspace_id: workspace.clone(),
                    }],
                    &[],
                )
            })?;
        }
        let policy_version = previous_version
            .checked_add(1)
            .ok_or_else(|| RepositoryError::Backend("IAM policy version exhausted".into()))?;
        let head_write = match expected_active_revision {
            None => {
                let mut params = vec![p(namespace.0.clone()), p(revision_key(revision))];
                let guard = if reject_retired_initial {
                    params.push(p(namespace.0.clone()));
                    format!(
                        "WHERE NOT EXISTS (SELECT 1 FROM {} WHERE namespace=? AND lifecycle IN ('active','retired'))",
                        self.table("authorization_profiles")
                    )
                } else {
                    String::new()
                };
                SqlWrite {
                    sql: format!(
                        "INSERT INTO {} (namespace, active_revision) SELECT ?,? {guard} ON CONFLICT (namespace) DO NOTHING",
                        self.table("authorization_profile_heads")
                    ),
                    params,
                }
            }
            Some(expected) => {
                let sql = format!(
                    "UPDATE {} SET active_revision = ? \
                     WHERE namespace = ? AND active_revision = ?",
                    self.table("authorization_profile_heads")
                );
                SqlWrite {
                    sql,
                    params: vec![
                        p(revision_key(revision)),
                        p(namespace.0.clone()),
                        p(revision_key(expected)),
                    ],
                }
            }
        };
        let mut writes = vec![
            head_write,
            SqlWrite {
                sql: format!(
                    "UPDATE {} SET version = version + 1 WHERE id = 1 AND CAST(version AS TEXT) = ?",
                    self.table("fence")
                ),
                params: vec![p(previous_version.to_string())],
            },
            SqlWrite {
                sql: format!(
                    "UPDATE {} SET lifecycle = 'active' WHERE namespace = ? AND revision = ?",
                    self.table("authorization_profiles")
                ),
                params: vec![p(namespace.0.clone()), p(revision_key(revision))],
            },
        ];
        if let Some(previous) = previous.filter(|previous| *previous != revision) {
            writes.push(SqlWrite {
                sql: format!(
                    "UPDATE {} SET lifecycle = 'retired' WHERE namespace = ? AND revision = ?",
                    self.table("authorization_profiles")
                ),
                params: vec![p(namespace.0.clone()), p(revision_key(previous))],
            });
        }
        self.backend
            .execute_transaction_checked(&writes, &[(0, 1), (1, 1), (2, 1)])?;
        Ok((previous, policy_version))
    }
}
