//! Authorization-profile persistence for this backend.

use super::*;

impl<B: SqlConn> AuthorizationProfileRepository for SqlStore<B> {
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
        let policy_version = previous_version
            .checked_add(1)
            .ok_or_else(|| RepositoryError::Backend("IAM policy version exhausted".into()))?;
        let head_write = match expected_active_revision {
            None => {
                let sql = format!(
                    "INSERT INTO {} (namespace, active_revision) VALUES (?, ?) \
                     ON CONFLICT (namespace) DO NOTHING",
                    self.table("authorization_profile_heads")
                );
                SqlWrite {
                    sql,
                    params: vec![p(namespace.0.clone()), p(revision_key(revision))],
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
        self.backend.execute_transaction_checked(
            &[
                head_write,
                SqlWrite {
                    sql: format!(
                        "UPDATE {} SET version = version + 1 WHERE id = 1 AND CAST(version AS TEXT) = ?",
                        self.table("fence")
                    ),
                    params: vec![p(previous_version.to_string())],
                },
            ],
            &[(0, 1), (1, 1)],
        )?;
        Ok((previous, policy_version))
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
