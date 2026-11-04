//! Authorization-profile persistence for this backend.

use super::*;

impl AuthorizationProfileRepository for InMemoryStore {
    fn profile_publication_workspace(
        &self,
        namespace: &NamespaceId,
    ) -> RepositoryResult<Option<WorkspaceId>> {
        Ok(self
            .authz
            .lock()
            .unwrap()
            .profile_publications
            .values()
            .find(|intent| intent.namespace == *namespace)
            .map(|intent| intent.workspace_id.clone()))
    }
    fn prepare_profile_publication(
        &self,
        request: awaken_iam_contract::PrepareScopedAuthorizationProfile,
        publisher: PrincipalRef,
        request_digest: String,
        checksum: String,
    ) -> RepositoryResult<awaken_iam_contract::ScopedAuthorizationProfileIntent> {
        use awaken_iam_contract::ScopedAuthorizationProfileIntent;
        let mut authz = self.authz.lock().unwrap();
        let namespace = request.profile.namespace.clone();
        let key = (namespace.0.clone(), request.request_key.clone());
        if let Some(original) = authz.profile_publications.get(&key) {
            if original.request_digest != request_digest
                || original.publisher != publisher
                || original.workspace_id != request.workspace_id
            {
                return Err(RepositoryError::Conflict(
                    "original profile publication has different content".into(),
                ));
            }
            return Ok(original.clone());
        }
        if authz.profile_publications.values().any(|intent| {
            intent.namespace == namespace && intent.workspace_id != request.workspace_id
        }) {
            return Err(RepositoryError::Conflict(
                "profile namespace belongs to another Workspace".into(),
            ));
        }
        ensure_admitted(
            &authz,
            &[ScopeRef::Workspace {
                workspace_id: request.workspace_id.clone(),
            }],
            &[],
        )?;
        if authz.active_profiles.get(&namespace.0).copied() != request.expected_active_revision {
            return Err(RepositoryError::Conflict(
                "active profile revision changed".into(),
            ));
        }
        if request.expected_active_revision.is_none()
            && authz.profiles.values().any(|profile| {
                profile.namespace == namespace
                    && matches!(
                        profile.lifecycle,
                        ProfileLifecycle::Active | ProfileLifecycle::Retired
                    )
            })
        {
            return Err(RepositoryError::Conflict(
                "retired namespace requires explicit administrative recovery".into(),
            ));
        }
        let revision = authz
            .profiles
            .keys()
            .filter(|(owner, _)| owner == &namespace.0)
            .map(|(_, revision)| *revision)
            .max()
            .unwrap_or(0)
            .checked_add(1)
            .ok_or_else(|| RepositoryError::Backend("profile revision exhausted".into()))?;
        let intent = ScopedAuthorizationProfileIntent {
            namespace: namespace.clone(),
            workspace_id: request.workspace_id,
            request_key: request.request_key,
            request_digest,
            publisher,
            revision,
            checksum: checksum.clone(),
            expected_active_revision: request.expected_active_revision,
            created_at: request.profile.created_at.clone(),
        };
        authz.profiles.insert(
            (namespace.0.clone(), revision),
            AuthorizationProfile {
                namespace,
                revision,
                lifecycle: ProfileLifecycle::Validated,
                document: request.profile.document,
                checksum,
                created_at: request.profile.created_at,
            },
        );
        authz.profile_publications.insert(key, intent.clone());
        Ok(intent)
    }

    fn profile_publication(
        &self,
        namespace: &NamespaceId,
        request_key: &str,
    ) -> RepositoryResult<Option<awaken_iam_contract::ScopedAuthorizationProfileIntent>> {
        Ok(self
            .authz
            .lock()
            .unwrap()
            .profile_publications
            .get(&(namespace.0.clone(), request_key.into()))
            .cloned())
    }
    fn create_profile(&self, profile: AuthorizationProfile) -> RepositoryResult<()> {
        let key = (profile.namespace.0.clone(), profile.revision);
        let mut authz = self.authz.lock().unwrap();
        if authz.profiles.contains_key(&key) {
            return Err(RepositoryError::Conflict(
                "profile revision already exists".into(),
            ));
        }
        authz.profiles.insert(key, profile);
        Ok(())
    }

    fn get_profile(
        &self,
        namespace: &NamespaceId,
        revision: u64,
    ) -> RepositoryResult<Option<AuthorizationProfile>> {
        let authz = self.authz.lock().unwrap();
        let mut profile = authz
            .profiles
            .get(&(namespace.0.clone(), revision))
            .cloned();
        if authz.active_profiles.get(&namespace.0) == Some(&revision)
            && let Some(profile) = &mut profile
        {
            profile.lifecycle = ProfileLifecycle::Active;
        }
        Ok(profile)
    }

    fn list_profiles(
        &self,
        namespace: &NamespaceId,
    ) -> RepositoryResult<Vec<AuthorizationProfile>> {
        let authz = self.authz.lock().unwrap();
        let active = authz.active_profiles.get(&namespace.0).copied();
        Ok(authz
            .profiles
            .iter()
            .filter(|((owner, _), _)| owner == &namespace.0)
            .map(|((_, revision), profile)| {
                let mut profile = profile.clone();
                if active == Some(*revision) {
                    profile.lifecycle = ProfileLifecycle::Active;
                }
                profile
            })
            .collect())
    }

    fn set_profile_lifecycle(
        &self,
        namespace: &NamespaceId,
        revision: u64,
        lifecycle: ProfileLifecycle,
    ) -> RepositoryResult<()> {
        let mut authz = self.authz.lock().unwrap();
        let profile = authz
            .profiles
            .get_mut(&(namespace.0.clone(), revision))
            .ok_or_else(|| RepositoryError::NotFound("profile revision not found".into()))?;
        profile.lifecycle = lifecycle;
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
        let mut authz = self.authz.lock().unwrap();
        let Some(active_revision) = authz.active_profiles.get(&namespace.0).copied() else {
            return Err(RepositoryError::NotFound(
                "active profile head not found".into(),
            ));
        };
        if active_revision != expected_active_revision {
            return Err(RepositoryError::Conflict(
                "active profile revision changed".into(),
            ));
        }
        if !authz
            .profiles
            .contains_key(&(namespace.0.clone(), active_revision))
        {
            return Err(RepositoryError::Backend(
                "active profile head is dangling".into(),
            ));
        }
        authz.active_profiles.remove(&namespace.0);
        let profile = authz
            .profiles
            .get_mut(&(namespace.0.clone(), active_revision))
            .expect("profile existence checked while holding the same lock");
        profile.lifecycle = ProfileLifecycle::Retired;
        let retired = profile.clone();
        let mut fence = self.fence.lock().unwrap();
        fence.version += 1;
        Ok((retired, fence.version))
    }

    fn active_profile(
        &self,
        namespace: &NamespaceId,
    ) -> RepositoryResult<Option<AuthorizationProfile>> {
        let authz = self.authz.lock().unwrap();
        let Some(revision) = authz.active_profiles.get(&namespace.0) else {
            return Ok(None);
        };
        let mut profile = authz
            .profiles
            .get(&(namespace.0.clone(), *revision))
            .cloned()
            .ok_or_else(|| RepositoryError::Backend("active profile head is dangling".into()))?;
        profile.lifecycle = ProfileLifecycle::Active;
        Ok(Some(profile))
    }

    fn active_profiles(&self) -> RepositoryResult<Vec<AuthorizationProfile>> {
        let authz = self.authz.lock().unwrap();
        authz
            .active_profiles
            .iter()
            .map(|(namespace, revision)| {
                let mut profile = authz
                    .profiles
                    .get(&(namespace.clone(), *revision))
                    .cloned()
                    .ok_or_else(|| {
                        RepositoryError::Backend("active profile head is dangling".into())
                    })?;
                profile.lifecycle = ProfileLifecycle::Active;
                Ok(profile)
            })
            .collect()
    }
}

impl InMemoryStore {
    fn activate_profile_head(
        &self,
        namespace: &NamespaceId,
        revision: u64,
        expected_active_revision: Option<u64>,
        reject_retired_initial: bool,
    ) -> RepositoryResult<(Option<u64>, u64)> {
        let mut authz = self.authz.lock().unwrap();
        let target = authz
            .profiles
            .get(&(namespace.0.clone(), revision))
            .ok_or_else(|| RepositoryError::NotFound("profile revision not found".into()))?;
        if target.lifecycle == ProfileLifecycle::Draft {
            return Err(RepositoryError::Conflict(
                "profile revision is not validated".into(),
            ));
        }
        if reject_retired_initial {
            let workspace = authz
                .profile_publications
                .values()
                .find(|intent| intent.namespace == *namespace && intent.revision == revision)
                .map(|intent| intent.workspace_id.clone())
                .ok_or_else(|| {
                    RepositoryError::NotFound("scoped publication intent is unavailable".into())
                })?;
            ensure_admitted(
                &authz,
                &[ScopeRef::Workspace {
                    workspace_id: workspace,
                }],
                &[],
            )?;
        }
        let previous = authz.active_profiles.get(&namespace.0).copied();
        if previous != expected_active_revision {
            return Err(RepositoryError::Conflict(
                "active profile revision changed".into(),
            ));
        }
        if reject_retired_initial
            && previous.is_none()
            && authz.profiles.values().any(|profile| {
                profile.namespace == *namespace
                    && matches!(
                        profile.lifecycle,
                        ProfileLifecycle::Active | ProfileLifecycle::Retired
                    )
            })
        {
            return Err(RepositoryError::Conflict(
                "retired namespace is not initial absence".into(),
            ));
        }
        if let Some(previous) = previous
            && previous != revision
            && let Some(profile) = authz.profiles.get_mut(&(namespace.0.clone(), previous))
        {
            profile.lifecycle = ProfileLifecycle::Retired;
        }
        authz.active_profiles.insert(namespace.0.clone(), revision);
        let mut fence = self.fence.lock().unwrap();
        fence.version += 1;
        Ok((previous, fence.version))
    }
}
