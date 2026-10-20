//! Authorization-profile persistence for this backend.

use super::*;

impl AuthorizationProfileRepository for InMemoryStore {
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
        let previous = authz.active_profiles.get(&namespace.0).copied();
        if previous != expected_active_revision {
            return Err(RepositoryError::Conflict(
                "active profile revision changed".into(),
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
