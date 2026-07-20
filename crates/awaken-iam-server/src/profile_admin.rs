//! Policy Administration Point for immutable, replaceable authorization profiles.

use std::collections::HashSet;
use std::sync::Arc;

use awaken_iam_contract::{
    ActivateAuthorizationProfile, AuthorizationProfile, AuthorizationProfileActivated,
    AuthorizationProfileDocument, AuthorizationProfileValidation, CreateAuthorizationProfile,
    NamespaceId, ProfileLifecycle, ScopeKind,
};
use awaken_iam_core::{AuthorizationProfileRepo, RepoError};
use sha2::{Digest, Sha256};

use crate::AuthzApi;

/// PAP failure with stable conflict/not-found/validation distinctions.
#[derive(Debug, thiserror::Error)]
pub enum ProfileAdminError {
    #[error("profile not found")]
    NotFound,
    #[error("profile conflict: {0}")]
    Conflict(String),
    #[error("profile validation failed")]
    Validation(Vec<String>),
    #[error("profile repository failed: {0}")]
    Repository(String),
}

impl From<RepoError> for ProfileAdminError {
    fn from(error: RepoError) -> Self {
        match error {
            RepoError::NotFound(_) => Self::NotFound,
            RepoError::Conflict(message) => Self::Conflict(message),
            RepoError::Backend(message) => Self::Repository(message),
        }
    }
}

/// Application service implementing draft, validate, activate, fetch, and rollback.
#[derive(Clone)]
pub struct AuthorizationProfileAdmin {
    repository: Arc<dyn AuthorizationProfileRepo>,
}

impl std::fmt::Debug for AuthorizationProfileAdmin {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("AuthorizationProfileAdmin")
            .finish_non_exhaustive()
    }
}

impl AuthorizationProfileAdmin {
    pub fn new(repository: Arc<dyn AuthorizationProfileRepo>) -> Self {
        Self { repository }
    }

    pub fn create_draft(
        &self,
        request: CreateAuthorizationProfile,
    ) -> Result<AuthorizationProfile, ProfileAdminError> {
        if request.namespace.0.is_empty()
            || !request
                .namespace
                .0
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-'))
        {
            return Err(ProfileAdminError::Validation(vec![
                "namespace must match [A-Za-z0-9._-]+".into(),
            ]));
        }
        let revision = self
            .repository
            .list_profiles(&request.namespace)?
            .last()
            .map_or(1, |profile| profile.revision + 1);
        let profile = AuthorizationProfile {
            namespace: request.namespace,
            revision,
            lifecycle: ProfileLifecycle::Draft,
            checksum: checksum(&request.document)?,
            document: request.document,
            created_at: request.created_at,
        };
        self.repository.create_profile(profile.clone())?;
        Ok(profile)
    }

    pub fn validate(
        &self,
        namespace: &NamespaceId,
        revision: u64,
    ) -> Result<AuthorizationProfileValidation, ProfileAdminError> {
        let profile = self
            .repository
            .get_profile(namespace, revision)?
            .ok_or(ProfileAdminError::NotFound)?;
        let errors = validate_document(&profile.document);
        let valid = errors.is_empty();
        if valid {
            self.repository.set_profile_lifecycle(
                namespace,
                revision,
                ProfileLifecycle::Validated,
            )?;
        }
        Ok(AuthorizationProfileValidation {
            namespace: namespace.clone(),
            revision,
            valid,
            errors,
            checksum: profile.checksum,
        })
    }

    pub fn activate(
        &self,
        authz: &mut AuthzApi,
        namespace: &NamespaceId,
        revision: u64,
        request: ActivateAuthorizationProfile,
    ) -> Result<AuthorizationProfileActivated, ProfileAdminError> {
        let profile = self
            .repository
            .get_profile(namespace, revision)?
            .ok_or(ProfileAdminError::NotFound)?;
        if profile.lifecycle == ProfileLifecycle::Draft {
            return Err(ProfileAdminError::Conflict(
                "draft must be validated before activation".into(),
            ));
        }
        let previous = self.repository.activate_profile(
            namespace,
            revision,
            request.expected_active_revision,
        )?;
        let policy_version = authz.activate_profile(profile.clone());
        Ok(AuthorizationProfileActivated {
            namespace: namespace.clone(),
            active_revision: revision,
            previous_active_revision: previous,
            policy_version,
            checksum: profile.checksum,
        })
    }

    pub fn rollback(
        &self,
        authz: &mut AuthzApi,
        namespace: &NamespaceId,
        target_revision: u64,
        expected_active_revision: u64,
    ) -> Result<AuthorizationProfileActivated, ProfileAdminError> {
        self.activate(
            authz,
            namespace,
            target_revision,
            ActivateAuthorizationProfile {
                expected_active_revision: Some(expected_active_revision),
            },
        )
    }

    pub fn get(
        &self,
        namespace: &NamespaceId,
        revision: u64,
    ) -> Result<Option<AuthorizationProfile>, ProfileAdminError> {
        Ok(self.repository.get_profile(namespace, revision)?)
    }

    pub fn list(
        &self,
        namespace: &NamespaceId,
    ) -> Result<Vec<AuthorizationProfile>, ProfileAdminError> {
        Ok(self.repository.list_profiles(namespace)?)
    }

    pub fn active(
        &self,
        namespace: &NamespaceId,
    ) -> Result<Option<AuthorizationProfile>, ProfileAdminError> {
        Ok(self.repository.active_profile(namespace)?)
    }

    /// Restore the durable active head into a freshly started evaluator.
    pub fn hydrate(
        &self,
        authz: &mut AuthzApi,
        namespace: &NamespaceId,
    ) -> Result<Option<u64>, ProfileAdminError> {
        let Some(profile) = self.repository.active_profile(namespace)? else {
            return Ok(None);
        };
        authz.activate_profile(profile.clone());
        Ok(Some(profile.revision))
    }

    /// Restore every namespace's durable active revision at process start.
    pub fn hydrate_all(&self, authz: &mut AuthzApi) -> Result<usize, ProfileAdminError> {
        let profiles = self.repository.active_profiles()?;
        let count = profiles.len();
        if count > 0 {
            authz.activate_profiles(profiles);
        }
        Ok(count)
    }
}

fn checksum(document: &AuthorizationProfileDocument) -> Result<String, ProfileAdminError> {
    let bytes = serde_json::to_vec(document)
        .map_err(|error| ProfileAdminError::Repository(error.to_string()))?;
    Ok(format!("sha256:{:x}", Sha256::digest(bytes)))
}

fn validate_document(document: &AuthorizationProfileDocument) -> Vec<String> {
    let mut errors = Vec::new();
    let mut resource_types = HashSet::new();
    let mut declared_actions = HashSet::new();
    for resource in &document.resource_model.resource_types {
        if !resource_types.insert(resource.resource_type.clone()) {
            errors.push(format!(
                "duplicate resource type {}",
                resource.resource_type.0
            ));
        }
        declared_actions.extend(resource.actions.iter().cloned());
    }
    declared_actions.extend(document.resource_model.actions.iter().cloned());

    for resource in &document.resource_model.resource_types {
        if let Some(parent) = &resource.parent_type
            && !resource_types.contains(parent)
        {
            errors.push(format!(
                "resource type {} references unknown parent type {}",
                resource.resource_type.0, parent.0
            ));
        }
    }
    for edge in &document.resource_model.edges {
        if !resource_types.contains(&edge.resource_type) {
            errors.push(format!(
                "resource edge references unknown type {}",
                edge.resource_type.0
            ));
        }
    }

    let mut ruled_actions = HashSet::new();
    for rule in &document.action_scope_rules {
        if !ruled_actions.insert(rule.action.clone()) {
            errors.push(format!("duplicate action scope rule {}", rule.action.0));
        }
        if !declared_actions.contains(&rule.action) {
            errors.push(format!(
                "scope rule references unknown action {}",
                rule.action.0
            ));
        }
        if rule.allowed_scope_kinds.is_empty() {
            errors.push(format!(
                "action {} has no allowed scope kind",
                rule.action.0
            ));
        }
        let mut unique = HashSet::new();
        for kind in &rule.allowed_scope_kinds {
            if !unique.insert(kind.clone()) {
                errors.push(format!("action {} repeats a scope kind", rule.action.0));
            }
            if let ScopeKind::Resource { resource_type } = kind
                && !resource_types.contains(resource_type)
            {
                errors.push(format!(
                    "action {} references unknown resource type {}",
                    rule.action.0, resource_type.0
                ));
            }
        }
    }
    for action in declared_actions {
        if !ruled_actions.contains(&action) {
            errors.push(format!("action {} has no scope rule", action.0));
        }
    }
    errors.sort();
    errors
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{SqliteBackend, sqlite_migrated_store};

    fn test_dir(label: &str) -> std::path::PathBuf {
        let nonce = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let path =
            std::env::temp_dir().join(format!("awaken-iam-{label}-{}-{nonce}", std::process::id()));
        std::fs::create_dir_all(&path).unwrap();
        path
    }
    use awaken_iam_contract::{
        ActionKey, ActionScopeRule, AuthorizationDecision, AuthorizationRequest, GrantEffect,
        GrantSnapshot, GrantSubjectRef, PrincipalRef, ResourceModelRegistration, ScopeRef,
        WorkspaceId,
    };

    fn request(scope_kind: ScopeKind) -> CreateAuthorizationProfile {
        let scope = match scope_kind.clone() {
            ScopeKind::Workspace => ScopeRef::Global,
            ScopeKind::Project => ScopeRef::Global,
            _ => ScopeRef::Global,
        };
        CreateAuthorizationProfile {
            namespace: NamespaceId("awaken.runtime".into()),
            document: AuthorizationProfileDocument {
                resource_model: ResourceModelRegistration {
                    actions: vec![ActionKey("memory.read".into())],
                    ..ResourceModelRegistration::default()
                },
                action_scope_rules: vec![ActionScopeRule {
                    action: ActionKey("memory.read".into()),
                    allowed_scope_kinds: vec![scope_kind],
                }],
                grants: vec![GrantSnapshot {
                    id: "grant_memory".into(),
                    subject: GrantSubjectRef::Principal {
                        principal: PrincipalRef::Service {
                            service_id: "runtime".into(),
                        },
                    },
                    action_pattern: "memory.*".into(),
                    scope,
                    effect: GrantEffect::Allow,
                }],
                ..AuthorizationProfileDocument::default()
            },
            created_at: awaken_iam_contract::Timestamp("2026-07-20T00:00:00Z".into()),
        }
    }

    fn auth_request(scope: ScopeRef) -> AuthorizationRequest {
        AuthorizationRequest::direct(
            PrincipalRef::Service {
                service_id: "runtime".into(),
            },
            ActionKey("memory.read".into()),
            scope,
        )
    }

    #[test]
    fn activate_replace_and_rollback_enforce_scope_kind_before_grants() {
        let repository = Arc::new(crate::InMemoryStore::new());
        let pap = AuthorizationProfileAdmin::new(repository);
        let mut authz = AuthzApi::new();

        let first = pap.create_draft(request(ScopeKind::Workspace)).unwrap();
        assert!(
            pap.validate(&first.namespace, first.revision)
                .unwrap()
                .valid
        );
        pap.activate(
            &mut authz,
            &first.namespace,
            first.revision,
            ActivateAuthorizationProfile {
                expected_active_revision: None,
            },
        )
        .unwrap();
        assert_eq!(
            authz
                .authorize(&auth_request(ScopeRef::Workspace {
                    workspace_id: WorkspaceId("ws".into()),
                }))
                .decision,
            AuthorizationDecision::Allow
        );
        let denied = authz.authorize(&auth_request(ScopeRef::Project {
            workspace_id: WorkspaceId("ws".into()),
            project_id: awaken_iam_contract::ProjectId("p".into()),
        }));
        assert_eq!(denied.decision, AuthorizationDecision::Deny);
        assert_eq!(denied.reason, "scope_kind_not_allowed");

        let second = pap.create_draft(request(ScopeKind::Project)).unwrap();
        assert!(
            pap.validate(&second.namespace, second.revision)
                .unwrap()
                .valid
        );
        pap.activate(
            &mut authz,
            &second.namespace,
            second.revision,
            ActivateAuthorizationProfile {
                expected_active_revision: Some(first.revision),
            },
        )
        .unwrap();
        assert_eq!(
            authz
                .authorize(&auth_request(ScopeRef::Project {
                    workspace_id: WorkspaceId("ws".into()),
                    project_id: awaken_iam_contract::ProjectId("p".into()),
                }))
                .decision,
            AuthorizationDecision::Allow
        );

        pap.rollback(
            &mut authz,
            &first.namespace,
            first.revision,
            second.revision,
        )
        .unwrap();
        assert_eq!(pap.active(&first.namespace).unwrap().unwrap().revision, 1);
    }

    #[test]
    fn sqlite_profile_head_and_revision_survive_restart() {
        let dir = test_dir("profile-restart");
        let path = dir.join("iam.sqlite");
        let namespace = NamespaceId("awaken.runtime".into());
        {
            let store = Arc::new(
                sqlite_migrated_store(SqliteBackend::open_path(&path).unwrap(), "iam").unwrap(),
            );
            let pap = AuthorizationProfileAdmin::new(store);
            let mut authz = AuthzApi::new();
            let profile = pap.create_draft(request(ScopeKind::Workspace)).unwrap();
            pap.validate(&namespace, profile.revision).unwrap();
            pap.activate(
                &mut authz,
                &namespace,
                profile.revision,
                ActivateAuthorizationProfile {
                    expected_active_revision: None,
                },
            )
            .unwrap();
        }
        let store = Arc::new(
            sqlite_migrated_store(SqliteBackend::open_path(&path).unwrap(), "iam").unwrap(),
        );
        let pap = AuthorizationProfileAdmin::new(store);
        let mut authz = AuthzApi::new();
        assert_eq!(pap.hydrate(&mut authz, &namespace).unwrap(), Some(1));
        assert_eq!(authz.snapshot().active_profiles[0].revision, 1);
        drop(pap);
        std::fs::remove_dir_all(dir).unwrap();
    }
}
