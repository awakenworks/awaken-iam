//! Policy Administration Point for immutable, replaceable authorization profiles.

use std::collections::HashSet;
use std::sync::Arc;

use awaken_iam_contract::{
    ActivateAuthorizationProfile, AuthorizationProfile, AuthorizationProfileActivated,
    AuthorizationProfileDocument, AuthorizationProfileRetired, AuthorizationProfileValidation,
    CreateAuthorizationProfile, NamespaceId, PolicySnapshot, ProfileLifecycle, ScopeKind,
};
use awaken_iam_core::{AuthorizationProfileRepository, PolicySet, RepositoryError};
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

impl From<RepositoryError> for ProfileAdminError {
    fn from(error: RepositoryError) -> Self {
        match error {
            RepositoryError::NotFound(_) => Self::NotFound,
            RepositoryError::Conflict(message) => Self::Conflict(message),
            RepositoryError::Backend(message) => Self::Repository(message),
        }
    }
}

/// Application service implementing draft, validate, activate, fetch, and rollback.
#[derive(Clone)]
pub struct AuthorizationProfileAdmin {
    repository: Arc<dyn AuthorizationProfileRepository>,
}

impl std::fmt::Debug for AuthorizationProfileAdmin {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("AuthorizationProfileAdmin")
            .finish_non_exhaustive()
    }
}

impl AuthorizationProfileAdmin {
    pub fn new(repository: Arc<dyn AuthorizationProfileRepository>) -> Self {
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
        let errors = validate_document(namespace, &profile.document);
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
        base: &PolicySnapshot,
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
        let (previous, policy_version) = self.repository.activate_profile(
            namespace,
            revision,
            request.expected_active_revision,
        )?;
        let mut profiles = authz.snapshot().active_profiles;
        profiles.retain(|active| active.namespace != profile.namespace);
        profiles.push(profile.clone());
        authz.replace_policy_at_version(
            PolicySet::from_snapshot_and_profiles(base, &profiles),
            policy_version,
        );
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
        base: &PolicySnapshot,
        namespace: &NamespaceId,
        target_revision: u64,
        expected_active_revision: u64,
    ) -> Result<AuthorizationProfileActivated, ProfileAdminError> {
        self.activate(
            authz,
            base,
            namespace,
            target_revision,
            ActivateAuthorizationProfile {
                expected_active_revision: Some(expected_active_revision),
            },
        )
    }

    /// Retire one active namespace without deleting its immutable revisions.
    pub fn retire(
        &self,
        authz: &mut AuthzApi,
        base: &PolicySnapshot,
        namespace: &NamespaceId,
        expected_active_revision: u64,
    ) -> Result<AuthorizationProfileRetired, ProfileAdminError> {
        let (retired, policy_version) = self
            .repository
            .retire_active_profile(namespace, expected_active_revision)?;
        let mut profiles = authz.snapshot().active_profiles;
        profiles.retain(|profile| profile.namespace != *namespace);
        authz.replace_policy_at_version(
            PolicySet::from_snapshot_and_profiles(base, &profiles),
            policy_version,
        );
        Ok(AuthorizationProfileRetired {
            namespace: namespace.clone(),
            retired_revision: retired.revision,
            policy_version,
            checksum: retired.checksum,
        })
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
        base: &PolicySnapshot,
        namespace: &NamespaceId,
    ) -> Result<Option<u64>, ProfileAdminError> {
        let Some(profile) = self.repository.active_profile(namespace)? else {
            return Ok(None);
        };
        let mut profiles = authz.snapshot().active_profiles;
        profiles.retain(|active| active.namespace != profile.namespace);
        profiles.push(profile.clone());
        let policy_version = base.version;
        authz.replace_policy_at_version(
            PolicySet::from_snapshot_and_profiles(base, &profiles),
            policy_version,
        );
        Ok(Some(profile.revision))
    }

    /// Restore every namespace's durable active revision at process start.
    pub fn hydrate_all(
        &self,
        authz: &mut AuthzApi,
        base: &PolicySnapshot,
    ) -> Result<usize, ProfileAdminError> {
        let profiles = self.repository.active_profiles()?;
        let count = profiles.len();
        let policy_version = base.version;
        authz.replace_policy_at_version(
            PolicySet::from_snapshot_and_profiles(base, &profiles),
            policy_version,
        );
        Ok(count)
    }

    /// Read the active profiles from the shared store when another daemon has
    /// advanced the policy fence.
    pub fn durable_active_profiles(&self) -> Result<Vec<AuthorizationProfile>, ProfileAdminError> {
        Ok(self.repository.active_profiles()?)
    }
}

fn checksum(document: &AuthorizationProfileDocument) -> Result<String, ProfileAdminError> {
    let bytes = serde_json::to_vec(document)
        .map_err(|error| ProfileAdminError::Repository(error.to_string()))?;
    Ok(format!("sha256:{:x}", Sha256::digest(bytes)))
}

fn validate_document(
    namespace: &NamespaceId,
    document: &AuthorizationProfileDocument,
) -> Vec<String> {
    let mut errors = Vec::new();
    let action_prefix = format!("{}::", namespace.0);
    let subject_prefix = format!("{}:", namespace.0);
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
        if rule.action_pattern.is_empty() {
            errors.push("action scope pattern must not be empty".into());
        }
        if rule.action_pattern == "*" {
            errors.push("global action wildcard is not allowed in a profile".into());
        }
        if !rule.action_pattern.starts_with(&action_prefix) {
            errors.push(format!(
                "action pattern {} is outside namespace {}",
                rule.action_pattern, namespace.0
            ));
        }
        if !ruled_actions.insert(rule.action_pattern.clone()) {
            errors.push(format!(
                "duplicate action scope rule {}",
                rule.action_pattern
            ));
        }
        if !declared_actions
            .iter()
            .any(|action| action.0 == rule.action_pattern)
        {
            errors.push(format!(
                "scope rule references unknown action pattern {}",
                rule.action_pattern
            ));
        }
        if rule.allowed_scope_kinds.is_empty() {
            errors.push(format!(
                "action pattern {} has no allowed scope kind",
                rule.action_pattern
            ));
        }
        let mut unique = HashSet::new();
        for kind in &rule.allowed_scope_kinds {
            if !unique.insert(kind.clone()) {
                errors.push(format!(
                    "action pattern {} repeats a scope kind",
                    rule.action_pattern
                ));
            }
            if let ScopeKind::Resource { resource_type } = kind
                && !resource_types.contains(resource_type)
            {
                errors.push(format!(
                    "action pattern {} references unknown resource type {}",
                    rule.action_pattern, resource_type.0
                ));
            }
        }
    }
    for action in declared_actions {
        if !action.0.starts_with(&action_prefix) {
            errors.push(format!(
                "declared action {} is outside namespace {}",
                action.0, namespace.0
            ));
        }
        if !ruled_actions.contains(&action.0) {
            errors.push(format!("action {} has no scope rule", action.0));
        }
    }

    for grant in &document.grants {
        if !grant.id.starts_with(&subject_prefix) {
            errors.push(format!(
                "grant id {} is outside namespace {}",
                grant.id, namespace.0
            ));
        }
        if !grant.action_pattern.starts_with(&action_prefix) {
            errors.push(format!(
                "grant action pattern {} is outside namespace {}",
                grant.action_pattern, namespace.0
            ));
        }
        match &grant.subject {
            awaken_iam_contract::GrantSubjectRef::Role { role_id }
                if !role_id.starts_with(&subject_prefix) =>
            {
                errors.push(format!(
                    "role id {role_id} is outside namespace {}",
                    namespace.0
                ));
            }
            awaken_iam_contract::GrantSubjectRef::Group { group_id }
                if !group_id.starts_with(&subject_prefix) =>
            {
                errors.push(format!(
                    "group id {group_id} is outside namespace {}",
                    namespace.0
                ));
            }
            _ => {}
        }
    }
    for binding in &document.role_bindings {
        if !binding.role_id.starts_with(&subject_prefix) {
            errors.push(format!(
                "role id {} is outside namespace {}",
                binding.role_id, namespace.0
            ));
        }
    }
    for roster in &document.group_rosters {
        if !roster.group_id.starts_with(&subject_prefix) {
            errors.push(format!(
                "group id {} is outside namespace {}",
                roster.group_id, namespace.0
            ));
        }
    }
    for binding in &document.group_role_bindings {
        if !binding.group_id.starts_with(&subject_prefix) {
            errors.push(format!(
                "group id {} is outside namespace {}",
                binding.group_id, namespace.0
            ));
        }
        if !binding.role_id.starts_with(&subject_prefix) {
            errors.push(format!(
                "role id {} is outside namespace {}",
                binding.role_id, namespace.0
            ));
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
                    actions: vec![ActionKey("awaken.runtime::memory.*".into())],
                    ..ResourceModelRegistration::default()
                },
                action_scope_rules: vec![ActionScopeRule {
                    action_pattern: "awaken.runtime::memory.*".into(),
                    allowed_scope_kinds: vec![scope_kind],
                }],
                grants: vec![GrantSnapshot {
                    id: "awaken.runtime:grant_memory".into(),
                    subject: GrantSubjectRef::Principal {
                        principal: PrincipalRef::Service {
                            service_id: "runtime".into(),
                        },
                    },
                    action_pattern: "awaken.runtime::memory.*".into(),
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
            ActionKey("awaken.runtime::memory.read".into()),
            scope,
        )
    }

    fn base_policy() -> PolicySnapshot {
        PolicySnapshot {
            version: 7,
            grants: vec![GrantSnapshot {
                id: "cloud:tenant-admin".into(),
                subject: GrantSubjectRef::Principal {
                    principal: PrincipalRef::Service {
                        service_id: "runtime".into(),
                    },
                },
                action_pattern: "console.tenant.admin.access".into(),
                scope: ScopeRef::Global,
                effect: GrantEffect::Allow,
            }],
            ..PolicySnapshot::default()
        }
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
            &PolicySnapshot::default(),
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
            &PolicySnapshot::default(),
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
            &PolicySnapshot::default(),
            &first.namespace,
            first.revision,
            second.revision,
        )
        .unwrap();
        assert_eq!(pap.active(&first.namespace).unwrap().unwrap().revision, 1);
    }

    #[test]
    fn profile_activation_preserves_unrelated_base_policy() {
        let repository = Arc::new(crate::InMemoryStore::new());
        let pap = AuthorizationProfileAdmin::new(repository);
        let mut authz = AuthzApi::new();
        let base = base_policy();
        let profile = pap.create_draft(request(ScopeKind::Workspace)).unwrap();
        pap.validate(&profile.namespace, profile.revision).unwrap();

        pap.activate(
            &mut authz,
            &base,
            &profile.namespace,
            profile.revision,
            ActivateAuthorizationProfile {
                expected_active_revision: None,
            },
        )
        .unwrap();

        let base_decision = authz.authorize(&AuthorizationRequest::direct(
            PrincipalRef::Service {
                service_id: "runtime".into(),
            },
            ActionKey("console.tenant.admin.access".into()),
            ScopeRef::Org {
                org_id: awaken_iam_contract::OrgId("personal:ada".into()),
            },
        ));
        assert_eq!(base_decision.decision, AuthorizationDecision::Allow);
        let active = authz.snapshot().active_profiles;
        assert_eq!(active.len(), 1);
        assert_eq!(active[0].namespace, profile.namespace);
        assert_eq!(active[0].revision, profile.revision);
    }

    #[test]
    fn retirement_cas_removes_only_the_expected_namespace_from_the_live_policy() {
        // Cause-effect graph: active-head presence and expected-revision equality
        // control the only mutation. A mismatch/absence preserves both repository
        // and PDP; an exact match retires the revision, removes its grants, and
        // preserves unrelated base policy.
        //
        // | active head | expected | effect |
        // | A | B | conflict; A still authorizes |
        // | A | A | retire A; profile action denied; base action allowed |
        // | absent | A | not found; policy unchanged |
        let repository = Arc::new(crate::InMemoryStore::new());
        let pap = AuthorizationProfileAdmin::new(repository);
        let mut authz = AuthzApi::new();
        let base = base_policy();
        let profile = pap.create_draft(request(ScopeKind::Workspace)).unwrap();
        pap.validate(&profile.namespace, profile.revision).unwrap();
        pap.activate(
            &mut authz,
            &base,
            &profile.namespace,
            profile.revision,
            ActivateAuthorizationProfile {
                expected_active_revision: None,
            },
        )
        .unwrap();

        assert!(matches!(
            pap.retire(&mut authz, &base, &profile.namespace, profile.revision + 1),
            Err(ProfileAdminError::Conflict(_))
        ));
        assert_eq!(
            authz
                .authorize(&auth_request(ScopeRef::Workspace {
                    workspace_id: WorkspaceId("ws".into()),
                }))
                .decision,
            AuthorizationDecision::Allow
        );

        let retired = pap
            .retire(&mut authz, &base, &profile.namespace, profile.revision)
            .unwrap();
        assert_eq!(retired.retired_revision, profile.revision);
        assert!(pap.active(&profile.namespace).unwrap().is_none());
        assert_eq!(
            pap.get(&profile.namespace, profile.revision)
                .unwrap()
                .unwrap()
                .lifecycle,
            ProfileLifecycle::Retired
        );
        assert_eq!(
            authz
                .authorize(&auth_request(ScopeRef::Workspace {
                    workspace_id: WorkspaceId("ws".into()),
                }))
                .decision,
            AuthorizationDecision::Deny
        );
        assert_eq!(
            authz
                .authorize(&AuthorizationRequest::direct(
                    PrincipalRef::Service {
                        service_id: "runtime".into(),
                    },
                    ActionKey("console.tenant.admin.access".into()),
                    ScopeRef::Org {
                        org_id: awaken_iam_contract::OrgId("personal:ada".into()),
                    },
                ))
                .decision,
            AuthorizationDecision::Allow
        );
        assert!(matches!(
            pap.retire(&mut authz, &base, &profile.namespace, profile.revision),
            Err(ProfileAdminError::NotFound)
        ));
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
                &PolicySnapshot::default(),
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
        assert_eq!(
            pap.hydrate(&mut authz, &PolicySnapshot::default(), &namespace)
                .unwrap(),
            Some(1)
        );
        assert_eq!(authz.snapshot().active_profiles[0].revision, 1);
        drop(pap);
        std::fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn sqlite_retirement_survives_restart_without_deleting_revision_evidence() {
        // Cause-effect coverage: exact active SQLite head -> retirement removes
        // hydration authority; immutable revision -> remains readable as retired.
        // Restart is the independent effect proving durable PDP composition does
        // not resurrect the namespace.
        let dir = test_dir("profile-retirement-restart");
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
                &PolicySnapshot::default(),
                &namespace,
                profile.revision,
                ActivateAuthorizationProfile {
                    expected_active_revision: None,
                },
            )
            .unwrap();
            pap.retire(
                &mut authz,
                &PolicySnapshot::default(),
                &namespace,
                profile.revision,
            )
            .unwrap();
        }
        let store = Arc::new(
            sqlite_migrated_store(SqliteBackend::open_path(&path).unwrap(), "iam").unwrap(),
        );
        let pap = AuthorizationProfileAdmin::new(store);
        let mut authz = AuthzApi::new();
        assert_eq!(
            pap.hydrate(&mut authz, &PolicySnapshot::default(), &namespace)
                .unwrap(),
            None
        );
        assert!(authz.snapshot().active_profiles.is_empty());
        assert_eq!(
            pap.get(&namespace, 1).unwrap().unwrap().lifecycle,
            ProfileLifecycle::Retired
        );
        drop(pap);
        std::fs::remove_dir_all(dir).unwrap();
    }
}
