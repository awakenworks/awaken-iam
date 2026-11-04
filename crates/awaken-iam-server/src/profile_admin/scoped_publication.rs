//! Original scoped intent recovery over the existing immutable profile owner.
use super::*;
use awaken_iam_contract::{
    GrantSubjectRef, PrepareScopedAuthorizationProfile, PrincipalRef, ScopeRef,
    ScopedAuthorizationProfileIntent, ScopedAuthorizationProfileReceipt,
    ScopedAuthorizationProfileStatus, WorkspaceId,
};

pub(crate) fn validate_scoped_document(
    namespace: &NamespaceId,
    workspace: &WorkspaceId,
    document: &AuthorizationProfileDocument,
) -> Result<(), ProfileAdminError> {
    let mut errors = validate_document(namespace, document);
    let within = |scope: &ScopeRef| matches!(scope, ScopeRef::Workspace{workspace_id}|ScopeRef::Project{workspace_id,..} if workspace_id==workspace);
    if !document.group_rosters.is_empty()
        || !document.resource_model.resource_types.is_empty()
        || !document.resource_model.edges.is_empty()
    {
        errors.push("scoped publication cannot replace rosters or resource topology".into());
    }
    if document.action_scope_rules.iter().any(|rule| {
        rule.allowed_scope_kinds
            .iter()
            .any(|kind| !matches!(kind, ScopeKind::Workspace | ScopeKind::Project))
    }) {
        errors.push("scoped profile actions require Workspace or Project scope".into());
    }
    for grant in &document.grants {
        let local_role = matches!(&grant.subject,GrantSubjectRef::Role{role_id} if document.permission_bundles.iter().any(|bundle|&bundle.role_id==role_id));
        if !(within(&grant.scope) || grant.scope == ScopeRef::Global && local_role) {
            errors.push("grant is outside the exact Workspace".into());
        }
    }
    if document
        .role_bindings
        .iter()
        .any(|binding| !within(&binding.scope))
        || document
            .group_role_bindings
            .iter()
            .any(|binding| !within(&binding.scope))
        || document
            .binding_limits
            .iter()
            .any(|binding| !within(&binding.scope))
        || document
            .permission_bundles
            .iter()
            .any(|bundle| !within(&bundle.owner_scope))
    {
        errors.push("profile binding is outside the exact Workspace".into());
    }
    if errors.is_empty() {
        Ok(())
    } else {
        Err(ProfileAdminError::Validation(errors))
    }
}

impl AuthorizationProfileAdmin {
    /// Exact-scope read of native publication history. Absence is explicit;
    /// retired history is never projected as a never-published namespace.
    pub fn scoped_publication_baseline(
        &self,
        namespace: &NamespaceId,
        workspace: &WorkspaceId,
    ) -> Result<awaken_iam_contract::ScopedAuthorizationProfileBaseline, ProfileAdminError> {
        if self
            .repository
            .profile_publication_workspace(namespace)?
            .is_some_and(|owner| owner != *workspace)
        {
            return Err(ProfileAdminError::NotFound);
        }
        for profile in self.repository.list_profiles(namespace)? {
            validate_scoped_document(namespace, workspace, &profile.document)?;
        }
        Ok(awaken_iam_contract::ScopedAuthorizationProfileBaseline {
            namespace: namespace.clone(),
            workspace_id: workspace.clone(),
            active: self.active(namespace)?,
            has_published_revision: self.publication_state(namespace)?.has_published_revision,
        })
    }

    /// Prepare once under an exact original key. The HTTP owner supplies the
    /// authenticated publisher after current native capability checks.
    pub fn prepare_scoped_publication(
        &self,
        request: PrepareScopedAuthorizationProfile,
        publisher: PrincipalRef,
    ) -> Result<ScopedAuthorizationProfileIntent, ProfileAdminError> {
        if request.request_key.is_empty()
            || request.request_key.len() > 160
            || request.request_key.trim() != request.request_key
            || request.request_key.chars().any(char::is_control)
            || request.workspace_id.0.is_empty()
            || request.workspace_id.0.len() > 256
            || request.workspace_id.0.trim() != request.workspace_id.0
            || request.workspace_id.0.chars().any(char::is_control)
            || request.profile.namespace.0.is_empty()
            || request.profile.namespace.0.len() > 256
            || !request
                .profile
                .namespace
                .0
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || b"._-".contains(&byte))
        {
            return Err(ProfileAdminError::Validation(vec![
                "exact publication key, namespace and Workspace required".into(),
            ]));
        }
        let bytes = serde_json::to_vec(&(&request, &publisher))
            .map_err(|error| ProfileAdminError::Repository(error.to_string()))?;
        let digest = format!("sha256:{:x}", Sha256::digest(bytes));
        // Recover an original intent before later source/state gates. Its
        // immutable body and current HTTP authorization must still match.
        if let Some(original) = self
            .repository
            .profile_publication(&request.profile.namespace, &request.request_key)?
        {
            if original.request_digest != digest || original.publisher != publisher {
                return Err(ProfileAdminError::Conflict(
                    "original profile publication has different content".into(),
                ));
            }
            return Ok(original);
        }
        validate_scoped_document(
            &request.profile.namespace,
            &request.workspace_id,
            &request.profile.document,
        )?;
        for previous in self.repository.list_profiles(&request.profile.namespace)? {
            validate_scoped_document(
                &previous.namespace,
                &request.workspace_id,
                &previous.document,
            )?;
        }
        let checksum = checksum(&request.profile.document)?;
        self.repository
            .prepare_profile_publication(request, publisher, digest, checksum)
            .map_err(Into::into)
    }

    pub fn scoped_publication(
        &self,
        namespace: &NamespaceId,
        key: &str,
    ) -> Result<Option<ScopedAuthorizationProfileIntent>, ProfileAdminError> {
        self.repository
            .profile_publication(namespace, key)
            .map_err(Into::into)
    }

    pub fn scoped_publication_receipt(
        &self,
        namespace: &NamespaceId,
        key: &str,
    ) -> Result<ScopedAuthorizationProfileReceipt, ProfileAdminError> {
        let intent = self
            .scoped_publication(namespace, key)?
            .ok_or(ProfileAdminError::NotFound)?;
        let profile = self
            .repository
            .get_profile(namespace, intent.revision)?
            .ok_or(ProfileAdminError::NotFound)?;
        if profile.checksum != intent.checksum {
            return Err(ProfileAdminError::Repository(
                "publication intent checksum mismatch".into(),
            ));
        }
        let current = self
            .repository
            .active_profile(namespace)?
            .map(|profile| profile.revision);
        let status = if current == Some(intent.revision) {
            ScopedAuthorizationProfileStatus::Active
        } else if matches!(
            profile.lifecycle,
            ProfileLifecycle::Active | ProfileLifecycle::Retired
        ) {
            if current.is_some() {
                ScopedAuthorizationProfileStatus::Superseded
            } else {
                ScopedAuthorizationProfileStatus::Retired
            }
        } else {
            ScopedAuthorizationProfileStatus::Prepared
        };
        Ok(ScopedAuthorizationProfileReceipt {
            intent,
            status,
            current_active_revision: current,
        })
    }

    /// An original successful or superseded effect is a read, never rollback.
    pub fn activate_scoped_publication(
        &self,
        authz: &mut AuthzApi,
        base: &PolicySnapshot,
        namespace: &NamespaceId,
        key: &str,
    ) -> Result<ScopedAuthorizationProfileReceipt, ProfileAdminError> {
        let receipt = self.scoped_publication_receipt(namespace, key)?;
        if receipt.status != ScopedAuthorizationProfileStatus::Prepared {
            return Ok(receipt);
        }
        let profile = self
            .repository
            .get_profile(namespace, receipt.intent.revision)?
            .ok_or(ProfileAdminError::NotFound)?;
        validate_scoped_document(namespace, &receipt.intent.workspace_id, &profile.document)?;
        self.activate(
            authz,
            base,
            namespace,
            receipt.intent.revision,
            ActivateAuthorizationProfile {
                expected_active_revision: receipt.intent.expected_active_revision,
            },
        )?;
        self.scoped_publication_receipt(namespace, key)
    }
}
