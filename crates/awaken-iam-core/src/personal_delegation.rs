//! Consent is immutable except for a monotonic revocation. Product conditions
//! remain with the product; every use also requires current IAM policy.
use crate::{RepositoryError, RepositoryResult};
use awaken_iam_contract::{
    AccountId, CreatePersonalDelegation, ListPersonalDelegations, PersonalDelegation,
    PersonalDelegationPage, ScopeRef,
};

pub trait PersonalDelegationRepository: Send + Sync {
    fn create_personal_delegation(
        &self,
        value: PersonalDelegation,
    ) -> RepositoryResult<PersonalDelegation>;
    fn personal_delegation(&self, id: &str) -> RepositoryResult<Option<PersonalDelegation>>;
    /// Stable id-ascending pages containing every lifecycle, only for this owner.
    fn list_personal_delegations(
        &self,
        owner: &AccountId,
        query: &ListPersonalDelegations,
    ) -> RepositoryResult<PersonalDelegationPage>;
    fn revoke_personal_delegation(
        &self,
        id: &str,
        owner: &AccountId,
        at: i64,
    ) -> RepositoryResult<PersonalDelegation>;
}

pub fn validate_personal_consent(
    value: &CreatePersonalDelegation,
    now: i64,
) -> RepositoryResult<()> {
    let valid = |s: &str, max| !s.trim().is_empty() && s.len() <= max;
    let exact = |s: &str| valid(s, 300) && s.trim() == s && !s.contains('*');
    let valid_scope = |scope: &ScopeRef| match scope {
        ScopeRef::Global => false,
        ScopeRef::Org { org_id } => exact(&org_id.0),
        ScopeRef::Workspace { workspace_id } => exact(&workspace_id.0),
        ScopeRef::Project {
            workspace_id,
            project_id,
        } => exact(&workspace_id.0) && exact(&project_id.0),
        ScopeRef::Namespace { namespace_id } => exact(&namespace_id.0),
        ScopeRef::Resource {
            resource_type,
            resource_id,
        } => exact(&resource_type.0) && exact(&resource_id.0),
    };
    if !valid(&value.request_key, 200)
        || !exact(&value.recipient_client_id)
        || !exact(&value.audience)
        || value.actions.is_empty()
        || value.actions.len() > 64
        || value.scopes.is_empty()
        || value.scopes.len() > 32
        || value.actions.iter().any(|a| !exact(&a.0))
        || value.scopes.iter().any(|s| !valid_scope(s))
        || value
            .actions
            .iter()
            .enumerate()
            .any(|(i, a)| value.actions[..i].contains(a))
        || value
            .scopes
            .iter()
            .enumerate()
            .any(|(i, s)| value.scopes[..i].contains(s))
        || value.valid_from < 0
        || value.valid_until <= value.valid_from
        || value.valid_until <= now
        || value.valid_until > 253_402_300_799
    {
        return Err(RepositoryError::Conflict(
            "finite exact consent is required".into(),
        ));
    }
    Ok(())
}
