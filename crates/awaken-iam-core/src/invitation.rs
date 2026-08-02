//! Organization invitation aggregate.

use awaken_iam_contract::{
    AccountId, InvitationBinding, InvitationDto, InvitationId, InvitationStatus, OrgId,
    PrincipalRef, Timestamp,
};

/// IAM-owned invitation state. The clear claim token is never persisted.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Invitation {
    pub id: InvitationId,
    pub idempotency_key: String,
    pub org_id: OrgId,
    pub email: String,
    pub bindings: Vec<InvitationBinding>,
    pub invited_by: PrincipalRef,
    pub token_hash: String,
    pub status: InvitationStatus,
    pub expires_at: Timestamp,
    pub created_at: Timestamp,
    pub updated_at: Timestamp,
    pub accepted_by_account_id: Option<AccountId>,
}

impl Invitation {
    /// Project the aggregate without its token hash/idempotency internals.
    pub fn to_dto(&self) -> InvitationDto {
        InvitationDto {
            id: self.id.clone(),
            org_id: self.org_id.clone(),
            email: self.email.clone(),
            bindings: self.bindings.clone(),
            invited_by: self.invited_by.clone(),
            status: self.status,
            expires_at: self.expires_at.clone(),
            created_at: self.created_at.clone(),
            updated_at: self.updated_at.clone(),
            accepted_by_account_id: self.accepted_by_account_id.clone(),
        }
    }
}

/// Normalize a routing email for comparison, never for account identity.
pub fn normalize_invitation_email(email: &str) -> Option<String> {
    let normalized = email.trim().to_ascii_lowercase();
    (normalized.contains('@')
        && !normalized.contains(char::is_whitespace)
        && normalized.len() <= 320)
        .then_some(normalized)
}
