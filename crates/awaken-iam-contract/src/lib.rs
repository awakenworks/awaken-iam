//! Shared IAM contract types.
//!
//! This crate is the stable seam used by product services. It contains DTOs and
//! identifiers only; evaluation, persistence, and server code live elsewhere.

mod identity;

use serde::{Deserialize, Serialize};

pub use identity::{
    Account, AccountStatus, ExternalIdentity, ExternalIdentityClaims, ExternalIdentityId,
    ExternalIdentityKey, ExternalSubject, IdentityProviderConfig, IdentityProviderConfigId,
    IdentityProviderKey, IdentityProviderKind, OAuthLoginState, OAuthLoginStateId, Session,
    SessionId, Timestamp,
};

/// Global account identifier.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct AccountId(pub String);

/// Organization / owner identifier.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct OrgId(pub String);

/// Namespace identifier used for package publishing.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct NamespaceId(pub String);

/// Product workspace identifier.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct WorkspaceId(pub String);

/// Product project identifier.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct ProjectId(pub String);

/// Actor making a request.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum PrincipalRef {
    /// A human/global account principal.
    Account { account_id: AccountId },
    /// A service account principal.
    Service { service_id: String },
    /// An API token principal.
    ApiToken { token_id: String },
}

/// Authorization scope.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum ScopeRef {
    /// Global platform scope.
    Global,
    /// Organization / owner scope.
    Org { org_id: OrgId },
    /// Package namespace scope.
    Namespace { namespace_id: NamespaceId },
    /// Workspace scope.
    Workspace { workspace_id: WorkspaceId },
    /// Project scope.
    Project {
        workspace_id: WorkspaceId,
        project_id: ProjectId,
    },
}

/// Action key checked by IAM.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct ActionKey(pub String);

/// Authorization request.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AuthorizationRequest {
    /// Requesting principal.
    pub principal: PrincipalRef,
    /// Action being performed.
    pub action: ActionKey,
    /// Target scope.
    pub scope: ScopeRef,
}

/// Authorization decision.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AuthorizationDecision {
    /// The operation is allowed.
    Allow,
    /// The operation is denied.
    Deny,
}

/// Entitlement request for account-tier/product-plan checks.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EntitlementRequest {
    /// Requesting principal.
    pub principal: PrincipalRef,
    /// Operation, feature, or SKU key.
    pub entitlement: String,
    /// Optional resource coordinate.
    pub resource: Option<String>,
}

/// Entitlement decision.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EntitlementDecision {
    /// Entitlement permits the operation.
    Allow,
    /// Entitlement blocks the operation.
    Deny,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn scope_ref_serializes_with_kind_tag() {
        let scope = ScopeRef::Namespace {
            namespace_id: NamespaceId("acme".into()),
        };
        let json = serde_json::to_string(&scope).unwrap();
        assert!(json.contains("namespace"));
        assert!(json.contains("acme"));
    }

    #[test]
    fn account_has_no_email_identity_key() {
        let account = Account {
            id: AccountId("acct_1".into()),
            status: AccountStatus::Active,
            display_name: Some("Ada".into()),
            created_at: Timestamp("2026-06-19T00:00:00Z".into()),
            updated_at: Timestamp("2026-06-19T00:00:00Z".into()),
        };
        let json = serde_json::to_value(account).unwrap();
        assert!(json.get("email").is_none());
    }

    #[test]
    fn external_identity_key_uses_provider_and_subject_not_email() {
        let claims = ExternalIdentityClaims {
            subject: ExternalSubject("sub_123".into()),
            email: Some("first@example.com".into()),
            email_verified: Some(true),
            display_name: Some("First Name".into()),
            username: None,
            avatar_url: None,
            locale: None,
        };
        let key = ExternalIdentityKey::from_claims(IdentityProviderKey("fake".into()), &claims);

        let mut changed_claims = claims.clone();
        changed_claims.email = Some("second@example.com".into());

        assert_eq!(
            key,
            ExternalIdentityKey::from_claims(IdentityProviderKey("fake".into()), &changed_claims)
        );
    }
}
