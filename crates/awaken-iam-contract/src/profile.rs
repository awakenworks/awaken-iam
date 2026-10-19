//! Versioned authorization-profile contract shared by PAP, PDP, and consumers.

use serde::{Deserialize, Serialize};

use crate::{
    GrantSnapshot, GroupRoleBindingSnapshot, GroupRosterSnapshot, NamespaceId,
    ResourceModelRegistration, ResourceType, RoleBindingSnapshot, Timestamp,
};

/// The structural kind of an authorization target.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum ScopeKind {
    Global,
    Org,
    Namespace,
    Workspace,
    Project,
    Resource { resource_type: ResourceType },
}

/// One exact action and the target kinds on which it is meaningful.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ActionScopeRule {
    /// IAM action pattern (`memory.read`, `tool.*`); the unconstrained `*`
    /// pattern is rejected by the PAP so one consumer cannot claim every
    /// namespace.
    pub action_pattern: String,
    pub allowed_scope_kinds: Vec<ScopeKind>,
}

/// Immutable policy content stored under one profile revision.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct AuthorizationProfileDocument {
    #[serde(default)]
    pub resource_model: ResourceModelRegistration,
    #[serde(default)]
    pub action_scope_rules: Vec<ActionScopeRule>,
    #[serde(default)]
    pub grants: Vec<GrantSnapshot>,
    #[serde(default)]
    pub role_bindings: Vec<RoleBindingSnapshot>,
    #[serde(default)]
    pub group_rosters: Vec<GroupRosterSnapshot>,
    #[serde(default)]
    pub group_role_bindings: Vec<GroupRoleBindingSnapshot>,
    /// Optional finite constraints on this profile's existing grants.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub grant_constraints: Vec<crate::GrantConstraint>,
    /// Source and display metadata for existing Roles.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub permission_bundles: Vec<crate::PermissionBundleMetadata>,
    /// Limits on the personal/Group bindings declared by this profile.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub binding_limits: Vec<crate::RoleBindingLimit>,
}

/// Administration lifecycle of a profile revision.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ProfileLifecycle {
    Draft,
    Validated,
    Active,
    Retired,
}

/// Read-only evidence from the Profile owner's immutable revision history.
///
/// This is not an authorization decision. A retired revision still counts as
/// published. Both fields are required on the wire: an incomplete response
/// must never look like a namespace that has not been configured.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AuthorizationProfilePublicationState {
    pub namespace: NamespaceId,
    pub has_published_revision: bool,
}

/// One immutable, checksummed profile revision.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AuthorizationProfile {
    pub namespace: NamespaceId,
    pub revision: u64,
    pub lifecycle: ProfileLifecycle,
    pub document: AuthorizationProfileDocument,
    pub checksum: String,
    pub created_at: Timestamp,
}

/// Request to create the next draft revision in a namespace.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CreateAuthorizationProfile {
    pub namespace: NamespaceId,
    pub document: AuthorizationProfileDocument,
    pub created_at: Timestamp,
}

/// Optimistic activation/rollback request.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ActivateAuthorizationProfile {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expected_active_revision: Option<u64>,
}

/// Optimistic request to retire the current active namespace head.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RetireAuthorizationProfile {
    pub expected_active_revision: u64,
}

/// Validation result. Invalid drafts remain drafts and cannot be activated.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AuthorizationProfileValidation {
    pub namespace: NamespaceId,
    pub revision: u64,
    pub valid: bool,
    pub errors: Vec<String>,
    pub checksum: String,
}

/// Result of an atomic activation or rollback.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AuthorizationProfileActivated {
    pub namespace: NamespaceId,
    pub active_revision: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub previous_active_revision: Option<u64>,
    pub policy_version: u64,
    pub checksum: String,
}

/// Result of retiring one active namespace head without deleting its revision.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AuthorizationProfileRetired {
    pub namespace: NamespaceId,
    pub retired_revision: u64,
    pub policy_version: u64,
    pub checksum: String,
}

#[cfg(test)]
mod publication_tests {
    use super::*;

    #[test]
    fn publication_evidence_requires_an_explicit_boolean_and_namespace() {
        // W1 explicit false/true -> exact round trip. W2 missing/null Boolean,
        // W3 missing namespace -> decode failure, never inferred absence.
        for published in [false, true] {
            let value = serde_json::json!({
                "namespace": "example.business", "has_published_revision": published
            });
            let state: AuthorizationProfilePublicationState =
                serde_json::from_value(value.clone()).unwrap();
            assert_eq!(state.has_published_revision, published);
            assert_eq!(serde_json::to_value(state).unwrap(), value);
        }
        for invalid in [
            serde_json::json!({"namespace":"example.business"}),
            serde_json::json!({"namespace":"example.business", "has_published_revision":null}),
            serde_json::json!({"has_published_revision":false}),
        ] {
            assert!(
                serde_json::from_value::<AuthorizationProfilePublicationState>(invalid).is_err()
            );
        }
    }
}
