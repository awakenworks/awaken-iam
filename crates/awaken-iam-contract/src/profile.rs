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
