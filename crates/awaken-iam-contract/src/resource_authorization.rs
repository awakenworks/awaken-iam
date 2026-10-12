//! Finite resource constraints; product facts remain consumer-owned.

use serde::{Deserialize, Serialize};

use crate::{AuthorizationRequest, GrantSubjectRef, PrincipalRef, ScopeRef};

/// Add trusted resource facts without changing the legacy authorization DTO.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ResourceAuthorizationRequest {
    pub request: AuthorizationRequest,
    pub context: AuthorizationContext,
}

/// Whether a request projects fields, changes fields, or performs another action.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AuthorizationAccess {
    Read,
    Write,
    #[default]
    Operate,
}

/// Exact monetary fact in minor currency units; no floating-point conversion.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AuthorizationAmount {
    pub minor_units: i64,
    pub currency: String,
}

/// Trusted facts resolved by an operation owner, never by a product's UI.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AuthorizationContext {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    /// Server evaluation time in Unix milliseconds.
    pub evaluated_at: Option<i64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub resource_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub resource_type: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub owner: Option<PrincipalRef>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub groups: Option<Vec<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub responsible: Option<PrincipalRef>,
    #[serde(default)]
    pub access: AuthorizationAccess,
    /// None means that the owner has not supplied an exact field demand.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub fields: Option<Vec<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub amount: Option<AuthorizationAmount>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub initiator: Option<PrincipalRef>,
}

/// Closed relationship selectors, independent of a consumer's object model.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AuthorizationDataScope {
    #[default]
    AuthorizedScope,
    Owner,
    BindingGroup,
    Responsible,
}

/// Amount range; bounds are inclusive and apply only to this exact currency.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AuthorizationAmountRange {
    pub currency: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub minimum: Option<i64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub maximum: Option<i64>,
}

/// Extra limits on one existing grant, stored with its immutable profile.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GrantConstraint {
    pub grant_id: String,
    #[serde(default)]
    pub data_scope: AuthorizationDataScope,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub readable_fields: Option<Vec<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub writable_fields: Option<Vec<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub amount_range: Option<AuthorizationAmountRange>,
    #[serde(default)]
    pub prohibit_initiator: bool,
}

/// Inert metadata for an existing Role, not a second grant collection.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PermissionBundleMetadata {
    pub role_id: String,
    pub key: String,
    pub name: String,
    pub owner_scope: ScopeRef,
    pub source_id: String,
    pub source_revision: String,
    pub source_digest: String,
}

/// Additional limits on an existing personal or live-Group role binding.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RoleBindingLimit {
    pub subject: GrantSubjectRef,
    pub role_id: String,
    pub scope: ScopeRef,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    /// Exclusive expiry in Unix milliseconds.
    pub expires_at: Option<i64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub resource_ids: Option<Vec<String>>,
}
