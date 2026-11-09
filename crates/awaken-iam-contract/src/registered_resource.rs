//! Opt-in registration qualification, evaluated with the native current PDP.
use crate::{
    ActionKey, AuthorizationEvaluation, NamespaceId, ProductId, ResourceAuthorizationRequest,
    ResourceId, ResourceType, WorkspaceId,
};
use serde::{Deserialize, Serialize};

/// Expectations constrain a question; none of these fields grant authority.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RegisteredResourceAuthorizationRequest {
    pub authorization: ResourceAuthorizationRequest,
    pub namespace: NamespaceId,
    pub product_id: ProductId,
    pub workspace_id: WorkspaceId,
    pub resource_type: ResourceType,
}

/// Evidence of the exact active registrations observed in the same PDP fence.
/// This is not a lease and cannot substitute for the contained decision.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ResourceRegistrationQualification {
    pub namespace: NamespaceId,
    pub profile_revision: u64,
    pub profile_checksum: String,
    pub action: ActionKey,
    pub product_id: ProductId,
    pub workspace_id: WorkspaceId,
    pub resource_type: ResourceType,
    pub resource_id: ResourceId,
    pub projection_id: String,
    pub projection_epoch: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RegisteredResourceAuthorizationEvaluation {
    pub evaluation: AuthorizationEvaluation,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub registration: Option<ResourceRegistrationQualification>,
}
