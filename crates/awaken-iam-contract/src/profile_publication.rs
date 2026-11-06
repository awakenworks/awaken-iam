//! Exact scoped policy publication; product policy compilation remains external.
use crate::{CreateAuthorizationProfile, NamespaceId, OrgId, PrincipalRef, Timestamp, WorkspaceId};

/// Authoritative publication baseline for one finite namespace/Workspace pair.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ScopedAuthorizationProfileBaseline {
    pub namespace: NamespaceId,
    pub workspace_id: WorkspaceId,
    pub active: Option<crate::AuthorizationProfile>,
    pub has_published_revision: bool,
}
use serde::{Deserialize, Serialize};

/// Exact native Group references whose current revisions a compiler needs.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ObserveScopedProfileGroups {
    pub group_ids: Vec<String>,
}

/// Owner evidence for the requested Groups. It carries no roster or grants.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ScopedProfileGroupSources {
    pub org_id: OrgId,
    pub workspace_id: WorkspaceId,
    pub namespace: NamespaceId,
    pub revisions: std::collections::BTreeMap<String, String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PrepareScopedAuthorizationProfile {
    pub request_key: String,
    pub workspace_id: WorkspaceId,
    pub profile: CreateAuthorizationProfile,
    pub expected_active_revision: Option<u64>,
}

/// Immutable receipt for the original publication intent. It does not itself
/// authorize activation and does not imply that this revision is still active.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ScopedAuthorizationProfileIntent {
    pub namespace: NamespaceId,
    pub workspace_id: WorkspaceId,
    pub request_key: String,
    pub request_digest: String,
    pub publisher: PrincipalRef,
    pub revision: u64,
    pub checksum: String,
    pub expected_active_revision: Option<u64>,
    pub created_at: Timestamp,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ScopedAuthorizationProfileStatus {
    Prepared,
    Active,
    Superseded,
    Retired,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ScopedAuthorizationProfileReceipt {
    pub intent: ScopedAuthorizationProfileIntent,
    pub status: ScopedAuthorizationProfileStatus,
    pub current_active_revision: Option<u64>,
}

/// One Workspace's already prepared original intents, to activate atomically.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ActivateScopedAuthorizationProfiles {
    pub intents: Vec<ScopedAuthorizationProfileIntent>,
}
