//! Finite personal consent; it narrows current policy and never replaces it.
use crate::{AccountId, ActionKey, ResourceAuthorizationRequest, ScopeRef};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CreatePersonalDelegation {
    /// An original intent key. Reusing it with a different body is a conflict.
    pub request_key: String,
    pub recipient_client_id: String,
    pub audience: String,
    pub actions: Vec<ActionKey>,
    /// Exact owner-resolved scopes, without wildcard or inferred ancestry.
    pub scopes: Vec<ScopeRef>,
    /// Unix seconds; the end is exclusive.
    pub valid_from: i64,
    pub valid_until: i64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PersonalDelegation {
    pub id: String,
    pub owner: AccountId,
    pub service_id: String,
    pub consent: CreatePersonalDelegation,
    pub created_at: i64,
    pub revoked_at: Option<i64>,
    pub version: u64,
}

/// A bounded direct-owner inventory query. Unknown selectors are refused.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ListPersonalDelegations {
    #[serde(default = "default_personal_delegation_limit")]
    pub limit: u16,
    /// Exclusive opaque identifier bound from the preceding page.
    pub after: Option<String>,
}
fn default_personal_delegation_limit() -> u16 {
    50
}
impl Default for ListPersonalDelegations {
    fn default() -> Self {
        Self {
            limit: 50,
            after: None,
        }
    }
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PersonalDelegationPage {
    pub items: Vec<PersonalDelegation>,
    pub next_cursor: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PersonalDelegationPurpose {
    Execute,
    OriginalOutcome,
    /// A scope-level read on the owner's behalf: no target, a `.read` action
    /// only, never a write. Each use is still evaluated against current policy.
    Read,
}

/// The target is an opaque owner identifier, never a product type inside IAM.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PersonalDelegationTarget {
    pub id: String,
    pub revision: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MintPersonalDelegationToken {
    pub grant_id: String,
    pub action: ActionKey,
    pub scope: ScopeRef,
    /// The exact native target; absent only for a scope-level `Read`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub target: Option<PersonalDelegationTarget>,
    pub purpose: PersonalDelegationPurpose,
    /// Required only for a read of the original native outcome.
    pub original_key: Option<String>,
}

/// A separate JWT family: legacy access-token verifiers must reject it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PersonalDelegationTokenClaims {
    pub iss: String,
    pub aud: String,
    pub sub: String,
    pub service_id: String,
    pub client_id: String,
    pub grant_id: String,
    pub iat: i64,
    pub exp: i64,
    pub binding: MintPersonalDelegationToken,
}

/// Only the authenticated operation owner supplies the actual authorization
/// facts. IAM independently verifies consent and current conjunctive policy.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AuthorizePersonalDelegation {
    pub token: String,
    pub audience: String,
    /// Exact execution target; absent only when authorizing a scope-level Read.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub target: Option<PersonalDelegationTarget>,
    pub request: ResourceAuthorizationRequest,
}
