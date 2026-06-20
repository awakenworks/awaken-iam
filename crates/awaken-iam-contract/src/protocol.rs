//! Remote authorization protocol DTOs.
//!
//! These are the wire shapes exchanged by the remote IAM protocol described in
//! `docs/design/remote-protocol.md`: the request/response bodies for
//! `POST /v1/authorize`, `POST /v1/authorize/batch`, `POST /v1/entitlements/check`,
//! and the policy snapshot served for local-mode synchronisation. Like the rest
//! of this crate they are DTOs only — evaluation lives in `awaken-iam-core` and
//! the protocol assembly lives in `awaken-iam-server`.
//!
//! Every authorization response carries enough explanation for an audit/debug
//! surface: the decision, a stable reason code, and the ids of the grants and
//! roles that produced it.

use serde::{Deserialize, Serialize};

use crate::{
    AuthorizationDecision, AuthorizationRequest, EntitlementDecision, NamespaceId, OrgId,
    PrincipalRef, ResourceId, ResourceType, ScopeRef, WorkspaceId,
};

/// Reasoned response to `POST /v1/authorize`.
///
/// Mirrors the engine's decision trace on the wire: the three-valued decision, a
/// stable snake_case reason code, and the ids of the grants and roles that
/// produced the deciding effect, so an audit/debug surface needs no second round
/// trip.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AuthorizationOutcome {
    /// Allow/deny/require-approval decision returned to the caller.
    pub decision: AuthorizationDecision,
    /// Stable snake_case reason code (e.g. `allowed_by_grant`, `default_deny`).
    pub reason: String,
    /// Ids of the grants that produced the deciding effect, in policy order.
    pub matched_grants: Vec<String>,
    /// Ids of the roles whose grants contributed to the deciding effect.
    pub matched_roles: Vec<String>,
}

/// Request body for `POST /v1/authorize/batch`.
///
/// A batch lets a caller resolve several authorization questions in one round
/// trip; the response preserves request order one-to-one, for list filtering.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BatchAuthorizationRequest {
    /// Authorization questions to evaluate, in order.
    pub requests: Vec<AuthorizationRequest>,
}

/// Response body for `POST /v1/authorize/batch`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BatchAuthorizationResponse {
    /// Outcomes positionally aligned with the request batch.
    pub outcomes: Vec<AuthorizationOutcome>,
}

/// Reasoned response to `POST /v1/entitlements/check`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EntitlementCheckResponse {
    /// Allow/deny decision returned to the caller.
    pub decision: EntitlementDecision,
    /// Stable snake_case reason code (e.g. `default_allow`, `plan_entitles`).
    pub reason: String,
}

/// Effect of a snapshot grant.
///
/// Mirrors the engine's three-valued effect lattice so a snapshot evaluated
/// locally is byte-identical to a remote `authorize` call.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum GrantEffect {
    /// Permit the action.
    Allow,
    /// Permit the action only after the caller completes an approval step.
    RequireApproval,
    /// Forbid the action, overriding any matching allow or approval grant.
    Deny,
}

/// Subject a snapshot grant applies to.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum GrantSubjectRef {
    /// A grant attached directly to a principal.
    Principal {
        /// Principal the grant is held by.
        principal: PrincipalRef,
    },
    /// A grant carried by a role and used by any principal bound to it.
    Role {
        /// Role id carrying the grant.
        role_id: String,
    },
}

/// Wire shape of a single grant in a policy snapshot.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GrantSnapshot {
    /// Stable grant id surfaced in the decision trace.
    pub id: String,
    /// Principal or role the grant applies to.
    pub subject: GrantSubjectRef,
    /// Action pattern the grant covers.
    pub action_pattern: String,
    /// Scope at which the grant is issued.
    pub scope: ScopeRef,
    /// Whether the grant allows, requires approval, or denies.
    pub effect: GrantEffect,
}

/// Wire shape of a role binding in a policy snapshot.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RoleBindingSnapshot {
    /// Principal that holds the role.
    pub principal: PrincipalRef,
    /// Role granted to the principal.
    pub role_id: String,
    /// Scope at which the binding applies.
    pub scope: ScopeRef,
}

/// A `namespace -> org` parent edge in the scope graph.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct NamespaceOrgEdge {
    /// Namespace owned by the org.
    pub namespace_id: NamespaceId,
    /// Owning org.
    pub org_id: OrgId,
}

/// A `workspace -> org` parent edge in the scope graph.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WorkspaceOrgEdge {
    /// Workspace owned by the org.
    pub workspace_id: WorkspaceId,
    /// Owning org.
    pub org_id: OrgId,
}

/// A parent edge for an open product resource in the scope graph.
///
/// Where a resource sits in the hierarchy is never inferred from its ids; it is
/// registered data, so the snapshot must carry these edges for a synced consumer
/// to resolve open resource scopes exactly as the server does.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ResourceParentEdge {
    /// Resource-type discriminator of the child resource.
    pub resource_type: ResourceType,
    /// Instance id of the child resource.
    pub resource_id: ResourceId,
    /// Parent scope the resource roots under.
    pub parent: ScopeRef,
}

/// Scope-graph parent links that cannot be derived from a [`ScopeRef`] alone.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct ScopeGraphSnapshot {
    /// `namespace -> org` edges.
    pub namespace_orgs: Vec<NamespaceOrgEdge>,
    /// `workspace -> org` edges.
    pub workspace_orgs: Vec<WorkspaceOrgEdge>,
    /// Open-resource parent edges.
    pub resource_parents: Vec<ResourceParentEdge>,
}

/// Versioned snapshot of the authorization policy served for local-mode sync.
///
/// A consumer running in local mode fetches this snapshot and evaluates
/// authorization in-process, re-fetching when `version` advances. The snapshot
/// is authorization-only: the entitlement plane is evaluated separately and is
/// never bundled here.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct PolicySnapshot {
    /// Monotonic version of the policy this snapshot captures.
    pub version: u64,
    /// All grants in policy order.
    pub grants: Vec<GrantSnapshot>,
    /// All role bindings in policy order.
    pub role_bindings: Vec<RoleBindingSnapshot>,
    /// Scope-graph parent links.
    pub scope_graph: ScopeGraphSnapshot,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{AccountId, ActionKey};

    #[test]
    fn authorization_outcome_round_trips_through_json() {
        let outcome = AuthorizationOutcome {
            decision: AuthorizationDecision::Allow,
            reason: "allowed_by_grant".into(),
            matched_grants: vec!["g1".into()],
            matched_roles: vec!["publisher".into()],
        };
        let json = serde_json::to_string(&outcome).unwrap();
        let parsed: AuthorizationOutcome = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed, outcome);
        assert!(json.contains("allowed_by_grant"));
    }

    #[test]
    fn batch_request_preserves_order_on_round_trip() {
        let request = BatchAuthorizationRequest {
            requests: vec![
                AuthorizationRequest::direct(
                    PrincipalRef::Account {
                        account_id: AccountId("acct_1".into()),
                    },
                    ActionKey("pack.read".into()),
                    ScopeRef::Global,
                ),
                AuthorizationRequest::direct(
                    PrincipalRef::Service {
                        service_id: "svc".into(),
                    },
                    ActionKey("pack.publish".into()),
                    ScopeRef::Namespace {
                        namespace_id: NamespaceId("acme".into()),
                    },
                ),
            ],
        };
        let json = serde_json::to_string(&request).unwrap();
        let parsed: BatchAuthorizationRequest = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed, request);
    }

    #[test]
    fn policy_snapshot_round_trips_through_json() {
        let snapshot = PolicySnapshot {
            version: 7,
            grants: vec![GrantSnapshot {
                id: "g1".into(),
                subject: GrantSubjectRef::Role {
                    role_id: "publisher".into(),
                },
                action_pattern: "pack.*".into(),
                scope: ScopeRef::Global,
                effect: GrantEffect::Allow,
            }],
            role_bindings: vec![RoleBindingSnapshot {
                principal: PrincipalRef::Account {
                    account_id: AccountId("acct_1".into()),
                },
                role_id: "publisher".into(),
                scope: ScopeRef::Global,
            }],
            scope_graph: ScopeGraphSnapshot {
                namespace_orgs: vec![NamespaceOrgEdge {
                    namespace_id: NamespaceId("acme".into()),
                    org_id: OrgId("acme".into()),
                }],
                workspace_orgs: vec![WorkspaceOrgEdge {
                    workspace_id: WorkspaceId("ws_main".into()),
                    org_id: OrgId("acme".into()),
                }],
                resource_parents: vec![ResourceParentEdge {
                    resource_type: ResourceType("issue".into()),
                    resource_id: ResourceId("42".into()),
                    parent: ScopeRef::Namespace {
                        namespace_id: NamespaceId("acme".into()),
                    },
                }],
            },
        };
        let json = serde_json::to_string(&snapshot).unwrap();
        let parsed: PolicySnapshot = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed, snapshot);
    }
}
