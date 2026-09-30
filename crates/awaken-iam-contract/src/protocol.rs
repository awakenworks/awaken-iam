//! Remote authorization protocol contracts.
//!
//! These are the wire shapes exchanged by the remote IAM protocol described in
//! `docs/design/remote-protocol.md`: the request/response bodies for
//! `POST /v1/authorize`, `POST /v1/authorize/batch`, `POST /v1/entitlements/check`,
//! and the policy snapshot served for local-mode synchronisation. Like the rest
//! of this crate they are data only — evaluation lives in `awaken-iam-core` and
//! the protocol assembly lives in `awaken-iam-server`.
//!
//! Every authorization response carries enough explanation for an audit/debug
//! surface: the decision, a stable reason code, and the ids of the grants and
//! roles that produced it.

use serde::{Deserialize, Serialize};

use crate::{
    ActionKey, AuthorizationDecision, AuthorizationRequest, EntitlementDecision, NamespaceId,
    OrgId, PrincipalRef, ProductId, ResourceId, ResourceType, ScopeRef, SignerKey, WorkspaceId,
};

/// Liveness status of an authenticated API token.
///
/// Only `active` is returned over HTTP (invalid/expired/revoked tokens yield a
/// `401 Unauthorized` instead of a response body), but the field is present for
/// forward-compatibility and to allow a single response shape for both online
/// introspection and any future cached/offline paths.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ApiTokenStatus {
    /// Token is currently valid: unrevoked and not past its expiry.
    Active,
}

/// Request body for `POST /v1/tokens/introspect`.
///
/// The caller presents the full cleartext bearer token; IAM resolves the
/// principal and workspace without the caller ever holding the `secret_hash`.
/// Token verification (argon2id) stays in IAM — consumers never re-implement it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TokenIntrospectionRequest {
    /// The full cleartext bearer token (`sk-awaken-<prefix>.<secret>`) to verify.
    pub token: String,
}

/// Response body for `POST /v1/tokens/introspect` (200 OK).
///
/// Returned only for tokens that are live (unrevoked and unexpired).
/// Invalid, expired, or revoked tokens yield `401 Unauthorized` instead, so
/// when this struct is present the token is always `status: active`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TokenIntrospectionResponse {
    /// Principal the token authenticates as.
    pub principal: PrincipalRef,
    /// Workspace the token is bound to for credential attribution.
    pub workspace: WorkspaceId,
    /// Liveness status — always `active` for a 200 response.
    pub status: ApiTokenStatus,
}

/// The authority empowered to discharge a require-approval obligation.
///
/// In the MVP this is the scope the deciding require-approval grant is anchored
/// at: an approval recorded at (or above) this scope discharges the obligation.
/// It is modeled as a struct rather than a bare [`ScopeRef`] so a future
/// widening — a named approver role or principal — is an additive field rather
/// than a wire break.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ApprovalAuthority {
    /// Scope that owns the obligation; approval is granted at or above it.
    pub scope: ScopeRef,
}

/// An approval obligation the caller must discharge before a
/// [`AuthorizationDecision::RequireApproval`] decision becomes an effective
/// allow.
///
/// It is carried only on a require-approval outcome and is the single hand-off
/// seam between IAM's decision and the caller's approval execution. The approval
/// is discharged **product-side** (a recorded approval keyed by `obligation_id`)
/// or by minting a **capability token bound to `obligation_id`** — never by
/// re-querying authorize and never by adding a per-instance grant, so the
/// decision stays a pure function of policy.
///
/// `obligation_id` is content-addressed over the principal chain, action, scope,
/// and deciding `policy_id`, so re-querying authorize for the same question
/// yields the same id and an approval discharged against it is idempotent.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ApprovalObligation {
    /// Stable, content-addressed id the approval is discharged against.
    pub obligation_id: String,
    /// Id of the policy (grant) whose require-approval effect imposed it.
    pub policy_id: String,
    /// Authority empowered to discharge the approval.
    pub authority: ApprovalAuthority,
}

/// Reasoned response to `POST /v1/authorize`.
///
/// Mirrors the engine's decision trace on the wire: the three-valued decision, a
/// stable snake_case reason code, and the ids of the grants and roles that
/// produced the deciding effect, so an audit/debug surface needs no second round
/// trip. A `require_approval` decision additionally carries the
/// [`ApprovalObligation`] the caller must discharge.
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
    /// Approval obligation, present iff `decision` is `require_approval`. The
    /// caller discharges it product-side or as a capability token bound to its
    /// `obligation_id`; an allow or deny carries none.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub obligation: Option<ApprovalObligation>,
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
    /// A grant carried by a group and used by any principal in the group's live
    /// roster. The roster is the single source of truth, so the grant follows
    /// membership the instant a principal joins or leaves the group.
    Group {
        /// Group id whose roster the grant follows.
        group_id: String,
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

/// Wire shape of a group's live roster in a policy snapshot.
///
/// The roster is the single source of truth for membership: a synced consumer
/// resolves a principal's groups from these entries at evaluation, so joining or
/// leaving a group changes effective permissions immediately with no
/// re-expansion. A `Group` is never a principal — these members are the
/// principals the group's grants and role bindings reach.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GroupRosterSnapshot {
    /// Group id whose roster this captures.
    pub group_id: String,
    /// Member principals, in stable order.
    pub members: Vec<PrincipalRef>,
}

/// Wire shape of a group role binding in a policy snapshot.
///
/// A group role binding lets every principal in the group's roster use the
/// role's grants at the binding scope and anything beneath it — the kernel of a
/// product **Team** (`Group` roster + a scope + this binding).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GroupRoleBindingSnapshot {
    /// Group whose roster holds the role.
    pub group_id: String,
    /// Role granted to the group's members.
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
    /// Permanently retired resources. No grant may authorize an exact retired resource.
    #[serde(default)]
    pub retired_resources: Vec<RetiredResource>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RetiredResource {
    pub resource_type: ResourceType,
    pub resource_id: ResourceId,
}

/// Wire shape of one resource type a consumer registers.
///
/// Mirrors the core resource-type definition: the type's own discriminator, the
/// type it nests under (documenting the intended hierarchy shape), and the
/// actions it contributes to the open action catalog. The concrete per-instance
/// parent is still carried separately as a [`ResourceParentEdge`], because a leaf
/// instance may nest under a well-known scope rather than another resource.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ResourceTypeRegistration {
    /// The resource type this entry declares.
    pub resource_type: ResourceType,
    /// The resource type this one nests under, if any.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub parent_type: Option<ResourceType>,
    /// Actions defined on the type, folded into the open action catalog.
    #[serde(default)]
    pub actions: Vec<ActionKey>,
}

/// Reusable resource-model vocabulary and in-process edge registration.
///
/// A consumer teaches IAM its hierarchy and vocabulary **as data**: the resource
/// types it anchors grants at, any standalone actions, and the per-instance
/// scope parent edges that let the evaluator resolve open
/// [`ScopeRef::Resource`](crate::ScopeRef::Resource) scopes through the same
/// ancestor walk used for the well-known scopes. The guarded daemon route
/// wraps this in [`ProductResourceModelRequest`] and accepts vocabulary only;
/// instance edges must use a versioned [`ResourceProjectionBatch`].
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct ResourceModelRegistration {
    /// Resource types the consumer registers, with their declared actions.
    #[serde(default)]
    pub resource_types: Vec<ResourceTypeRegistration>,
    /// Standalone actions registered into the open catalog.
    #[serde(default)]
    pub actions: Vec<ActionKey>,
    /// Per-instance scope parent edges anchoring resources in the hierarchy.
    #[serde(default)]
    pub edges: Vec<ResourceParentEdge>,
}

/// Response to `POST /v1/authz/resource-model`.
///
/// Returns the policy version the registration advanced to, so a local-mode
/// consumer knows the snapshot it must reach before the registered resources
/// resolve identically in-process.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct ResourceModelRegistered {
    /// Monotonic policy version after the registration was applied.
    pub version: u64,
}

/// Product-scoped vocabulary registration for the daemon's guarded route.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProductResourceModelRequest {
    pub product_id: ProductId,
    pub resource_model: ResourceModelRegistration,
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
    /// Live group rosters resolved at evaluation. Defaulted for snapshots minted
    /// before groups became a first-class subject.
    #[serde(default)]
    pub group_rosters: Vec<GroupRosterSnapshot>,
    /// Group role bindings in policy order. Defaulted for older snapshots.
    #[serde(default)]
    pub group_role_bindings: Vec<GroupRoleBindingSnapshot>,
    /// Scope-graph parent links.
    pub scope_graph: ScopeGraphSnapshot,
    /// Active, immutable authorization profiles whose action/scope rules the
    /// local evaluator must enforce. Empty preserves pre-profile compatibility.
    #[serde(default)]
    pub active_profiles: Vec<crate::AuthorizationProfile>,
}

/// A namespace's active signer set, served under the policy version fence.
///
/// `GET /v1/namespaces/{namespace_id}/signers` returns this so a registry
/// consumer (Pack Hub) can cache the namespace's trusted signing keys and
/// re-fetch only when `version` advances. It carries the *same* fence as
/// [`PolicySnapshot`], so a signer registration or revocation propagates on the
/// next sync — verification stays possible offline while revocation is never
/// stale by more than one fence step. Only public key material is ever carried;
/// IAM is not a secrets store.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SignerSetSnapshot {
    /// Namespace whose signer set this captures.
    pub namespace_id: NamespaceId,
    /// Monotonic version fence the signer set was captured at, shared with the
    /// authorization [`PolicySnapshot`] so consumers cache both behind one fence.
    pub version: u64,
    /// Active signer keys, ordered by key id for a deterministic sequence.
    pub signers: Vec<SignerKey>,
}

/// The grant/edge effect of creating one product resource, propagated to IAM so
/// the authorization plane stays consistent with the consumer's domain row.
///
/// When a remote consumer creates a Workspace/Project/Issue it must also write
/// the scope edges and grants that make the new resource authorizable. The
/// consumer cannot write both its own database and IAM's atomically, so it
/// records this payload in a **transactional outbox** alongside the domain row
/// (one local transaction) and propagates it asynchronously (see
/// [ADR-0004](../adr/0004-consumers-reuse-iam-authz.md) #4). An embedded
/// consumer applies the same payload directly inside the single shared-database
/// transaction instead.
///
/// The legacy applier upserts grants and edges by their own ids. It does not
/// persist the idempotency key or enforce the carried epoch. Consumers that
/// need replacement, revocation, or retirement must use a persisted
/// [`ResourceProjectionBatch`] stream instead.
/// Eventual consistency is safe because authorization fails closed: until this
/// payload lands, a request against the new resource simply matches no grant and
/// is denied — it never over-permits.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct ResourceProvision {
    /// Deterministic dedup key for the resource-create event (e.g. the resource
    /// id), so an at-least-once redelivery collapses to a no-op.
    pub idempotency_key: String,
    /// Consumer's resource epoch at mint time; the legacy applier ignores it.
    pub epoch: u64,
    /// Grants that make the new resource authorizable, upserted by grant id.
    pub grants: Vec<GrantSnapshot>,
    /// Scope-graph parent edges anchoring the new resource in the hierarchy.
    pub scope_edges: Vec<ResourceParentEdge>,
}

/// Complete desired authorization state for one product-owned projection stream.
///
/// `projection_id` is stable across changes to the same campus or staff member;
/// `epoch` increases on each change. IAM atomically replaces grants and edges
/// owned by that stream, so a delayed older delivery cannot restore retired
/// access. This is the wire body for `POST /v1/authz/resource-provisions`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ResourceProjectionBatch {
    pub product_id: ProductId,
    pub org_id: OrgId,
    pub projection_id: String,
    pub idempotency_key: String,
    pub epoch: u64,
    pub grants: Vec<GrantSnapshot>,
    pub scope_edges: Vec<ResourceParentEdge>,
    pub retirements: Vec<ResourceRetirement>,
}

/// Retire one product resource and the grants that made it authorizable.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ResourceRetirement {
    pub resource_type: ResourceType,
    pub resource_id: ResourceId,
    pub grant_ids: Vec<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ResourceProjectionDisposition {
    Applied,
    Replayed,
    Stale,
}

/// IAM policy version and disposition returned for the submitted stream epoch.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ResourceProjectionReceipt {
    pub idempotency_key: String,
    pub epoch: u64,
    pub version: u64,
    pub disposition: ResourceProjectionDisposition,
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
            obligation: None,
        };
        let json = serde_json::to_string(&outcome).unwrap();
        let parsed: AuthorizationOutcome = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed, outcome);
        assert!(json.contains("allowed_by_grant"));
        // An allow carries no obligation, and the field is omitted on the wire.
        assert!(!json.contains("obligation"));
    }

    #[test]
    fn require_approval_outcome_carries_its_obligation_envelope() {
        let outcome = AuthorizationOutcome {
            decision: AuthorizationDecision::RequireApproval,
            reason: "needs_approval".into(),
            matched_grants: vec!["g_gate".into()],
            matched_roles: vec![],
            obligation: Some(ApprovalObligation {
                obligation_id: "obl_abc123".into(),
                policy_id: "g_gate".into(),
                authority: ApprovalAuthority {
                    scope: ScopeRef::Namespace {
                        namespace_id: NamespaceId("acme".into()),
                    },
                },
            }),
        };
        let json = serde_json::to_string(&outcome).unwrap();
        let parsed: AuthorizationOutcome = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed, outcome);
        let obligation = parsed.obligation.expect("require_approval carries one");
        assert_eq!(obligation.obligation_id, "obl_abc123");
        assert_eq!(obligation.policy_id, "g_gate");
    }

    #[test]
    fn outcome_without_obligation_field_still_deserializes() {
        // A payload written before the obligation envelope existed (an allow with
        // no `obligation` key) still parses, defaulting the field to absent.
        let json = r#"{"decision":"allow","reason":"allowed_by_grant",
            "matched_grants":["g1"],"matched_roles":[]}"#;
        let parsed: AuthorizationOutcome = serde_json::from_str(json).unwrap();
        assert_eq!(parsed.decision, AuthorizationDecision::Allow);
        assert!(parsed.obligation.is_none());
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
            group_rosters: vec![GroupRosterSnapshot {
                group_id: "eng".into(),
                members: vec![PrincipalRef::Account {
                    account_id: AccountId("acct_1".into()),
                }],
            }],
            group_role_bindings: vec![GroupRoleBindingSnapshot {
                group_id: "eng".into(),
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
                retired_resources: Vec::new(),
            },
            active_profiles: Vec::new(),
        };
        let json = serde_json::to_string(&snapshot).unwrap();
        let parsed: PolicySnapshot = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed, snapshot);
    }

    #[test]
    fn signer_set_snapshot_round_trips_through_json() {
        use crate::{
            SignerKey, SignerKeyAlgorithm, SignerKeyFingerprint, SignerKeyId, SignerKeyStatus,
            Timestamp,
        };
        let snapshot = SignerSetSnapshot {
            namespace_id: NamespaceId("acme".into()),
            version: 9,
            signers: vec![SignerKey {
                id: SignerKeyId("key_1".into()),
                namespace_id: NamespaceId("acme".into()),
                fingerprint: SignerKeyFingerprint("fp_abc".into()),
                algorithm: SignerKeyAlgorithm::Ed25519,
                public_key: "base64-public-key".into(),
                status: SignerKeyStatus::Active,
                label: Some("release signer".into()),
                registered_at: Timestamp("2026-06-20T00:00:00Z".into()),
                revoked_at: None,
            }],
        };
        let json = serde_json::to_string(&snapshot).unwrap();
        let parsed: SignerSetSnapshot = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed, snapshot);
        // The version fence is carried so a consumer can cache behind it.
        assert_eq!(parsed.version, 9);
    }

    #[test]
    fn resource_model_registration_round_trips_through_json() {
        let registration = ResourceModelRegistration {
            resource_types: vec![ResourceTypeRegistration {
                resource_type: ResourceType("issue".into()),
                parent_type: None,
                actions: vec![
                    ActionKey("issue.read".into()),
                    ActionKey("issue.close".into()),
                ],
            }],
            actions: vec![ActionKey("issue.assign".into())],
            edges: vec![ResourceParentEdge {
                resource_type: ResourceType("issue".into()),
                resource_id: ResourceId("42".into()),
                parent: ScopeRef::Namespace {
                    namespace_id: NamespaceId("acme".into()),
                },
            }],
        };
        let json = serde_json::to_string(&registration).unwrap();
        let parsed: ResourceModelRegistration = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed, registration);

        let registered = ResourceModelRegistered { version: 7 };
        let json = serde_json::to_string(&registered).unwrap();
        assert_eq!(
            serde_json::from_str::<ResourceModelRegistered>(&json).unwrap(),
            registered
        );
    }

    #[test]
    fn resource_model_registration_defaults_empty_fields() {
        // A consumer may register only edges (or only types); omitted arrays
        // default to empty rather than failing to deserialize.
        let parsed: ResourceModelRegistration = serde_json::from_str(r#"{"edges":[]}"#).unwrap();
        assert_eq!(parsed, ResourceModelRegistration::default());
    }

    #[test]
    fn resource_provision_round_trips_through_json() {
        let provision = ResourceProvision {
            idempotency_key: "issue:42".into(),
            epoch: 9,
            grants: vec![GrantSnapshot {
                id: "g_issue_42_owner".into(),
                subject: GrantSubjectRef::Principal {
                    principal: PrincipalRef::Account {
                        account_id: AccountId("ada".into()),
                    },
                },
                action_pattern: "issue.*".into(),
                scope: ScopeRef::Resource {
                    resource_type: ResourceType("issue".into()),
                    resource_id: ResourceId("42".into()),
                },
                effect: GrantEffect::Allow,
            }],
            scope_edges: vec![ResourceParentEdge {
                resource_type: ResourceType("issue".into()),
                resource_id: ResourceId("42".into()),
                parent: ScopeRef::Namespace {
                    namespace_id: NamespaceId("acme".into()),
                },
            }],
        };
        let json = serde_json::to_string(&provision).unwrap();
        let parsed: ResourceProvision = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed, provision);
    }

    #[test]
    fn product_projection_wire_requires_stream_and_round_trips_retirement() {
        let body = serde_json::json!({
            "product_id": "tutor", "org_id": "acme", "projection_id": "campus:c1",
            "idempotency_key": "campus:c1:2", "epoch": 2,
            "grants": [], "scope_edges": [],
            "retirements": [{"resource_type": "tutor.campus", "resource_id": "c1",
                "grant_ids": ["tutor:campus:c1:creator"]}]
        });
        let parsed: ResourceProjectionBatch = serde_json::from_value(body.clone()).unwrap();
        assert_eq!(serde_json::to_value(&parsed).unwrap(), body);
        assert_eq!(parsed.product_id.as_str(), "tutor");
        assert_eq!(parsed.retirements.len(), 1);
        let mut missing_stream = body.clone();
        missing_stream
            .as_object_mut()
            .unwrap()
            .remove("projection_id");
        assert!(serde_json::from_value::<ResourceProjectionBatch>(missing_stream).is_err());
        let mut unknown = body;
        unknown["untrusted_owner"] = serde_json::json!("other");
        assert!(serde_json::from_value::<ResourceProjectionBatch>(unknown).is_err());
        let receipt = ResourceProjectionReceipt {
            idempotency_key: parsed.idempotency_key,
            epoch: parsed.epoch,
            version: 7,
            disposition: ResourceProjectionDisposition::Replayed,
        };
        assert_eq!(
            serde_json::to_value(receipt).unwrap()["disposition"],
            "replayed"
        );
    }

    #[test]
    fn snapshot_without_group_fields_defaults_to_empty() {
        // A snapshot minted before groups became a subject omits the new fields;
        // it must still deserialize, with empty group rosters and bindings.
        let legacy = r#"{"version":1,"grants":[],"role_bindings":[],"scope_graph":{"namespace_orgs":[],"workspace_orgs":[],"resource_parents":[]}}"#;
        let parsed: PolicySnapshot = serde_json::from_str(legacy).unwrap();
        assert!(parsed.group_rosters.is_empty());
        assert!(parsed.group_role_bindings.is_empty());
        assert!(parsed.scope_graph.retired_resources.is_empty());
    }
}
