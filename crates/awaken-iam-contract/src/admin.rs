//! Policy-administration wire DTOs.
//!
//! These are the request/response shapes the standalone daemon serves under
//! `/v1/admin/*`, the console <-> remote-daemon management seam a remote control
//! plane administers the authorization model through (organizations, groups,
//! roles, grants, and memberships). Like the rest of this crate they are DTOs
//! only: the policy-administration logic lives in `awaken-iam-server`'s Policy
//! Administration Point, which maps these onto the `awaken-iam-core` aggregates.
//!
//! Ids that live in `awaken-iam-core` (group, role) are carried as plain strings
//! here so the contract stays free of any dependency on the core crate, matching
//! the convention the snapshot DTOs already use (a grant's `role_id` /
//! `group_id`). Grant issue and membership reuse the snapshot grant/role-binding
//! shapes ([`GrantSnapshot`](crate::GrantSnapshot) and
//! [`RoleBindingSnapshot`](crate::RoleBindingSnapshot)) rather than duplicating
//! them.

use serde::{Deserialize, Serialize};

use crate::{AccountId, OrgId, PrincipalRef, ScopeRef, Timestamp};

/// Stable identity of one user-visible node in an organization's directory.
///
/// A node is placement metadata only. Product business identity and IAM scope
/// identity never derive from this value, so moving a node cannot rewrite a
/// product aggregate or silently change authorization.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct DirectoryNodeId(pub String);

/// Stable, product-qualified identity of a product-owned space.
///
/// `product` is an open namespace (`"agents"`, `"workforce"`, ...), not an IAM
/// enum. `space_id` is opaque to IAM and remains stable when its directory node
/// moves or is renamed.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct ProductSpaceRef {
    pub product: String,
    pub space_id: String,
}

/// Public projection of one arbitrary-depth directory node.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DirectoryNodeView {
    pub id: DirectoryNodeId,
    /// Immutable security, billing, and data-partition root.
    pub org_id: OrgId,
    /// Direct parent inside the same organization; `None` denotes a root node.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub parent_id: Option<DirectoryNodeId>,
    pub name: String,
    pub slug: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    #[serde(default)]
    pub archived: bool,
    pub created_at: Timestamp,
    pub updated_at: Timestamp,
}

/// Placement of a stable product space in the user-visible directory.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProductSpacePlacement {
    pub product_space: ProductSpaceRef,
    /// Immutable tenant partition of the product space and target node.
    pub org_id: OrgId,
    pub node_id: DirectoryNodeId,
}

/// Create one user-managed folder in an organization's Directory.
///
/// Product-owned spaces use [`EnsureProductSpacePlacement`] instead. Keeping
/// those commands separate leaves IAM as the only authority that derives a
/// product node id, canonical slug, timestamps, active state, and audit data.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CreateDirectoryNode {
    pub org_id: OrgId,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub parent_id: Option<DirectoryNodeId>,
    pub name: String,
    pub preferred_slug: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
}

/// Idempotently place one product-owned space in the user-visible Directory.
///
/// The optional parent is another stable product-space identity rather than a
/// Directory node id. This preserves the product relationship without giving
/// a product authority over IAM-generated node identifiers.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EnsureProductSpacePlacement {
    pub product_space: ProductSpaceRef,
    pub org_id: OrgId,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub parent_product_space: Option<ProductSpaceRef>,
    pub name: String,
    pub preferred_slug: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
}

/// Move one directory node without changing product-space or authorization ids.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MoveDirectoryNode {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub parent_id: Option<DirectoryNodeId>,
}

/// Replace user-visible metadata without changing placement or product identity.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct UpdateDirectoryNode {
    pub name: String,
    pub slug: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
}

/// Query the direct children of one directory parent in an organization.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DirectoryChildrenQuery {
    pub org_id: OrgId,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub parent_id: Option<DirectoryNodeId>,
}

/// Directory mutation acknowledgement, fenced independently from IAM policy.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct DirectoryMutationAck {
    pub revision: u64,
}

/// Result of creating one user-managed Directory folder.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DirectoryNodeMutationResult {
    pub revision: u64,
    pub node: DirectoryNodeView,
}

/// Result of the canonical product-space placement command.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProductSpacePlacementResult {
    pub revision: u64,
    pub node: DirectoryNodeView,
    pub placement: ProductSpacePlacement,
    /// `true` only when this command created the node and placement. Exact
    /// retries return the existing user-managed presentation unchanged.
    pub created: bool,
}

/// Stable identifier of an organization invitation.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct InvitationId(pub String);

/// Authoritative invitation lifecycle. Delivery is deliberately not a state:
/// mail can be retried while the invitation remains pending.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum InvitationStatus {
    Pending,
    Accepted,
    Revoked,
    Expired,
}

/// One role IAM will materialize when an invitation is accepted.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct InvitationBinding {
    pub role_id: String,
    pub scope: ScopeRef,
}

/// Public projection of IAM's invitation aggregate. The token hash is never
/// exposed; a clear token appears only in create/resend responses.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct InvitationView {
    pub id: InvitationId,
    pub org_id: OrgId,
    pub email: String,
    pub bindings: Vec<InvitationBinding>,
    pub invited_by: PrincipalRef,
    pub status: InvitationStatus,
    pub expires_at: Timestamp,
    pub created_at: Timestamp,
    pub updated_at: Timestamp,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub accepted_by_account_id: Option<AccountId>,
}

/// Idempotent invitation creation command.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CreateInvitation {
    pub idempotency_key: String,
    pub org_id: OrgId,
    pub email: String,
    pub bindings: Vec<InvitationBinding>,
    pub invited_by: PrincipalRef,
    pub expires_at: Timestamp,
}

/// Invitation plus the one-time token a delivery adapter must send.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct IssuedInvitation {
    pub invitation: InvitationView,
    pub token: String,
    pub version: u64,
}

/// Organization-scoped invitation list query.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct InvitationQuery {
    pub org_id: OrgId,
}

/// Rotate a pending invitation token and set its new expiry.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ResendInvitation {
    pub expires_at: Timestamp,
}

/// Authenticated acceptance command from a trusted relying party. The party
/// must obtain `verified_email` from IAM's signed-token UserInfo endpoint; it
/// must never accept a caller-entered email as this assertion.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AcceptInvitation {
    pub account_id: AccountId,
    pub verified_email: String,
    pub token: String,
}

/// Successful acceptance response and the PDP visibility fence.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AcceptedInvitation {
    pub invitation: InvitationView,
    pub version: u64,
}

/// Internal PAP query for one principal's live role bindings.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MembershipQuery {
    pub principal: PrincipalRef,
}

/// Internal PAP query for exact role bindings at one scope.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ScopeMembershipQuery {
    pub scope: ScopeRef,
}

/// Atomically replace one caller-owned family of exact-scope role bindings.
///
/// `managed_role_ids` declares the finite role family the caller is authorized
/// to manage. IAM removes only matching roles for `principal` at the exact
/// `scope`, then materializes `replacement_role_ids` in the same repository
/// transaction. Replacement roles must be a subset of the managed family.
/// Unrelated roles and bindings at parent, child, or sibling scopes are never
/// touched.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReplaceScopedMemberships {
    pub principal: PrincipalRef,
    pub scope: ScopeRef,
    pub managed_role_ids: Vec<String>,
    #[serde(default)]
    pub replacement_role_ids: Vec<String>,
}

/// Wire shape of an organization administered through `/v1/admin/orgs`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct OrgView {
    /// Stable organization id, also usable as an org scope anchor.
    pub id: OrgId,
    /// Optional human-readable name.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub display_name: Option<String>,
    /// The single owner principal.
    pub owner: PrincipalRef,
    /// Creation timestamp.
    pub created_at: Timestamp,
    /// Last metadata update timestamp.
    pub updated_at: Timestamp,
}

/// Wire shape of a group administered through `/v1/admin/groups`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GroupView {
    /// Stable group id (a core id, carried as a string).
    pub id: String,
    /// Organization the group belongs to.
    pub org: OrgId,
    /// Optional human-readable name.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub display_name: Option<String>,
    /// Member principals, in stable order.
    #[serde(default)]
    pub members: Vec<PrincipalRef>,
    /// Creation timestamp.
    pub created_at: Timestamp,
    /// Last metadata update timestamp.
    pub updated_at: Timestamp,
}

/// Wire shape of a role definition administered through `/v1/admin/roles`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RoleView {
    /// Stable role id (a core id, carried as a string).
    pub id: String,
    /// Optional human-readable name.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub display_name: Option<String>,
    /// Action patterns the role carries.
    #[serde(default)]
    pub action_patterns: Vec<String>,
    /// Creation timestamp.
    pub created_at: Timestamp,
    /// Last metadata update timestamp.
    pub updated_at: Timestamp,
}

/// Acknowledgement returned by every `/v1/admin/*` mutation.
///
/// Carries the authorization snapshot `version` the mutation advanced to, so the
/// administering caller (and any synced consumer polling
/// `GET /v1/authz/snapshot`) knows the fence the change is visible behind. It
/// mirrors [`ResourceModelRegistered`](crate::ResourceModelRegistered): an
/// additive field rather than a bespoke envelope per route.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct AdminMutationAck {
    /// Monotonic snapshot version after the mutation was applied.
    pub version: u64,
}

#[cfg(test)]
mod tests {
    use super::*;

    fn account(id: &str) -> PrincipalRef {
        PrincipalRef::Account {
            account_id: crate::AccountId(id.into()),
        }
    }

    #[test]
    fn org_view_round_trips_and_omits_absent_name() {
        let view = OrgView {
            id: OrgId("acme".into()),
            display_name: None,
            owner: account("ada"),
            created_at: Timestamp("2026-06-21T00:00:00Z".into()),
            updated_at: Timestamp("2026-06-21T00:00:00Z".into()),
        };
        let json = serde_json::to_string(&view).unwrap();
        assert!(!json.contains("display_name"));
        assert_eq!(serde_json::from_str::<OrgView>(&json).unwrap(), view);
    }

    #[test]
    fn group_and_role_views_round_trip() {
        let group = GroupView {
            id: "eng".into(),
            org: OrgId("acme".into()),
            display_name: Some("Engineering".into()),
            members: vec![account("ada")],
            created_at: Timestamp("2026-06-21T00:00:00Z".into()),
            updated_at: Timestamp("2026-06-21T00:00:00Z".into()),
        };
        let json = serde_json::to_string(&group).unwrap();
        assert_eq!(serde_json::from_str::<GroupView>(&json).unwrap(), group);

        let role = RoleView {
            id: "publisher".into(),
            display_name: None,
            action_patterns: vec!["pack.*".into()],
            created_at: Timestamp("2026-06-21T00:00:00Z".into()),
            updated_at: Timestamp("2026-06-21T00:00:00Z".into()),
        };
        let json = serde_json::to_string(&role).unwrap();
        assert_eq!(serde_json::from_str::<RoleView>(&json).unwrap(), role);
    }

    #[test]
    fn group_view_defaults_empty_members() {
        let parsed: GroupView =
            serde_json::from_str(r#"{"id":"eng","org":"acme","created_at":"t","updated_at":"t"}"#)
                .unwrap();
        assert!(parsed.members.is_empty());
    }

    #[test]
    fn mutation_ack_round_trips() {
        let ack = AdminMutationAck { version: 7 };
        let json = serde_json::to_string(&ack).unwrap();
        assert_eq!(
            serde_json::from_str::<AdminMutationAck>(&json).unwrap(),
            ack
        );
    }

    #[test]
    fn directory_wire_shape_keeps_placement_separate_from_product_identity() {
        // Cause/effect decision table: C1 optional parent/description omitted
        // -> E1 root placement with no description; C2 open product namespace
        // -> E2 lossless round-trip without an enum; C3 move omits parent -> E3
        // move to root. W1-W3 pin the shared embedded/HTTP published language.
        let json = r#"{
          "product_space":{"product":"future-product","space_id":"space-a"},
          "org_id":"acme", "name":"Team", "preferred_slug":"Team"
        }"#;
        let command: EnsureProductSpacePlacement = serde_json::from_str(json).unwrap();
        assert!(command.parent_product_space.is_none());
        assert!(command.description.is_none());
        assert_eq!(command.product_space.product, "future-product");
        assert_eq!(
            serde_json::from_str::<EnsureProductSpacePlacement>(
                &serde_json::to_string(&command).unwrap()
            )
            .unwrap(),
            command
        );
        let move_to_root: MoveDirectoryNode = serde_json::from_str("{}").unwrap();
        assert!(move_to_root.parent_id.is_none());
    }
}
