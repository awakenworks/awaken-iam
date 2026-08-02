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
pub struct InvitationDto {
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
    pub invitation: InvitationDto,
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
    pub invitation: InvitationDto,
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

/// Wire shape of an organization administered through `/v1/admin/orgs`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct OrgDto {
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
pub struct GroupDto {
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
pub struct RoleDto {
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
    fn org_dto_round_trips_and_omits_absent_name() {
        let dto = OrgDto {
            id: OrgId("acme".into()),
            display_name: None,
            owner: account("ada"),
            created_at: Timestamp("2026-06-21T00:00:00Z".into()),
            updated_at: Timestamp("2026-06-21T00:00:00Z".into()),
        };
        let json = serde_json::to_string(&dto).unwrap();
        assert!(!json.contains("display_name"));
        assert_eq!(serde_json::from_str::<OrgDto>(&json).unwrap(), dto);
    }

    #[test]
    fn group_and_role_dtos_round_trip() {
        let group = GroupDto {
            id: "eng".into(),
            org: OrgId("acme".into()),
            display_name: Some("Engineering".into()),
            members: vec![account("ada")],
            created_at: Timestamp("2026-06-21T00:00:00Z".into()),
            updated_at: Timestamp("2026-06-21T00:00:00Z".into()),
        };
        let json = serde_json::to_string(&group).unwrap();
        assert_eq!(serde_json::from_str::<GroupDto>(&json).unwrap(), group);

        let role = RoleDto {
            id: "publisher".into(),
            display_name: None,
            action_patterns: vec!["pack.*".into()],
            created_at: Timestamp("2026-06-21T00:00:00Z".into()),
            updated_at: Timestamp("2026-06-21T00:00:00Z".into()),
        };
        let json = serde_json::to_string(&role).unwrap();
        assert_eq!(serde_json::from_str::<RoleDto>(&json).unwrap(), role);
    }

    #[test]
    fn group_dto_defaults_empty_members() {
        let parsed: GroupDto =
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
}
