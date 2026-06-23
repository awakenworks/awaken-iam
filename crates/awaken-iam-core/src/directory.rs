//! Organization, group, and role directory aggregates.
//!
//! These are the small supporting-subdomain aggregates the
//! [domain model](../../../docs/design/domain-model.md) names alongside the
//! authorization core: an [`Organization`] is an ownership root, a [`Group`] is a
//! named bundle of member principals, and a [`RoleDef`] is a reusable bundle of
//! action patterns a [`RoleBinding`](crate::RoleBinding) (membership) attaches to
//! a principal at a scope.
//!
//! Each aggregate is a consistency boundary holding one invariant cluster and
//! references other aggregates only by id — an [`Organization`] never loads its
//! groups, a [`Group`] holds principal references rather than account internals.
//! The aggregates are pure data; persistence is the responsibility of the
//! [`OrgRepo`](crate::OrgRepo), [`GroupRepo`](crate::GroupRepo), and
//! [`RoleRepo`](crate::RoleRepo) ports, and policy administration over them lives
//! in the server's Policy Administration Point.

use awaken_iam_contract::{OrgId, PrincipalRef, Timestamp};

use crate::{ActionPattern, RoleId};

/// Identifier of a [`Group`] (a named bundle of member principals).
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct GroupId(pub String);

/// An organization: an ownership root in the scope hierarchy.
///
/// The invariant is that an organization has exactly one owner principal at all
/// times; ownership transfers by replacing [`Organization::owner`], never by
/// leaving it absent.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Organization {
    /// Stable organization id, also usable as an [`crate::ScopeRef::Org`] anchor.
    pub id: OrgId,
    /// Optional human-readable name.
    pub display_name: Option<String>,
    /// The single owner principal.
    pub owner: PrincipalRef,
    /// Creation timestamp.
    pub created_at: Timestamp,
    /// Last metadata update timestamp.
    pub updated_at: Timestamp,
}

/// A group: a named bundle of member principals within an organization.
///
/// Membership is expressed as principal references resolved in the domain, so a
/// group never loads an account's internals. Members are deduplicated and kept in
/// a stable order so "who is in this group" is a cheap, deterministic query.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Group {
    /// Stable group id.
    pub id: GroupId,
    /// Organization the group belongs to.
    pub org: OrgId,
    /// Optional human-readable name.
    pub display_name: Option<String>,
    /// Member principals, deduplicated in insertion order.
    pub members: Vec<PrincipalRef>,
    /// Creation timestamp.
    pub created_at: Timestamp,
    /// Last metadata update timestamp.
    pub updated_at: Timestamp,
}

impl Group {
    /// Returns whether `principal` is a member of this group.
    pub fn contains(&self, principal: &PrincipalRef) -> bool {
        self.members.contains(principal)
    }

    /// Add `principal` to the group, returning whether it was newly added.
    ///
    /// Membership is idempotent: re-adding an existing member is a no-op so the
    /// member list never carries duplicates.
    pub fn add_member(&mut self, principal: PrincipalRef) -> bool {
        if self.members.contains(&principal) {
            return false;
        }
        self.members.push(principal);
        true
    }

    /// Remove `principal` from the group, returning whether it was present.
    pub fn remove_member(&mut self, principal: &PrincipalRef) -> bool {
        let before = self.members.len();
        self.members.retain(|member| member != principal);
        self.members.len() != before
    }
}

/// A role definition: a reusable, named bundle of action patterns.
///
/// A role carries the action patterns a principal bound to it (a membership) may
/// exercise. Following the model's "patterns are exact or single-glob; no
/// wildcard-all" invariant, a role may not carry the catch-all `*` pattern — that
/// would make the role a hidden superuser — so [`RoleDef::validate`] rejects it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RoleDef {
    /// Stable role id, referenced by grants and memberships.
    pub id: RoleId,
    /// Optional human-readable name.
    pub display_name: Option<String>,
    /// Action patterns the role carries.
    pub action_patterns: Vec<ActionPattern>,
    /// Creation timestamp.
    pub created_at: Timestamp,
    /// Last metadata update timestamp.
    pub updated_at: Timestamp,
}

/// Reason a [`RoleDef`] failed its invariant check.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum RoleInvariant {
    /// The role carried the catch-all `*` pattern, which is not permitted.
    #[error("role may not carry the catch-all `*` action pattern")]
    WildcardAll,
    /// The role defined no action patterns.
    #[error("role must carry at least one action pattern")]
    Empty,
}

impl RoleDef {
    /// Validate the role's invariants: it must carry at least one action pattern
    /// and may not carry the catch-all `*`.
    pub fn validate(&self) -> Result<(), RoleInvariant> {
        if self.action_patterns.is_empty() {
            return Err(RoleInvariant::Empty);
        }
        if self.action_patterns.iter().any(|pattern| pattern.0 == "*") {
            return Err(RoleInvariant::WildcardAll);
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ts() -> Timestamp {
        Timestamp("2026-06-21T00:00:00Z".into())
    }

    fn account(id: &str) -> PrincipalRef {
        PrincipalRef::Account {
            account_id: awaken_iam_contract::AccountId(id.into()),
        }
    }

    #[test]
    fn group_membership_is_idempotent() {
        let mut group = Group {
            id: GroupId("g".into()),
            org: OrgId("acme".into()),
            display_name: None,
            members: Vec::new(),
            created_at: ts(),
            updated_at: ts(),
        };
        assert!(group.add_member(account("ada")));
        assert!(!group.add_member(account("ada")));
        assert_eq!(group.members.len(), 1);
        assert!(group.contains(&account("ada")));
        assert!(group.remove_member(&account("ada")));
        assert!(!group.remove_member(&account("ada")));
        assert!(group.members.is_empty());
    }

    #[test]
    fn role_rejects_wildcard_all_and_empty() {
        let mut role = RoleDef {
            id: RoleId("publisher".into()),
            display_name: Some("Publisher".into()),
            action_patterns: vec![ActionPattern("pack.*".into())],
            created_at: ts(),
            updated_at: ts(),
        };
        assert_eq!(role.validate(), Ok(()));

        role.action_patterns.push(ActionPattern("*".into()));
        assert_eq!(role.validate(), Err(RoleInvariant::WildcardAll));

        role.action_patterns.clear();
        assert_eq!(role.validate(), Err(RoleInvariant::Empty));
    }
}
