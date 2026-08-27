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
//! [`OrgRepository`](crate::OrgRepository), [`GroupRepository`](crate::GroupRepository), and
//! [`RoleRepository`](crate::RoleRepository) repository contracts, and policy administration over them lives
//! in the server's Policy Administration Point.

use awaken_iam_contract::{
    DirectoryNodeId, DirectoryNodeView, OrgId, PrincipalRef, ProductSpacePlacement, Timestamp,
};

use crate::{ActionPattern, RoleId};

/// One arbitrary-depth, user-visible placement node inside an organization.
///
/// Directory placement is deliberately independent of product identity and
/// authorization scope. The aggregate owns display metadata and its parent
/// edge; products retain their own stable space ids through
/// [`ProductSpacePlacement`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DirectoryNode {
    pub id: DirectoryNodeId,
    pub org_id: OrgId,
    pub parent_id: Option<DirectoryNodeId>,
    pub name: String,
    pub slug: String,
    pub description: Option<String>,
    pub archived: bool,
    pub created_at: Timestamp,
    pub updated_at: Timestamp,
}

impl From<DirectoryNodeView> for DirectoryNode {
    fn from(node: DirectoryNodeView) -> Self {
        Self {
            id: node.id,
            org_id: node.org_id,
            parent_id: node.parent_id,
            name: node.name,
            slug: node.slug,
            description: node.description,
            archived: node.archived,
            created_at: node.created_at,
            updated_at: node.updated_at,
        }
    }
}

impl From<DirectoryNode> for DirectoryNodeView {
    fn from(node: DirectoryNode) -> Self {
        Self {
            id: node.id,
            org_id: node.org_id,
            parent_id: node.parent_id,
            name: node.name,
            slug: node.slug,
            description: node.description,
            archived: node.archived,
            created_at: node.created_at,
            updated_at: node.updated_at,
        }
    }
}

/// Why a directory node or binding is invalid before persistence.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum DirectoryInvariant {
    #[error("directory node id must not be empty")]
    EmptyNodeId,
    #[error("directory node name must not be empty")]
    EmptyName,
    #[error("directory slug must be lowercase alphanumeric with internal hyphens")]
    InvalidSlug,
    #[error("a directory node cannot be its own parent")]
    SelfParent,
    #[error("product namespace and space id must not be empty")]
    EmptyProductSpace,
    #[error("product-space binding must target the same organization as its node")]
    CrossTenantBinding,
}

impl DirectoryNode {
    /// Validate representation invariants that do not require repository state.
    pub fn validate(&self) -> Result<(), DirectoryInvariant> {
        if self.id.0.trim().is_empty() {
            return Err(DirectoryInvariant::EmptyNodeId);
        }
        if self.name.trim().is_empty() {
            return Err(DirectoryInvariant::EmptyName);
        }
        if !directory_slug_is_valid(&self.slug) {
            return Err(DirectoryInvariant::InvalidSlug);
        }
        if self.parent_id.as_ref() == Some(&self.id) {
            return Err(DirectoryInvariant::SelfParent);
        }
        Ok(())
    }

    /// Validate an optional product-space placement against this node.
    pub fn validate_placement(
        &self,
        placement: &ProductSpacePlacement,
    ) -> Result<(), DirectoryInvariant> {
        if placement.product_space.product.trim().is_empty()
            || placement.product_space.space_id.trim().is_empty()
        {
            return Err(DirectoryInvariant::EmptyProductSpace);
        }
        if placement.org_id != self.org_id || placement.node_id != self.id {
            return Err(DirectoryInvariant::CrossTenantBinding);
        }
        Ok(())
    }
}

fn directory_slug_is_valid(raw: &str) -> bool {
    let bytes = raw.as_bytes();
    if bytes.is_empty() || bytes.len() > 50 {
        return false;
    }
    let alnum = |byte: u8| byte.is_ascii_lowercase() || byte.is_ascii_digit();
    alnum(bytes[0])
        && alnum(bytes[bytes.len() - 1])
        && bytes.iter().all(|byte| alnum(*byte) || *byte == b'-')
}

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

    fn node(parent_id: Option<&str>) -> DirectoryNode {
        DirectoryNode {
            id: DirectoryNodeId("node-a".into()),
            org_id: OrgId("org-a".into()),
            parent_id: parent_id.map(|id| DirectoryNodeId(id.into())),
            name: "Engineering".into(),
            slug: "engineering".into(),
            description: None,
            archived: false,
            created_at: ts(),
            updated_at: ts(),
        }
    }

    #[test]
    fn directory_node_and_binding_validate_without_fixed_levels() {
        // Cause/effect graph: C1 valid metadata, C2 parent is self, C3 binding
        // product identity is empty, C4 binding tenant/node disagrees. Effects:
        // E1 accept any non-self parent (no Org/Workspace/Project tier enum),
        // E2 reject a one-node cycle, E3 reject an unqualified product space,
        // E4 reject cross-tenant or wrong-node placement. Rules R1-R4 exercise
        // every representation invariant before a repository transaction.
        let valid = node(Some("arbitrary-parent"));
        assert_eq!(valid.validate(), Ok(()));

        let self_parent = node(Some("node-a"));
        assert_eq!(self_parent.validate(), Err(DirectoryInvariant::SelfParent));

        let mut binding = ProductSpacePlacement {
            product_space: awaken_iam_contract::ProductSpaceRef {
                product: String::new(),
                space_id: "space-a".into(),
            },
            org_id: valid.org_id.clone(),
            node_id: valid.id.clone(),
        };
        assert_eq!(
            valid.validate_placement(&binding),
            Err(DirectoryInvariant::EmptyProductSpace)
        );
        binding.product_space.product = "agents".into();
        binding.org_id = OrgId("org-b".into());
        assert_eq!(
            valid.validate_placement(&binding),
            Err(DirectoryInvariant::CrossTenantBinding)
        );
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
