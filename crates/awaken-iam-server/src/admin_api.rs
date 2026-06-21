//! Policy Administration Point (PAP): admin CRUD over the policy stores.
//!
//! This is the framework-agnostic seam that lets an administrator manage the
//! authorization model — organizations, groups, roles, grants, and memberships —
//! on top of the [repository ports](awaken_iam_core). Like [`AuthApi`](crate::AuthApi)
//! and [`AuthzApi`](crate::AuthzApi) it speaks in logical request/response values
//! (the aggregates in [`awaken_iam_core`]) rather than binding to a concrete HTTP
//! framework; a deployment maps these methods onto its router of choice:
//!
//! | Route | Method on [`PolicyAdminApi`] |
//! |---|---|
//! | `POST /v1/admin/orgs` | [`PolicyAdminApi::create_org`] |
//! | `PUT /v1/admin/orgs/{id}` | [`PolicyAdminApi::update_org`] |
//! | `DELETE /v1/admin/orgs/{id}` | [`PolicyAdminApi::delete_org`] |
//! | `GET /v1/admin/orgs` | [`PolicyAdminApi::list_orgs`] |
//! | `POST /v1/admin/groups` | [`PolicyAdminApi::create_group`] |
//! | `PUT /v1/admin/groups/{id}` | [`PolicyAdminApi::update_group`] |
//! | `DELETE /v1/admin/groups/{id}` | [`PolicyAdminApi::delete_group`] |
//! | `POST /v1/admin/roles` | [`PolicyAdminApi::define_role`] |
//! | `PUT /v1/admin/roles/{id}` | [`PolicyAdminApi::update_role`] |
//! | `DELETE /v1/admin/roles/{id}` | [`PolicyAdminApi::delete_role`] |
//! | `POST /v1/admin/grants` | [`PolicyAdminApi::issue_grant`] |
//! | `DELETE /v1/admin/grants/{id}` | [`PolicyAdminApi::revoke_grant`] |
//! | `POST /v1/admin/memberships` | [`PolicyAdminApi::grant_membership`] |
//! | `DELETE /v1/admin/memberships` | [`PolicyAdminApi::revoke_membership`] |
//!
//! Every mutation emits a [`DomainEvent`] that is appended to the audit trail and
//! **bumps the snapshot version**. A local-mode consumer that synchronises the
//! authorization policy through [`AuthzApi::snapshot`](crate::AuthzApi::snapshot)
//! re-fetches whenever the version advances, so an administrative change made
//! here propagates to in-process evaluators on their next poll.

use awaken_iam_contract::{OrgId, PrincipalRef, ScopeRef, Timestamp};
use awaken_iam_core::{
    AuditEvent, AuditSink, Grant, GrantId, GrantRepo, Group, GroupId, GroupRepo, OrgRepo,
    Organization, RepoError, RoleBinding, RoleBindingRepo, RoleDef, RoleId, RoleInvariant,
    RoleRepo,
};

/// A policy-administration domain event.
///
/// Each variant records one state change applied through the
/// [`PolicyAdminApi`]. Events feed the audit trail and bump the snapshot version
/// that invalidates synced consumer caches, matching the domain events named in
/// the [domain model](../../../docs/design/domain-model.md).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DomainEvent {
    /// A new organization was created.
    OrganizationCreated(OrgId),
    /// An existing organization's metadata changed.
    OrganizationUpdated(OrgId),
    /// An organization was deleted.
    OrganizationDeleted(OrgId),
    /// A new group was created.
    GroupCreated(GroupId),
    /// An existing group changed (membership or metadata).
    GroupUpdated(GroupId),
    /// A group was deleted.
    GroupDeleted(GroupId),
    /// A new role was defined.
    RoleDefined(RoleId),
    /// An existing role's patterns or metadata changed.
    RoleUpdated(RoleId),
    /// A role was deleted.
    RoleDeleted(RoleId),
    /// A grant was issued.
    GrantIssued(GrantId),
    /// A grant was revoked.
    GrantRevoked(GrantId),
    /// A principal was granted a role at a scope (a membership).
    MembershipGranted {
        /// Principal that holds the role.
        principal: PrincipalRef,
        /// Role granted to the principal.
        role: RoleId,
        /// Scope at which the binding applies.
        scope: ScopeRef,
    },
    /// A membership was revoked.
    MembershipRevoked {
        /// Principal that held the role.
        principal: PrincipalRef,
        /// Role revoked from the principal.
        role: RoleId,
        /// Scope at which the binding applied.
        scope: ScopeRef,
    },
}

impl DomainEvent {
    /// Stable snake_case action key recorded in the audit trail.
    pub fn action(&self) -> &'static str {
        match self {
            DomainEvent::OrganizationCreated(_) => "org.create",
            DomainEvent::OrganizationUpdated(_) => "org.update",
            DomainEvent::OrganizationDeleted(_) => "org.delete",
            DomainEvent::GroupCreated(_) => "group.create",
            DomainEvent::GroupUpdated(_) => "group.update",
            DomainEvent::GroupDeleted(_) => "group.delete",
            DomainEvent::RoleDefined(_) => "role.define",
            DomainEvent::RoleUpdated(_) => "role.update",
            DomainEvent::RoleDeleted(_) => "role.delete",
            DomainEvent::GrantIssued(_) => "grant.issue",
            DomainEvent::GrantRevoked(_) => "grant.revoke",
            DomainEvent::MembershipGranted { .. } => "membership.grant",
            DomainEvent::MembershipRevoked { .. } => "membership.revoke",
        }
    }

    /// Human-readable detail captured alongside the event in the audit trail.
    pub fn detail(&self) -> String {
        match self {
            DomainEvent::OrganizationCreated(id)
            | DomainEvent::OrganizationUpdated(id)
            | DomainEvent::OrganizationDeleted(id) => format!("org {}", id.0),
            DomainEvent::GroupCreated(id)
            | DomainEvent::GroupUpdated(id)
            | DomainEvent::GroupDeleted(id) => format!("group {}", id.0),
            DomainEvent::RoleDefined(id)
            | DomainEvent::RoleUpdated(id)
            | DomainEvent::RoleDeleted(id) => format!("role {}", id.0),
            DomainEvent::GrantIssued(id) | DomainEvent::GrantRevoked(id) => {
                format!("grant {}", id.0)
            }
            DomainEvent::MembershipGranted {
                principal,
                role,
                scope,
            }
            | DomainEvent::MembershipRevoked {
                principal,
                role,
                scope,
            } => format!("role {} for {principal:?} at {scope:?}", role.0),
        }
    }
}

/// Failure surface for policy-administration operations.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum AdminError {
    /// A create targeted an id that already exists.
    #[error("already exists: {0}")]
    AlreadyExists(String),
    /// An update or delete targeted an id that does not exist.
    #[error("not found: {0}")]
    NotFound(String),
    /// The submitted aggregate violated an invariant.
    #[error("invalid: {0}")]
    Invalid(String),
    /// The backend failed for a reason outside the domain's control.
    #[error("storage backend error: {0}")]
    Backend(String),
}

impl From<RepoError> for AdminError {
    fn from(err: RepoError) -> Self {
        match err {
            RepoError::Conflict(message) => AdminError::AlreadyExists(message),
            RepoError::NotFound(message) => AdminError::NotFound(message),
            RepoError::Backend(message) => AdminError::Backend(message),
        }
    }
}

impl From<RoleInvariant> for AdminError {
    fn from(err: RoleInvariant) -> Self {
        AdminError::Invalid(err.to_string())
    }
}

/// Result alias for policy-administration operations.
pub type AdminResult<T> = Result<T, AdminError>;

/// Policy Administration Point over a set of repository ports.
///
/// `S` is any store implementing the policy repository ports and the audit sink;
/// the in-memory [`InMemoryStore`](crate::InMemoryStore) backs tests and local
/// mode, and a database adapter backs the service. Mutating methods append a
/// [`DomainEvent`] and advance the [snapshot version](PolicyAdminApi::version);
/// read methods never advance it.
#[derive(Debug)]
pub struct PolicyAdminApi<S> {
    store: S,
    version: u64,
    events: Vec<DomainEvent>,
}

impl<S> PolicyAdminApi<S>
where
    S: OrgRepo + GroupRepo + RoleRepo + GrantRepo + RoleBindingRepo + AuditSink,
{
    /// Build a PAP over `store` at initial snapshot version 1.
    pub fn new(store: S) -> Self {
        Self {
            store,
            version: 1,
            events: Vec::new(),
        }
    }

    /// The current monotonic snapshot version. It advances by one on every
    /// successful mutation and is the value a synced consumer fences against.
    pub fn version(&self) -> u64 {
        self.version
    }

    /// The domain events emitted so far, in application order.
    pub fn events(&self) -> &[DomainEvent] {
        &self.events
    }

    /// Read-only access to the underlying store.
    pub fn store(&self) -> &S {
        &self.store
    }

    /// Append `event` to the audit trail and advance the snapshot version.
    ///
    /// The audit record is written first; only once it is durable is the version
    /// bumped and the event retained, so a failed audit write leaves the snapshot
    /// version unchanged.
    fn commit(&mut self, event: DomainEvent, at: Timestamp) -> AdminResult<u64> {
        self.store.record(AuditEvent {
            at,
            actor: None,
            action: event.action().to_owned(),
            detail: event.detail(),
        })?;
        self.version += 1;
        self.events.push(event);
        Ok(self.version)
    }

    // -- organizations ------------------------------------------------------

    /// Create an organization, failing closed when its id already exists.
    pub fn create_org(&mut self, org: Organization, at: Timestamp) -> AdminResult<u64> {
        if OrgRepo::get(&self.store, &org.id)?.is_some() {
            return Err(AdminError::AlreadyExists(format!(
                "organization {}",
                org.id.0
            )));
        }
        let id = org.id.clone();
        OrgRepo::upsert(&self.store, org)?;
        self.commit(DomainEvent::OrganizationCreated(id), at)
    }

    /// Replace an existing organization, failing closed when it is absent.
    pub fn update_org(&mut self, org: Organization, at: Timestamp) -> AdminResult<u64> {
        if OrgRepo::get(&self.store, &org.id)?.is_none() {
            return Err(AdminError::NotFound(format!("organization {}", org.id.0)));
        }
        let id = org.id.clone();
        OrgRepo::upsert(&self.store, org)?;
        self.commit(DomainEvent::OrganizationUpdated(id), at)
    }

    /// Delete an organization, failing closed when it is absent.
    pub fn delete_org(&mut self, id: &OrgId, at: Timestamp) -> AdminResult<u64> {
        OrgRepo::remove(&self.store, id)?;
        self.commit(DomainEvent::OrganizationDeleted(id.clone()), at)
    }

    /// Resolve an organization by id.
    pub fn get_org(&self, id: &OrgId) -> AdminResult<Option<Organization>> {
        Ok(OrgRepo::get(&self.store, id)?)
    }

    /// List every organization.
    pub fn list_orgs(&self) -> AdminResult<Vec<Organization>> {
        Ok(OrgRepo::list(&self.store)?)
    }

    // -- groups -------------------------------------------------------------

    /// Create a group, failing closed when its id already exists.
    pub fn create_group(&mut self, group: Group, at: Timestamp) -> AdminResult<u64> {
        if GroupRepo::get(&self.store, &group.id)?.is_some() {
            return Err(AdminError::AlreadyExists(format!("group {}", group.id.0)));
        }
        let id = group.id.clone();
        GroupRepo::upsert(&self.store, group)?;
        self.commit(DomainEvent::GroupCreated(id), at)
    }

    /// Replace an existing group (membership or metadata), failing closed when
    /// it is absent.
    pub fn update_group(&mut self, group: Group, at: Timestamp) -> AdminResult<u64> {
        if GroupRepo::get(&self.store, &group.id)?.is_none() {
            return Err(AdminError::NotFound(format!("group {}", group.id.0)));
        }
        let id = group.id.clone();
        GroupRepo::upsert(&self.store, group)?;
        self.commit(DomainEvent::GroupUpdated(id), at)
    }

    /// Delete a group, failing closed when it is absent.
    pub fn delete_group(&mut self, id: &GroupId, at: Timestamp) -> AdminResult<u64> {
        GroupRepo::remove(&self.store, id)?;
        self.commit(DomainEvent::GroupDeleted(id.clone()), at)
    }

    /// Resolve a group by id.
    pub fn get_group(&self, id: &GroupId) -> AdminResult<Option<Group>> {
        Ok(GroupRepo::get(&self.store, id)?)
    }

    /// List every group.
    pub fn list_groups(&self) -> AdminResult<Vec<Group>> {
        Ok(GroupRepo::list(&self.store)?)
    }

    // -- roles --------------------------------------------------------------

    /// Define a role, validating its invariants and failing closed when its id
    /// already exists.
    pub fn define_role(&mut self, role: RoleDef, at: Timestamp) -> AdminResult<u64> {
        role.validate()?;
        if RoleRepo::get(&self.store, &role.id)?.is_some() {
            return Err(AdminError::AlreadyExists(format!("role {}", role.id.0)));
        }
        let id = role.id.clone();
        RoleRepo::upsert(&self.store, role)?;
        self.commit(DomainEvent::RoleDefined(id), at)
    }

    /// Replace an existing role, validating its invariants and failing closed
    /// when it is absent.
    pub fn update_role(&mut self, role: RoleDef, at: Timestamp) -> AdminResult<u64> {
        role.validate()?;
        if RoleRepo::get(&self.store, &role.id)?.is_none() {
            return Err(AdminError::NotFound(format!("role {}", role.id.0)));
        }
        let id = role.id.clone();
        RoleRepo::upsert(&self.store, role)?;
        self.commit(DomainEvent::RoleUpdated(id), at)
    }

    /// Delete a role, failing closed when it is absent.
    pub fn delete_role(&mut self, id: &RoleId, at: Timestamp) -> AdminResult<u64> {
        RoleRepo::remove(&self.store, id)?;
        self.commit(DomainEvent::RoleDeleted(id.clone()), at)
    }

    /// Resolve a role by id.
    pub fn get_role(&self, id: &RoleId) -> AdminResult<Option<RoleDef>> {
        Ok(RoleRepo::get(&self.store, id)?)
    }

    /// List every role.
    pub fn list_roles(&self) -> AdminResult<Vec<RoleDef>> {
        Ok(RoleRepo::list(&self.store)?)
    }

    // -- grants -------------------------------------------------------------

    /// Issue a grant, inserting or replacing it by id.
    pub fn issue_grant(&mut self, grant: Grant, at: Timestamp) -> AdminResult<u64> {
        let id = grant.id.clone();
        GrantRepo::put(&self.store, grant)?;
        self.commit(DomainEvent::GrantIssued(id), at)
    }

    /// Revoke a grant, failing closed when it is absent.
    pub fn revoke_grant(&mut self, id: &GrantId, at: Timestamp) -> AdminResult<u64> {
        GrantRepo::remove(&self.store, id)?;
        self.commit(DomainEvent::GrantRevoked(id.clone()), at)
    }

    /// Resolve a grant by id.
    pub fn get_grant(&self, id: &GrantId) -> AdminResult<Option<Grant>> {
        Ok(GrantRepo::get(&self.store, id)?)
    }

    /// List every grant.
    pub fn list_grants(&self) -> AdminResult<Vec<Grant>> {
        Ok(GrantRepo::list(&self.store)?)
    }

    // -- memberships --------------------------------------------------------

    /// Grant a membership: bind a principal to a role at a scope. Idempotent —
    /// re-granting an identical binding still advances the snapshot version so a
    /// consumer never misses an administrative action.
    pub fn grant_membership(&mut self, binding: RoleBinding, at: Timestamp) -> AdminResult<u64> {
        let event = DomainEvent::MembershipGranted {
            principal: binding.principal.clone(),
            role: binding.role.clone(),
            scope: binding.scope.clone(),
        };
        RoleBindingRepo::add(&self.store, binding)?;
        self.commit(event, at)
    }

    /// Revoke a membership, failing closed when the exact binding is absent.
    pub fn revoke_membership(&mut self, binding: &RoleBinding, at: Timestamp) -> AdminResult<u64> {
        RoleBindingRepo::remove(&self.store, binding)?;
        self.commit(
            DomainEvent::MembershipRevoked {
                principal: binding.principal.clone(),
                role: binding.role.clone(),
                scope: binding.scope.clone(),
            },
            at,
        )
    }

    /// List every membership.
    pub fn list_memberships(&self) -> AdminResult<Vec<RoleBinding>> {
        Ok(RoleBindingRepo::list(&self.store)?)
    }

    /// List the memberships held by a principal.
    pub fn memberships_for_principal(
        &self,
        principal: &PrincipalRef,
    ) -> AdminResult<Vec<RoleBinding>> {
        Ok(RoleBindingRepo::list_for_principal(&self.store, principal)?)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::InMemoryStore;
    use awaken_iam_contract::AccountId;
    use awaken_iam_core::{ActionPattern, Effect, GrantSubject};

    fn at() -> Timestamp {
        Timestamp("2026-06-21T00:00:00Z".into())
    }

    fn account(id: &str) -> PrincipalRef {
        PrincipalRef::Account {
            account_id: AccountId(id.into()),
        }
    }

    fn org(id: &str) -> Organization {
        Organization {
            id: OrgId(id.into()),
            display_name: Some(id.to_uppercase()),
            owner: account("ada"),
            created_at: at(),
            updated_at: at(),
        }
    }

    fn role(id: &str) -> RoleDef {
        RoleDef {
            id: RoleId(id.into()),
            display_name: None,
            action_patterns: vec![ActionPattern("pack.*".into())],
            created_at: at(),
            updated_at: at(),
        }
    }

    fn pap() -> PolicyAdminApi<InMemoryStore> {
        PolicyAdminApi::new(InMemoryStore::new())
    }

    #[test]
    fn create_org_persists_and_bumps_version_and_emits_event() {
        let mut pap = pap();
        assert_eq!(pap.version(), 1);
        let version = pap.create_org(org("acme"), at()).unwrap();
        assert_eq!(version, 2);
        assert_eq!(pap.version(), 2);
        assert_eq!(pap.list_orgs().unwrap().len(), 1);
        assert_eq!(
            pap.get_org(&OrgId("acme".into())).unwrap().unwrap().id,
            OrgId("acme".into())
        );
        assert_eq!(
            pap.events(),
            &[DomainEvent::OrganizationCreated(OrgId("acme".into()))]
        );
        // The audit trail captured the change too.
        let audit = AuditSink::events(pap.store()).unwrap();
        assert_eq!(audit.len(), 1);
        assert_eq!(audit[0].action, "org.create");
    }

    #[test]
    fn create_is_conflict_and_update_delete_require_existence() {
        let mut pap = pap();
        pap.create_org(org("acme"), at()).unwrap();
        assert_eq!(
            pap.create_org(org("acme"), at()),
            Err(AdminError::AlreadyExists("organization acme".into()))
        );
        // A failed create does not advance the version.
        assert_eq!(pap.version(), 2);

        assert!(matches!(
            pap.update_org(org("ghost"), at()),
            Err(AdminError::NotFound(_))
        ));
        assert!(matches!(
            pap.delete_org(&OrgId("ghost".into()), at()),
            Err(AdminError::NotFound(_))
        ));
        assert_eq!(pap.version(), 2);

        pap.update_org(org("acme"), at()).unwrap();
        pap.delete_org(&OrgId("acme".into()), at()).unwrap();
        assert!(pap.list_orgs().unwrap().is_empty());
        assert_eq!(pap.version(), 4);
    }

    #[test]
    fn define_role_rejects_wildcard_all() {
        let mut pap = pap();
        let mut bad = role("super");
        bad.action_patterns = vec![ActionPattern("*".into())];
        assert!(matches!(
            pap.define_role(bad, at()),
            Err(AdminError::Invalid(_))
        ));
        // The rejected role neither persisted nor advanced the version.
        assert!(pap.list_roles().unwrap().is_empty());
        assert_eq!(pap.version(), 1);

        pap.define_role(role("publisher"), at()).unwrap();
        assert_eq!(pap.list_roles().unwrap().len(), 1);
    }

    #[test]
    fn grant_lifecycle_emits_issue_and_revoke() {
        let mut pap = pap();
        let grant = Grant {
            id: GrantId("g1".into()),
            subject: GrantSubject::Principal(account("ada")),
            action_pattern: ActionPattern("pack.read".into()),
            scope: ScopeRef::Global,
            effect: Effect::Allow,
        };
        pap.issue_grant(grant, at()).unwrap();
        assert_eq!(pap.list_grants().unwrap().len(), 1);
        let version = pap.revoke_grant(&GrantId("g1".into()), at()).unwrap();
        assert_eq!(version, 3);
        assert!(pap.list_grants().unwrap().is_empty());
        assert!(matches!(
            pap.revoke_grant(&GrantId("g1".into()), at()),
            Err(AdminError::NotFound(_))
        ));
        assert_eq!(
            pap.events(),
            &[
                DomainEvent::GrantIssued(GrantId("g1".into())),
                DomainEvent::GrantRevoked(GrantId("g1".into())),
            ]
        );
    }

    #[test]
    fn membership_grant_and_revoke_round_trip() {
        let mut pap = pap();
        let binding = RoleBinding {
            principal: account("ada"),
            role: RoleId("publisher".into()),
            scope: ScopeRef::Org {
                org_id: OrgId("acme".into()),
            },
        };
        pap.grant_membership(binding.clone(), at()).unwrap();
        assert_eq!(pap.list_memberships().unwrap().len(), 1);
        assert_eq!(
            pap.memberships_for_principal(&account("ada"))
                .unwrap()
                .len(),
            1
        );

        pap.revoke_membership(&binding, at()).unwrap();
        assert!(pap.list_memberships().unwrap().is_empty());
        assert!(matches!(
            pap.revoke_membership(&binding, at()),
            Err(AdminError::NotFound(_))
        ));
        assert!(matches!(
            pap.events().first().unwrap(),
            DomainEvent::MembershipGranted { .. }
        ));
    }

    #[test]
    fn group_membership_updates_through_the_pap() {
        let mut pap = pap();
        let mut group = Group {
            id: GroupId("eng".into()),
            org: OrgId("acme".into()),
            display_name: None,
            members: Vec::new(),
            created_at: at(),
            updated_at: at(),
        };
        pap.create_group(group.clone(), at()).unwrap();
        group.add_member(account("ada"));
        let version = pap.update_group(group, at()).unwrap();
        assert_eq!(version, 3);
        assert_eq!(
            pap.get_group(&GroupId("eng".into()))
                .unwrap()
                .unwrap()
                .members
                .len(),
            1
        );
        pap.delete_group(&GroupId("eng".into()), at()).unwrap();
        assert!(pap.list_groups().unwrap().is_empty());
    }
}
