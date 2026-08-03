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

use awaken_iam_contract::{
    AcceptInvitation, AcceptedInvitation, CreateInvitation, InvitationId, InvitationStatus,
    IssuedInvitation, OrgId, PrincipalRef, ResourceModelRegistration, ScopeRef, Timestamp,
    WorkspaceId, WorkspaceOrgEdge,
};
use awaken_iam_core::{
    AuditEvent, AuditSink, Grant, GrantId, GrantRepo, Group, GroupId, GroupRepo, Invitation,
    InvitationRepo, OrgRepo, Organization, PolicySet, RepoError, ResourceEdge, ResourceModelRepo,
    RoleBinding, RoleBindingRepo, RoleDef, RoleId, RoleInvariant, RoleRepo,
    normalize_invitation_email,
};
use base64::Engine;
use sha2::{Digest, Sha256};
use time::{OffsetDateTime, format_description::well_known::Rfc3339};

use crate::FenceStore;

/// Repository capabilities required by the one policy-administration pipeline.
///
/// This marker keeps deployment selection generic without wrapping every PAP
/// operation in a second forwarding interface.
pub trait PolicyStore:
    OrgRepo
    + GroupRepo
    + RoleRepo
    + GrantRepo
    + RoleBindingRepo
    + InvitationRepo
    + ResourceModelRepo
    + AuditSink
    + FenceStore
{
}

impl<T> PolicyStore for T where
    T: OrgRepo
        + GroupRepo
        + RoleRepo
        + GrantRepo
        + RoleBindingRepo
        + InvitationRepo
        + ResourceModelRepo
        + AuditSink
        + FenceStore
{
}

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
    InvitationCreated(InvitationId),
    InvitationResent(InvitationId),
    InvitationRevoked(InvitationId),
    InvitationAccepted(InvitationId),
    InvitationExpired(InvitationId),
    /// A consumer registered (or extended) its resource model.
    ResourceModelRegistered {
        /// Number of resource types declared in the registration.
        resource_types: usize,
        /// Number of per-instance scope parent edges registered.
        edges: usize,
    },
    /// A product projected one Workspace → Org ownership edge.
    WorkspaceOrgAssigned {
        workspace_id: WorkspaceId,
        org_id: OrgId,
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
            DomainEvent::InvitationCreated(_) => "invitation.create",
            DomainEvent::InvitationResent(_) => "invitation.resend",
            DomainEvent::InvitationRevoked(_) => "invitation.revoke",
            DomainEvent::InvitationAccepted(_) => "invitation.accept",
            DomainEvent::InvitationExpired(_) => "invitation.expire",
            DomainEvent::ResourceModelRegistered { .. } => "resource_model.register",
            DomainEvent::WorkspaceOrgAssigned { .. } => "scope.workspace.assign",
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
            DomainEvent::InvitationCreated(id)
            | DomainEvent::InvitationResent(id)
            | DomainEvent::InvitationRevoked(id)
            | DomainEvent::InvitationAccepted(id)
            | DomainEvent::InvitationExpired(id) => format!("invitation {}", id.0),
            DomainEvent::ResourceModelRegistered {
                resource_types,
                edges,
            } => format!("resource model: {resource_types} types, {edges} edges"),
            DomainEvent::WorkspaceOrgAssigned {
                workspace_id,
                org_id,
            } => format!("workspace {} -> org {}", workspace_id.0, org_id.0),
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

fn hash_claim_token(token: &str) -> String {
    format!("{:x}", Sha256::digest(token.as_bytes()))
}

fn new_claim_token() -> AdminResult<String> {
    let mut bytes = [0_u8; 32];
    getrandom::fill(&mut bytes)
        .map_err(|error| AdminError::Backend(format!("invitation entropy unavailable: {error}")))?;
    Ok(base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(bytes))
}

fn invitation_id(org_id: &OrgId, idempotency_key: &str) -> InvitationId {
    let digest = Sha256::digest(format!("{}\0{idempotency_key}", org_id.0).as_bytes());
    InvitationId(format!(
        "invite_{}",
        base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(&digest[..18])
    ))
}

fn validate_timestamp_order(now: &Timestamp, expires_at: &Timestamp) -> AdminResult<()> {
    if timestamp_is_expired(now, expires_at)? {
        return Err(AdminError::Invalid("invitation is expired".into()));
    }
    Ok(())
}

fn timestamp_is_expired(now: &Timestamp, expires_at: &Timestamp) -> AdminResult<bool> {
    Ok(parse_timestamp(expires_at)? <= parse_timestamp(now)?)
}

fn parse_timestamp(value: &Timestamp) -> AdminResult<OffsetDateTime> {
    OffsetDateTime::parse(&value.0, &Rfc3339)
        .map_err(|_| AdminError::Invalid("timestamps must be RFC 3339".into()))
}

/// Policy Administration Point over a set of repository ports.
///
/// `S` is any store implementing the policy repository ports, the audit sink,
/// and the [`FenceStore`]; the in-memory [`InMemoryStore`](crate::InMemoryStore)
/// backs tests and local mode, and a database adapter backs the service.
/// Mutating methods append a [`DomainEvent`] and advance the
/// [snapshot version](PolicyAdminApi::version) **in the shared store**; read
/// methods never advance it.
///
/// The version is store-backed (HA rule 3): a bump is written in the same
/// transaction as the change it fences, so every node that shares the store sees
/// it on the next read. The in-memory `version` field caches the value this node
/// last observed; [`store_version`](PolicyAdminApi::store_version) reads the
/// authoritative counter fresh.
#[derive(Debug)]
pub struct PolicyAdminApi<S> {
    store: S,
    version: u64,
    events: Vec<DomainEvent>,
}

impl<S> PolicyAdminApi<S>
where
    S: PolicyStore,
{
    /// Build a PAP over `store`, seeding the cached snapshot version from the
    /// store's fence (a fresh store starts at version 1).
    pub fn new(store: S) -> Self {
        let version = store.fence().map(|fence| fence.version).unwrap_or(1);
        Self {
            store,
            version,
            events: Vec::new(),
        }
    }

    /// The snapshot version this node last observed. It advances on every
    /// successful mutation and is the value a synced consumer fences against; for
    /// the authoritative cross-node value read [`store_version`](Self::store_version).
    pub fn version(&self) -> u64 {
        self.version
    }

    /// Read the authoritative snapshot version fresh from the shared store.
    ///
    /// On a multi-node deployment this reflects bumps made by *other* nodes,
    /// which the cached [`version`](Self::version) does not — it is the read a
    /// consumer's freshness check fences against.
    pub fn store_version(&self) -> AdminResult<u64> {
        Ok(self.store.fence()?.version)
    }

    /// The domain events emitted so far, in application order.
    pub fn events(&self) -> &[DomainEvent] {
        &self.events
    }

    /// Read-only access to the underlying store.
    pub fn store(&self) -> &S {
        &self.store
    }

    /// Append `event` to the audit trail and advance the snapshot version in the
    /// shared store.
    ///
    /// The audit record is written first; only once it is durable is the store
    /// fence advanced and the event retained, so a failed audit write leaves the
    /// snapshot version unchanged. The bump rides the store (HA rule 3), so a
    /// change made on this node is visible to every node fencing on the same
    /// store; the cached [`version`](Self::version) is refreshed to the value the
    /// store returned.
    fn commit(&mut self, event: DomainEvent, at: Timestamp) -> AdminResult<u64> {
        self.store.record(AuditEvent {
            at,
            actor: None,
            action: event.action().to_owned(),
            detail: event.detail(),
        })?;
        self.version = self.store.advance_version()?;
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

    /// List exact bindings anchored at `scope`; inherited effective membership
    /// remains a read projection above this primitive.
    pub fn memberships_for_scope(&self, scope: &ScopeRef) -> AdminResult<Vec<RoleBinding>> {
        Ok(RoleBindingRepo::list(&self.store)?
            .into_iter()
            .filter(|binding| &binding.scope == scope)
            .collect())
    }

    /// Create an invitation or idempotently rotate its delivery token when the
    /// same command is retried while still pending.
    pub fn create_invitation(
        &mut self,
        request: CreateInvitation,
        at: Timestamp,
    ) -> AdminResult<IssuedInvitation> {
        validate_timestamp_order(&at, &request.expires_at)?;
        let email = normalize_invitation_email(&request.email)
            .ok_or_else(|| AdminError::Invalid("invalid invitation email".into()))?;
        self.validate_invitation_targets(&request.org_id, &request.bindings)?;
        if request.idempotency_key.trim().is_empty() || request.idempotency_key.len() > 200 {
            return Err(AdminError::Invalid("invalid idempotency key".into()));
        }
        let token = new_claim_token()?;
        let token_hash = hash_claim_token(&token);
        if let Some(mut existing) = self
            .store
            .get_invitation_by_idempotency(&request.org_id, &request.idempotency_key)?
        {
            if existing.email != email
                || existing.bindings != request.bindings
                || existing.invited_by != request.invited_by
                || existing.status != InvitationStatus::Pending
            {
                return Err(AdminError::AlreadyExists(
                    "idempotency key belongs to another invitation command".into(),
                ));
            }
            let expected = existing.token_hash.clone();
            existing.token_hash = token_hash;
            existing.expires_at = request.expires_at;
            existing.updated_at = at.clone();
            if !self
                .store
                .replace_pending_invitation(existing.clone(), &expected)?
            {
                return Err(AdminError::AlreadyExists(
                    "invitation changed concurrently".into(),
                ));
            }
            let version = self.commit(DomainEvent::InvitationResent(existing.id.clone()), at)?;
            return Ok(IssuedInvitation {
                invitation: existing.to_dto(),
                token,
                version,
            });
        }
        let id = invitation_id(&request.org_id, &request.idempotency_key);
        let invitation = Invitation {
            id: id.clone(),
            idempotency_key: request.idempotency_key,
            org_id: request.org_id,
            email,
            bindings: request.bindings,
            invited_by: request.invited_by,
            token_hash,
            status: InvitationStatus::Pending,
            expires_at: request.expires_at,
            created_at: at.clone(),
            updated_at: at.clone(),
            accepted_by_account_id: None,
        };
        self.store.create_invitation(invitation.clone())?;
        let version = self.commit(DomainEvent::InvitationCreated(id), at)?;
        Ok(IssuedInvitation {
            invitation: invitation.to_dto(),
            token,
            version,
        })
    }

    pub fn list_invitations(
        &self,
        org_id: &OrgId,
    ) -> AdminResult<Vec<awaken_iam_contract::InvitationDto>> {
        Ok(self
            .store
            .list_invitations_for_org(org_id)?
            .into_iter()
            .map(|value| value.to_dto())
            .collect())
    }

    pub fn resend_invitation(
        &mut self,
        id: &InvitationId,
        expires_at: Timestamp,
        at: Timestamp,
    ) -> AdminResult<IssuedInvitation> {
        validate_timestamp_order(&at, &expires_at)?;
        let mut invitation = self
            .store
            .get_invitation(id)?
            .ok_or_else(|| AdminError::NotFound("invitation".into()))?;
        if invitation.status != InvitationStatus::Pending {
            return Err(AdminError::Invalid(
                "only pending invitations can be resent".into(),
            ));
        }
        let token = new_claim_token()?;
        let expected = invitation.token_hash.clone();
        invitation.token_hash = hash_claim_token(&token);
        invitation.expires_at = expires_at;
        invitation.updated_at = at.clone();
        if !self
            .store
            .replace_pending_invitation(invitation.clone(), &expected)?
        {
            return Err(AdminError::AlreadyExists(
                "invitation changed concurrently".into(),
            ));
        }
        let version = self.commit(DomainEvent::InvitationResent(id.clone()), at)?;
        Ok(IssuedInvitation {
            invitation: invitation.to_dto(),
            token,
            version,
        })
    }

    pub fn revoke_invitation(&mut self, id: &InvitationId, at: Timestamp) -> AdminResult<u64> {
        let mut invitation = self
            .store
            .get_invitation(id)?
            .ok_or_else(|| AdminError::NotFound("invitation".into()))?;
        if invitation.status == InvitationStatus::Revoked {
            return self.store_version();
        }
        if invitation.status != InvitationStatus::Pending {
            return Err(AdminError::Invalid(
                "accepted invitation cannot be revoked".into(),
            ));
        }
        let expected = invitation.token_hash.clone();
        invitation.status = InvitationStatus::Revoked;
        invitation.updated_at = at.clone();
        if !self
            .store
            .replace_pending_invitation(invitation, &expected)?
        {
            return Err(AdminError::AlreadyExists(
                "invitation changed concurrently".into(),
            ));
        }
        self.commit(DomainEvent::InvitationRevoked(id.clone()), at)
    }

    pub fn accept_invitation(
        &mut self,
        id: &InvitationId,
        request: AcceptInvitation,
        at: Timestamp,
    ) -> AdminResult<AcceptedInvitation> {
        let invitation = self
            .store
            .get_invitation(id)?
            .ok_or_else(|| AdminError::NotFound("invitation".into()))?;
        let expected = hash_claim_token(&request.token);
        if invitation.token_hash != expected {
            return Err(AdminError::NotFound("invitation".into()));
        }
        if invitation.status == InvitationStatus::Accepted
            && invitation.accepted_by_account_id.as_ref() == Some(&request.account_id)
        {
            return Ok(AcceptedInvitation {
                invitation: invitation.to_dto(),
                version: self.store_version()?,
            });
        }
        if invitation.status != InvitationStatus::Pending {
            return Err(AdminError::NotFound("invitation".into()));
        }
        if timestamp_is_expired(&at, &invitation.expires_at)? {
            let mut expired = invitation;
            expired.status = InvitationStatus::Expired;
            expired.updated_at = at.clone();
            if self.store.replace_pending_invitation(expired, &expected)? {
                self.commit(DomainEvent::InvitationExpired(id.clone()), at)?;
            }
            return Err(AdminError::Invalid("invitation is expired".into()));
        }
        if normalize_invitation_email(&request.verified_email).as_deref()
            != Some(invitation.email.as_str())
        {
            return Err(AdminError::NotFound("invitation".into()));
        }
        let accepted = self
            .store
            .accept_pending_invitation(id, &expected, &request.account_id, &at)?
            .ok_or_else(|| AdminError::AlreadyExists("invitation changed concurrently".into()))?;
        let version = self.commit(DomainEvent::InvitationAccepted(id.clone()), at)?;
        Ok(AcceptedInvitation {
            invitation: accepted.to_dto(),
            version,
        })
    }

    fn validate_invitation_targets(
        &self,
        org_id: &OrgId,
        targets: &[awaken_iam_contract::InvitationBinding],
    ) -> AdminResult<()> {
        if OrgRepo::get(&self.store, org_id)?.is_none() {
            return Err(AdminError::NotFound(format!("organization {}", org_id.0)));
        }
        if targets.is_empty() || !targets.iter().any(|target| matches!(&target.scope, ScopeRef::Org { org_id: target_org } if target_org == org_id)) {
            return Err(AdminError::Invalid("an invitation requires an exact organization binding".into()));
        }
        let mut unique = std::collections::HashSet::new();
        for target in targets {
            let key = serde_json::to_string(target)
                .map_err(|error| AdminError::Backend(error.to_string()))?;
            if !unique.insert(key) {
                return Err(AdminError::Invalid("duplicate invitation binding".into()));
            }
            match &target.scope {
                ScopeRef::Org { org_id: target_org } if target_org == org_id => {}
                ScopeRef::Workspace { workspace_id } => {
                    let edge = self.store.workspace_org(workspace_id)?;
                    if edge.as_ref().map(|edge| &edge.org_id) != Some(org_id) {
                        return Err(AdminError::Invalid(
                            "workspace is not owned by invitation organization".into(),
                        ));
                    }
                }
                _ => {
                    return Err(AdminError::Invalid(
                        "invitation bindings may target only its organization or owned workspaces"
                            .into(),
                    ));
                }
            }
        }
        Ok(())
    }

    // -- resource model -----------------------------------------------------

    /// Register a consumer's resource model, persisting its per-instance scope
    /// parent edges so the product hierarchy survives a restart and feeds the
    /// authorization snapshot.
    ///
    /// Edges are upserted by `(resource_type, resource_id)`, so re-registering an
    /// instance replaces its parent rather than duplicating it (the
    /// "registered, never inferred" invariant). The resource types and standalone
    /// actions are vocabulary the evaluator folds in live through
    /// [`AuthzApi::register_resource_model`](crate::AuthzApi::register_resource_model);
    /// only the edges are durable policy state, so they are what this PAP
    /// persists. Advances the snapshot version once for the whole registration.
    pub fn register_resource_model(
        &mut self,
        registration: &ResourceModelRegistration,
        at: Timestamp,
    ) -> AdminResult<u64> {
        for edge in &registration.edges {
            ResourceModelRepo::put_edge(&self.store, ResourceEdge::from(edge.clone()))?;
        }
        self.commit(
            DomainEvent::ResourceModelRegistered {
                resource_types: registration.resource_types.len(),
                edges: registration.edges.len(),
            },
            at,
        )
    }

    /// List every persisted resource-model parent edge.
    pub fn list_resource_edges(&self) -> AdminResult<Vec<ResourceEdge>> {
        Ok(ResourceModelRepo::list_edges(&self.store)?)
    }

    /// Persist one product-owned Workspace → IAM Org projection.
    ///
    /// Exact redelivery is idempotent. Re-parenting is rejected because a
    /// caller must never move an existing workspace across tenants implicitly.
    pub fn assign_workspace_org(
        &mut self,
        edge: WorkspaceOrgEdge,
        at: Timestamp,
    ) -> AdminResult<u64> {
        if OrgRepo::get(&self.store, &edge.org_id)?.is_none() {
            return Err(AdminError::NotFound(format!(
                "organization {}",
                edge.org_id.0
            )));
        }
        if let Some(existing) = ResourceModelRepo::workspace_org(&self.store, &edge.workspace_id)? {
            if existing == edge {
                return self.store_version();
            }
            return Err(AdminError::AlreadyExists(format!(
                "workspace {} belongs to organization {}",
                existing.workspace_id.0, existing.org_id.0
            )));
        }
        ResourceModelRepo::put_workspace_org(&self.store, edge.clone())?;
        self.commit(
            DomainEvent::WorkspaceOrgAssigned {
                workspace_id: edge.workspace_id,
                org_id: edge.org_id,
            },
            at,
        )
    }

    /// Rebuild the evaluator input from the authoritative policy repositories.
    ///
    /// This is the single hydration path used both after an administrative
    /// mutation and at process startup. It deliberately reads the same store the
    /// PAP writes; maintaining a second in-memory policy makes a successful
    /// membership response lie about effective authorization.
    pub fn policy(&self) -> AdminResult<PolicySet> {
        let mut policy = PolicySet::new();
        for grant in GrantRepo::list(&self.store)? {
            policy.add_grant(grant);
        }
        for binding in RoleBindingRepo::list(&self.store)? {
            policy.bind_role(binding);
        }
        for group in GroupRepo::list(&self.store)? {
            policy.set_group_roster(group.id, group.members);
        }
        for edge in ResourceModelRepo::list_edges(&self.store)? {
            policy.scope_graph_mut().assign_resource_parent(
                edge.resource_type,
                edge.resource_id,
                edge.parent,
            );
        }
        for edge in ResourceModelRepo::list_workspace_orgs(&self.store)? {
            policy
                .scope_graph_mut()
                .assign_workspace(edge.workspace_id, edge.org_id);
        }
        Ok(policy)
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

    fn invitation_request(key: &str) -> CreateInvitation {
        CreateInvitation {
            idempotency_key: key.into(),
            org_id: OrgId("acme".into()),
            email: " Bob@Example.COM ".into(),
            bindings: vec![awaken_iam_contract::InvitationBinding {
                role_id: "member".into(),
                scope: ScopeRef::Org {
                    org_id: OrgId("acme".into()),
                },
            }],
            invited_by: account("ada"),
            expires_at: Timestamp("2026-06-22T00:00:00Z".into()),
        }
    }

    fn invitation_pap() -> PolicyAdminApi<InMemoryStore> {
        let mut pap = pap();
        pap.create_org(org("acme"), at()).unwrap();
        pap.define_role(role("member"), at()).unwrap();
        pap
    }

    #[test]
    fn invitation_acceptance_materializes_exact_bindings_once() {
        // Cause/effect graph: C1=pending, C2=live token, C3=matching verified
        // email, C4=unexpired, C5=same account retry. R1(C1+C2+C3+C4)->Accepted
        // plus exact RoleBinding and version bump; R2(R1+C5)->same Accepted
        // projection with no duplicate binding/version bump.
        let mut pap = invitation_pap();
        let issued = pap
            .create_invitation(invitation_request("request-1"), at())
            .unwrap();
        assert_eq!(issued.invitation.email, "bob@example.com");
        let before_accept = pap.version();
        let request = AcceptInvitation {
            account_id: AccountId("bob".into()),
            verified_email: "BOB@example.com".into(),
            token: issued.token,
        };
        let accepted = pap
            .accept_invitation(&issued.invitation.id, request.clone(), at())
            .unwrap();
        assert_eq!(accepted.invitation.status, InvitationStatus::Accepted);
        assert_eq!(
            pap.memberships_for_principal(&account("bob"))
                .unwrap()
                .len(),
            1
        );
        assert_eq!(accepted.version, before_accept + 1);

        let retried = pap
            .accept_invitation(&issued.invitation.id, request, at())
            .unwrap();
        assert_eq!(retried.version, accepted.version);
        assert_eq!(
            pap.memberships_for_principal(&account("bob"))
                .unwrap()
                .len(),
            1
        );
    }

    #[test]
    fn invitation_accepts_profile_owned_workspace_role() {
        // Cause/effect decision table:
        // C1 exact Org binding | C2 workspace belongs to Org | C3 role has a
        // base RoleDef | result
        // yes | yes | no  -> invitation accepted and both exact bindings persist
        // yes | no  | any -> rejected by the workspace ownership rule (covered below)
        // Constraint: product authorization profiles own their role grants;
        // an ungranted role id is inert and therefore fails closed in the PDP.
        let mut pap = invitation_pap();
        let workspace = WorkspaceId("flow-acme".into());
        pap.assign_workspace_org(
            WorkspaceOrgEdge {
                workspace_id: workspace.clone(),
                org_id: OrgId("acme".into()),
            },
            at(),
        )
        .unwrap();
        let mut request = invitation_request("profile-role");
        request
            .bindings
            .push(awaken_iam_contract::InvitationBinding {
                role_id: "awaken.flow:workspace_user".into(),
                scope: ScopeRef::Workspace {
                    workspace_id: workspace.clone(),
                },
            });

        let issued = pap.create_invitation(request, at()).unwrap();
        pap.accept_invitation(
            &issued.invitation.id,
            AcceptInvitation {
                account_id: AccountId("bob".into()),
                verified_email: "bob@example.com".into(),
                token: issued.token,
            },
            at(),
        )
        .unwrap();

        let bindings = pap.memberships_for_principal(&account("bob")).unwrap();
        assert_eq!(bindings.len(), 2);
        assert!(bindings.iter().any(|binding| {
            binding.role == RoleId("awaken.flow:workspace_user".into())
                && binding.scope
                    == ScopeRef::Workspace {
                        workspace_id: workspace.clone(),
                    }
        }));
    }

    #[test]
    fn invitation_claim_failures_leave_membership_unchanged() {
        // Decision table causes: token T, verified-email E, expiry X, pending P.
        // R1 !T+P -> NotFound; R2 T+!E+P -> NotFound; R3 T+E+X+P -> Invalid;
        // R4 T+E+!X+!P(revoked) -> NotFound. Every rule has no role binding;
        // only R3 records the terminal Expired transition and its version bump.
        for case in ["token", "email", "expired", "revoked"] {
            let mut pap = invitation_pap();
            let mut create = invitation_request(&format!("request-{case}"));
            if case == "expired" {
                create.expires_at = Timestamp("2026-06-21T00:00:01Z".into());
            }
            let issued = pap.create_invitation(create, at()).unwrap();
            if case == "revoked" {
                pap.revoke_invitation(&issued.invitation.id, at()).unwrap();
            }
            let version = pap.version();
            let result = pap.accept_invitation(
                &issued.invitation.id,
                AcceptInvitation {
                    account_id: AccountId("bob".into()),
                    verified_email: if case == "email" {
                        "mallory@example.com"
                    } else {
                        "bob@example.com"
                    }
                    .into(),
                    token: if case == "token" {
                        "wrong".into()
                    } else {
                        issued.token
                    },
                },
                if case == "expired" {
                    Timestamp("2026-06-21T00:00:02Z".into())
                } else {
                    at()
                },
            );
            assert!(result.is_err(), "{case}");
            assert!(
                pap.memberships_for_principal(&account("bob"))
                    .unwrap()
                    .is_empty(),
                "{case}"
            );
            if case == "expired" {
                assert_eq!(pap.version(), version + 1, "{case}");
                assert_eq!(
                    pap.list_invitations(&OrgId("acme".into())).unwrap()[0].status,
                    InvitationStatus::Expired,
                );
            } else {
                assert_eq!(pap.version(), version, "{case}");
            }
        }
    }

    #[test]
    fn invitation_idempotency_and_resend_rotate_tokens() {
        // Causes: same org+idempotency key S, same command fingerprint F,
        // pending P. R1(S+F+P)->same invitation id/new token; old token denies
        // and new token accepts. R2(S+!F)->Conflict and original intent stays.
        let mut pap = invitation_pap();
        let first = pap
            .create_invitation(invitation_request("same"), at())
            .unwrap();
        let second = pap
            .create_invitation(invitation_request("same"), at())
            .unwrap();
        assert_eq!(first.invitation.id, second.invitation.id);
        assert_ne!(first.token, second.token);
        assert!(
            pap.accept_invitation(
                &first.invitation.id,
                AcceptInvitation {
                    account_id: AccountId("bob".into()),
                    verified_email: "bob@example.com".into(),
                    token: first.token
                },
                at(),
            )
            .is_err()
        );

        let mut conflict = invitation_request("same");
        conflict.email = "other@example.com".into();
        assert!(matches!(
            pap.create_invitation(conflict, at()),
            Err(AdminError::AlreadyExists(_))
        ));
        pap.accept_invitation(
            &second.invitation.id,
            AcceptInvitation {
                account_id: AccountId("bob".into()),
                verified_email: "bob@example.com".into(),
                token: second.token,
            },
            at(),
        )
        .unwrap();
    }

    #[test]
    fn invitation_rejects_cross_org_workspace_binding() {
        // C1=mandatory exact Org binding, C2=Workspace projected to the same
        // Org. R1(C1+!C2)->Invalid and no invitation/audit/version mutation.
        let mut pap = invitation_pap();
        pap.create_org(org("other"), at()).unwrap();
        pap.assign_workspace_org(
            WorkspaceOrgEdge {
                workspace_id: WorkspaceId("ws-other".into()),
                org_id: OrgId("other".into()),
            },
            at(),
        )
        .unwrap();
        let mut request = invitation_request("cross-org");
        request
            .bindings
            .push(awaken_iam_contract::InvitationBinding {
                role_id: "member".into(),
                scope: ScopeRef::Workspace {
                    workspace_id: WorkspaceId("ws-other".into()),
                },
            });
        let version = pap.version();
        assert!(matches!(
            pap.create_invitation(request, at()),
            Err(AdminError::Invalid(_))
        ));
        assert_eq!(pap.version(), version);
        assert!(
            pap.list_invitations(&OrgId("acme".into()))
                .unwrap()
                .is_empty()
        );
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
    fn resource_model_registration_persists_edges_and_bumps_version() {
        use awaken_iam_contract::{
            ResourceId, ResourceModelRegistration, ResourceParentEdge, ResourceType,
            ResourceTypeRegistration,
        };

        let mut pap = pap();
        let registration = ResourceModelRegistration {
            resource_types: vec![ResourceTypeRegistration {
                resource_type: ResourceType("issue".into()),
                parent_type: None,
                actions: Vec::new(),
            }],
            actions: Vec::new(),
            edges: vec![ResourceParentEdge {
                resource_type: ResourceType("issue".into()),
                resource_id: ResourceId("42".into()),
                parent: ScopeRef::Org {
                    org_id: OrgId("acme".into()),
                },
            }],
        };
        let version = pap.register_resource_model(&registration, at()).unwrap();
        assert_eq!(version, 2);
        let edges = pap.list_resource_edges().unwrap();
        assert_eq!(edges.len(), 1);
        assert_eq!(edges[0].resource_id, ResourceId("42".into()));

        // Re-registering the same instance with a new parent replaces it rather
        // than duplicating — edges are upserted by (type, id).
        let mut moved = registration.clone();
        moved.edges[0].parent = ScopeRef::Global;
        pap.register_resource_model(&moved, at()).unwrap();
        let edges = pap.list_resource_edges().unwrap();
        assert_eq!(edges.len(), 1);
        assert_eq!(edges[0].parent, ScopeRef::Global);

        assert!(matches!(
            pap.events().first().unwrap(),
            DomainEvent::ResourceModelRegistered {
                resource_types: 1,
                edges: 1
            }
        ));
        let audit = AuditSink::events(pap.store()).unwrap();
        assert_eq!(audit[0].action, "resource_model.register");
    }

    #[test]
    fn version_is_backed_by_the_store_fence() {
        let mut pap = pap();
        // Each successful mutation advances the store fence, and the cached
        // version mirrors the authoritative store value read fresh.
        assert_eq!(pap.version(), 1);
        assert_eq!(pap.store_version().unwrap(), 1);
        let after = pap.create_org(org("acme"), at()).unwrap();
        assert_eq!(after, 2);
        assert_eq!(pap.version(), 2);
        assert_eq!(pap.store_version().unwrap(), 2);
    }

    #[test]
    fn new_pap_seeds_its_version_from_an_existing_store_fence() {
        // A node joining a deployment whose store already advanced (other nodes
        // made changes) must resume from the store's version, not restart at 1.
        let store = InMemoryStore::new();
        store.advance_version().unwrap();
        store.advance_version().unwrap();
        let pap = PolicyAdminApi::new(store);
        assert_eq!(pap.version(), 3);
        assert_eq!(pap.store_version().unwrap(), 3);
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

    #[test]
    fn role_lifecycle_define_update_delete_and_conflicts() {
        let mut pap = pap();
        pap.define_role(role("publisher"), at()).unwrap();
        // A duplicate id is a conflict and does not advance the version.
        assert_eq!(
            pap.define_role(role("publisher"), at()),
            Err(AdminError::AlreadyExists("role publisher".into()))
        );
        assert_eq!(pap.version(), 2);

        // Updating an absent role fails closed.
        assert!(matches!(
            pap.update_role(role("ghost"), at()),
            Err(AdminError::NotFound(_))
        ));

        // A valid update replaces the role and advances the version.
        let mut updated = role("publisher");
        updated.action_patterns = vec![ActionPattern("pack.publish".into())];
        pap.update_role(updated, at()).unwrap();
        assert_eq!(
            pap.get_role(&RoleId("publisher".into()))
                .unwrap()
                .unwrap()
                .action_patterns,
            vec![ActionPattern("pack.publish".into())]
        );

        pap.delete_role(&RoleId("publisher".into()), at()).unwrap();
        assert!(pap.get_role(&RoleId("publisher".into())).unwrap().is_none());
        assert!(matches!(
            pap.delete_role(&RoleId("publisher".into()), at()),
            Err(AdminError::NotFound(_))
        ));
        // The update and delete events carry their stable action keys and detail.
        let actions: Vec<_> = pap.events().iter().map(|e| e.action()).collect();
        assert!(actions.contains(&"role.update"));
        assert!(actions.contains(&"role.delete"));
        let update_detail = DomainEvent::RoleUpdated(RoleId("publisher".into())).detail();
        assert_eq!(update_detail, "role publisher");
    }

    #[test]
    fn group_and_grant_reads_and_duplicate_guards() {
        let mut pap = pap();
        let group = Group {
            id: GroupId("eng".into()),
            org: OrgId("acme".into()),
            display_name: None,
            members: Vec::new(),
            created_at: at(),
            updated_at: at(),
        };
        pap.create_group(group.clone(), at()).unwrap();
        // A duplicate group id is a conflict.
        assert_eq!(
            pap.create_group(group, at()),
            Err(AdminError::AlreadyExists("group eng".into()))
        );
        // Updating a missing group fails closed.
        let ghost = Group {
            id: GroupId("ghost".into()),
            org: OrgId("acme".into()),
            display_name: None,
            members: Vec::new(),
            created_at: at(),
            updated_at: at(),
        };
        assert!(matches!(
            pap.update_group(ghost, at()),
            Err(AdminError::NotFound(_))
        ));

        // get_grant resolves an issued grant and returns None for an absent one.
        let grant = Grant {
            id: GrantId("g1".into()),
            subject: GrantSubject::Principal(account("ada")),
            action_pattern: ActionPattern("pack.read".into()),
            scope: ScopeRef::Global,
            effect: Effect::Allow,
        };
        pap.issue_grant(grant, at()).unwrap();
        assert_eq!(
            pap.get_grant(&GrantId("g1".into())).unwrap().unwrap().id,
            GrantId("g1".into())
        );
        assert!(pap.get_grant(&GrantId("absent".into())).unwrap().is_none());
    }

    #[test]
    fn repo_errors_map_onto_the_admin_error_surface() {
        assert_eq!(
            AdminError::from(RepoError::Conflict("x".into())),
            AdminError::AlreadyExists("x".into())
        );
        assert_eq!(
            AdminError::from(RepoError::NotFound("x".into())),
            AdminError::NotFound("x".into())
        );
        assert_eq!(
            AdminError::from(RepoError::Backend("x".into())),
            AdminError::Backend("x".into())
        );
    }
}
