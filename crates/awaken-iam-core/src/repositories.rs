//! Repository contracts the domain depends on.
//!
//! The core declares the persistence boundary as traits; adapters live at the
//! edges (an in-memory adapter for tests and the `local` client, a database
//! adapter for the service). Keeping the contracts here — not in the server —
//! preserves the [guardrails](../../../AGENTS.md): the core never references
//! SQL, a pool, or any concrete store, and the server depends inward to provide
//! the adapters.
//!
//! The repositories are grouped by the same subdomain scopes IAM partitions its
//! storage into (`iam.identity`, `iam.authz`, `iam.entitlement`), so a port and
//! the migration bundle that backs it line up one-to-one. References *between*
//! subdomains are by id resolved in the domain, never by a cross-component
//! foreign key — see [deployment](../../../docs/design/deployment.md).

use awaken_iam_contract::{
    Account, AccountId, ApiToken, ApiTokenId, ApiTokenPrefix, AuthorizationProfile,
    DirectoryNodeId, ExternalIdentity, ExternalIdentityId, ExternalIdentityKey, NamespaceId,
    OAuthLoginState, OAuthLoginStateId, OrgId, PrincipalRef, ProductSpacePlacement,
    ProductSpacePlacementStatus, ProductSpaceRef, ProfileLifecycle, Session, SessionId, Timestamp,
    WorkspaceId, WorkspaceOrgEdge,
};

use crate::oauth_provider::StoredAuthorizationCode;
use crate::{
    DirectoryNode, Grant, GrantId, Group, GroupId, Invitation, Organization, Plan, PlanId,
    RegisteredClient, ResourceEdge, RoleBinding, RoleDef, RoleId,
};

/// Error surface shared by every repository contract.
///
/// Adapters map their backend failures onto these variants so the domain and
/// application services handle persistence outcomes uniformly regardless of
/// whether the in-memory or database adapter is mounted.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum RepositoryError {
    /// A uniqueness invariant was violated (duplicate id or natural key).
    #[error("conflict: {0}")]
    Conflict(String),
    /// A referenced row was expected to exist but does not.
    #[error("not found: {0}")]
    NotFound(String),
    /// The backend failed for a reason outside the domain's control.
    #[error("storage backend error: {0}")]
    Backend(String),
}

/// Result alias for repository operations.
pub type RepositoryResult<T> = Result<T, RepositoryError>;

// ---------------------------------------------------------------------------
// iam.identity
// ---------------------------------------------------------------------------

/// Persistence for platform [`Account`] rows.
pub trait AccountRepository: Send + Sync {
    /// Resolve an account by id, returning `None` when absent.
    fn get(&self, id: &AccountId) -> RepositoryResult<Option<Account>>;
    /// Insert or replace account metadata.
    fn upsert(&self, account: Account) -> RepositoryResult<()>;
    /// List every account ordered by id for stable iteration.
    fn list(&self) -> RepositoryResult<Vec<Account>>;
}

/// Persistence for [`ExternalIdentity`] links (provider subject -> account).
///
/// The natural key is `(provider_key, subject)`; mutable claims such as email
/// never participate in lookup.
pub trait ExternalIdentityRepository: Send + Sync {
    /// Resolve an identity by its provider+subject uniqueness key.
    fn get_by_key(&self, key: &ExternalIdentityKey) -> RepositoryResult<Option<ExternalIdentity>>;
    /// Link a provider subject to an account, failing closed on a duplicate key.
    fn link(&self, identity: ExternalIdentity) -> RepositoryResult<()>;
    /// Refresh the mutable claims and `last_seen_at` of an existing identity.
    fn update_claims(&self, identity: ExternalIdentity) -> RepositoryResult<()>;
    /// List identities linked to an account, ordered by identity id.
    fn list_for_account(&self, account_id: &AccountId) -> RepositoryResult<Vec<ExternalIdentity>>;
}

/// Atomic commands spanning the platform Account aggregate and its external
/// identity links.
///
/// Query ownership remains with [`AccountRepository`] and [`ExternalIdentityRepository`].
/// This narrow port exists only for effects that must commit together so a
/// concurrent first login can never leave a half-created global account.
pub trait AccountIdentityRepository: Send + Sync {
    /// Create a new account and its first external identity in one transaction.
    fn provision(&self, account: Account, identity: ExternalIdentity) -> RepositoryResult<()>;

    /// Remove an exact identity owned by `account_id`, refusing the last link.
    fn unlink(
        &self,
        key: &ExternalIdentityKey,
        account_id: &AccountId,
    ) -> RepositoryResult<ExternalIdentity>;
}

/// Persistence for login [`Session`] rows.
pub trait SessionRepository: Send + Sync {
    /// Resolve a session by id.
    fn get(&self, id: &SessionId) -> RepositoryResult<Option<Session>>;
    /// Resolve a session from a presented bearer token hash.
    fn get_by_token_hash(&self, token_hash: &str) -> RepositoryResult<Option<Session>>;
    /// Persist a newly established session, failing on a duplicate id.
    fn create(&self, session: Session) -> RepositoryResult<()>;
    /// Replace an existing session (activity refresh, revocation).
    fn update(&self, session: Session) -> RepositoryResult<()>;
}

/// Persistence for long-lived, principal-scoped [`ApiToken`] rows.
///
/// The natural lookup key on the authentication path is the public
/// [`ApiTokenPrefix`]; only the argon2id `secret_hash` is stored, never the
/// cleartext token. Revocation is an in-place update of an existing row.
pub trait ApiTokenRepository: Send + Sync {
    /// Persist a newly minted token, failing closed on a duplicate id or prefix.
    fn create(&self, token: ApiToken) -> RepositoryResult<()>;
    /// Resolve a token by id.
    fn get(&self, id: &ApiTokenId) -> RepositoryResult<Option<ApiToken>>;
    /// Resolve a token from its presented public prefix.
    fn get_by_prefix(&self, prefix: &ApiTokenPrefix) -> RepositoryResult<Option<ApiToken>>;
    /// List tokens held by a principal, ordered by token id.
    fn list_for_principal(&self, principal: &PrincipalRef) -> RepositoryResult<Vec<ApiToken>>;
    /// Replace an existing token (revocation, scope update).
    fn update(&self, token: ApiToken) -> RepositoryResult<()>;
}

/// Persistence for in-flight OAuth login-state challenges.
pub trait LoginFlowRepository: Send + Sync {
    /// Record a freshly issued challenge, failing on a duplicate id.
    fn start(&self, state: OAuthLoginState) -> RepositoryResult<()>;
    /// Resolve a challenge by id without consuming it.
    fn get(&self, id: &OAuthLoginStateId) -> RepositoryResult<Option<OAuthLoginState>>;
    /// Mark a challenge consumed at `at`; consumed challenges cannot be reused.
    fn mark_consumed(&self, id: &OAuthLoginStateId, at: Timestamp) -> RepositoryResult<()>;
}

/// Persistence for downstream OAuth provider [`RegisteredClient`] rows.
///
/// These are the product clients allowed to integrate against IAM as an OAuth
/// authorization server. The natural key is the public `client_id`; only the
/// confidential `secret_hash` is stored, never the cleartext secret. Durable
/// authorization servers read this port directly on every operation rather
/// than hydrating a per-process registry snapshot.
pub trait OAuthClientRepository: Send + Sync {
    /// Insert or replace a registered client by its `client_id`.
    fn upsert(&self, client: RegisteredClient) -> RepositoryResult<()>;
    /// Resolve a registered client by id, returning `None` when absent.
    fn get(&self, client_id: &str) -> RepositoryResult<Option<RegisteredClient>>;
    /// List every registered client ordered by id.
    fn list(&self) -> RepositoryResult<Vec<RegisteredClient>>;
    /// Remove a registered client, failing closed when it is absent.
    fn remove(&self, client_id: &str) -> RepositoryResult<()>;
}

/// Persistence for short-lived downstream OAuth authorization codes.
///
/// Only the cleartext code's hash is stored. Redemption validates the returned
/// record in the domain, then calls [`AuthCodeRepository::consume_if_live`] as the
/// atomic replay fence shared by every replica.
pub trait AuthCodeRepository: Send + Sync {
    /// Persist a freshly issued, unconsumed code record.
    fn create(&self, code: StoredAuthorizationCode) -> RepositoryResult<()>;
    /// Resolve a record from the presented code hash.
    fn get(&self, code_hash: &str) -> RepositoryResult<Option<StoredAuthorizationCode>>;
    /// Atomically consume the code only when it is unconsumed and expires after
    /// `now`; returns `false` for absent, consumed, or expired records.
    fn consume_if_live(&self, code_hash: &str, now: &Timestamp) -> RepositoryResult<bool>;
}

// ---------------------------------------------------------------------------
// iam.authz
// ---------------------------------------------------------------------------

/// Persistence for [`Organization`] aggregates.
pub trait OrgRepository: Send + Sync {
    /// Resolve an organization by id, returning `None` when absent.
    fn get(&self, id: &OrgId) -> RepositoryResult<Option<Organization>>;
    /// Insert or replace an organization.
    fn upsert(&self, org: Organization) -> RepositoryResult<()>;
    /// List every organization ordered by id.
    fn list(&self) -> RepositoryResult<Vec<Organization>>;
    /// Remove an organization, failing closed when it is absent.
    fn remove(&self, id: &OrgId) -> RepositoryResult<()>;
}

/// Persistence authority for the user-visible, arbitrary-depth directory.
///
/// Every mutation is one adapter-owned transaction that advances the directory
/// revision exactly once. The directory revision is deliberately independent
/// from the authorization policy fence because moving placement metadata does
/// not change a product-space id or its permissions.
pub trait DirectoryRepository: Send + Sync {
    /// Atomically insert a node and its optional initial product-space binding.
    fn create_directory_node(
        &self,
        node: DirectoryNode,
        placement: Option<ProductSpacePlacement>,
        actor: &PrincipalRef,
    ) -> RepositoryResult<u64>;
    fn directory_node(&self, id: &DirectoryNodeId) -> RepositoryResult<Option<DirectoryNode>>;
    fn directory_children(
        &self,
        org_id: &OrgId,
        parent_id: Option<&DirectoryNodeId>,
    ) -> RepositoryResult<(u64, Vec<DirectoryNode>)>;
    /// Move a live node inside its immutable organization, rejecting cycles.
    fn move_directory_node(
        &self,
        id: &DirectoryNodeId,
        parent_id: Option<&DirectoryNodeId>,
        updated_at: &Timestamp,
        actor: &PrincipalRef,
    ) -> RepositoryResult<u64>;
    /// Replace display metadata while preserving parent and product binding.
    fn update_directory_node(
        &self,
        id: &DirectoryNodeId,
        name: &str,
        slug: &str,
        description: Option<&str>,
        updated_at: &Timestamp,
        actor: &PrincipalRef,
    ) -> RepositoryResult<u64>;
    /// Archive a live leaf. Product-space bindings remain stable and resolvable.
    fn archive_directory_node(
        &self,
        id: &DirectoryNodeId,
        updated_at: &Timestamp,
        actor: &PrincipalRef,
    ) -> RepositoryResult<u64>;
    /// Restore an archived node without changing its user-selected metadata or
    /// parent. The parent, when present, must still be live in the same Org.
    fn restore_directory_node(
        &self,
        id: &DirectoryNodeId,
        updated_at: &Timestamp,
        actor: &PrincipalRef,
    ) -> RepositoryResult<u64>;
    /// Atomically activate or retire one existing product-space placement.
    /// Activation also restores its node when necessary; retirement never
    /// mutates the user-managed node hierarchy or archive state.
    fn set_product_space_placement_status(
        &self,
        org_id: &OrgId,
        product_space: &ProductSpaceRef,
        status: ProductSpacePlacementStatus,
        updated_at: &Timestamp,
        actor: &PrincipalRef,
    ) -> RepositoryResult<u64>;
    /// Resolve the current placement of one stable product space.
    fn product_space_placement(
        &self,
        org_id: &OrgId,
        product_space: &ProductSpaceRef,
    ) -> RepositoryResult<Option<ProductSpacePlacement>>;
    /// Read the authoritative freshness fence for one organization Directory.
    fn directory_revision(&self, org_id: &OrgId) -> RepositoryResult<u64>;
}

/// One idempotent IAM-owned organization privacy lifecycle command.
///
/// Implementations remove the organization plus every IAM authorization and
/// credential projection reachable from its authoritative scope graph.  The
/// boolean reports whether this invocation changed any row; an exact retry is
/// a successful `false`, never a not-found error.
pub trait OrgPrivacyRepository: Send + Sync {
    fn erase_org_privacy(&self, id: &OrgId) -> RepositoryResult<bool>;
}

/// Persistence for [`Group`] aggregates.
pub trait GroupRepository: Send + Sync {
    /// Resolve a group by id, returning `None` when absent.
    fn get(&self, id: &GroupId) -> RepositoryResult<Option<Group>>;
    /// Insert or replace a group.
    fn upsert(&self, group: Group) -> RepositoryResult<()>;
    /// List every group ordered by id.
    fn list(&self) -> RepositoryResult<Vec<Group>>;
    /// Remove a group, failing closed when it is absent.
    fn remove(&self, id: &GroupId) -> RepositoryResult<()>;
}

/// Persistence for [`RoleDef`] definitions.
pub trait RoleRepository: Send + Sync {
    /// Resolve a role definition by id, returning `None` when absent.
    fn get(&self, id: &RoleId) -> RepositoryResult<Option<RoleDef>>;
    /// Insert or replace a role definition.
    fn upsert(&self, role: RoleDef) -> RepositoryResult<()>;
    /// List every role definition ordered by id.
    fn list(&self) -> RepositoryResult<Vec<RoleDef>>;
    /// Remove a role definition, failing closed when it is absent.
    fn remove(&self, id: &RoleId) -> RepositoryResult<()>;
}

/// Seed (upsert) a set of role definitions into `repo`.
///
/// The product-neutral seeding *mechanism*: idempotently upsert each role so a
/// deployment can call this on every boot without duplicating or drifting roles,
/// and roles under other ids are untouched. The catalog itself — which roles
/// carry which patterns — is policy the caller supplies; a preset pack such as
/// `awaken-iam-preset` builds it, while the kernel only drives the loop and
/// never names a product's roles.
pub fn seed_roles(
    repo: &dyn RoleRepository,
    roles: impl IntoIterator<Item = RoleDef>,
) -> RepositoryResult<()> {
    for role in roles {
        repo.upsert(role)?;
    }
    Ok(())
}

/// Persistence for authorization [`Grant`] rows.
pub trait GrantRepository: Send + Sync {
    /// Insert or replace a grant.
    fn put(&self, grant: Grant) -> RepositoryResult<()>;
    /// Resolve a grant by id.
    fn get(&self, id: &GrantId) -> RepositoryResult<Option<Grant>>;
    /// List every grant ordered by id.
    fn list(&self) -> RepositoryResult<Vec<Grant>>;
    /// Remove a grant, failing closed when it is absent.
    fn remove(&self, id: &GrantId) -> RepositoryResult<()>;
}

/// Persistence for role membership [`RoleBinding`] rows.
pub trait RoleBindingRepository: Send + Sync {
    /// Record that a principal holds a role at a scope (idempotent).
    fn add(&self, binding: RoleBinding) -> RepositoryResult<()>;
    /// List every binding held by a principal.
    fn list_for_principal(&self, principal: &PrincipalRef) -> RepositoryResult<Vec<RoleBinding>>;
    /// List every binding.
    fn list(&self) -> RepositoryResult<Vec<RoleBinding>>;
    /// Remove an exact binding, failing closed when it is absent.
    fn remove(&self, binding: &RoleBinding) -> RepositoryResult<()>;
    /// Atomically replace the managed role family held by one principal at one
    /// exact scope. Roles outside `managed_roles` remain untouched.
    fn replace_scoped(
        &self,
        principal: &PrincipalRef,
        scope: &awaken_iam_contract::ScopeRef,
        managed_roles: &[RoleId],
        replacement_roles: &[RoleId],
    ) -> RepositoryResult<()>;
}

/// Persistence and atomic materialization for organization invitations.
/// Accepting changes the invitation and creates every declared role binding in
/// one repository transaction so a user is never half-added.
pub trait InvitationRepository: Send + Sync {
    fn create_invitation(&self, invitation: Invitation) -> RepositoryResult<()>;
    fn get_invitation(
        &self,
        id: &awaken_iam_contract::InvitationId,
    ) -> RepositoryResult<Option<Invitation>>;
    fn get_invitation_by_idempotency(
        &self,
        org_id: &OrgId,
        idempotency_key: &str,
    ) -> RepositoryResult<Option<Invitation>>;
    fn list_invitations_for_org(&self, org_id: &OrgId) -> RepositoryResult<Vec<Invitation>>;
    /// Replace a pending invitation iff its current token hash matches.
    fn replace_pending_invitation(
        &self,
        invitation: Invitation,
        expected_token_hash: &str,
    ) -> RepositoryResult<bool>;
    /// Atomically accept and materialize bindings iff pending and token matches.
    fn accept_pending_invitation(
        &self,
        id: &awaken_iam_contract::InvitationId,
        expected_token_hash: &str,
        account_id: &AccountId,
        at: &Timestamp,
    ) -> RepositoryResult<Option<Invitation>>;
}

/// Persistence for the product resource-model registry (parent edges).
pub trait ResourceModelRepository: Send + Sync {
    /// Register or replace the parent edge for a resource instance.
    fn put_edge(&self, edge: ResourceEdge) -> RepositoryResult<()>;
    /// List every registered parent edge.
    fn list_edges(&self) -> RepositoryResult<Vec<ResourceEdge>>;
    /// Persist or replace one well-known Workspace → Org scope edge.
    fn put_workspace_org(&self, _edge: WorkspaceOrgEdge) -> RepositoryResult<()> {
        Err(RepositoryError::Backend(
            "Workspace to Org projections are not supported by this adapter".into(),
        ))
    }
    /// Resolve a Workspace → Org scope edge.
    fn workspace_org(
        &self,
        _workspace_id: &WorkspaceId,
    ) -> RepositoryResult<Option<WorkspaceOrgEdge>> {
        Err(RepositoryError::Backend(
            "Workspace to Org projections are not supported by this adapter".into(),
        ))
    }
    /// List every persisted Workspace → Org edge in stable workspace order.
    fn list_workspace_orgs(&self) -> RepositoryResult<Vec<WorkspaceOrgEdge>> {
        Err(RepositoryError::Backend(
            "Workspace to Org projections are not supported by this adapter".into(),
        ))
    }
}

/// Persistence for immutable authorization-profile revisions and the atomic
/// active-head pointer of each consumer namespace.
pub trait AuthorizationProfileRepository: Send + Sync {
    /// Store a new draft revision. Namespace/revision is unique and immutable.
    fn create_profile(&self, profile: AuthorizationProfile) -> RepositoryResult<()>;
    /// Resolve one revision, projecting the active-head state when applicable.
    fn get_profile(
        &self,
        namespace: &NamespaceId,
        revision: u64,
    ) -> RepositoryResult<Option<AuthorizationProfile>>;
    /// List every revision in ascending revision order.
    fn list_profiles(&self, namespace: &NamespaceId)
    -> RepositoryResult<Vec<AuthorizationProfile>>;
    /// Advance a draft to validated after deterministic validation succeeds.
    fn set_profile_lifecycle(
        &self,
        namespace: &NamespaceId,
        revision: u64,
        lifecycle: ProfileLifecycle,
    ) -> RepositoryResult<()>;
    /// Atomically compare-and-set the active revision, returning its predecessor.
    fn activate_profile(
        &self,
        namespace: &NamespaceId,
        revision: u64,
        expected_active_revision: Option<u64>,
    ) -> RepositoryResult<Option<u64>>;
    /// Compare-and-set removal of one active head while retaining the revision.
    fn retire_active_profile(
        &self,
        namespace: &NamespaceId,
        expected_active_revision: u64,
    ) -> RepositoryResult<AuthorizationProfile>;
    /// Resolve the active revision for a namespace.
    fn active_profile(
        &self,
        namespace: &NamespaceId,
    ) -> RepositoryResult<Option<AuthorizationProfile>>;
    /// List the active profile of every namespace for process-start hydration.
    fn active_profiles(&self) -> RepositoryResult<Vec<AuthorizationProfile>>;
}

// ---------------------------------------------------------------------------
// iam.entitlement
// ---------------------------------------------------------------------------

/// Persistence for entitlement [`Plan`] definitions and principal assignments.
///
/// A principal's plan assignment is the v1 subscription record; it references a
/// plan by id, resolved in the domain rather than by a database foreign key.
pub trait PlanRepository: Send + Sync {
    /// Insert or replace a plan definition.
    fn put(&self, plan: Plan) -> RepositoryResult<()>;
    /// Resolve a plan by id.
    fn get(&self, id: &PlanId) -> RepositoryResult<Option<Plan>>;
    /// List every plan ordered by id.
    fn list(&self) -> RepositoryResult<Vec<Plan>>;
    /// Assign (subscribe) a principal to a plan, replacing any prior assignment.
    fn subscribe(&self, principal: PrincipalRef, plan: PlanId) -> RepositoryResult<()>;
    /// Resolve the plan a principal is currently subscribed to.
    fn subscription(&self, principal: &PrincipalRef) -> RepositoryResult<Option<PlanId>>;
}

// ---------------------------------------------------------------------------
// audit
// ---------------------------------------------------------------------------

/// A single append-only audit record.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuditEvent {
    /// When the event occurred.
    pub at: Timestamp,
    /// Principal responsible for the event, when one is attributable.
    pub actor: Option<PrincipalRef>,
    /// Stable action key, for example `account.disable` or `grant.revoke`.
    pub action: String,
    /// Free-form human-readable detail captured with the event.
    pub detail: String,
}

/// Append-only sink for audit events.
pub trait AuditSink: Send + Sync {
    /// Append an audit event.
    fn record(&self, event: AuditEvent) -> RepositoryResult<()>;
    /// Read the recorded events in append order.
    fn events(&self) -> RepositoryResult<Vec<AuditEvent>>;
}

/// Identifier helper used by adapters to derive a stable external identity id
/// from its natural key when one was not supplied by the caller.
pub fn external_identity_id_hint(key: &ExternalIdentityKey) -> ExternalIdentityId {
    ExternalIdentityId(format!("{}:{}", key.provider_key.0, key.subject.0))
}
