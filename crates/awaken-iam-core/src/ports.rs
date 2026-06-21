//! Repository ports (hexagonal) the domain depends on.
//!
//! The core declares the persistence boundary as traits; adapters live at the
//! edges (an in-memory adapter for tests and the `local` client, a database
//! adapter for the service). Keeping the ports here — not in the server —
//! preserves the [guardrails](../../../AGENTS.md): the core never references
//! SQL, a pool, or any concrete store, and the server depends inward to provide
//! the adapters.
//!
//! The ports are grouped by the same subdomain scopes IAM partitions its
//! storage into (`iam.identity`, `iam.authz`, `iam.entitlement`), so a port and
//! the migration bundle that backs it line up one-to-one. References *between*
//! subdomains are by id resolved in the domain, never by a cross-component
//! foreign key — see [deployment](../../../docs/design/deployment.md).

use awaken_iam_contract::{
    Account, AccountId, ApiToken, ApiTokenId, ApiTokenPrefix, ExternalIdentity, ExternalIdentityId,
    ExternalIdentityKey, OAuthLoginState, OAuthLoginStateId, OrgId, PrincipalRef, Session,
    SessionId, Timestamp,
};

use crate::{
    Grant, GrantId, Group, GroupId, Organization, Plan, PlanId, ResourceEdge, RoleBinding, RoleDef,
    RoleId,
};

/// Error surface shared by every repository port.
///
/// Adapters map their backend failures onto these variants so the domain and
/// application services handle persistence outcomes uniformly regardless of
/// whether the in-memory or database adapter is mounted.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum RepoError {
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
pub type RepoResult<T> = Result<T, RepoError>;

// ---------------------------------------------------------------------------
// iam.identity
// ---------------------------------------------------------------------------

/// Persistence for platform [`Account`] rows.
pub trait AccountRepo: Send + Sync {
    /// Resolve an account by id, returning `None` when absent.
    fn get(&self, id: &AccountId) -> RepoResult<Option<Account>>;
    /// Insert or replace account metadata.
    fn upsert(&self, account: Account) -> RepoResult<()>;
    /// List every account ordered by id for stable iteration.
    fn list(&self) -> RepoResult<Vec<Account>>;
}

/// Persistence for [`ExternalIdentity`] links (provider subject -> account).
///
/// The natural key is `(provider_key, subject)`; mutable claims such as email
/// never participate in lookup.
pub trait ExternalIdentityRepo: Send + Sync {
    /// Resolve an identity by its provider+subject uniqueness key.
    fn get_by_key(&self, key: &ExternalIdentityKey) -> RepoResult<Option<ExternalIdentity>>;
    /// Link a provider subject to an account, failing closed on a duplicate key.
    fn link(&self, identity: ExternalIdentity) -> RepoResult<()>;
    /// Refresh the mutable claims and `last_seen_at` of an existing identity.
    fn update_claims(&self, identity: ExternalIdentity) -> RepoResult<()>;
    /// List identities linked to an account, ordered by identity id.
    fn list_for_account(&self, account_id: &AccountId) -> RepoResult<Vec<ExternalIdentity>>;
}

/// Persistence for login [`Session`] rows.
pub trait SessionRepo: Send + Sync {
    /// Resolve a session by id.
    fn get(&self, id: &SessionId) -> RepoResult<Option<Session>>;
    /// Resolve a session from a presented bearer token hash.
    fn get_by_token_hash(&self, token_hash: &str) -> RepoResult<Option<Session>>;
    /// Persist a newly established session, failing on a duplicate id.
    fn create(&self, session: Session) -> RepoResult<()>;
    /// Replace an existing session (activity refresh, revocation).
    fn update(&self, session: Session) -> RepoResult<()>;
}

/// Persistence for long-lived, principal-scoped [`ApiToken`] rows.
///
/// The natural lookup key on the authentication path is the public
/// [`ApiTokenPrefix`]; only the argon2id `secret_hash` is stored, never the
/// cleartext token. Revocation is an in-place update of an existing row.
pub trait ApiTokenRepo: Send + Sync {
    /// Persist a newly minted token, failing closed on a duplicate id or prefix.
    fn create(&self, token: ApiToken) -> RepoResult<()>;
    /// Resolve a token by id.
    fn get(&self, id: &ApiTokenId) -> RepoResult<Option<ApiToken>>;
    /// Resolve a token from its presented public prefix.
    fn get_by_prefix(&self, prefix: &ApiTokenPrefix) -> RepoResult<Option<ApiToken>>;
    /// List tokens held by a principal, ordered by token id.
    fn list_for_principal(&self, principal: &PrincipalRef) -> RepoResult<Vec<ApiToken>>;
    /// Replace an existing token (revocation, scope update).
    fn update(&self, token: ApiToken) -> RepoResult<()>;
}

/// Persistence for in-flight OAuth login-state challenges.
pub trait LoginFlowRepo: Send + Sync {
    /// Record a freshly issued challenge, failing on a duplicate id.
    fn start(&self, state: OAuthLoginState) -> RepoResult<()>;
    /// Resolve a challenge by id without consuming it.
    fn get(&self, id: &OAuthLoginStateId) -> RepoResult<Option<OAuthLoginState>>;
    /// Mark a challenge consumed at `at`; consumed challenges cannot be reused.
    fn mark_consumed(&self, id: &OAuthLoginStateId, at: Timestamp) -> RepoResult<()>;
}

// ---------------------------------------------------------------------------
// iam.authz
// ---------------------------------------------------------------------------

/// Persistence for [`Organization`] aggregates.
pub trait OrgRepo: Send + Sync {
    /// Resolve an organization by id, returning `None` when absent.
    fn get(&self, id: &OrgId) -> RepoResult<Option<Organization>>;
    /// Insert or replace an organization.
    fn upsert(&self, org: Organization) -> RepoResult<()>;
    /// List every organization ordered by id.
    fn list(&self) -> RepoResult<Vec<Organization>>;
    /// Remove an organization, failing closed when it is absent.
    fn remove(&self, id: &OrgId) -> RepoResult<()>;
}

/// Persistence for [`Group`] aggregates.
pub trait GroupRepo: Send + Sync {
    /// Resolve a group by id, returning `None` when absent.
    fn get(&self, id: &GroupId) -> RepoResult<Option<Group>>;
    /// Insert or replace a group.
    fn upsert(&self, group: Group) -> RepoResult<()>;
    /// List every group ordered by id.
    fn list(&self) -> RepoResult<Vec<Group>>;
    /// Remove a group, failing closed when it is absent.
    fn remove(&self, id: &GroupId) -> RepoResult<()>;
}

/// Persistence for [`RoleDef`] definitions.
pub trait RoleRepo: Send + Sync {
    /// Resolve a role definition by id, returning `None` when absent.
    fn get(&self, id: &RoleId) -> RepoResult<Option<RoleDef>>;
    /// Insert or replace a role definition.
    fn upsert(&self, role: RoleDef) -> RepoResult<()>;
    /// List every role definition ordered by id.
    fn list(&self) -> RepoResult<Vec<RoleDef>>;
    /// Remove a role definition, failing closed when it is absent.
    fn remove(&self, id: &RoleId) -> RepoResult<()>;
}

/// Persistence for authorization [`Grant`] rows.
pub trait GrantRepo: Send + Sync {
    /// Insert or replace a grant.
    fn put(&self, grant: Grant) -> RepoResult<()>;
    /// Resolve a grant by id.
    fn get(&self, id: &GrantId) -> RepoResult<Option<Grant>>;
    /// List every grant ordered by id.
    fn list(&self) -> RepoResult<Vec<Grant>>;
    /// Remove a grant, failing closed when it is absent.
    fn remove(&self, id: &GrantId) -> RepoResult<()>;
}

/// Persistence for role membership [`RoleBinding`] rows.
pub trait RoleBindingRepo: Send + Sync {
    /// Record that a principal holds a role at a scope (idempotent).
    fn add(&self, binding: RoleBinding) -> RepoResult<()>;
    /// List every binding held by a principal.
    fn list_for_principal(&self, principal: &PrincipalRef) -> RepoResult<Vec<RoleBinding>>;
    /// List every binding.
    fn list(&self) -> RepoResult<Vec<RoleBinding>>;
    /// Remove an exact binding, failing closed when it is absent.
    fn remove(&self, binding: &RoleBinding) -> RepoResult<()>;
}

/// Persistence for the product resource-model registry (parent edges).
pub trait ResourceModelRepo: Send + Sync {
    /// Register or replace the parent edge for a resource instance.
    fn put_edge(&self, edge: ResourceEdge) -> RepoResult<()>;
    /// List every registered parent edge.
    fn list_edges(&self) -> RepoResult<Vec<ResourceEdge>>;
}

// ---------------------------------------------------------------------------
// iam.entitlement
// ---------------------------------------------------------------------------

/// Persistence for entitlement [`Plan`] definitions and principal assignments.
///
/// A principal's plan assignment is the v1 subscription record; it references a
/// plan by id, resolved in the domain rather than by a database foreign key.
pub trait PlanRepo: Send + Sync {
    /// Insert or replace a plan definition.
    fn put(&self, plan: Plan) -> RepoResult<()>;
    /// Resolve a plan by id.
    fn get(&self, id: &PlanId) -> RepoResult<Option<Plan>>;
    /// List every plan ordered by id.
    fn list(&self) -> RepoResult<Vec<Plan>>;
    /// Assign (subscribe) a principal to a plan, replacing any prior assignment.
    fn subscribe(&self, principal: PrincipalRef, plan: PlanId) -> RepoResult<()>;
    /// Resolve the plan a principal is currently subscribed to.
    fn subscription(&self, principal: &PrincipalRef) -> RepoResult<Option<PlanId>>;
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
    fn record(&self, event: AuditEvent) -> RepoResult<()>;
    /// Read the recorded events in append order.
    fn events(&self) -> RepoResult<Vec<AuditEvent>>;
}

/// Identifier helper used by adapters to derive a stable external identity id
/// from its natural key when one was not supplied by the caller.
pub fn external_identity_id_hint(key: &ExternalIdentityKey) -> ExternalIdentityId {
    ExternalIdentityId(format!("{}:{}", key.provider_key.0, key.subject.0))
}
