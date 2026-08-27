//! In-memory adapter implementing the core's repository contracts.
//!
//! This backs tests and the `local` client deployment. It enforces the same
//! uniqueness and lifecycle invariants the database adapter does, so code
//! exercised against it behaves identically once a real pool is mounted. State
//! lives behind a single [`Mutex`] keyed by subdomain, mirroring the
//! scope-partitioned bundles without ever coupling them by a foreign key.

use std::collections::{BTreeMap, BTreeSet};
use std::sync::{Arc, Mutex};

use awaken_iam_contract::{
    Account, AccountId, ApiToken, ApiTokenId, ApiTokenPrefix, AuthorizationProfile,
    ExternalIdentity, ExternalIdentityKey, InvitationId, InvitationStatus, NamespaceId,
    OAuthLoginState, OAuthLoginStateId, OrgId, PrincipalRef, ProductSpacePlacement,
    ProfileLifecycle, ScopeRef, Session, SessionId, Timestamp, WorkspaceId, WorkspaceOrgEdge,
};
#[cfg(any(test, feature = "test-support"))]
use awaken_iam_contract::{DirectoryNodeId, ProductSpaceRef};
#[cfg(any(test, feature = "test-support"))]
use awaken_iam_core::DirectoryRepository;
use awaken_iam_core::{
    AccountIdentityRepository, AccountRepository, ApiTokenRepository, AuditEvent, AuditSink,
    AuthCodeRepository, AuthorizationProfileRepository, DirectoryNode, ExternalIdentityRepository,
    Grant, GrantId, GrantRepository, GrantSubject, Group, GroupId, GroupRepository, Invitation,
    InvitationRepository, LoginFlowRepository, OAuthClientRepository, OrgPrivacyRepository,
    OrgRepository, Organization, OrganizationPrivacyScope, Plan, PlanId, PlanRepository,
    RegisteredClient, RepositoryError, RepositoryResult, ResourceEdge, ResourceModelRepository,
    RoleBinding, RoleBindingRepository, RoleDef, RoleId, RoleRepository, SessionRepository,
    StoredAuthorizationCode,
};

use super::fence::{Fence, FenceStore};

#[cfg(any(test, feature = "test-support"))]
mod directory;

/// JSON-serializable key used to index rows whose natural key is a contract
/// value object (principal, scope, resource coordinate).
fn json_key<T: serde::Serialize>(value: &T, what: &str) -> RepositoryResult<String> {
    serde_json::to_string(value)
        .map_err(|err| RepositoryError::Backend(format!("encode {what}: {err}")))
}

#[derive(Default)]
struct Identity {
    accounts: BTreeMap<String, Account>,
    external: BTreeMap<String, ExternalIdentity>,
    sessions: BTreeMap<String, Session>,
    sessions_by_token: BTreeMap<String, String>,
    login_flows: BTreeMap<String, OAuthLoginState>,
    api_tokens: BTreeMap<String, ApiToken>,
    api_tokens_by_prefix: BTreeMap<String, String>,
    oauth_clients: BTreeMap<String, RegisteredClient>,
    oauth_codes: BTreeMap<String, StoredAuthorizationCode>,
}

#[derive(Default)]
struct Authz {
    orgs: BTreeMap<String, Organization>,
    groups: BTreeMap<String, Group>,
    roles: BTreeMap<String, RoleDef>,
    grants: BTreeMap<String, Grant>,
    role_bindings: BTreeMap<String, RoleBinding>,
    invitations: BTreeMap<String, Invitation>,
    resource_edges: BTreeMap<String, ResourceEdge>,
    workspace_orgs: BTreeMap<String, WorkspaceOrgEdge>,
    profiles: BTreeMap<(String, u64), AuthorizationProfile>,
    active_profiles: BTreeMap<String, u64>,
    directory_nodes: BTreeMap<String, DirectoryNode>,
    product_space_bindings: BTreeMap<String, ProductSpacePlacement>,
    #[cfg(any(test, feature = "test-support"))]
    directory_revision: u64,
}

#[derive(Default)]
struct Entitlement {
    plans: BTreeMap<String, Plan>,
    subscriptions: BTreeMap<String, PlanId>,
}

/// In-memory implementation of every IAM repository port.
#[derive(Clone, Default)]
pub struct InMemoryStore {
    identity: Arc<Mutex<Identity>>,
    authz: Arc<Mutex<Authz>>,
    entitlement: Arc<Mutex<Entitlement>>,
    audit: Arc<Mutex<Vec<AuditEvent>>>,
    fence: Arc<Mutex<Fence>>,
}

impl std::fmt::Debug for InMemoryStore {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("InMemoryStore").finish_non_exhaustive()
    }
}

impl InMemoryStore {
    /// Create an empty store.
    pub fn new() -> Self {
        Self::default()
    }
}

fn external_key(key: &ExternalIdentityKey) -> String {
    format!("{}\u{1f}{}", key.provider_key.0, key.subject.0)
}

impl AccountRepository for InMemoryStore {
    fn get(&self, id: &AccountId) -> RepositoryResult<Option<Account>> {
        Ok(self.identity.lock().unwrap().accounts.get(&id.0).cloned())
    }

    fn upsert(&self, account: Account) -> RepositoryResult<()> {
        self.identity
            .lock()
            .unwrap()
            .accounts
            .insert(account.id.0.clone(), account);
        Ok(())
    }

    fn list(&self) -> RepositoryResult<Vec<Account>> {
        Ok(self
            .identity
            .lock()
            .unwrap()
            .accounts
            .values()
            .cloned()
            .collect())
    }
}

impl ExternalIdentityRepository for InMemoryStore {
    fn get_by_key(&self, key: &ExternalIdentityKey) -> RepositoryResult<Option<ExternalIdentity>> {
        Ok(self
            .identity
            .lock()
            .unwrap()
            .external
            .get(&external_key(key))
            .cloned())
    }

    fn link(&self, identity: ExternalIdentity) -> RepositoryResult<()> {
        let key = external_key(&identity.key());
        let mut guard = self.identity.lock().unwrap();
        if guard.external.contains_key(&key) {
            return Err(RepositoryError::Conflict(format!(
                "external identity {key} is already linked"
            )));
        }
        guard.external.insert(key, identity);
        Ok(())
    }

    fn update_claims(&self, identity: ExternalIdentity) -> RepositoryResult<()> {
        let key = external_key(&identity.key());
        let mut guard = self.identity.lock().unwrap();
        if !guard.external.contains_key(&key) {
            return Err(RepositoryError::NotFound(format!(
                "external identity {key} is not linked"
            )));
        }
        guard.external.insert(key, identity);
        Ok(())
    }

    fn list_for_account(&self, account_id: &AccountId) -> RepositoryResult<Vec<ExternalIdentity>> {
        let guard = self.identity.lock().unwrap();
        let mut found: Vec<ExternalIdentity> = guard
            .external
            .values()
            .filter(|identity| &identity.account_id == account_id)
            .cloned()
            .collect();
        found.sort_by(|a, b| a.id.0.cmp(&b.id.0));
        Ok(found)
    }
}

impl AccountIdentityRepository for InMemoryStore {
    fn provision(&self, account: Account, identity: ExternalIdentity) -> RepositoryResult<()> {
        let key = external_key(&identity.key());
        let mut guard = self.identity.lock().unwrap();
        if guard.accounts.contains_key(&account.id.0) || guard.external.contains_key(&key) {
            return Err(RepositoryError::Conflict(format!(
                "account {} or external identity {key} already exists",
                account.id.0
            )));
        }
        guard.accounts.insert(account.id.0.clone(), account);
        guard.external.insert(key, identity);
        Ok(())
    }

    fn unlink(
        &self,
        key: &ExternalIdentityKey,
        account_id: &AccountId,
    ) -> RepositoryResult<ExternalIdentity> {
        let encoded = external_key(key);
        let mut guard = self.identity.lock().unwrap();
        let identity = guard
            .external
            .get(&encoded)
            .cloned()
            .ok_or_else(|| RepositoryError::NotFound(format!("external identity {encoded}")))?;
        if &identity.account_id != account_id {
            return Err(RepositoryError::Conflict(format!(
                "external identity {encoded} belongs to another account"
            )));
        }
        let linked = guard
            .external
            .values()
            .filter(|candidate| &candidate.account_id == account_id)
            .count();
        if linked <= 1 {
            return Err(RepositoryError::Conflict(format!(
                "account {} must retain one external identity",
                account_id.0
            )));
        }
        guard.external.remove(&encoded);
        Ok(identity)
    }
}

impl SessionRepository for InMemoryStore {
    fn get(&self, id: &SessionId) -> RepositoryResult<Option<Session>> {
        Ok(self.identity.lock().unwrap().sessions.get(&id.0).cloned())
    }

    fn get_by_token_hash(&self, token_hash: &str) -> RepositoryResult<Option<Session>> {
        let guard = self.identity.lock().unwrap();
        Ok(guard
            .sessions_by_token
            .get(token_hash)
            .and_then(|id| guard.sessions.get(id))
            .cloned())
    }

    fn create(&self, session: Session) -> RepositoryResult<()> {
        let mut guard = self.identity.lock().unwrap();
        if guard.sessions.contains_key(&session.id.0) {
            return Err(RepositoryError::Conflict(format!(
                "session {} already exists",
                session.id.0
            )));
        }
        guard
            .sessions_by_token
            .insert(session.token_hash.clone(), session.id.0.clone());
        guard.sessions.insert(session.id.0.clone(), session);
        Ok(())
    }

    fn update(&self, session: Session) -> RepositoryResult<()> {
        let mut guard = self.identity.lock().unwrap();
        if !guard.sessions.contains_key(&session.id.0) {
            return Err(RepositoryError::NotFound(format!(
                "session {} does not exist",
                session.id.0
            )));
        }
        guard
            .sessions_by_token
            .insert(session.token_hash.clone(), session.id.0.clone());
        guard.sessions.insert(session.id.0.clone(), session);
        Ok(())
    }
}

impl LoginFlowRepository for InMemoryStore {
    fn start(&self, state: OAuthLoginState) -> RepositoryResult<()> {
        let mut guard = self.identity.lock().unwrap();
        if guard.login_flows.contains_key(&state.id.0) {
            return Err(RepositoryError::Conflict(format!(
                "login flow {} already started",
                state.id.0
            )));
        }
        guard.login_flows.insert(state.id.0.clone(), state);
        Ok(())
    }

    fn get(&self, id: &OAuthLoginStateId) -> RepositoryResult<Option<OAuthLoginState>> {
        Ok(self
            .identity
            .lock()
            .unwrap()
            .login_flows
            .get(&id.0)
            .cloned())
    }

    fn mark_consumed(&self, id: &OAuthLoginStateId, at: Timestamp) -> RepositoryResult<()> {
        let mut guard = self.identity.lock().unwrap();
        let flow = guard
            .login_flows
            .get_mut(&id.0)
            .ok_or_else(|| RepositoryError::NotFound(format!("login flow {} not found", id.0)))?;
        if flow.consumed_at.is_some() {
            return Err(RepositoryError::Conflict(format!(
                "login flow {} already consumed",
                id.0
            )));
        }
        flow.consumed_at = Some(at);
        Ok(())
    }
}

impl ApiTokenRepository for InMemoryStore {
    fn create(&self, token: ApiToken) -> RepositoryResult<()> {
        let mut guard = self.identity.lock().unwrap();
        if guard.api_tokens.contains_key(&token.id.0) {
            return Err(RepositoryError::Conflict(format!(
                "api token {} already exists",
                token.id.0
            )));
        }
        if guard.api_tokens_by_prefix.contains_key(&token.prefix.0) {
            return Err(RepositoryError::Conflict(format!(
                "api token prefix {} already exists",
                token.prefix.0
            )));
        }
        guard
            .api_tokens_by_prefix
            .insert(token.prefix.0.clone(), token.id.0.clone());
        guard.api_tokens.insert(token.id.0.clone(), token);
        Ok(())
    }

    fn get(&self, id: &ApiTokenId) -> RepositoryResult<Option<ApiToken>> {
        Ok(self.identity.lock().unwrap().api_tokens.get(&id.0).cloned())
    }

    fn get_by_prefix(&self, prefix: &ApiTokenPrefix) -> RepositoryResult<Option<ApiToken>> {
        let guard = self.identity.lock().unwrap();
        Ok(guard
            .api_tokens_by_prefix
            .get(&prefix.0)
            .and_then(|id| guard.api_tokens.get(id))
            .cloned())
    }

    fn list_for_principal(&self, principal: &PrincipalRef) -> RepositoryResult<Vec<ApiToken>> {
        let guard = self.identity.lock().unwrap();
        let mut found: Vec<ApiToken> = guard
            .api_tokens
            .values()
            .filter(|token| &token.principal == principal)
            .cloned()
            .collect();
        found.sort_by(|a, b| a.id.0.cmp(&b.id.0));
        Ok(found)
    }

    fn update(&self, token: ApiToken) -> RepositoryResult<()> {
        let mut guard = self.identity.lock().unwrap();
        if !guard.api_tokens.contains_key(&token.id.0) {
            return Err(RepositoryError::NotFound(format!(
                "api token {} does not exist",
                token.id.0
            )));
        }
        guard
            .api_tokens_by_prefix
            .insert(token.prefix.0.clone(), token.id.0.clone());
        guard.api_tokens.insert(token.id.0.clone(), token);
        Ok(())
    }
}

impl OAuthClientRepository for InMemoryStore {
    fn upsert(&self, client: RegisteredClient) -> RepositoryResult<()> {
        self.identity
            .lock()
            .unwrap()
            .oauth_clients
            .insert(client.client_id.clone(), client);
        Ok(())
    }

    fn get(&self, client_id: &str) -> RepositoryResult<Option<RegisteredClient>> {
        Ok(self
            .identity
            .lock()
            .unwrap()
            .oauth_clients
            .get(client_id)
            .cloned())
    }

    fn list(&self) -> RepositoryResult<Vec<RegisteredClient>> {
        Ok(self
            .identity
            .lock()
            .unwrap()
            .oauth_clients
            .values()
            .cloned()
            .collect())
    }

    fn remove(&self, client_id: &str) -> RepositoryResult<()> {
        self.identity
            .lock()
            .unwrap()
            .oauth_clients
            .remove(client_id)
            .map(|_| ())
            .ok_or_else(|| RepositoryError::NotFound(format!("oauth client {client_id} not found")))
    }
}

impl AuthCodeRepository for InMemoryStore {
    fn create(&self, code: StoredAuthorizationCode) -> RepositoryResult<()> {
        let mut identity = self.identity.lock().unwrap();
        if identity.oauth_codes.contains_key(&code.code_hash) {
            return Err(RepositoryError::Conflict(
                "duplicate authorization code".into(),
            ));
        }
        identity.oauth_codes.insert(code.code_hash.clone(), code);
        Ok(())
    }

    fn get(&self, code_hash: &str) -> RepositoryResult<Option<StoredAuthorizationCode>> {
        Ok(self
            .identity
            .lock()
            .unwrap()
            .oauth_codes
            .get(code_hash)
            .cloned())
    }

    fn consume_if_live(&self, code_hash: &str, now: &Timestamp) -> RepositoryResult<bool> {
        let mut identity = self.identity.lock().unwrap();
        let Some(code) = identity.oauth_codes.get_mut(code_hash) else {
            return Ok(false);
        };
        if code.consumed_at.is_some() || code.expires_at.0 <= now.0 {
            return Ok(false);
        }
        code.consumed_at = Some(now.clone());
        Ok(true)
    }
}

impl OrgRepository for InMemoryStore {
    fn get(&self, id: &OrgId) -> RepositoryResult<Option<Organization>> {
        Ok(self.authz.lock().unwrap().orgs.get(&id.0).cloned())
    }

    fn upsert(&self, org: Organization) -> RepositoryResult<()> {
        self.authz
            .lock()
            .unwrap()
            .orgs
            .insert(org.id.0.clone(), org);
        Ok(())
    }

    fn list(&self) -> RepositoryResult<Vec<Organization>> {
        Ok(self.authz.lock().unwrap().orgs.values().cloned().collect())
    }

    fn remove(&self, id: &OrgId) -> RepositoryResult<()> {
        self.authz
            .lock()
            .unwrap()
            .orgs
            .remove(&id.0)
            .map(|_| ())
            .ok_or_else(|| RepositoryError::NotFound(format!("organization {} not found", id.0)))
    }
}

impl OrgPrivacyRepository for InMemoryStore {
    fn erase_org_privacy(&self, id: &OrgId) -> RepositoryResult<bool> {
        let mut authz = self.authz.lock().unwrap_or_else(|error| error.into_inner());
        let workspace_edges = authz.workspace_orgs.values().cloned().collect::<Vec<_>>();
        let resource_edges = authz.resource_edges.values().cloned().collect::<Vec<_>>();
        let privacy = OrganizationPrivacyScope::resolve(id, &workspace_edges, &resource_edges);
        let group_ids = authz
            .groups
            .values()
            .filter(|group| &group.org == id)
            .map(|group| group.id.0.clone())
            .collect::<BTreeSet<_>>();
        let authz_before = authz.orgs.len()
            + authz.groups.len()
            + authz.grants.len()
            + authz.role_bindings.len()
            + authz.invitations.len()
            + authz.resource_edges.len()
            + authz.workspace_orgs.len()
            + authz.directory_nodes.len()
            + authz.product_space_bindings.len();

        authz.orgs.remove(&id.0);
        authz.groups.retain(|_, group| &group.org != id);
        authz
            .invitations
            .retain(|_, invitation| &invitation.org_id != id);
        authz.workspace_orgs.retain(|_, edge| &edge.org_id != id);
        authz
            .product_space_bindings
            .retain(|_, binding| &binding.org_id != id);
        authz.directory_nodes.retain(|_, node| &node.org_id != id);
        authz
            .role_bindings
            .retain(|_, binding| !privacy.contains(&binding.scope));
        authz.grants.retain(|_, grant| {
            !privacy.contains(&grant.scope)
                && !matches!(
                    &grant.subject,
                    GrantSubject::Group(group) if group_ids.contains(&group.0)
                )
        });
        authz.resource_edges.retain(|_, edge| {
            !privacy.contains(&edge.parent)
                && !privacy.contains(&ScopeRef::Resource {
                    resource_type: edge.resource_type.clone(),
                    resource_id: edge.resource_id.clone(),
                })
        });
        let authz_after = authz.orgs.len()
            + authz.groups.len()
            + authz.grants.len()
            + authz.role_bindings.len()
            + authz.invitations.len()
            + authz.resource_edges.len()
            + authz.workspace_orgs.len()
            + authz.directory_nodes.len()
            + authz.product_space_bindings.len();
        drop(authz);

        let mut identity = self
            .identity
            .lock()
            .unwrap_or_else(|error| error.into_inner());
        let token_count = identity.api_tokens.len();
        identity
            .api_tokens
            .retain(|_, token| !privacy.contains_workspace(&token.workspace.0));
        let retained_token_ids = identity.api_tokens.keys().cloned().collect::<BTreeSet<_>>();
        identity
            .api_tokens_by_prefix
            .retain(|_, token_id| retained_token_ids.contains(token_id));

        Ok(authz_before != authz_after || token_count != identity.api_tokens.len())
    }
}

impl GroupRepository for InMemoryStore {
    fn get(&self, id: &GroupId) -> RepositoryResult<Option<Group>> {
        Ok(self.authz.lock().unwrap().groups.get(&id.0).cloned())
    }

    fn upsert(&self, group: Group) -> RepositoryResult<()> {
        self.authz
            .lock()
            .unwrap()
            .groups
            .insert(group.id.0.clone(), group);
        Ok(())
    }

    fn list(&self) -> RepositoryResult<Vec<Group>> {
        Ok(self
            .authz
            .lock()
            .unwrap()
            .groups
            .values()
            .cloned()
            .collect())
    }

    fn remove(&self, id: &GroupId) -> RepositoryResult<()> {
        self.authz
            .lock()
            .unwrap()
            .groups
            .remove(&id.0)
            .map(|_| ())
            .ok_or_else(|| RepositoryError::NotFound(format!("group {} not found", id.0)))
    }
}

impl RoleRepository for InMemoryStore {
    fn get(&self, id: &RoleId) -> RepositoryResult<Option<RoleDef>> {
        Ok(self.authz.lock().unwrap().roles.get(&id.0).cloned())
    }

    fn upsert(&self, role: RoleDef) -> RepositoryResult<()> {
        self.authz
            .lock()
            .unwrap()
            .roles
            .insert(role.id.0.clone(), role);
        Ok(())
    }

    fn list(&self) -> RepositoryResult<Vec<RoleDef>> {
        Ok(self.authz.lock().unwrap().roles.values().cloned().collect())
    }

    fn remove(&self, id: &RoleId) -> RepositoryResult<()> {
        self.authz
            .lock()
            .unwrap()
            .roles
            .remove(&id.0)
            .map(|_| ())
            .ok_or_else(|| RepositoryError::NotFound(format!("role {} not found", id.0)))
    }
}

impl GrantRepository for InMemoryStore {
    fn put(&self, grant: Grant) -> RepositoryResult<()> {
        self.authz
            .lock()
            .unwrap()
            .grants
            .insert(grant.id.0.clone(), grant);
        Ok(())
    }

    fn get(&self, id: &GrantId) -> RepositoryResult<Option<Grant>> {
        Ok(self.authz.lock().unwrap().grants.get(&id.0).cloned())
    }

    fn list(&self) -> RepositoryResult<Vec<Grant>> {
        Ok(self
            .authz
            .lock()
            .unwrap()
            .grants
            .values()
            .cloned()
            .collect())
    }

    fn remove(&self, id: &GrantId) -> RepositoryResult<()> {
        self.authz
            .lock()
            .unwrap()
            .grants
            .remove(&id.0)
            .map(|_| ())
            .ok_or_else(|| RepositoryError::NotFound(format!("grant {} not found", id.0)))
    }
}

impl RoleBindingRepository for InMemoryStore {
    fn add(&self, binding: RoleBinding) -> RepositoryResult<()> {
        let key = json_key(
            &(&binding.principal, &binding.role.0, &binding.scope),
            "role binding",
        )?;
        self.authz
            .lock()
            .unwrap()
            .role_bindings
            .insert(key, binding);
        Ok(())
    }

    fn list_for_principal(&self, principal: &PrincipalRef) -> RepositoryResult<Vec<RoleBinding>> {
        Ok(self
            .authz
            .lock()
            .unwrap()
            .role_bindings
            .values()
            .filter(|binding| &binding.principal == principal)
            .cloned()
            .collect())
    }

    fn list(&self) -> RepositoryResult<Vec<RoleBinding>> {
        Ok(self
            .authz
            .lock()
            .unwrap()
            .role_bindings
            .values()
            .cloned()
            .collect())
    }

    fn remove(&self, binding: &RoleBinding) -> RepositoryResult<()> {
        let key = json_key(
            &(&binding.principal, &binding.role.0, &binding.scope),
            "role binding",
        )?;
        self.authz
            .lock()
            .unwrap()
            .role_bindings
            .remove(&key)
            .map(|_| ())
            .ok_or_else(|| RepositoryError::NotFound("role binding not found".to_owned()))
    }

    fn replace_scoped(
        &self,
        principal: &PrincipalRef,
        scope: &ScopeRef,
        managed_roles: &[RoleId],
        replacement_roles: &[RoleId],
    ) -> RepositoryResult<()> {
        let managed: BTreeSet<&str> = managed_roles.iter().map(|role| role.0.as_str()).collect();
        let mut guard = self.authz.lock().unwrap();
        guard.role_bindings.retain(|_, binding| {
            &binding.principal != principal
                || &binding.scope != scope
                || !managed.contains(binding.role.0.as_str())
        });
        for role in replacement_roles {
            let binding = RoleBinding {
                principal: principal.clone(),
                role: role.clone(),
                scope: scope.clone(),
            };
            let key = json_key(
                &(&binding.principal, &binding.role.0, &binding.scope),
                "role binding",
            )?;
            guard.role_bindings.insert(key, binding);
        }
        Ok(())
    }
}

impl InvitationRepository for InMemoryStore {
    fn create_invitation(&self, invitation: Invitation) -> RepositoryResult<()> {
        let mut guard = self.authz.lock().unwrap();
        if guard.invitations.contains_key(&invitation.id.0)
            || guard.invitations.values().any(|existing| {
                existing.org_id == invitation.org_id
                    && existing.idempotency_key == invitation.idempotency_key
            })
        {
            return Err(RepositoryError::Conflict(
                "invitation already exists".into(),
            ));
        }
        guard
            .invitations
            .insert(invitation.id.0.clone(), invitation);
        Ok(())
    }

    fn get_invitation(&self, id: &InvitationId) -> RepositoryResult<Option<Invitation>> {
        Ok(self.authz.lock().unwrap().invitations.get(&id.0).cloned())
    }

    fn get_invitation_by_idempotency(
        &self,
        org_id: &OrgId,
        idempotency_key: &str,
    ) -> RepositoryResult<Option<Invitation>> {
        Ok(self
            .authz
            .lock()
            .unwrap()
            .invitations
            .values()
            .find(|invite| &invite.org_id == org_id && invite.idempotency_key == idempotency_key)
            .cloned())
    }

    fn list_invitations_for_org(&self, org_id: &OrgId) -> RepositoryResult<Vec<Invitation>> {
        Ok(self
            .authz
            .lock()
            .unwrap()
            .invitations
            .values()
            .filter(|invite| &invite.org_id == org_id)
            .cloned()
            .collect())
    }

    fn replace_pending_invitation(
        &self,
        invitation: Invitation,
        expected_token_hash: &str,
    ) -> RepositoryResult<bool> {
        let mut guard = self.authz.lock().unwrap();
        let Some(current) = guard.invitations.get(&invitation.id.0) else {
            return Err(RepositoryError::NotFound("invitation not found".into()));
        };
        if current.status != InvitationStatus::Pending || current.token_hash != expected_token_hash
        {
            return Ok(false);
        }
        guard
            .invitations
            .insert(invitation.id.0.clone(), invitation);
        Ok(true)
    }

    fn accept_pending_invitation(
        &self,
        id: &InvitationId,
        expected_token_hash: &str,
        account_id: &AccountId,
        at: &Timestamp,
    ) -> RepositoryResult<Option<Invitation>> {
        let mut guard = self.authz.lock().unwrap();
        let Some(current) = guard.invitations.get(&id.0).cloned() else {
            return Err(RepositoryError::NotFound("invitation not found".into()));
        };
        if current.status == InvitationStatus::Accepted
            && current.accepted_by_account_id.as_ref() == Some(account_id)
            && current.token_hash == expected_token_hash
        {
            return Ok(Some(current));
        }
        if current.status != InvitationStatus::Pending || current.token_hash != expected_token_hash
        {
            return Ok(None);
        }
        let principal = PrincipalRef::Account {
            account_id: account_id.clone(),
        };
        for target in &current.bindings {
            let binding = RoleBinding {
                principal: principal.clone(),
                role: RoleId(target.role_id.clone()),
                scope: target.scope.clone(),
            };
            let key = json_key(
                &(&binding.principal, &binding.role.0, &binding.scope),
                "role binding",
            )?;
            guard.role_bindings.insert(key, binding);
        }
        let mut accepted = current;
        accepted.status = InvitationStatus::Accepted;
        accepted.accepted_by_account_id = Some(account_id.clone());
        accepted.updated_at = at.clone();
        guard.invitations.insert(id.0.clone(), accepted.clone());
        Ok(Some(accepted))
    }
}

impl ResourceModelRepository for InMemoryStore {
    fn put_edge(&self, edge: ResourceEdge) -> RepositoryResult<()> {
        let key = format!("{}\u{1f}{}", edge.resource_type.0, edge.resource_id.0);
        self.authz.lock().unwrap().resource_edges.insert(key, edge);
        Ok(())
    }

    fn list_edges(&self) -> RepositoryResult<Vec<ResourceEdge>> {
        Ok(self
            .authz
            .lock()
            .unwrap()
            .resource_edges
            .values()
            .cloned()
            .collect())
    }

    fn put_workspace_org(&self, edge: WorkspaceOrgEdge) -> RepositoryResult<()> {
        self.authz
            .lock()
            .unwrap()
            .workspace_orgs
            .insert(edge.workspace_id.0.clone(), edge);
        Ok(())
    }

    fn workspace_org(
        &self,
        workspace_id: &WorkspaceId,
    ) -> RepositoryResult<Option<WorkspaceOrgEdge>> {
        Ok(self
            .authz
            .lock()
            .unwrap()
            .workspace_orgs
            .get(&workspace_id.0)
            .cloned())
    }

    fn list_workspace_orgs(&self) -> RepositoryResult<Vec<WorkspaceOrgEdge>> {
        Ok(self
            .authz
            .lock()
            .unwrap()
            .workspace_orgs
            .values()
            .cloned()
            .collect())
    }
}

impl AuthorizationProfileRepository for InMemoryStore {
    fn create_profile(&self, profile: AuthorizationProfile) -> RepositoryResult<()> {
        let key = (profile.namespace.0.clone(), profile.revision);
        let mut authz = self.authz.lock().unwrap();
        if authz.profiles.contains_key(&key) {
            return Err(RepositoryError::Conflict(
                "profile revision already exists".into(),
            ));
        }
        authz.profiles.insert(key, profile);
        Ok(())
    }

    fn get_profile(
        &self,
        namespace: &NamespaceId,
        revision: u64,
    ) -> RepositoryResult<Option<AuthorizationProfile>> {
        let authz = self.authz.lock().unwrap();
        let mut profile = authz
            .profiles
            .get(&(namespace.0.clone(), revision))
            .cloned();
        if authz.active_profiles.get(&namespace.0) == Some(&revision)
            && let Some(profile) = &mut profile
        {
            profile.lifecycle = ProfileLifecycle::Active;
        }
        Ok(profile)
    }

    fn list_profiles(
        &self,
        namespace: &NamespaceId,
    ) -> RepositoryResult<Vec<AuthorizationProfile>> {
        let authz = self.authz.lock().unwrap();
        let active = authz.active_profiles.get(&namespace.0).copied();
        Ok(authz
            .profiles
            .iter()
            .filter(|((owner, _), _)| owner == &namespace.0)
            .map(|((_, revision), profile)| {
                let mut profile = profile.clone();
                if active == Some(*revision) {
                    profile.lifecycle = ProfileLifecycle::Active;
                }
                profile
            })
            .collect())
    }

    fn set_profile_lifecycle(
        &self,
        namespace: &NamespaceId,
        revision: u64,
        lifecycle: ProfileLifecycle,
    ) -> RepositoryResult<()> {
        let mut authz = self.authz.lock().unwrap();
        let profile = authz
            .profiles
            .get_mut(&(namespace.0.clone(), revision))
            .ok_or_else(|| RepositoryError::NotFound("profile revision not found".into()))?;
        profile.lifecycle = lifecycle;
        Ok(())
    }

    fn activate_profile(
        &self,
        namespace: &NamespaceId,
        revision: u64,
        expected_active_revision: Option<u64>,
    ) -> RepositoryResult<Option<u64>> {
        let mut authz = self.authz.lock().unwrap();
        let target = authz
            .profiles
            .get(&(namespace.0.clone(), revision))
            .ok_or_else(|| RepositoryError::NotFound("profile revision not found".into()))?;
        if target.lifecycle == ProfileLifecycle::Draft {
            return Err(RepositoryError::Conflict(
                "profile revision is not validated".into(),
            ));
        }
        let previous = authz.active_profiles.get(&namespace.0).copied();
        if previous != expected_active_revision {
            return Err(RepositoryError::Conflict(
                "active profile revision changed".into(),
            ));
        }
        if let Some(previous) = previous
            && previous != revision
            && let Some(profile) = authz.profiles.get_mut(&(namespace.0.clone(), previous))
        {
            profile.lifecycle = ProfileLifecycle::Retired;
        }
        authz.active_profiles.insert(namespace.0.clone(), revision);
        Ok(previous)
    }

    fn retire_active_profile(
        &self,
        namespace: &NamespaceId,
        expected_active_revision: u64,
    ) -> RepositoryResult<AuthorizationProfile> {
        let mut authz = self.authz.lock().unwrap();
        let Some(active_revision) = authz.active_profiles.get(&namespace.0).copied() else {
            return Err(RepositoryError::NotFound(
                "active profile head not found".into(),
            ));
        };
        if active_revision != expected_active_revision {
            return Err(RepositoryError::Conflict(
                "active profile revision changed".into(),
            ));
        }
        if !authz
            .profiles
            .contains_key(&(namespace.0.clone(), active_revision))
        {
            return Err(RepositoryError::Backend(
                "active profile head is dangling".into(),
            ));
        }
        authz.active_profiles.remove(&namespace.0);
        let profile = authz
            .profiles
            .get_mut(&(namespace.0.clone(), active_revision))
            .expect("profile existence checked while holding the same lock");
        profile.lifecycle = ProfileLifecycle::Retired;
        Ok(profile.clone())
    }

    fn active_profile(
        &self,
        namespace: &NamespaceId,
    ) -> RepositoryResult<Option<AuthorizationProfile>> {
        let authz = self.authz.lock().unwrap();
        let Some(revision) = authz.active_profiles.get(&namespace.0) else {
            return Ok(None);
        };
        let mut profile = authz
            .profiles
            .get(&(namespace.0.clone(), *revision))
            .cloned()
            .ok_or_else(|| RepositoryError::Backend("active profile head is dangling".into()))?;
        profile.lifecycle = ProfileLifecycle::Active;
        Ok(Some(profile))
    }

    fn active_profiles(&self) -> RepositoryResult<Vec<AuthorizationProfile>> {
        let authz = self.authz.lock().unwrap();
        authz
            .active_profiles
            .iter()
            .map(|(namespace, revision)| {
                let mut profile = authz
                    .profiles
                    .get(&(namespace.clone(), *revision))
                    .cloned()
                    .ok_or_else(|| {
                        RepositoryError::Backend("active profile head is dangling".into())
                    })?;
                profile.lifecycle = ProfileLifecycle::Active;
                Ok(profile)
            })
            .collect()
    }
}

impl PlanRepository for InMemoryStore {
    fn put(&self, plan: Plan) -> RepositoryResult<()> {
        self.entitlement
            .lock()
            .unwrap()
            .plans
            .insert(plan.id.0.clone(), plan);
        Ok(())
    }

    fn get(&self, id: &PlanId) -> RepositoryResult<Option<Plan>> {
        Ok(self.entitlement.lock().unwrap().plans.get(&id.0).cloned())
    }

    fn list(&self) -> RepositoryResult<Vec<Plan>> {
        Ok(self
            .entitlement
            .lock()
            .unwrap()
            .plans
            .values()
            .cloned()
            .collect())
    }

    fn subscribe(&self, principal: PrincipalRef, plan: PlanId) -> RepositoryResult<()> {
        let key = json_key(&principal, "principal")?;
        self.entitlement
            .lock()
            .unwrap()
            .subscriptions
            .insert(key, plan);
        Ok(())
    }

    fn subscription(&self, principal: &PrincipalRef) -> RepositoryResult<Option<PlanId>> {
        let key = json_key(principal, "principal")?;
        Ok(self
            .entitlement
            .lock()
            .unwrap()
            .subscriptions
            .get(&key)
            .cloned())
    }
}

impl AuditSink for InMemoryStore {
    fn record(&self, event: AuditEvent) -> RepositoryResult<()> {
        self.audit.lock().unwrap().push(event);
        Ok(())
    }

    fn events(&self) -> RepositoryResult<Vec<AuditEvent>> {
        Ok(self.audit.lock().unwrap().clone())
    }
}

impl FenceStore for InMemoryStore {
    fn fence(&self) -> RepositoryResult<Fence> {
        Ok(*self.fence.lock().unwrap())
    }

    fn advance_version(&self) -> RepositoryResult<u64> {
        let mut fence = self.fence.lock().unwrap();
        fence.version += 1;
        Ok(fence.version)
    }

    fn advance_epoch(&self) -> RepositoryResult<u64> {
        let mut fence = self.fence.lock().unwrap();
        fence.epoch += 1;
        Ok(fence.epoch)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use awaken_iam_contract::{
        ExternalIdentityClaims, ExternalIdentityId, ExternalSubject, IdentityProviderKey, OrgId,
        ScopeRef,
    };
    use awaken_iam_core::{ActionPattern, Effect, GrantSubject, PlanTier, RoleId};

    fn ts(value: &str) -> Timestamp {
        Timestamp(value.into())
    }

    fn account(id: &str) -> Account {
        Account {
            id: AccountId(id.into()),
            status: awaken_iam_contract::AccountStatus::Active,
            display_name: None,
            created_at: ts("2026-06-19T00:00:00Z"),
            updated_at: ts("2026-06-19T00:00:00Z"),
        }
    }

    fn external(id: &str, account_id: &str, subject: &str) -> ExternalIdentity {
        ExternalIdentity {
            id: ExternalIdentityId(id.into()),
            account_id: AccountId(account_id.into()),
            provider_key: IdentityProviderKey("fake".into()),
            claims: ExternalIdentityClaims {
                subject: ExternalSubject(subject.into()),
                email: None,
                email_verified: None,
                display_name: None,
                username: None,
                avatar_url: None,
                locale: None,
            },
            first_seen_at: ts("2026-06-19T00:00:00Z"),
            last_seen_at: ts("2026-06-19T00:00:00Z"),
        }
    }

    #[test]
    fn accounts_round_trip() {
        let store = InMemoryStore::new();
        assert_eq!(
            AccountRepository::get(&store, &AccountId("a".into())).unwrap(),
            None
        );
        AccountRepository::upsert(&store, account("a")).unwrap();
        assert_eq!(AccountRepository::list(&store).unwrap().len(), 1);
        assert_eq!(
            AccountRepository::get(&store, &AccountId("a".into()))
                .unwrap()
                .unwrap()
                .id,
            AccountId("a".into())
        );
    }

    #[test]
    fn external_identity_link_is_unique_by_provider_and_subject() {
        let store = InMemoryStore::new();
        store.link(external("e1", "a", "sub")).unwrap();
        let dup = store.link(external("e2", "a", "sub"));
        assert!(matches!(dup, Err(RepositoryError::Conflict(_))));
        let key = ExternalIdentityKey {
            provider_key: IdentityProviderKey("fake".into()),
            subject: ExternalSubject("sub".into()),
        };
        assert_eq!(store.get_by_key(&key).unwrap().unwrap().id.0, "e1");
        assert_eq!(
            store
                .list_for_account(&AccountId("a".into()))
                .unwrap()
                .len(),
            1
        );
    }

    #[test]
    fn sessions_resolve_by_id_and_token_hash() {
        let store = InMemoryStore::new();
        let session = Session {
            id: SessionId("s1".into()),
            account_id: AccountId("a".into()),
            token_hash: "hash".into(),
            external_identity_id: None,
            created_at: ts("2026-06-19T00:00:00Z"),
            last_seen_at: ts("2026-06-19T00:00:00Z"),
            expires_at: ts("2026-06-20T00:00:00Z"),
            revoked_at: None,
        };
        SessionRepository::create(&store, session.clone()).unwrap();
        assert!(matches!(
            SessionRepository::create(&store, session.clone()),
            Err(RepositoryError::Conflict(_))
        ));
        assert_eq!(store.get_by_token_hash("hash").unwrap().unwrap().id.0, "s1");

        let mut revoked = session;
        revoked.revoked_at = Some(ts("2026-06-19T01:00:00Z"));
        SessionRepository::update(&store, revoked).unwrap();
        assert!(
            SessionRepository::get(&store, &SessionId("s1".into()))
                .unwrap()
                .unwrap()
                .revoked_at
                .is_some()
        );
    }

    #[test]
    fn login_flow_is_consumed_at_most_once() {
        let store = InMemoryStore::new();
        let flow = OAuthLoginState {
            id: OAuthLoginStateId("l1".into()),
            provider_key: IdentityProviderKey("fake".into()),
            state_hash: "sh".into(),
            nonce_hash: None,
            pkce_verifier_hash: None,
            return_to: None,
            created_at: ts("2026-06-19T00:00:00Z"),
            expires_at: ts("2026-06-19T00:10:00Z"),
            consumed_at: None,
        };
        store.start(flow.clone()).unwrap();
        assert!(matches!(
            store.start(flow),
            Err(RepositoryError::Conflict(_))
        ));
        store
            .mark_consumed(&OAuthLoginStateId("l1".into()), ts("2026-06-19T00:05:00Z"))
            .unwrap();
        let reuse =
            store.mark_consumed(&OAuthLoginStateId("l1".into()), ts("2026-06-19T00:06:00Z"));
        assert!(matches!(reuse, Err(RepositoryError::Conflict(_))));
    }

    #[test]
    fn api_tokens_resolve_by_id_and_prefix_and_revoke_in_place() {
        let store = InMemoryStore::new();
        let token = ApiToken {
            id: ApiTokenId("tok_1".into()),
            prefix: ApiTokenPrefix("pfx".into()),
            principal: PrincipalRef::Service {
                service_id: "ci".into(),
            },
            secret_hash: "$argon2id$hash".into(),
            workspace: awaken_iam_contract::WorkspaceId("wrkspc_default".into()),
            created_at: ts("2026-06-19T00:00:00Z"),
            expires_at: None,
            revoked_at: None,
        };
        ApiTokenRepository::create(&store, token.clone()).unwrap();
        // Duplicate id and duplicate prefix both fail closed.
        assert!(matches!(
            ApiTokenRepository::create(&store, token.clone()),
            Err(RepositoryError::Conflict(_))
        ));
        assert_eq!(
            store
                .get_by_prefix(&ApiTokenPrefix("pfx".into()))
                .unwrap()
                .unwrap()
                .id
                .0,
            "tok_1"
        );
        let principal = PrincipalRef::Service {
            service_id: "ci".into(),
        };
        assert_eq!(
            ApiTokenRepository::list_for_principal(&store, &principal)
                .unwrap()
                .len(),
            1
        );

        let mut revoked = token;
        revoked.revoked_at = Some(ts("2026-06-19T01:00:00Z"));
        ApiTokenRepository::update(&store, revoked).unwrap();
        assert!(
            ApiTokenRepository::get(&store, &ApiTokenId("tok_1".into()))
                .unwrap()
                .unwrap()
                .revoked_at
                .is_some()
        );
    }

    #[test]
    fn grants_put_get_remove() {
        let store = InMemoryStore::new();
        let grant = Grant {
            id: GrantId("g1".into()),
            subject: GrantSubject::Principal(PrincipalRef::Service {
                service_id: "svc".into(),
            }),
            action_pattern: awaken_iam_core::ActionPattern("pack.read".into()),
            scope: ScopeRef::Global,
            effect: Effect::Allow,
        };
        GrantRepository::put(&store, grant).unwrap();
        assert!(
            GrantRepository::get(&store, &GrantId("g1".into()))
                .unwrap()
                .is_some()
        );
        assert_eq!(GrantRepository::list(&store).unwrap().len(), 1);
        GrantRepository::remove(&store, &GrantId("g1".into())).unwrap();
        assert!(matches!(
            GrantRepository::remove(&store, &GrantId("g1".into())),
            Err(RepositoryError::NotFound(_))
        ));
    }

    #[test]
    fn role_bindings_filter_by_principal() {
        let store = InMemoryStore::new();
        let principal = PrincipalRef::Account {
            account_id: AccountId("ada".into()),
        };
        store
            .add(RoleBinding {
                principal: principal.clone(),
                role: RoleId("admin".into()),
                scope: ScopeRef::Global,
            })
            .unwrap();
        assert_eq!(
            RoleBindingRepository::list_for_principal(&store, &principal)
                .unwrap()
                .len(),
            1
        );
        assert_eq!(RoleBindingRepository::list(&store).unwrap().len(), 1);

        let binding = RoleBinding {
            principal: principal.clone(),
            role: RoleId("admin".into()),
            scope: ScopeRef::Global,
        };
        RoleBindingRepository::remove(&store, &binding).unwrap();
        assert_eq!(RoleBindingRepository::list(&store).unwrap().len(), 0);
        assert!(matches!(
            RoleBindingRepository::remove(&store, &binding),
            Err(RepositoryError::NotFound(_))
        ));
    }

    #[test]
    fn oauth_clients_upsert_get_list_and_remove() {
        let store = InMemoryStore::new();
        assert_eq!(OAuthClientRepository::get(&store, "web").unwrap(), None);

        let public = RegisteredClient::public(
            "web",
            vec!["https://web.example/cb".into()],
            ["openid", "email"],
        );
        OAuthClientRepository::upsert(&store, public.clone()).unwrap();
        assert_eq!(
            OAuthClientRepository::get(&store, "web").unwrap(),
            Some(public.clone())
        );
        assert_eq!(OAuthClientRepository::list(&store).unwrap().len(), 1);

        // Upsert replaces in place by client id (a rotation rewrites the secret).
        let confidential = RegisteredClient::confidential(
            "web",
            "s3cret",
            vec!["https://web.example/cb".into()],
            ["openid", "email"],
        );
        OAuthClientRepository::upsert(&store, confidential.clone()).unwrap();
        assert_eq!(
            OAuthClientRepository::get(&store, "web").unwrap(),
            Some(confidential)
        );
        assert_eq!(OAuthClientRepository::list(&store).unwrap().len(), 1);

        OAuthClientRepository::remove(&store, "web").unwrap();
        assert!(matches!(
            OAuthClientRepository::remove(&store, "web"),
            Err(RepositoryError::NotFound(_))
        ));
        assert!(OAuthClientRepository::list(&store).unwrap().is_empty());
    }

    #[test]
    fn orgs_groups_and_roles_round_trip() {
        let store = InMemoryStore::new();
        let org = Organization {
            id: OrgId("acme".into()),
            display_name: Some("Acme".into()),
            owner: PrincipalRef::Account {
                account_id: AccountId("ada".into()),
            },
            created_at: ts("2026-06-21T00:00:00Z"),
            updated_at: ts("2026-06-21T00:00:00Z"),
        };
        OrgRepository::upsert(&store, org.clone()).unwrap();
        assert_eq!(
            OrgRepository::get(&store, &OrgId("acme".into())).unwrap(),
            Some(org)
        );
        assert_eq!(OrgRepository::list(&store).unwrap().len(), 1);
        OrgRepository::remove(&store, &OrgId("acme".into())).unwrap();
        assert!(matches!(
            OrgRepository::remove(&store, &OrgId("acme".into())),
            Err(RepositoryError::NotFound(_))
        ));

        let group = Group {
            id: GroupId("eng".into()),
            org: OrgId("acme".into()),
            display_name: None,
            members: vec![PrincipalRef::Account {
                account_id: AccountId("ada".into()),
            }],
            created_at: ts("2026-06-21T00:00:00Z"),
            updated_at: ts("2026-06-21T00:00:00Z"),
        };
        GroupRepository::upsert(&store, group.clone()).unwrap();
        assert_eq!(
            GroupRepository::get(&store, &group.id).unwrap(),
            Some(group)
        );
        assert_eq!(GroupRepository::list(&store).unwrap().len(), 1);

        let role = RoleDef {
            id: RoleId("publisher".into()),
            display_name: Some("Publisher".into()),
            action_patterns: vec![ActionPattern("pack.*".into())],
            created_at: ts("2026-06-21T00:00:00Z"),
            updated_at: ts("2026-06-21T00:00:00Z"),
        };
        RoleRepository::upsert(&store, role.clone()).unwrap();
        assert_eq!(RoleRepository::get(&store, &role.id).unwrap(), Some(role));
        assert_eq!(RoleRepository::list(&store).unwrap().len(), 1);
        RoleRepository::remove(&store, &RoleId("publisher".into())).unwrap();
        assert!(matches!(
            RoleRepository::remove(&store, &RoleId("publisher".into())),
            Err(RepositoryError::NotFound(_))
        ));
    }

    #[test]
    fn plans_and_subscriptions_resolve_by_principal() {
        let store = InMemoryStore::new();
        PlanRepository::put(
            &store,
            Plan::new(PlanId("pro".into()), PlanTier::Pro, ["pack.read"]),
        )
        .unwrap();
        let principal = PrincipalRef::Account {
            account_id: AccountId("ada".into()),
        };
        assert_eq!(store.subscription(&principal).unwrap(), None);
        store
            .subscribe(principal.clone(), PlanId("pro".into()))
            .unwrap();
        assert_eq!(
            store.subscription(&principal).unwrap(),
            Some(PlanId("pro".into()))
        );
        assert_eq!(PlanRepository::list(&store).unwrap().len(), 1);
    }

    #[test]
    fn external_claims_update_requires_an_existing_link() {
        let store = InMemoryStore::new();
        // Updating claims for an unlinked identity fails closed.
        assert!(matches!(
            store.update_claims(external("e1", "a", "sub")),
            Err(RepositoryError::NotFound(_))
        ));
        store.link(external("e1", "a", "sub")).unwrap();
        let mut refreshed = external("e1", "a", "sub");
        refreshed.claims.email = Some("ada@acme.example".into());
        store.update_claims(refreshed).unwrap();
        let key = ExternalIdentityKey {
            provider_key: IdentityProviderKey("fake".into()),
            subject: ExternalSubject("sub".into()),
        };
        assert_eq!(
            store
                .get_by_key(&key)
                .unwrap()
                .unwrap()
                .claims
                .email
                .as_deref(),
            Some("ada@acme.example")
        );
    }

    #[test]
    fn session_and_login_flow_reads_and_missing_updates() {
        let store = InMemoryStore::new();
        // Updating a session that was never created fails closed.
        let session = Session {
            id: SessionId("ghost".into()),
            account_id: AccountId("a".into()),
            token_hash: "h".into(),
            external_identity_id: None,
            created_at: ts("2026-06-19T00:00:00Z"),
            last_seen_at: ts("2026-06-19T00:00:00Z"),
            expires_at: ts("2026-06-20T00:00:00Z"),
            revoked_at: None,
        };
        assert!(matches!(
            SessionRepository::update(&store, session),
            Err(RepositoryError::NotFound(_))
        ));
        assert_eq!(
            SessionRepository::get(&store, &SessionId("ghost".into())).unwrap(),
            None
        );

        // A login flow is resolvable by id through the standalone getter.
        let flow = OAuthLoginState {
            id: OAuthLoginStateId("l1".into()),
            provider_key: IdentityProviderKey("fake".into()),
            state_hash: "sh".into(),
            nonce_hash: None,
            pkce_verifier_hash: None,
            return_to: None,
            created_at: ts("2026-06-19T00:00:00Z"),
            expires_at: ts("2026-06-19T00:10:00Z"),
            consumed_at: None,
        };
        store.start(flow).unwrap();
        assert!(
            LoginFlowRepository::get(&store, &OAuthLoginStateId("l1".into()))
                .unwrap()
                .is_some()
        );
        // Consuming an unknown flow fails closed.
        assert!(matches!(
            store.mark_consumed(
                &OAuthLoginStateId("absent".into()),
                ts("2026-06-19T00:05:00Z")
            ),
            Err(RepositoryError::NotFound(_))
        ));
    }

    #[test]
    fn api_token_prefix_conflict_and_missing_update_fail_closed() {
        let store = InMemoryStore::new();
        let base = ApiToken {
            id: ApiTokenId("tok_1".into()),
            prefix: ApiTokenPrefix("pfx".into()),
            principal: PrincipalRef::Service {
                service_id: "ci".into(),
            },
            secret_hash: "$argon2id$hash".into(),
            workspace: awaken_iam_contract::WorkspaceId("wrkspc_default".into()),
            created_at: ts("2026-06-19T00:00:00Z"),
            expires_at: None,
            revoked_at: None,
        };
        ApiTokenRepository::create(&store, base.clone()).unwrap();
        // A distinct id that reuses an existing prefix is a conflict on its own.
        let mut clashing = base.clone();
        clashing.id = ApiTokenId("tok_2".into());
        assert!(matches!(
            ApiTokenRepository::create(&store, clashing),
            Err(RepositoryError::Conflict(_))
        ));
        // Updating a token id that does not exist fails closed.
        let mut ghost = base;
        ghost.id = ApiTokenId("ghost".into());
        assert!(matches!(
            ApiTokenRepository::update(&store, ghost),
            Err(RepositoryError::NotFound(_))
        ));
    }

    #[test]
    fn resource_edges_and_plan_reads_round_trip() {
        let store = InMemoryStore::new();
        // The Debug projection redacts the contents.
        assert!(format!("{store:?}").contains("InMemoryStore"));

        let edge = ResourceEdge {
            resource_type: awaken_iam_contract::ResourceType("pack".into()),
            resource_id: awaken_iam_contract::ResourceId("r1".into()),
            parent: ScopeRef::Org {
                org_id: OrgId("acme".into()),
            },
        };
        store.put_edge(edge).unwrap();
        assert_eq!(
            ResourceModelRepository::list_edges(&store).unwrap().len(),
            1
        );

        PlanRepository::put(
            &store,
            Plan::new(PlanId("pro".into()), PlanTier::Pro, ["pack.read"]),
        )
        .unwrap();
        assert!(
            PlanRepository::get(&store, &PlanId("pro".into()))
                .unwrap()
                .is_some()
        );
        assert_eq!(
            PlanRepository::get(&store, &PlanId("absent".into())).unwrap(),
            None
        );
    }

    #[test]
    fn organization_privacy_erases_owned_closure_and_retains_foreign_state() {
        // Cause/effect decision table:
        // C1 row is the Org, its group/invitation, owned Workspace, Project or
        // recursive Resource scope or Directory placement -> E1 remove; C2 API
        // token is bound to an owned Workspace -> E2 remove; C3 row belongs to
        // a foreign Org -> E3 retain; C4 exact retry after E1/E2 -> E4 false
        // with no new effect.
        let store = InMemoryStore::new();
        let owner = PrincipalRef::Account {
            account_id: AccountId("owner".into()),
        };
        for id in ["org-a", "org-b"] {
            OrgRepository::upsert(
                &store,
                Organization {
                    id: OrgId(id.into()),
                    display_name: None,
                    owner: owner.clone(),
                    created_at: ts("2026-06-19T00:00:00Z"),
                    updated_at: ts("2026-06-19T00:00:00Z"),
                },
            )
            .unwrap();
        }
        for suffix in ["a", "b"] {
            let org_id = OrgId(format!("org-{suffix}"));
            let node_id = DirectoryNodeId(format!("node-{suffix}"));
            DirectoryRepository::create_directory_node(
                &store,
                DirectoryNode {
                    id: node_id.clone(),
                    org_id: org_id.clone(),
                    parent_id: None,
                    name: format!("Root {suffix}"),
                    slug: format!("root-{suffix}"),
                    description: None,
                    archived: false,
                    created_at: ts("2026-06-19T00:00:00Z"),
                    updated_at: ts("2026-06-19T00:00:00Z"),
                },
                Some(ProductSpacePlacement {
                    product_space: ProductSpaceRef {
                        product: "agents".into(),
                        space_id: format!("space-{suffix}"),
                    },
                    org_id,
                    node_id,
                }),
                &owner,
            )
            .unwrap();
        }
        GroupRepository::upsert(
            &store,
            Group {
                id: GroupId("group-a".into()),
                org: OrgId("org-a".into()),
                display_name: None,
                members: vec![owner.clone()],
                created_at: ts("2026-06-19T00:00:00Z"),
                updated_at: ts("2026-06-19T00:00:00Z"),
            },
        )
        .unwrap();
        for (workspace, org) in [("ws-a", "org-a"), ("ws-b", "org-b")] {
            ResourceModelRepository::put_workspace_org(
                &store,
                WorkspaceOrgEdge {
                    workspace_id: WorkspaceId(workspace.into()),
                    org_id: OrgId(org.into()),
                },
            )
            .unwrap();
        }
        let owned_resource = ResourceEdge {
            resource_type: awaken_iam_contract::ResourceType("issue".into()),
            resource_id: awaken_iam_contract::ResourceId("owned".into()),
            parent: ScopeRef::Project {
                workspace_id: WorkspaceId("ws-a".into()),
                project_id: awaken_iam_contract::ProjectId("project-a".into()),
            },
        };
        ResourceModelRepository::put_edge(&store, owned_resource.clone()).unwrap();
        GrantRepository::put(
            &store,
            Grant {
                id: GrantId("owned-grant".into()),
                subject: GrantSubject::Group(GroupId("group-a".into())),
                action_pattern: ActionPattern("issue.read".into()),
                scope: ScopeRef::Resource {
                    resource_type: owned_resource.resource_type.clone(),
                    resource_id: owned_resource.resource_id.clone(),
                },
                effect: Effect::Allow,
            },
        )
        .unwrap();
        RoleBindingRepository::add(
            &store,
            RoleBinding {
                principal: owner.clone(),
                role: RoleId("member".into()),
                scope: ScopeRef::Workspace {
                    workspace_id: WorkspaceId("ws-a".into()),
                },
            },
        )
        .unwrap();
        for (id, workspace) in [("token-a", "ws-a"), ("token-b", "ws-b")] {
            ApiTokenRepository::create(
                &store,
                ApiToken {
                    id: ApiTokenId(id.into()),
                    prefix: ApiTokenPrefix(format!("prefix-{id}")),
                    principal: owner.clone(),
                    secret_hash: "hash".into(),
                    workspace: WorkspaceId(workspace.into()),
                    created_at: ts("2026-06-19T00:00:00Z"),
                    expires_at: None,
                    revoked_at: None,
                },
            )
            .unwrap();
        }

        assert!(store.erase_org_privacy(&OrgId("org-a".into())).unwrap());
        assert!(!store.erase_org_privacy(&OrgId("org-a".into())).unwrap());
        assert!(
            OrgRepository::get(&store, &OrgId("org-a".into()))
                .unwrap()
                .is_none()
        );
        assert!(
            OrgRepository::get(&store, &OrgId("org-b".into()))
                .unwrap()
                .is_some()
        );
        assert!(
            DirectoryRepository::directory_node(&store, &DirectoryNodeId("node-a".into()))
                .unwrap()
                .is_none()
        );
        assert!(
            DirectoryRepository::product_space_binding(
                &store,
                &ProductSpaceRef {
                    product: "agents".into(),
                    space_id: "space-b".into(),
                },
            )
            .unwrap()
            .is_some()
        );
        assert!(GroupRepository::list(&store).unwrap().is_empty());
        assert!(GrantRepository::list(&store).unwrap().is_empty());
        assert!(RoleBindingRepository::list(&store).unwrap().is_empty());
        assert!(
            ResourceModelRepository::list_edges(&store)
                .unwrap()
                .is_empty()
        );
        assert!(
            ApiTokenRepository::get(&store, &ApiTokenId("token-a".into()))
                .unwrap()
                .is_none()
        );
        assert!(
            ApiTokenRepository::get(&store, &ApiTokenId("token-b".into()))
                .unwrap()
                .is_some()
        );
    }

    #[test]
    fn audit_events_append_in_order() {
        let store = InMemoryStore::new();
        store
            .record(AuditEvent {
                at: ts("2026-06-19T00:00:00Z"),
                actor: None,
                action: "account.disable".into(),
                detail: "first".into(),
            })
            .unwrap();
        store
            .record(AuditEvent {
                at: ts("2026-06-19T00:01:00Z"),
                actor: None,
                action: "grant.revoke".into(),
                detail: "second".into(),
            })
            .unwrap();
        let events = store.events().unwrap();
        assert_eq!(events.len(), 2);
        assert_eq!(events[0].detail, "first");
        assert_eq!(events[1].detail, "second");
    }

    #[test]
    fn clones_share_one_authoritative_store() {
        let writer = InMemoryStore::new();
        let reader = writer.clone();
        AccountRepository::upsert(&writer, account("shared")).unwrap();

        assert!(
            AccountRepository::get(&reader, &AccountId("shared".into()))
                .unwrap()
                .is_some()
        );
        assert_eq!(reader.advance_version().unwrap(), 2);
        assert_eq!(writer.fence().unwrap().version, 2);
    }
}
