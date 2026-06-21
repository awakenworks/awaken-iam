//! In-memory adapter implementing the core's repository ports.
//!
//! This backs tests and the `local` client deployment. It enforces the same
//! uniqueness and lifecycle invariants the database adapter does, so code
//! exercised against it behaves identically once a real pool is mounted. State
//! lives behind a single [`Mutex`] keyed by subdomain, mirroring the
//! scope-partitioned bundles without ever coupling them by a foreign key.

use std::collections::BTreeMap;
use std::sync::Mutex;

use awaken_iam_contract::{
    Account, AccountId, ApiToken, ApiTokenId, ApiTokenPrefix, ExternalIdentity, ExternalIdentityKey,
    OAuthLoginState, OAuthLoginStateId, OrgId, PrincipalRef, Session, SessionId, Timestamp,
};
use awaken_iam_core::{
    AccountRepo, ApiTokenRepo, AuditEvent, AuditSink, ExternalIdentityRepo, Grant, GrantId,
    GrantRepo, Group, GroupId, GroupRepo, LoginFlowRepo, OrgRepo, Organization, Plan, PlanId,
    PlanRepo, RepoError, RepoResult, ResourceEdge, ResourceModelRepo, RoleBinding, RoleBindingRepo,
    RoleDef, RoleId, RoleRepo, SessionRepo,
};

/// JSON-serializable key used to index rows whose natural key is a contract
/// value object (principal, scope, resource coordinate).
fn json_key<T: serde::Serialize>(value: &T, what: &str) -> RepoResult<String> {
    serde_json::to_string(value).map_err(|err| RepoError::Backend(format!("encode {what}: {err}")))
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
}

#[derive(Default)]
struct Authz {
    orgs: BTreeMap<String, Organization>,
    groups: BTreeMap<String, Group>,
    roles: BTreeMap<String, RoleDef>,
    grants: BTreeMap<String, Grant>,
    role_bindings: BTreeMap<String, RoleBinding>,
    resource_edges: BTreeMap<String, ResourceEdge>,
}

#[derive(Default)]
struct Entitlement {
    plans: BTreeMap<String, Plan>,
    subscriptions: BTreeMap<String, PlanId>,
}

/// In-memory implementation of every IAM repository port.
#[derive(Default)]
pub struct InMemoryStore {
    identity: Mutex<Identity>,
    authz: Mutex<Authz>,
    entitlement: Mutex<Entitlement>,
    audit: Mutex<Vec<AuditEvent>>,
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

impl AccountRepo for InMemoryStore {
    fn get(&self, id: &AccountId) -> RepoResult<Option<Account>> {
        Ok(self.identity.lock().unwrap().accounts.get(&id.0).cloned())
    }

    fn upsert(&self, account: Account) -> RepoResult<()> {
        self.identity
            .lock()
            .unwrap()
            .accounts
            .insert(account.id.0.clone(), account);
        Ok(())
    }

    fn list(&self) -> RepoResult<Vec<Account>> {
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

impl ExternalIdentityRepo for InMemoryStore {
    fn get_by_key(&self, key: &ExternalIdentityKey) -> RepoResult<Option<ExternalIdentity>> {
        Ok(self
            .identity
            .lock()
            .unwrap()
            .external
            .get(&external_key(key))
            .cloned())
    }

    fn link(&self, identity: ExternalIdentity) -> RepoResult<()> {
        let key = external_key(&identity.key());
        let mut guard = self.identity.lock().unwrap();
        if guard.external.contains_key(&key) {
            return Err(RepoError::Conflict(format!(
                "external identity {key} is already linked"
            )));
        }
        guard.external.insert(key, identity);
        Ok(())
    }

    fn update_claims(&self, identity: ExternalIdentity) -> RepoResult<()> {
        let key = external_key(&identity.key());
        let mut guard = self.identity.lock().unwrap();
        if !guard.external.contains_key(&key) {
            return Err(RepoError::NotFound(format!(
                "external identity {key} is not linked"
            )));
        }
        guard.external.insert(key, identity);
        Ok(())
    }

    fn list_for_account(&self, account_id: &AccountId) -> RepoResult<Vec<ExternalIdentity>> {
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

impl SessionRepo for InMemoryStore {
    fn get(&self, id: &SessionId) -> RepoResult<Option<Session>> {
        Ok(self.identity.lock().unwrap().sessions.get(&id.0).cloned())
    }

    fn get_by_token_hash(&self, token_hash: &str) -> RepoResult<Option<Session>> {
        let guard = self.identity.lock().unwrap();
        Ok(guard
            .sessions_by_token
            .get(token_hash)
            .and_then(|id| guard.sessions.get(id))
            .cloned())
    }

    fn create(&self, session: Session) -> RepoResult<()> {
        let mut guard = self.identity.lock().unwrap();
        if guard.sessions.contains_key(&session.id.0) {
            return Err(RepoError::Conflict(format!(
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

    fn update(&self, session: Session) -> RepoResult<()> {
        let mut guard = self.identity.lock().unwrap();
        if !guard.sessions.contains_key(&session.id.0) {
            return Err(RepoError::NotFound(format!(
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

impl LoginFlowRepo for InMemoryStore {
    fn start(&self, state: OAuthLoginState) -> RepoResult<()> {
        let mut guard = self.identity.lock().unwrap();
        if guard.login_flows.contains_key(&state.id.0) {
            return Err(RepoError::Conflict(format!(
                "login flow {} already started",
                state.id.0
            )));
        }
        guard.login_flows.insert(state.id.0.clone(), state);
        Ok(())
    }

    fn get(&self, id: &OAuthLoginStateId) -> RepoResult<Option<OAuthLoginState>> {
        Ok(self
            .identity
            .lock()
            .unwrap()
            .login_flows
            .get(&id.0)
            .cloned())
    }

    fn mark_consumed(&self, id: &OAuthLoginStateId, at: Timestamp) -> RepoResult<()> {
        let mut guard = self.identity.lock().unwrap();
        let flow = guard
            .login_flows
            .get_mut(&id.0)
            .ok_or_else(|| RepoError::NotFound(format!("login flow {} not found", id.0)))?;
        if flow.consumed_at.is_some() {
            return Err(RepoError::Conflict(format!(
                "login flow {} already consumed",
                id.0
            )));
        }
        flow.consumed_at = Some(at);
        Ok(())
    }
}

impl ApiTokenRepo for InMemoryStore {
    fn create(&self, token: ApiToken) -> RepoResult<()> {
        let mut guard = self.identity.lock().unwrap();
        if guard.api_tokens.contains_key(&token.id.0) {
            return Err(RepoError::Conflict(format!(
                "api token {} already exists",
                token.id.0
            )));
        }
        if guard.api_tokens_by_prefix.contains_key(&token.prefix.0) {
            return Err(RepoError::Conflict(format!(
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

    fn get(&self, id: &ApiTokenId) -> RepoResult<Option<ApiToken>> {
        Ok(self.identity.lock().unwrap().api_tokens.get(&id.0).cloned())
    }

    fn get_by_prefix(&self, prefix: &ApiTokenPrefix) -> RepoResult<Option<ApiToken>> {
        let guard = self.identity.lock().unwrap();
        Ok(guard
            .api_tokens_by_prefix
            .get(&prefix.0)
            .and_then(|id| guard.api_tokens.get(id))
            .cloned())
    }

    fn list_for_principal(&self, principal: &PrincipalRef) -> RepoResult<Vec<ApiToken>> {
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

    fn update(&self, token: ApiToken) -> RepoResult<()> {
        let mut guard = self.identity.lock().unwrap();
        if !guard.api_tokens.contains_key(&token.id.0) {
            return Err(RepoError::NotFound(format!(
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

impl OrgRepo for InMemoryStore {
    fn get(&self, id: &OrgId) -> RepoResult<Option<Organization>> {
        Ok(self.authz.lock().unwrap().orgs.get(&id.0).cloned())
    }

    fn upsert(&self, org: Organization) -> RepoResult<()> {
        self.authz
            .lock()
            .unwrap()
            .orgs
            .insert(org.id.0.clone(), org);
        Ok(())
    }

    fn list(&self) -> RepoResult<Vec<Organization>> {
        Ok(self.authz.lock().unwrap().orgs.values().cloned().collect())
    }

    fn remove(&self, id: &OrgId) -> RepoResult<()> {
        self.authz
            .lock()
            .unwrap()
            .orgs
            .remove(&id.0)
            .map(|_| ())
            .ok_or_else(|| RepoError::NotFound(format!("organization {} not found", id.0)))
    }
}

impl GroupRepo for InMemoryStore {
    fn get(&self, id: &GroupId) -> RepoResult<Option<Group>> {
        Ok(self.authz.lock().unwrap().groups.get(&id.0).cloned())
    }

    fn upsert(&self, group: Group) -> RepoResult<()> {
        self.authz
            .lock()
            .unwrap()
            .groups
            .insert(group.id.0.clone(), group);
        Ok(())
    }

    fn list(&self) -> RepoResult<Vec<Group>> {
        Ok(self
            .authz
            .lock()
            .unwrap()
            .groups
            .values()
            .cloned()
            .collect())
    }

    fn remove(&self, id: &GroupId) -> RepoResult<()> {
        self.authz
            .lock()
            .unwrap()
            .groups
            .remove(&id.0)
            .map(|_| ())
            .ok_or_else(|| RepoError::NotFound(format!("group {} not found", id.0)))
    }
}

impl RoleRepo for InMemoryStore {
    fn get(&self, id: &RoleId) -> RepoResult<Option<RoleDef>> {
        Ok(self.authz.lock().unwrap().roles.get(&id.0).cloned())
    }

    fn upsert(&self, role: RoleDef) -> RepoResult<()> {
        self.authz
            .lock()
            .unwrap()
            .roles
            .insert(role.id.0.clone(), role);
        Ok(())
    }

    fn list(&self) -> RepoResult<Vec<RoleDef>> {
        Ok(self.authz.lock().unwrap().roles.values().cloned().collect())
    }

    fn remove(&self, id: &RoleId) -> RepoResult<()> {
        self.authz
            .lock()
            .unwrap()
            .roles
            .remove(&id.0)
            .map(|_| ())
            .ok_or_else(|| RepoError::NotFound(format!("role {} not found", id.0)))
    }
}

impl GrantRepo for InMemoryStore {
    fn put(&self, grant: Grant) -> RepoResult<()> {
        self.authz
            .lock()
            .unwrap()
            .grants
            .insert(grant.id.0.clone(), grant);
        Ok(())
    }

    fn get(&self, id: &GrantId) -> RepoResult<Option<Grant>> {
        Ok(self.authz.lock().unwrap().grants.get(&id.0).cloned())
    }

    fn list(&self) -> RepoResult<Vec<Grant>> {
        Ok(self
            .authz
            .lock()
            .unwrap()
            .grants
            .values()
            .cloned()
            .collect())
    }

    fn remove(&self, id: &GrantId) -> RepoResult<()> {
        self.authz
            .lock()
            .unwrap()
            .grants
            .remove(&id.0)
            .map(|_| ())
            .ok_or_else(|| RepoError::NotFound(format!("grant {} not found", id.0)))
    }
}

impl RoleBindingRepo for InMemoryStore {
    fn add(&self, binding: RoleBinding) -> RepoResult<()> {
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

    fn list_for_principal(&self, principal: &PrincipalRef) -> RepoResult<Vec<RoleBinding>> {
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

    fn list(&self) -> RepoResult<Vec<RoleBinding>> {
        Ok(self
            .authz
            .lock()
            .unwrap()
            .role_bindings
            .values()
            .cloned()
            .collect())
    }

    fn remove(&self, binding: &RoleBinding) -> RepoResult<()> {
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
            .ok_or_else(|| RepoError::NotFound("role binding not found".to_owned()))
    }
}

impl ResourceModelRepo for InMemoryStore {
    fn put_edge(&self, edge: ResourceEdge) -> RepoResult<()> {
        let key = format!("{}\u{1f}{}", edge.resource_type.0, edge.resource_id.0);
        self.authz.lock().unwrap().resource_edges.insert(key, edge);
        Ok(())
    }

    fn list_edges(&self) -> RepoResult<Vec<ResourceEdge>> {
        Ok(self
            .authz
            .lock()
            .unwrap()
            .resource_edges
            .values()
            .cloned()
            .collect())
    }
}

impl PlanRepo for InMemoryStore {
    fn put(&self, plan: Plan) -> RepoResult<()> {
        self.entitlement
            .lock()
            .unwrap()
            .plans
            .insert(plan.id.0.clone(), plan);
        Ok(())
    }

    fn get(&self, id: &PlanId) -> RepoResult<Option<Plan>> {
        Ok(self.entitlement.lock().unwrap().plans.get(&id.0).cloned())
    }

    fn list(&self) -> RepoResult<Vec<Plan>> {
        Ok(self
            .entitlement
            .lock()
            .unwrap()
            .plans
            .values()
            .cloned()
            .collect())
    }

    fn subscribe(&self, principal: PrincipalRef, plan: PlanId) -> RepoResult<()> {
        let key = json_key(&principal, "principal")?;
        self.entitlement
            .lock()
            .unwrap()
            .subscriptions
            .insert(key, plan);
        Ok(())
    }

    fn subscription(&self, principal: &PrincipalRef) -> RepoResult<Option<PlanId>> {
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
    fn record(&self, event: AuditEvent) -> RepoResult<()> {
        self.audit.lock().unwrap().push(event);
        Ok(())
    }

    fn events(&self) -> RepoResult<Vec<AuditEvent>> {
        Ok(self.audit.lock().unwrap().clone())
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
            AccountRepo::get(&store, &AccountId("a".into())).unwrap(),
            None
        );
        AccountRepo::upsert(&store, account("a")).unwrap();
        assert_eq!(AccountRepo::list(&store).unwrap().len(), 1);
        assert_eq!(
            AccountRepo::get(&store, &AccountId("a".into()))
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
        assert!(matches!(dup, Err(RepoError::Conflict(_))));
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
        SessionRepo::create(&store, session.clone()).unwrap();
        assert!(matches!(
            SessionRepo::create(&store, session.clone()),
            Err(RepoError::Conflict(_))
        ));
        assert_eq!(store.get_by_token_hash("hash").unwrap().unwrap().id.0, "s1");

        let mut revoked = session;
        revoked.revoked_at = Some(ts("2026-06-19T01:00:00Z"));
        SessionRepo::update(&store, revoked).unwrap();
        assert!(
            SessionRepo::get(&store, &SessionId("s1".into()))
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
        assert!(matches!(store.start(flow), Err(RepoError::Conflict(_))));
        store
            .mark_consumed(&OAuthLoginStateId("l1".into()), ts("2026-06-19T00:05:00Z"))
            .unwrap();
        let reuse =
            store.mark_consumed(&OAuthLoginStateId("l1".into()), ts("2026-06-19T00:06:00Z"));
        assert!(matches!(reuse, Err(RepoError::Conflict(_))));
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
            scope: vec![awaken_iam_contract::ActionKey("pack.publish".into())],
            created_at: ts("2026-06-19T00:00:00Z"),
            expires_at: None,
            revoked_at: None,
        };
        ApiTokenRepo::create(&store, token.clone()).unwrap();
        // Duplicate id and duplicate prefix both fail closed.
        assert!(matches!(
            ApiTokenRepo::create(&store, token.clone()),
            Err(RepoError::Conflict(_))
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
            ApiTokenRepo::list_for_principal(&store, &principal)
                .unwrap()
                .len(),
            1
        );

        let mut revoked = token;
        revoked.revoked_at = Some(ts("2026-06-19T01:00:00Z"));
        ApiTokenRepo::update(&store, revoked).unwrap();
        assert!(
            ApiTokenRepo::get(&store, &ApiTokenId("tok_1".into()))
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
        GrantRepo::put(&store, grant).unwrap();
        assert!(
            GrantRepo::get(&store, &GrantId("g1".into()))
                .unwrap()
                .is_some()
        );
        assert_eq!(GrantRepo::list(&store).unwrap().len(), 1);
        GrantRepo::remove(&store, &GrantId("g1".into())).unwrap();
        assert!(matches!(
            GrantRepo::remove(&store, &GrantId("g1".into())),
            Err(RepoError::NotFound(_))
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
            RoleBindingRepo::list_for_principal(&store, &principal)
                .unwrap()
                .len(),
            1
        );
        assert_eq!(RoleBindingRepo::list(&store).unwrap().len(), 1);

        let binding = RoleBinding {
            principal: principal.clone(),
            role: RoleId("admin".into()),
            scope: ScopeRef::Global,
        };
        RoleBindingRepo::remove(&store, &binding).unwrap();
        assert_eq!(RoleBindingRepo::list(&store).unwrap().len(), 0);
        assert!(matches!(
            RoleBindingRepo::remove(&store, &binding),
            Err(RepoError::NotFound(_))
        ));
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
        OrgRepo::upsert(&store, org.clone()).unwrap();
        assert_eq!(
            OrgRepo::get(&store, &OrgId("acme".into())).unwrap(),
            Some(org)
        );
        assert_eq!(OrgRepo::list(&store).unwrap().len(), 1);
        OrgRepo::remove(&store, &OrgId("acme".into())).unwrap();
        assert!(matches!(
            OrgRepo::remove(&store, &OrgId("acme".into())),
            Err(RepoError::NotFound(_))
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
        GroupRepo::upsert(&store, group.clone()).unwrap();
        assert_eq!(GroupRepo::get(&store, &group.id).unwrap(), Some(group));
        assert_eq!(GroupRepo::list(&store).unwrap().len(), 1);

        let role = RoleDef {
            id: RoleId("publisher".into()),
            display_name: Some("Publisher".into()),
            action_patterns: vec![ActionPattern("pack.*".into())],
            created_at: ts("2026-06-21T00:00:00Z"),
            updated_at: ts("2026-06-21T00:00:00Z"),
        };
        RoleRepo::upsert(&store, role.clone()).unwrap();
        assert_eq!(RoleRepo::get(&store, &role.id).unwrap(), Some(role));
        assert_eq!(RoleRepo::list(&store).unwrap().len(), 1);
        RoleRepo::remove(&store, &RoleId("publisher".into())).unwrap();
        assert!(matches!(
            RoleRepo::remove(&store, &RoleId("publisher".into())),
            Err(RepoError::NotFound(_))
        ));
    }

    #[test]
    fn plans_and_subscriptions_resolve_by_principal() {
        let store = InMemoryStore::new();
        PlanRepo::put(
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
        assert_eq!(PlanRepo::list(&store).unwrap().len(), 1);
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
}
