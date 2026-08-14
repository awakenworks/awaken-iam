//! Backend-neutral SQL adapter implementing every IAM repository port.
//!
//! The two real database backends — Postgres and SQLite — differ only in the
//! driver edge: how a parameterized statement is rendered (placeholder syntax,
//! `jsonb` casts) and executed. Everything above that — the table layout, the
//! column encoding of contract value objects, the uniqueness and lifecycle
//! invariants the ports require — is identical, so it lives here once over a
//! small [`SqlConn`] seam. [`super::sqlite`] and [`super::postgres`] each provide
//! a `SqlConn`; mounting either behind [`SqlStore`] is what makes the backend a
//! configuration choice rather than a code fork (see
//! [ADR-0003](../../../../docs/adr/0003-storage-backends.md)).
//!
//! Statements are authored against a tiny portable placeholder dialect: `?` is a
//! plain bound parameter and `?j` is a parameter bound into a JSON column. Each
//! backend rewrites those markers to its own form (`$1` / `$1::jsonb` for
//! Postgres, `?` for SQLite), so the shared SQL never names a dialect. JSON
//! columns are read back with `CAST(col AS TEXT)`, portable across both.

use awaken_iam_contract::{
    Account, AccountId, ApiToken, ApiTokenId, ApiTokenPrefix, AuthorizationProfile,
    AuthorizationProfileDocument, ExternalIdentity, ExternalIdentityClaims, ExternalIdentityId,
    ExternalIdentityKey, GrantSubjectRef, IdentityProviderKey, InvitationBinding, InvitationId,
    InvitationStatus, NamespaceId, OAuthLoginState, OAuthLoginStateId, OrgId, PrincipalRef,
    ProfileLifecycle, ResourceId, ResourceType, Session, SessionId, Timestamp, WorkspaceId,
    WorkspaceOrgEdge,
};
use awaken_iam_core::{
    AccountIdentityRepo, AccountRepo, ActionPattern, ApiTokenRepo, AuditEvent, AuditSink,
    AuthCodeRepo, AuthorizationProfileRepo, Effect, ExternalIdentityRepo, Grant, GrantId,
    GrantRepo, GrantSubject, Group, GroupId, GroupRepo, Invitation, InvitationRepo, LoginFlowRepo,
    OAuthClientRepo, OrgRepo, Organization, Plan, PlanId, PlanRepo, PlanTier, Quota, RateLimit,
    RegisteredClient, RepoError, RepoResult, ResourceEdge, ResourceModelRepo, RoleBinding,
    RoleBindingRepo, RoleDef, RoleId, RoleRepo, SessionRepo, StoredAuthorizationCode,
};
use std::collections::{BTreeMap, BTreeSet};

use super::migration::Dialect;
use super::{Fence, FenceStore};

/// A bound parameter value. Every IAM column is text or JSON-as-text, so a
/// nullable string is the only shape a backend has to bind.
pub type SqlParam = Option<String>;

/// A materialized result row: one nullable string per selected column, in select
/// order. JSON columns arrive already rendered to text by the backend.
pub type SqlRow = Vec<Option<String>>;

/// One parameterized write in a backend-owned atomic transaction.
#[derive(Debug, Clone)]
pub struct SqlWrite {
    pub sql: String,
    pub params: Vec<SqlParam>,
}

/// The driver seam each backend implements: render the portable placeholder
/// dialect, bind parameters, and run a statement against its connection.
///
/// Implementations map a uniqueness-constraint violation to
/// [`RepoError::Conflict`] and any other backend failure to [`RepoError::Backend`]
/// so the shared store logic stays dialect-free.
pub trait SqlConn: Send + Sync {
    /// The backend dialect, mirroring the migration executor's choice.
    fn dialect(&self) -> Dialect;
    /// Execute a write, returning the number of rows affected.
    fn execute(&self, sql: &str, params: &[SqlParam]) -> RepoResult<u64>;
    /// Execute a read, returning every matching row.
    fn query(&self, sql: &str, params: &[SqlParam]) -> RepoResult<Vec<SqlRow>>;
    /// Execute every write atomically and return each affected-row count.
    fn execute_transaction(&self, writes: &[SqlWrite]) -> RepoResult<Vec<u64>>;
}

/// A storage adapter that serves every IAM repository port from a real database.
///
/// Generic over the [`SqlConn`] backend so the same logic backs Postgres and
/// SQLite. The table `prefix` matches the one the migration plan rendered, so the
/// adapter reads and writes exactly the tables [`super::IamStore`] created.
#[derive(Debug, Clone)]
pub struct SqlStore<B> {
    backend: B,
    prefix: String,
}

impl<B: SqlConn> SqlStore<B> {
    /// Build a store over `backend` for tables under `prefix`.
    ///
    /// The prefix must be the same bare identifier the migration store used; it
    /// is validated the same way to keep interpolated table names injection-free.
    pub fn with_prefix(backend: B, prefix: impl Into<String>) -> RepoResult<Self> {
        let prefix = prefix.into();
        if prefix.is_empty()
            || !prefix
                .bytes()
                .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'_')
        {
            return Err(RepoError::Backend(format!(
                "invalid table prefix {prefix:?}: expected [a-z0-9_]+"
            )));
        }
        Ok(Self { backend, prefix })
    }

    /// Borrow the underlying backend.
    pub fn backend(&self) -> &B {
        &self.backend
    }

    /// Fully-qualified table name `<prefix>_<name>`.
    fn table(&self, name: &str) -> String {
        format!("{}_{}", self.prefix, name)
    }
}

// --- column encoding -------------------------------------------------------

fn json_encode<T: serde::Serialize>(value: &T, what: &str) -> RepoResult<String> {
    serde_json::to_string(value).map_err(|err| RepoError::Backend(format!("encode {what}: {err}")))
}

fn json_decode<T: serde::de::DeserializeOwned>(raw: &str, what: &str) -> RepoResult<T> {
    serde_json::from_str(raw).map_err(|err| RepoError::Backend(format!("decode {what}: {err}")))
}

/// A non-null string column, or a backend error when the column was unexpectedly
/// absent or null.
fn req(row: &SqlRow, idx: usize, what: &str) -> RepoResult<String> {
    row.get(idx)
        .and_then(|cell| cell.clone())
        .ok_or_else(|| RepoError::Backend(format!("missing column {idx} ({what})")))
}

/// A nullable string column.
fn opt(row: &SqlRow, idx: usize) -> Option<String> {
    row.get(idx).and_then(|cell| cell.clone())
}

fn encode_effect(effect: Effect) -> &'static str {
    match effect {
        Effect::Allow => "allow",
        Effect::RequireApproval => "require_approval",
        Effect::Deny => "deny",
    }
}

fn decode_effect(raw: &str) -> RepoResult<Effect> {
    match raw {
        "allow" => Ok(Effect::Allow),
        "require_approval" => Ok(Effect::RequireApproval),
        "deny" => Ok(Effect::Deny),
        other => Err(RepoError::Backend(format!("unknown effect {other:?}"))),
    }
}

fn encode_tier(tier: PlanTier) -> &'static str {
    match tier {
        PlanTier::Free => "free",
        PlanTier::Pro => "pro",
        PlanTier::Team => "team",
        PlanTier::Enterprise => "enterprise",
    }
}

fn decode_tier(raw: &str) -> RepoResult<PlanTier> {
    match raw {
        "free" => Ok(PlanTier::Free),
        "pro" => Ok(PlanTier::Pro),
        "team" => Ok(PlanTier::Team),
        "enterprise" => Ok(PlanTier::Enterprise),
        other => Err(RepoError::Backend(format!("unknown plan tier {other:?}"))),
    }
}

fn encode_grant_subject(subject: &GrantSubject) -> RepoResult<String> {
    let dto = match subject {
        GrantSubject::Principal(principal) => GrantSubjectRef::Principal {
            principal: principal.clone(),
        },
        GrantSubject::Role(role) => GrantSubjectRef::Role {
            role_id: role.0.clone(),
        },
        GrantSubject::Group(group) => GrantSubjectRef::Group {
            group_id: group.0.clone(),
        },
    };
    json_encode(&dto, "grant subject")
}

fn decode_grant_subject(raw: &str) -> RepoResult<GrantSubject> {
    let dto: GrantSubjectRef = json_decode(raw, "grant subject")?;
    Ok(match dto {
        GrantSubjectRef::Principal { principal } => GrantSubject::Principal(principal),
        GrantSubjectRef::Role { role_id } => GrantSubject::Role(RoleId(role_id)),
        GrantSubjectRef::Group { group_id } => GrantSubject::Group(GroupId(group_id)),
    })
}

/// Convenience: a `Some(String)` text parameter.
fn p(value: impl Into<String>) -> SqlParam {
    Some(value.into())
}

// --- row decoders ----------------------------------------------------------

fn decode_account(row: &SqlRow) -> RepoResult<Account> {
    Ok(Account {
        id: AccountId(req(row, 0, "account.id")?),
        status: json_decode(
            &format!("\"{}\"", req(row, 1, "account.status")?),
            "account status",
        )?,
        display_name: opt(row, 2),
        created_at: Timestamp(req(row, 3, "account.created_at")?),
        updated_at: Timestamp(req(row, 4, "account.updated_at")?),
    })
}

fn decode_external(row: &SqlRow) -> RepoResult<ExternalIdentity> {
    let claims: ExternalIdentityClaims = json_decode(&req(row, 3, "identity.claims")?, "claims")?;
    Ok(ExternalIdentity {
        id: ExternalIdentityId(req(row, 0, "identity.id")?),
        account_id: AccountId(req(row, 1, "identity.account_id")?),
        provider_key: IdentityProviderKey(req(row, 2, "identity.provider_key")?),
        claims,
        first_seen_at: Timestamp(req(row, 4, "identity.first_seen_at")?),
        last_seen_at: Timestamp(req(row, 5, "identity.last_seen_at")?),
    })
}

fn decode_session(row: &SqlRow) -> RepoResult<Session> {
    Ok(Session {
        id: SessionId(req(row, 0, "session.id")?),
        account_id: AccountId(req(row, 1, "session.account_id")?),
        token_hash: req(row, 2, "session.token_hash")?,
        external_identity_id: opt(row, 3).map(ExternalIdentityId),
        created_at: Timestamp(req(row, 4, "session.created_at")?),
        last_seen_at: Timestamp(req(row, 5, "session.last_seen_at")?),
        expires_at: Timestamp(req(row, 6, "session.expires_at")?),
        revoked_at: opt(row, 7).map(Timestamp),
    })
}

fn decode_login_flow(row: &SqlRow) -> RepoResult<OAuthLoginState> {
    Ok(OAuthLoginState {
        id: OAuthLoginStateId(req(row, 0, "login_flow.id")?),
        provider_key: IdentityProviderKey(req(row, 1, "login_flow.provider_key")?),
        state_hash: req(row, 2, "login_flow.state_hash")?,
        nonce_hash: opt(row, 3),
        pkce_verifier_hash: opt(row, 4),
        return_to: opt(row, 5),
        created_at: Timestamp(req(row, 6, "login_flow.created_at")?),
        expires_at: Timestamp(req(row, 7, "login_flow.expires_at")?),
        consumed_at: opt(row, 8).map(Timestamp),
    })
}

fn decode_oauth_client(row: &SqlRow) -> RepoResult<RegisteredClient> {
    Ok(RegisteredClient {
        client_id: req(row, 0, "oauth_client.client_id")?,
        redirect_uris: json_decode(
            &req(row, 1, "oauth_client.redirect_uris")?,
            "oauth redirect URIs",
        )?,
        allowed_scopes: json_decode(
            &req(row, 2, "oauth_client.allowed_scopes")?,
            "oauth allowed scopes",
        )?,
        secret_hash: opt(row, 3),
    })
}

fn decode_auth_code(row: &SqlRow) -> RepoResult<StoredAuthorizationCode> {
    Ok(StoredAuthorizationCode {
        code_hash: req(row, 0, "oauth_code.code_hash")?,
        client_id: req(row, 1, "oauth_code.client_id")?,
        redirect_uri: req(row, 2, "oauth_code.redirect_uri")?,
        account_id: AccountId(req(row, 3, "oauth_code.account_id")?),
        scopes: json_decode(&req(row, 4, "oauth_code.scopes")?, "oauth code scopes")?,
        code_challenge: opt(row, 5),
        nonce: opt(row, 6),
        expires_at: Timestamp(req(row, 7, "oauth_code.expires_at")?),
        consumed_at: opt(row, 8).map(Timestamp),
    })
}

fn decode_api_token(row: &SqlRow) -> RepoResult<ApiToken> {
    Ok(ApiToken {
        id: ApiTokenId(req(row, 0, "api_token.id")?),
        prefix: ApiTokenPrefix(req(row, 1, "api_token.prefix")?),
        principal: json_decode(&req(row, 2, "api_token.principal")?, "principal")?,
        secret_hash: req(row, 3, "api_token.secret_hash")?,
        workspace: WorkspaceId(req(row, 4, "api_token.workspace")?),
        created_at: Timestamp(req(row, 5, "api_token.created_at")?),
        expires_at: opt(row, 6).map(Timestamp),
        revoked_at: opt(row, 7).map(Timestamp),
    })
}

fn decode_grant(row: &SqlRow) -> RepoResult<Grant> {
    Ok(Grant {
        id: GrantId(req(row, 0, "grant.id")?),
        subject: decode_grant_subject(&req(row, 1, "grant.subject")?)?,
        action_pattern: ActionPattern(req(row, 2, "grant.action_pattern")?),
        scope: json_decode(&req(row, 3, "grant.scope")?, "grant scope")?,
        effect: decode_effect(&req(row, 4, "grant.effect")?)?,
    })
}

fn decode_role_binding(row: &SqlRow) -> RepoResult<RoleBinding> {
    Ok(RoleBinding {
        principal: json_decode(&req(row, 0, "binding.principal")?, "principal")?,
        role: RoleId(req(row, 1, "binding.role")?),
        scope: json_decode(&req(row, 2, "binding.scope")?, "binding scope")?,
    })
}

fn decode_resource_edge(row: &SqlRow) -> RepoResult<ResourceEdge> {
    Ok(ResourceEdge {
        resource_type: ResourceType(req(row, 0, "edge.resource_type")?),
        resource_id: ResourceId(req(row, 1, "edge.resource_id")?),
        parent: json_decode(&req(row, 2, "edge.parent")?, "edge parent")?,
    })
}

fn decode_workspace_org(row: &SqlRow) -> RepoResult<WorkspaceOrgEdge> {
    Ok(WorkspaceOrgEdge {
        workspace_id: WorkspaceId(req(row, 0, "workspace_org.workspace_id")?),
        org_id: OrgId(req(row, 1, "workspace_org.org_id")?),
    })
}

fn decode_invitation(row: &SqlRow) -> RepoResult<Invitation> {
    let status = match req(row, 7, "invitation.status")?.as_str() {
        "pending" => InvitationStatus::Pending,
        "accepted" => InvitationStatus::Accepted,
        "revoked" => InvitationStatus::Revoked,
        "expired" => InvitationStatus::Expired,
        other => {
            return Err(RepoError::Backend(format!(
                "invalid invitation status {other}"
            )));
        }
    };
    Ok(Invitation {
        id: InvitationId(req(row, 0, "invitation.id")?),
        idempotency_key: req(row, 1, "invitation.idempotency_key")?,
        org_id: OrgId(req(row, 2, "invitation.org_id")?),
        email: req(row, 3, "invitation.email")?,
        bindings: json_decode::<Vec<InvitationBinding>>(
            &req(row, 4, "invitation.bindings")?,
            "invitation bindings",
        )?,
        invited_by: json_decode::<PrincipalRef>(
            &req(row, 5, "invitation.invited_by")?,
            "invitation inviter",
        )?,
        token_hash: req(row, 6, "invitation.token_hash")?,
        status,
        expires_at: Timestamp(req(row, 8, "invitation.expires_at")?),
        created_at: Timestamp(req(row, 9, "invitation.created_at")?),
        updated_at: Timestamp(req(row, 10, "invitation.updated_at")?),
        accepted_by_account_id: opt(row, 11).map(AccountId),
    })
}

fn invitation_columns() -> &'static str {
    "id, idempotency_key, org_id, email, CAST(bindings AS TEXT), \
     CAST(invited_by AS TEXT), token_hash, status, expires_at, created_at, \
     updated_at, accepted_by_account_id"
}

fn revision_key(revision: u64) -> String {
    format!("{revision:020}")
}

fn parse_revision(raw: &str) -> RepoResult<u64> {
    raw.parse()
        .map_err(|err| RepoError::Backend(format!("decode profile revision: {err}")))
}

fn lifecycle_name(lifecycle: ProfileLifecycle) -> &'static str {
    match lifecycle {
        ProfileLifecycle::Draft => "draft",
        ProfileLifecycle::Validated => "validated",
        ProfileLifecycle::Active => "active",
        ProfileLifecycle::Retired => "retired",
    }
}

fn decode_lifecycle(raw: &str) -> RepoResult<ProfileLifecycle> {
    match raw {
        "draft" => Ok(ProfileLifecycle::Draft),
        "validated" => Ok(ProfileLifecycle::Validated),
        "active" => Ok(ProfileLifecycle::Active),
        "retired" => Ok(ProfileLifecycle::Retired),
        _ => Err(RepoError::Backend(format!(
            "decode profile lifecycle: unknown value {raw:?}"
        ))),
    }
}

fn decode_profile(row: &SqlRow) -> RepoResult<AuthorizationProfile> {
    let namespace = req(row, 0, "profile namespace")?;
    let revision = req(row, 1, "profile revision")?;
    let lifecycle = req(row, 2, "profile lifecycle")?;
    let document = req(row, 3, "profile document")?;
    let checksum = req(row, 4, "profile checksum")?;
    let created_at = req(row, 5, "profile created_at")?;
    Ok(AuthorizationProfile {
        namespace: NamespaceId(namespace),
        revision: parse_revision(&revision)?,
        lifecycle: decode_lifecycle(&lifecycle)?,
        document: json_decode::<AuthorizationProfileDocument>(&document, "profile document")?,
        checksum,
        created_at: Timestamp(created_at),
    })
}

fn decode_plan(row: &SqlRow) -> RepoResult<Plan> {
    Ok(Plan {
        id: PlanId(req(row, 0, "plan.id")?),
        tier: decode_tier(&req(row, 1, "plan.tier")?)?,
        features: json_decode::<BTreeSet<String>>(&req(row, 2, "plan.features")?, "plan features")?,
        limits: json_decode::<BTreeMap<String, Quota>>(
            &req(row, 3, "plan.limits")?,
            "plan limits",
        )?,
        rates: json_decode::<BTreeMap<String, RateLimit>>(
            &req(row, 4, "plan.rates")?,
            "plan rates",
        )?,
    })
}

fn decode_org(row: &SqlRow) -> RepoResult<Organization> {
    Ok(Organization {
        id: OrgId(req(row, 0, "org.id")?),
        display_name: opt(row, 1),
        owner: json_decode(&req(row, 2, "org.owner")?, "org owner")?,
        created_at: Timestamp(req(row, 3, "org.created_at")?),
        updated_at: Timestamp(req(row, 4, "org.updated_at")?),
    })
}

fn decode_group(row: &SqlRow) -> RepoResult<Group> {
    Ok(Group {
        id: GroupId(req(row, 0, "group.id")?),
        org: OrgId(req(row, 1, "group.org_id")?),
        display_name: opt(row, 2),
        members: json_decode(&req(row, 3, "group.members")?, "group members")?,
        created_at: Timestamp(req(row, 4, "group.created_at")?),
        updated_at: Timestamp(req(row, 5, "group.updated_at")?),
    })
}

fn decode_role(row: &SqlRow) -> RepoResult<RoleDef> {
    let patterns: Vec<String> =
        json_decode(&req(row, 2, "role.action_patterns")?, "role patterns")?;
    Ok(RoleDef {
        id: RoleId(req(row, 0, "role.id")?),
        display_name: opt(row, 1),
        action_patterns: patterns.into_iter().map(ActionPattern).collect(),
        created_at: Timestamp(req(row, 3, "role.created_at")?),
        updated_at: Timestamp(req(row, 4, "role.updated_at")?),
    })
}

fn decode_audit(row: &SqlRow) -> RepoResult<AuditEvent> {
    let actor = match opt(row, 1) {
        Some(raw) => Some(json_decode::<PrincipalRef>(&raw, "audit actor")?),
        None => None,
    };
    Ok(AuditEvent {
        at: Timestamp(req(row, 0, "audit.at")?),
        actor,
        action: req(row, 2, "audit.action")?,
        detail: req(row, 3, "audit.detail")?,
    })
}

// --- iam.identity ----------------------------------------------------------

impl<B: SqlConn> AccountRepo for SqlStore<B> {
    fn get(&self, id: &AccountId) -> RepoResult<Option<Account>> {
        let sql = format!(
            "SELECT id, status, display_name, created_at, updated_at FROM {} WHERE id = ?",
            self.table("accounts")
        );
        let rows = self.backend.query(&sql, &[p(id.0.clone())])?;
        rows.first().map(decode_account).transpose()
    }

    fn upsert(&self, account: Account) -> RepoResult<()> {
        let status = json_encode(&account.status, "account status")?;
        let status = status.trim_matches('"').to_owned();
        let sql = format!(
            "INSERT INTO {t} (id, status, display_name, created_at, updated_at) \
             VALUES (?, ?, ?, ?, ?) \
             ON CONFLICT (id) DO UPDATE SET \
             status = excluded.status, display_name = excluded.display_name, \
             created_at = excluded.created_at, updated_at = excluded.updated_at",
            t = self.table("accounts")
        );
        self.backend.execute(
            &sql,
            &[
                p(account.id.0),
                p(status),
                account.display_name,
                p(account.created_at.0),
                p(account.updated_at.0),
            ],
        )?;
        Ok(())
    }

    fn list(&self) -> RepoResult<Vec<Account>> {
        let sql = format!(
            "SELECT id, status, display_name, created_at, updated_at FROM {} ORDER BY id",
            self.table("accounts")
        );
        self.backend
            .query(&sql, &[])?
            .iter()
            .map(decode_account)
            .collect()
    }
}

impl<B: SqlConn> ExternalIdentityRepo for SqlStore<B> {
    fn get_by_key(&self, key: &ExternalIdentityKey) -> RepoResult<Option<ExternalIdentity>> {
        let sql = format!(
            "SELECT id, account_id, provider_key, CAST(claims AS TEXT), first_seen_at, last_seen_at \
             FROM {} WHERE provider_key = ? AND subject = ?",
            self.table("external_identities")
        );
        let rows = self.backend.query(
            &sql,
            &[p(key.provider_key.0.clone()), p(key.subject.0.clone())],
        )?;
        rows.first().map(decode_external).transpose()
    }

    fn link(&self, identity: ExternalIdentity) -> RepoResult<()> {
        let key = identity.key();
        let claims = json_encode(&identity.claims, "claims")?;
        let sql = format!(
            "INSERT INTO {t} \
             (id, account_id, provider_key, subject, claims, first_seen_at, last_seen_at) \
             VALUES (?, ?, ?, ?, ?j, ?, ?)",
            t = self.table("external_identities")
        );
        self.backend.execute(
            &sql,
            &[
                p(identity.id.0),
                p(identity.account_id.0),
                p(key.provider_key.0),
                p(key.subject.0),
                p(claims),
                p(identity.first_seen_at.0),
                p(identity.last_seen_at.0),
            ],
        )?;
        Ok(())
    }

    fn update_claims(&self, identity: ExternalIdentity) -> RepoResult<()> {
        let key = identity.key();
        let claims = json_encode(&identity.claims, "claims")?;
        let sql = format!(
            "UPDATE {t} SET claims = ?j, last_seen_at = ? \
             WHERE provider_key = ? AND subject = ?",
            t = self.table("external_identities")
        );
        let affected = self.backend.execute(
            &sql,
            &[
                p(claims),
                p(identity.last_seen_at.0),
                p(key.provider_key.0.clone()),
                p(key.subject.0.clone()),
            ],
        )?;
        if affected == 0 {
            return Err(RepoError::NotFound(format!(
                "external identity {}:{} is not linked",
                key.provider_key.0, key.subject.0
            )));
        }
        Ok(())
    }

    fn list_for_account(&self, account_id: &AccountId) -> RepoResult<Vec<ExternalIdentity>> {
        let sql = format!(
            "SELECT id, account_id, provider_key, CAST(claims AS TEXT), first_seen_at, last_seen_at \
             FROM {} WHERE account_id = ? ORDER BY id",
            self.table("external_identities")
        );
        self.backend
            .query(&sql, &[p(account_id.0.clone())])?
            .iter()
            .map(decode_external)
            .collect()
    }
}

impl<B: SqlConn> AccountIdentityRepo for SqlStore<B> {
    fn provision(&self, account: Account, identity: ExternalIdentity) -> RepoResult<()> {
        let status = json_encode(&account.status, "account status")?
            .trim_matches('"')
            .to_owned();
        let key = identity.key();
        let claims = json_encode(&identity.claims, "claims")?;
        self.backend.execute_transaction(&[
            SqlWrite {
                sql: format!(
                    "INSERT INTO {} (id, status, display_name, created_at, updated_at) \
                     VALUES (?, ?, ?, ?, ?)",
                    self.table("accounts")
                ),
                params: vec![
                    p(account.id.0),
                    p(status),
                    account.display_name,
                    p(account.created_at.0),
                    p(account.updated_at.0),
                ],
            },
            SqlWrite {
                sql: format!(
                    "INSERT INTO {} \
                     (id, account_id, provider_key, subject, claims, first_seen_at, last_seen_at) \
                     VALUES (?, ?, ?, ?, ?j, ?, ?)",
                    self.table("external_identities")
                ),
                params: vec![
                    p(identity.id.0),
                    p(identity.account_id.0),
                    p(key.provider_key.0),
                    p(key.subject.0),
                    p(claims),
                    p(identity.first_seen_at.0),
                    p(identity.last_seen_at.0),
                ],
            },
        ])?;
        Ok(())
    }

    fn unlink(
        &self,
        key: &ExternalIdentityKey,
        account_id: &AccountId,
    ) -> RepoResult<ExternalIdentity> {
        let existing = ExternalIdentityRepo::get_by_key(self, key)?.ok_or_else(|| {
            RepoError::NotFound(format!(
                "external identity {}:{}",
                key.provider_key.0, key.subject.0
            ))
        })?;
        if &existing.account_id != account_id {
            return Err(RepoError::Conflict(format!(
                "external identity {}:{} belongs to another account",
                key.provider_key.0, key.subject.0
            )));
        }
        let table = self.table("external_identities");
        let affected = self.backend.execute(
            &format!(
                "DELETE FROM {table} WHERE provider_key = ? AND subject = ? AND account_id = ? \
                 AND (SELECT COUNT(*) FROM {table} WHERE account_id = ?) > 1"
            ),
            &[
                p(key.provider_key.0.clone()),
                p(key.subject.0.clone()),
                p(account_id.0.clone()),
                p(account_id.0.clone()),
            ],
        )?;
        if affected == 0 {
            return Err(RepoError::Conflict(format!(
                "account {} must retain one external identity",
                account_id.0
            )));
        }
        Ok(existing)
    }
}

impl<B: SqlConn> SessionRepo for SqlStore<B> {
    fn get(&self, id: &SessionId) -> RepoResult<Option<Session>> {
        let sql = format!(
            "SELECT id, account_id, token_hash, external_identity_id, created_at, last_seen_at, \
             expires_at, revoked_at FROM {} WHERE id = ?",
            self.table("sessions")
        );
        let rows = self.backend.query(&sql, &[p(id.0.clone())])?;
        rows.first().map(decode_session).transpose()
    }

    fn get_by_token_hash(&self, token_hash: &str) -> RepoResult<Option<Session>> {
        let sql = format!(
            "SELECT id, account_id, token_hash, external_identity_id, created_at, last_seen_at, \
             expires_at, revoked_at FROM {} WHERE token_hash = ?",
            self.table("sessions")
        );
        let rows = self.backend.query(&sql, &[p(token_hash)])?;
        rows.first().map(decode_session).transpose()
    }

    fn create(&self, session: Session) -> RepoResult<()> {
        let sql = format!(
            "INSERT INTO {t} \
             (id, account_id, token_hash, external_identity_id, created_at, last_seen_at, \
             expires_at, revoked_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
            t = self.table("sessions")
        );
        self.backend.execute(
            &sql,
            &[
                p(session.id.0),
                p(session.account_id.0),
                p(session.token_hash),
                session.external_identity_id.map(|i| i.0),
                p(session.created_at.0),
                p(session.last_seen_at.0),
                p(session.expires_at.0),
                session.revoked_at.map(|t| t.0),
            ],
        )?;
        Ok(())
    }

    fn update(&self, session: Session) -> RepoResult<()> {
        let sql = format!(
            "UPDATE {t} SET account_id = ?, token_hash = ?, external_identity_id = ?, \
             created_at = ?, last_seen_at = ?, expires_at = ?, revoked_at = ? WHERE id = ?",
            t = self.table("sessions")
        );
        let affected = self.backend.execute(
            &sql,
            &[
                p(session.account_id.0),
                p(session.token_hash),
                session.external_identity_id.map(|i| i.0),
                p(session.created_at.0),
                p(session.last_seen_at.0),
                p(session.expires_at.0),
                session.revoked_at.map(|t| t.0),
                p(session.id.0.clone()),
            ],
        )?;
        if affected == 0 {
            return Err(RepoError::NotFound(format!(
                "session {} does not exist",
                session.id.0
            )));
        }
        Ok(())
    }
}

impl<B: SqlConn> LoginFlowRepo for SqlStore<B> {
    fn start(&self, state: OAuthLoginState) -> RepoResult<()> {
        let sql = format!(
            "INSERT INTO {t} \
             (id, provider_key, state_hash, nonce_hash, pkce_verifier_hash, return_to, \
             created_at, expires_at, consumed_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
            t = self.table("login_flows")
        );
        self.backend.execute(
            &sql,
            &[
                p(state.id.0),
                p(state.provider_key.0),
                p(state.state_hash),
                state.nonce_hash,
                state.pkce_verifier_hash,
                state.return_to,
                p(state.created_at.0),
                p(state.expires_at.0),
                state.consumed_at.map(|t| t.0),
            ],
        )?;
        Ok(())
    }

    fn get(&self, id: &OAuthLoginStateId) -> RepoResult<Option<OAuthLoginState>> {
        let sql = format!(
            "SELECT id, provider_key, state_hash, nonce_hash, pkce_verifier_hash, return_to, \
             created_at, expires_at, consumed_at FROM {} WHERE id = ?",
            self.table("login_flows")
        );
        let rows = self.backend.query(&sql, &[p(id.0.clone())])?;
        rows.first().map(decode_login_flow).transpose()
    }

    fn mark_consumed(&self, id: &OAuthLoginStateId, at: Timestamp) -> RepoResult<()> {
        let sql = format!(
            "UPDATE {t} SET consumed_at = ? WHERE id = ? AND consumed_at IS NULL",
            t = self.table("login_flows")
        );
        let affected = self.backend.execute(&sql, &[p(at.0), p(id.0.clone())])?;
        if affected == 0 {
            // Distinguish "no such flow" (NotFound) from "already consumed"
            // (Conflict), matching the in-memory adapter's fail-closed reuse
            // detection.
            let exists = format!("SELECT id FROM {} WHERE id = ?", self.table("login_flows"));
            if self.backend.query(&exists, &[p(id.0.clone())])?.is_empty() {
                return Err(RepoError::NotFound(format!(
                    "login flow {} not found",
                    id.0
                )));
            }
            return Err(RepoError::Conflict(format!(
                "login flow {} already consumed",
                id.0
            )));
        }
        Ok(())
    }
}

impl<B: SqlConn> OAuthClientRepo for SqlStore<B> {
    fn upsert(&self, client: RegisteredClient) -> RepoResult<()> {
        let redirect_uris = json_encode(&client.redirect_uris, "oauth redirect URIs")?;
        let allowed_scopes = json_encode(&client.allowed_scopes, "oauth allowed scopes")?;
        let sql = format!(
            "INSERT INTO {t} (client_id, redirect_uris, allowed_scopes, secret_hash) \
             VALUES (?, ?j, ?j, ?) ON CONFLICT (client_id) DO UPDATE SET \
             redirect_uris = excluded.redirect_uris, \
             allowed_scopes = excluded.allowed_scopes, secret_hash = excluded.secret_hash",
            t = self.table("oauth_clients")
        );
        self.backend.execute(
            &sql,
            &[
                p(client.client_id),
                p(redirect_uris),
                p(allowed_scopes),
                client.secret_hash,
            ],
        )?;
        Ok(())
    }

    fn get(&self, client_id: &str) -> RepoResult<Option<RegisteredClient>> {
        let sql = format!(
            "SELECT client_id, CAST(redirect_uris AS TEXT), \
             CAST(allowed_scopes AS TEXT), secret_hash FROM {} WHERE client_id = ?",
            self.table("oauth_clients")
        );
        let rows = self.backend.query(&sql, &[p(client_id)])?;
        rows.first().map(decode_oauth_client).transpose()
    }

    fn list(&self) -> RepoResult<Vec<RegisteredClient>> {
        let sql = format!(
            "SELECT client_id, CAST(redirect_uris AS TEXT), \
             CAST(allowed_scopes AS TEXT), secret_hash FROM {} ORDER BY client_id",
            self.table("oauth_clients")
        );
        self.backend
            .query(&sql, &[])?
            .iter()
            .map(decode_oauth_client)
            .collect()
    }

    fn remove(&self, client_id: &str) -> RepoResult<()> {
        let sql = format!(
            "DELETE FROM {} WHERE client_id = ?",
            self.table("oauth_clients")
        );
        if self.backend.execute(&sql, &[p(client_id)])? == 0 {
            return Err(RepoError::NotFound(format!(
                "oauth client {client_id} not found"
            )));
        }
        Ok(())
    }
}

impl<B: SqlConn> AuthCodeRepo for SqlStore<B> {
    fn create(&self, code: StoredAuthorizationCode) -> RepoResult<()> {
        let scopes = json_encode(&code.scopes, "oauth code scopes")?;
        let sql = format!(
            "INSERT INTO {t} (code_hash, client_id, redirect_uri, account_id, scopes, \
             code_challenge, nonce, expires_at, consumed_at) \
             VALUES (?, ?, ?, ?, ?j, ?, ?, ?, ?)",
            t = self.table("oauth_authorization_codes")
        );
        self.backend.execute(
            &sql,
            &[
                p(code.code_hash),
                p(code.client_id),
                p(code.redirect_uri),
                p(code.account_id.0),
                p(scopes),
                code.code_challenge,
                code.nonce,
                p(code.expires_at.0),
                code.consumed_at.map(|timestamp| timestamp.0),
            ],
        )?;
        Ok(())
    }

    fn get(&self, code_hash: &str) -> RepoResult<Option<StoredAuthorizationCode>> {
        let sql = format!(
            "SELECT code_hash, client_id, redirect_uri, account_id, CAST(scopes AS TEXT), \
             code_challenge, nonce, expires_at, consumed_at FROM {} WHERE code_hash = ?",
            self.table("oauth_authorization_codes")
        );
        let rows = self.backend.query(&sql, &[p(code_hash)])?;
        rows.first().map(decode_auth_code).transpose()
    }

    fn consume_if_live(&self, code_hash: &str, now: &Timestamp) -> RepoResult<bool> {
        let sql = format!(
            "UPDATE {t} SET consumed_at = ? WHERE code_hash = ? \
             AND consumed_at IS NULL AND expires_at > ?",
            t = self.table("oauth_authorization_codes")
        );
        Ok(self
            .backend
            .execute(&sql, &[p(now.0.clone()), p(code_hash), p(now.0.clone())])?
            == 1)
    }
}

impl<B: SqlConn> ApiTokenRepo for SqlStore<B> {
    fn create(&self, token: ApiToken) -> RepoResult<()> {
        let principal = json_encode(&token.principal, "principal")?;
        let sql = format!(
            "INSERT INTO {t} \
             (id, prefix, principal, secret_hash, workspace, created_at, expires_at, revoked_at) \
             VALUES (?, ?, ?j, ?, ?, ?, ?, ?)",
            t = self.table("api_tokens")
        );
        self.backend.execute(
            &sql,
            &[
                p(token.id.0),
                p(token.prefix.0),
                p(principal),
                p(token.secret_hash),
                p(token.workspace.0),
                p(token.created_at.0),
                token.expires_at.map(|t| t.0),
                token.revoked_at.map(|t| t.0),
            ],
        )?;
        Ok(())
    }

    fn get(&self, id: &ApiTokenId) -> RepoResult<Option<ApiToken>> {
        let sql = format!(
            "SELECT id, prefix, CAST(principal AS TEXT), secret_hash, workspace, \
             created_at, expires_at, revoked_at FROM {} WHERE id = ?",
            self.table("api_tokens")
        );
        let rows = self.backend.query(&sql, &[p(id.0.clone())])?;
        rows.first().map(decode_api_token).transpose()
    }

    fn get_by_prefix(&self, prefix: &ApiTokenPrefix) -> RepoResult<Option<ApiToken>> {
        let sql = format!(
            "SELECT id, prefix, CAST(principal AS TEXT), secret_hash, workspace, \
             created_at, expires_at, revoked_at FROM {} WHERE prefix = ?",
            self.table("api_tokens")
        );
        let rows = self.backend.query(&sql, &[p(prefix.0.clone())])?;
        rows.first().map(decode_api_token).transpose()
    }

    fn list_for_principal(&self, principal: &PrincipalRef) -> RepoResult<Vec<ApiToken>> {
        let principal_json = json_encode(principal, "principal")?;
        let sql = format!(
            "SELECT id, prefix, CAST(principal AS TEXT), secret_hash, workspace, \
             created_at, expires_at, revoked_at FROM {} WHERE principal = ?j ORDER BY id",
            self.table("api_tokens")
        );
        self.backend
            .query(&sql, &[p(principal_json)])?
            .iter()
            .map(decode_api_token)
            .collect()
    }

    fn update(&self, token: ApiToken) -> RepoResult<()> {
        let principal = json_encode(&token.principal, "principal")?;
        let sql = format!(
            "UPDATE {t} SET prefix = ?, principal = ?j, secret_hash = ?, workspace = ?, \
             created_at = ?, expires_at = ?, revoked_at = ? WHERE id = ?",
            t = self.table("api_tokens")
        );
        let affected = self.backend.execute(
            &sql,
            &[
                p(token.prefix.0),
                p(principal),
                p(token.secret_hash),
                p(token.workspace.0),
                p(token.created_at.0),
                token.expires_at.map(|t| t.0),
                token.revoked_at.map(|t| t.0),
                p(token.id.0.clone()),
            ],
        )?;
        if affected == 0 {
            return Err(RepoError::NotFound(format!(
                "api token {} does not exist",
                token.id.0
            )));
        }
        Ok(())
    }
}

// --- iam.authz -------------------------------------------------------------

impl<B: SqlConn> OrgRepo for SqlStore<B> {
    fn get(&self, id: &OrgId) -> RepoResult<Option<Organization>> {
        let sql = format!(
            "SELECT id, display_name, CAST(owner AS TEXT), created_at, updated_at \
             FROM {} WHERE id = ?",
            self.table("orgs")
        );
        let rows = self.backend.query(&sql, &[p(id.0.clone())])?;
        rows.first().map(decode_org).transpose()
    }

    fn upsert(&self, org: Organization) -> RepoResult<()> {
        let owner = json_encode(&org.owner, "org owner")?;
        let sql = format!(
            "INSERT INTO {t} (id, display_name, owner, created_at, updated_at) \
             VALUES (?, ?, ?j, ?, ?) \
             ON CONFLICT (id) DO UPDATE SET display_name = excluded.display_name, \
             owner = excluded.owner, created_at = excluded.created_at, \
             updated_at = excluded.updated_at",
            t = self.table("orgs")
        );
        self.backend.execute(
            &sql,
            &[
                p(org.id.0),
                org.display_name,
                p(owner),
                p(org.created_at.0),
                p(org.updated_at.0),
            ],
        )?;
        Ok(())
    }

    fn list(&self) -> RepoResult<Vec<Organization>> {
        let sql = format!(
            "SELECT id, display_name, CAST(owner AS TEXT), created_at, updated_at \
             FROM {} ORDER BY id",
            self.table("orgs")
        );
        self.backend
            .query(&sql, &[])?
            .iter()
            .map(decode_org)
            .collect()
    }

    fn remove(&self, id: &OrgId) -> RepoResult<()> {
        let sql = format!("DELETE FROM {} WHERE id = ?", self.table("orgs"));
        if self.backend.execute(&sql, &[p(id.0.clone())])? == 0 {
            return Err(RepoError::NotFound(format!(
                "organization {} not found",
                id.0
            )));
        }
        Ok(())
    }
}

impl<B: SqlConn> GroupRepo for SqlStore<B> {
    fn get(&self, id: &GroupId) -> RepoResult<Option<Group>> {
        let sql = format!(
            "SELECT id, org_id, display_name, CAST(members AS TEXT), created_at, updated_at \
             FROM {} WHERE id = ?",
            self.table("groups")
        );
        let rows = self.backend.query(&sql, &[p(id.0.clone())])?;
        rows.first().map(decode_group).transpose()
    }

    fn upsert(&self, group: Group) -> RepoResult<()> {
        let members = json_encode(&group.members, "group members")?;
        let sql = format!(
            "INSERT INTO {t} (id, org_id, display_name, members, created_at, updated_at) \
             VALUES (?, ?, ?, ?j, ?, ?) \
             ON CONFLICT (id) DO UPDATE SET org_id = excluded.org_id, \
             display_name = excluded.display_name, members = excluded.members, \
             created_at = excluded.created_at, updated_at = excluded.updated_at",
            t = self.table("groups")
        );
        self.backend.execute(
            &sql,
            &[
                p(group.id.0),
                p(group.org.0),
                group.display_name,
                p(members),
                p(group.created_at.0),
                p(group.updated_at.0),
            ],
        )?;
        Ok(())
    }

    fn list(&self) -> RepoResult<Vec<Group>> {
        let sql = format!(
            "SELECT id, org_id, display_name, CAST(members AS TEXT), created_at, updated_at \
             FROM {} ORDER BY id",
            self.table("groups")
        );
        self.backend
            .query(&sql, &[])?
            .iter()
            .map(decode_group)
            .collect()
    }

    fn remove(&self, id: &GroupId) -> RepoResult<()> {
        let sql = format!("DELETE FROM {} WHERE id = ?", self.table("groups"));
        if self.backend.execute(&sql, &[p(id.0.clone())])? == 0 {
            return Err(RepoError::NotFound(format!("group {} not found", id.0)));
        }
        Ok(())
    }
}

impl<B: SqlConn> RoleRepo for SqlStore<B> {
    fn get(&self, id: &RoleId) -> RepoResult<Option<RoleDef>> {
        let sql = format!(
            "SELECT id, display_name, CAST(action_patterns AS TEXT), created_at, updated_at \
             FROM {} WHERE id = ?",
            self.table("roles")
        );
        let rows = self.backend.query(&sql, &[p(id.0.clone())])?;
        rows.first().map(decode_role).transpose()
    }

    fn upsert(&self, role: RoleDef) -> RepoResult<()> {
        let patterns: Vec<String> = role.action_patterns.iter().map(|p| p.0.clone()).collect();
        let patterns = json_encode(&patterns, "role patterns")?;
        let sql = format!(
            "INSERT INTO {t} (id, display_name, action_patterns, created_at, updated_at) \
             VALUES (?, ?, ?j, ?, ?) \
             ON CONFLICT (id) DO UPDATE SET display_name = excluded.display_name, \
             action_patterns = excluded.action_patterns, created_at = excluded.created_at, \
             updated_at = excluded.updated_at",
            t = self.table("roles")
        );
        self.backend.execute(
            &sql,
            &[
                p(role.id.0),
                role.display_name,
                p(patterns),
                p(role.created_at.0),
                p(role.updated_at.0),
            ],
        )?;
        Ok(())
    }

    fn list(&self) -> RepoResult<Vec<RoleDef>> {
        let sql = format!(
            "SELECT id, display_name, CAST(action_patterns AS TEXT), created_at, updated_at \
             FROM {} ORDER BY id",
            self.table("roles")
        );
        self.backend
            .query(&sql, &[])?
            .iter()
            .map(decode_role)
            .collect()
    }

    fn remove(&self, id: &RoleId) -> RepoResult<()> {
        let sql = format!("DELETE FROM {} WHERE id = ?", self.table("roles"));
        if self.backend.execute(&sql, &[p(id.0.clone())])? == 0 {
            return Err(RepoError::NotFound(format!("role {} not found", id.0)));
        }
        Ok(())
    }
}

impl<B: SqlConn> GrantRepo for SqlStore<B> {
    fn put(&self, grant: Grant) -> RepoResult<()> {
        let subject = encode_grant_subject(&grant.subject)?;
        let scope = json_encode(&grant.scope, "grant scope")?;
        let sql = format!(
            "INSERT INTO {t} (id, subject, action_pattern, scope, effect) \
             VALUES (?, ?j, ?, ?j, ?) \
             ON CONFLICT (id) DO UPDATE SET subject = excluded.subject, \
             action_pattern = excluded.action_pattern, scope = excluded.scope, \
             effect = excluded.effect",
            t = self.table("grants")
        );
        self.backend.execute(
            &sql,
            &[
                p(grant.id.0),
                p(subject),
                p(grant.action_pattern.0),
                p(scope),
                p(encode_effect(grant.effect)),
            ],
        )?;
        Ok(())
    }

    fn get(&self, id: &GrantId) -> RepoResult<Option<Grant>> {
        let sql = format!(
            "SELECT id, CAST(subject AS TEXT), action_pattern, CAST(scope AS TEXT), effect \
             FROM {} WHERE id = ?",
            self.table("grants")
        );
        let rows = self.backend.query(&sql, &[p(id.0.clone())])?;
        rows.first().map(decode_grant).transpose()
    }

    fn list(&self) -> RepoResult<Vec<Grant>> {
        let sql = format!(
            "SELECT id, CAST(subject AS TEXT), action_pattern, CAST(scope AS TEXT), effect \
             FROM {} ORDER BY id",
            self.table("grants")
        );
        self.backend
            .query(&sql, &[])?
            .iter()
            .map(decode_grant)
            .collect()
    }

    fn remove(&self, id: &GrantId) -> RepoResult<()> {
        let sql = format!("DELETE FROM {} WHERE id = ?", self.table("grants"));
        if self.backend.execute(&sql, &[p(id.0.clone())])? == 0 {
            return Err(RepoError::NotFound(format!("grant {} not found", id.0)));
        }
        Ok(())
    }
}

impl<B: SqlConn> RoleBindingRepo for SqlStore<B> {
    fn add(&self, binding: RoleBinding) -> RepoResult<()> {
        let principal = json_encode(&binding.principal, "principal")?;
        let scope = json_encode(&binding.scope, "binding scope")?;
        let sql = format!(
            "INSERT INTO {t} (principal, role, scope) VALUES (?j, ?, ?j) \
             ON CONFLICT (principal, role, scope) DO NOTHING",
            t = self.table("role_bindings")
        );
        self.backend
            .execute(&sql, &[p(principal), p(binding.role.0), p(scope)])?;
        Ok(())
    }

    fn list_for_principal(&self, principal: &PrincipalRef) -> RepoResult<Vec<RoleBinding>> {
        let principal_json = json_encode(principal, "principal")?;
        let sql = format!(
            "SELECT CAST(principal AS TEXT), role, CAST(scope AS TEXT) FROM {} \
             WHERE principal = ?j ORDER BY role, scope",
            self.table("role_bindings")
        );
        self.backend
            .query(&sql, &[p(principal_json)])?
            .iter()
            .map(decode_role_binding)
            .collect()
    }

    fn list(&self) -> RepoResult<Vec<RoleBinding>> {
        let sql = format!(
            "SELECT CAST(principal AS TEXT), role, CAST(scope AS TEXT) FROM {} \
             ORDER BY principal, role, scope",
            self.table("role_bindings")
        );
        self.backend
            .query(&sql, &[])?
            .iter()
            .map(decode_role_binding)
            .collect()
    }

    fn remove(&self, binding: &RoleBinding) -> RepoResult<()> {
        let principal = json_encode(&binding.principal, "principal")?;
        let scope = json_encode(&binding.scope, "binding scope")?;
        let sql = format!(
            "DELETE FROM {} WHERE principal = ?j AND role = ? AND scope = ?j",
            self.table("role_bindings")
        );
        let affected = self
            .backend
            .execute(&sql, &[p(principal), p(binding.role.0.clone()), p(scope)])?;
        if affected == 0 {
            return Err(RepoError::NotFound("role binding not found".to_owned()));
        }
        Ok(())
    }

    fn replace_scoped(
        &self,
        principal: &PrincipalRef,
        scope: &awaken_iam_contract::ScopeRef,
        managed_roles: &[RoleId],
        replacement_roles: &[RoleId],
    ) -> RepoResult<()> {
        let principal = json_encode(principal, "principal")?;
        let scope = json_encode(scope, "binding scope")?;
        let table = self.table("role_bindings");
        let mut writes = Vec::with_capacity(managed_roles.len() + replacement_roles.len());
        for role in managed_roles {
            writes.push(SqlWrite {
                sql: format!(
                    "DELETE FROM {table} WHERE principal = ?j AND role = ? AND scope = ?j"
                ),
                params: vec![p(principal.clone()), p(role.0.clone()), p(scope.clone())],
            });
        }
        for role in replacement_roles {
            writes.push(SqlWrite {
                sql: format!(
                    "INSERT INTO {table} (principal, role, scope) VALUES (?j, ?, ?j) \
                     ON CONFLICT (principal, role, scope) DO NOTHING"
                ),
                params: vec![p(principal.clone()), p(role.0.clone()), p(scope.clone())],
            });
        }
        self.backend.execute_transaction(&writes)?;
        Ok(())
    }
}

impl<B: SqlConn> InvitationRepo for SqlStore<B> {
    fn create_invitation(&self, invitation: Invitation) -> RepoResult<()> {
        let bindings = json_encode(&invitation.bindings, "invitation bindings")?;
        let invited_by = json_encode(&invitation.invited_by, "invitation inviter")?;
        let sql = format!(
            "INSERT INTO {} (id,idempotency_key,org_id,email,bindings,invited_by,token_hash,status,expires_at,created_at,updated_at,accepted_by_account_id) \
             VALUES (?,?,?,?,?j,?j,?,?,?,?,?,?)",
            self.table("invitations")
        );
        self.backend.execute(
            &sql,
            &[
                p(invitation.id.0),
                p(invitation.idempotency_key),
                p(invitation.org_id.0),
                p(invitation.email),
                p(bindings),
                p(invited_by),
                p(invitation.token_hash),
                p(encode_invitation_status(invitation.status)),
                p(invitation.expires_at.0),
                p(invitation.created_at.0),
                p(invitation.updated_at.0),
                invitation.accepted_by_account_id.map(|id| id.0),
            ],
        )?;
        Ok(())
    }

    fn get_invitation(&self, id: &InvitationId) -> RepoResult<Option<Invitation>> {
        let sql = format!(
            "SELECT {} FROM {} WHERE id = ?",
            invitation_columns(),
            self.table("invitations")
        );
        self.backend
            .query(&sql, &[p(id.0.clone())])?
            .first()
            .map(decode_invitation)
            .transpose()
    }

    fn get_invitation_by_idempotency(
        &self,
        org_id: &OrgId,
        key: &str,
    ) -> RepoResult<Option<Invitation>> {
        let sql = format!(
            "SELECT {} FROM {} WHERE org_id = ? AND idempotency_key = ?",
            invitation_columns(),
            self.table("invitations")
        );
        self.backend
            .query(&sql, &[p(org_id.0.clone()), p(key.to_owned())])?
            .first()
            .map(decode_invitation)
            .transpose()
    }

    fn list_invitations_for_org(&self, org_id: &OrgId) -> RepoResult<Vec<Invitation>> {
        let sql = format!(
            "SELECT {} FROM {} WHERE org_id = ? ORDER BY created_at, id",
            invitation_columns(),
            self.table("invitations")
        );
        self.backend
            .query(&sql, &[p(org_id.0.clone())])?
            .iter()
            .map(decode_invitation)
            .collect()
    }

    fn replace_pending_invitation(
        &self,
        invitation: Invitation,
        expected: &str,
    ) -> RepoResult<bool> {
        let bindings = json_encode(&invitation.bindings, "invitation bindings")?;
        let invited_by = json_encode(&invitation.invited_by, "invitation inviter")?;
        let sql = format!(
            "UPDATE {} SET email=?,bindings=?j,invited_by=?j,token_hash=?,status=?,expires_at=?,updated_at=?,accepted_by_account_id=? \
             WHERE id=? AND status='pending' AND token_hash=?",
            self.table("invitations")
        );
        Ok(self.backend.execute(
            &sql,
            &[
                p(invitation.email),
                p(bindings),
                p(invited_by),
                p(invitation.token_hash),
                p(encode_invitation_status(invitation.status)),
                p(invitation.expires_at.0),
                p(invitation.updated_at.0),
                invitation.accepted_by_account_id.map(|id| id.0),
                p(invitation.id.0),
                p(expected.to_owned()),
            ],
        )? == 1)
    }

    fn accept_pending_invitation(
        &self,
        id: &InvitationId,
        expected: &str,
        account_id: &AccountId,
        at: &Timestamp,
    ) -> RepoResult<Option<Invitation>> {
        let current = self
            .get_invitation(id)?
            .ok_or_else(|| RepoError::NotFound("invitation not found".into()))?;
        if current.status == InvitationStatus::Accepted
            && current.accepted_by_account_id.as_ref() == Some(account_id)
            && current.token_hash == expected
        {
            return Ok(Some(current));
        }
        let mut writes = vec![SqlWrite {
            sql: format!(
                "UPDATE {} SET status='accepted',accepted_by_account_id=?,updated_at=? WHERE id=? AND status='pending' AND token_hash=?",
                self.table("invitations")
            ),
            params: vec![
                p(account_id.0.clone()),
                p(at.0.clone()),
                p(id.0.clone()),
                p(expected.to_owned()),
            ],
        }];
        let principal = json_encode(
            &PrincipalRef::Account {
                account_id: account_id.clone(),
            },
            "principal",
        )?;
        for target in &current.bindings {
            let scope = json_encode(&target.scope, "binding scope")?;
            writes.push(SqlWrite {
                sql: format!(
                    "INSERT INTO {bindings} (principal,role,scope) \
                     SELECT ?j,?,?j WHERE EXISTS (SELECT 1 FROM {invites} WHERE id=? AND status='accepted' AND accepted_by_account_id=? AND token_hash=?) \
                     ON CONFLICT (principal,role,scope) DO NOTHING",
                    bindings = self.table("role_bindings"), invites = self.table("invitations")
                ),
                params: vec![p(principal.clone()), p(target.role_id.clone()), p(scope), p(id.0.clone()), p(account_id.0.clone()), p(expected.to_owned())],
            });
        }
        let affected = self.backend.execute_transaction(&writes)?;
        if affected.first().copied() != Some(1) {
            return Ok(None);
        }
        self.get_invitation(id)
    }
}

fn encode_invitation_status(status: InvitationStatus) -> &'static str {
    match status {
        InvitationStatus::Pending => "pending",
        InvitationStatus::Accepted => "accepted",
        InvitationStatus::Revoked => "revoked",
        InvitationStatus::Expired => "expired",
    }
}

impl<B: SqlConn> ResourceModelRepo for SqlStore<B> {
    fn put_edge(&self, edge: ResourceEdge) -> RepoResult<()> {
        let parent = json_encode(&edge.parent, "edge parent")?;
        let sql = format!(
            "INSERT INTO {t} (resource_type, resource_id, parent) VALUES (?, ?, ?j) \
             ON CONFLICT (resource_type, resource_id) DO UPDATE SET parent = excluded.parent",
            t = self.table("resource_edges")
        );
        self.backend.execute(
            &sql,
            &[p(edge.resource_type.0), p(edge.resource_id.0), p(parent)],
        )?;
        Ok(())
    }

    fn list_edges(&self) -> RepoResult<Vec<ResourceEdge>> {
        let sql = format!(
            "SELECT resource_type, resource_id, CAST(parent AS TEXT) FROM {} \
             ORDER BY resource_type, resource_id",
            self.table("resource_edges")
        );
        self.backend
            .query(&sql, &[])?
            .iter()
            .map(decode_resource_edge)
            .collect()
    }

    fn put_workspace_org(&self, edge: WorkspaceOrgEdge) -> RepoResult<()> {
        let sql = format!(
            "INSERT INTO {t} (workspace_id, org_id) VALUES (?, ?) \
             ON CONFLICT (workspace_id) DO UPDATE SET org_id = excluded.org_id",
            t = self.table("workspace_org_edges")
        );
        self.backend
            .execute(&sql, &[p(edge.workspace_id.0), p(edge.org_id.0)])?;
        Ok(())
    }

    fn workspace_org(&self, workspace_id: &WorkspaceId) -> RepoResult<Option<WorkspaceOrgEdge>> {
        let sql = format!(
            "SELECT workspace_id, org_id FROM {} WHERE workspace_id = ?",
            self.table("workspace_org_edges")
        );
        let rows = self.backend.query(&sql, &[p(workspace_id.0.clone())])?;
        rows.first().map(decode_workspace_org).transpose()
    }

    fn list_workspace_orgs(&self) -> RepoResult<Vec<WorkspaceOrgEdge>> {
        let sql = format!(
            "SELECT workspace_id, org_id FROM {} ORDER BY workspace_id",
            self.table("workspace_org_edges")
        );
        self.backend
            .query(&sql, &[])?
            .iter()
            .map(decode_workspace_org)
            .collect()
    }
}

impl<B: SqlConn> AuthorizationProfileRepo for SqlStore<B> {
    fn create_profile(&self, profile: AuthorizationProfile) -> RepoResult<()> {
        let document = json_encode(&profile.document, "authorization profile document")?;
        let sql = format!(
            "INSERT INTO {} (namespace, revision, lifecycle, document, checksum, created_at) \
             VALUES (?, ?, ?, ?j, ?, ?)",
            self.table("authorization_profiles")
        );
        self.backend.execute(
            &sql,
            &[
                p(profile.namespace.0),
                p(revision_key(profile.revision)),
                p(lifecycle_name(profile.lifecycle)),
                p(document),
                p(profile.checksum),
                p(profile.created_at.0),
            ],
        )?;
        Ok(())
    }

    fn get_profile(
        &self,
        namespace: &NamespaceId,
        revision: u64,
    ) -> RepoResult<Option<AuthorizationProfile>> {
        let sql = format!(
            "SELECT namespace, revision, lifecycle, CAST(document AS TEXT), checksum, created_at \
             FROM {} WHERE namespace = ? AND revision = ?",
            self.table("authorization_profiles")
        );
        let rows = self
            .backend
            .query(&sql, &[p(namespace.0.clone()), p(revision_key(revision))])?;
        let mut profile = rows.first().map(decode_profile).transpose()?;
        if let Some(profile) = &mut profile
            && self.active_revision(namespace)? == Some(revision)
        {
            profile.lifecycle = ProfileLifecycle::Active;
        }
        Ok(profile)
    }

    fn list_profiles(&self, namespace: &NamespaceId) -> RepoResult<Vec<AuthorizationProfile>> {
        let sql = format!(
            "SELECT namespace, revision, lifecycle, CAST(document AS TEXT), checksum, created_at \
             FROM {} WHERE namespace = ? ORDER BY revision",
            self.table("authorization_profiles")
        );
        let active = self.active_revision(namespace)?;
        self.backend
            .query(&sql, &[p(namespace.0.clone())])?
            .iter()
            .map(|row| {
                let mut profile = decode_profile(row)?;
                if active == Some(profile.revision) {
                    profile.lifecycle = ProfileLifecycle::Active;
                }
                Ok(profile)
            })
            .collect()
    }

    fn set_profile_lifecycle(
        &self,
        namespace: &NamespaceId,
        revision: u64,
        lifecycle: ProfileLifecycle,
    ) -> RepoResult<()> {
        let sql = format!(
            "UPDATE {} SET lifecycle = ? WHERE namespace = ? AND revision = ?",
            self.table("authorization_profiles")
        );
        let affected = self.backend.execute(
            &sql,
            &[
                p(lifecycle_name(lifecycle)),
                p(namespace.0.clone()),
                p(revision_key(revision)),
            ],
        )?;
        if affected == 0 {
            return Err(RepoError::NotFound("profile revision not found".into()));
        }
        Ok(())
    }

    fn activate_profile(
        &self,
        namespace: &NamespaceId,
        revision: u64,
        expected_active_revision: Option<u64>,
    ) -> RepoResult<Option<u64>> {
        let target = self
            .get_profile(namespace, revision)?
            .ok_or_else(|| RepoError::NotFound("profile revision not found".into()))?;
        if target.lifecycle == ProfileLifecycle::Draft {
            return Err(RepoError::Conflict(
                "profile revision is not validated".into(),
            ));
        }
        let previous = self.active_revision(namespace)?;
        if previous != expected_active_revision {
            return Err(RepoError::Conflict(
                "active profile revision changed".into(),
            ));
        }
        let affected = match expected_active_revision {
            None => {
                let sql = format!(
                    "INSERT INTO {} (namespace, active_revision) VALUES (?, ?) \
                     ON CONFLICT (namespace) DO NOTHING",
                    self.table("authorization_profile_heads")
                );
                self.backend
                    .execute(&sql, &[p(namespace.0.clone()), p(revision_key(revision))])?
            }
            Some(expected) => {
                let sql = format!(
                    "UPDATE {} SET active_revision = ? \
                     WHERE namespace = ? AND active_revision = ?",
                    self.table("authorization_profile_heads")
                );
                self.backend.execute(
                    &sql,
                    &[
                        p(revision_key(revision)),
                        p(namespace.0.clone()),
                        p(revision_key(expected)),
                    ],
                )?
            }
        };
        if affected != 1 {
            return Err(RepoError::Conflict(
                "active profile revision changed".into(),
            ));
        }
        Ok(previous)
    }

    fn retire_active_profile(
        &self,
        namespace: &NamespaceId,
        expected_active_revision: u64,
    ) -> RepoResult<AuthorizationProfile> {
        let mut profile = self
            .get_profile(namespace, expected_active_revision)?
            .ok_or_else(|| RepoError::NotFound("profile revision not found".into()))?;
        let profiles = self.table("authorization_profiles");
        let heads = self.table("authorization_profile_heads");
        let affected = self.backend.execute_transaction(&[
            SqlWrite {
                sql: format!(
                    "UPDATE {profiles} SET lifecycle = 'retired' \
                     WHERE namespace = ? AND revision = ? \
                       AND EXISTS (SELECT 1 FROM {heads} \
                                   WHERE namespace = ? AND active_revision = ?)"
                ),
                params: vec![
                    p(namespace.0.clone()),
                    p(revision_key(expected_active_revision)),
                    p(namespace.0.clone()),
                    p(revision_key(expected_active_revision)),
                ],
            },
            SqlWrite {
                sql: format!(
                    "DELETE FROM {heads} WHERE namespace = ? AND active_revision = ? \
                     AND EXISTS (SELECT 1 FROM {profiles} \
                                 WHERE namespace = ? AND revision = ? AND lifecycle = 'retired')"
                ),
                params: vec![
                    p(namespace.0.clone()),
                    p(revision_key(expected_active_revision)),
                    p(namespace.0.clone()),
                    p(revision_key(expected_active_revision)),
                ],
            },
        ])?;
        if affected.as_slice() != [1, 1] {
            return match self.active_revision(namespace)? {
                None => Err(RepoError::NotFound("active profile head not found".into())),
                Some(_) => Err(RepoError::Conflict(
                    "active profile revision changed".into(),
                )),
            };
        }
        profile.lifecycle = ProfileLifecycle::Retired;
        Ok(profile)
    }

    fn active_profile(&self, namespace: &NamespaceId) -> RepoResult<Option<AuthorizationProfile>> {
        let Some(revision) = self.active_revision(namespace)? else {
            return Ok(None);
        };
        self.get_profile(namespace, revision)
    }

    fn active_profiles(&self) -> RepoResult<Vec<AuthorizationProfile>> {
        let sql = format!(
            "SELECT p.namespace, p.revision, p.lifecycle, CAST(p.document AS TEXT), \
                    p.checksum, p.created_at \
             FROM {profiles} p JOIN {heads} h \
               ON p.namespace = h.namespace AND p.revision = h.active_revision \
             ORDER BY p.namespace",
            profiles = self.table("authorization_profiles"),
            heads = self.table("authorization_profile_heads")
        );
        self.backend
            .query(&sql, &[])?
            .iter()
            .map(|row| {
                let mut profile = decode_profile(row)?;
                profile.lifecycle = ProfileLifecycle::Active;
                Ok(profile)
            })
            .collect()
    }
}

impl<B: SqlConn> SqlStore<B> {
    fn active_revision(&self, namespace: &NamespaceId) -> RepoResult<Option<u64>> {
        let sql = format!(
            "SELECT active_revision FROM {} WHERE namespace = ?",
            self.table("authorization_profile_heads")
        );
        let rows = self.backend.query(&sql, &[p(namespace.0.clone())])?;
        rows.first()
            .map(|row| parse_revision(&req(row, 0, "active profile revision")?))
            .transpose()
    }
}

// --- iam.entitlement -------------------------------------------------------

impl<B: SqlConn> PlanRepo for SqlStore<B> {
    fn put(&self, plan: Plan) -> RepoResult<()> {
        let features = json_encode(&plan.features, "plan features")?;
        let limits = json_encode(&plan.limits, "plan limits")?;
        let rates = json_encode(&plan.rates, "plan rates")?;
        let sql = format!(
            "INSERT INTO {t} (id, tier, features, limits, rates) VALUES (?, ?, ?j, ?j, ?j) \
             ON CONFLICT (id) DO UPDATE SET tier = excluded.tier, features = excluded.features, \
             limits = excluded.limits, rates = excluded.rates",
            t = self.table("plans")
        );
        self.backend.execute(
            &sql,
            &[
                p(plan.id.0),
                p(encode_tier(plan.tier)),
                p(features),
                p(limits),
                p(rates),
            ],
        )?;
        Ok(())
    }

    fn get(&self, id: &PlanId) -> RepoResult<Option<Plan>> {
        let sql = format!(
            "SELECT id, tier, CAST(features AS TEXT), CAST(limits AS TEXT), CAST(rates AS TEXT) \
             FROM {} WHERE id = ?",
            self.table("plans")
        );
        let rows = self.backend.query(&sql, &[p(id.0.clone())])?;
        rows.first().map(decode_plan).transpose()
    }

    fn list(&self) -> RepoResult<Vec<Plan>> {
        let sql = format!(
            "SELECT id, tier, CAST(features AS TEXT), CAST(limits AS TEXT), CAST(rates AS TEXT) \
             FROM {} ORDER BY id",
            self.table("plans")
        );
        self.backend
            .query(&sql, &[])?
            .iter()
            .map(decode_plan)
            .collect()
    }

    fn subscribe(&self, principal: PrincipalRef, plan: PlanId) -> RepoResult<()> {
        let principal_json = json_encode(&principal, "principal")?;
        let sql = format!(
            "INSERT INTO {t} (principal, plan_id) VALUES (?j, ?) \
             ON CONFLICT (principal) DO UPDATE SET plan_id = excluded.plan_id",
            t = self.table("subscriptions")
        );
        self.backend
            .execute(&sql, &[p(principal_json), p(plan.0)])?;
        Ok(())
    }

    fn subscription(&self, principal: &PrincipalRef) -> RepoResult<Option<PlanId>> {
        let principal_json = json_encode(principal, "principal")?;
        let sql = format!(
            "SELECT plan_id FROM {} WHERE principal = ?j",
            self.table("subscriptions")
        );
        let rows = self.backend.query(&sql, &[p(principal_json)])?;
        match rows.first() {
            Some(row) => Ok(Some(PlanId(req(row, 0, "subscription.plan_id")?))),
            None => Ok(None),
        }
    }
}

// --- audit -----------------------------------------------------------------

impl<B: SqlConn> AuditSink for SqlStore<B> {
    fn record(&self, event: AuditEvent) -> RepoResult<()> {
        let actor = match &event.actor {
            Some(principal) => Some(json_encode(principal, "audit actor")?),
            None => None,
        };
        let sql = format!(
            "INSERT INTO {t} (at, actor, action, detail) VALUES (?, ?j, ?, ?)",
            t = self.table("audit_events")
        );
        self.backend.execute(
            &sql,
            &[p(event.at.0), actor, p(event.action), p(event.detail)],
        )?;
        Ok(())
    }

    fn events(&self) -> RepoResult<Vec<AuditEvent>> {
        let sql = format!(
            "SELECT at, CAST(actor AS TEXT), action, detail FROM {} ORDER BY seq",
            self.table("audit_events")
        );
        self.backend
            .query(&sql, &[])?
            .iter()
            .map(decode_audit)
            .collect()
    }
}

impl<B: SqlConn> FenceStore for SqlStore<B> {
    fn fence(&self) -> RepoResult<Fence> {
        let sql = format!(
            "SELECT CAST(version AS TEXT), CAST(epoch AS TEXT) FROM {} WHERE id = 1",
            self.table("fence")
        );
        let rows = self.backend.query(&sql, &[])?;
        let row = rows
            .first()
            .ok_or_else(|| RepoError::Backend("IAM freshness fence is missing".to_owned()))?;
        Ok(Fence {
            version: parse_fence_value(row.first(), "version")?,
            epoch: parse_fence_value(row.get(1), "epoch")?,
        })
    }

    fn advance_version(&self) -> RepoResult<u64> {
        self.advance_fence("version")
    }

    fn advance_epoch(&self) -> RepoResult<u64> {
        self.advance_fence("epoch")
    }
}

impl<B: SqlConn> SqlStore<B> {
    fn advance_fence(&self, column: &str) -> RepoResult<u64> {
        debug_assert!(matches!(column, "version" | "epoch"));
        let sql = format!(
            "UPDATE {table} SET {column} = {column} + 1 WHERE id = 1 \
             RETURNING CAST({column} AS TEXT)",
            table = self.table("fence")
        );
        let rows = self.backend.query(&sql, &[])?;
        let row = rows
            .first()
            .ok_or_else(|| RepoError::Backend("IAM freshness fence is missing".to_owned()))?;
        parse_fence_value(row.first(), column)
    }
}

fn parse_fence_value(value: Option<&Option<String>>, name: &str) -> RepoResult<u64> {
    value
        .and_then(Option::as_deref)
        .ok_or_else(|| RepoError::Backend(format!("IAM freshness fence {name} is null")))?
        .parse()
        .map_err(|error| RepoError::Backend(format!("invalid IAM fence {name}: {error}")))
}
