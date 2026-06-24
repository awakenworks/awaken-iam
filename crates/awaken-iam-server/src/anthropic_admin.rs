//! Anthropic-compatible Admin API wire surface over the one permission model
//! (ADR-0008 decision 6).
//!
//! The Anthropic Claude platform exposes organization administration under
//! `/v1/organizations/...` with typed object envelopes, `x-api-key` /
//! `Bearer org:admin` auth, cursor pagination, and prefixed resource ids. This
//! module renders that exact shape **over the existing one model**: member,
//! workspace-member, API-key, and service-account operations are expressed as
//! [`RoleBinding`] edits through [`PolicyAdminApi::grant_membership`],
//! [`PolicyAdminApi::revoke_membership`], and [`PolicyAdminApi::list_memberships`],
//! and federation issuers/rules are projected from the existing
//! [`TrustedIssuer`]/[`WorkloadBinding`] token-exchange model. There is no second
//! engine — an org role is a binding at [`ScopeRef::Org`], a workspace role a
//! binding at [`ScopeRef::Workspace`], exactly as the kernel already evaluates
//! them.
//!
//! Like the other admin seams ([`PolicyAdminApi`], [`OAuthClientAdminApi`](crate::OAuthClientAdminApi))
//! this is framework-agnostic: it speaks in logical request/response values, and
//! a deployment maps the methods onto the route manifest the assembly declares:
//!
//! | Route | Method on [`AnthropicAdminApi`] |
//! |---|---|
//! | `GET /v1/organizations/users` | [`AnthropicAdminApi::list_members`] |
//! | `GET /v1/organizations/users/{user_id}` | [`AnthropicAdminApi::get_member`] |
//! | `POST /v1/organizations/users/{user_id}` | [`AnthropicAdminApi::set_member_role`] |
//! | `DELETE /v1/organizations/users/{user_id}` | [`AnthropicAdminApi::remove_member`] |
//! | `GET /v1/organizations/workspaces/{workspace_id}/members` | [`AnthropicAdminApi::list_workspace_members`] |
//! | `POST /v1/organizations/workspaces/{workspace_id}/members` | [`AnthropicAdminApi::add_workspace_member`] |
//! | `GET /v1/organizations/workspaces/{workspace_id}/members/{user_id}` | [`AnthropicAdminApi::get_workspace_member`] |
//! | `DELETE /v1/organizations/workspaces/{workspace_id}/members/{user_id}` | [`AnthropicAdminApi::remove_workspace_member`] |
//! | `GET /v1/organizations/api_keys` | [`AnthropicAdminApi::list_api_keys`] |
//! | `POST /v1/organizations/api_keys/{api_key_id}` | [`AnthropicAdminApi::set_api_key_role`] |
//! | `GET /v1/organizations/service_accounts` | [`AnthropicAdminApi::list_service_accounts`] |
//! | `POST /v1/organizations/service_accounts` | [`AnthropicAdminApi::add_service_account`] |
//! | `DELETE /v1/organizations/service_accounts/{service_account_id}` | [`AnthropicAdminApi::remove_service_account`] |
//! | `GET /v1/organizations/federation_issuers` | [`project_federation_issuers`] |
//! | `GET /v1/organizations/federation_rules` | [`project_federation_rules`] |
//!
//! Two divergences are **owned, not silent** (ADR-0008 decision 6): the API-key
//! credential is rendered `oiam_`-style today (an `sk-ant-` rendering is a
//! separately-sequenced minter change), and our [`ScopeRef`] is a superset of
//! org/workspace — these endpoints expose only those two levels, deeper scopes
//! stay on our own admin surface.

use awaken_iam_contract::{
    AccountId, ActionKey, AuthorizationRequest, OrgId, PrincipalRef, ScopeRef, Timestamp,
    WorkspaceId,
};
use awaken_iam_core::{
    AuditSink, GrantRepo, GroupRepo, OrgRepo, ResourceModelRepo, RoleBinding, RoleBindingRepo,
    RoleId, RoleRepo,
};
use serde::{Deserialize, Serialize};

use crate::FenceStore;
use crate::admin_api::{AdminError, PolicyAdminApi};
use crate::token_exchange::{TrustedIssuer, WorkloadBinding};

/// Id prefix for a workspace resource, matching the Anthropic `wrkspc_` shape.
pub const WORKSPACE_ID_PREFIX: &str = "wrkspc_";
/// Id prefix for a service-account principal, matching Anthropic `svac_`.
pub const SERVICE_ACCOUNT_ID_PREFIX: &str = "svac_";
/// Id prefix for a federation issuer, matching Anthropic `fdis_`.
pub const FEDERATION_ISSUER_ID_PREFIX: &str = "fdis_";
/// Id prefix for a federation rule, matching Anthropic `fdrl_`.
pub const FEDERATION_RULE_ID_PREFIX: &str = "fdrl_";

/// Default page size when a list request omits `limit`.
pub const DEFAULT_PAGE_LIMIT: usize = 20;
/// Largest page size a list request may ask for.
pub const MAX_PAGE_LIMIT: usize = 100;

/// Concrete action a caller must be authorized for to use this surface; the
/// `org:admin` posture resolves to an `authorize(admin, "org.admin.*", Org{..})`
/// under the one model (ADR-0008 decision 6).
pub const ORG_ADMIN_ACTION: &str = "org.admin.manage";

/// Prefix of the cleartext credential an Anthropic admin key carries
/// (`sk-ant-admin...`); used only to recognise the credential shape on the wire.
pub const ADMIN_API_KEY_PREFIX: &str = "sk-ant-admin";

/// Errors the Anthropic-compatible admin surface returns.
#[derive(Debug, thiserror::Error)]
pub enum AdminApiError {
    /// No admin credential was presented, or it did not carry `org:admin`.
    #[error("unauthorized: a valid org:admin credential is required")]
    Unauthorized,
    /// A role name on the wire is not one of the decision-2 role enums.
    #[error("unknown role: {0}")]
    UnknownRole(String),
    /// The requested `limit` is zero or above [`MAX_PAGE_LIMIT`].
    #[error("invalid limit: {0}")]
    InvalidLimit(usize),
    /// A pagination cursor did not resolve to a known item, or both
    /// `before_id` and `after_id` were supplied.
    #[error("invalid cursor: {0}")]
    InvalidCursor(String),
    /// The underlying policy-administration operation failed.
    #[error(transparent)]
    Admin(#[from] AdminError),
}

/// Result alias for the Anthropic-compatible admin surface.
pub type ApiResult<T> = Result<T, AdminApiError>;

/// The five org-level roles of the decision-2 catalog, rendered with Anthropic's
/// exact role names.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum OrgRole {
    /// Full organization authority.
    Admin,
    /// Manages API keys.
    Developer,
    /// Manages billing.
    Billing,
    /// Ordinary member.
    User,
    /// Claude Code user.
    ClaudeCodeUser,
}

impl OrgRole {
    /// The catalog [`RoleId`] this role binds to (its Anthropic name).
    pub fn as_str(self) -> &'static str {
        match self {
            OrgRole::Admin => "admin",
            OrgRole::Developer => "developer",
            OrgRole::Billing => "billing",
            OrgRole::User => "user",
            OrgRole::ClaudeCodeUser => "claude_code_user",
        }
    }

    /// Build the catalog [`RoleId`] this role binds to.
    pub fn role_id(self) -> RoleId {
        RoleId(self.as_str().to_owned())
    }

    /// Parse an org role from a catalog [`RoleId`], failing for any id that is
    /// not one of the five org names.
    pub fn from_role_id(role: &RoleId) -> ApiResult<Self> {
        match role.0.as_str() {
            "admin" => Ok(OrgRole::Admin),
            "developer" => Ok(OrgRole::Developer),
            "billing" => Ok(OrgRole::Billing),
            "user" => Ok(OrgRole::User),
            "claude_code_user" => Ok(OrgRole::ClaudeCodeUser),
            other => Err(AdminApiError::UnknownRole(other.to_owned())),
        }
    }
}

/// The five workspace-level roles of the decision-2 catalog.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum WorkspaceRole {
    /// Full workspace authority.
    WorkspaceAdmin,
    /// Manages workspace API keys, files, and skills.
    WorkspaceDeveloper,
    /// Read-only on API keys; manages files and skills.
    WorkspaceLimitedDeveloper,
    /// Read-only workspace member.
    WorkspaceUser,
    /// Workspace billing.
    WorkspaceBilling,
}

impl WorkspaceRole {
    /// The catalog [`RoleId`] this role binds to (its Anthropic name).
    pub fn as_str(self) -> &'static str {
        match self {
            WorkspaceRole::WorkspaceAdmin => "workspace_admin",
            WorkspaceRole::WorkspaceDeveloper => "workspace_developer",
            WorkspaceRole::WorkspaceLimitedDeveloper => "workspace_limited_developer",
            WorkspaceRole::WorkspaceUser => "workspace_user",
            WorkspaceRole::WorkspaceBilling => "workspace_billing",
        }
    }

    /// Build the catalog [`RoleId`] this role binds to.
    pub fn role_id(self) -> RoleId {
        RoleId(self.as_str().to_owned())
    }

    /// Parse a workspace role from a catalog [`RoleId`].
    pub fn from_role_id(role: &RoleId) -> ApiResult<Self> {
        match role.0.as_str() {
            "workspace_admin" => Ok(WorkspaceRole::WorkspaceAdmin),
            "workspace_developer" => Ok(WorkspaceRole::WorkspaceDeveloper),
            "workspace_limited_developer" => Ok(WorkspaceRole::WorkspaceLimitedDeveloper),
            "workspace_user" => Ok(WorkspaceRole::WorkspaceUser),
            "workspace_billing" => Ok(WorkspaceRole::WorkspaceBilling),
            other => Err(AdminApiError::UnknownRole(other.to_owned())),
        }
    }

    /// Map a federation OAuth scope (`workspace:developer`) to the workspace role
    /// its minted token is treated as holding (ADR-0008 decision 5). Returns
    /// `None` for a scope that names no workspace role.
    pub fn from_oauth_scope(scope: &str) -> Option<Self> {
        let suffix = scope.strip_prefix("workspace:")?;
        WorkspaceRole::from_role_id(&RoleId(format!("workspace_{suffix}"))).ok()
    }
}

/// The `type` discriminator stamped on every Anthropic object envelope.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ObjectKind {
    /// An organization member.
    User,
    /// A member of a workspace.
    WorkspaceMember,
    /// An API key bound to a workspace.
    ApiKey,
    /// A non-human service-account principal.
    ServiceAccount,
    /// A trusted federation issuer.
    FederationIssuer,
    /// A federation subject-to-workspace-role rule.
    FederationRule,
}

/// An organization member envelope (`{"type":"user", ...}`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Member {
    /// Always [`ObjectKind::User`].
    #[serde(rename = "type")]
    pub object: ObjectKind,
    /// The member's account id.
    pub id: String,
    /// The member's org role.
    pub role: OrgRole,
}

/// A workspace member envelope (`{"type":"workspace_member", ...}`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WorkspaceMember {
    /// Always [`ObjectKind::WorkspaceMember`].
    #[serde(rename = "type")]
    pub object: ObjectKind,
    /// The `wrkspc_`-prefixed workspace id.
    pub workspace_id: String,
    /// The member's account id.
    pub user_id: String,
    /// The role held in this workspace.
    pub workspace_role: WorkspaceRole,
}

/// An API-key envelope (`{"type":"api_key", ...}`).
///
/// The key's authority is the workspace plus the workspace role its binding
/// carries; there is no per-key scope (ADR-0008 decision 3).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ApiKey {
    /// Always [`ObjectKind::ApiKey`].
    #[serde(rename = "type")]
    pub object: ObjectKind,
    /// The API token id.
    pub id: String,
    /// The `wrkspc_`-prefixed workspace the key is bound to.
    pub workspace_id: String,
    /// The workspace role the key holds.
    pub workspace_role: WorkspaceRole,
}

/// A service-account envelope (`{"type":"service_account", ...}`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ServiceAccount {
    /// Always [`ObjectKind::ServiceAccount`].
    #[serde(rename = "type")]
    pub object: ObjectKind,
    /// The `svac_`-prefixed service-account id.
    pub id: String,
    /// The `wrkspc_`-prefixed workspace it is added to.
    pub workspace_id: String,
    /// The workspace role it holds.
    pub workspace_role: WorkspaceRole,
}

/// A federation-issuer envelope (`{"type":"federation_issuer", ...}`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FederationIssuer {
    /// Always [`ObjectKind::FederationIssuer`].
    #[serde(rename = "type")]
    pub object: ObjectKind,
    /// The `fdis_`-prefixed issuer id.
    pub id: String,
    /// The issuer identifier matching the assertion `iss` claim.
    pub issuer: String,
    /// Audience values an assertion may carry to be accepted.
    pub audiences: Vec<String>,
    /// Whether exchanges from this issuer are currently allowed.
    pub enabled: bool,
}

/// A federation-rule envelope (`{"type":"federation_rule", ...}`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FederationRule {
    /// Always [`ObjectKind::FederationRule`].
    #[serde(rename = "type")]
    pub object: ObjectKind,
    /// The `fdrl_`-prefixed rule id.
    pub id: String,
    /// The `fdis_`-prefixed issuer this rule belongs to.
    pub issuer_id: String,
    /// The exact upstream subject the rule authorizes.
    pub subject: String,
    /// The `svac_`-prefixed service account a minted token assumes.
    pub service_account_id: String,
    /// The OAuth scopes the rule carries.
    pub scopes: Vec<String>,
    /// The workspace role the minted token is treated as holding, when one of
    /// the rule's scopes names a workspace role (ADR-0008 decision 5).
    pub workspace_role: Option<WorkspaceRole>,
}

/// A cursor-paginated page of objects, matching Anthropic's list envelope.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Page<T> {
    /// The objects in this page, in stable id order.
    pub data: Vec<T>,
    /// Whether more objects exist beyond this page in the paging direction.
    pub has_more: bool,
    /// Id of the first object in `data`, for paging backward.
    pub first_id: Option<String>,
    /// Id of the last object in `data`, for paging forward.
    pub last_id: Option<String>,
}

/// Parameters of a cursor-paginated list request.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ListParams {
    /// Page size; defaults to [`DEFAULT_PAGE_LIMIT`], capped at [`MAX_PAGE_LIMIT`].
    pub limit: usize,
    /// Return the objects immediately before this id (paging backward).
    pub before_id: Option<String>,
    /// Return the objects immediately after this id (paging forward).
    pub after_id: Option<String>,
}

impl Default for ListParams {
    fn default() -> Self {
        Self {
            limit: DEFAULT_PAGE_LIMIT,
            before_id: None,
            after_id: None,
        }
    }
}

/// A presented admin credential, recognised by shape on the wire.
///
/// Enforcement is the deployment's: the resolved principal must satisfy
/// [`admin_authorization_request`] under the same [`AuthzApi`](crate::AuthzApi)
/// the rest of the model uses.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AdminCredential {
    /// An `x-api-key: sk-ant-admin...` admin key.
    ApiKey(String),
    /// An `Authorization: Bearer <token>` carrying `org:admin`.
    Bearer(String),
}

impl AdminCredential {
    /// Recognise an admin credential from the `x-api-key` and `Authorization`
    /// header values. `x-api-key` takes precedence, matching Anthropic; a
    /// non-`Bearer` authorization or an `x-api-key` without the admin prefix is
    /// not a recognised admin credential.
    pub fn from_headers(x_api_key: Option<&str>, authorization: Option<&str>) -> Option<Self> {
        if let Some(key) = x_api_key
            && key.starts_with(ADMIN_API_KEY_PREFIX)
        {
            return Some(AdminCredential::ApiKey(key.to_owned()));
        }
        let token = authorization?.strip_prefix("Bearer ")?.trim();
        if token.is_empty() {
            return None;
        }
        Some(AdminCredential::Bearer(token.to_owned()))
    }
}

/// The authorization request the admin caller must pass to use this surface:
/// the `org.admin.manage` action at the target [`ScopeRef::Org`]. This is the
/// `org:admin` posture expressed under the one model (ADR-0008 decision 6).
pub fn admin_authorization_request(principal: PrincipalRef, org: &OrgId) -> AuthorizationRequest {
    AuthorizationRequest::direct(
        principal,
        ActionKey(ORG_ADMIN_ACTION.to_owned()),
        ScopeRef::Org {
            org_id: org.clone(),
        },
    )
}

/// Render a stable, prefixed wire id, leaving an already-prefixed id untouched
/// so the rendering is idempotent.
fn prefixed(prefix: &str, raw: &str) -> String {
    if raw.starts_with(prefix) {
        raw.to_owned()
    } else {
        format!("{prefix}{raw}")
    }
}

/// Strip a wire id prefix to recover the underlying raw id.
fn unprefixed(prefix: &str, id: &str) -> String {
    id.strip_prefix(prefix).unwrap_or(id).to_owned()
}

/// Page a stably-id-ordered list of objects per Anthropic's cursor semantics.
///
/// `items` must already be sorted ascending by the id `id_of` returns. With
/// `after_id` the page is the objects immediately after the cursor; with
/// `before_id` it is the objects immediately before it; with neither it is the
/// first `limit`. A cursor that names no item, or both cursors at once, is an
/// [`AdminApiError::InvalidCursor`].
fn paginate<T, F>(items: Vec<T>, params: &ListParams, id_of: F) -> ApiResult<Page<T>>
where
    F: Fn(&T) -> String,
{
    let limit = params.limit;
    if limit == 0 || limit > MAX_PAGE_LIMIT {
        return Err(AdminApiError::InvalidLimit(limit));
    }
    if params.before_id.is_some() && params.after_id.is_some() {
        return Err(AdminApiError::InvalidCursor(
            "before_id and after_id are mutually exclusive".to_owned(),
        ));
    }

    let ids: Vec<String> = items.iter().map(&id_of).collect();
    let (window, has_more) = if let Some(after) = &params.after_id {
        let pos = ids
            .iter()
            .position(|id| id == after)
            .ok_or_else(|| AdminApiError::InvalidCursor(after.clone()))?;
        let rest: Vec<T> = items.into_iter().skip(pos + 1).collect();
        let has_more = rest.len() > limit;
        (rest.into_iter().take(limit).collect::<Vec<T>>(), has_more)
    } else if let Some(before) = &params.before_id {
        let pos = ids
            .iter()
            .position(|id| id == before)
            .ok_or_else(|| AdminApiError::InvalidCursor(before.clone()))?;
        let head: Vec<T> = items.into_iter().take(pos).collect();
        let has_more = head.len() > limit;
        let skip = head.len().saturating_sub(limit);
        (head.into_iter().skip(skip).collect::<Vec<T>>(), has_more)
    } else {
        let has_more = items.len() > limit;
        (items.into_iter().take(limit).collect::<Vec<T>>(), has_more)
    };

    let first_id = window.first().map(&id_of);
    let last_id = window.last().map(&id_of);
    Ok(Page {
        data: window,
        has_more,
        first_id,
        last_id,
    })
}

/// Project the trusted-issuer registry into a page of federation-issuer
/// envelopes (read rendering of the decision-5 token-exchange model).
pub fn project_federation_issuers(
    issuers: &[TrustedIssuer],
    params: &ListParams,
) -> ApiResult<Page<FederationIssuer>> {
    let mut rendered: Vec<FederationIssuer> =
        issuers.iter().map(render_federation_issuer).collect();
    rendered.sort_by(|a, b| a.id.cmp(&b.id));
    paginate(rendered, params, |issuer| issuer.id.clone())
}

/// Project every issuer's workload bindings into a page of federation-rule
/// envelopes.
pub fn project_federation_rules(
    issuers: &[TrustedIssuer],
    params: &ListParams,
) -> ApiResult<Page<FederationRule>> {
    let mut rendered: Vec<FederationRule> = issuers
        .iter()
        .flat_map(|issuer| {
            issuer
                .bindings
                .iter()
                .map(move |binding| render_federation_rule(&issuer.issuer, binding))
        })
        .collect();
    rendered.sort_by(|a, b| a.id.cmp(&b.id));
    paginate(rendered, params, |rule| rule.id.clone())
}

fn render_federation_issuer(issuer: &TrustedIssuer) -> FederationIssuer {
    FederationIssuer {
        object: ObjectKind::FederationIssuer,
        id: prefixed(FEDERATION_ISSUER_ID_PREFIX, &issuer.issuer),
        issuer: issuer.issuer.clone(),
        audiences: issuer.audiences.clone(),
        enabled: issuer.enabled,
    }
}

fn render_federation_rule(issuer: &str, binding: &WorkloadBinding) -> FederationRule {
    let workspace_role = binding
        .scopes
        .iter()
        .find_map(|scope| WorkspaceRole::from_oauth_scope(scope));
    FederationRule {
        object: ObjectKind::FederationRule,
        id: prefixed(
            FEDERATION_RULE_ID_PREFIX,
            &format!("{issuer}.{}", binding.subject),
        ),
        issuer_id: prefixed(FEDERATION_ISSUER_ID_PREFIX, issuer),
        subject: binding.subject.clone(),
        service_account_id: prefixed(SERVICE_ACCOUNT_ID_PREFIX, &binding.service_id),
        scopes: binding.scopes.clone(),
        workspace_role,
    }
}

/// The Anthropic-compatible Admin API, scoped to one organization.
///
/// It borrows a [`PolicyAdminApi`] and renders org administration over its
/// membership primitives. Every mutation is a [`RoleBinding`] edit at the org or
/// a workspace scope; nothing here is a second authorization engine.
pub struct AnthropicAdminApi<'a, S> {
    pap: &'a mut PolicyAdminApi<S>,
    org: OrgId,
}

impl<'a, S> AnthropicAdminApi<'a, S>
where
    S: OrgRepo
        + GroupRepo
        + RoleRepo
        + GrantRepo
        + RoleBindingRepo
        + ResourceModelRepo
        + AuditSink
        + FenceStore,
{
    /// Bind the surface to `pap`, administering organization `org`.
    pub fn new(pap: &'a mut PolicyAdminApi<S>, org: OrgId) -> Self {
        Self { pap, org }
    }

    fn org_scope(&self) -> ScopeRef {
        ScopeRef::Org {
            org_id: self.org.clone(),
        }
    }

    fn workspace_scope(workspace: &WorkspaceId) -> ScopeRef {
        ScopeRef::Workspace {
            workspace_id: workspace.clone(),
        }
    }

    // -- organization members ----------------------------------------------

    /// Add an organization member by binding their account to an org role.
    pub fn add_member(
        &mut self,
        account: AccountId,
        role: OrgRole,
        at: Timestamp,
    ) -> ApiResult<Member> {
        let binding = RoleBinding {
            principal: PrincipalRef::Account {
                account_id: account.clone(),
            },
            role: role.role_id(),
            scope: self.org_scope(),
        };
        self.pap.grant_membership(binding, at)?;
        Ok(Member {
            object: ObjectKind::User,
            id: account.0,
            role,
        })
    }

    /// Replace a member's org role, failing closed if they hold no org binding.
    pub fn set_member_role(
        &mut self,
        account: &AccountId,
        role: OrgRole,
        at: Timestamp,
    ) -> ApiResult<Member> {
        self.revoke_org_bindings(account, &at)?;
        self.add_member(account.clone(), role, at)
    }

    /// Read a member's org-role envelope.
    pub fn get_member(&self, account: &AccountId) -> ApiResult<Member> {
        let principal = PrincipalRef::Account {
            account_id: account.clone(),
        };
        let scope = self.org_scope();
        for binding in self.pap.memberships_for_principal(&principal)? {
            if binding.scope == scope {
                return Ok(Member {
                    object: ObjectKind::User,
                    id: account.0.clone(),
                    role: OrgRole::from_role_id(&binding.role)?,
                });
            }
        }
        Err(AdminApiError::Admin(AdminError::NotFound(format!(
            "member {}",
            account.0
        ))))
    }

    /// Remove a member, revoking every org-scoped binding they hold.
    pub fn remove_member(&mut self, account: &AccountId, at: Timestamp) -> ApiResult<()> {
        self.revoke_org_bindings(account, &at)
    }

    fn revoke_org_bindings(&mut self, account: &AccountId, at: &Timestamp) -> ApiResult<()> {
        let principal = PrincipalRef::Account {
            account_id: account.clone(),
        };
        let scope = self.org_scope();
        let bindings: Vec<RoleBinding> = self
            .pap
            .memberships_for_principal(&principal)?
            .into_iter()
            .filter(|binding| binding.scope == scope)
            .collect();
        if bindings.is_empty() {
            return Err(AdminApiError::Admin(AdminError::NotFound(format!(
                "member {}",
                account.0
            ))));
        }
        for binding in bindings {
            self.pap.revoke_membership(&binding, at.clone())?;
        }
        Ok(())
    }

    /// List organization members, cursor-paginated by account id.
    pub fn list_members(&self, params: &ListParams) -> ApiResult<Page<Member>> {
        let scope = self.org_scope();
        let mut members: Vec<Member> = self
            .pap
            .list_memberships()?
            .into_iter()
            .filter(|binding| binding.scope == scope)
            .filter_map(|binding| match binding.principal {
                PrincipalRef::Account { account_id } => OrgRole::from_role_id(&binding.role)
                    .ok()
                    .map(|role| Member {
                        object: ObjectKind::User,
                        id: account_id.0,
                        role,
                    }),
                _ => None,
            })
            .collect();
        members.sort_by(|a, b| a.id.cmp(&b.id));
        paginate(members, params, |member| member.id.clone())
    }

    // -- workspace members -------------------------------------------------

    /// Add a workspace member by binding their account to a workspace role.
    pub fn add_workspace_member(
        &mut self,
        workspace: &WorkspaceId,
        account: AccountId,
        role: WorkspaceRole,
        at: Timestamp,
    ) -> ApiResult<WorkspaceMember> {
        let binding = RoleBinding {
            principal: PrincipalRef::Account {
                account_id: account.clone(),
            },
            role: role.role_id(),
            scope: Self::workspace_scope(workspace),
        };
        self.pap.grant_membership(binding, at)?;
        Ok(WorkspaceMember {
            object: ObjectKind::WorkspaceMember,
            workspace_id: prefixed(WORKSPACE_ID_PREFIX, &workspace.0),
            user_id: account.0,
            workspace_role: role,
        })
    }

    /// Read one workspace member's envelope.
    pub fn get_workspace_member(
        &self,
        workspace: &WorkspaceId,
        account: &AccountId,
    ) -> ApiResult<WorkspaceMember> {
        let principal = PrincipalRef::Account {
            account_id: account.clone(),
        };
        let scope = Self::workspace_scope(workspace);
        for binding in self.pap.memberships_for_principal(&principal)? {
            if binding.scope == scope {
                return Ok(WorkspaceMember {
                    object: ObjectKind::WorkspaceMember,
                    workspace_id: prefixed(WORKSPACE_ID_PREFIX, &workspace.0),
                    user_id: account.0.clone(),
                    workspace_role: WorkspaceRole::from_role_id(&binding.role)?,
                });
            }
        }
        Err(AdminApiError::Admin(AdminError::NotFound(format!(
            "workspace member {}",
            account.0
        ))))
    }

    /// Remove a workspace member, revoking their bindings at that workspace.
    pub fn remove_workspace_member(
        &mut self,
        workspace: &WorkspaceId,
        account: &AccountId,
        at: Timestamp,
    ) -> ApiResult<()> {
        let principal = PrincipalRef::Account {
            account_id: account.clone(),
        };
        let scope = Self::workspace_scope(workspace);
        let bindings: Vec<RoleBinding> = self
            .pap
            .memberships_for_principal(&principal)?
            .into_iter()
            .filter(|binding| binding.scope == scope)
            .collect();
        if bindings.is_empty() {
            return Err(AdminApiError::Admin(AdminError::NotFound(format!(
                "workspace member {}",
                account.0
            ))));
        }
        for binding in bindings {
            self.pap.revoke_membership(&binding, at.clone())?;
        }
        Ok(())
    }

    /// List a workspace's members, cursor-paginated by account id.
    pub fn list_workspace_members(
        &self,
        workspace: &WorkspaceId,
        params: &ListParams,
    ) -> ApiResult<Page<WorkspaceMember>> {
        let scope = Self::workspace_scope(workspace);
        let workspace_id = prefixed(WORKSPACE_ID_PREFIX, &workspace.0);
        let mut members: Vec<WorkspaceMember> = self
            .pap
            .list_memberships()?
            .into_iter()
            .filter(|binding| binding.scope == scope)
            .filter_map(|binding| match binding.principal {
                PrincipalRef::Account { account_id } => WorkspaceRole::from_role_id(&binding.role)
                    .ok()
                    .map(|role| WorkspaceMember {
                        object: ObjectKind::WorkspaceMember,
                        workspace_id: workspace_id.clone(),
                        user_id: account_id.0,
                        workspace_role: role,
                    }),
                _ => None,
            })
            .collect();
        members.sort_by(|a, b| a.user_id.cmp(&b.user_id));
        paginate(members, params, |member| member.user_id.clone())
    }

    // -- API keys ----------------------------------------------------------

    /// Bind an API token to a workspace role (the binding side of minting a key,
    /// ADR-0008 decision 4; the credential rendering is sequenced separately).
    pub fn bind_api_key(
        &mut self,
        token_id: &str,
        workspace: &WorkspaceId,
        role: WorkspaceRole,
        at: Timestamp,
    ) -> ApiResult<ApiKey> {
        let binding = RoleBinding {
            principal: PrincipalRef::ApiToken {
                token_id: token_id.to_owned(),
            },
            role: role.role_id(),
            scope: Self::workspace_scope(workspace),
        };
        self.pap.grant_membership(binding, at)?;
        Ok(ApiKey {
            object: ObjectKind::ApiKey,
            id: token_id.to_owned(),
            workspace_id: prefixed(WORKSPACE_ID_PREFIX, &workspace.0),
            workspace_role: role,
        })
    }

    /// Replace the workspace role an API key holds.
    pub fn set_api_key_role(
        &mut self,
        token_id: &str,
        workspace: &WorkspaceId,
        role: WorkspaceRole,
        at: Timestamp,
    ) -> ApiResult<ApiKey> {
        let principal = PrincipalRef::ApiToken {
            token_id: token_id.to_owned(),
        };
        let scope = Self::workspace_scope(workspace);
        let bindings: Vec<RoleBinding> = self
            .pap
            .memberships_for_principal(&principal)?
            .into_iter()
            .filter(|binding| binding.scope == scope)
            .collect();
        if bindings.is_empty() {
            return Err(AdminApiError::Admin(AdminError::NotFound(format!(
                "api key {token_id}"
            ))));
        }
        for binding in bindings {
            self.pap.revoke_membership(&binding, at.clone())?;
        }
        self.bind_api_key(token_id, workspace, role, at)
    }

    /// List API keys (token principals) bound to any workspace, paginated by id.
    pub fn list_api_keys(&self, params: &ListParams) -> ApiResult<Page<ApiKey>> {
        let mut keys: Vec<ApiKey> = self
            .pap
            .list_memberships()?
            .into_iter()
            .filter_map(|binding| match (&binding.principal, &binding.scope) {
                (PrincipalRef::ApiToken { token_id }, ScopeRef::Workspace { workspace_id }) => {
                    WorkspaceRole::from_role_id(&binding.role)
                        .ok()
                        .map(|role| ApiKey {
                            object: ObjectKind::ApiKey,
                            id: token_id.clone(),
                            workspace_id: prefixed(WORKSPACE_ID_PREFIX, &workspace_id.0),
                            workspace_role: role,
                        })
                }
                _ => None,
            })
            .collect();
        keys.sort_by(|a, b| a.id.cmp(&b.id));
        paginate(keys, params, |key| key.id.clone())
    }

    // -- service accounts --------------------------------------------------

    /// Add a service account to a workspace with a workspace role.
    pub fn add_service_account(
        &mut self,
        service_id: &str,
        workspace: &WorkspaceId,
        role: WorkspaceRole,
        at: Timestamp,
    ) -> ApiResult<ServiceAccount> {
        let binding = RoleBinding {
            principal: PrincipalRef::Service {
                service_id: service_id.to_owned(),
            },
            role: role.role_id(),
            scope: Self::workspace_scope(workspace),
        };
        self.pap.grant_membership(binding, at)?;
        Ok(ServiceAccount {
            object: ObjectKind::ServiceAccount,
            id: prefixed(SERVICE_ACCOUNT_ID_PREFIX, service_id),
            workspace_id: prefixed(WORKSPACE_ID_PREFIX, &workspace.0),
            workspace_role: role,
        })
    }

    /// Remove a service account from a workspace.
    pub fn remove_service_account(
        &mut self,
        service_account_id: &str,
        workspace: &WorkspaceId,
        at: Timestamp,
    ) -> ApiResult<()> {
        let service_id = unprefixed(SERVICE_ACCOUNT_ID_PREFIX, service_account_id);
        let principal = PrincipalRef::Service {
            service_id: service_id.clone(),
        };
        let scope = Self::workspace_scope(workspace);
        let bindings: Vec<RoleBinding> = self
            .pap
            .memberships_for_principal(&principal)?
            .into_iter()
            .filter(|binding| binding.scope == scope)
            .collect();
        if bindings.is_empty() {
            return Err(AdminApiError::Admin(AdminError::NotFound(format!(
                "service account {service_id}"
            ))));
        }
        for binding in bindings {
            self.pap.revoke_membership(&binding, at.clone())?;
        }
        Ok(())
    }

    /// List service accounts bound to any workspace, paginated by id.
    pub fn list_service_accounts(&self, params: &ListParams) -> ApiResult<Page<ServiceAccount>> {
        let mut accounts: Vec<ServiceAccount> = self
            .pap
            .list_memberships()?
            .into_iter()
            .filter_map(|binding| match (&binding.principal, &binding.scope) {
                (PrincipalRef::Service { service_id }, ScopeRef::Workspace { workspace_id }) => {
                    WorkspaceRole::from_role_id(&binding.role)
                        .ok()
                        .map(|role| ServiceAccount {
                            object: ObjectKind::ServiceAccount,
                            id: prefixed(SERVICE_ACCOUNT_ID_PREFIX, service_id),
                            workspace_id: prefixed(WORKSPACE_ID_PREFIX, &workspace_id.0),
                            workspace_role: role,
                        })
                }
                _ => None,
            })
            .collect();
        accounts.sort_by(|a, b| a.id.cmp(&b.id));
        paginate(accounts, params, |account| account.id.clone())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::InMemoryStore;
    use awaken_iam_core::seed_named_roles;

    fn at() -> Timestamp {
        Timestamp("2026-06-23T00:00:00Z".to_owned())
    }

    fn org() -> OrgId {
        OrgId("acme".to_owned())
    }

    fn workspace() -> WorkspaceId {
        WorkspaceId("default".to_owned())
    }

    fn pap() -> PolicyAdminApi<InMemoryStore> {
        let store = InMemoryStore::new();
        seed_named_roles(&store, &at()).expect("seed catalog");
        PolicyAdminApi::new(store)
    }

    #[test]
    fn org_role_round_trips_through_its_catalog_id() {
        for role in [
            OrgRole::Admin,
            OrgRole::Developer,
            OrgRole::Billing,
            OrgRole::User,
            OrgRole::ClaudeCodeUser,
        ] {
            assert_eq!(OrgRole::from_role_id(&role.role_id()).unwrap(), role);
        }
        assert!(matches!(
            OrgRole::from_role_id(&RoleId("workspace_admin".to_owned())),
            Err(AdminApiError::UnknownRole(_))
        ));
    }

    #[test]
    fn workspace_role_maps_from_an_oauth_scope() {
        assert_eq!(
            WorkspaceRole::from_oauth_scope("workspace:developer"),
            Some(WorkspaceRole::WorkspaceDeveloper)
        );
        assert_eq!(
            WorkspaceRole::from_oauth_scope("workspace:admin"),
            Some(WorkspaceRole::WorkspaceAdmin)
        );
        assert_eq!(WorkspaceRole::from_oauth_scope("billing:read"), None);
    }

    #[test]
    fn envelopes_render_the_anthropic_type_tag() {
        let member = Member {
            object: ObjectKind::User,
            id: "acct_1".to_owned(),
            role: OrgRole::Admin,
        };
        let value = serde_json::to_value(&member).unwrap();
        assert_eq!(value["type"], "user");
        assert_eq!(value["role"], "admin");
        assert_eq!(value["id"], "acct_1");
    }

    #[test]
    fn admin_credential_prefers_the_admin_api_key() {
        let cred =
            AdminCredential::from_headers(Some("sk-ant-admin-abc"), Some("Bearer something"));
        assert_eq!(
            cred,
            Some(AdminCredential::ApiKey("sk-ant-admin-abc".to_owned()))
        );
        // A non-admin x-api-key falls through to the bearer token.
        let cred = AdminCredential::from_headers(Some("sk-ant-user"), Some("Bearer tok"));
        assert_eq!(cred, Some(AdminCredential::Bearer("tok".to_owned())));
        // Nothing recognised.
        assert_eq!(AdminCredential::from_headers(None, Some("Basic x")), None);
        assert_eq!(AdminCredential::from_headers(None, None), None);
    }

    #[test]
    fn admin_authorization_request_targets_org_admin_at_the_org_scope() {
        let principal = PrincipalRef::Account {
            account_id: AccountId("root".to_owned()),
        };
        let request = admin_authorization_request(principal, &org());
        assert_eq!(request.action, ActionKey(ORG_ADMIN_ACTION.to_owned()));
        assert_eq!(request.scope, ScopeRef::Org { org_id: org() });
    }

    #[test]
    fn add_member_persists_a_binding_and_renders_the_envelope() {
        let mut pap = pap();
        let mut api = AnthropicAdminApi::new(&mut pap, org());
        let member = api
            .add_member(AccountId("alice".to_owned()), OrgRole::Developer, at())
            .unwrap();
        assert_eq!(member.object, ObjectKind::User);
        assert_eq!(member.id, "alice");
        assert_eq!(member.role, OrgRole::Developer);

        let read = api.get_member(&AccountId("alice".to_owned())).unwrap();
        assert_eq!(read.role, OrgRole::Developer);
    }

    #[test]
    fn set_member_role_replaces_the_org_binding() {
        let mut pap = pap();
        let mut api = AnthropicAdminApi::new(&mut pap, org());
        api.add_member(AccountId("bob".to_owned()), OrgRole::User, at())
            .unwrap();
        api.set_member_role(&AccountId("bob".to_owned()), OrgRole::Admin, at())
            .unwrap();

        let page = api.list_members(&ListParams::default()).unwrap();
        let bob: Vec<&Member> = page.data.iter().filter(|m| m.id == "bob").collect();
        assert_eq!(bob.len(), 1, "role replaced, not duplicated");
        assert_eq!(bob[0].role, OrgRole::Admin);
    }

    #[test]
    fn remove_member_fails_closed_when_absent() {
        let mut pap = pap();
        let mut api = AnthropicAdminApi::new(&mut pap, org());
        let err = api
            .remove_member(&AccountId("ghost".to_owned()), at())
            .unwrap_err();
        assert!(matches!(err, AdminApiError::Admin(AdminError::NotFound(_))));
    }

    #[test]
    fn workspace_member_binding_round_trips_with_the_wrkspc_prefix() {
        let mut pap = pap();
        let mut api = AnthropicAdminApi::new(&mut pap, org());
        let member = api
            .add_workspace_member(
                &workspace(),
                AccountId("carol".to_owned()),
                WorkspaceRole::WorkspaceDeveloper,
                at(),
            )
            .unwrap();
        assert_eq!(member.workspace_id, "wrkspc_default");
        assert_eq!(member.workspace_role, WorkspaceRole::WorkspaceDeveloper);

        let read = api
            .get_workspace_member(&workspace(), &AccountId("carol".to_owned()))
            .unwrap();
        assert_eq!(read.user_id, "carol");
        api.remove_workspace_member(&workspace(), &AccountId("carol".to_owned()), at())
            .unwrap();
        assert!(matches!(
            api.get_workspace_member(&workspace(), &AccountId("carol".to_owned())),
            Err(AdminApiError::Admin(AdminError::NotFound(_)))
        ));
    }

    #[test]
    fn api_key_and_service_account_bindings_render_prefixed_ids() {
        let mut pap = pap();
        let mut api = AnthropicAdminApi::new(&mut pap, org());

        let key = api
            .bind_api_key("tok_1", &workspace(), WorkspaceRole::WorkspaceUser, at())
            .unwrap();
        assert_eq!(key.object, ObjectKind::ApiKey);
        assert_eq!(key.workspace_id, "wrkspc_default");

        let svc = api
            .add_service_account("ci", &workspace(), WorkspaceRole::WorkspaceDeveloper, at())
            .unwrap();
        assert_eq!(svc.id, "svac_ci");

        let keys = api.list_api_keys(&ListParams::default()).unwrap();
        assert_eq!(keys.data.len(), 1);
        assert_eq!(keys.data[0].id, "tok_1");

        let accounts = api.list_service_accounts(&ListParams::default()).unwrap();
        assert_eq!(accounts.data.len(), 1);
        assert_eq!(accounts.data[0].id, "svac_ci");

        api.remove_service_account("svac_ci", &workspace(), at())
            .unwrap();
        assert!(
            api.list_service_accounts(&ListParams::default())
                .unwrap()
                .data
                .is_empty()
        );
    }

    #[test]
    fn list_members_paginates_forward_and_reports_cursors() {
        let mut pap = pap();
        let mut api = AnthropicAdminApi::new(&mut pap, org());
        for name in ["a", "b", "c", "d", "e"] {
            api.add_member(AccountId(name.to_owned()), OrgRole::User, at())
                .unwrap();
        }

        let first = api
            .list_members(&ListParams {
                limit: 2,
                before_id: None,
                after_id: None,
            })
            .unwrap();
        assert_eq!(
            first.data.iter().map(|m| m.id.as_str()).collect::<Vec<_>>(),
            ["a", "b"]
        );
        assert!(first.has_more);
        assert_eq!(first.first_id.as_deref(), Some("a"));
        assert_eq!(first.last_id.as_deref(), Some("b"));

        let next = api
            .list_members(&ListParams {
                limit: 2,
                before_id: None,
                after_id: Some("b".to_owned()),
            })
            .unwrap();
        assert_eq!(
            next.data.iter().map(|m| m.id.as_str()).collect::<Vec<_>>(),
            ["c", "d"]
        );
        assert!(next.has_more);
    }

    #[test]
    fn list_members_paginates_backward_with_before_id() {
        let mut pap = pap();
        let mut api = AnthropicAdminApi::new(&mut pap, org());
        for name in ["a", "b", "c", "d", "e"] {
            api.add_member(AccountId(name.to_owned()), OrgRole::User, at())
                .unwrap();
        }
        let page = api
            .list_members(&ListParams {
                limit: 2,
                before_id: Some("e".to_owned()),
                after_id: None,
            })
            .unwrap();
        assert_eq!(
            page.data.iter().map(|m| m.id.as_str()).collect::<Vec<_>>(),
            ["c", "d"]
        );
        assert!(page.has_more);
    }

    #[test]
    fn pagination_rejects_a_bad_limit_and_unknown_cursor() {
        let mut pap = pap();
        let mut api = AnthropicAdminApi::new(&mut pap, org());
        api.add_member(AccountId("a".to_owned()), OrgRole::User, at())
            .unwrap();

        assert!(matches!(
            api.list_members(&ListParams {
                limit: 0,
                before_id: None,
                after_id: None,
            }),
            Err(AdminApiError::InvalidLimit(0))
        ));
        assert!(matches!(
            api.list_members(&ListParams {
                limit: MAX_PAGE_LIMIT + 1,
                before_id: None,
                after_id: None,
            }),
            Err(AdminApiError::InvalidLimit(_))
        ));
        assert!(matches!(
            api.list_members(&ListParams {
                limit: 10,
                before_id: None,
                after_id: Some("missing".to_owned()),
            }),
            Err(AdminApiError::InvalidCursor(_))
        ));
        assert!(matches!(
            api.list_members(&ListParams {
                limit: 10,
                before_id: Some("a".to_owned()),
                after_id: Some("a".to_owned()),
            }),
            Err(AdminApiError::InvalidCursor(_))
        ));
    }

    #[test]
    fn federation_issuers_and_rules_project_with_prefixes() {
        use awaken_iam_contract::Jwks;

        let issuer = TrustedIssuer {
            issuer: "https://idp.example".to_owned(),
            audiences: vec!["iam".to_owned()],
            keys: Jwks { keys: Vec::new() },
            bindings: vec![WorkloadBinding {
                subject: "spiffe://ci".to_owned(),
                service_id: "ci".to_owned(),
                audience: "iam".to_owned(),
                scopes: vec!["workspace:developer".to_owned()],
            }],
            enabled: true,
        };

        let issuers =
            project_federation_issuers(std::slice::from_ref(&issuer), &ListParams::default())
                .unwrap();
        assert_eq!(issuers.data.len(), 1);
        assert_eq!(issuers.data[0].object, ObjectKind::FederationIssuer);
        assert!(issuers.data[0].id.starts_with(FEDERATION_ISSUER_ID_PREFIX));

        let rules = project_federation_rules(&[issuer], &ListParams::default()).unwrap();
        assert_eq!(rules.data.len(), 1);
        assert_eq!(rules.data[0].object, ObjectKind::FederationRule);
        assert!(rules.data[0].id.starts_with(FEDERATION_RULE_ID_PREFIX));
        assert_eq!(rules.data[0].service_account_id, "svac_ci");
        assert_eq!(
            rules.data[0].workspace_role,
            Some(WorkspaceRole::WorkspaceDeveloper)
        );
    }
}
