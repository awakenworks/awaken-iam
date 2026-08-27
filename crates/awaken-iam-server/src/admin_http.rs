//! Axum binding of the standalone daemon's `/v1` surface, including the
//! policy-administration seam.
//!
//! [`http`](crate::http) binds the read-only authorization half of `/v1` over a
//! shared [`Arc<AuthzApi>`](crate::AuthzApi) for an embedded host. The standalone
//! daemon additionally serves the `/v1/admin/*` routes a remote control plane
//! (cloud-console) administers the authorization model through — the console
//! <-> remote-daemon management seam the [`assembly`](crate::assembly) manifest
//! ([`ADMIN_ROUTES`](crate::assembly)) declares but that nothing bound until now.
//!
//! Those routes mutate (`&mut self` on [`PolicyAdminApi`]), so the daemon serves
//! the whole surface over one shared mutable [`DaemonState`] behind a
//! [`Mutex`](std::sync::Mutex) — the single-applier seam — rather than the
//! read-only `Arc` the embedded path uses. Each admin mutation advances the same
//! authorization snapshot version `GET /v1/authz/snapshot` reports (see
//! [`AuthzApi::bump_policy_version`]), so a synced consumer re-fetches after a
//! policy-administration change just as it does after a grant edit.
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
//! | `PUT /v1/admin/memberships/scoped` | [`PolicyAdminApi::replace_scoped_memberships`] |
//!
//! Every admin route is guarded: a caller must present a recognised admin
//! credential ([`AdminCredential`]) the daemon's [`AdminAuthPolicy`] accepts, or
//! the request is rejected `401`/`403` before any state is touched. An embedded
//! host never mounts this router — it administers the model in-process — so the
//! seam is exposed over HTTP only by the standalone daemon.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use awaken_iam_contract::{
    AcceptInvitation, AcceptedInvitation, ActivateAuthorizationProfile, AdminMutationAck,
    AuthorizationOutcome, AuthorizationRequest, BatchAuthorizationRequest,
    BatchAuthorizationResponse, CreateAuthorizationProfile, CreateDirectoryNode, CreateInvitation,
    DirectoryChildrenQuery, DirectoryNodeId, DirectoryRevisionQuery, EnsureProductSpacePlacement,
    EntitlementCheckResponse, EntitlementRequest, GrantSnapshot, GrantSubjectRef, GroupView,
    InvitationId, InvitationQuery, IssuedInvitation, MembershipQuery, MoveDirectoryNode,
    NamespaceId, OrgId, OrgView, PolicySnapshot, ProductId, ProductSpacePlacementQuery,
    ReplaceScopedMemberships, ResendInvitation, RetireAuthorizationProfile, RoleBindingSnapshot,
    RoleView, ScopeMembershipQuery, Timestamp, UpdateDirectoryNode, WorkspaceOrgEdge,
};
use awaken_iam_core::{
    ActionPattern, AuthorizationProfileRepository, Effect, Grant, GrantId, GrantSubject, Group,
    GroupId, Organization, PolicySet, RoleBinding, RoleDef, RoleId,
};
use axum::{
    Json, Router,
    extract::{Path, Query, State},
    http::{HeaderMap, StatusCode},
    response::{IntoResponse, Response},
    routing::{delete, get, post, put},
};
use serde::Deserialize;
use sha2::{Digest, Sha256};

use crate::{
    AccessTokenAuthority, AdminCredential, AdminError, AuthorizationProfileAdmin, CapabilityCheck,
    LeaseEpoch, MintCapability, PolicyAdminApi, PolicyStore, ProfileAdminError, mint_capability,
    verify_capability,
};
use awaken_iam_contract::GrantEffect;

/// Who may administer policy over the wire.
///
/// AuthN/AuthZ for the admin seam: a presented [`AdminCredential`] is accepted
/// only when its token is in this allow-list. An empty policy fails closed —
/// every admin call is rejected — so a daemon started without an admin secret
/// never silently exposes an unauthenticated control plane.
#[derive(Debug, Clone, Default)]
pub struct AdminAuthPolicy {
    accepted: HashMap<String, DirectoryCredentialAccess>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum DirectoryCredentialAccess {
    Administrator,
    Product(ProductId),
}

impl AdminAuthPolicy {
    /// Accept exactly the given credential tokens (the `x-api-key` admin key or
    /// `Authorization: Bearer` value). No token means deny-all.
    pub fn new(tokens: impl IntoIterator<Item = String>) -> Self {
        Self {
            accepted: tokens
                .into_iter()
                .filter(|token| !token.is_empty())
                .map(|token| (token, DirectoryCredentialAccess::Administrator))
                .collect(),
        }
    }

    /// Add one credential that may ensure and query only its own product spaces.
    pub fn with_product_token(mut self, product_id: ProductId, token: impl Into<String>) -> Self {
        let token = token.into();
        if !token.is_empty() {
            self.accepted
                .insert(token, DirectoryCredentialAccess::Product(product_id));
        }
        self
    }

    /// A policy that rejects every admin caller (the secure default before an
    /// admin secret is configured).
    pub fn deny_all() -> Self {
        Self::default()
    }

    fn access(&self, credential: &AdminCredential) -> Option<&DirectoryCredentialAccess> {
        let token = match credential {
            AdminCredential::ApiKey(token) | AdminCredential::Bearer(token) => token,
        };
        self.accepted.get(token)
    }

    /// Whether `credential` carries unrestricted administration authority.
    #[cfg(test)]
    fn accepts(&self, credential: &AdminCredential) -> bool {
        self.access(credential) == Some(&DirectoryCredentialAccess::Administrator)
    }
}

/// The daemon's shared, mutable `/v1` state: the read engines plus the
/// policy-administration point over one store, behind a single applier lock.
pub struct DaemonState<S> {
    authz: crate::AuthzApi,
    admin: PolicyAdminApi<S>,
    directory: crate::DirectoryApi<S>,
    profiles: AuthorizationProfileAdmin,
    capability_tokens: AccessTokenAuthority,
    auth: AdminAuthPolicy,
}

impl<S> std::fmt::Debug for DaemonState<S> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DaemonState").finish_non_exhaustive()
    }
}

impl<S: PolicyStore + awaken_iam_core::DirectoryRepository + Clone> DaemonState<S> {
    /// Assemble the daemon over one explicit policy store.
    ///
    /// Production and tests pass one migrated SQL store for policy, profiles,
    /// and Directory state. The PAP, restart hydration, and live PDP therefore
    /// consume one source of truth; Directory has no parallel memory repository.
    pub fn with_policy_store(
        mut authz: crate::AuthzApi,
        auth: AdminAuthPolicy,
        profiles: Arc<dyn AuthorizationProfileRepository>,
        store: S,
        capability_tokens: AccessTokenAuthority,
    ) -> Result<Self, AdminError> {
        let directory = crate::DirectoryApi::new(store.clone());
        let admin = PolicyAdminApi::new(store);
        let version = admin.store_version()?;
        let base = admin.policy()?;
        let base = base.snapshot(version);
        let profiles = AuthorizationProfileAdmin::new(profiles);
        profiles
            .hydrate_all(&mut authz, &base)
            .map_err(|error| AdminError::Backend(error.to_string()))?;
        Ok(Self {
            authz,
            admin,
            directory,
            profiles,
            capability_tokens,
            auth,
        })
    }
}

impl<S: PolicyStore> DaemonState<S> {
    /// Refresh the live PDP from the same repositories the PAP just committed.
    fn refresh_authorization(&mut self, version: u64) -> Result<(), AdminError> {
        let base = self.admin.policy()?;
        let base_snapshot = base.snapshot(version);
        let active_profiles = self.authz.snapshot().active_profiles;
        let policy = PolicySet::from_snapshot_and_profiles(&base_snapshot, &active_profiles);
        self.authz.replace_policy_at_version(policy, version);
        Ok(())
    }
}

/// Shared handle to the daemon's `/v1` state every request is dispatched to.
pub type SharedDaemonState<S> = Arc<Mutex<DaemonState<S>>>;

/// Build the [`axum::Router`] the standalone daemon serves: the authorization
/// half of `/v1`, the operational `GET /healthz` probe, and the guarded
/// `/v1/admin/*` policy-administration seam — all over one shared
/// [`DaemonState`].
pub fn daemon_router<S>(state: SharedDaemonState<S>) -> Router
where
    S: PolicyStore + awaken_iam_core::DirectoryRepository + Clone + 'static,
{
    Router::new()
        .route("/healthz", get(healthz))
        .route("/v1/authorize", post(authorize))
        .route("/v1/authorize/batch", post(authorize_batch))
        .route("/v1/entitlements/check", post(check_entitlement))
        .route("/v1/authz/snapshot", get(snapshot))
        .route("/v1/capabilities/introspect", post(introspect_capability))
        .route("/v1/admin/orgs", post(create_org).get(list_orgs))
        .route("/v1/admin/orgs/{id}", put(update_org).delete(delete_org))
        .route(
            "/v1/admin/directory/nodes",
            post(create_directory_node).get(list_directory_children),
        )
        .route(
            "/v1/admin/directory/nodes/{id}",
            get(get_directory_node)
                .put(move_directory_node)
                .patch(update_directory_node)
                .delete(archive_directory_node),
        )
        .route(
            "/v1/admin/directory/product-spaces/query",
            post(get_product_space_placement),
        )
        .route("/v1/admin/directory/revision", get(get_directory_revision))
        .route(
            "/v1/admin/directory/product-spaces/ensure",
            post(ensure_product_space_placement),
        )
        .route(
            "/v1/admin/directory/nodes/{id}/restore",
            post(restore_directory_node),
        )
        .route("/v1/admin/groups", post(create_group))
        .route(
            "/v1/admin/groups/{id}",
            put(update_group).delete(delete_group),
        )
        .route("/v1/admin/roles", post(define_role))
        .route("/v1/admin/roles/{id}", put(update_role).delete(delete_role))
        .route("/v1/admin/grants", post(issue_grant))
        .route("/v1/admin/grants/{id}", delete(revoke_grant))
        .route("/v1/admin/capabilities", post(issue_capability))
        .route(
            "/v1/admin/memberships",
            post(grant_membership).delete(revoke_membership),
        )
        .route(
            "/v1/admin/memberships/scoped",
            put(replace_scoped_memberships),
        )
        .route("/v1/admin/memberships/query", post(query_memberships))
        .route(
            "/v1/admin/memberships/query-scope",
            post(query_scope_memberships),
        )
        .route("/v1/admin/invitations", post(create_invitation))
        .route("/v1/admin/invitations/query", post(list_invitations))
        .route("/v1/admin/invitations/{id}", delete(revoke_invitation))
        .route("/v1/admin/invitations/{id}/resend", post(resend_invitation))
        .route("/v1/admin/invitations/{id}/accept", post(accept_invitation))
        .route("/v1/admin/scope/workspace-orgs", post(assign_workspace_org))
        .route("/v1/admin/authz/profiles", post(create_profile))
        .route("/v1/admin/authz/profiles/{namespace}", get(list_profiles))
        .route(
            "/v1/admin/authz/profiles/{namespace}/active",
            get(active_profile),
        )
        .route(
            "/v1/admin/authz/profiles/{namespace}/retire",
            post(retire_profile),
        )
        .route(
            "/v1/admin/authz/profiles/{namespace}/{revision}",
            get(get_profile),
        )
        .route(
            "/v1/admin/authz/profiles/{namespace}/{revision}/validate",
            post(validate_profile),
        )
        .route(
            "/v1/admin/authz/profiles/{namespace}/{revision}/activate",
            post(activate_profile),
        )
        .route(
            "/v1/admin/authz/profiles/{namespace}/{revision}/rollback",
            post(rollback_profile),
        )
        .with_state(state)
}

#[derive(Debug, Deserialize)]
struct CapabilityMintBody {
    issuer: String,
    subject: String,
    audience: String,
    token_id: String,
    issued_at: i64,
    expires_at: i64,
    scopes: Vec<String>,
}

#[derive(Debug, Deserialize)]
struct CapabilityIntrospectionBody {
    token: String,
    audience: String,
}

/// Mint one root capability under the daemon's existing signing authority.
/// The admin guard is the issuance authority; product-specific grants remain
/// ordinary PAP records and are deliberately not duplicated in this token.
async fn issue_capability(
    State(state): State<SharedDaemonState<impl PolicyStore>>,
    headers: HeaderMap,
    Json(request): Json<CapabilityMintBody>,
) -> Response {
    let authority = {
        let guard = lock(&state);
        if let Some(rejection) = authorize_admin(&guard.auth, &headers) {
            return rejection;
        }
        guard.capability_tokens.clone()
    };
    if [
        &request.issuer,
        &request.subject,
        &request.audience,
        &request.token_id,
    ]
    .into_iter()
    .any(|value| value.trim().is_empty())
        || request.scopes.is_empty()
        || request.scopes.iter().any(|scope| scope.trim().is_empty())
    {
        return error_response(
            StatusCode::UNPROCESSABLE_ENTITY,
            "invalid_capability",
            "issuer, subject, audience, token_id, and non-empty scopes are required",
        );
    }
    let mint = MintCapability {
        iss: request.issuer,
        sub: request.subject,
        aud: request.audience,
        jti: request.token_id,
        iat: request.issued_at,
        exp: request.expires_at,
        epoch: LeaseEpoch::initial(),
        scope: request.scopes,
        obligation: None,
    };
    match mint_capability(&authority, mint).await {
        Ok(token) => (
            StatusCode::CREATED,
            Json(serde_json::json!({ "token": token })),
        )
            .into_response(),
        Err(error) => error_response(
            StatusCode::UNPROCESSABLE_ENTITY,
            "invalid_capability",
            &error.to_string(),
        ),
    }
}

/// Verify the bearer itself against the shared JWKS, fixed public-link epoch,
/// audience, and current time. Authorization remains a separate `/v1/authorize`
/// decision over the returned subject, action, and exact product resource.
async fn introspect_capability(
    State(state): State<SharedDaemonState<impl PolicyStore>>,
    Json(request): Json<CapabilityIntrospectionBody>,
) -> Response {
    let jwks = lock(&state).capability_tokens.jwks();
    match verify_capability(
        &request.token,
        &jwks,
        CapabilityCheck {
            audience: &request.audience,
            epoch: LeaseEpoch::initial(),
            now: unix_seconds(),
        },
    ) {
        Ok(claims) => Json(claims).into_response(),
        Err(_) => StatusCode::UNAUTHORIZED.into_response(),
    }
}

fn unix_seconds() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |duration| duration.as_secs() as i64)
}

async fn create_profile(
    State(state): State<SharedDaemonState<impl PolicyStore>>,
    headers: HeaderMap,
    Json(request): Json<CreateAuthorizationProfile>,
) -> Response {
    let guard = lock(&state);
    if let Some(rejection) = authorize_admin(&guard.auth, &headers) {
        return rejection;
    }
    profile_result(guard.profiles.create_draft(request))
}

async fn list_profiles(
    State(state): State<SharedDaemonState<impl PolicyStore>>,
    headers: HeaderMap,
    Path(namespace): Path<String>,
) -> Response {
    let guard = lock(&state);
    if let Some(rejection) = authorize_admin(&guard.auth, &headers) {
        return rejection;
    }
    profile_result(guard.profiles.list(&NamespaceId(namespace)))
}

async fn active_profile(
    State(state): State<SharedDaemonState<impl PolicyStore>>,
    headers: HeaderMap,
    Path(namespace): Path<String>,
) -> Response {
    let guard = lock(&state);
    if let Some(rejection) = authorize_admin(&guard.auth, &headers) {
        return rejection;
    }
    match guard.profiles.active(&NamespaceId(namespace)) {
        Ok(Some(profile)) => Json(profile).into_response(),
        Ok(None) => StatusCode::NOT_FOUND.into_response(),
        Err(error) => profile_error_response(&error),
    }
}

async fn get_profile(
    State(state): State<SharedDaemonState<impl PolicyStore>>,
    headers: HeaderMap,
    Path((namespace, revision)): Path<(String, u64)>,
) -> Response {
    let guard = lock(&state);
    if let Some(rejection) = authorize_admin(&guard.auth, &headers) {
        return rejection;
    }
    match guard.profiles.get(&NamespaceId(namespace), revision) {
        Ok(Some(profile)) => Json(profile).into_response(),
        Ok(None) => StatusCode::NOT_FOUND.into_response(),
        Err(error) => profile_error_response(&error),
    }
}

async fn validate_profile(
    State(state): State<SharedDaemonState<impl PolicyStore>>,
    headers: HeaderMap,
    Path((namespace, revision)): Path<(String, u64)>,
) -> Response {
    let guard = lock(&state);
    if let Some(rejection) = authorize_admin(&guard.auth, &headers) {
        return rejection;
    }
    profile_result(guard.profiles.validate(&NamespaceId(namespace), revision))
}

async fn activate_profile(
    State(state): State<SharedDaemonState<impl PolicyStore>>,
    headers: HeaderMap,
    Path((namespace, revision)): Path<(String, u64)>,
    Json(request): Json<ActivateAuthorizationProfile>,
) -> Response {
    let mut guard = lock(&state);
    if let Some(rejection) = authorize_admin(&guard.auth, &headers) {
        return rejection;
    }
    let profiles = guard.profiles.clone();
    let base = match guard.admin.policy().and_then(|policy| {
        guard
            .admin
            .store_version()
            .map(|version| policy.snapshot(version))
    }) {
        Ok(base) => base,
        Err(error) => return admin_error_response(&error),
    };
    profile_result(profiles.activate(
        &mut guard.authz,
        &base,
        &NamespaceId(namespace),
        revision,
        request,
    ))
}

async fn rollback_profile(
    State(state): State<SharedDaemonState<impl PolicyStore>>,
    headers: HeaderMap,
    Path((namespace, revision)): Path<(String, u64)>,
    Json(request): Json<ActivateAuthorizationProfile>,
) -> Response {
    let Some(expected) = request.expected_active_revision else {
        return error_response(
            StatusCode::UNPROCESSABLE_ENTITY,
            "expected_revision_required",
            "rollback requires expected_active_revision",
        );
    };
    let mut guard = lock(&state);
    if let Some(rejection) = authorize_admin(&guard.auth, &headers) {
        return rejection;
    }
    let profiles = guard.profiles.clone();
    let base = match guard.admin.policy().and_then(|policy| {
        guard
            .admin
            .store_version()
            .map(|version| policy.snapshot(version))
    }) {
        Ok(base) => base,
        Err(error) => return admin_error_response(&error),
    };
    profile_result(profiles.rollback(
        &mut guard.authz,
        &base,
        &NamespaceId(namespace),
        revision,
        expected,
    ))
}

async fn retire_profile(
    State(state): State<SharedDaemonState<impl PolicyStore>>,
    headers: HeaderMap,
    Path(namespace): Path<String>,
    Json(request): Json<RetireAuthorizationProfile>,
) -> Response {
    let mut guard = lock(&state);
    if let Some(rejection) = authorize_admin(&guard.auth, &headers) {
        return rejection;
    }
    let profiles = guard.profiles.clone();
    let base = match guard.admin.policy().and_then(|policy| {
        guard
            .admin
            .store_version()
            .map(|version| policy.snapshot(version))
    }) {
        Ok(base) => base,
        Err(error) => return admin_error_response(&error),
    };
    profile_result(profiles.retire(
        &mut guard.authz,
        &base,
        &NamespaceId(namespace),
        request.expected_active_revision,
    ))
}

// -- authorization half of /v1 (shared state, read-only per request) ----------

async fn healthz() -> Json<serde_json::Value> {
    Json(serde_json::json!({ "status": "ok" }))
}

async fn authorize(
    State(state): State<SharedDaemonState<impl PolicyStore>>,
    Json(request): Json<AuthorizationRequest>,
) -> Json<AuthorizationOutcome> {
    let guard = lock(&state);
    Json(guard.authz.authorize(&request))
}

async fn authorize_batch(
    State(state): State<SharedDaemonState<impl PolicyStore>>,
    Json(request): Json<BatchAuthorizationRequest>,
) -> Json<BatchAuthorizationResponse> {
    let guard = lock(&state);
    Json(guard.authz.authorize_batch(&request))
}

async fn check_entitlement(
    State(state): State<SharedDaemonState<impl PolicyStore>>,
    Json(request): Json<EntitlementRequest>,
) -> Json<EntitlementCheckResponse> {
    let guard = lock(&state);
    Json(guard.authz.check_entitlement(&request))
}

/// Query string for `GET /v1/authz/snapshot?since={version}`.
#[derive(Debug, Default, Deserialize)]
struct SnapshotQuery {
    since: Option<u64>,
}

async fn snapshot(
    State(state): State<SharedDaemonState<impl PolicyStore>>,
    Query(query): Query<SnapshotQuery>,
) -> Response {
    let guard = lock(&state);
    match query.since {
        Some(since) => match guard.authz.snapshot_since(since) {
            Some(snapshot) => Json(snapshot).into_response(),
            None => StatusCode::NOT_MODIFIED.into_response(),
        },
        None => Json::<PolicySnapshot>(guard.authz.snapshot()).into_response(),
    }
}

// -- policy-administration seam (shared state, mutating) ----------------------

async fn create_org(
    State(state): State<SharedDaemonState<impl PolicyStore>>,
    headers: HeaderMap,
    Json(dto): Json<OrgView>,
) -> Response {
    apply(&state, &headers, move |admin, at| {
        admin.create_org(org_from_dto(dto), at)
    })
}

async fn update_org(
    State(state): State<SharedDaemonState<impl PolicyStore>>,
    headers: HeaderMap,
    Path(id): Path<String>,
    Json(mut dto): Json<OrgView>,
) -> Response {
    dto.id = OrgId(id);
    apply(&state, &headers, move |admin, at| {
        admin.update_org(org_from_dto(dto), at)
    })
}

async fn delete_org(
    State(state): State<SharedDaemonState<impl PolicyStore>>,
    headers: HeaderMap,
    Path(id): Path<String>,
) -> Response {
    apply(&state, &headers, move |admin, at| {
        admin.delete_org(&OrgId(id), at)
    })
}

async fn list_orgs(
    State(state): State<SharedDaemonState<impl PolicyStore>>,
    headers: HeaderMap,
) -> Response {
    read(&state, &headers, |admin| {
        admin
            .list_orgs()
            .map(|orgs| orgs.into_iter().map(org_to_dto).collect::<Vec<_>>())
    })
}

async fn create_directory_node(
    State(state): State<SharedDaemonState<impl PolicyStore + awaken_iam_core::DirectoryRepository>>,
    headers: HeaderMap,
    Json(request): Json<CreateDirectoryNode>,
) -> Response {
    directory_command(&state, &headers, move |directory, context| {
        directory.create_node(request, context)
    })
}

async fn ensure_product_space_placement(
    State(state): State<SharedDaemonState<impl PolicyStore + awaken_iam_core::DirectoryRepository>>,
    headers: HeaderMap,
    Json(request): Json<EnsureProductSpacePlacement>,
) -> Response {
    let product_id = request.product_space.product_id.clone();
    product_directory_command(&state, &headers, &product_id, move |directory, context| {
        directory.ensure_product_space_placement(request, context)
    })
}

async fn get_directory_node(
    State(state): State<SharedDaemonState<impl PolicyStore + awaken_iam_core::DirectoryRepository>>,
    headers: HeaderMap,
    Path(id): Path<String>,
) -> Response {
    let guard = lock(&state);
    if let Some(rejection) = authorize_admin(&guard.auth, &headers) {
        return rejection;
    }
    match guard.directory.node(&DirectoryNodeId(id)) {
        Ok(Some(node)) => Json(node).into_response(),
        Ok(None) => StatusCode::NOT_FOUND.into_response(),
        Err(error) => admin_error_response(&error),
    }
}

async fn list_directory_children(
    State(state): State<SharedDaemonState<impl PolicyStore + awaken_iam_core::DirectoryRepository>>,
    headers: HeaderMap,
    Query(query): Query<DirectoryChildrenQuery>,
) -> Response {
    directory_read(&state, &headers, move |directory| {
        directory.children(&query.org_id, query.parent_id.as_ref())
    })
}

async fn move_directory_node(
    State(state): State<SharedDaemonState<impl PolicyStore + awaken_iam_core::DirectoryRepository>>,
    headers: HeaderMap,
    Path(id): Path<String>,
    Json(request): Json<MoveDirectoryNode>,
) -> Response {
    directory_command(&state, &headers, move |directory, context| {
        directory.move_node(&DirectoryNodeId(id), request, context)
    })
}

async fn update_directory_node(
    State(state): State<SharedDaemonState<impl PolicyStore + awaken_iam_core::DirectoryRepository>>,
    headers: HeaderMap,
    Path(id): Path<String>,
    Json(request): Json<UpdateDirectoryNode>,
) -> Response {
    directory_command(&state, &headers, move |directory, context| {
        directory.update_node(&DirectoryNodeId(id), request, context)
    })
}

async fn archive_directory_node(
    State(state): State<SharedDaemonState<impl PolicyStore + awaken_iam_core::DirectoryRepository>>,
    headers: HeaderMap,
    Path(id): Path<String>,
) -> Response {
    directory_command(&state, &headers, move |directory, context| {
        directory.archive_node(&DirectoryNodeId(id), context)
    })
}

async fn restore_directory_node(
    State(state): State<SharedDaemonState<impl PolicyStore + awaken_iam_core::DirectoryRepository>>,
    headers: HeaderMap,
    Path(id): Path<String>,
) -> Response {
    directory_command(&state, &headers, move |directory, context| {
        directory.restore_node(&DirectoryNodeId(id), context)
    })
}

async fn get_product_space_placement(
    State(state): State<SharedDaemonState<impl PolicyStore + awaken_iam_core::DirectoryRepository>>,
    headers: HeaderMap,
    Json(query): Json<ProductSpacePlacementQuery>,
) -> Response {
    let guard = lock(&state);
    let access = match directory_credential_access(&guard.auth, &headers) {
        Ok(access) => access,
        Err(rejection) => return rejection.into_response(),
    };
    if let DirectoryCredentialAccess::Product(product_id) = &access
        && product_id != &query.product_space.product_id
    {
        return error_response(
            StatusCode::FORBIDDEN,
            "forbidden_product",
            "the presented credential may access only its own product spaces",
        );
    }
    match guard
        .directory
        .product_space_placement(&query.org_id, &query.product_space)
    {
        Ok(Some(placement)) => Json(placement).into_response(),
        Ok(None) => StatusCode::NOT_FOUND.into_response(),
        Err(error) => admin_error_response(&error),
    }
}

async fn get_directory_revision(
    State(state): State<SharedDaemonState<impl PolicyStore + awaken_iam_core::DirectoryRepository>>,
    headers: HeaderMap,
    Query(query): Query<DirectoryRevisionQuery>,
) -> Response {
    directory_read(&state, &headers, move |directory| {
        directory.revision(&query.org_id)
    })
}

async fn create_group(
    State(state): State<SharedDaemonState<impl PolicyStore>>,
    headers: HeaderMap,
    Json(dto): Json<GroupView>,
) -> Response {
    apply(&state, &headers, move |admin, at| {
        admin.create_group(group_from_dto(dto), at)
    })
}

async fn update_group(
    State(state): State<SharedDaemonState<impl PolicyStore>>,
    headers: HeaderMap,
    Path(id): Path<String>,
    Json(mut dto): Json<GroupView>,
) -> Response {
    dto.id = id;
    apply(&state, &headers, move |admin, at| {
        admin.update_group(group_from_dto(dto), at)
    })
}

async fn delete_group(
    State(state): State<SharedDaemonState<impl PolicyStore>>,
    headers: HeaderMap,
    Path(id): Path<String>,
) -> Response {
    apply(&state, &headers, move |admin, at| {
        admin.delete_group(&GroupId(id), at)
    })
}

async fn define_role(
    State(state): State<SharedDaemonState<impl PolicyStore>>,
    headers: HeaderMap,
    Json(dto): Json<RoleView>,
) -> Response {
    apply(&state, &headers, move |admin, at| {
        admin.define_role(role_from_dto(dto), at)
    })
}

async fn update_role(
    State(state): State<SharedDaemonState<impl PolicyStore>>,
    headers: HeaderMap,
    Path(id): Path<String>,
    Json(mut dto): Json<RoleView>,
) -> Response {
    dto.id = id;
    apply(&state, &headers, move |admin, at| {
        admin.update_role(role_from_dto(dto), at)
    })
}

async fn delete_role(
    State(state): State<SharedDaemonState<impl PolicyStore>>,
    headers: HeaderMap,
    Path(id): Path<String>,
) -> Response {
    apply(&state, &headers, move |admin, at| {
        admin.delete_role(&RoleId(id), at)
    })
}

async fn issue_grant(
    State(state): State<SharedDaemonState<impl PolicyStore>>,
    headers: HeaderMap,
    Json(dto): Json<GrantSnapshot>,
) -> Response {
    apply(&state, &headers, move |admin, at| {
        admin.issue_grant(grant_from_dto(dto), at)
    })
}

async fn revoke_grant(
    State(state): State<SharedDaemonState<impl PolicyStore>>,
    headers: HeaderMap,
    Path(id): Path<String>,
) -> Response {
    apply(&state, &headers, move |admin, at| {
        admin.revoke_grant(&GrantId(id), at)
    })
}

async fn grant_membership(
    State(state): State<SharedDaemonState<impl PolicyStore>>,
    headers: HeaderMap,
    Json(dto): Json<RoleBindingSnapshot>,
) -> Response {
    apply(&state, &headers, move |admin, at| {
        admin.grant_membership(role_binding_from_dto(dto), at)
    })
}

async fn revoke_membership(
    State(state): State<SharedDaemonState<impl PolicyStore>>,
    headers: HeaderMap,
    Json(dto): Json<RoleBindingSnapshot>,
) -> Response {
    apply(&state, &headers, move |admin, at| {
        admin.revoke_membership(&role_binding_from_dto(dto), at)
    })
}

async fn replace_scoped_memberships(
    State(state): State<SharedDaemonState<impl PolicyStore>>,
    headers: HeaderMap,
    Json(request): Json<ReplaceScopedMemberships>,
) -> Response {
    apply(&state, &headers, move |admin, at| {
        admin.replace_scoped_memberships(
            request.principal,
            request.scope,
            request.managed_role_ids.into_iter().map(RoleId).collect(),
            request
                .replacement_role_ids
                .into_iter()
                .map(RoleId)
                .collect(),
            at,
        )
    })
}

async fn query_memberships(
    State(state): State<SharedDaemonState<impl PolicyStore>>,
    headers: HeaderMap,
    Json(query): Json<MembershipQuery>,
) -> Response {
    read(&state, &headers, |admin| {
        admin
            .memberships_for_principal(&query.principal)
            .map(|bindings| {
                bindings
                    .into_iter()
                    .map(role_binding_to_dto)
                    .collect::<Vec<_>>()
            })
    })
}

async fn query_scope_memberships(
    State(state): State<SharedDaemonState<impl PolicyStore>>,
    headers: HeaderMap,
    Json(query): Json<ScopeMembershipQuery>,
) -> Response {
    read(&state, &headers, |admin| {
        admin.memberships_for_scope(&query.scope).map(|bindings| {
            bindings
                .into_iter()
                .map(role_binding_to_dto)
                .collect::<Vec<_>>()
        })
    })
}

async fn create_invitation(
    State(state): State<SharedDaemonState<impl PolicyStore>>,
    headers: HeaderMap,
    Json(request): Json<CreateInvitation>,
) -> Response {
    apply_value(
        &state,
        &headers,
        move |admin, at| admin.create_invitation(request, at),
        |value| value.version,
    )
}

async fn list_invitations(
    State(state): State<SharedDaemonState<impl PolicyStore>>,
    headers: HeaderMap,
    Json(query): Json<InvitationQuery>,
) -> Response {
    read(&state, &headers, |admin| {
        admin.list_invitations(&query.org_id)
    })
}

async fn revoke_invitation(
    State(state): State<SharedDaemonState<impl PolicyStore>>,
    headers: HeaderMap,
    Path(id): Path<String>,
) -> Response {
    apply(&state, &headers, move |admin, at| {
        admin.revoke_invitation(&InvitationId(id), at)
    })
}

async fn resend_invitation(
    State(state): State<SharedDaemonState<impl PolicyStore>>,
    headers: HeaderMap,
    Path(id): Path<String>,
    Json(request): Json<ResendInvitation>,
) -> Response {
    apply_value(
        &state,
        &headers,
        move |admin, at| admin.resend_invitation(&InvitationId(id), request.expires_at, at),
        |value: &IssuedInvitation| value.version,
    )
}

async fn accept_invitation(
    State(state): State<SharedDaemonState<impl PolicyStore>>,
    headers: HeaderMap,
    Path(id): Path<String>,
    Json(request): Json<AcceptInvitation>,
) -> Response {
    apply_value(
        &state,
        &headers,
        move |admin, at| admin.accept_invitation(&InvitationId(id), request, at),
        |value: &AcceptedInvitation| value.version,
    )
}

async fn assign_workspace_org(
    State(state): State<SharedDaemonState<impl PolicyStore>>,
    headers: HeaderMap,
    Json(edge): Json<WorkspaceOrgEdge>,
) -> Response {
    apply(&state, &headers, move |admin, at| {
        admin.assign_workspace_org(edge, at)
    })
}

// -- shared dispatch helpers --------------------------------------------------

fn lock<S>(state: &SharedDaemonState<S>) -> std::sync::MutexGuard<'_, DaemonState<S>> {
    // A poisoned lock means a prior handler panicked mid-mutation; recover the
    // guard rather than cascade-panicking every later request.
    state.lock().unwrap_or_else(|poison| poison.into_inner())
}

/// Run one guarded admin mutation: enforce the credential, apply it, then bump
/// the shared authorization snapshot version so the change fences a consumer's
/// next poll. The version returned to the caller is that same fence.
fn apply<S, F>(state: &SharedDaemonState<S>, headers: &HeaderMap, op: F) -> Response
where
    S: PolicyStore,
    F: FnOnce(&mut PolicyAdminApi<S>, Timestamp) -> Result<u64, AdminError>,
{
    let mut guard = lock(state);
    if let Some(rejection) = authorize_admin(&guard.auth, headers) {
        return rejection;
    }
    match op(&mut guard.admin, now_timestamp()) {
        Ok(version) => match guard.refresh_authorization(version) {
            Ok(()) => (StatusCode::OK, Json(AdminMutationAck { version })).into_response(),
            Err(error) => admin_error_response(&error),
        },
        Err(error) => admin_error_response(&error),
    }
}

fn apply_value<S, T, F, V>(
    state: &SharedDaemonState<S>,
    headers: &HeaderMap,
    op: F,
    version: V,
) -> Response
where
    S: PolicyStore,
    T: serde::Serialize,
    F: FnOnce(&mut PolicyAdminApi<S>, Timestamp) -> Result<T, AdminError>,
    V: FnOnce(&T) -> u64,
{
    let mut guard = lock(state);
    if let Some(rejection) = authorize_admin(&guard.auth, headers) {
        return rejection;
    }
    match op(&mut guard.admin, now_timestamp()) {
        Ok(value) => match guard.refresh_authorization(version(&value)) {
            Ok(()) => (StatusCode::OK, Json(value)).into_response(),
            Err(error) => admin_error_response(&error),
        },
        Err(error) => admin_error_response(&error),
    }
}

/// Run one guarded admin read.
fn read<S, T, F>(state: &SharedDaemonState<S>, headers: &HeaderMap, op: F) -> Response
where
    S: PolicyStore,
    T: serde::Serialize,
    F: FnOnce(&PolicyAdminApi<S>) -> Result<T, AdminError>,
{
    let guard = lock(state);
    if let Some(rejection) = authorize_admin(&guard.auth, headers) {
        return rejection;
    }
    match op(&guard.admin) {
        Ok(value) => (StatusCode::OK, Json(value)).into_response(),
        Err(error) => admin_error_response(&error),
    }
}

fn directory_read<S, T, F>(state: &SharedDaemonState<S>, headers: &HeaderMap, op: F) -> Response
where
    S: awaken_iam_core::DirectoryRepository,
    T: serde::Serialize,
    F: FnOnce(&crate::DirectoryApi<S>) -> Result<T, AdminError>,
{
    let guard = lock(state);
    if let Some(rejection) = authorize_admin(&guard.auth, headers) {
        return rejection;
    }
    match op(&guard.directory) {
        Ok(value) => (StatusCode::OK, Json(value)).into_response(),
        Err(error) => admin_error_response(&error),
    }
}

fn directory_command<S, T, F>(state: &SharedDaemonState<S>, headers: &HeaderMap, op: F) -> Response
where
    S: awaken_iam_core::DirectoryRepository,
    T: serde::Serialize,
    F: FnOnce(&crate::DirectoryApi<S>, crate::DirectoryCommandContext) -> Result<T, AdminError>,
{
    let guard = lock(state);
    if let Some(rejection) = authorize_admin(&guard.auth, headers) {
        return rejection;
    }
    let context = crate::DirectoryCommandContext::new(admin_actor(headers), now_timestamp());
    match op(&guard.directory, context) {
        Ok(value) => (StatusCode::OK, Json(value)).into_response(),
        Err(error) => admin_error_response(&error),
    }
}

fn product_directory_command<S, T, F>(
    state: &SharedDaemonState<S>,
    headers: &HeaderMap,
    requested_product_id: &ProductId,
    op: F,
) -> Response
where
    S: awaken_iam_core::DirectoryRepository,
    T: serde::Serialize,
    F: FnOnce(&crate::DirectoryApi<S>, crate::DirectoryCommandContext) -> Result<T, AdminError>,
{
    let guard = lock(state);
    let access = match directory_credential_access(&guard.auth, headers) {
        Ok(access) => access,
        Err(rejection) => return rejection.into_response(),
    };
    if let DirectoryCredentialAccess::Product(product_id) = &access
        && product_id != requested_product_id
    {
        return error_response(
            StatusCode::FORBIDDEN,
            "forbidden_product",
            "the presented credential may access only its own product spaces",
        );
    }
    let actor = admin_actor(headers);
    let context = match access {
        DirectoryCredentialAccess::Administrator => {
            crate::DirectoryCommandContext::new(actor, now_timestamp())
        }
        DirectoryCredentialAccess::Product(product_id) => {
            crate::DirectoryCommandContext::product_service(
                product_id,
                actor_id(actor),
                now_timestamp(),
            )
        }
    };
    match op(&guard.directory, context) {
        Ok(value) => (StatusCode::OK, Json(value)).into_response(),
        Err(error) => admin_error_response(&error),
    }
}

fn actor_id(actor: awaken_iam_contract::PrincipalRef) -> String {
    match actor {
        awaken_iam_contract::PrincipalRef::Service { service_id } => service_id,
        _ => unreachable!("admin_actor always creates a service principal"),
    }
}

fn admin_actor(headers: &HeaderMap) -> awaken_iam_contract::PrincipalRef {
    let header = |name: &str| headers.get(name).and_then(|value| value.to_str().ok());
    let credential = AdminCredential::from_headers(header("x-api-key"), header("authorization"))
        .expect("directory command is authenticated before actor derivation");
    let token = match credential {
        AdminCredential::ApiKey(token) | AdminCredential::Bearer(token) => token,
    };
    let digest = Sha256::digest(token.as_bytes());
    let fingerprint = digest[..12]
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect::<String>();
    awaken_iam_contract::PrincipalRef::Service {
        service_id: format!("iam-admin:{fingerprint}"),
    }
}

/// Enforce the admin guard, returning `Some(rejection)` when the caller may not
/// administer policy: a missing credential is `401`, an unaccepted one `403`,
/// decided before any state is read or written. `None` means the call proceeds.
fn authorize_admin(auth: &AdminAuthPolicy, headers: &HeaderMap) -> Option<Response> {
    match directory_credential_access(auth, headers) {
        Ok(DirectoryCredentialAccess::Administrator) => None,
        Ok(DirectoryCredentialAccess::Product(_)) => Some(error_response(
            StatusCode::FORBIDDEN,
            "forbidden",
            "the presented product credential may not administer IAM",
        )),
        Err(rejection) => Some(rejection.into_response()),
    }
}

#[derive(Debug, Clone, Copy)]
enum DirectoryCredentialRejection {
    Missing,
    Forbidden,
}

impl DirectoryCredentialRejection {
    fn into_response(self) -> Response {
        match self {
            Self::Missing => error_response(
                StatusCode::UNAUTHORIZED,
                "missing_admin_credential",
                "an admin credential is required to administer policy",
            ),
            Self::Forbidden => error_response(
                StatusCode::FORBIDDEN,
                "forbidden",
                "the presented credential may not administer policy",
            ),
        }
    }
}

fn directory_credential_access(
    auth: &AdminAuthPolicy,
    headers: &HeaderMap,
) -> Result<DirectoryCredentialAccess, DirectoryCredentialRejection> {
    let header = |name: &str| headers.get(name).and_then(|value| value.to_str().ok());
    let Some(credential) =
        AdminCredential::from_headers(header("x-api-key"), header("authorization"))
    else {
        return Err(DirectoryCredentialRejection::Missing);
    };
    auth.access(&credential)
        .cloned()
        .ok_or(DirectoryCredentialRejection::Forbidden)
}

/// Map an [`AdminError`] onto its HTTP status and a stable error body.
fn admin_error_response(error: &AdminError) -> Response {
    let (status, code) = match error {
        AdminError::AlreadyExists(_) => (StatusCode::CONFLICT, "already_exists"),
        AdminError::NotFound(_) => (StatusCode::NOT_FOUND, "not_found"),
        AdminError::Invalid(_) => (StatusCode::UNPROCESSABLE_ENTITY, "invalid"),
        AdminError::Backend(_) => (StatusCode::INTERNAL_SERVER_ERROR, "backend_error"),
    };
    error_response(status, code, &error.to_string())
}

fn profile_result<T: serde::Serialize>(result: Result<T, ProfileAdminError>) -> Response {
    match result {
        Ok(value) => (StatusCode::OK, Json(value)).into_response(),
        Err(error) => profile_error_response(&error),
    }
}

fn profile_error_response(error: &ProfileAdminError) -> Response {
    let (status, code) = match error {
        ProfileAdminError::NotFound => (StatusCode::NOT_FOUND, "not_found"),
        ProfileAdminError::Conflict(_) => (StatusCode::CONFLICT, "profile_conflict"),
        ProfileAdminError::Validation(_) => (StatusCode::UNPROCESSABLE_ENTITY, "profile_invalid"),
        ProfileAdminError::Repository(_) => (StatusCode::INTERNAL_SERVER_ERROR, "backend_error"),
    };
    error_response(status, code, &error.to_string())
}

fn error_response(status: StatusCode, code: &str, message: &str) -> Response {
    (
        status,
        Json(serde_json::json!({ "error": code, "message": message })),
    )
        .into_response()
}

// -- Wire contract <-> core aggregate conversions -----------------------------

fn org_from_dto(dto: OrgView) -> Organization {
    Organization {
        id: dto.id,
        display_name: dto.display_name,
        owner: dto.owner,
        created_at: dto.created_at,
        updated_at: dto.updated_at,
    }
}

fn org_to_dto(org: Organization) -> OrgView {
    OrgView {
        id: org.id,
        display_name: org.display_name,
        owner: org.owner,
        created_at: org.created_at,
        updated_at: org.updated_at,
    }
}

fn group_from_dto(dto: GroupView) -> Group {
    Group {
        id: GroupId(dto.id),
        org: dto.org,
        display_name: dto.display_name,
        members: dto.members,
        created_at: dto.created_at,
        updated_at: dto.updated_at,
    }
}

fn role_from_dto(dto: RoleView) -> RoleDef {
    RoleDef {
        id: RoleId(dto.id),
        display_name: dto.display_name,
        action_patterns: dto.action_patterns.into_iter().map(ActionPattern).collect(),
        created_at: dto.created_at,
        updated_at: dto.updated_at,
    }
}

fn grant_from_dto(dto: GrantSnapshot) -> Grant {
    Grant {
        id: GrantId(dto.id),
        subject: match dto.subject {
            GrantSubjectRef::Principal { principal } => GrantSubject::Principal(principal),
            GrantSubjectRef::Role { role_id } => GrantSubject::Role(RoleId(role_id)),
            GrantSubjectRef::Group { group_id } => GrantSubject::Group(GroupId(group_id)),
        },
        action_pattern: ActionPattern(dto.action_pattern),
        scope: dto.scope,
        effect: match dto.effect {
            GrantEffect::Allow => Effect::Allow,
            GrantEffect::RequireApproval => Effect::RequireApproval,
            GrantEffect::Deny => Effect::Deny,
        },
    }
}

fn role_binding_from_dto(dto: RoleBindingSnapshot) -> RoleBinding {
    RoleBinding {
        principal: dto.principal,
        role: RoleId(dto.role_id),
        scope: dto.scope,
    }
}

fn role_binding_to_dto(binding: RoleBinding) -> RoleBindingSnapshot {
    RoleBindingSnapshot {
        principal: binding.principal,
        role_id: binding.role.0,
        scope: binding.scope,
    }
}

/// The wall-clock instant the daemon stamps an audit record with, as an RFC 3339
/// UTC string (the [`Timestamp`] convention). The store records but never parses
/// it, so it is the application time rather than a resource's own timestamp.
fn now_timestamp() -> Timestamp {
    crate::clock::now_timestamp()
}

#[cfg(test)]
mod tests {
    use super::*;
    use awaken_iam_contract::{AccountId, PrincipalRef, ScopeRef};

    fn account(id: &str) -> PrincipalRef {
        PrincipalRef::Account {
            account_id: AccountId(id.into()),
        }
    }

    fn ts() -> Timestamp {
        Timestamp("2026-06-21T00:00:00Z".into())
    }

    #[test]
    fn auth_policy_accepts_only_configured_tokens_and_denies_by_default() {
        let policy = AdminAuthPolicy::new(["sk-ant-admin-secret".to_owned()]);
        assert!(policy.accepts(&AdminCredential::ApiKey("sk-ant-admin-secret".into())));
        assert!(policy.accepts(&AdminCredential::Bearer("sk-ant-admin-secret".into())));
        assert!(!policy.accepts(&AdminCredential::Bearer("other".into())));
        // Deny-all rejects every credential.
        assert!(!AdminAuthPolicy::deny_all().accepts(&AdminCredential::ApiKey("any".into())));
        // An empty token never grants access.
        assert!(
            !AdminAuthPolicy::new([String::new()]).accepts(&AdminCredential::Bearer("".into()))
        );
    }

    #[test]
    fn org_dto_round_trips_through_the_core_aggregate() {
        let dto = OrgView {
            id: OrgId("acme".into()),
            display_name: Some("ACME".into()),
            owner: account("ada"),
            created_at: ts(),
            updated_at: ts(),
        };
        assert_eq!(org_to_dto(org_from_dto(dto.clone())), dto);
    }

    #[test]
    fn grant_dto_maps_subject_and_effect_onto_the_core_grant() {
        let grant = grant_from_dto(GrantSnapshot {
            id: "g1".into(),
            subject: GrantSubjectRef::Role {
                role_id: "publisher".into(),
            },
            action_pattern: "pack.*".into(),
            scope: ScopeRef::Global,
            effect: GrantEffect::RequireApproval,
        });
        assert_eq!(grant.id, GrantId("g1".into()));
        assert_eq!(
            grant.subject,
            GrantSubject::Role(RoleId("publisher".into()))
        );
        assert_eq!(grant.action_pattern, ActionPattern("pack.*".into()));
        assert_eq!(grant.effect, Effect::RequireApproval);
    }

    #[test]
    fn membership_dto_maps_onto_the_core_binding() {
        let binding = role_binding_from_dto(RoleBindingSnapshot {
            principal: account("ada"),
            role_id: "publisher".into(),
            scope: ScopeRef::Org {
                org_id: OrgId("acme".into()),
            },
        });
        assert_eq!(binding.role, RoleId("publisher".into()));
        assert_eq!(binding.principal, account("ada"));
    }

    #[test]
    fn rfc3339_formats_a_known_instant() {
        // 1_700_000_000 seconds after the epoch is 2023-11-14T22:13:20Z.
        assert_eq!(
            crate::clock::timestamp(1_700_000_000).0,
            "2023-11-14T22:13:20Z"
        );
        // The epoch itself.
        assert_eq!(crate::clock::timestamp(0).0, "1970-01-01T00:00:00Z");
    }
}
