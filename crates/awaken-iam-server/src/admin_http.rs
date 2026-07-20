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
//!
//! Every admin route is guarded: a caller must present a recognised admin
//! credential ([`AdminCredential`]) the daemon's [`AdminAuthPolicy`] accepts, or
//! the request is rejected `401`/`403` before any state is touched. An embedded
//! host never mounts this router — it administers the model in-process — so the
//! seam is exposed over HTTP only by the standalone daemon.

use std::collections::HashSet;
use std::sync::{Arc, Mutex};

use awaken_iam_contract::{
    ActivateAuthorizationProfile, AdminMutationAck, AuthorizationOutcome, AuthorizationRequest,
    BatchAuthorizationRequest, BatchAuthorizationResponse, CreateAuthorizationProfile,
    EntitlementCheckResponse, EntitlementRequest, GrantSnapshot, GrantSubjectRef, GroupDto,
    NamespaceId, OrgDto, OrgId, PolicySnapshot, RoleBindingSnapshot, RoleDto, Timestamp,
};
use awaken_iam_core::{
    ActionPattern, AuthorizationProfileRepo, Effect, Grant, GrantId, GrantSubject, Group, GroupId,
    Organization, RoleBinding, RoleDef, RoleId,
};
use axum::{
    Json, Router,
    extract::{Path, Query, State},
    http::{HeaderMap, StatusCode},
    response::{IntoResponse, Response},
    routing::{delete, get, post, put},
};
use serde::Deserialize;

use crate::{
    AdminCredential, AdminError, AuthorizationProfileAdmin, InMemoryStore, PolicyAdminApi,
    ProfileAdminError,
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
    accepted: HashSet<String>,
}

impl AdminAuthPolicy {
    /// Accept exactly the given credential tokens (the `x-api-key` admin key or
    /// `Authorization: Bearer` value). No token means deny-all.
    pub fn new(tokens: impl IntoIterator<Item = String>) -> Self {
        Self {
            accepted: tokens.into_iter().filter(|t| !t.is_empty()).collect(),
        }
    }

    /// A policy that rejects every admin caller (the secure default before an
    /// admin secret is configured).
    pub fn deny_all() -> Self {
        Self::default()
    }

    /// Whether `credential` is permitted to administer policy.
    fn accepts(&self, credential: &AdminCredential) -> bool {
        let token = match credential {
            AdminCredential::ApiKey(token) | AdminCredential::Bearer(token) => token,
        };
        self.accepted.contains(token)
    }
}

/// The daemon's shared, mutable `/v1` state: the read engines plus the
/// policy-administration point over one store, behind a single applier lock.
#[derive(Debug)]
pub struct DaemonState {
    authz: crate::AuthzApi,
    admin: PolicyAdminApi<InMemoryStore>,
    profiles: AuthorizationProfileAdmin,
    auth: AdminAuthPolicy,
}

impl DaemonState {
    /// Assemble the daemon state over the daemon's authorization engine, a fresh
    /// policy-administration store, and the admin auth policy.
    pub fn new(authz: crate::AuthzApi, auth: AdminAuthPolicy) -> Self {
        Self::with_profile_repository(authz, auth, Arc::new(InMemoryStore::new()))
    }

    /// Assemble the daemon with an explicit durable profile repository.
    pub fn with_profile_repository(
        authz: crate::AuthzApi,
        auth: AdminAuthPolicy,
        profiles: Arc<dyn AuthorizationProfileRepo>,
    ) -> Self {
        Self {
            authz,
            admin: PolicyAdminApi::new(InMemoryStore::new()),
            profiles: AuthorizationProfileAdmin::new(profiles),
            auth,
        }
    }
}

/// Shared handle to the daemon's `/v1` state every request is dispatched to.
pub type SharedDaemonState = Arc<Mutex<DaemonState>>;

/// Build the [`axum::Router`] the standalone daemon serves: the authorization
/// half of `/v1`, the operational `GET /healthz` probe, and the guarded
/// `/v1/admin/*` policy-administration seam — all over one shared
/// [`DaemonState`].
pub fn daemon_router(state: SharedDaemonState) -> Router {
    Router::new()
        .route("/healthz", get(healthz))
        .route("/v1/authorize", post(authorize))
        .route("/v1/authorize/batch", post(authorize_batch))
        .route("/v1/entitlements/check", post(check_entitlement))
        .route("/v1/authz/snapshot", get(snapshot))
        .route("/v1/admin/orgs", post(create_org).get(list_orgs))
        .route("/v1/admin/orgs/{id}", put(update_org).delete(delete_org))
        .route("/v1/admin/groups", post(create_group))
        .route(
            "/v1/admin/groups/{id}",
            put(update_group).delete(delete_group),
        )
        .route("/v1/admin/roles", post(define_role))
        .route("/v1/admin/roles/{id}", put(update_role).delete(delete_role))
        .route("/v1/admin/grants", post(issue_grant))
        .route("/v1/admin/grants/{id}", delete(revoke_grant))
        .route(
            "/v1/admin/memberships",
            post(grant_membership).delete(revoke_membership),
        )
        .route("/v1/admin/authz/profiles", post(create_profile))
        .route("/v1/admin/authz/profiles/{namespace}", get(list_profiles))
        .route(
            "/v1/admin/authz/profiles/{namespace}/active",
            get(active_profile),
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

async fn create_profile(
    State(state): State<SharedDaemonState>,
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
    State(state): State<SharedDaemonState>,
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
    State(state): State<SharedDaemonState>,
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
    State(state): State<SharedDaemonState>,
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
    State(state): State<SharedDaemonState>,
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
    State(state): State<SharedDaemonState>,
    headers: HeaderMap,
    Path((namespace, revision)): Path<(String, u64)>,
    Json(request): Json<ActivateAuthorizationProfile>,
) -> Response {
    let mut guard = lock(&state);
    if let Some(rejection) = authorize_admin(&guard.auth, &headers) {
        return rejection;
    }
    let profiles = guard.profiles.clone();
    profile_result(profiles.activate(&mut guard.authz, &NamespaceId(namespace), revision, request))
}

async fn rollback_profile(
    State(state): State<SharedDaemonState>,
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
    profile_result(profiles.rollback(
        &mut guard.authz,
        &NamespaceId(namespace),
        revision,
        expected,
    ))
}

// -- authorization half of /v1 (shared state, read-only per request) ----------

async fn healthz() -> Json<serde_json::Value> {
    Json(serde_json::json!({ "status": "ok" }))
}

async fn authorize(
    State(state): State<SharedDaemonState>,
    Json(request): Json<AuthorizationRequest>,
) -> Json<AuthorizationOutcome> {
    let guard = lock(&state);
    Json(guard.authz.authorize(&request))
}

async fn authorize_batch(
    State(state): State<SharedDaemonState>,
    Json(request): Json<BatchAuthorizationRequest>,
) -> Json<BatchAuthorizationResponse> {
    let guard = lock(&state);
    Json(guard.authz.authorize_batch(&request))
}

async fn check_entitlement(
    State(state): State<SharedDaemonState>,
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
    State(state): State<SharedDaemonState>,
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
    State(state): State<SharedDaemonState>,
    headers: HeaderMap,
    Json(dto): Json<OrgDto>,
) -> Response {
    apply(&state, &headers, move |admin, at| {
        admin.create_org(org_from_dto(dto), at)
    })
}

async fn update_org(
    State(state): State<SharedDaemonState>,
    headers: HeaderMap,
    Path(id): Path<String>,
    Json(mut dto): Json<OrgDto>,
) -> Response {
    dto.id = OrgId(id);
    apply(&state, &headers, move |admin, at| {
        admin.update_org(org_from_dto(dto), at)
    })
}

async fn delete_org(
    State(state): State<SharedDaemonState>,
    headers: HeaderMap,
    Path(id): Path<String>,
) -> Response {
    apply(&state, &headers, move |admin, at| {
        admin.delete_org(&OrgId(id), at)
    })
}

async fn list_orgs(State(state): State<SharedDaemonState>, headers: HeaderMap) -> Response {
    read(&state, &headers, |admin| {
        admin
            .list_orgs()
            .map(|orgs| orgs.into_iter().map(org_to_dto).collect::<Vec<_>>())
    })
}

async fn create_group(
    State(state): State<SharedDaemonState>,
    headers: HeaderMap,
    Json(dto): Json<GroupDto>,
) -> Response {
    apply(&state, &headers, move |admin, at| {
        admin.create_group(group_from_dto(dto), at)
    })
}

async fn update_group(
    State(state): State<SharedDaemonState>,
    headers: HeaderMap,
    Path(id): Path<String>,
    Json(mut dto): Json<GroupDto>,
) -> Response {
    dto.id = id;
    apply(&state, &headers, move |admin, at| {
        admin.update_group(group_from_dto(dto), at)
    })
}

async fn delete_group(
    State(state): State<SharedDaemonState>,
    headers: HeaderMap,
    Path(id): Path<String>,
) -> Response {
    apply(&state, &headers, move |admin, at| {
        admin.delete_group(&GroupId(id), at)
    })
}

async fn define_role(
    State(state): State<SharedDaemonState>,
    headers: HeaderMap,
    Json(dto): Json<RoleDto>,
) -> Response {
    apply(&state, &headers, move |admin, at| {
        admin.define_role(role_from_dto(dto), at)
    })
}

async fn update_role(
    State(state): State<SharedDaemonState>,
    headers: HeaderMap,
    Path(id): Path<String>,
    Json(mut dto): Json<RoleDto>,
) -> Response {
    dto.id = id;
    apply(&state, &headers, move |admin, at| {
        admin.update_role(role_from_dto(dto), at)
    })
}

async fn delete_role(
    State(state): State<SharedDaemonState>,
    headers: HeaderMap,
    Path(id): Path<String>,
) -> Response {
    apply(&state, &headers, move |admin, at| {
        admin.delete_role(&RoleId(id), at)
    })
}

async fn issue_grant(
    State(state): State<SharedDaemonState>,
    headers: HeaderMap,
    Json(dto): Json<GrantSnapshot>,
) -> Response {
    apply(&state, &headers, move |admin, at| {
        admin.issue_grant(grant_from_dto(dto), at)
    })
}

async fn revoke_grant(
    State(state): State<SharedDaemonState>,
    headers: HeaderMap,
    Path(id): Path<String>,
) -> Response {
    apply(&state, &headers, move |admin, at| {
        admin.revoke_grant(&GrantId(id), at)
    })
}

async fn grant_membership(
    State(state): State<SharedDaemonState>,
    headers: HeaderMap,
    Json(dto): Json<RoleBindingSnapshot>,
) -> Response {
    apply(&state, &headers, move |admin, at| {
        admin.grant_membership(role_binding_from_dto(dto), at)
    })
}

async fn revoke_membership(
    State(state): State<SharedDaemonState>,
    headers: HeaderMap,
    Json(dto): Json<RoleBindingSnapshot>,
) -> Response {
    apply(&state, &headers, move |admin, at| {
        admin.revoke_membership(&role_binding_from_dto(dto), at)
    })
}

// -- shared dispatch helpers --------------------------------------------------

fn lock(state: &SharedDaemonState) -> std::sync::MutexGuard<'_, DaemonState> {
    // A poisoned lock means a prior handler panicked mid-mutation; recover the
    // guard rather than cascade-panicking every later request.
    state.lock().unwrap_or_else(|poison| poison.into_inner())
}

/// Run one guarded admin mutation: enforce the credential, apply it, then bump
/// the shared authorization snapshot version so the change fences a consumer's
/// next poll. The version returned to the caller is that same fence.
fn apply<F>(state: &SharedDaemonState, headers: &HeaderMap, op: F) -> Response
where
    F: FnOnce(&mut PolicyAdminApi<InMemoryStore>, Timestamp) -> Result<u64, AdminError>,
{
    let mut guard = lock(state);
    if let Some(rejection) = authorize_admin(&guard.auth, headers) {
        return rejection;
    }
    match op(&mut guard.admin, now_timestamp()) {
        Ok(_) => {
            let version = guard.authz.bump_policy_version();
            (StatusCode::OK, Json(AdminMutationAck { version })).into_response()
        }
        Err(error) => admin_error_response(&error),
    }
}

/// Run one guarded admin read.
fn read<T, F>(state: &SharedDaemonState, headers: &HeaderMap, op: F) -> Response
where
    T: serde::Serialize,
    F: FnOnce(&PolicyAdminApi<InMemoryStore>) -> Result<T, AdminError>,
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

/// Enforce the admin guard, returning `Some(rejection)` when the caller may not
/// administer policy: a missing credential is `401`, an unaccepted one `403`,
/// decided before any state is read or written. `None` means the call proceeds.
fn authorize_admin(auth: &AdminAuthPolicy, headers: &HeaderMap) -> Option<Response> {
    let header = |name: &str| headers.get(name).and_then(|value| value.to_str().ok());
    let Some(credential) =
        AdminCredential::from_headers(header("x-api-key"), header("authorization"))
    else {
        return Some(error_response(
            StatusCode::UNAUTHORIZED,
            "missing_admin_credential",
            "an admin credential is required to administer policy",
        ));
    };
    if auth.accepts(&credential) {
        None
    } else {
        Some(error_response(
            StatusCode::FORBIDDEN,
            "forbidden",
            "the presented credential may not administer policy",
        ))
    }
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

// -- DTO <-> core aggregate conversions ---------------------------------------

fn org_from_dto(dto: OrgDto) -> Organization {
    Organization {
        id: dto.id,
        display_name: dto.display_name,
        owner: dto.owner,
        created_at: dto.created_at,
        updated_at: dto.updated_at,
    }
}

fn org_to_dto(org: Organization) -> OrgDto {
    OrgDto {
        id: org.id,
        display_name: org.display_name,
        owner: org.owner,
        created_at: org.created_at,
        updated_at: org.updated_at,
    }
}

fn group_from_dto(dto: GroupDto) -> Group {
    Group {
        id: GroupId(dto.id),
        org: dto.org,
        display_name: dto.display_name,
        members: dto.members,
        created_at: dto.created_at,
        updated_at: dto.updated_at,
    }
}

fn role_from_dto(dto: RoleDto) -> RoleDef {
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

/// The wall-clock instant the daemon stamps an audit record with, as an RFC 3339
/// UTC string (the [`Timestamp`] convention). The store records but never parses
/// it, so it is the application time rather than a resource's own timestamp.
fn now_timestamp() -> Timestamp {
    let secs = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|elapsed| elapsed.as_secs())
        .unwrap_or(0);
    Timestamp(format_rfc3339(secs))
}

/// Format whole seconds since the Unix epoch as `YYYY-MM-DDTHH:MM:SSZ`.
fn format_rfc3339(secs: u64) -> String {
    let days = (secs / 86_400) as i64;
    let time = secs % 86_400;
    let (hour, minute, second) = (time / 3600, (time % 3600) / 60, time % 60);
    let (year, month, day) = civil_from_days(days);
    format!("{year:04}-{month:02}-{day:02}T{hour:02}:{minute:02}:{second:02}Z")
}

/// Convert days since 1970-01-01 to a civil `(year, month, day)` (Howard
/// Hinnant's algorithm), valid for the entire representable range.
fn civil_from_days(days: i64) -> (i64, u32, u32) {
    let z = days + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let doe = (z - era * 146_097) as u64;
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let year = yoe as i64 + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let day = (doy - (153 * mp + 2) / 5 + 1) as u32;
    let month = if mp < 10 { mp + 3 } else { mp - 9 } as u32;
    (if month <= 2 { year + 1 } else { year }, month, day)
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
        let dto = OrgDto {
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
        assert_eq!(format_rfc3339(1_700_000_000), "2023-11-14T22:13:20Z");
        // The epoch itself.
        assert_eq!(format_rfc3339(0), "1970-01-01T00:00:00Z");
    }
}
