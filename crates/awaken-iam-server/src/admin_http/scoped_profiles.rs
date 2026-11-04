//! Finite namespace/Workspace publication capabilities, never global PAP keys.
use super::*;
use awaken_iam_contract::{PrepareScopedAuthorizationProfile, PrincipalRef, ScopeRef, WorkspaceId};
use awaken_iam_core::{
    AccountRepository, ApiTokenOwnerRepository, ApiTokenRepository, PolicySet,
    ResourceModelRepository, authenticate_stored_api_token,
};

pub fn scoped_profile_router<S>(state: SharedDaemonState<S>) -> Router
where
    S: PolicyStore + ApiTokenRepository + ApiTokenOwnerRepository + AccountRepository + 'static,
{
    let limit = lock(&state).profile_body_limit;
    Router::new()
        .route("/v1/scoped-authz/workspaces/{workspace}/profiles/{namespace}", get(baseline::<S>))
        .route("/v1/scoped-authz/workspaces/{workspace}/profiles/{namespace}/publications",post(prepare::<S>).layer(DefaultBodyLimit::max(limit)))
        .route("/v1/scoped-authz/workspaces/{workspace}/profiles/{namespace}/publications/{key}",get(receipt::<S>))
        .route("/v1/scoped-authz/workspaces/{workspace}/profiles/{namespace}/publications/{key}/activate",post(activate::<S>))
        .with_state(state)
}

#[allow(clippy::result_large_err)]
fn admit<S>(
    guard: &mut DaemonState<S>,
    headers: &HeaderMap,
    workspace: &str,
    namespace: &str,
    operation: &str,
) -> Result<PrincipalRef, Response>
where
    S: PolicyStore + ApiTokenRepository + ApiTokenOwnerRepository,
{
    let scope = ScopeRef::Workspace {
        workspace_id: WorkspaceId(workspace.into()),
    };
    let action = format!("iam.authorization-profile.{operation}:{namespace}");
    let principal = super::principal_access::admit(guard, headers, &action, scope.clone())?
        .ok_or_else(|| {
            error_response(
                StatusCode::FORBIDDEN,
                "scoped_service_required",
                "scoped publication needs an owned service identity",
            )
        })?;
    let presented = headers
        .get("authorization")
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.strip_prefix("Bearer "))
        .ok_or_else(|| {
            error_response(
                StatusCode::UNAUTHORIZED,
                "invalid_credential",
                "live service credential required",
            )
        })?;
    let token = authenticate_stored_api_token(guard.admin.store(), presented, &now_timestamp())
        .map_err(|error| admin_error_response(&AdminError::from(error)))?
        .ok_or_else(|| {
            error_response(
                StatusCode::UNAUTHORIZED,
                "invalid_credential",
                "live service credential required",
            )
        })?;
    if token.workspace.0 != workspace {
        return Err(error_response(
            StatusCode::FORBIDDEN,
            "credential_workspace_mismatch",
            "publisher credential belongs to another Workspace",
        ));
    }
    let request = AuthorizationRequest::direct(
        principal.clone(),
        awaken_iam_contract::ActionKey(action.clone()),
        scope.clone(),
    );
    let decision = guard.authz.authorize(&request);
    let exact = guard.authz.snapshot().grants.iter().any(|grant| {
        grant.action_pattern == action
            && grant.scope == scope
            && grant.subject
                == (GrantSubjectRef::Principal {
                    principal: principal.clone(),
                })
            && grant.effect == GrantEffect::Allow
            && decision.matched_grants.contains(&grant.id)
    });
    if decision.decision != awaken_iam_contract::AuthorizationDecision::Allow || !exact {
        return Err(error_response(
            StatusCode::FORBIDDEN,
            "exact_publication_capability_required",
            "an exact namespace and Workspace capability is required",
        ));
    }
    Ok(principal)
}

// New scoped inputs must retain every supplied field through native decoding.
// Unknown constraints cannot be silently ignored by a legacy profile DTO.
fn retained(input: &serde_json::Value, canonical: &serde_json::Value) -> bool {
    match (input, canonical) {
        (serde_json::Value::Object(input), serde_json::Value::Object(output)) => input
            .iter()
            .all(|(key, value)| output.get(key).is_some_and(|known| retained(value, known))),
        (serde_json::Value::Array(input), serde_json::Value::Array(output)) => {
            input.len() == output.len()
                && input
                    .iter()
                    .zip(output)
                    .all(|(input, output)| retained(input, output))
        }
        _ => input == canonical,
    }
}

#[allow(clippy::result_large_err)]
fn decode(body: serde_json::Value) -> Result<PrepareScopedAuthorizationProfile, Response> {
    let request: PrepareScopedAuthorizationProfile =
        serde_json::from_value(body.clone()).map_err(|_| {
            error_response(
                StatusCode::UNPROCESSABLE_ENTITY,
                "invalid_profile_publication",
                "invalid scoped publication contract",
            )
        })?;
    let canonical = serde_json::to_value(&request).map_err(|_| {
        error_response(
            StatusCode::INTERNAL_SERVER_ERROR,
            "profile_contract_error",
            "profile contract unavailable",
        )
    })?;
    if !retained(&body, &canonical) {
        return Err(error_response(
            StatusCode::UNPROCESSABLE_ENTITY,
            "unknown_profile_field",
            "unknown or noncanonical profile field",
        ));
    }
    Ok(request)
}

#[allow(clippy::result_large_err)]
fn live_subjects<S>(
    guard: &DaemonState<S>,
    workspace: &WorkspaceId,
    document: &awaken_iam_contract::AuthorizationProfileDocument,
    publisher: &PrincipalRef,
) -> Result<(), Response>
where
    S: PolicyStore + AccountRepository,
{
    let edge = ResourceModelRepository::workspace_org(guard.admin.store(), workspace)
        .map_err(|error| admin_error_response(&AdminError::from(error)))?
        .ok_or_else(|| {
            error_response(
                StatusCode::FORBIDDEN,
                "unbound_workspace",
                "Workspace ownership is unavailable",
            )
        })?;
    if guard
        .admin
        .get_org(&edge.org_id)
        .map_err(|error| admin_error_response(&error))?
        .is_none()
    {
        return Err(error_response(
            StatusCode::FORBIDDEN,
            "inactive_organization",
            "organization is unavailable",
        ));
    }
    let policy = PolicySet::from_snapshot(&guard.authz.snapshot());
    let org_scope = ScopeRef::Org {
        org_id: edge.org_id.clone(),
    };
    let group = |id: &str| -> Result<(), Response> {
        let current = guard
            .admin
            .get_group(&awaken_iam_core::GroupId(id.into()))
            .map_err(|error| admin_error_response(&error))?;
        if current.is_none_or(|group| group.org != edge.org_id) {
            return Err(error_response(
                StatusCode::FORBIDDEN,
                "foreign_profile_group",
                "profile Group does not belong to this organization",
            ));
        }
        Ok(())
    };
    let principal = |value: &PrincipalRef| -> Result<(), Response> {
        if !matches!(value, PrincipalRef::Account { .. }) && value != publisher {
            return Err(error_response(
                StatusCode::FORBIDDEN,
                "unbound_profile_principal",
                "a non-account profile principal must be the scoped publisher",
            ));
        }
        if let PrincipalRef::Account { account_id } = value {
            let account = AccountRepository::get(guard.admin.store(), account_id)
                .map_err(|error| admin_error_response(&AdminError::from(error)))?;
            let member = guard
                .admin
                .memberships_for_principal(value)
                .map_err(|error| admin_error_response(&error))?
                .iter()
                .any(|binding| policy.scope_graph().covers(&org_scope, &binding.scope));
            if account
                .is_none_or(|account| account.status != awaken_iam_contract::AccountStatus::Active)
                || !member
            {
                return Err(error_response(
                    StatusCode::FORBIDDEN,
                    "foreign_profile_principal",
                    "profile account lacks current organization membership",
                ));
            }
        }
        Ok(())
    };
    for grant in &document.grants {
        match &grant.subject {
            GrantSubjectRef::Group { group_id } => group(group_id)?,
            GrantSubjectRef::Principal { principal: value } => principal(value)?,
            _ => {}
        }
    }
    for binding in &document.group_role_bindings {
        group(&binding.group_id)?;
    }
    for binding in &document.role_bindings {
        principal(&binding.principal)?;
    }
    for limit in &document.binding_limits {
        match &limit.subject {
            GrantSubjectRef::Group { group_id } => group(group_id)?,
            GrantSubjectRef::Principal { principal: value } => principal(value)?,
            _ => {}
        }
    }
    Ok(())
}

async fn prepare<S>(
    State(state): State<SharedDaemonState<S>>,
    Path((workspace, namespace)): Path<(String, String)>,
    headers: HeaderMap,
    Json(body): Json<serde_json::Value>,
) -> Response
where
    S: PolicyStore + ApiTokenRepository + ApiTokenOwnerRepository + AccountRepository,
{
    let mut guard = lock(&state);
    let actor = match admit(&mut guard, &headers, &workspace, &namespace, "publish") {
        Ok(actor) => actor,
        Err(error) => return error,
    };
    let request = match decode(body) {
        Ok(request) => request,
        Err(error) => return error,
    };
    if request.workspace_id.0 != workspace || request.profile.namespace.0 != namespace {
        return error_response(
            StatusCode::UNPROCESSABLE_ENTITY,
            "profile_target_mismatch",
            "path and publication target differ",
        );
    }
    match guard
        .profiles
        .scoped_publication(&NamespaceId(namespace.clone()), &request.request_key)
    {
        Ok(Some(_)) => {
            let key = request.request_key.clone();
            return match guard.profiles.prepare_scoped_publication(request, actor) {
                Ok(_) => profile_result(
                    guard
                        .profiles
                        .scoped_publication_receipt(&NamespaceId(namespace), &key),
                ),
                Err(error) => profile_error_response(&error),
            };
        }
        Ok(None) => {}
        Err(error) => return profile_error_response(&error),
    }
    if let Err(error) = live_subjects(
        &guard,
        &request.workspace_id,
        &request.profile.document,
        &actor,
    ) {
        return error;
    }
    let key = request.request_key.clone();
    match guard.profiles.prepare_scoped_publication(request, actor) {
        Ok(_) => profile_result(
            guard
                .profiles
                .scoped_publication_receipt(&NamespaceId(namespace), &key),
        ),
        Err(error) => profile_error_response(&error),
    }
}

async fn baseline<S>(
    State(state): State<SharedDaemonState<S>>,
    Path((workspace, namespace)): Path<(String, String)>,
    headers: HeaderMap,
) -> Response
where
    S: PolicyStore + ApiTokenRepository + ApiTokenOwnerRepository + AccountRepository,
{
    let mut guard = lock(&state);
    let actor = match admit(&mut guard, &headers, &workspace, &namespace, "read") {
        Ok(actor) => actor,
        Err(error) => return error,
    };
    let workspace = WorkspaceId(workspace);
    if let Err(error) = live_subjects(&guard, &workspace, &Default::default(), &actor) {
        return error;
    }
    profile_result(
        guard
            .profiles
            .scoped_publication_baseline(&NamespaceId(namespace), &workspace),
    )
}

async fn receipt<S>(
    State(state): State<SharedDaemonState<S>>,
    Path((workspace, namespace, key)): Path<(String, String, String)>,
    headers: HeaderMap,
) -> Response
where
    S: PolicyStore + ApiTokenRepository + ApiTokenOwnerRepository + AccountRepository,
{
    let mut guard = lock(&state);
    if let Err(error) = admit(&mut guard, &headers, &workspace, &namespace, "read") {
        return error;
    }
    match guard
        .profiles
        .scoped_publication(&NamespaceId(namespace.clone()), &key)
    {
        Ok(Some(intent)) if intent.workspace_id.0 == workspace => profile_result(
            guard
                .profiles
                .scoped_publication_receipt(&NamespaceId(namespace), &key),
        ),
        Ok(_) => StatusCode::NOT_FOUND.into_response(),
        Err(error) => profile_error_response(&error),
    }
}

async fn activate<S>(
    State(state): State<SharedDaemonState<S>>,
    Path((workspace, namespace, key)): Path<(String, String, String)>,
    headers: HeaderMap,
) -> Response
where
    S: PolicyStore + ApiTokenRepository + ApiTokenOwnerRepository + AccountRepository,
{
    let mut guard = lock(&state);
    let actor = match admit(&mut guard, &headers, &workspace, &namespace, "publish") {
        Ok(actor) => actor,
        Err(error) => return error,
    };
    let namespace = NamespaceId(namespace);
    let intent = match guard.profiles.scoped_publication(&namespace, &key) {
        Ok(Some(intent)) if intent.workspace_id.0 == workspace => intent,
        Ok(_) => return StatusCode::NOT_FOUND.into_response(),
        Err(error) => return profile_error_response(&error),
    };
    if actor != intent.publisher {
        return error_response(
            StatusCode::FORBIDDEN,
            "publication_publisher_mismatch",
            "original publisher identity required",
        );
    }
    match guard.profiles.scoped_publication_receipt(&namespace, &key) {
        Ok(receipt)
            if receipt.status
                != awaken_iam_contract::ScopedAuthorizationProfileStatus::Prepared =>
        {
            return Json(receipt).into_response();
        }
        Ok(_) => {}
        Err(error) => return profile_error_response(&error),
    }
    let profile = match guard.profiles.get(&namespace, intent.revision) {
        Ok(Some(profile)) => profile,
        Ok(None) => return StatusCode::NOT_FOUND.into_response(),
        Err(error) => return profile_error_response(&error),
    };
    if let Err(error) = live_subjects(&guard, &intent.workspace_id, &profile.document, &actor) {
        return error;
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
    profile_result(profiles.activate_scoped_publication(&mut guard.authz, &base, &namespace, &key))
}
