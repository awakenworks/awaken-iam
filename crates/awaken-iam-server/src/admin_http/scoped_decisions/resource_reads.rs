//! Finite scoped read capabilities, sharing native admission and PDP assembly.
use super::*;
use awaken_iam_contract::{
    AuthorizationAccess, AuthorizationContext, AuthorizationRequest,
    RESOURCE_AUTHORIZATION_BATCH_MAX, RESOURCE_AUTHORIZATION_CHAIN_MAX,
    ResourceAuthorizationBatchEvaluation, ResourceAuthorizationBatchRequest,
    ResourceAuthorizationMode, ResourceCandidateEvaluation, ResourceCandidatePlan,
    ResourceCandidatePredicate, ResourceCandidateReason, ResourceCandidateRequest,
};
use awaken_iam_core::{ApiTokenOwnerRepository, ApiTokenRepository};

fn unsupported() -> Response {
    error_response(
        StatusCode::NOT_IMPLEMENTED,
        "unsupported_authorization_capability",
        "this capability supports ordinary scoped reads, not personal delegation",
    )
}
fn invalid() -> Response {
    error_response(
        StatusCode::BAD_REQUEST,
        "invalid_scoped_resource_read",
        "questions must retain one verified caller chain, Workspace and namespace within native limits",
    )
}
fn question_matches(
    request: &AuthorizationRequest,
    workspace: &WorkspaceId,
    namespace: &NamespaceId,
) -> bool {
    request.on_behalf_of.len() < RESOURCE_AUTHORIZATION_CHAIN_MAX
        && matches!(&request.scope, ScopeRef::Workspace { workspace_id } | ScopeRef::Project { workspace_id, .. } if workspace_id == workspace)
        && request
            .action
            .0
            .split_once("::")
            .is_some_and(|(prefix, _)| prefix == namespace.0)
}
fn trusted_now() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(i64::MAX, |duration| {
            i64::try_from(duration.as_millis()).unwrap_or(i64::MAX)
        })
}

pub(in crate::admin_http) async fn authorize_batch<S>(
    State(state): State<SharedDaemonState<S>>,
    Path((workspace, namespace)): Path<(String, String)>,
    headers: HeaderMap,
    Json(request): Json<ResourceAuthorizationBatchRequest>,
) -> Response
where
    S: PolicyStore
        + AuthorizationProfileRepository
        + ApiTokenRepository
        + ApiTokenOwnerRepository
        + AccountRepository,
{
    if request.mode != ResourceAuthorizationMode::Scoped {
        return unsupported();
    }
    let workspace = WorkspaceId(workspace);
    let namespace = NamespaceId(namespace);
    if request.requests.len() > RESOURCE_AUTHORIZATION_BATCH_MAX
        || request.requests.iter().any(|item| {
            !question_matches(&item.request, &workspace, &namespace)
                || request.requests.first().is_some_and(|first| {
                    first.request.principal != item.request.principal
                        || first.request.on_behalf_of != item.request.on_behalf_of
                })
        })
    {
        return invalid();
    }
    let mut guard = lock(&state);
    let Ok(before) = guard.admin.store().fence() else {
        return unavailable();
    };
    if let Err(rejection) = super::super::scoped_profiles::admit(
        &mut guard,
        &headers,
        &workspace.0,
        &namespace.0,
        "read",
    ) {
        return rejection;
    }
    guard.with_fresh_state(|state| {
        let outcomes = request
            .requests
            .iter()
            .map(|item| decide(state, item, Some((&workspace, &namespace))))
            .collect::<Result<Vec<_>, _>>();
        let Ok(outcomes) = outcomes else {
            return unavailable();
        };
        let Ok(after) = state.admin.store().fence() else {
            return unavailable();
        };
        if before != after {
            return unavailable();
        }
        let freshness = crate::authorization_freshness(after);
        (
            [(
                awaken_iam_contract::AUTHORIZATION_FRESHNESS_HEADER,
                freshness.clone(),
            )],
            Json(ResourceAuthorizationBatchEvaluation {
                outcomes,
                freshness,
            }),
        )
            .into_response()
    })
}

pub(in crate::admin_http) async fn candidates<S>(
    State(state): State<SharedDaemonState<S>>,
    Path((workspace, namespace)): Path<(String, String)>,
    headers: HeaderMap,
    Json(request): Json<ResourceCandidateRequest>,
) -> Response
where
    S: PolicyStore
        + AuthorizationProfileRepository
        + ApiTokenRepository
        + ApiTokenOwnerRepository
        + AccountRepository,
{
    if request.mode != ResourceAuthorizationMode::Scoped
        || request.access != AuthorizationAccess::Read
    {
        return unsupported();
    }
    let workspace = WorkspaceId(workspace);
    let namespace = NamespaceId(namespace);
    if !question_matches(&request.request, &workspace, &namespace)
        || request.resource_type.as_ref().is_some_and(|value| {
            value.is_empty() || value.len() > 512 || value.chars().any(char::is_control)
        })
    {
        return invalid();
    }
    let mut guard = lock(&state);
    let Ok(before) = guard.admin.store().fence() else {
        return unavailable();
    };
    if let Err(rejection) = super::super::scoped_profiles::admit(
        &mut guard,
        &headers,
        &workspace.0,
        &namespace.0,
        "read",
    ) {
        return rejection;
    }
    guard.with_fresh_state(|state| {
        let plan = scoped_plan(state, &workspace, &namespace, &request);
        let Ok(plan) = plan else {
            return unavailable();
        };
        let Ok(after) = state.admin.store().fence() else {
            return unavailable();
        };
        if before != after || after != state.observed_fence() {
            return unavailable();
        }
        let freshness = crate::authorization_freshness(after);
        (
            [(
                awaken_iam_contract::AUTHORIZATION_FRESHNESS_HEADER,
                freshness.clone(),
            )],
            Json(ResourceCandidateEvaluation { plan, freshness }),
        )
            .into_response()
    })
}

fn scoped_plan<S: PolicyStore + AccountRepository + AuthorizationProfileRepository>(
    state: &DaemonState<S>,
    workspace: &WorkspaceId,
    namespace: &NamespaceId,
    request: &ResourceCandidateRequest,
) -> Result<ResourceCandidatePlan, Unavailable> {
    let no_candidates = || ResourceCandidatePlan {
        predicate: ResourceCandidatePredicate::None,
        broadening_reasons: vec![],
    };
    if native_workspace(state, namespace)?.as_ref() != Some(workspace) {
        return Ok(no_candidates());
    }
    let resource = ResourceAuthorizationRequest {
        request: request.request.clone(),
        context: AuthorizationContext {
            resource_type: request.resource_type.clone(),
            access: request.access,
            ..Default::default()
        },
    };
    let Some(policy) = policy_for_request(state, workspace, namespace, &resource)? else {
        return Ok(no_candidates());
    };
    let mut plan = policy
        .resource_candidates(request, trusted_now())
        .map_err(|_| Unavailable)?;
    // The actual existing PDP still applies inherited native Deny/approval
    // ceilings. Omitting those from a positive candidate only broadens it.
    if !plan
        .broadening_reasons
        .contains(&ResourceCandidateReason::NativeCeilingsDeferred)
    {
        plan.broadening_reasons
            .push(ResourceCandidateReason::NativeCeilingsDeferred);
    }
    Ok(plan)
}
