//! Strict registration and actual decisions share one complete native fence.
use super::*;
use awaken_iam_contract::{
    AuthorizationDecision, AuthorizationEvaluation, AuthorizationOutcome, ProfileLifecycle,
    RegisteredResourceAuthorizationEvaluation, RegisteredResourceAuthorizationRequest,
    ResourceRegistrationQualification, ResourceType, ScopeKind, ScopeRef,
};
use awaken_iam_core::{AuthorizationProfileRepository, PolicySet, ResourceModelRepository};
use std::collections::HashSet;

pub(super) async fn authorize<
    S: PolicyStore + ResourceProjectionStore + AuthorizationProfileRepository,
>(
    State(state): State<SharedDaemonState<S>>,
    Json(request): Json<RegisteredResourceAuthorizationRequest>,
) -> Response {
    let guard = lock(&state);
    match evaluate(&guard, &request) {
        Ok(evaluation) => Json(evaluation).into_response(),
        Err(_) => scoped_decisions::unavailable(),
    }
}

fn denied() -> AuthorizationOutcome {
    AuthorizationOutcome {
        decision: AuthorizationDecision::Deny,
        reason: "resource_registration_required".into(),
        matched_grants: Vec::new(),
        matched_roles: Vec::new(),
        obligation: None,
    }
}

pub(super) fn evaluate<
    S: PolicyStore + ResourceProjectionStore + AuthorizationProfileRepository,
>(
    state: &DaemonState<S>,
    request: &RegisteredResourceAuthorizationRequest,
) -> Result<RegisteredResourceAuthorizationEvaluation, scoped_decisions::Unavailable> {
    let before = state
        .admin
        .store()
        .fence()
        .map_err(|_| scoped_decisions::Unavailable)?;
    let registration = qualify(state, request)?;
    // The legacy '*' fallback is never evaluated as permission when required
    // registrations are absent. Qualification never upgrades the actual PDP.
    let outcome = if registration.is_some() {
        current_outcome(state, request)?
    } else {
        denied()
    };
    let after = state
        .admin
        .store()
        .fence()
        .map_err(|_| scoped_decisions::Unavailable)?;
    if before != after {
        return Err(scoped_decisions::Unavailable);
    }
    Ok(RegisteredResourceAuthorizationEvaluation {
        evaluation: AuthorizationEvaluation {
            outcome,
            freshness: Some(crate::authorization_freshness(after)),
        },
        registration,
    })
}

fn qualify<S: PolicyStore + ResourceProjectionStore + AuthorizationProfileRepository>(
    state: &DaemonState<S>,
    expected: &RegisteredResourceAuthorizationRequest,
) -> Result<Option<ResourceRegistrationQualification>, scoped_decisions::Unavailable> {
    let request = &expected.authorization.request;
    let ScopeRef::Resource {
        resource_type,
        resource_id,
    } = &request.scope
    else {
        return Ok(None);
    };
    if expected
        .authorization
        .context
        .resource_id
        .as_ref()
        .is_some_and(|id| id != &resource_id.0)
        || expected
            .authorization
            .context
            .resource_type
            .as_ref()
            .is_some_and(|kind| kind != &resource_type.0)
        || resource_type != &expected.resource_type
        || resource_id.0.is_empty()
        || request
            .action
            .0
            .split_once("::")
            .map(|(namespace, _)| namespace)
            != Some(expected.namespace.0.as_str())
    {
        return Ok(None);
    }
    let store = state.admin.store();
    // The strict protocol never trusts a separately supplied profile repository
    // or hydrated legacy cache to establish same-store registration authority.
    let Some(profile) = AuthorizationProfileRepository::active_profile(store, &expected.namespace)
        .map_err(|_| scoped_decisions::Unavailable)?
    else {
        return Ok(None);
    };
    // The existing scoped-publication contract admits only Workspace/Project
    // actions and forbids resource topology. It cannot mint Resource authority.
    if AuthorizationProfileRepository::profile_publication_workspace(store, &expected.namespace)
        .map_err(|_| scoped_decisions::Unavailable)?
        .is_some()
    {
        return Ok(None);
    }

    if profile.lifecycle != ProfileLifecycle::Active
        || profile.document.resource_product.as_ref() != Some(&expected.product_id)
        || !profile
            .document
            .resource_model
            .resource_types
            .iter()
            .any(|kind| {
                kind.resource_type == *resource_type && kind.actions.contains(&request.action)
            })
        || !profile.document.action_scope_rules.iter().any(|rule| {
            rule.action_pattern == request.action.0
                && rule.allowed_scope_kinds.contains(&ScopeKind::Resource {
                    resource_type: resource_type.clone(),
                })
        })
    {
        return Ok(None);
    }
    let store = state.admin.store();
    if !store
        .registered_product_action(&expected.product_id, resource_type, &request.action)
        .map_err(|_| scoped_decisions::Unavailable)?
    {
        return Ok(None);
    }
    let Some(workspace) = ResourceModelRepository::workspace_org(store, &expected.workspace_id)
        .map_err(|_| scoped_decisions::Unavailable)?
    else {
        return Ok(None);
    };
    if state
        .admin
        .get_org(&workspace.org_id)
        .map_err(|_| scoped_decisions::Unavailable)?
        .is_none()
    {
        return Ok(None);
    }
    let mut current = request.scope.clone();
    let mut seen = HashSet::new();
    let mut first = None;
    let mut rooted = false;
    // Only committed, product-owned versioned edges prove a Resource path.
    // Snapshot/profile/manual edges do not participate in this qualification.
    for _ in 0..64 {
        if !seen.insert(current.clone()) {
            return Ok(None);
        }
        match current {
            ScopeRef::Resource {
                resource_type: kind,
                resource_id: id,
            } => {
                let Some(projection) = store
                    .observe_resource_projection(&kind, &id)
                    .map_err(|_| scoped_decisions::Unavailable)?
                else {
                    return Ok(None);
                };
                if projection.product_id != expected.product_id
                    || projection.org_id != workspace.org_id
                {
                    return Ok(None);
                }
                if first.is_none() {
                    first = Some(projection.clone());
                }
                current = projection.parent;
            }
            ScopeRef::Workspace { workspace_id } | ScopeRef::Project { workspace_id, .. } => {
                rooted = workspace_id == expected.workspace_id;
                break;
            }
            _ => return Ok(None),
        }
    }
    if !rooted {
        return Ok(None);
    }
    let Some(first) = first else {
        return Ok(None);
    };
    Ok(Some(ResourceRegistrationQualification {
        namespace: expected.namespace.clone(),
        profile_revision: profile.revision,
        profile_checksum: profile.checksum,
        action: request.action.clone(),
        product_id: expected.product_id.clone(),
        workspace_id: expected.workspace_id.clone(),
        resource_type: ResourceType(resource_type.0.clone()),
        resource_id: resource_id.clone(),
        projection_id: first.projection_id,
        projection_epoch: first.epoch,
    }))
}

fn current_outcome<S: PolicyStore + AuthorizationProfileRepository>(
    state: &DaemonState<S>,
    request: &RegisteredResourceAuthorizationRequest,
) -> Result<AuthorizationOutcome, scoped_decisions::Unavailable> {
    Ok(native_current_evaluator(state)?.authorize_resource(&request.authorization))
}

/// One native policy/profile source for compound protocols; a separately
/// supplied legacy profile repository cannot qualify this evaluator.
pub(super) fn native_current_evaluator<S: PolicyStore + AuthorizationProfileRepository>(
    state: &DaemonState<S>,
) -> Result<crate::AuthzApi, scoped_decisions::Unavailable> {
    let version = state
        .admin
        .store()
        .fence()
        .map_err(|_| scoped_decisions::Unavailable)?
        .version;
    let base = state
        .admin
        .policy()
        .map_err(|_| scoped_decisions::Unavailable)?
        .snapshot(version);
    let profiles = AuthorizationProfileRepository::active_profiles(state.admin.store())
        .map_err(|_| scoped_decisions::Unavailable)?;
    let mut evaluator = crate::AuthzApi::new();
    evaluator.replace_policy_at_version(
        PolicySet::from_snapshot_and_profiles(&base, &profiles),
        version,
    );
    Ok(evaluator)
}
