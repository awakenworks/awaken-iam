//! Current native admission for Workspace-pinned profile namespaces.
use super::*;
use awaken_iam_contract::{
    AuthorizationOutcome, AuthorizationProfileDocument, GroupRosterSnapshot, PrincipalRef,
    ResourceAuthorizationRequest, ScopeRef, WorkspaceId,
};
use awaken_iam_core::{AccountRepository, PolicySet, ResourceModelRepository};
use std::collections::BTreeSet;

pub(super) struct Unavailable;
pub(super) type DecisionPort<S> = fn(
    &DaemonState<S>,
    &WorkspaceId,
    &NamespaceId,
    &ResourceAuthorizationRequest,
) -> Result<AuthorizationOutcome, Unavailable>;

pub(super) fn unavailable() -> Response {
    error_response(
        StatusCode::SERVICE_UNAVAILABLE,
        "policy_unavailable",
        "Current scoped policy is unavailable",
    )
}
fn denied(request: &ResourceAuthorizationRequest) -> AuthorizationOutcome {
    PolicySet::new().evaluate_resource(request).to_outcome()
}

pub(super) fn response<S: PolicyStore>(
    state: &DaemonState<S>,
    request: &ResourceAuthorizationRequest,
    expected: Option<(&WorkspaceId, &NamespaceId)>,
) -> Response {
    match decide(state, request, expected) {
        Ok(outcome) => Json(outcome).into_response(),
        Err(_) => unavailable(),
    }
}

pub(super) fn decide<S: PolicyStore>(
    state: &DaemonState<S>,
    request: &ResourceAuthorizationRequest,
    expected: Option<(&WorkspaceId, &NamespaceId)>,
) -> Result<AuthorizationOutcome, Unavailable> {
    let version = state.observed_store_version;
    let namespace = request
        .request
        .action
        .0
        .split_once("::")
        .map(|(value, _)| NamespaceId(value.into()));
    if expected.is_some_and(|(_, target)| namespace.as_ref() != Some(target)) {
        return Ok(denied(request));
    }
    let owner = namespace
        .as_ref()
        .map(|namespace| state.profiles.scoped_workspace(namespace))
        .transpose()
        .map_err(|_| Unavailable)?
        .flatten();
    let outcome = match (namespace, owner) {
        (Some(namespace), Some(workspace)) => {
            if expected.is_some_and(|(target, _)| target != &workspace) {
                return Ok(denied(request));
            }
            state.scoped_decision.ok_or(Unavailable)?(state, &workspace, &namespace, request)?
        }
        _ if expected.is_some() => denied(request),
        _ => state.authz.authorize_resource(request),
    };
    if state.admin.store_version().map_err(|_| Unavailable)? != version {
        return Err(Unavailable);
    }
    Ok(outcome)
}

/// An explicit scoped request never falls back to an unpinned legacy profile.
pub(super) async fn authorize<S: PolicyStore>(
    State(state): State<SharedDaemonState<S>>,
    Path((workspace, namespace)): Path<(String, String)>,
    Json(request): Json<ResourceAuthorizationRequest>,
) -> Response {
    let mut guard = lock(&state);
    guard.with_fresh_state(|state| {
        response(
            state,
            &request,
            Some((&WorkspaceId(workspace), &NamespaceId(namespace))),
        )
    })
}

fn explicitly_named(document: &AuthorizationProfileDocument, principal: &PrincipalRef) -> bool {
    document.role_bindings.iter().any(|binding| &binding.principal == principal) ||
        document.grants.iter().any(|grant| matches!(&grant.subject, GrantSubjectRef::Principal { principal: named } if named == principal))
}

pub(super) fn evaluate<S: PolicyStore + AccountRepository>(
    state: &DaemonState<S>,
    workspace: &WorkspaceId,
    namespace: &NamespaceId,
    request: &ResourceAuthorizationRequest,
) -> Result<AuthorizationOutcome, Unavailable> {
    if !matches!(&request.request.scope, ScopeRef::Workspace { workspace_id } | ScopeRef::Project { workspace_id, .. } if workspace_id == workspace)
    {
        return Ok(denied(request));
    }
    let Some(profile) = state.profiles.active(namespace).map_err(|_| Unavailable)? else {
        return Ok(denied(request));
    };
    crate::profile_admin::validate_scoped_document(namespace, workspace, &profile.document)
        .map_err(|_| Unavailable)?;
    let Some(edge) = ResourceModelRepository::workspace_org(state.admin.store(), workspace)
        .map_err(|_| Unavailable)?
    else {
        return Ok(denied(request));
    };
    if state
        .admin
        .get_org(&edge.org_id)
        .map_err(|_| Unavailable)?
        .is_none()
    {
        return Ok(denied(request));
    }
    let org = ScopeRef::Org {
        org_id: edge.org_id.clone(),
    };
    let mut service_roles = super::scoped_service_roles::CurrentServiceRoles::default();
    let mut unavailable_service_bindings = Vec::new();
    for principal in request.request.principal_chain() {
        match principal {
            PrincipalRef::Account { account_id } => {
                let active = AccountRepository::get(state.admin.store(), account_id)
                    .map_err(|_| Unavailable)?
                    .is_some_and(|account| {
                        account.status == awaken_iam_contract::AccountStatus::Active
                    });
                let member = state
                    .admin
                    .memberships_for_principal(principal)
                    .map_err(|_| Unavailable)?
                    .iter()
                    .any(|binding| binding.scope == org);
                if !active || !member {
                    return Ok(denied(request));
                }
            }
            PrincipalRef::Service { .. } => {
                let direct = profile.document.grants.iter().any(|grant|
                    matches!(&grant.subject, GrantSubjectRef::Principal { principal: named } if named == principal));
                let mut held_role = false;
                for binding in profile
                    .document
                    .role_bindings
                    .iter()
                    .filter(|binding| &binding.principal == principal)
                {
                    if service_roles
                        .contains(state, principal, &binding.role_id, &binding.scope)
                        .map_err(|_| Unavailable)?
                    {
                        held_role = true;
                    } else {
                        unavailable_service_bindings.push(awaken_iam_core::RoleBinding {
                            principal: principal.clone(),
                            role: awaken_iam_core::RoleId(binding.role_id.clone()),
                            scope: binding.scope.clone(),
                        });
                    }
                }
                if !direct && !held_role {
                    return Ok(denied(request));
                }
            }
            _ if !explicitly_named(&profile.document, principal) => return Ok(denied(request)),
            _ => {}
        }
    }
    let mut base = PolicySnapshot::default();
    base.scope_graph.workspace_orgs.push(edge.clone());
    let groups = profile
        .document
        .group_role_bindings
        .iter()
        .map(|binding| binding.group_id.clone())
        .chain(
            profile
                .document
                .grants
                .iter()
                .filter_map(|grant| match &grant.subject {
                    GrantSubjectRef::Group { group_id } => Some(group_id.clone()),
                    _ => None,
                }),
        )
        .collect::<BTreeSet<_>>();
    for id in groups {
        if let Some(group) = state
            .admin
            .get_group(&GroupId(id.clone()))
            .map_err(|_| Unavailable)?
            .filter(|group| group.org == edge.org_id)
        {
            base.group_rosters.push(GroupRosterSnapshot {
                group_id: id,
                members: group
                    .members
                    .into_iter()
                    .filter(|member| matches!(member, PrincipalRef::Account { .. }))
                    .collect(),
            });
        }
    }
    // Immutable document identity is retained. Base Allows and Workspace roles
    // cannot supply the profile's permission. Existing native Deny/approval
    // ceilings still constrain a scoped Allow.
    let mut policy = PolicySet::from_snapshot_and_profiles(&base, &[profile]);
    for binding in unavailable_service_bindings {
        policy.unbind_role(&binding);
    }
    let mut evaluator = crate::AuthzApi::new();
    evaluator.replace_policy_at_version(policy, state.observed_store_version);
    let scoped = evaluator.authorize_resource(request);
    let inherited = state.authz.authorize_resource(request);
    use awaken_iam_contract::AuthorizationDecision::{Allow, Deny, RequireApproval};
    Ok(match (scoped.decision, inherited.decision) {
        (_, Deny) | (Allow, RequireApproval) => inherited,
        _ => scoped,
    })
}
