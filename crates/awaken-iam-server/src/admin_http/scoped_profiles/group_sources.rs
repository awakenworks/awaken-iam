//! Current same-Org Group evidence for scoped policy compilation.

use super::*;
use awaken_iam_contract::{ObserveScopedProfileGroups, ScopedProfileGroupSources};
use awaken_iam_core::GroupId;
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};

pub(super) async fn observe<S>(
    State(state): State<SharedDaemonState<S>>,
    Path((workspace, namespace)): Path<(String, String)>,
    headers: HeaderMap,
    Json(request): Json<ObserveScopedProfileGroups>,
) -> Response
where
    S: PolicyStore + AuthorizationProfileRepository + ApiTokenRepository + ApiTokenOwnerRepository,
{
    match current_groups(&state, &headers, workspace, namespace, request) {
        Ok(observed) => Json(observed).into_response(),
        Err(error) => error,
    }
}

#[allow(clippy::result_large_err)]
fn current_groups<S>(
    state: &SharedDaemonState<S>,
    headers: &HeaderMap,
    workspace: String,
    namespace: String,
    request: ObserveScopedProfileGroups,
) -> Result<ScopedProfileGroupSources, Response>
where
    S: PolicyStore + AuthorizationProfileRepository + ApiTokenRepository + ApiTokenOwnerRepository,
{
    let mut guard = lock(state);
    admit(
        &mut guard,
        headers,
        &workspace,
        &namespace,
        "observe-groups",
    )?;
    let ids: BTreeSet<_> = request.group_ids.iter().collect();
    if ids.len() != request.group_ids.len()
        || ids.len() > 32
        || ids.iter().any(|id| {
            !id.starts_with("awaken.flow:")
                || id.len() <= "awaken.flow:".len()
                || id.len() > 256
                || id.trim() != id.as_str()
                || id.chars().any(char::is_control)
        })
    {
        return Err(error_response(
            StatusCode::UNPROCESSABLE_ENTITY,
            "invalid_profile_group_sources",
            "expected at most 32 unique exact Flow Group identifiers",
        ));
    }
    let version = || {
        guard
            .admin
            .store_version()
            .map_err(|error| admin_error_response(&error))
    };
    let before = version()?;
    let workspace_id = WorkspaceId(workspace);
    let org_id = workspace_org(&guard, &workspace_id)?;
    let mut revisions = BTreeMap::new();
    for id in ids {
        let group = guard
            .admin
            .get_group(&GroupId(id.clone()))
            .map_err(|error| admin_error_response(&error))?
            .filter(|group| group.org == org_id)
            .ok_or_else(|| {
                error_response(
                    StatusCode::FORBIDDEN,
                    "foreign_profile_group",
                    "profile Group does not belong to this organization",
                )
            })?;
        let content = serde_json::to_vec(&(
            &group.id.0,
            &group.org,
            &group.created_at,
            &group.updated_at,
            &group.members,
        ))
        .map_err(|_| {
            error_response(
                StatusCode::SERVICE_UNAVAILABLE,
                "group_source_unavailable",
                "Group evidence is unavailable",
            )
        })?;
        revisions.insert(id.clone(), format!("sha256:{:x}", Sha256::digest(content)));
    }
    if version()? != before {
        return Err(error_response(
            StatusCode::SERVICE_UNAVAILABLE,
            "group_source_changed",
            "Group evidence changed during observation",
        ));
    }
    Ok(ScopedProfileGroupSources {
        org_id,
        workspace_id,
        namespace: NamespaceId(namespace),
        revisions,
    })
}
