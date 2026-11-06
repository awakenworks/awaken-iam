//! Atomically activate the prepared native intents for one Workspace.

use super::*;
use awaken_iam_contract::{
    ActivateScopedAuthorizationProfiles, ScopedAuthorizationProfileReceipt,
    ScopedAuthorizationProfileStatus,
};

pub(super) async fn activate<S>(
    State(state): State<SharedDaemonState<S>>,
    Path(workspace): Path<String>,
    headers: HeaderMap,
    Json(request): Json<ActivateScopedAuthorizationProfiles>,
) -> Response
where
    S: PolicyStore + ApiTokenRepository + ApiTokenOwnerRepository + AccountRepository,
{
    match activate_current(&state, &headers, &workspace, request) {
        Ok(receipts) => Json(receipts).into_response(),
        Err(error) => error,
    }
}

#[allow(clippy::result_large_err)]
fn activate_current<S>(
    state: &SharedDaemonState<S>,
    headers: &HeaderMap,
    workspace: &str,
    request: ActivateScopedAuthorizationProfiles,
) -> Result<Vec<ScopedAuthorizationProfileReceipt>, Response>
where
    S: PolicyStore + ApiTokenRepository + ApiTokenOwnerRepository + AccountRepository,
{
    let mut namespaces = std::collections::HashSet::new();
    if request.intents.is_empty()
        || request.intents.len() > 16
        || request.intents.iter().any(|intent| {
            intent.workspace_id.0 != workspace || !namespaces.insert(&intent.namespace)
        })
    {
        return Err(error_response(
            StatusCode::UNPROCESSABLE_ENTITY,
            "invalid_activation_set",
            "activation requires distinct exact intents in one Workspace",
        ));
    }
    let mut guard = lock(state);
    let version = guard
        .admin
        .store_version()
        .map_err(|error| admin_error_response(&error))?;
    let profiles = guard.profiles.clone();
    let mut receipts = Vec::with_capacity(request.intents.len());
    let mut targets = Vec::new();
    for intent in request.intents {
        let actor = admit(
            &mut guard,
            headers,
            workspace,
            &intent.namespace.0,
            "activate-set",
        )?;
        if actor != intent.publisher {
            return Err(error_response(
                StatusCode::FORBIDDEN,
                "publication_publisher_mismatch",
                "original publisher identity required",
            ));
        }
        let receipt = profiles
            .scoped_publication_receipt(&intent.namespace, &intent.request_key)
            .map_err(|error| profile_error_response(&error))?;
        if receipt.intent != intent {
            return Err(error_response(
                StatusCode::CONFLICT,
                "publication_intent_mismatch",
                "original publication intent changed",
            ));
        }
        if receipt.status == ScopedAuthorizationProfileStatus::Prepared {
            let profile = profiles
                .get(&intent.namespace, intent.revision)
                .map_err(|error| profile_error_response(&error))?
                .ok_or_else(|| StatusCode::NOT_FOUND.into_response())?;
            live_subjects(&guard, &intent.workspace_id, &profile.document, &actor)?;
            targets.push((intent, profile));
        }
        receipts.push(receipt);
    }
    let base = guard
        .admin
        .policy()
        .map_err(|error| admin_error_response(&error))?;
    if guard
        .admin
        .store_version()
        .map_err(|error| admin_error_response(&error))?
        != version
    {
        return Err(StatusCode::CONFLICT.into_response());
    }
    if targets.is_empty() {
        return Ok(receipts);
    }
    if targets.len() != receipts.len() {
        return Err(error_response(
            StatusCode::CONFLICT,
            "partially_activated_set",
            "activation set contains earlier effects",
        ));
    }
    profiles
        .activate_scoped_publication_set(
            &mut guard.authz,
            &base.snapshot(version),
            targets,
            version,
        )
        .map_err(|error| profile_error_response(&error))
}
