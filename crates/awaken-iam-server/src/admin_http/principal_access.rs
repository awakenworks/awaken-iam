//! Scoped administration for a consumer's personnel owner (ADR-0018).
//!
//! | rule | credential                                   | outcome |
//! |------|----------------------------------------------|---------|
//! | C1   | administrator key                            | admitted |
//! | C2   | service-account API token, owner recorded, live, holding the action at the target scope | admitted |
//! | C3   | missing or unauthenticated credential        | 401 |
//! | C4   | token without a recorded owner, of a non-service principal, or without the action | 403 |
//! | C5   | product Directory credential                 | 403 |

use awaken_iam_contract::{
    ActionKey, ApiToken, AuthorizationDecision, AuthorizationRequest, NamespaceId, PrincipalRef,
    ScopeRef, TeamAccessReplacement,
};
use awaken_iam_core::{ApiTokenOwnerRepository, ApiTokenRepository, authenticate_stored_api_token};

use super::*;
use crate::{ACTION_AUTHZ_PROFILE_READ, ACTION_PRINCIPAL_ACCESS_REPLACE, PrincipalAccessStore};

/// Mount the fenced team access command and the business profile read beside
/// the generic daemon router. Only stores that persist the fence and API
/// tokens implement this extension.
pub fn principal_access_router<S>(state: SharedDaemonState<S>) -> Router
where
    S: PolicyStore + PrincipalAccessStore + ApiTokenRepository + ApiTokenOwnerRepository + 'static,
{
    Router::new()
        .route(
            "/v1/admin/principal-access/team-replacements",
            post(replace_team_access::<S>),
        )
        .route(
            "/v1/admin/principal-access/profiles/{namespace}",
            get(read_active_profile::<S>),
        )
        .with_state(state)
}

/// Admit the caller for one action at one scope, returning the audit actor.
/// The refusal is the finished HTTP response, like the other admin guards.
#[allow(clippy::result_large_err)]
pub(super) fn admit<S>(
    guard: &mut DaemonState<S>,
    headers: &HeaderMap,
    action: &str,
    scope: ScopeRef,
) -> Result<Option<PrincipalRef>, Response>
where
    S: PolicyStore + ApiTokenRepository + ApiTokenOwnerRepository,
{
    admit_with_token(guard, headers, action, scope).map(|token| token.map(|token| token.principal))
}

/// Retain the original authenticated service token for callers which must also
/// fence its Workspace. Administrator admission remains the explicit None case.
/// Every invocation reads and verifies the current native credential; this is
/// a request-local observation, never an authentication cache.
#[allow(clippy::result_large_err)]
pub(super) fn admit_with_token<S>(
    guard: &mut DaemonState<S>,
    headers: &HeaderMap,
    action: &str,
    scope: ScopeRef,
) -> Result<Option<ApiToken>, Response>
where
    S: PolicyStore + ApiTokenRepository + ApiTokenOwnerRepository,
{
    let Some(token) = authenticate_service_token(guard, headers)? else {
        return Ok(None);
    };
    let request =
        AuthorizationRequest::direct(token.principal.clone(), ActionKey(action.into()), scope);
    let mut allowed = false;
    let rendered = guard.with_fresh_authorization(|authz| {
        allowed = authz.authorize(&request).decision == AuthorizationDecision::Allow;
        StatusCode::OK.into_response()
    });
    if rendered.status() != StatusCode::OK {
        return Err(rendered);
    }
    if !allowed {
        return Err(error_response(
            StatusCode::FORBIDDEN,
            "forbidden",
            "the service account lacks this access administration action",
        ));
    }
    Ok(Some(token))
}

/// Reuse the current native credential owner without selecting a policy source.
/// Compound scoped protocols subsequently evaluate the exact native capability.
#[allow(clippy::result_large_err)]
pub(super) fn authenticate_service_token<S>(
    guard: &DaemonState<S>,
    headers: &HeaderMap,
) -> Result<Option<ApiToken>, Response>
where
    S: PolicyStore + ApiTokenRepository + ApiTokenOwnerRepository,
{
    match directory_credential_access(&guard.auth, headers) {
        Ok(DirectoryCredentialAccess::Administrator) => return Ok(None),
        Ok(DirectoryCredentialAccess::Product(_)) => {
            return Err(error_response(
                StatusCode::FORBIDDEN,
                "forbidden",
                "the presented product credential may not administer access",
            ));
        }
        Err(_) => {}
    }
    let presented = headers
        .get("authorization")
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.strip_prefix("Bearer "))
        .ok_or_else(|| DirectoryCredentialRejection::Missing.into_response())?;
    let store = guard.admin.store();
    let token = match authenticate_stored_api_token(store, presented, &now_timestamp()) {
        Ok(Some(token)) => token,
        Ok(None) => {
            return Err(error_response(
                StatusCode::UNAUTHORIZED,
                "invalid_credential",
                "the presented credential is not a live API token",
            ));
        }
        Err(error) => return Err(admin_error_response(&AdminError::from(error))),
    };
    let owned = match store.api_token_owner(&token.id) {
        Ok(owner) => owner.is_some(),
        Err(error) => return Err(admin_error_response(&AdminError::from(error))),
    };
    if !owned || !matches!(token.principal, PrincipalRef::Service { .. }) {
        return Err(error_response(
            StatusCode::FORBIDDEN,
            "forbidden",
            "access administration needs an owned service-account token",
        ));
    }
    Ok(Some(token))
}

async fn replace_team_access<S>(
    State(state): State<SharedDaemonState<S>>,
    headers: HeaderMap,
    Json(command): Json<TeamAccessReplacement>,
) -> Response
where
    S: PolicyStore + PrincipalAccessStore + ApiTokenRepository + ApiTokenOwnerRepository,
{
    let mut guard = lock(&state);
    let scope = ScopeRef::Workspace {
        workspace_id: command.workspace_id.clone(),
    };
    let actor = match admit(&mut guard, &headers, ACTION_PRINCIPAL_ACCESS_REPLACE, scope) {
        Ok(actor) => actor,
        Err(rejection) => return rejection,
    };
    match guard
        .admin
        .replace_team_access(command, actor, now_timestamp())
    {
        Ok(receipt) => match guard.refresh_authorization(receipt.version) {
            Ok(()) => Json(receipt).into_response(),
            Err(error) => admin_error_response(&error),
        },
        Err(AdminError::AlreadyExists(message)) if message.starts_with("stale_access_fence") => {
            error_response(StatusCode::CONFLICT, "stale_access_fence", &message)
        }
        Err(error) => admin_error_response(&error),
    }
}

async fn read_active_profile<S>(
    State(state): State<SharedDaemonState<S>>,
    headers: HeaderMap,
    Path(namespace): Path<String>,
) -> Response
where
    S: PolicyStore + ApiTokenRepository + ApiTokenOwnerRepository,
{
    let mut guard = lock(&state);
    let scope = ScopeRef::Namespace {
        namespace_id: NamespaceId(namespace.clone()),
    };
    if let Err(rejection) = admit(&mut guard, &headers, ACTION_AUTHZ_PROFILE_READ, scope) {
        return rejection;
    }
    match guard.profiles.active(&NamespaceId(namespace)) {
        Ok(Some(profile)) => Json(profile).into_response(),
        // A typed body lets a consumer tell "no profile" from a missing route.
        Ok(None) => error_response(
            StatusCode::NOT_FOUND,
            "no_active_profile",
            "the namespace has no active profile",
        ),
        Err(error) => profile_error_response(&error),
    }
}
