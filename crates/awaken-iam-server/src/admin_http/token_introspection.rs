//! Resolve API credentials from current native storage, never startup snapshots.
use super::*;
use awaken_iam_contract::{ApiTokenStatus, TokenIntrospectionRequest, TokenIntrospectionResponse};
use awaken_iam_core::{ApiTokenRepository, authenticate_stored_api_token};

pub(super) async fn introspect<S>(
    State(state): State<SharedDaemonState<S>>,
    Json(request): Json<TokenIntrospectionRequest>,
) -> Response
where
    S: PolicyStore + ApiTokenRepository + Clone + 'static,
{
    // Clone the native repository handle without retaining the daemon mutex
    // across storage I/O or Argon2. This reads issuance/revocation independently
    // of the policy cache's version marker on every replica.
    let store = lock(&state).admin.store().clone();
    match tokio::task::spawn_blocking(move || {
        authenticate_stored_api_token(&store, &request.token, &now_timestamp())
    })
    .await
    {
        Ok(Ok(Some(token))) => Json(TokenIntrospectionResponse {
            principal: token.principal,
            workspace: token.workspace,
            status: ApiTokenStatus::Active,
        })
        .into_response(),
        Ok(Ok(None)) => StatusCode::UNAUTHORIZED.into_response(),
        Ok(Err(_)) | Err(_) => error_response(
            StatusCode::SERVICE_UNAVAILABLE,
            "credential_unavailable",
            "credential verification is unavailable",
        ),
    }
}
