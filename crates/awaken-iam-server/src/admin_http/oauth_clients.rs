//! Downstream OAuth client administration over `/v1/admin/oauth-clients`.
//!
//! Every client kind obeys one redirect rule (HTTPS, or HTTP on a loopback
//! host) enforced by [`OAuthClientAdminApi`], and may carry an
//! administrator-owned RFC 8693 token-exchange policy (ADR-0017).

use awaken_iam_core::ClientTokenExchangePolicy;

use super::*;

#[derive(Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub(super) enum OAuthClientRegistration {
    Public {
        client_id: String,
        redirect_uris: Vec<String>,
        allowed_scopes: Vec<String>,
        #[serde(default)]
        token_exchange: ClientTokenExchangePolicy,
    },
    Confidential {
        client_id: String,
        redirect_uris: Vec<String>,
        allowed_scopes: Vec<String>,
        #[serde(default)]
        token_exchange: ClientTokenExchangePolicy,
    },
}

fn oauth_client_view(client: RegisteredClient) -> serde_json::Value {
    serde_json::json!({
        "client_id": client.client_id,
        "kind": if client.secret_hash.is_some() { "confidential" } else { "public" },
        "redirect_uris": client.redirect_uris,
        "allowed_scopes": client.allowed_scopes,
        "token_exchange": client.token_exchange,
    })
}

pub(super) async fn register_oauth_client(
    State(state): State<SharedDaemonState<impl PolicyStore + OAuthClientRepository>>,
    headers: HeaderMap,
    Json(request): Json<OAuthClientRegistration>,
) -> Response {
    let mut guard = lock(&state);
    if let Some(rejection) = authorize_admin(&guard.auth, &headers) {
        return rejection;
    }
    let now = now_timestamp();
    match request {
        OAuthClientRegistration::Public {
            client_id,
            redirect_uris,
            allowed_scopes,
            token_exchange,
        } => {
            let client = RegisteredClient::public(client_id, redirect_uris, allowed_scopes)
                .with_token_exchange(token_exchange);
            match guard.oauth_clients.register(client.clone(), now) {
                Ok(_) => (
                    StatusCode::CREATED,
                    Json(serde_json::json!({
                        "client": oauth_client_view(client),
                    })),
                )
                    .into_response(),
                Err(error) => admin_error_response(&error),
            }
        }
        OAuthClientRegistration::Confidential {
            client_id,
            redirect_uris,
            allowed_scopes,
            token_exchange,
        } => match guard.oauth_clients.register_confidential_with_exchange(
            client_id,
            redirect_uris,
            allowed_scopes,
            token_exchange,
            &mut OsEntropy,
            now,
        ) {
            Ok((_, issued)) => (
                StatusCode::CREATED,
                Json(serde_json::json!({
                    "client_id": issued.client_id, "client_secret": issued.secret,
                })),
            )
                .into_response(),
            Err(error) => admin_error_response(&error),
        },
    }
}

pub(super) async fn list_oauth_clients(
    State(state): State<SharedDaemonState<impl PolicyStore + OAuthClientRepository>>,
    headers: HeaderMap,
) -> Response {
    let guard = lock(&state);
    if let Some(rejection) = authorize_admin(&guard.auth, &headers) {
        return rejection;
    }
    match guard.oauth_clients.list_clients() {
        Ok(clients) => Json(serde_json::json!({
            "clients": clients.into_iter().map(oauth_client_view).collect::<Vec<_>>()
        }))
        .into_response(),
        Err(error) => admin_error_response(&error),
    }
}

pub(super) async fn get_oauth_client(
    State(state): State<SharedDaemonState<impl PolicyStore + OAuthClientRepository>>,
    headers: HeaderMap,
    Path(id): Path<String>,
) -> Response {
    let guard = lock(&state);
    if let Some(rejection) = authorize_admin(&guard.auth, &headers) {
        return rejection;
    }
    match guard.oauth_clients.get_client(&id) {
        Ok(Some(client)) => Json(oauth_client_view(client)).into_response(),
        Ok(None) => error_response(StatusCode::NOT_FOUND, "not_found", "oauth client not found"),
        Err(error) => admin_error_response(&error),
    }
}

pub(super) async fn rotate_oauth_client_secret(
    State(state): State<SharedDaemonState<impl PolicyStore + OAuthClientRepository>>,
    headers: HeaderMap,
    Path(id): Path<String>,
) -> Response {
    let mut guard = lock(&state);
    if let Some(rejection) = authorize_admin(&guard.auth, &headers) {
        return rejection;
    }
    match guard
        .oauth_clients
        .rotate_secret(&id, &mut OsEntropy, now_timestamp())
    {
        Ok(issued) => Json(serde_json::json!({
            "client_id": issued.client_id, "client_secret": issued.secret,
        }))
        .into_response(),
        Err(error) => admin_error_response(&error),
    }
}

/// `PUT /v1/admin/oauth-clients/{id}/token-exchange`: replace the client's
/// RFC 8693 admission. An empty body object clears it.
pub(super) async fn replace_oauth_client_token_exchange(
    State(state): State<SharedDaemonState<impl PolicyStore + OAuthClientRepository>>,
    headers: HeaderMap,
    Path(id): Path<String>,
    Json(policy): Json<ClientTokenExchangePolicy>,
) -> Response {
    let mut guard = lock(&state);
    if let Some(rejection) = authorize_admin(&guard.auth, &headers) {
        return rejection;
    }
    match guard
        .oauth_clients
        .replace_token_exchange(&id, policy, now_timestamp())
    {
        Ok(client) => Json(oauth_client_view(client)).into_response(),
        Err(error) => admin_error_response(&error),
    }
}

pub(super) async fn deregister_oauth_client(
    State(state): State<SharedDaemonState<impl PolicyStore + OAuthClientRepository>>,
    headers: HeaderMap,
    Path(id): Path<String>,
) -> Response {
    let mut guard = lock(&state);
    if let Some(rejection) = authorize_admin(&guard.auth, &headers) {
        return rejection;
    }
    match guard.oauth_clients.deregister(&id, now_timestamp()) {
        Ok(_) => Json(serde_json::json!({ "deleted": true })).into_response(),
        Err(error) => admin_error_response(&error),
    }
}
