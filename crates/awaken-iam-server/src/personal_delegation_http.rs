//! Explicit owner consent, recipient minting, and conjunctive live evaluation.
use crate::personal_delegation::*;
use crate::{PolicyStore, SharedAuthApi, SharedDaemonState};
use awaken_iam_contract::*;
use awaken_iam_core::{
    AccountRepository, OAuthClientRepository, PersonalDelegationRepository, RegisteredClient,
    RepositoryError, validate_personal_consent,
};
use axum::{
    Json, Router,
    extract::{Path, Query, State},
    http::{HeaderMap, StatusCode},
    routing::{get, post},
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::sync::Arc;

type Failure = (StatusCode, Json<serde_json::Value>);
fn failure(status: StatusCode, code: &str) -> Failure {
    (status, Json(serde_json::json!({"error":code})))
}
fn denied() -> Failure {
    failure(StatusCode::FORBIDDEN, "personal_delegation_denied")
}
fn unavailable() -> Failure {
    failure(
        StatusCode::SERVICE_UNAVAILABLE,
        "personal_delegation_unavailable",
    )
}
fn storage(e: RepositoryError) -> Failure {
    match e {
        RepositoryError::Conflict(_) => {
            failure(StatusCode::CONFLICT, "personal_delegation_conflict")
        }
        RepositoryError::NotFound(_) => {
            failure(StatusCode::NOT_FOUND, "personal_delegation_not_found")
        }
        _ => unavailable(),
    }
}
#[derive(Clone)]
struct PersonalState<S> {
    auth: SharedAuthApi,
    daemon: SharedDaemonState<S>,
    store: Arc<S>,
    issuer: String,
}

/// Mount explicitly beside OP and native authorization routes using the same
/// SQL store, signer, identity owner, and current policy fence.
pub fn personal_delegation_router<S>(
    auth: SharedAuthApi,
    daemon: SharedDaemonState<S>,
    store: Arc<S>,
    issuer: String,
) -> Router
where
    S: PolicyStore
        + PersonalDelegationRepository
        + OAuthClientRepository
        + AccountRepository
        + Clone
        + 'static,
{
    Router::new()
        .route("/v1/personal-delegations", post(create::<S>).get(list::<S>))
        .route("/v1/personal-delegations/{id}", get(read::<S>))
        .route("/v1/personal-delegations/{id}/revoke", post(revoke::<S>))
        .route("/v1/personal-delegations/token", post(token::<S>))
        .route("/v1/personal-delegations/inspect", post(inspect::<S>))
        .route("/v1/authorize/personal-delegation", post(authorize::<S>))
        .with_state(PersonalState {
            auth,
            daemon,
            store,
            issuer,
        })
}
fn bearer(headers: &HeaderMap) -> Result<&str, Failure> {
    headers
        .get("authorization")
        .and_then(|v| v.to_str().ok())
        .and_then(|s| s.strip_prefix("Bearer "))
        .filter(|s| !s.is_empty())
        .ok_or_else(denied)
}
fn current_account<S: AccountRepository>(
    state: &PersonalState<S>,
    id: &AccountId,
) -> Result<(), Failure> {
    match state.store.get(id).map_err(storage)? {
        Some(a) if a.status == AccountStatus::Active => Ok(()),
        _ => Err(denied()),
    }
}
async fn owner<S: AccountRepository>(
    state: &PersonalState<S>,
    headers: &HeaderMap,
    now: i64,
) -> Result<AccountId, Failure> {
    let verified = state
        .auth
        .lock()
        .await
        .verify_delegated_access_token(bearer(headers)?)
        .map_err(|_| denied())?;
    let c = verified.claims;
    if verified.act.is_some()
        || c.iss != state.issuer
        || c.aud != PERSONAL_DELEGATION_CONSENT_AUDIENCE
        || c.iat > now
        || c.exp <= now
        || c.subject_kind != crate::AccessTokenSubjectKind::Account
        || !c
            .scope
            .iter()
            .any(|s| s == PERSONAL_DELEGATION_CONSENT_SCOPE)
    {
        return Err(denied());
    }
    let account = AccountId(c.sub);
    current_account(state, &account)?;
    Ok(account)
}
async fn list<S>(
    State(state): State<PersonalState<S>>,
    headers: HeaderMap,
    Query(query): Query<ListPersonalDelegations>,
) -> Result<Json<PersonalDelegationPage>, Failure>
where
    S: AccountRepository + PersonalDelegationRepository,
{
    let now = crate::clock::unix_seconds() as i64;
    let account = owner(&state, &headers, now).await?;
    if !(1..=100).contains(&query.limit)
        || query.after.as_ref().is_some_and(|cursor| {
            cursor.is_empty() || cursor.len() > 300 || cursor.trim() != cursor
        })
    {
        return Err(failure(
            StatusCode::BAD_REQUEST,
            "personal_delegation_invalid_page",
        ));
    }
    Ok(Json(
        state
            .store
            .list_personal_delegations(&account, &query)
            .map_err(storage)?,
    ))
}
fn recipient<S: OAuthClientRepository>(
    state: &PersonalState<S>,
    id: &str,
    audience: &str,
) -> Result<RegisteredClient, Failure> {
    let client = state.store.get(id).map_err(storage)?.ok_or_else(denied)?;
    if !client.is_confidential()
        || !client
            .allowed_scopes
            .contains(PERSONAL_DELEGATION_CLIENT_SCOPE)
        || !client
            .token_exchange
            .delegation
            .as_ref()
            .is_some_and(|d| d.audiences.contains(audience))
    {
        return Err(denied());
    }
    Ok(client)
}
fn evaluate<S: PolicyStore>(
    state: &PersonalState<S>,
    request: &ResourceAuthorizationRequest,
) -> Result<AuthorizationOutcome, Failure> {
    state
        .daemon
        .lock()
        .map_err(|_| unavailable())?
        .authorize_current_resource(request)
        .map_err(|_| unavailable())
}
fn chain(
    grant: &PersonalDelegation,
    action: ActionKey,
    scope: ScopeRef,
    now: i64,
) -> ResourceAuthorizationRequest {
    ResourceAuthorizationRequest {
        request: AuthorizationRequest {
            principal: PrincipalRef::Service {
                service_id: grant.service_id.clone(),
            },
            on_behalf_of: vec![PrincipalRef::Account {
                account_id: grant.owner.clone(),
            }],
            action,
            scope,
        },
        context: AuthorizationContext {
            evaluated_at: Some(now * 1000),
            ..Default::default()
        },
    }
}
async fn create<S>(
    State(state): State<PersonalState<S>>,
    headers: HeaderMap,
    Json(consent): Json<CreatePersonalDelegation>,
) -> Result<Json<PersonalDelegation>, Failure>
where
    S: PolicyStore + PersonalDelegationRepository + OAuthClientRepository + AccountRepository,
{
    let now = crate::clock::unix_seconds() as i64;
    let owner = owner(&state, &headers, now).await?;
    // The original intent stays recoverable even after expiry, revocation or a
    // policy change. No new consent is created on this branch.
    let id = format!(
        "pd_{:x}",
        Sha256::digest(serde_json::to_vec(&(&owner, &consent.request_key)).map_err(|_| denied())?)
    );
    if let Some(stored) = state.store.personal_delegation(&id).map_err(storage)? {
        if stored.owner != owner || stored.consent != consent {
            return Err(failure(
                StatusCode::CONFLICT,
                "personal_delegation_conflict",
            ));
        }
        return Ok(Json(stored));
    }
    validate_personal_consent(&consent, now)
        .map_err(|_| failure(StatusCode::BAD_REQUEST, "invalid_personal_consent"))?;
    let client = recipient(&state, &consent.recipient_client_id, &consent.audience)?;
    let grant = PersonalDelegation {
        id,
        owner,
        service_id: client
            .token_exchange
            .delegation
            .as_ref()
            .ok_or_else(denied)?
            .service_id
            .clone(),
        consent,
        created_at: now,
        revoked_at: None,
        version: 1,
    };
    // Consent grants no policy authority. Only the native operation owner can
    // resolve amount/initiator/data-scope facts; evaluating incomplete facts
    // here would prevent every person with a bounded amount grant consenting.
    // The compound use endpoint always evaluates those exact current facts.
    Ok(Json(
        state
            .store
            .create_personal_delegation(grant)
            .map_err(storage)?,
    ))
}
async fn read<S>(
    State(state): State<PersonalState<S>>,
    Path(id): Path<String>,
    headers: HeaderMap,
) -> Result<Json<PersonalDelegation>, Failure>
where
    S: PersonalDelegationRepository + AccountRepository,
{
    let owner = owner(&state, &headers, crate::clock::unix_seconds() as i64).await?;
    let grant = state
        .store
        .personal_delegation(&id)
        .map_err(storage)?
        .filter(|g| g.owner == owner)
        .ok_or_else(denied)?;
    Ok(Json(grant))
}
async fn revoke<S>(
    State(state): State<PersonalState<S>>,
    Path(id): Path<String>,
    headers: HeaderMap,
) -> Result<Json<PersonalDelegation>, Failure>
where
    S: PersonalDelegationRepository + AccountRepository,
{
    let now = crate::clock::unix_seconds() as i64;
    let owner = owner(&state, &headers, now).await?;
    Ok(Json(
        state
            .store
            .revoke_personal_delegation(&id, &owner, now)
            .map_err(storage)?,
    ))
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct TokenRequest {
    client_id: String,
    client_secret: String,
    binding: MintPersonalDelegationToken,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct InspectRequest {
    client_id: String,
    client_secret: String,
    grant_id: String,
}
async fn inspect<S>(
    State(state): State<PersonalState<S>>,
    Json(body): Json<InspectRequest>,
) -> Result<Json<PersonalDelegation>, Failure>
where
    S: PersonalDelegationRepository + OAuthClientRepository + AccountRepository,
{
    let client = state
        .auth
        .lock()
        .await
        .personal_recipient(&body.client_id, &body.client_secret)
        .map_err(|_| denied())?;
    let grant = state
        .store
        .personal_delegation(&body.grant_id)
        .map_err(storage)?
        .ok_or_else(denied)?;
    let admitted = recipient(&state, &client.client_id, &grant.consent.audience)?;
    if grant.consent.recipient_client_id != client.client_id
        || admitted
            .token_exchange
            .delegation
            .as_ref()
            .is_none_or(|d| d.service_id != grant.service_id)
    {
        return Err(denied());
    }
    current_account(&state, &grant.owner)?;
    Ok(Json(grant))
}
#[derive(Serialize)]
struct TokenResponse {
    access_token: String,
    token_type: &'static str,
    expires_in: i64,
}
async fn token<S>(
    State(state): State<PersonalState<S>>,
    Json(body): Json<TokenRequest>,
) -> Result<Json<TokenResponse>, Failure>
where
    S: PersonalDelegationRepository + OAuthClientRepository + AccountRepository,
{
    let now = crate::clock::unix_seconds() as i64;
    let auth = state.auth.lock().await;
    let client = auth
        .personal_recipient(&body.client_id, &body.client_secret)
        .map_err(|_| denied())?;
    let grant = state
        .store
        .personal_delegation(&body.binding.grant_id)
        .map_err(storage)?
        .ok_or_else(denied)?;
    current_account(&state, &grant.owner)?;
    let admitted = recipient(&state, &client.client_id, &grant.consent.audience)?;
    if grant.consent.recipient_client_id != client.client_id
        || admitted
            .token_exchange
            .delegation
            .as_ref()
            .is_none_or(|d| d.service_id != grant.service_id)
        || !grant.consent.actions.contains(&body.binding.action)
        || !grant.consent.scopes.contains(&body.binding.scope)
        || !crate::personal_delegation::binding_shape_is_valid(&body.binding)
        || crate::personal_delegation::bounded_by_consent(body.binding.purpose)
            && (grant.revoked_at.is_some()
                || now < grant.consent.valid_from
                || now >= grant.consent.valid_until)
    {
        return Err(denied());
    }
    let exp = if crate::personal_delegation::bounded_by_consent(body.binding.purpose) {
        (now + 300).min(grant.consent.valid_until)
    } else {
        now + 300
    };
    let access_token = crate::personal_delegation::mint(
        &auth.token_authority(),
        &grant,
        body.binding,
        &state.issuer,
        now,
    )
    .await
    .map_err(|_| denied())?;
    Ok(Json(TokenResponse {
        access_token,
        token_type: "Bearer",
        expires_in: exp - now,
    }))
}
async fn authorize<S>(
    State(state): State<PersonalState<S>>,
    Json(body): Json<AuthorizePersonalDelegation>,
) -> Result<Json<AuthorizationOutcome>, Failure>
where
    S: PolicyStore + PersonalDelegationRepository + OAuthClientRepository + AccountRepository,
{
    let now = crate::clock::unix_seconds() as i64;
    let claims = verify_personal_delegation_token(
        &body.token,
        &state.auth.lock().await.jwks(),
        &state.issuer,
        &body.audience,
        now,
    )
    .map_err(|_| denied())?;
    let grant = state
        .store
        .personal_delegation(&claims.grant_id)
        .map_err(storage)?
        .ok_or_else(denied)?;
    current_account(&state, &grant.owner)?;
    let client = recipient(&state, &claims.client_id, &claims.aud)?;
    let target_matches = match claims.binding.purpose {
        PersonalDelegationPurpose::Execute => body
            .target
            .as_ref()
            .is_some_and(|target| claims.binding.target.as_ref() == Some(target)),
        PersonalDelegationPurpose::Read => body.target.is_none(),
        PersonalDelegationPurpose::OriginalOutcome => false,
    };
    if !target_matches
        || grant.revoked_at.is_some()
        || now < grant.consent.valid_from
        || now >= grant.consent.valid_until
        || claims.sub != grant.owner.0
        || claims.service_id != grant.service_id
        || claims.client_id != grant.consent.recipient_client_id
        || claims.aud != grant.consent.audience
        || client
            .token_exchange
            .delegation
            .as_ref()
            .is_none_or(|d| d.service_id != grant.service_id)
        || claims.binding.action != body.request.request.action
        || claims.binding.scope != body.request.request.scope
        || !grant.consent.actions.contains(&claims.binding.action)
        || !grant.consent.scopes.contains(&claims.binding.scope)
    {
        return Err(denied());
    }
    let expected = chain(
        &grant,
        body.request.request.action.clone(),
        body.request.request.scope.clone(),
        now,
    );
    if expected.request != body.request.request {
        return Err(denied());
    }
    let mut request = body.request;
    request.context.evaluated_at = Some(now * 1000);
    Ok(Json(evaluate(&state, &request)?))
}
