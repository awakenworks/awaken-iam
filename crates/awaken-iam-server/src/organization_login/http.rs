//! Product-independent HTTP binding; the host injects its existing access and audit owners.

use super::{
    CreateConnection, OrganizationLoginError as Error, OrganizationLoginService, UpdateConnection,
};
use awaken_iam_contract::{AccountId, OrgId, UserInfo};
use awaken_iam_core::AuditEvent;
use axum::{
    Json, Router,
    extract::{DefaultBodyLimit, Path, State},
    http::{HeaderMap, StatusCode, header},
    response::{IntoResponse, Response},
    routing::{get, put},
};
use serde::Deserialize;
use std::sync::Arc;

/// Current identity, organization administration and audit remain with the host's
/// canonical IAM composition. Implementations delegate; this port issues no token.
#[async_trait::async_trait]
pub trait OrganizationLoginAccess: Send + Sync {
    async fn userinfo(&self, headers: &HeaderMap, audience: &str) -> Result<UserInfo, StatusCode>;
    async fn administrator(
        &self,
        headers: &HeaderMap,
        audience: &str,
        org: &str,
    ) -> Result<AccountId, StatusCode>;
    fn audit(&self, event: AuditEvent) -> Result<(), Error>;
}

/// Static route binding over an already-registered IAM product/client. It is
/// neither a product registry nor a second identity/credential authority.
#[derive(Clone)]
pub struct OrganizationLoginProduct {
    pub service: Arc<OrganizationLoginService>,
    pub audience: String,
}

#[derive(Clone)]
struct HttpState {
    products: Vec<OrganizationLoginProduct>,
    access: Arc<dyn OrganizationLoginAccess>,
}
impl HttpState {
    fn product(&self, id: &str) -> Result<OrganizationLoginProduct, Response> {
        self.products
            .iter()
            .find(|value| value.service.product_id().as_str() == id)
            .cloned()
            .ok_or_else(|| StatusCode::NOT_FOUND.into_response())
    }
}

pub fn organization_login_router(
    products: Vec<OrganizationLoginProduct>,
    access: Arc<dyn OrganizationLoginAccess>,
) -> Result<Router, Error> {
    let mut ids = std::collections::HashSet::new();
    if products.iter().any(|product| {
        product.audience.trim().is_empty() || !ids.insert(product.service.product_id().clone())
    }) {
        return Err(Error::Invalid);
    }
    Ok(Router::new()
        .route("/v1/products/{product}/userinfo", get(userinfo))
        .route(
            "/v1/products/{product}/organizations/{org}/login-connections",
            get(list).post(create),
        )
        .route(
            "/v1/products/{product}/organizations/{org}/login-connections/{id}",
            put(update).delete(remove),
        )
        .route(
            "/v1/products/{product}/organizations/{org}/login-options",
            get(options),
        )
        .layer(DefaultBodyLimit::max(16 * 1024))
        .with_state(HttpState { products, access }))
}

async fn userinfo(
    State(state): State<HttpState>,
    Path(product): Path<String>,
    headers: HeaderMap,
) -> Response {
    let product = match state.product(&product) {
        Ok(value) => value,
        Err(response) => return response,
    };
    match state.access.userinfo(&headers, &product.audience).await {
        Ok(info) => ([(header::CACHE_CONTROL, "no-store")], Json(info)).into_response(),
        Err(status) => status.into_response(),
    }
}

async fn authorized(
    state: &HttpState,
    headers: &HeaderMap,
    product: &str,
    org: &str,
) -> Result<(Arc<OrganizationLoginService>, AccountId), Response> {
    let product = state.product(product)?;
    let actor = state
        .access
        .administrator(headers, &product.audience, org)
        .await
        .map_err(IntoResponse::into_response)?;
    Ok((product.service, actor))
}

async fn list(
    State(state): State<HttpState>,
    Path((product, org)): Path<(String, String)>,
    headers: HeaderMap,
) -> Response {
    let (service, _) = match authorized(&state, &headers, &product, &org).await {
        Ok(value) => value,
        Err(response) => return response,
    };
    respond(tokio::task::spawn_blocking(move || service.settings(&OrgId(org))).await)
}
async fn options(
    State(state): State<HttpState>,
    Path((product, org)): Path<(String, String)>,
) -> Response {
    let service = match state.product(&product) {
        Ok(value) => value.service,
        Err(response) => return response,
    };
    respond(tokio::task::spawn_blocking(move || service.options(&OrgId(org))).await)
}
async fn create(
    State(state): State<HttpState>,
    Path((product, org)): Path<(String, String)>,
    headers: HeaderMap,
    Json(body): Json<CreateConnection>,
) -> Response {
    let (service, actor) = match authorized(&state, &headers, &product, &org).await {
        Ok(value) => value,
        Err(response) => return response,
    };
    respond(
        tokio::task::spawn_blocking(move || {
            audited(
                state.access.as_ref(),
                &actor,
                &product,
                &org,
                None,
                "create",
                || service.create(&OrgId(org.clone()), body),
            )
        })
        .await,
    )
}
async fn update(
    State(state): State<HttpState>,
    Path((product, org, id)): Path<(String, String, String)>,
    headers: HeaderMap,
    Json(body): Json<UpdateConnection>,
) -> Response {
    let (service, actor) = match authorized(&state, &headers, &product, &org).await {
        Ok(value) => value,
        Err(response) => return response,
    };
    respond(
        tokio::task::spawn_blocking(move || {
            audited(
                state.access.as_ref(),
                &actor,
                &product,
                &org,
                Some(&id),
                "update",
                || service.update(&OrgId(org.clone()), &id, body),
            )
        })
        .await,
    )
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RemoveConnection {
    version: String,
}
async fn remove(
    State(state): State<HttpState>,
    Path((product, org, id)): Path<(String, String, String)>,
    headers: HeaderMap,
    Json(body): Json<RemoveConnection>,
) -> Response {
    let (service, actor) = match authorized(&state, &headers, &product, &org).await {
        Ok(value) => value,
        Err(response) => return response,
    };
    match tokio::task::spawn_blocking(move || {
        audited(
            state.access.as_ref(),
            &actor,
            &product,
            &org,
            Some(&id),
            "remove",
            || service.remove(&OrgId(org.clone()), &id, &body.version),
        )
    })
    .await
    {
        Ok(Ok(())) => StatusCode::NO_CONTENT.into_response(),
        Ok(Err(error)) => response_error(error),
        Err(_) => response_error(Error::Unavailable),
    }
}

fn audited<T>(
    audit: &dyn OrganizationLoginAccess,
    actor: &AccountId,
    product: &str,
    org: &str,
    connection: Option<&str>,
    action: &str,
    operation: impl FnOnce() -> Result<T, Error>,
) -> Result<T, Error> {
    let mut nonce = [0u8; 16];
    getrandom::fill(&mut nonce).map_err(|_| Error::Unavailable)?;
    let operation_id = super::model::hex(&nonce);
    let record = |phase: &str| {
        audit.audit(AuditEvent {
        at: awaken_iam_contract::Timestamp(time::OffsetDateTime::now_utc().format(&time::format_description::well_known::Rfc3339).map_err(|_|Error::Unavailable)?),
        actor:Some(awaken_iam_contract::PrincipalRef::Account {account_id:actor.clone()}),
        action:format!("institution_login.{action}"),
        detail:serde_json::json!({"operation_id":operation_id,"product_id":product,"organization_id":org,"connection_id":connection,"phase":phase}).to_string(),
    })
    };
    record("attempt").map_err(|_| Error::Unavailable)?;
    let result = operation();
    record(if result.is_ok() {
        "confirmed"
    } else {
        "failed_or_uncertain"
    })
    .map_err(|_| Error::Uncertain)?;
    result
}
fn respond<T: serde::Serialize>(
    result: Result<Result<T, Error>, tokio::task::JoinError>,
) -> Response {
    match result {
        Ok(Ok(value)) => Json(value).into_response(),
        Ok(Err(error)) => response_error(error),
        Err(_) => response_error(Error::Unavailable),
    }
}
fn response_error(error: Error) -> Response {
    let (status, code) = match error {
        Error::Invalid => (StatusCode::BAD_REQUEST, "INSTITUTION_LOGIN_INVALID"),
        Error::NotFound => (StatusCode::NOT_FOUND, "INSTITUTION_LOGIN_NOT_FOUND"),
        Error::Conflict => (StatusCode::CONFLICT, "INSTITUTION_LOGIN_CONFLICT"),
        Error::Busy => (StatusCode::CONFLICT, "INSTITUTION_LOGIN_BUSY"),
        Error::Unavailable => (
            StatusCode::SERVICE_UNAVAILABLE,
            "INSTITUTION_LOGIN_UNAVAILABLE",
        ),
        Error::Uncertain => (
            StatusCode::SERVICE_UNAVAILABLE,
            "INSTITUTION_LOGIN_UNCERTAIN",
        ),
    };
    (
        status,
        Json(serde_json::json!({"code":code,"detail":error.to_string()})),
    )
        .into_response()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::{
        Mutex,
        atomic::{AtomicUsize, Ordering},
    };
    struct Access {
        events: Mutex<Vec<AuditEvent>>,
        fail_at: usize,
        calls: AtomicUsize,
    }
    #[async_trait::async_trait]
    impl OrganizationLoginAccess for Access {
        async fn userinfo(&self, _: &HeaderMap, _: &str) -> Result<UserInfo, StatusCode> {
            unreachable!("audit test authenticates no caller")
        }
        async fn administrator(
            &self,
            _: &HeaderMap,
            _: &str,
            _: &str,
        ) -> Result<AccountId, StatusCode> {
            unreachable!("audit test authenticates no caller")
        }
        fn audit(&self, event: AuditEvent) -> Result<(), Error> {
            let call = self.calls.fetch_add(1, Ordering::SeqCst);
            if call == self.fail_at {
                return Err(Error::Unavailable);
            }
            self.events.lock().unwrap().push(event);
            Ok(())
        }
    }
    #[test]
    fn audit_attempt_fences_the_effect_and_final_failure_reports_uncertainty() {
        // Causes C1 attempt audit succeeds/fails; C2 remote effect succeeds/fails;
        // C3 final audit succeeds/fails. A1 !C1 => unavailable, zero effect;
        // A2 C1+!C3 => uncertain after exactly one effect, no rollback;
        // A3 C1+C3 => preserve effect result and two correlated safe events.
        for fail_at in [0, 1, usize::MAX] {
            for effect_succeeds in [false, true] {
                let access = Access {
                    events: Mutex::new(Vec::new()),
                    fail_at,
                    calls: AtomicUsize::new(0),
                };
                let effects = std::cell::Cell::new(0);
                let result = audited(
                    &access,
                    &AccountId("admin".into()),
                    "any-product",
                    "org",
                    Some("connection"),
                    "create",
                    || {
                        effects.set(effects.get() + 1);
                        if effect_succeeds {
                            Ok("secret-result-marker")
                        } else {
                            Err(Error::Conflict)
                        }
                    },
                );
                assert_eq!(effects.get(), usize::from(fail_at != 0));
                match fail_at {
                    0 => assert_eq!(result, Err(Error::Unavailable)),
                    1 => assert_eq!(result, Err(Error::Uncertain)),
                    _ => {
                        assert_eq!(
                            result,
                            if effect_succeeds {
                                Ok("secret-result-marker")
                            } else {
                                Err(Error::Conflict)
                            }
                        );
                        let events = access.events.lock().unwrap();
                        assert_eq!(events.len(), 2);
                        let details: Vec<serde_json::Value> = events
                            .iter()
                            .map(|event| serde_json::from_str(&event.detail).unwrap())
                            .collect();
                        assert_eq!(details[0]["operation_id"], details[1]["operation_id"]);
                        assert_eq!(details[0]["phase"], "attempt");
                        assert!(
                            events
                                .iter()
                                .all(|event| event.action == "institution_login.create"),
                            "retain the deployed audit event name"
                        );
                        assert_eq!(details[0]["product_id"], "any-product");
                        assert!(
                            events
                                .iter()
                                .all(|event| !event.detail.contains("secret-result-marker"))
                        );
                    }
                }
            }
        }
    }
}
