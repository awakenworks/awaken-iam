//! WeChat Mini Program `wx.login` code exchange bound to canonical IAM accounts.

use std::collections::HashMap;
use std::sync::Arc;

use async_trait::async_trait;
use awaken_iam_contract::{
    ExternalIdentityClaims, ExternalSubject, IdentityProviderKey, WechatMiniProgramTokenRequest,
    WechatMiniProgramTokenResponse,
};
use axum::extract::State;
use axum::http::StatusCode;
use axum::routing::post;
use axum::{Json, Router};
use serde::Deserialize;

use crate::op_http::SharedAuthApi;
use crate::{AuthApiError, IssueTokenGrant};

const ACCESS_TOKEN_TTL_SECS: u64 = 3_600;
const REFRESH_TOKEN_TTL_SECS: u64 = 30 * 24 * 3_600;

/// Verified result of WeChat's `code2Session` response. `session_key` is
/// deliberately absent: IAM needs only the immutable provider subject.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WechatIdentity {
    /// Mini Program-scoped stable identity.
    pub openid: String,
}

/// Provider exchange seam used by the production HTTP adapter and deterministic tests.
#[async_trait]
pub trait WechatMiniProgramExchange: Send + Sync {
    /// Redeem one `wx.login` code. Codes are single-use provider credentials and
    /// must never be persisted or logged by implementations.
    async fn exchange(&self, code: &str) -> Result<WechatIdentity, WechatExchangeError>;
}

/// Stable exchange failures kept separate from account/token authority errors.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum WechatExchangeError {
    /// WeChat rejected or expired the one-time code.
    #[error("wechat rejected login code")]
    Rejected,
    /// Network/provider service was unavailable.
    #[error("wechat code exchange unavailable")]
    Unavailable,
    /// Provider returned no valid `openid`.
    #[error("wechat returned malformed identity")]
    Malformed,
}

/// Production `code2Session` HTTP adapter. The app secret stays only in this
/// deployment-owned instance and never enters public provider configuration.
pub struct ReqwestWechatMiniProgramExchange {
    client: reqwest::Client,
    endpoint: String,
    app_id: String,
    app_secret: String,
}

impl ReqwestWechatMiniProgramExchange {
    /// Create one customer Mini Program adapter.
    pub fn new(
        endpoint: impl Into<String>,
        app_id: impl Into<String>,
        app_secret: impl Into<String>,
    ) -> Self {
        Self {
            client: reqwest::Client::new(),
            endpoint: endpoint.into(),
            app_id: app_id.into(),
            app_secret: app_secret.into(),
        }
    }
}

#[derive(Debug, Deserialize)]
struct Code2SessionResponse {
    openid: Option<String>,
    #[serde(rename = "session_key")]
    _session_key: Option<String>,
    errcode: Option<i64>,
}

#[async_trait]
impl WechatMiniProgramExchange for ReqwestWechatMiniProgramExchange {
    async fn exchange(&self, code: &str) -> Result<WechatIdentity, WechatExchangeError> {
        let response = self
            .client
            .get(&self.endpoint)
            .query(&[
                ("appid", self.app_id.as_str()),
                ("secret", self.app_secret.as_str()),
                ("js_code", code),
                ("grant_type", "authorization_code"),
            ])
            .send()
            .await
            .map_err(|_| WechatExchangeError::Unavailable)?;
        if !response.status().is_success() {
            return Err(WechatExchangeError::Unavailable);
        }
        let body: Code2SessionResponse = response
            .json()
            .await
            .map_err(|_| WechatExchangeError::Malformed)?;
        if body.errcode.is_some_and(|code| code != 0) {
            return Err(WechatExchangeError::Rejected);
        }
        let openid = body
            .openid
            .filter(|value| !value.trim().is_empty())
            .ok_or(WechatExchangeError::Malformed)?;
        Ok(WechatIdentity { openid })
    }
}

/// Customer-specific Mini Program registration.
pub struct WechatMiniProgramRegistration {
    /// Stable provider namespace; different customer apps use different keys.
    pub provider_key: IdentityProviderKey,
    /// The only product audience this registration may mint.
    pub audience: String,
    /// Granted scopes.
    pub scopes: Vec<String>,
    /// Provider-specific code exchanger.
    pub exchange: Arc<dyn WechatMiniProgramExchange>,
}

#[derive(Clone)]
struct WechatState {
    auth: SharedAuthApi,
    issuer: Arc<str>,
    providers: Arc<HashMap<IdentityProviderKey, WechatMiniProgramRegistration>>,
}

/// Build the direct Mini Program login surface. It composes beside `op_router`
/// and shares the exact same `AuthApi` account, identity and token stores.
pub fn wechat_mini_program_router(
    auth: SharedAuthApi,
    issuer: impl Into<String>,
    registrations: Vec<WechatMiniProgramRegistration>,
) -> Router {
    let providers = registrations
        .into_iter()
        .map(|item| (item.provider_key.clone(), item))
        .collect();
    Router::new()
        .route("/v1/auth/wechat-miniapp/token", post(exchange_token))
        .with_state(WechatState {
            auth,
            issuer: Arc::from(issuer.into()),
            providers: Arc::new(providers),
        })
}

async fn exchange_token(
    State(state): State<WechatState>,
    Json(request): Json<WechatMiniProgramTokenRequest>,
) -> Result<Json<WechatMiniProgramTokenResponse>, (StatusCode, &'static str)> {
    if request.code.trim().is_empty()
        || request.code.len() > 512
        || request.audience.trim().is_empty()
    {
        return Err((StatusCode::BAD_REQUEST, "invalid_request"));
    }
    let provider = state
        .providers
        .get(&request.provider_key)
        .ok_or((StatusCode::BAD_REQUEST, "unknown_provider"))?;
    if provider.audience != request.audience {
        return Err((StatusCode::FORBIDDEN, "audience_not_allowed"));
    }
    let identity =
        provider
            .exchange
            .exchange(&request.code)
            .await
            .map_err(|error| match error {
                WechatExchangeError::Rejected => (StatusCode::UNAUTHORIZED, "invalid_grant"),
                WechatExchangeError::Unavailable => {
                    (StatusCode::SERVICE_UNAVAILABLE, "temporarily_unavailable")
                }
                WechatExchangeError::Malformed => {
                    (StatusCode::BAD_GATEWAY, "invalid_provider_response")
                }
            })?;
    let now = crate::clock::unix_seconds();
    let now_i64 = i64::try_from(now)
        .map_err(|_| (StatusCode::SERVICE_UNAVAILABLE, "temporarily_unavailable"))?;
    let mut auth = state.auth.lock().await;
    let resolved = auth
        .resolve_verified_external_identity(
            request.provider_key,
            ExternalIdentityClaims {
                subject: ExternalSubject(identity.openid),
                email: None,
                email_verified: None,
                display_name: None,
                username: None,
                avatar_url: None,
                locale: None,
            },
            crate::clock::timestamp(now),
        )
        .map_err(auth_error)?;
    let grant = auth
        .issue_token_grant(IssueTokenGrant {
            account_id: resolved.account_id.clone(),
            issuer: state.issuer.to_string(),
            subject: resolved.account_id.0,
            audience: request.audience,
            scopes: provider.scopes.clone(),
            issued_at: now_i64,
            access_expires_at: now_i64 + ACCESS_TOKEN_TTL_SECS as i64,
            now: crate::clock::timestamp(now),
            refresh_expires_at: crate::clock::timestamp(now + REFRESH_TOKEN_TTL_SECS),
        })
        .await
        .map_err(auth_error)?;
    Ok(Json(WechatMiniProgramTokenResponse {
        access_token: grant.access_token,
        token_type: "Bearer".into(),
        expires_in: ACCESS_TOKEN_TTL_SECS,
        refresh_token: grant.refresh_token,
        scope: provider.scopes.join(" "),
    }))
}

fn auth_error(_: AuthApiError) -> (StatusCode, &'static str) {
    (StatusCode::SERVICE_UNAVAILABLE, "temporarily_unavailable")
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::body::Body;
    use axum::http::Request;
    use tower::ServiceExt as _;

    struct FakeExchange;
    #[async_trait]
    impl WechatMiniProgramExchange for FakeExchange {
        async fn exchange(&self, code: &str) -> Result<WechatIdentity, WechatExchangeError> {
            match code {
                "valid" => Ok(WechatIdentity {
                    openid: "openid-1".into(),
                }),
                "offline" => Err(WechatExchangeError::Unavailable),
                _ => Err(WechatExchangeError::Rejected),
            }
        }
    }

    // Cause/effect decision table:
    // W1 known provider + allowed audience + valid code -> canonical IAM grant.
    // W2 same provider subject again -> same account subject, not a duplicate account.
    // W3 unknown provider/audience mismatch/rejected code/unavailable provider -> fail closed with distinct status.
    #[tokio::test]
    async fn mini_program_exchange_reuses_account_authority_and_fails_closed() {
        let auth = Arc::new(tokio::sync::Mutex::new(
            crate::AuthApi::new().with_issuer("https://iam.example"),
        ));
        let app = wechat_mini_program_router(
            auth.clone(),
            "https://iam.example",
            vec![WechatMiniProgramRegistration {
                provider_key: IdentityProviderKey("customer-a".into()),
                audience: "tutor-api".into(),
                scopes: vec!["openid".into(), "profile".into()],
                exchange: Arc::new(FakeExchange),
            }],
        );
        let call = |provider: &str, code: &str, audience: &str| {
            Request::builder()
                .method("POST")
                .uri("/v1/auth/wechat-miniapp/token")
                .header("content-type", "application/json")
                .body(Body::from(
                    serde_json::json!({"provider_key":provider,"code":code,"audience":audience})
                        .to_string(),
                ))
                .unwrap()
        };
        let first = app
            .clone()
            .oneshot(call("customer-a", "valid", "tutor-api"))
            .await
            .unwrap();
        assert_eq!(first.status(), StatusCode::OK);
        let first_body: WechatMiniProgramTokenResponse = serde_json::from_slice(
            &axum::body::to_bytes(first.into_body(), usize::MAX)
                .await
                .unwrap(),
        )
        .unwrap();
        let first_claims = auth
            .lock()
            .await
            .verify_access_token(&first_body.access_token)
            .unwrap();
        let second = app
            .clone()
            .oneshot(call("customer-a", "valid", "tutor-api"))
            .await
            .unwrap();
        let second_body: WechatMiniProgramTokenResponse = serde_json::from_slice(
            &axum::body::to_bytes(second.into_body(), usize::MAX)
                .await
                .unwrap(),
        )
        .unwrap();
        assert_eq!(
            first_claims.sub,
            auth.lock()
                .await
                .verify_access_token(&second_body.access_token)
                .unwrap()
                .sub
        );
        assert_eq!(
            app.clone()
                .oneshot(call("missing", "valid", "tutor-api"))
                .await
                .unwrap()
                .status(),
            StatusCode::BAD_REQUEST
        );
        assert_eq!(
            app.clone()
                .oneshot(call("customer-a", "valid", "other"))
                .await
                .unwrap()
                .status(),
            StatusCode::FORBIDDEN
        );
        assert_eq!(
            app.clone()
                .oneshot(call("customer-a", "bad", "tutor-api"))
                .await
                .unwrap()
                .status(),
            StatusCode::UNAUTHORIZED
        );
        assert_eq!(
            app.oneshot(call("customer-a", "offline", "tutor-api"))
                .await
                .unwrap()
                .status(),
            StatusCode::SERVICE_UNAVAILABLE
        );
    }
}
