//! Canonical Axum binding for Awaken IAM's OpenID Provider surface.

use std::sync::Arc;

use awaken_iam_core::{OAuthAuthorizationRequest, OAuthProviderError, TokenRedemption};
use axum::extract::{Form, Query, State};
use axum::http::{HeaderMap, StatusCode, header};
use axum::response::{IntoResponse, Redirect, Response};
use axum::routing::{get, post};
use axum::{Json, Router};
use serde::{Deserialize, Serialize};
use tokio::sync::Mutex;

use crate::{
    AuthApi, AuthApiError, DownstreamAuthorizeRequest, RedeemAuthorizationCode, RefreshGrant,
    RevokeToken, RevokeTokenHint,
};

const ACCESS_TOKEN_TTL_SECS: u64 = 3_600;
const AUTHORIZATION_CODE_TTL_SECS: u64 = 300;
const REFRESH_TOKEN_TTL_SECS: u64 = 30 * 24 * 3_600;

/// One shared mutable OP instance. Embedded hosts mount this handle rather than
/// reimplementing authorization-code, PKCE, refresh, revoke, or UserInfo logic.
pub type SharedAuthApi = Arc<Mutex<AuthApi>>;

#[derive(Clone)]
struct OpHttpState {
    auth: SharedAuthApi,
    issuer: Arc<str>,
}

/// Bind the canonical public OP endpoints over `auth`.
///
/// JWKS is deliberately not mounted here: an embedding product may publish
/// additional token families under the same platform JWKS. The supplied
/// `AuthApi` must use that deployment's shared [`AccessTokenAuthority`](crate::AccessTokenAuthority).
pub fn op_router(auth: SharedAuthApi, issuer: impl Into<String>) -> Router {
    let state = OpHttpState {
        auth,
        issuer: Arc::from(issuer.into()),
    };
    Router::new()
        .route(
            "/.well-known/openid-configuration",
            get(openid_configuration),
        )
        .route("/v1/oauth/authorize", get(authorize))
        .route("/v1/oauth/token", post(token))
        .route("/v1/oauth/revoke", post(revoke))
        .route("/v1/oauth/userinfo", get(userinfo))
        .with_state(state)
}

#[derive(Debug, Deserialize)]
struct AuthorizeQuery {
    client_id: String,
    redirect_uri: String,
    response_type: String,
    #[serde(default)]
    scope: String,
    state: Option<String>,
    code_challenge: Option<String>,
    code_challenge_method: Option<String>,
    nonce: Option<String>,
}

#[derive(Debug, Deserialize)]
struct TokenForm {
    grant_type: String,
    client_id: String,
    client_secret: Option<String>,
    code: Option<String>,
    redirect_uri: Option<String>,
    code_verifier: Option<String>,
    refresh_token: Option<String>,
}

#[derive(Debug, Deserialize)]
struct RevokeForm {
    token: String,
    token_type_hint: Option<String>,
}

#[derive(Debug, Serialize)]
struct TokenResponse {
    access_token: String,
    token_type: &'static str,
    expires_in: u64,
    refresh_token: String,
    scope: String,
}

#[derive(Debug, Serialize)]
struct OAuthError {
    error: &'static str,
}

async fn openid_configuration(State(state): State<OpHttpState>) -> Response {
    let auth = state.auth.lock().await;
    Json(auth.openid_configuration(&state.issuer)).into_response()
}

async fn authorize(
    State(state): State<OpHttpState>,
    Query(query): Query<AuthorizeQuery>,
    headers: HeaderMap,
) -> Response {
    if query.response_type != "code" {
        return oauth_error(StatusCode::BAD_REQUEST, "unsupported_response_type");
    }
    let now = crate::clock::unix_seconds();
    let cookie_header = headers
        .get(header::COOKIE)
        .and_then(|value| value.to_str().ok())
        .unwrap_or_default()
        .to_owned();
    let request = DownstreamAuthorizeRequest {
        cookie_header,
        authorization: OAuthAuthorizationRequest {
            client_id: query.client_id,
            redirect_uri: query.redirect_uri,
            scopes: split_scope(&query.scope),
            code_challenge: query.code_challenge,
            code_challenge_method: query.code_challenge_method,
            nonce: query.nonce,
            state: query.state,
        },
        now: crate::clock::timestamp(now),
        code_expires_at: crate::clock::timestamp(now + AUTHORIZATION_CODE_TTL_SECS),
    };
    match state.auth.lock().await.authorize(request) {
        Ok(outcome) => Redirect::to(&outcome.redirect_to).into_response(),
        Err(AuthApiError::Unauthenticated | AuthApiError::Login(_)) => {
            oauth_error(StatusCode::UNAUTHORIZED, "login_required")
        }
        Err(AuthApiError::OAuthProvider(error)) => oauth_provider_error(error),
        Err(_) => oauth_error(StatusCode::SERVICE_UNAVAILABLE, "temporarily_unavailable"),
    }
}

async fn token(State(state): State<OpHttpState>, Form(form): Form<TokenForm>) -> Response {
    let now = crate::clock::unix_seconds();
    let now_timestamp = crate::clock::timestamp(now);
    let refresh_expires_at = crate::clock::timestamp(now + REFRESH_TOKEN_TTL_SECS);
    let mut auth = state.auth.lock().await;
    let result = match form.grant_type.as_str() {
        "authorization_code" => {
            let (Some(code), Some(redirect_uri)) = (form.code, form.redirect_uri) else {
                return oauth_error(StatusCode::BAD_REQUEST, "invalid_request");
            };
            auth.redeem_authorization_code(RedeemAuthorizationCode {
                redemption: TokenRedemption {
                    client_id: form.client_id,
                    client_secret: form.client_secret,
                    code,
                    redirect_uri,
                    code_verifier: form.code_verifier,
                },
                issuer: state.issuer.to_string(),
                issued_at: now as i64,
                access_expires_at: (now + ACCESS_TOKEN_TTL_SECS) as i64,
                now: now_timestamp,
                refresh_expires_at,
            })
            .await
        }
        "refresh_token" => {
            let Some(refresh_token) = form.refresh_token else {
                return oauth_error(StatusCode::BAD_REQUEST, "invalid_request");
            };
            auth.refresh_registered_client(
                &form.client_id,
                form.client_secret.as_deref(),
                RefreshGrant {
                    presented_refresh_token: refresh_token,
                    issuer: state.issuer.to_string(),
                    issued_at: now as i64,
                    access_expires_at: (now + ACCESS_TOKEN_TTL_SECS) as i64,
                    now: now_timestamp,
                    refresh_expires_at,
                },
            )
            .await
        }
        _ => return oauth_error(StatusCode::BAD_REQUEST, "unsupported_grant_type"),
    };

    match result {
        Ok(grant) => Json(TokenResponse {
            access_token: grant.access_token,
            token_type: "Bearer",
            expires_in: ACCESS_TOKEN_TTL_SECS,
            refresh_token: grant.refresh_token,
            scope: grant.refresh_token_view.scope.join(" "),
        })
        .into_response(),
        Err(AuthApiError::OAuthProvider(error)) => oauth_provider_error(error),
        Err(_) => oauth_error(StatusCode::BAD_REQUEST, "invalid_grant"),
    }
}

async fn revoke(State(state): State<OpHttpState>, Form(form): Form<RevokeForm>) -> Response {
    let hint = match form.token_type_hint.as_deref() {
        Some("access_token") => Some(RevokeTokenHint::AccessToken),
        Some("refresh_token") => Some(RevokeTokenHint::RefreshToken),
        _ => None,
    };
    state.auth.lock().await.revoke_token(RevokeToken {
        token: form.token,
        token_type_hint: hint,
        now: crate::clock::now_timestamp(),
    });
    StatusCode::OK.into_response()
}

async fn userinfo(State(state): State<OpHttpState>, headers: HeaderMap) -> Response {
    let Some(token) = bearer_token(&headers) else {
        return oauth_error(StatusCode::UNAUTHORIZED, "invalid_token");
    };
    let auth = state.auth.lock().await;
    let Ok(claims) = auth.verify_access_token(token) else {
        return oauth_error(StatusCode::UNAUTHORIZED, "invalid_token");
    };
    let now = crate::clock::unix_seconds() as i64;
    if claims.iss != state.issuer.as_ref() || claims.iat > now || claims.exp <= now {
        return oauth_error(StatusCode::UNAUTHORIZED, "invalid_token");
    }
    match auth.userinfo_for_access_token(token) {
        Ok(info) => Json(info).into_response(),
        Err(_) => oauth_error(StatusCode::UNAUTHORIZED, "invalid_token"),
    }
}

fn bearer_token(headers: &HeaderMap) -> Option<&str> {
    headers
        .get(header::AUTHORIZATION)?
        .to_str()
        .ok()?
        .strip_prefix("Bearer ")
        .filter(|token| !token.is_empty())
}

fn split_scope(scope: &str) -> Vec<String> {
    scope.split_whitespace().map(str::to_owned).collect()
}

fn oauth_provider_error(error: OAuthProviderError) -> Response {
    match error {
        OAuthProviderError::UnknownClient | OAuthProviderError::InvalidClientSecret => {
            oauth_error(StatusCode::UNAUTHORIZED, "invalid_client")
        }
        OAuthProviderError::ScopeNotAllowed => {
            oauth_error(StatusCode::BAD_REQUEST, "invalid_scope")
        }
        OAuthProviderError::PkceRequired
        | OAuthProviderError::UnsupportedCodeChallengeMethod
        | OAuthProviderError::UnregisteredRedirectUri
        | OAuthProviderError::RedirectUriMismatch
        | OAuthProviderError::InvalidGrant
        | OAuthProviderError::PkceVerificationFailed => {
            oauth_error(StatusCode::BAD_REQUEST, "invalid_grant")
        }
    }
}

fn oauth_error(status: StatusCode, error: &'static str) -> Response {
    (status, Json(OAuthError { error })).into_response()
}

#[cfg(test)]
mod tests {
    use super::*;
    use awaken_iam_contract::{
        ExternalIdentityClaims, ExternalSubject, IdentityProviderConfig, IdentityProviderConfigId,
        IdentityProviderKey, IdentityProviderKind,
    };
    use awaken_iam_core::{
        AuthorizationRedirect, AuthorizationUrlRequest, CallbackExchange, IdentityProviderAdapter,
        ProviderError, RegisteredClient,
    };
    use axum::body::Body;
    use axum::http::Request;
    use base64::Engine as _;
    use base64::engine::general_purpose::URL_SAFE_NO_PAD;
    use sha2::{Digest, Sha256};
    use tower::ServiceExt as _;

    struct FakeAdapter;

    impl IdentityProviderAdapter for FakeAdapter {
        fn provider_kind(&self) -> IdentityProviderKind {
            IdentityProviderKind::Fake
        }

        fn authorization_url(
            &self,
            _config: &IdentityProviderConfig,
            request: &AuthorizationUrlRequest,
        ) -> Result<AuthorizationRedirect, ProviderError> {
            Ok(AuthorizationRedirect {
                url: format!("https://idp.example/authorize?state={}", request.state),
            })
        }

        fn exchange_callback(
            &self,
            _config: &IdentityProviderConfig,
            _callback: &CallbackExchange,
        ) -> Result<ExternalIdentityClaims, ProviderError> {
            Ok(ExternalIdentityClaims {
                subject: ExternalSubject("subject-1".into()),
                email: Some("user@example.com".into()),
                email_verified: Some(true),
                display_name: Some("Example User".into()),
                username: None,
                avatar_url: None,
                locale: None,
            })
        }
    }

    async fn logged_in_router() -> (Router, String) {
        let issuer = "https://accounts.example";
        let mut auth = AuthApi::new().with_issuer(issuer);
        auth.register_oauth_client(RegisteredClient::public(
            "desktop",
            vec!["http://127.0.0.1:9234/callback".into()],
            ["openid", "email", "profile"],
        ));
        auth.register_provider(crate::ProviderRegistration {
            config: IdentityProviderConfig {
                id: IdentityProviderConfigId("fake-config".into()),
                provider_key: IdentityProviderKey("fake".into()),
                kind: IdentityProviderKind::Fake,
                display_name: "Fake".into(),
                issuer_url: Some("https://idp.example".into()),
                authorization_endpoint: Some("https://idp.example/authorize".into()),
                token_endpoint: Some("https://idp.example/token".into()),
                client_id: Some("iam".into()),
                enabled: true,
            },
            adapter: Box::new(FakeAdapter),
            redirect_uri: format!("{issuer}/v1/auth/callback/fake"),
            scopes: vec!["openid".into(), "email".into()],
            include_nonce: true,
            include_pkce: true,
        });
        let now = crate::clock::unix_seconds();
        let started = auth
            .start_login(crate::StartLogin {
                provider_key: IdentityProviderKey("fake".into()),
                return_to: None,
                created_at: crate::clock::timestamp(now),
                expires_at: crate::clock::timestamp(now + 300),
                cookie_max_age_secs: Some(300),
            })
            .unwrap();
        let login_cookie = started.set_cookie.split(';').next().unwrap().to_owned();
        let state = started.redirect_url.split("state=").nth(1).unwrap();
        let completed = auth
            .complete_callback(crate::CallbackRequest {
                provider_key: IdentityProviderKey("fake".into()),
                cookie_header: login_cookie,
                code: "accepted".into(),
                state: state.into(),
                now: crate::clock::timestamp(now + 1),
                session_expires_at: crate::clock::timestamp(now + 3_600),
                session_cookie_max_age_secs: Some(3_600),
            })
            .unwrap();
        let session_cookie = completed
            .set_session_cookie
            .split(';')
            .next()
            .unwrap()
            .to_owned();
        let shared = Arc::new(Mutex::new(auth));
        (op_router(shared, issuer), session_cookie)
    }

    #[tokio::test]
    async fn desktop_pkce_http_flow_authorizes_redeems_refreshes_and_reads_userinfo() {
        let (app, cookie) = logged_in_router().await;
        let verifier = "desktop-verifier-with-enough-entropy";
        let challenge = URL_SAFE_NO_PAD.encode(Sha256::digest(verifier.as_bytes()));
        let authorize_uri = format!(
            "/v1/oauth/authorize?client_id=desktop&redirect_uri=http%3A%2F%2F127.0.0.1%3A9234%2Fcallback&response_type=code&scope=openid%20email&state=opaque&code_challenge={challenge}&code_challenge_method=S256"
        );
        let response = app
            .clone()
            .oneshot(
                Request::builder()
                    .uri(authorize_uri)
                    .header(header::COOKIE, cookie)
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::SEE_OTHER);
        let location = response.headers()[header::LOCATION].to_str().unwrap();
        let code = location
            .split("code=")
            .nth(1)
            .unwrap()
            .split('&')
            .next()
            .unwrap();

        let token_body = format!(
            "grant_type=authorization_code&client_id=desktop&code={code}&redirect_uri=http%3A%2F%2F127.0.0.1%3A9234%2Fcallback&code_verifier={verifier}"
        );
        let response = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/v1/oauth/token")
                    .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
                    .body(Body::from(token_body))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let bytes = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        let grant: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        let access_token = grant["access_token"].as_str().unwrap();
        let refresh_token = grant["refresh_token"].as_str().unwrap();

        let response = app
            .clone()
            .oneshot(
                Request::builder()
                    .uri("/v1/oauth/userinfo")
                    .header(header::AUTHORIZATION, format!("Bearer {access_token}"))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);

        let refresh_body =
            format!("grant_type=refresh_token&client_id=desktop&refresh_token={refresh_token}");
        let response = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/v1/oauth/token")
                    .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
                    .body(Body::from(refresh_body))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
    }
}
