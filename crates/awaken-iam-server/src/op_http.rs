//! Canonical Axum binding for Awaken IAM's OpenID Provider surface.

use std::sync::Arc;

use awaken_iam_core::{OAuthAuthorizationRequest, OAuthProviderError, TokenRedemption};
use axum::extract::{Form, Path, Query, State};
use axum::http::{HeaderMap, HeaderValue, StatusCode, header};
use axum::response::{Html, IntoResponse, Redirect, Response};
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
const LOGIN_TTL_SECS: u64 = 300;
const BROWSER_SESSION_TTL_SECS: u64 = 24 * 3_600;

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
/// JWKS is deliberately composed separately through [`jwks_router`]: an
/// embedding product may publish additional token families under the same
/// platform JWKS. The supplied `AuthApi` must use that deployment's shared
/// [`AccessTokenAuthority`](crate::AccessTokenAuthority).
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
        .route("/v1/auth/login/{provider}", get(start_provider_login))
        .route("/v1/auth/callback/{provider}", get(complete_provider_login))
        .route("/v1/oauth/browser/start", get(browser_start))
        .route("/v1/oauth/browser/callback", get(browser_callback))
        .route("/v1/oauth/token", post(token))
        .route("/v1/oauth/revoke", post(revoke))
        .route("/v1/oauth/userinfo", get(userinfo))
        .with_state(state)
}

/// Publish the standalone IAM process's access-token trust anchor.
///
/// Product embeddings that aggregate additional signing families keep their
/// own combined JWKS route and use [`op_router`] alone. `iam-daemon` composes
/// this router exactly once beside the OP and administration routes.
pub fn jwks_router(auth: SharedAuthApi) -> Router {
    Router::new()
        .route("/.well-known/jwks.json", get(jwks))
        .with_state(auth)
}

async fn jwks(State(auth): State<SharedAuthApi>) -> Response {
    Json(auth.lock().await.jwks()).into_response()
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

#[derive(Debug, Deserialize, Serialize)]
struct BrowserStartQuery {
    client_id: String,
    redirect_uri: String,
    return_to: String,
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
    #[serde(skip_serializing_if = "Option::is_none")]
    id_token: Option<String>,
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

/// Product-neutral browser bootstrap for Authorization Code + PKCE.
///
/// Hosted product ingresses proxy this path to IAM, so the page executes under
/// the product origin and can retain the verifier in that origin's
/// `sessionStorage`. Authorization still uses the canonical IAM issuer and its
/// SSO cookie; code redemption returns through the exact registered product
/// redirect URI. Products do not implement or persist a second OAuth client.
async fn browser_start(
    State(state): State<OpHttpState>,
    Query(query): Query<BrowserStartQuery>,
) -> Response {
    if !valid_browser_coordinate(&query) {
        return oauth_error(StatusCode::BAD_REQUEST, "invalid_request");
    }
    let config = serde_json::json!({
        "issuer": state.issuer.as_ref(),
        "clientId": query.client_id,
        "redirectUri": query.redirect_uri,
        "returnTo": query.return_to,
    });
    Html(format!(
        r#"<!doctype html><meta charset="utf-8"><title>Connecting to Awaken</title>
<main><h1>Connecting to Awaken</h1><p id="status">Preparing secure sign-in…</p></main>
<script type="module">
const status=document.querySelector('#status');
const config={config};
try {{
  const bytes=n=>crypto.getRandomValues(new Uint8Array(n));
  const b64=b=>btoa(String.fromCharCode(...b)).replaceAll('+','-').replaceAll('/','_').replaceAll('=','');
  const verifier=b64(bytes(48));
  const state=b64(bytes(32));
  const digest=await crypto.subtle.digest('SHA-256',new TextEncoder().encode(verifier));
  sessionStorage.setItem('awaken.oauth.pending',JSON.stringify({{...config,verifier,state}}));
  const authorize=new URL('/v1/oauth/authorize',config.issuer);
  authorize.search=new URLSearchParams({{client_id:config.clientId,redirect_uri:config.redirectUri,response_type:'code',scope:'openid email profile',state,code_challenge:b64(new Uint8Array(digest)),code_challenge_method:'S256'}});
  location.replace(authorize);
}} catch (error) {{
  console.error('Unable to prepare secure sign-in',error);
  status.textContent='Unable to start secure sign-in. Reload this page to try again.';
}}
</script>"#
    ))
    .into_response()
}

/// Product-neutral PKCE callback page. It validates browser state before
/// redeeming through the same-origin ingress proxy and stores only the
/// short-lived access token. Provider refresh credentials remain in IAM.
async fn browser_callback() -> Html<&'static str> {
    Html(
        r#"<!doctype html><meta charset="utf-8"><title>Completing sign-in</title>
<main><h1>Completing sign-in</h1><p id="status">Verifying secure sign-in…</p></main>
<script type="module">
const status=document.querySelector('#status');
const fail=message=>{status.textContent=message;throw new Error(message)};
try {
  const params=new URLSearchParams(location.search);
  const pendingRaw=sessionStorage.getItem('awaken.oauth.pending');
  if(!pendingRaw)fail('Sign-in session expired. Return to Awaken Cloud and try again.');
  const pending=JSON.parse(pendingRaw);
  if(!params.get('code')||params.get('state')!==pending.state)fail('Sign-in validation failed. Return to Awaken Cloud and try again.');
  const form=new URLSearchParams({grant_type:'authorization_code',client_id:pending.clientId,code:params.get('code'),redirect_uri:pending.redirectUri,code_verifier:pending.verifier});
  const controller=new AbortController();
  const timeout=setTimeout(()=>controller.abort(),15000);
  let response;
  try {
    response=await fetch('/v1/oauth/token',{method:'POST',headers:{'content-type':'application/x-www-form-urlencoded'},body:form,signal:controller.signal});
  } finally {
    clearTimeout(timeout);
  }
  if(!response.ok)fail('Awaken could not complete sign-in. Return to Awaken Cloud and try again.');
  const grant=await response.json();
  if(typeof grant.access_token!=='string'||!grant.access_token)fail('Awaken returned an invalid sign-in result.');
  sessionStorage.setItem('awaken.product.session-bearer',grant.access_token);
  sessionStorage.removeItem('awaken.oauth.pending');
  location.replace(pending.returnTo);
} catch (error) {
  console.error('Unable to complete secure sign-in',error);
  if(status.textContent==='Verifying secure sign-in…')status.textContent='Sign-in did not complete. Return to Awaken Cloud and try again.';
}
</script>"#,
    )
}

fn valid_browser_coordinate(query: &BrowserStartQuery) -> bool {
    let safe_text = |value: &str| {
        !value.trim().is_empty() && !value.contains(['<', '>', '\n', '\r']) && value.len() <= 2_048
    };
    safe_text(&query.client_id)
        && safe_text(&query.redirect_uri)
        && (query.redirect_uri.starts_with("https://")
            || query.redirect_uri.starts_with("http://127.0.0.1:")
            || query.redirect_uri.starts_with("http://localhost:"))
        && query.return_to.starts_with('/')
        && !query.return_to.starts_with("//")
        && safe_text(&query.return_to)
}

async fn authorize(
    State(state): State<OpHttpState>,
    Query(query): Query<AuthorizeQuery>,
    headers: HeaderMap,
) -> Response {
    if query.response_type != "code" {
        return oauth_error(StatusCode::BAD_REQUEST, "unsupported_response_type");
    }
    let return_to = authorize_return_to(&query);
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
    let authorization = state.auth.lock().await.authorize(request);
    match authorization {
        Ok(outcome) => Redirect::to(&outcome.redirect_to).into_response(),
        Err(AuthApiError::Unauthenticated | AuthApiError::Login(_)) => {
            login_required(&state, &return_to).await
        }
        Err(AuthApiError::OAuthProvider(error)) => oauth_provider_error(error),
        Err(_) => oauth_error(StatusCode::SERVICE_UNAVAILABLE, "temporarily_unavailable"),
    }
}

fn authorize_return_to(query: &AuthorizeQuery) -> String {
    let mut encoded = url::form_urlencoded::Serializer::new(String::new());
    encoded
        .append_pair("client_id", &query.client_id)
        .append_pair("redirect_uri", &query.redirect_uri)
        .append_pair("response_type", &query.response_type)
        .append_pair("scope", &query.scope);
    for (key, value) in [
        ("state", query.state.as_deref()),
        ("code_challenge", query.code_challenge.as_deref()),
        (
            "code_challenge_method",
            query.code_challenge_method.as_deref(),
        ),
        ("nonce", query.nonce.as_deref()),
    ] {
        if let Some(value) = value {
            encoded.append_pair(key, value);
        }
    }
    format!("/v1/oauth/authorize?{}", encoded.finish())
}

async fn login_required(state: &OpHttpState, return_to: &str) -> Response {
    let providers = state.auth.lock().await.list_providers();
    if providers.is_empty() {
        return oauth_error(StatusCode::UNAUTHORIZED, "login_required");
    }

    let login_url = |provider_key: &str| {
        let mut query = url::form_urlencoded::Serializer::new(String::new());
        query.append_pair("return_to", return_to);
        let mut path = url::Url::parse("https://iam.invalid/v1/auth/login/")
            .expect("static login base URL is valid");
        path.path_segments_mut()
            .expect("static login base URL can hold path segments")
            .pop_if_empty()
            .push(provider_key);
        format!("{}?{}", path.path(), query.finish())
    };
    if providers.len() == 1 {
        return Redirect::to(&login_url(&providers[0].provider_key.0)).into_response();
    }

    let choices = providers
        .into_iter()
        .map(|provider| {
            format!(
                "<li><a href=\"{}\">Continue with {}</a></li>",
                html_escape(&login_url(&provider.provider_key.0)),
                html_escape(&provider.display_name),
            )
        })
        .collect::<String>();
    Html(format!(
        "<!doctype html><meta charset=\"utf-8\"><title>Sign in to Awaken</title>\
         <main><h1>Sign in to Awaken</h1><p>Choose your account provider.</p>\
         <ul>{choices}</ul></main>"
    ))
    .into_response()
}

#[derive(Deserialize)]
struct ProviderLoginQuery {
    return_to: Option<String>,
}

#[derive(Deserialize)]
struct ProviderCallbackQuery {
    code: Option<String>,
    state: Option<String>,
    error: Option<String>,
}

fn redirect_with_cookies(location: &str, cookies: &[&str]) -> Response {
    let mut response = Redirect::to(location).into_response();
    for cookie in cookies {
        let Ok(value) = HeaderValue::from_str(cookie) else {
            return oauth_error(StatusCode::INTERNAL_SERVER_ERROR, "server_error");
        };
        response.headers_mut().append(header::SET_COOKIE, value);
    }
    response
}

fn provider_login_error(error: AuthApiError) -> Response {
    match error {
        AuthApiError::UnknownProvider(_) => oauth_error(StatusCode::NOT_FOUND, "invalid_request"),
        AuthApiError::ProviderDisabled(_) => oauth_error(StatusCode::FORBIDDEN, "access_denied"),
        AuthApiError::Provider(_) | AuthApiError::Repository(_) => {
            oauth_error(StatusCode::SERVICE_UNAVAILABLE, "temporarily_unavailable")
        }
        _ => oauth_error(StatusCode::BAD_REQUEST, "invalid_request"),
    }
}

async fn start_provider_login(
    State(state): State<OpHttpState>,
    Path(provider): Path<String>,
    Query(query): Query<ProviderLoginQuery>,
) -> Response {
    let now = crate::clock::unix_seconds();
    let request = crate::StartLogin {
        provider_key: awaken_iam_contract::IdentityProviderKey(provider),
        return_to: query.return_to,
        created_at: crate::clock::timestamp(now),
        expires_at: crate::clock::timestamp(now + LOGIN_TTL_SECS),
        cookie_max_age_secs: Some(LOGIN_TTL_SECS),
    };
    let auth = state.auth.clone();
    match tokio::task::spawn_blocking(move || auth.blocking_lock().start_login(request)).await {
        Ok(Ok(started)) => redirect_with_cookies(
            &started.redirect_url,
            &[&started.set_cookie, &started.set_proof_cookie],
        ),
        Ok(Err(error)) => provider_login_error(error),
        Err(_) => oauth_error(StatusCode::SERVICE_UNAVAILABLE, "temporarily_unavailable"),
    }
}

async fn complete_provider_login(
    State(state): State<OpHttpState>,
    Path(provider): Path<String>,
    Query(query): Query<ProviderCallbackQuery>,
    headers: HeaderMap,
) -> Response {
    if query.error.is_some() {
        return oauth_error(StatusCode::BAD_REQUEST, "access_denied");
    }
    let (Some(code), Some(oauth_state)) = (query.code, query.state) else {
        return oauth_error(StatusCode::BAD_REQUEST, "invalid_request");
    };
    let now = crate::clock::unix_seconds();
    let request = crate::CallbackRequest {
        provider_key: awaken_iam_contract::IdentityProviderKey(provider),
        cookie_header: headers
            .get(header::COOKIE)
            .and_then(|value| value.to_str().ok())
            .unwrap_or_default()
            .to_owned(),
        code,
        state: oauth_state,
        now: crate::clock::timestamp(now),
        session_expires_at: crate::clock::timestamp(now + BROWSER_SESSION_TTL_SECS),
        session_cookie_max_age_secs: Some(BROWSER_SESSION_TTL_SECS),
    };
    let auth = state.auth.clone();
    match tokio::task::spawn_blocking(move || auth.blocking_lock().complete_callback(request)).await
    {
        Ok(Ok(completed)) => redirect_with_cookies(
            &completed.redirect_to,
            &[
                &completed.set_session_cookie,
                &completed.clear_login_cookie,
                &completed.clear_login_proof_cookie,
            ],
        ),
        Ok(Err(error)) => provider_login_error(error),
        Err(_) => oauth_error(StatusCode::SERVICE_UNAVAILABLE, "temporarily_unavailable"),
    }
}

fn html_escape(value: &str) -> String {
    value
        .replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&#39;")
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
            id_token: grant.id_token,
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
        Err(AuthApiError::Repository(_)) => {
            oauth_error(StatusCode::SERVICE_UNAVAILABLE, "temporarily_unavailable")
        }
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
        OAuthProviderError::StorageUnavailable => {
            oauth_error(StatusCode::SERVICE_UNAVAILABLE, "temporarily_unavailable")
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

    fn configured_auth(providers: &[(&str, &str)]) -> AuthApi {
        let issuer = "https://accounts.example";
        let mut auth = AuthApi::new().with_issuer(issuer);
        auth.register_oauth_client(RegisteredClient::public(
            "desktop",
            vec!["http://127.0.0.1:9234/callback".into()],
            ["openid", "email", "profile"],
        ))
        .unwrap();
        for (provider_key, display_name) in providers {
            auth.register_provider(crate::ProviderRegistration {
                config: IdentityProviderConfig {
                    id: IdentityProviderConfigId(format!("{provider_key}-config")),
                    provider_key: IdentityProviderKey((*provider_key).into()),
                    kind: IdentityProviderKind::Fake,
                    display_name: (*display_name).into(),
                    issuer_url: Some("https://idp.example".into()),
                    authorization_endpoint: Some("https://idp.example/authorize".into()),
                    token_endpoint: Some("https://idp.example/token".into()),
                    client_id: Some("iam".into()),
                    enabled: true,
                },
                adapter: Box::new(FakeAdapter),
                redirect_uri: format!("{issuer}/v1/auth/callback/{provider_key}"),
                scopes: vec!["openid".into(), "email".into()],
                include_nonce: true,
                include_pkce: true,
            });
        }
        auth
    }

    async fn logged_in_router() -> (Router, String) {
        let issuer = "https://accounts.example";
        let mut auth = configured_auth(&[("fake", "Fake")]);
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
        let login_proof_cookie = started
            .set_proof_cookie
            .split(';')
            .next()
            .unwrap()
            .to_owned();
        let state = started.redirect_url.split("state=").nth(1).unwrap();
        let completed = auth
            .complete_callback(crate::CallbackRequest {
                provider_key: IdentityProviderKey("fake".into()),
                cookie_header: format!("{login_cookie}; {login_proof_cookie}"),
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
    async fn standalone_jwks_router_publishes_the_auth_api_trust_anchor() {
        // Cause/effect decision table:
        // | composition | requested route | effect |
        // | standalone JWKS router | /.well-known/jwks.json | exact AuthApi keys |
        // | product OP router only | same route | absent; product may aggregate keys |
        // Constraint: there is one access-token authority; this route projects
        // it and never creates or caches another signing-key source.
        let auth = AuthApi::new();
        let expected = auth.jwks();
        let response = jwks_router(Arc::new(Mutex::new(auth)))
            .oneshot(
                Request::builder()
                    .uri("/.well-known/jwks.json")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        assert_eq!(
            serde_json::from_slice::<awaken_iam_contract::Jwks>(&body).unwrap(),
            expected
        );
    }

    /// Causal table for the shared browser bootstrap:
    ///
    /// | client/redirect | return path | result |
    /// |---|---|---|
    /// | valid coordinates | WebCrypto succeeds | executable module stores PKCE state and redirects |
    /// | valid coordinates | WebCrypto/storage fails | visible retryable terminal error; no infinite loading state |
    /// | any | external/scheme-relative return path | reject before browser redirect |
    /// | markup/control input | any | reject; never reflect executable input |
    #[tokio::test]
    async fn browser_bootstrap_accepts_only_bounded_product_coordinates() {
        let (app, _) = logged_in_router().await;
        let accepted = app
            .clone()
            .oneshot(
                Request::builder()
                    .uri("/v1/oauth/browser/start?client_id=awaken-flow&redirect_uri=https%3A%2F%2Fflow.example%2Fv1%2Foauth%2Fbrowser%2Fcallback&return_to=%2Fw%2Fws%253Atenant")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(accepted.status(), StatusCode::OK);
        let body = axum::body::to_bytes(accepted.into_body(), usize::MAX)
            .await
            .unwrap();
        let html = String::from_utf8(body.to_vec()).unwrap();
        assert!(html.contains("<script type=\"module\">"));
        assert!(html.contains("crypto.subtle.digest"));
        assert!(html.contains("awaken.oauth.pending"));
        assert!(html.contains("https://flow.example/v1/oauth/browser/callback"));
        assert!(html.contains("Unable to start secure sign-in"));

        for uri in [
            "/v1/oauth/browser/start?client_id=awaken-flow&redirect_uri=https%3A%2F%2Fflow.example%2Fcallback&return_to=https%3A%2F%2Fevil.example",
            "/v1/oauth/browser/start?client_id=%3Cscript%3E&redirect_uri=https%3A%2F%2Fflow.example%2Fcallback&return_to=%2F",
        ] {
            let rejected = app
                .clone()
                .oneshot(Request::builder().uri(uri).body(Body::empty()).unwrap())
                .await
                .unwrap();
            assert_eq!(rejected.status(), StatusCode::BAD_REQUEST);
        }
    }

    /// Callback cause/effect decision table:
    ///
    /// | pending state | callback state/code | token exchange | effect |
    /// | valid | matching | valid grant | store one session bearer and return |
    /// | absent | any | not attempted | visible expired-session failure |
    /// | valid | missing/mismatched | not attempted | visible validation failure |
    /// | valid | matching | error/invalid/timeout | visible terminal failure within 15s |
    /// The executable module is required for the awaited exchange; a classic
    /// script would fail at parse time and leave the loading copy forever.
    #[tokio::test]
    async fn browser_callback_uses_one_standard_session_bearer_and_state_check() {
        let (app, _) = logged_in_router().await;
        let response = app
            .oneshot(
                Request::builder()
                    .uri("/v1/oauth/browser/callback?code=opaque&state=opaque")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        let html = String::from_utf8(body.to_vec()).unwrap();
        assert!(html.contains("<script type=\"module\">"));
        assert!(html.contains("params.get('state')!==pending.state"));
        assert!(html.contains("new AbortController()"));
        assert!(html.contains("15000"));
        assert!(html.contains("Sign-in did not complete"));
        assert!(html.contains("awaken.product.session-bearer"));
        assert!(!html.contains("localStorage"));
    }

    #[tokio::test]
    async fn desktop_pkce_http_flow_authorizes_redeems_refreshes_and_reads_userinfo() {
        // Wire decision rules: W1 a valid authorization code => access,
        // refresh and ID token from the one canonical grant; W2 a refresh
        // token => rotated access/refresh only, never a new ID token.
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
        assert_eq!(
            grant["id_token"].as_str().unwrap().split('.').count(),
            3,
            "W1"
        );

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
        let bytes = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        let refreshed: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        assert!(refreshed.get("id_token").is_none(), "W2");
    }

    #[tokio::test]
    async fn provider_login_routes_resume_the_same_product_oidc_authorization() {
        // End-to-end decision rule L1: C1 no IAM Session + one configured
        // upstream provider + registered product/PKCE => E1 redirect through
        // provider login, bind two correlation cookies, establish an IAM
        // Session, resume the exact authorization, then issue one code and a
        // verified ID token. State-mismatch rejection is owned by AuthApi's
        // separate challenge tests.
        let shared = Arc::new(Mutex::new(configured_auth(&[("fake", "Fake")])));
        let app = op_router(shared.clone(), "https://accounts.example");
        let verifier = "desktop-verifier-with-enough-entropy";
        let challenge = URL_SAFE_NO_PAD.encode(Sha256::digest(verifier.as_bytes()));
        let authorize_uri = format!(
            "/v1/oauth/authorize?client_id=desktop&redirect_uri=http%3A%2F%2F127.0.0.1%3A9234%2Fcallback&response_type=code&scope=openid%20email&state=product-state&nonce=product-nonce&code_challenge={challenge}&code_challenge_method=S256"
        );
        let first = app
            .clone()
            .oneshot(
                Request::builder()
                    .uri(authorize_uri)
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(first.status(), StatusCode::SEE_OTHER);
        let login_uri = first.headers()[header::LOCATION].to_str().unwrap();
        assert!(login_uri.starts_with("/v1/auth/login/fake?return_to="));
        let login = app
            .clone()
            .oneshot(
                Request::builder()
                    .uri(login_uri)
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(login.status(), StatusCode::SEE_OTHER);
        let upstream =
            url::Url::parse(login.headers()[header::LOCATION].to_str().unwrap()).unwrap();
        let upstream_state = upstream
            .query_pairs()
            .find(|(key, _)| key == "state")
            .unwrap()
            .1;
        let cookies = login
            .headers()
            .get_all(header::SET_COOKIE)
            .iter()
            .map(|value| {
                value
                    .to_str()
                    .unwrap()
                    .split(';')
                    .next()
                    .unwrap()
                    .to_owned()
            })
            .collect::<Vec<_>>()
            .join("; ");
        assert_eq!(cookies.split(';').count(), 2);
        let callback_uri = format!("/v1/auth/callback/fake?code=accepted&state={upstream_state}");
        let callback = app
            .clone()
            .oneshot(
                Request::builder()
                    .uri(callback_uri)
                    .header(header::COOKIE, cookies)
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(callback.status(), StatusCode::SEE_OTHER);
        let session_cookie = callback
            .headers()
            .get_all(header::SET_COOKIE)
            .iter()
            .map(|value| value.to_str().unwrap())
            .find(|value| value.starts_with(crate::DEFAULT_SESSION_COOKIE_NAME))
            .unwrap()
            .split(';')
            .next()
            .unwrap()
            .to_owned();
        let return_to = callback.headers()[header::LOCATION].to_str().unwrap();
        assert!(return_to.starts_with("/v1/oauth/authorize?"));
        let authorized = app
            .clone()
            .oneshot(
                Request::builder()
                    .uri(return_to)
                    .header(header::COOKIE, session_cookie)
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(authorized.status(), StatusCode::SEE_OTHER);
        let product =
            url::Url::parse(authorized.headers()[header::LOCATION].to_str().unwrap()).unwrap();
        assert_eq!(
            product
                .query_pairs()
                .find(|(key, _)| key == "state")
                .unwrap()
                .1,
            "product-state"
        );
        let code = product
            .query_pairs()
            .find(|(key, _)| key == "code")
            .unwrap()
            .1;
        let form = format!(
            "grant_type=authorization_code&client_id=desktop&code={code}&redirect_uri=http%3A%2F%2F127.0.0.1%3A9234%2Fcallback&code_verifier={verifier}"
        );
        let redeemed = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/v1/oauth/token")
                    .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
                    .body(Body::from(form))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(redeemed.status(), StatusCode::OK);
        let bytes = axum::body::to_bytes(redeemed.into_body(), usize::MAX)
            .await
            .unwrap();
        let grant: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        let id = crate::verify_id_token(
            grant["id_token"].as_str().unwrap(),
            &shared.lock().await.jwks(),
        )
        .unwrap();
        assert_eq!(id.aud, "desktop");
        assert_eq!(id.nonce.as_deref(), Some("product-nonce"));
    }

    /// Logged-out authorization cause/effect decision table:
    ///
    /// | live IAM session | enabled providers | effect |
    /// | yes | any | issue the product code through the existing OP path |
    /// | no | one | redirect to that IAM-owned provider login and preserve every authorize field |
    /// | no | multiple | render escaped IAM-owned provider choices |
    /// | no | none | return `login_required`; no unusable link or product-owned picker |
    ///
    /// The reconstructed `return_to` is always a relative canonical OP path;
    /// caller input cannot select the post-provider host.
    #[tokio::test]
    async fn logged_out_desktop_authorize_resumes_through_iam_provider_login() {
        let (app, _) = logged_in_router().await;
        let response = app
            .oneshot(
                Request::builder()
                    .uri("/v1/oauth/authorize?client_id=desktop&redirect_uri=http%3A%2F%2F127.0.0.1%3A9234%2Fcallback&response_type=code&scope=openid%20email&state=state-1&code_challenge=challenge-1&code_challenge_method=S256")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::SEE_OTHER);
        let location = response.headers()[header::LOCATION].to_str().unwrap();
        assert!(location.starts_with("/v1/auth/login/fake?return_to="));
        let parsed = url::Url::parse(&format!("https://accounts.example{location}")).unwrap();
        let return_to = parsed
            .query_pairs()
            .find_map(|(key, value)| (key == "return_to").then(|| value.into_owned()))
            .unwrap();
        assert!(return_to.starts_with("/v1/oauth/authorize?"));
        assert!(return_to.contains("client_id=desktop"));
        assert!(return_to.contains("state=state-1"));
        assert!(return_to.contains("code_challenge=challenge-1"));
        assert!(!return_to.contains("accounts.example"));
    }

    #[tokio::test]
    async fn logged_out_authorize_handles_zero_or_multiple_enabled_providers() {
        let authorize = "/v1/oauth/authorize?client_id=desktop&redirect_uri=http%3A%2F%2F127.0.0.1%3A9234%2Fcallback&response_type=code&scope=openid&state=state-1&code_challenge=challenge-1&code_challenge_method=S256";
        let empty = op_router(
            Arc::new(Mutex::new(configured_auth(&[]))),
            "https://accounts.example",
        )
        .oneshot(
            Request::builder()
                .uri(authorize)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
        assert_eq!(empty.status(), StatusCode::UNAUTHORIZED);

        let choices = op_router(
            Arc::new(Mutex::new(configured_auth(&[
                ("github", "GitHub"),
                ("google", "Google"),
            ]))),
            "https://accounts.example",
        )
        .oneshot(
            Request::builder()
                .uri(authorize)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
        assert_eq!(choices.status(), StatusCode::OK);
        let body = axum::body::to_bytes(choices.into_body(), usize::MAX)
            .await
            .unwrap();
        let html = String::from_utf8(body.to_vec()).unwrap();
        assert!(html.contains("Continue with GitHub"));
        assert!(html.contains("Continue with Google"));
        assert!(html.contains("/v1/auth/login/github?return_to="));
    }
}
/// OAuth storage failure cause/effect rule: C1=the authoritative client or
/// code repository is unavailable. R1(C1) returns HTTP 503 with the OAuth
/// temporarily_unavailable class; it must not collapse to invalid_grant or
/// fall back to replica memory.
#[test]
fn oauth_storage_failure_is_temporarily_unavailable() {
    let response = oauth_provider_error(OAuthProviderError::StorageUnavailable);
    assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
}
