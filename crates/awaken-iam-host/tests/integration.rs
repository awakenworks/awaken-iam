use awaken_iam_client::{AuthzTransport, IamClient, RemoteError, RemoteIamClient};
use awaken_iam_contract::ApiTokenId;
use awaken_iam_contract::WorkspaceId;
use awaken_iam_contract::{
    AccountId, ActionKey, AuthorizationDecision, AuthorizationOutcome, AuthorizationRequest,
    BatchAuthorizationRequest, BatchAuthorizationResponse, EntitlementCheckResponse,
    EntitlementDecision, EntitlementRequest, NamespaceId, PolicySnapshot, PrincipalRef,
    ProductResourceModelRequest, ResourceModelRegistered, ScopeRef, SignerSetSnapshot, Timestamp,
};
use awaken_iam_core::{MintApiToken, RoleId};
use awaken_iam_host::{
    AccessTokenActor, AccessTokenAuthority, AccessTokenClaims, AccessTokenSubjectKind,
    DelegatedAccessTokenClaims, HostConfig, IamGate, LocalSeedSigner, RouteActions, TokenActor,
    auth_layer, embed_local, verify_access_token,
};
use axum::{Router, body::Body, http::Request, http::StatusCode, routing::get};
use tower::ServiceExt;

// ── helpers ──────────────────────────────────────────────────────────────────

fn now_ts() -> Timestamp {
    Timestamp("2026-01-01T00:00:00Z".into())
}

const NOW_UNIX: i64 = 1_751_328_000; // 2025-07-01 UTC (well in the future for most exp fields)

fn svc(name: &str) -> PrincipalRef {
    PrincipalRef::Service {
        service_id: name.into(),
    }
}

// ── open mode ────────────────────────────────────────────────────────────────

#[test]
fn open_mode_is_open_and_always_allows() {
    let gate = IamGate::open();
    assert!(gate.is_open());

    let decision = gate.authorize(AuthorizationRequest::direct(
        svc("any-service"),
        ActionKey("billing.read".into()),
        ScopeRef::Global,
    ));
    assert_eq!(decision, AuthorizationDecision::Allow);

    // R1: Open is explicit, so all existing Result projections stay Allow;
    // the new local availability boundary must not turn Open into an outage.
    let request = AuthorizationRequest::direct(
        svc("any-service"),
        ActionKey("billing.read".into()),
        ScopeRef::Global,
    );
    assert_eq!(
        gate.authorize_result(request.clone()),
        Ok(AuthorizationDecision::Allow)
    );
    assert_eq!(
        gate.authorize_resource_result(awaken_iam_contract::ResourceAuthorizationRequest {
            request,
            context: Default::default(),
        })
        .unwrap()
        .decision,
        AuthorizationDecision::Allow,
    );
    assert_eq!(
        gate.check_entitlement_result(EntitlementRequest {
            principal: svc("any-service"),
            entitlement: "ai.basic".into(),
            resource: None,
        }),
        Ok(EntitlementDecision::Allow),
    );
}

#[test]
fn open_mode_authenticate_bearer_returns_none() {
    // In open mode there is no token to validate; callers check is_open() first.
    let gate = IamGate::open();
    let ts = now_ts();
    assert!(
        gate.authenticate_bearer("sk-ant-anything", &ts, NOW_UNIX)
            .is_none()
    );
}

// ── local mode: sk-ant- mint → authenticate → authorize → revoke ─────────────

#[test]
fn local_mode_api_token_lifecycle() {
    let cfg = HostConfig::local_in_memory();
    let mut handle = embed_local(&cfg).expect("embed_local should succeed");

    // Mint a token for a service principal.
    let principal = svc("svc-under-test");
    let workspace = WorkspaceId("wrkspc_test".into());
    let req = MintApiToken {
        id: ApiTokenId("tok_test_1".into()),
        principal: principal.clone(),
        workspace: workspace.clone(),
        role: RoleId("admin".into()),
        created_at: Timestamp("2026-01-01T00:00:00Z".into()),
        expires_at: None,
    };
    let issued = handle.mint_api_token(req).expect("mint should succeed");
    assert!(
        issued.secret.starts_with("sk-awaken-") || issued.secret.starts_with("sk-ant-"),
        "issued secret should carry a recognised prefix; got: {}",
        &issued.secret[..16.min(issued.secret.len())]
    );

    // Authenticate: the cleartext token resolves to the principal.
    let ts = now_ts();
    let resolved = handle
        .gate
        .authenticate_bearer(&issued.secret, &ts, NOW_UNIX)
        .expect("freshly minted token must authenticate");
    assert_eq!(resolved, principal);

    // Authorize: without explicit grants the deny-by-default policy applies.
    // This verifies that the authorization plane IS evaluated (not bypassed) for
    // Local mode tokens. A product that needs Allow would add an explicit Grant.
    let decision = handle.gate.authorize(AuthorizationRequest::direct(
        resolved.clone(),
        ActionKey("iam.admin".into()),
        ScopeRef::Workspace {
            workspace_id: workspace.clone(),
        },
    ));
    assert_eq!(
        decision,
        AuthorizationDecision::Deny,
        "no explicit grant → deny-by-default is the expected safe behavior"
    );

    // Revoke the token.
    handle
        .revoke_api_token(&issued.token.id, ts.clone())
        .expect("revoke should succeed");

    // After revocation the token no longer authenticates.
    assert!(
        handle
            .gate
            .authenticate_bearer(&issued.secret, &ts, NOW_UNIX)
            .is_none(),
        "revoked token must not authenticate"
    );
}

#[test]
fn local_mode_admin_token_is_present_and_authenticates() {
    let cfg = HostConfig::local_in_memory();
    let handle = embed_local(&cfg).expect("embed_local should succeed");

    let ts = now_ts();
    let resolved = handle
        .gate
        .authenticate_bearer(&handle.admin_token, &ts, NOW_UNIX)
        .expect("bootstrap admin token must authenticate");
    assert!(
        matches!(resolved, PrincipalRef::Service { .. }),
        "admin token should resolve to a service principal"
    );
}

// ── remote mode: fail-closed to Deny ─────────────────────────────────────────

/// A transport that always returns an error, simulating an unreachable daemon.
struct AlwaysFailTransport;

impl AuthzTransport for AlwaysFailTransport {
    fn authorize(&self, _: &AuthorizationRequest) -> Result<AuthorizationOutcome, RemoteError> {
        Err(RemoteError("simulated connection refused".into()))
    }

    fn authorize_batch(
        &self,
        _: &BatchAuthorizationRequest,
    ) -> Result<BatchAuthorizationResponse, RemoteError> {
        Err(RemoteError("simulated connection refused".into()))
    }

    fn check_entitlement(
        &self,
        _: &EntitlementRequest,
    ) -> Result<EntitlementCheckResponse, RemoteError> {
        Err(RemoteError("simulated connection refused".into()))
    }

    fn register_resource_model(
        &self,
        _: &ProductResourceModelRequest,
    ) -> Result<ResourceModelRegistered, RemoteError> {
        Err(RemoteError("simulated connection refused".into()))
    }

    fn fetch_snapshot(&self) -> Result<PolicySnapshot, RemoteError> {
        Err(RemoteError("simulated connection refused".into()))
    }

    fn fetch_signers(&self, _: &NamespaceId) -> Result<SignerSetSnapshot, RemoteError> {
        Err(RemoteError("simulated connection refused".into()))
    }
}

#[test]
fn remote_transport_failure_fails_closed_to_deny() {
    let client = RemoteIamClient::new(AlwaysFailTransport);

    let decision = client.authorize(AuthorizationRequest::direct(
        svc("any"),
        ActionKey("resource.write".into()),
        ScopeRef::Global,
    ));
    assert_eq!(
        decision,
        AuthorizationDecision::Deny,
        "a transport failure must return Deny, not Allow"
    );
}

#[test]
fn remote_transport_failure_entitlement_fails_closed_to_deny() {
    let client = RemoteIamClient::new(AlwaysFailTransport);

    let decision = client.check_entitlement(EntitlementRequest {
        principal: svc("any"),
        entitlement: "ai.basic".into(),
        resource: None,
    });
    assert_eq!(decision, EntitlementDecision::Deny);
}

// ── JWT verify: EdDSA + JWKS + iss/aud/exp ──────────────────────────────────

const JWT_SEED: [u8; 32] = [
    0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10,
    0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f, 0x20,
];

fn make_authority() -> AccessTokenAuthority {
    AccessTokenAuthority::new(LocalSeedSigner::new("test-kid", JWT_SEED))
}

fn make_claims(exp: i64) -> AccessTokenClaims {
    AccessTokenClaims {
        iss: "https://iam.example.com".into(),
        sub: "acct_test_1".into(),
        subject_kind: AccessTokenSubjectKind::Account,
        aud: "https://api.example.com".into(),
        exp,
        iat: NOW_UNIX - 60,
        jti: "jti_test_1".into(),
        scope: vec![],
    }
}

#[tokio::test]
async fn jwt_verify_valid_eddsa_token() {
    let authority = make_authority();
    let jwks = authority.jwks();
    let claims = make_claims(NOW_UNIX + 3600);
    let token = authority.mint(&claims).await.expect("mint should succeed");

    let recovered = verify_access_token(&token, &jwks).expect("valid token must verify");
    assert_eq!(recovered.sub, "acct_test_1");
    assert_eq!(recovered.iss, "https://iam.example.com");
    assert_eq!(recovered.aud, "https://api.example.com");
    assert_eq!(recovered.jti, "jti_test_1");
}

#[tokio::test]
async fn jwt_expired_token_fails_verification_in_gate() {
    // A token whose `exp` is in the past must not authenticate even when the
    // signature is valid.
    let cfg = HostConfig::local_in_memory().with_seal_key(JWT_SEED);
    let handle = embed_local(&cfg).expect("embed_local should succeed");

    // Use the gate's own authority so the kid matches the JWKS it trusts.
    let authority = handle.jwt_authority.as_ref().expect("jwt_authority");
    let jwks = authority.jwks();

    let exp_past = NOW_UNIX - 1; // already expired relative to NOW_UNIX
    let claims = make_claims(exp_past);
    let token = authority.mint(&claims).await.expect("mint should succeed");

    // Signature alone passes:
    assert!(
        verify_access_token(&token, &jwks).is_ok(),
        "signature should be valid"
    );

    // But the gate must reject it because exp <= now_unix:
    let ts = now_ts();
    assert_eq!(
        handle
            .gate
            .authenticate_detailed(&token, &ts, NOW_UNIX)
            .unwrap_err(),
        awaken_iam_host::AuthReject::Expired,
        "expired JWT must retain its explicit rejection reason"
    );
}

#[tokio::test]
async fn jwt_wrong_issuer_rejected_by_gate() {
    // Gate configured to expect a different issuer than the one in the token claims.
    let cfg = HostConfig::local_in_memory()
        .with_seal_key(JWT_SEED)
        .with_issuer("https://other-iam.example.com");
    let handle = embed_local(&cfg).expect("embed_local");

    let authority = handle.jwt_authority.as_ref().expect("jwt_authority");
    let claims = make_claims(NOW_UNIX + 3600);
    let token = authority.mint(&claims).await.expect("mint");

    let ts = now_ts();
    assert!(
        handle
            .gate
            .authenticate_bearer(&token, &ts, NOW_UNIX)
            .is_none(),
        "wrong iss must be rejected"
    );
}

#[tokio::test]
async fn jwt_wrong_audience_rejected_by_gate() {
    // Gate configured to expect a different audience than the one in the token claims.
    let cfg = HostConfig::local_in_memory()
        .with_seal_key(JWT_SEED)
        .with_audience("https://other-api.example.com");
    let handle = embed_local(&cfg).expect("embed_local");

    let authority = handle.jwt_authority.as_ref().expect("jwt_authority");
    let claims = make_claims(NOW_UNIX + 3600);
    let token = authority.mint(&claims).await.expect("mint");

    let ts = now_ts();
    assert!(
        handle
            .gate
            .authenticate_bearer(&token, &ts, NOW_UNIX)
            .is_none(),
        "wrong aud must be rejected"
    );
}

#[tokio::test]
async fn jwt_matching_issuer_and_audience_resolves_principal() {
    let cfg = HostConfig::local_in_memory()
        .with_seal_key(JWT_SEED)
        .with_issuer("https://iam.example.com")
        .with_audience("https://api.example.com");
    let handle = embed_local(&cfg).expect("embed_local");

    // Use the gate's own signing authority so the kid in the JWT matches the JWKS.
    let authority = handle
        .jwt_authority
        .as_ref()
        .expect("jwt_authority must be set when seal_key is configured");
    let claims = make_claims(NOW_UNIX + 3600);
    let token = authority.mint(&claims).await.expect("mint");

    let ts = now_ts();
    let principal = handle
        .gate
        .authenticate_bearer(&token, &ts, NOW_UNIX)
        .expect("matching iss+aud must resolve a principal");
    assert!(
        matches!(principal, PrincipalRef::Account { .. }),
        "JWT sub should resolve to an Account principal"
    );
}

/// Causal graph:
///
/// verified JWT -> explicit subject kind -> exact `PrincipalRef` -> policy key
///
/// Decision table:
///
/// | wire subject kind | resolved principal |
/// |---|---|
/// | absent (legacy) | Account |
/// | `account` | Account |
/// | `service` | Service |
#[tokio::test]
async fn jwt_subject_kind_preserves_account_compatibility_and_service_identity() {
    let cfg = HostConfig::local_in_memory()
        .with_seal_key(JWT_SEED)
        .with_issuer("https://iam.example.com")
        .with_audience("https://api.example.com");
    let handle = embed_local(&cfg).expect("embed_local");
    let authority = handle.jwt_authority.as_ref().expect("jwt authority");
    let timestamp = now_ts();

    let account_claims = make_claims(NOW_UNIX + 3600);
    assert!(
        serde_json::to_value(&account_claims)
            .unwrap()
            .get("subject_kind")
            .is_none(),
        "Account remains the backward-compatible omitted wire default"
    );
    let account = authority.mint(&account_claims).await.expect("mint account");
    assert_eq!(
        handle
            .gate
            .authenticate_bearer(&account, &timestamp, NOW_UNIX),
        Some(PrincipalRef::Account {
            account_id: AccountId("acct_test_1".into()),
        })
    );

    let mut service_claims = make_claims(NOW_UNIX + 3600);
    service_claims.sub = "svc_ci_publisher".into();
    service_claims.subject_kind = AccessTokenSubjectKind::Service;
    assert_eq!(
        serde_json::to_value(&service_claims).unwrap()["subject_kind"],
        "service"
    );
    let service = authority.mint(&service_claims).await.expect("mint service");
    assert_eq!(
        handle
            .gate
            .authenticate_bearer(&service, &timestamp, NOW_UNIX),
        Some(PrincipalRef::Service {
            service_id: "svc_ci_publisher".into(),
        })
    );
}

// ── axum middleware layer: HTTP request-layer tests ───────────────────────────

/// A no-op `RouteActions` that never maps a method+path to an action.
/// Using it means authentication still runs but no authorization check is performed.
#[derive(Clone)]
struct NoActions;

impl RouteActions for NoActions {
    fn action_for(&self, _method: &axum::http::Method, _path: &str) -> Option<ActionKey> {
        None
    }
}

/// Build a minimal test router: `GET /ping` returns 200 "ok", wrapped in the
/// IAM auth layer using the given gate.
fn test_router(gate: IamGate) -> Router {
    Router::new()
        .route("/ping", get(|| async { "ok" }))
        .layer(auth_layer(gate, NoActions))
}

fn get_request(uri: &str) -> Request<Body> {
    Request::builder()
        .method("GET")
        .uri(uri)
        .body(Body::empty())
        .expect("build request")
}

fn bearer_request(uri: &str, token: &str) -> Request<Body> {
    Request::builder()
        .method("GET")
        .uri(uri)
        .header("Authorization", format!("Bearer {token}"))
        .body(Body::empty())
        .expect("build request")
}

/// Open mode: every request passes through without any credentials.
#[tokio::test]
async fn middleware_open_mode_bypasses_auth() {
    let router = test_router(IamGate::open());
    let resp = router
        .oneshot(get_request("/ping"))
        .await
        .expect("dispatch");
    assert_eq!(resp.status(), StatusCode::OK);
}

/// Non-open mode with no Authorization header → 401.
#[tokio::test]
async fn middleware_missing_token_returns_401() {
    let cfg = HostConfig::local_in_memory();
    let handle = embed_local(&cfg).expect("embed_local");
    let router = test_router(handle.gate);

    let resp = router
        .oneshot(get_request("/ping"))
        .await
        .expect("dispatch");
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
}

/// A valid (non-expired) bearer token authenticates and passes through.
#[tokio::test]
async fn middleware_valid_token_passes_through() {
    let cfg = HostConfig::local_in_memory();
    let handle = embed_local(&cfg).expect("embed_local");

    let resp = test_router(handle.gate)
        .oneshot(bearer_request("/ping", &handle.admin_token))
        .await
        .expect("dispatch");
    assert_eq!(resp.status(), StatusCode::OK);
}

/// An invalid/garbage bearer token → 401.
#[tokio::test]
async fn middleware_invalid_token_returns_401() {
    let cfg = HostConfig::local_in_memory();
    let handle = embed_local(&cfg).expect("embed_local");
    let router = test_router(handle.gate);

    let resp = router
        .oneshot(bearer_request("/ping", "sk-awaken-totally-wrong-secret"))
        .await
        .expect("dispatch");
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
}

/// A JWT whose `exp` is in the past must be rejected with 401, demonstrating
/// that the middleware uses real wall-clock time (not a hardcoded past value).
#[tokio::test]
async fn middleware_expired_jwt_returns_401_with_real_clock() {
    let cfg = HostConfig::local_in_memory().with_seal_key(JWT_SEED);
    let handle = embed_local(&cfg).expect("embed_local");

    let authority = handle.jwt_authority.as_ref().expect("jwt_authority");
    // exp = unix epoch 1 — far in the past regardless of real clock
    let claims = AccessTokenClaims {
        iss: "https://iam.example.com".into(),
        sub: "acct_expired".into(),
        subject_kind: AccessTokenSubjectKind::Account,
        aud: "https://api.example.com".into(),
        exp: 1,
        iat: 0,
        jti: "jti_expired".into(),
        scope: vec![],
    };
    let expired_token = authority.mint(&claims).await.expect("mint");

    let resp = test_router(handle.gate)
        .oneshot(bearer_request("/ping", &expired_token))
        .await
        .expect("dispatch");
    // The middleware must reject this with 401, proving it reads real time
    // and does not use a frozen past timestamp that would accept all exp values.
    assert_eq!(
        resp.status(),
        StatusCode::UNAUTHORIZED,
        "expired JWT must be rejected by the middleware using real wall-clock time"
    );
}

/// A revoked API token → 401.
#[tokio::test]
async fn middleware_revoked_token_returns_401() {
    let cfg = HostConfig::local_in_memory();
    let mut handle = embed_local(&cfg).expect("embed_local");

    let principal = PrincipalRef::Service {
        service_id: "svc-revoke-test".into(),
    };
    let workspace = WorkspaceId("wrkspc_rev".into());
    let req = MintApiToken {
        id: ApiTokenId("tok_rev_1".into()),
        principal: principal.clone(),
        workspace: workspace.clone(),
        role: RoleId("admin".into()),
        created_at: Timestamp("2026-01-01T00:00:00Z".into()),
        expires_at: None,
    };
    let issued = handle.mint_api_token(req).expect("mint");

    // Confirm it passes before revocation.
    let gate_before = handle.gate.clone();
    let resp = test_router(gate_before)
        .oneshot(bearer_request("/ping", &issued.secret))
        .await
        .expect("dispatch");
    assert_eq!(
        resp.status(),
        StatusCode::OK,
        "token should pass before revoke"
    );

    // Revoke the token.
    handle
        .revoke_api_token(&issued.token.id, Timestamp("2026-01-01T00:00:00Z".into()))
        .expect("revoke");

    // After revocation it should be rejected.
    let resp = test_router(handle.gate)
        .oneshot(bearer_request("/ping", &issued.secret))
        .await
        .expect("dispatch");
    assert_eq!(
        resp.status(),
        StatusCode::UNAUTHORIZED,
        "revoked token must return 401"
    );
}

/// Principal is inserted into request extensions and accessible by handlers.
#[tokio::test]
async fn middleware_inserts_principal_into_extensions() {
    use axum::extract::Extension;

    let cfg = HostConfig::local_in_memory();
    let handle = embed_local(&cfg).expect("embed_local");

    // A handler that extracts the principal and returns its service_id.
    async fn principal_handler(Extension(p): Extension<PrincipalRef>) -> String {
        match p {
            PrincipalRef::Service { service_id } => service_id,
            _ => "not-a-service".into(),
        }
    }

    let router = Router::new()
        .route("/whoami", get(principal_handler))
        .layer(auth_layer(handle.gate.clone(), NoActions));

    let resp = router
        .oneshot(bearer_request("/whoami", &handle.admin_token))
        .await
        .expect("dispatch");
    assert_eq!(resp.status(), StatusCode::OK);
    let body = axum::body::to_bytes(resp.into_body(), usize::MAX)
        .await
        .expect("read body");
    let service_id = String::from_utf8(body.to_vec()).expect("utf8");
    // Admin token resolves to a Service principal.
    assert!(
        !service_id.is_empty(),
        "principal service_id must not be empty"
    );
}

// ── ADR-0048: per-request scope derivation (RouteActions::scope_for) ──────────

/// The default `scope_for` authorizes at `Global`, preserving the pre-scope
/// behavior for any `RouteActions` impl that does not override it. This is what
/// keeps the extension backward-compatible: existing impls (and the middleware
/// tests above) are unchanged.
#[test]
fn default_scope_for_is_global() {
    let uri: axum::http::Uri = "/v1/anything?x=1".parse().unwrap();
    let scope = NoActions.scope_for(
        &axum::http::Method::GET,
        &uri,
        &axum::http::Extensions::new(),
    );
    assert_eq!(scope, ScopeRef::Global);
}

/// A `RouteActions` that records every `scope_for` call and derives a workspace
/// scope from the `/w/{workspace}/...` path prefix — the shape a product uses to
/// enforce per-tenant authorization.
#[derive(Clone, Default)]
struct RecordingActions {
    seen: std::sync::Arc<std::sync::Mutex<Vec<(String, String)>>>,
}

impl RouteActions for RecordingActions {
    fn action_for(&self, _method: &axum::http::Method, _path: &str) -> Option<ActionKey> {
        // Require *some* action so the middleware consults `scope_for`.
        Some(ActionKey("agent.run".into()))
    }

    fn scope_for(
        &self,
        method: &axum::http::Method,
        uri: &axum::http::Uri,
        _extensions: &axum::http::Extensions,
    ) -> ScopeRef {
        self.seen
            .lock()
            .unwrap()
            .push((method.to_string(), uri.to_string()));
        match uri
            .path()
            .strip_prefix("/w/")
            .and_then(|rest| rest.split('/').next())
        {
            Some(id) if !id.is_empty() => ScopeRef::Workspace {
                workspace_id: WorkspaceId(id.to_owned()),
            },
            _ => ScopeRef::Global,
        }
    }
}

/// The middleware consults `scope_for` with the request's real method+uri before
/// authorizing — the hook a product uses to enforce per-workspace tenancy. The
/// admin token authenticates and the route maps to an action, so `scope_for`
/// runs; embed installs no grants so the request is denied (deny-by-default),
/// but the derivation ran with the real coordinates.
#[tokio::test]
async fn middleware_consults_scope_for_with_request_coordinates() {
    let cfg = HostConfig::local_in_memory();
    let handle = embed_local(&cfg).expect("embed_local");
    let actions = RecordingActions::default();
    let seen = std::sync::Arc::clone(&actions.seen);

    let router = Router::new()
        .route("/w/wrkspc_acme/threads", get(|| async { "ok" }))
        .layer(auth_layer(handle.gate.clone(), actions));

    let resp = router
        .oneshot(bearer_request(
            "/w/wrkspc_acme/threads",
            &handle.admin_token,
        ))
        .await
        .expect("dispatch");
    assert_eq!(resp.status(), StatusCode::FORBIDDEN);

    let calls = seen.lock().unwrap();
    assert_eq!(calls.len(), 1, "scope_for consulted exactly once");
    assert_eq!(calls[0].0, "GET", "scope_for saw the real method");
    assert!(
        calls[0].1.contains("/w/wrkspc_acme/threads"),
        "scope_for saw the real request uri; got {}",
        calls[0].1
    );
}

/// `from_local_state` wraps a **product-owned** embed (its own directory, policy,
/// grants, and bootstrap identity, behind one lock) into a Local-mode gate — the
/// constructor a product with its own tenancy model uses instead of
/// `embed_local`. The product's own token authenticates through the gate, and
/// `authenticate_scoped` recovers the token's workspace binding.
#[test]
fn from_local_state_wraps_a_product_owned_embed() {
    use awaken_iam_core::{ApiTokenDirectory, ApiTokenMinter, OsEntropy};
    use awaken_iam_host::{IamGate, LocalIamState};
    use std::sync::{Arc, Mutex};

    let mut directory = ApiTokenDirectory::new();
    let mut authz = awaken_iam_host::AuthzApi::new();
    let principal = svc("svc-product");
    let issued = ApiTokenMinter::new(OsEntropy)
        .mint(
            &mut directory,
            authz.policy_mut(),
            MintApiToken {
                id: ApiTokenId("tok_product_1".into()),
                principal: principal.clone(),
                workspace: WorkspaceId("wrkspc_product".into()),
                role: RoleId("admin".into()),
                created_at: now_ts(),
                expires_at: None,
            },
        )
        .expect("mint into the product-owned state");

    // C1=the original shared state is healthy, C2=an explicit read grant,
    // C3=the default-deny write/entitlement, C4=that same state is poisoned.
    // Decision table: R1(C1,C2)->Ok(Allow); R2(C1,C3)->Ok(Deny);
    // R3(C4)->Err(Unavailable) for all three Result methods, no policy/token
    // mutation; R4(C4,legacy API)->Deny without panic. The token and policy
    // stay behind one Arc/Mutex; no recovery into possibly inconsistent data.
    use awaken_iam_client::IamDecisionError;
    use awaken_iam_core::{ActionPattern, Effect, Grant, GrantId, GrantSubject};
    authz.policy_mut().add_grant(Grant {
        id: GrantId("product-read".into()),
        subject: GrantSubject::Principal(principal.clone()),
        action_pattern: ActionPattern("product.read".into()),
        scope: ScopeRef::Global,
        effect: Effect::Allow,
    });
    let state = Arc::new(Mutex::new(LocalIamState { authz, directory }));
    let gate = IamGate::from_local_state(state.clone());

    assert!(!gate.is_open(), "a product-owned gate is not open mode");
    // authenticate_scoped recovers principal AND the token's workspace binding.
    let (resolved, workspace) = gate
        .authenticate_scoped(&issued.secret, &now_ts(), NOW_UNIX)
        .expect("the product's own token authenticates through the wrapped gate");
    assert_eq!(resolved, principal);
    assert_eq!(workspace, Some(WorkspaceId("wrkspc_product".into())));

    let allowed = AuthorizationRequest::direct(
        principal.clone(),
        ActionKey("product.read".into()),
        ScopeRef::Global,
    );
    let denied = AuthorizationRequest::direct(
        principal.clone(),
        ActionKey("product.write".into()),
        ScopeRef::Global,
    );
    let resource = awaken_iam_contract::ResourceAuthorizationRequest {
        request: allowed.clone(),
        context: Default::default(),
    };
    let entitlement = EntitlementRequest {
        principal,
        entitlement: "ai.basic".into(),
        resource: None,
    };
    assert_eq!(
        gate.authorize_result(allowed.clone()),
        Ok(AuthorizationDecision::Allow)
    );
    assert_eq!(
        gate.authorize_result(denied),
        Ok(AuthorizationDecision::Deny)
    );
    let outcome = gate.authorize_resource_result(resource.clone()).unwrap();
    assert_eq!(outcome.decision, AuthorizationDecision::Allow);
    assert_eq!(outcome.matched_grants, vec!["product-read".to_owned()]);
    assert_eq!(
        gate.check_entitlement_result(entitlement.clone()),
        Ok(EntitlementDecision::Deny)
    );
    assert_eq!(
        gate.authorize(allowed.clone()),
        AuthorizationDecision::Allow
    );
    let before = state.lock().unwrap().authz.snapshot();

    let poisoned = state.clone();
    assert!(
        std::thread::spawn(move || {
            let _guard = poisoned.lock().unwrap();
            panic!("injected failure while the shared local state is locked");
        })
        .join()
        .is_err()
    );
    assert!(state.is_poisoned());
    assert_eq!(
        gate.authorize_result(allowed.clone()),
        Err(IamDecisionError::Unavailable)
    );
    assert_eq!(
        gate.authorize_resource_result(resource),
        Err(IamDecisionError::Unavailable)
    );
    assert_eq!(
        gate.check_entitlement_result(entitlement.clone()),
        Err(IamDecisionError::Unavailable)
    );
    assert_eq!(gate.authorize(allowed), AuthorizationDecision::Deny);
    assert_eq!(
        gate.check_entitlement(entitlement),
        EntitlementDecision::Deny
    );
    assert!(state.is_poisoned(), "decision calls must not clear poison");
    // Test-only forensic inspection proves inertness; production never recovers
    // the guard or treats these contents as a valid authorization decision.
    let guard = state.lock().err().unwrap().into_inner();
    assert_eq!(guard.authz.snapshot(), before);
    assert_eq!(guard.directory.token(&issued.token.id), Some(&issued.token));
}

// ── ADR-0048: product-customizable PEP (credential extraction, error envelope,
//    token-workspace stash) ───────────────────────────────────────────────────

/// A `RouteActions` that authenticates via `x-api-key` (not `Authorization`),
/// renders auth failures in a product envelope, and maps no action (authn +
/// stash only).
#[derive(Clone)]
struct XApiKeyActions;

impl RouteActions for XApiKeyActions {
    fn action_for(&self, _method: &axum::http::Method, _path: &str) -> Option<ActionKey> {
        None
    }

    fn extract_credential(&self, headers: &axum::http::HeaderMap) -> Option<String> {
        headers
            .get("x-api-key")
            .and_then(|value| value.to_str().ok())
            .map(|value| value.to_owned())
    }

    fn render_auth_error(&self, error: &awaken_iam_host::AuthError) -> axum::response::Response {
        use axum::response::IntoResponse;
        let status = match error {
            awaken_iam_host::AuthError::Forbidden => StatusCode::FORBIDDEN,
            _ => StatusCode::UNAUTHORIZED,
        };
        (
            status,
            axum::Json(serde_json::json!({ "product_error": error.to_string() })),
        )
            .into_response()
    }
}

async fn token_workspace_handler(req: axum::extract::Request) -> String {
    req.extensions()
        .get::<awaken_iam_host::TokenWorkspace>()
        .map(|w| w.0.0.clone())
        .unwrap_or_else(|| "none".to_string())
}

/// x-api-key auth + the token-workspace stash: a request carrying the admin
/// token in `x-api-key` (no `Authorization` header) authenticates through the
/// product's credential extractor, and the handler reads the token's home
/// workspace from `TokenWorkspace` in the request extensions.
#[tokio::test]
async fn middleware_x_api_key_auth_and_token_workspace_stash() {
    let handle = embed_local(&HostConfig::local_in_memory()).expect("embed_local");

    let router = Router::new()
        .route("/w", get(token_workspace_handler))
        .layer(auth_layer(handle.gate.clone(), XApiKeyActions));

    let req = Request::builder()
        .method("GET")
        .uri("/w")
        .header("x-api-key", &handle.admin_token)
        .body(Body::empty())
        .expect("build request");
    let resp = router.oneshot(req).await.expect("dispatch");
    assert_eq!(
        resp.status(),
        StatusCode::OK,
        "the x-api-key credential authenticates via the product extractor"
    );
    let body = axum::body::to_bytes(resp.into_body(), usize::MAX)
        .await
        .expect("read body");
    assert_eq!(
        String::from_utf8(body.to_vec()).expect("utf8"),
        "wrkspc_admin",
        "handler reads the token's home workspace from TokenWorkspace"
    );
}

/// The product error renderer replaces host's problem+json: a missing credential
/// yields the product envelope with a 401.
#[tokio::test]
async fn middleware_uses_product_error_renderer() {
    let handle = embed_local(&HostConfig::local_in_memory()).expect("embed_local");

    let router = Router::new()
        .route("/w", get(token_workspace_handler))
        .layer(auth_layer(handle.gate.clone(), XApiKeyActions));

    let resp = router.oneshot(get_request("/w")).await.expect("dispatch");
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    let body = axum::body::to_bytes(resp.into_body(), usize::MAX)
        .await
        .expect("read body");
    let text = String::from_utf8(body.to_vec()).expect("utf8");
    assert!(
        text.contains("product_error"),
        "the product renderer replaced host's problem+json; got {text}"
    );
}

/// `authenticate_detailed` surfaces the distinct 401 reasons: a valid token
/// resolves, an expired one rejects as Expired, and garbage rejects as Invalid.
#[test]
fn authenticate_detailed_surfaces_reject_reasons() {
    use awaken_iam_host::AuthReject;

    let cfg = HostConfig::local_in_memory();
    let mut handle = embed_local(&cfg).expect("embed_local");

    // A token that is already expired (expiry strictly after creation, both past).
    let expired = handle
        .mint_api_token(MintApiToken {
            id: ApiTokenId("tok_expired".into()),
            principal: svc("svc-expired"),
            workspace: WorkspaceId("wrkspc_test".into()),
            role: RoleId("admin".into()),
            created_at: Timestamp("2020-01-01T00:00:00Z".into()),
            expires_at: Some(Timestamp("2020-01-02T00:00:00Z".into())),
        })
        .expect("mint expired token");

    let now = now_ts(); // 2026 — well past the 2020 expiry
    assert_eq!(
        handle
            .gate
            .authenticate_detailed(&expired.secret, &now, NOW_UNIX)
            .unwrap_err(),
        AuthReject::Expired,
        "an expired token rejects as Expired"
    );
    assert_eq!(
        handle
            .gate
            .authenticate_detailed("sk-awaken-nope.not-real", &now, NOW_UNIX)
            .unwrap_err(),
        AuthReject::Invalid,
        "a forged token rejects as Invalid"
    );
    // The bootstrap admin still authenticates cleanly.
    assert!(
        handle
            .gate
            .authenticate_detailed(&handle.admin_token, &now, NOW_UNIX)
            .is_ok(),
        "the bootstrap admin authenticates"
    );
}

// ── RFC 8693 delegation: `act` exposure and conjunctive authorization ────────

/// Cause/effect decision table for delegated JWTs at the gate:
///
/// | token `act` | gate audience | effect |
/// |---|---|---|
/// | none | matching | principal = sub, actor = None, direct authorization request |
/// | service actor | matching | principal = sub, actor = service, request = actor on_behalf_of [sub] |
/// | service actor | different | Invalid (exact audience, act grants nothing extra) |
#[tokio::test]
async fn gate_exposes_the_delegation_actor_and_authorizes_conjunctively() {
    let cfg = HostConfig::local_in_memory()
        .with_seal_key(JWT_SEED)
        .with_audience("https://api.example.com");
    let handle = embed_local(&cfg).expect("embed_local");
    let authority = handle.jwt_authority.as_ref().expect("jwt_authority");
    let ts = now_ts();

    let direct = authority
        .mint(&make_claims(NOW_UNIX + 300))
        .await
        .expect("mint");
    let verified = handle
        .gate
        .authenticate_verified(&direct, &ts, NOW_UNIX)
        .expect("direct token verifies");
    assert_eq!(verified.actor, None);
    let action = ActionKey("flow.write".into());
    assert!(
        verified
            .authorization_request(action.clone(), ScopeRef::Global)
            .on_behalf_of
            .is_empty()
    );

    let delegated = DelegatedAccessTokenClaims {
        claims: make_claims(NOW_UNIX + 300),
        act: Some(AccessTokenActor {
            sub: "business-service".into(),
            subject_kind: AccessTokenSubjectKind::Service,
        }),
    };
    let token = authority.mint_delegated(&delegated).await.expect("mint");
    let verified = handle
        .gate
        .authenticate_verified(&token, &ts, NOW_UNIX)
        .expect("delegated token verifies");
    let user = PrincipalRef::Account {
        account_id: AccountId("acct_test_1".into()),
    };
    assert_eq!(verified.principal, user);
    assert_eq!(verified.actor, Some(svc("business-service")));
    assert_eq!(verified.access_token.as_ref(), Some(&delegated.claims));
    let request = verified.authorization_request(action, ScopeRef::Global);
    assert_eq!(request.principal, svc("business-service"));
    assert_eq!(request.on_behalf_of, vec![user.clone()]);
    // Existing projections keep their shapes and report the subject.
    assert_eq!(
        handle.gate.authenticate_bearer(&token, &ts, NOW_UNIX),
        Some(user)
    );

    let mut foreign = delegated.clone();
    foreign.claims.aud = "https://other.example.com".into();
    let foreign = authority.mint_delegated(&foreign).await.expect("mint");
    assert_eq!(
        handle
            .gate
            .authenticate_verified(&foreign, &ts, NOW_UNIX)
            .unwrap_err(),
        awaken_iam_host::AuthReject::Invalid
    );
}

#[derive(Clone)]
struct ActorEcho;

impl RouteActions for ActorEcho {
    fn action_for(&self, _method: &axum::http::Method, _path: &str) -> Option<ActionKey> {
        None
    }
}

/// The middleware stashes the subject principal and, for a delegated token,
/// the [`TokenActor`] so downstream handlers can attribute the request to both.
#[tokio::test]
async fn middleware_inserts_the_token_actor_extension() {
    let cfg = HostConfig::local_in_memory().with_seal_key(JWT_SEED);
    let handle = embed_local(&cfg).expect("embed_local");
    let authority = handle.jwt_authority.as_ref().expect("jwt_authority");
    let far_future = 4_102_444_800; // 2100-01-01
    let delegated = DelegatedAccessTokenClaims {
        claims: make_claims(far_future),
        act: Some(AccessTokenActor {
            sub: "business-service".into(),
            subject_kind: AccessTokenSubjectKind::Service,
        }),
    };
    let token = authority.mint_delegated(&delegated).await.expect("mint");
    let app = Router::new()
        .route(
            "/whoami",
            get(
                |principal: axum::Extension<PrincipalRef>,
                 actor: Option<axum::Extension<TokenActor>>| async move {
                    let actor = actor.map(|axum::Extension(TokenActor(actor))| actor);
                    axum::Json(serde_json::json!({
                        "principal": principal.0,
                        "actor": actor,
                    }))
                },
            ),
        )
        .layer(auth_layer(handle.gate.clone(), ActorEcho));
    let response = app
        .oneshot(bearer_request("/whoami", &token))
        .await
        .expect("response");
    assert_eq!(response.status(), StatusCode::OK);
    let body = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .expect("body");
    let json: serde_json::Value = serde_json::from_slice(&body).expect("json");
    assert_eq!(json["principal"]["account_id"], "acct_test_1");
    assert_eq!(json["actor"]["service_id"], "business-service");
}

// ── service-account API tokens: accountability and bulk revocation ───────────

/// I4 decision table at the embedding seam:
///
/// | request | result |
/// |---|---|
/// | admin path, service token without expiry | refused, nothing authenticates |
/// | admin path, two owned expiring tokens of one service account | both authenticate, owner recorded |
/// | revoke the service account | both refused; another account's token survives |
/// | library `mint_api_token` without owner/expiry | unchanged behaviour (bootstrap admin) |
#[test]
fn service_account_tokens_are_owned_expiring_and_revocable_together() {
    let cfg = HostConfig::local_in_memory();
    let mut handle = embed_local(&cfg).expect("embed_local");
    let ts = now_ts();
    let owner = AccountId("acct_owner".into());
    let request = |id: &str, service: &str| MintApiToken {
        id: ApiTokenId(id.into()),
        principal: svc(service),
        workspace: WorkspaceId("wrkspc_ops".into()),
        role: RoleId("admin".into()),
        created_at: Timestamp("2026-01-01T00:00:00Z".into()),
        expires_at: Some(Timestamp("2099-01-01T00:00:00Z".into())),
    };
    let mut unbounded = request("tok_unbounded", "svc-import");
    unbounded.expires_at = None;
    assert!(
        handle
            .mint_service_account_token(unbounded, owner.clone())
            .is_err()
    );

    let first = handle
        .mint_service_account_token(request("tok_import_a", "svc-import"), owner.clone())
        .expect("owned token");
    let second = handle
        .mint_service_account_token(request("tok_import_b", "svc-import"), owner.clone())
        .expect("owned token");
    let other = handle
        .mint_service_account_token(request("tok_other", "svc-other"), owner.clone())
        .expect("owned token");
    assert_eq!(first.owner, owner);

    let revoked = handle.revoke_service_account_tokens("svc-import", ts.clone());
    assert_eq!(
        revoked,
        vec![
            ApiTokenId("tok_import_a".into()),
            ApiTokenId("tok_import_b".into())
        ]
    );
    for secret in [&first.issued.secret, &second.issued.secret] {
        assert_eq!(
            handle
                .gate
                .authenticate_detailed(secret, &ts, NOW_UNIX)
                .unwrap_err(),
            awaken_iam_host::AuthReject::Revoked
        );
    }
    assert!(
        handle
            .gate
            .authenticate_bearer(&other.issued.secret, &ts, NOW_UNIX)
            .is_some()
    );
    assert!(
        handle
            .gate
            .authenticate_bearer(&handle.admin_token, &ts, NOW_UNIX)
            .is_some()
    );
}
