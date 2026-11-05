use std::sync::{
    Arc,
    atomic::{AtomicBool, AtomicU16, AtomicUsize, Ordering},
};

use awaken_iam_client::{HttpAuthzTransport, HttpTransportConfig, RemoteIamClient};
use awaken_iam_server::{
    AccessTokenActor, AccessTokenAuthority, AccessTokenClaims, AccessTokenSubjectKind,
    DelegatedAccessTokenClaims, LocalSeedSigner,
};
use axum::{
    Json, Router,
    extract::State,
    http::{HeaderMap, StatusCode},
    response::{IntoResponse, Response},
    routing::get,
};

use super::*;

const ISSUER: &str = "https://identity.example.test";
const AUDIENCE: &str = "private-session-host";
const NOW: i64 = 1_100;

struct Observation {
    expected: String,
    calls: AtomicUsize,
    status: AtomicU16,
    wrong_subject: AtomicBool,
}

async fn userinfo(State(state): State<Arc<Observation>>, headers: HeaderMap) -> Response {
    state.calls.fetch_add(1, Ordering::SeqCst);
    if headers
        .get("authorization")
        .and_then(|value| value.to_str().ok())
        != Some(state.expected.as_str())
    {
        return StatusCode::UNAUTHORIZED.into_response();
    }
    let status = StatusCode::from_u16(state.status.load(Ordering::SeqCst)).unwrap();
    if status != StatusCode::OK {
        return status.into_response();
    }
    let sub = if state.wrong_subject.load(Ordering::SeqCst) {
        "other"
    } else {
        "alice"
    };
    Json(serde_json::json!({ "sub": sub })).into_response()
}

fn claims() -> AccessTokenClaims {
    AccessTokenClaims {
        iss: ISSUER.into(),
        sub: "alice".into(),
        subject_kind: AccessTokenSubjectKind::Account,
        aud: AUDIENCE.into(),
        exp: 1_900,
        iat: 1_000,
        jti: "direct-alice".into(),
        scope: vec!["openid".into()],
    }
}

#[test]
fn verified_direct_account_uses_original_bearer_and_observes_current_userinfo_every_time() {
    let runtime = tokio::runtime::Runtime::new().unwrap();
    let authority =
        AccessTokenAuthority::new(LocalSeedSigner::new("current-account-fixture", [19; 32]));
    let (direct, rejected) = runtime.block_on(async {
        let direct = authority.mint(&claims()).await.unwrap();
        let mut rejected = Vec::new();
        for variant in [
            AccessTokenClaims {
                subject_kind: AccessTokenSubjectKind::Service,
                ..claims()
            },
            AccessTokenClaims {
                aud: "foreign-audience".into(),
                ..claims()
            },
            AccessTokenClaims {
                iss: "https://foreign.example.test".into(),
                ..claims()
            },
            AccessTokenClaims {
                iat: NOW + 1,
                ..claims()
            },
        ] {
            rejected.push(authority.mint(&variant).await.unwrap());
        }
        rejected.push(
            authority
                .mint_delegated(&DelegatedAccessTokenClaims {
                    claims: claims(),
                    act: Some(AccessTokenActor {
                        sub: "service".into(),
                        subject_kind: AccessTokenSubjectKind::Service,
                    }),
                })
                .await
                .unwrap(),
        );
        rejected.push(concat!("sk-", "awaken-", "current-account-fixture").into());
        (direct, rejected)
    });
    let state = Arc::new(Observation {
        expected: format!("Bearer {direct}"),
        calls: AtomicUsize::new(0),
        status: AtomicU16::new(200),
        wrong_subject: AtomicBool::new(false),
    });
    let (url, server) = runtime.block_on(async {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let url = format!("http://{}", listener.local_addr().unwrap());
        let router = Router::new()
            .route("/v1/oauth/userinfo", get(userinfo))
            .with_state(state.clone());
        (
            url,
            tokio::spawn(async move { axum::serve(listener, router).await.unwrap() }),
        )
    });
    let transport = HttpAuthzTransport::new(
        HttpTransportConfig::new(url).with_service_token("fixture-pdp-carrier"),
    )
    .unwrap();
    let gate = IamGate::remote(RemoteIamClient::new(transport), Some(authority.jwks()))
        .with_issuer(ISSUER)
        .with_audience(AUDIENCE);
    assert_eq!(
        IamGate::open().authenticate_current_account(&direct, NOW),
        Err(AuthReject::Unavailable)
    );
    assert_eq!(
        gate.clone()
            .with_audience("")
            .authenticate_current_account(&direct, NOW),
        Err(AuthReject::Unavailable)
    );
    assert_eq!(
        gate.authenticate_current_account(&direct, 1_900),
        Err(AuthReject::Expired)
    );
    for token in rejected {
        assert_eq!(
            gate.authenticate_current_account(&token, NOW),
            Err(AuthReject::Invalid)
        );
    }
    assert_eq!(state.calls.load(Ordering::SeqCst), 0);
    assert_eq!(
        gate.authenticate_current_account(&direct, NOW),
        Ok(AccountId("alice".into()))
    );
    state.status.store(401, Ordering::SeqCst);
    assert_eq!(
        gate.authenticate_current_account(&direct, NOW),
        Err(AuthReject::Invalid)
    );
    state.status.store(503, Ordering::SeqCst);
    assert_eq!(
        gate.authenticate_current_account(&direct, NOW),
        Err(AuthReject::Unavailable)
    );
    state.status.store(200, Ordering::SeqCst);
    state.wrong_subject.store(true, Ordering::SeqCst);
    assert_eq!(
        gate.authenticate_current_account(&direct, NOW),
        Err(AuthReject::Unavailable)
    );
    assert_eq!(state.calls.load(Ordering::SeqCst), 4);
    server.abort();
}
