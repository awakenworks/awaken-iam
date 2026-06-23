//! End-to-end federated workload identity (RFC 8693 token exchange).
//!
//! Drives the public seam a deployment wires: register a trusted external
//! issuer, present an assertion that issuer signed, and exchange it for an IAM
//! access token that verifies against IAM's own published JWKS — exercising the
//! whole path through [`AuthApi::exchange_token`] with no internal access.

use awaken_iam_contract::PrincipalRef;
use awaken_iam_server::{
    AccessTokenAuthority, AuthApi, AuthApiError, AuthAuditEvent, SUBJECT_TOKEN_TYPE_JWT,
    SigningKeyMaterial, TOKEN_EXCHANGE_GRANT_TYPE, TokenExchangeError, TokenExchangeRequest,
    TrustedIssuer, WorkloadBinding, verify_access_token,
};
use serde::Serialize;

const ISSUER: &str = "https://sts.ci.example";
const SUBJECT: &str = "repo:acme/app:ref:refs/heads/main";
const IAM_ISSUER: &str = "https://iam.example";

/// An external issuer's assertion, signed for the exchange.
#[derive(Serialize)]
struct UpstreamClaims {
    iss: String,
    sub: String,
    aud: String,
    exp: i64,
}

/// Build an `AuthApi` that trusts a single external issuer, plus the authority
/// that stands in as that issuer's signing STS.
fn federated() -> (AuthApi, AccessTokenAuthority) {
    let issuer = AccessTokenAuthority::new(SigningKeyMaterial::new("ext-key-1", [9u8; 32]));
    let mut api = AuthApi::new().with_issuer(IAM_ISSUER);
    api.register_trusted_issuer(TrustedIssuer {
        issuer: ISSUER.into(),
        audiences: vec![IAM_ISSUER.into()],
        keys: issuer.jwks(),
        bindings: vec![WorkloadBinding {
            subject: SUBJECT.into(),
            service_id: "svc_ci_publisher".into(),
            audience: "packs-service".into(),
            scopes: vec!["pack.publish".into()],
        }],
        enabled: true,
    });
    (api, issuer)
}

fn assertion(issuer: &AccessTokenAuthority, aud: &str) -> String {
    issuer
        .sign_claims(&UpstreamClaims {
            iss: ISSUER.into(),
            sub: SUBJECT.into(),
            aud: aud.into(),
            exp: 2_000,
        })
        .unwrap()
}

fn request(subject_token: String) -> TokenExchangeRequest {
    TokenExchangeRequest {
        grant_type: TOKEN_EXCHANGE_GRANT_TYPE.into(),
        subject_token,
        subject_token_type: SUBJECT_TOKEN_TYPE_JWT.into(),
        audience: None,
        now: 1_000,
        issued_token_lifetime_secs: 3_600,
    }
}

#[test]
fn exchange_mints_an_iam_token_for_the_bound_service_principal() {
    let (mut api, issuer) = federated();
    let response = api
        .exchange_token(request(assertion(&issuer, IAM_ISSUER)))
        .unwrap();

    // The issued token authenticates the bound service principal with its
    // scopes, targets the bound audience, and is RFC 8693-shaped.
    assert_eq!(
        response.principal,
        PrincipalRef::Service {
            service_id: "svc_ci_publisher".into()
        }
    );
    assert_eq!(response.token_type, "Bearer");
    assert_eq!(response.expires_in, 3_600);
    assert_eq!(response.scope, vec!["pack.publish".to_owned()]);

    // It is signed by IAM's own key and verifies against the published JWKS,
    // identically to any other IAM access token — no shared secret needed.
    let claims = verify_access_token(&response.access_token, &api.jwks()).unwrap();
    assert_eq!(claims.iss, IAM_ISSUER);
    assert_eq!(claims.sub, "svc_ci_publisher");
    assert_eq!(claims.aud, "packs-service");
    assert_eq!(claims.iat, 1_000);
    assert_eq!(claims.exp, 4_600);
    assert!(claims.jti.starts_with("jti_"));

    assert!(api.audit_log().iter().any(|event| matches!(
        event,
        AuthAuditEvent::WorkloadIdentityFederated { issuer, subject, .. }
        if issuer == ISSUER && subject == SUBJECT
    )));
}

#[test]
fn exchange_rejects_an_untrusted_assertion_and_audits_it() {
    let (mut api, issuer) = federated();
    // Same issuer id, but the assertion targets an audience IAM does not
    // accept, so it must fail closed and emit no token.
    let err = api
        .exchange_token(request(assertion(&issuer, "https://wrong.example")))
        .unwrap_err();
    assert!(matches!(
        err,
        AuthApiError::TokenExchange(TokenExchangeError::AudienceRejected)
    ));
    assert!(api.audit_log().iter().any(|event| matches!(
        event,
        AuthAuditEvent::WorkloadIdentityRejected {
            reason: TokenExchangeError::AudienceRejected,
            ..
        }
    )));
    assert!(
        !api.audit_log()
            .iter()
            .any(|event| matches!(event, AuthAuditEvent::WorkloadIdentityFederated { .. }))
    );
}
