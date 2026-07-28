//! End-to-end federated workload identity (RFC 8693 token exchange).
//!
//! Drives the public seam a deployment wires: register a trusted external
//! issuer, present an assertion that issuer signed, and exchange it for an IAM
//! access token that verifies against IAM's own published JWKS — exercising the
//! whole path through [`AuthApi::exchange_token`] with no internal access.

use awaken_iam_contract::{PrincipalRef, ScopeRef, WorkspaceId};
use awaken_iam_core::{RoleBinding, RoleId};
use awaken_iam_server::{
    AccessTokenAuthority, AuthApi, AuthApiError, AuthAuditEvent, LocalSeedSigner,
    SUBJECT_TOKEN_TYPE_JWT, TOKEN_EXCHANGE_GRANT_TYPE, TokenExchangeError, TokenExchangeRequest,
    TrustedIssuer, WorkloadBinding, verify_access_token,
};
use serde::Serialize;

const ISSUER: &str = "https://sts.ci.example";
const SUBJECT: &str = "repo:acme/app:ref:refs/heads/main";
const IAM_ISSUER: &str = "https://iam.example";
const WORKSPACE: &str = "wrkspc_default";

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
    let issuer = AccessTokenAuthority::new(LocalSeedSigner::new("ext-key-1", [9u8; 32]));
    let mut api = AuthApi::new().with_issuer(IAM_ISSUER);
    api.register_trusted_issuer(TrustedIssuer {
        issuer: ISSUER.into(),
        audiences: vec![IAM_ISSUER.into()],
        keys: issuer.jwks(),
        bindings: vec![WorkloadBinding {
            subject: SUBJECT.into(),
            service_id: "svc_ci_publisher".into(),
            audience: "packs-service".into(),
            scopes: vec!["pack.publish".into(), "workspace:developer".into()],
            workspace: WorkspaceId(WORKSPACE.into()),
        }],
        enabled: true,
    });
    (api, issuer)
}

async fn assertion(issuer: &AccessTokenAuthority, aud: &str) -> String {
    issuer
        .sign_claims(&UpstreamClaims {
            iss: ISSUER.into(),
            sub: SUBJECT.into(),
            aud: aud.into(),
            exp: 2_000,
        })
        .await
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

#[tokio::test]
async fn exchange_mints_an_iam_token_for_the_bound_service_principal() {
    let (mut api, issuer) = federated();
    let response = api
        .exchange_token(request(assertion(&issuer, IAM_ISSUER).await))
        .await
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
    assert_eq!(
        response.scope,
        vec!["pack.publish".to_owned(), "workspace:developer".to_owned()]
    );

    // The rule's `workspace:developer` OAuth scope maps to the workspace role the
    // minted token is treated as holding for its service principal (ADR-0008
    // decision 5), while the plain `pack.publish` capability yields no role.
    assert_eq!(
        response.workspace_roles,
        vec![RoleBinding {
            principal: PrincipalRef::Service {
                service_id: "svc_ci_publisher".into()
            },
            role: RoleId("workspace_developer".into()),
            scope: ScopeRef::Workspace {
                workspace_id: WorkspaceId(WORKSPACE.into())
            },
        }]
    );

    // It is signed by IAM's own key and verifies against the published JWKS,
    // identically to any other IAM access token — no shared secret needed.
    let claims = verify_access_token(&response.access_token, &api.jwks()).unwrap();
    assert_eq!(claims.iss, IAM_ISSUER);
    assert_eq!(claims.sub, "svc_ci_publisher");
    assert_eq!(
        claims.subject_kind,
        awaken_iam_server::AccessTokenSubjectKind::Service
    );
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

#[tokio::test]
async fn exchange_rejects_an_untrusted_assertion_and_audits_it() {
    let (mut api, issuer) = federated();
    // Same issuer id, but the assertion targets an audience IAM does not
    // accept, so it must fail closed and emit no token.
    let err = api
        .exchange_token(request(assertion(&issuer, "https://wrong.example").await))
        .await
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
