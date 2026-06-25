//! Federated workload identity via RFC 8693 token exchange.
//!
//! This module lets an external workload — a CI job, a cloud function, another
//! cloud's STS — present an assertion it already holds from a *trusted external
//! issuer* and receive a short-lived IAM access token for a **service
//! principal**, with no long-lived secret stored on either side. It realizes the
//! "federated workload identity" leg of the [auth-server design]: IAM is the
//! broker, so a workload federates through one trust anchor instead of every
//! product minting its own credentials.
//!
//! The exchange is a single [`AuthApi::exchange_token`](crate::AuthApi::exchange_token)
//! call:
//!
//! ```text
//! 1. The workload presents subject_token (an upstream JWT) at
//!    POST /v1/oauth/token with grant_type=urn:ietf:params:oauth:grant-type:token-exchange.
//! 2. IAM reads the assertion's untrusted `iss`, selects that trusted issuer's
//!    published keys, and verifies the assertion's signature against them.
//! 3. IAM validates the assertion's value claims: issuer match, audience,
//!    expiry, and not-before.
//! 4. IAM resolves the verified (issuer, subject) to a configured workload
//!    binding — the service principal and scopes it may assume.
//! 5. IAM mints its own EdDSA access token for that service principal, signed by
//!    the same key it publishes at /.well-known/jwks.json, and returns it.
//! ```
//!
//! Every step fails closed and is audited. A token-exchange failure never leaks
//! *why* in a way that distinguishes an unknown issuer from a bad signature from
//! a missing binding — the design's "no information leak" rule — beyond the
//! coarse OAuth error code RFC 8693 requires.
//!
//! [auth-server design]: ../../../../docs/design/auth-server.md
//!
//! ## MVP scope
//!
//! Upstream assertions are verified as `EdDSA`/`Ed25519` JWTs, matching the
//! single algorithm IAM signs and publishes with elsewhere; an issuer's trust
//! anchor is the [`Jwks`] it would expose at its own discovery endpoint. The
//! `subject_token_type` is constrained to the JWT family. Mapping is by exact
//! upstream subject. The contract shapes (issuer registry, binding, request,
//! response) are deliberately extensible so a later ADR can add RS256 upstream
//! verification or subject-pattern matching without a wire break.

use awaken_iam_contract::{Jwks, PrincipalRef, ScopeRef, WorkspaceId};
use awaken_iam_core::{RoleBinding, RoleId};
use awaken_iam_preset::ANTHROPIC_ROLE_IDS;
use serde::Deserialize;

use crate::access_token::{AccessTokenError, decode_unverified_claims, verify_signed_claims};

/// OAuth scope prefix marking a federation rule scope that maps to a **workspace
/// role** rather than a plain capability (ADR-0008 decision 5). A rule scope of
/// `workspace:developer` rides the same `scopes` list as a capability scope like
/// `pack.publish`; this prefix is what distinguishes the two.
pub const WORKSPACE_ROLE_SCOPE_PREFIX: &str = "workspace:";

/// Map a federation rule's OAuth scope to the seeded **workspace role** its
/// minted token is treated as holding (ADR-0008 decision 5).
///
/// A scope of the form `workspace:<suffix>` resolves to the workspace role
/// `workspace_<suffix>` (so `workspace:developer` → `workspace_developer`), and
/// only when that role is one of the seeded named-catalog roles. Any other input
/// returns `None` and is **not** a workspace-role mapping: a plain capability
/// scope (`pack.publish`), a bare `workspace:`, or an unknown role
/// (`workspace:superuser`). This is a pure projection onto the existing catalog —
/// it mints no token, writes no binding, and defines no new role.
pub fn workspace_role_for_scope(scope: &str) -> Option<RoleId> {
    let suffix = scope.strip_prefix(WORKSPACE_ROLE_SCOPE_PREFIX)?;
    if suffix.is_empty() {
        return None;
    }
    let role_id = format!("workspace_{suffix}");
    ANTHROPIC_ROLE_IDS
        .iter()
        .find(|known| **known == role_id)
        .map(|known| RoleId((*known).to_owned()))
}

/// RFC 8693 `grant_type` selecting a token exchange at the token endpoint.
pub const TOKEN_EXCHANGE_GRANT_TYPE: &str = "urn:ietf:params:oauth:grant-type:token-exchange";
/// RFC 8693 token-type URN for a generic JWT subject token.
pub const SUBJECT_TOKEN_TYPE_JWT: &str = "urn:ietf:params:oauth:token-type:jwt";
/// RFC 8693 token-type URN for an OIDC ID token presented as the subject token.
pub const SUBJECT_TOKEN_TYPE_ID_TOKEN: &str = "urn:ietf:params:oauth:token-type:id_token";
/// RFC 8693 token-type URN for an access token presented as the subject token.
pub const SUBJECT_TOKEN_TYPE_ACCESS_TOKEN: &str = "urn:ietf:params:oauth:token-type:access_token";
/// RFC 8693 `issued_token_type` of the IAM token this exchange returns.
pub const ISSUED_TOKEN_TYPE_ACCESS_TOKEN: &str = "urn:ietf:params:oauth:token-type:access_token";
/// OAuth `token_type` of the issued bearer token.
pub const BEARER_TOKEN_TYPE: &str = "Bearer";

/// A binding from a verified upstream subject to an IAM service principal.
///
/// This is the authorization decision of federation: only an upstream subject
/// with a binding may assume a service principal, and only the principal and
/// scopes named here. Absent a binding the exchange fails closed — a valid
/// upstream assertion is necessary but never sufficient.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WorkloadBinding {
    /// Exact upstream `sub` this binding authorizes.
    pub subject: String,
    /// Service principal id the issued IAM token authenticates as.
    pub service_id: String,
    /// Audience stamped into the issued IAM token (the service it targets).
    pub audience: String,
    /// Scopes granted to the issued IAM token.
    ///
    /// A scope of the form `workspace:<role>` is a **federation rule → workspace
    /// role** mapping (ADR-0008 decision 5): the minted token is treated as
    /// holding that workspace role in [`workspace`](WorkloadBinding::workspace).
    /// See [`workspace_role_bindings`](WorkloadBinding::workspace_role_bindings).
    /// Any other scope is a plain capability carried verbatim on the token.
    pub scopes: Vec<String>,
    /// Workspace the federated token holds its workspace roles in.
    ///
    /// A service account is implicitly in the default workspace and explicitly
    /// addable to others (ADR-0008 decision 5); this names the workspace the
    /// rule's `workspace:<role>` scopes resolve their [`RoleBinding`]s at.
    pub workspace: WorkspaceId,
}

impl WorkloadBinding {
    /// The workspace [`RoleBinding`]s the issued token is treated as holding
    /// (ADR-0008 decision 5).
    ///
    /// Each `workspace:<role>` scope is projected to a binding that holds the
    /// corresponding seeded workspace role for this rule's service principal,
    /// scoped to the rule's [`workspace`](WorkloadBinding::workspace). Scopes that
    /// are not workspace-role scopes (plain capabilities, unknown roles) are
    /// skipped, and a role listed more than once yields one binding, first-seen
    /// order preserved. The result reuses the existing `RoleBinding` engine type:
    /// federation grants a workspace role through the one permission model, with
    /// no separate federation engine.
    pub fn workspace_role_bindings(&self) -> Vec<RoleBinding> {
        let principal = PrincipalRef::Service {
            service_id: self.service_id.clone(),
        };
        let mut bindings: Vec<RoleBinding> = Vec::new();
        for scope in &self.scopes {
            let Some(role) = workspace_role_for_scope(scope) else {
                continue;
            };
            if bindings.iter().any(|binding| binding.role == role) {
                continue;
            }
            bindings.push(RoleBinding {
                principal: principal.clone(),
                role,
                scope: ScopeRef::Workspace {
                    workspace_id: self.workspace.clone(),
                },
            });
        }
        bindings
    }
}

/// A trusted external issuer whose assertions IAM will exchange for IAM tokens.
///
/// The issuer is identified by the `iss` it stamps into its assertions; its
/// trust anchor is the set of public [`keys`](TrustedIssuer::keys) IAM verifies
/// against (the issuer's own JWKS). An assertion is honored only when its
/// audience is one of [`audiences`](TrustedIssuer::audiences) and its verified
/// subject has a [`binding`](TrustedIssuer::bindings).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TrustedIssuer {
    /// Issuer identifier matching the assertion `iss` claim.
    pub issuer: String,
    /// Audience values an assertion may carry to be accepted (`aud`).
    pub audiences: Vec<String>,
    /// Public keys the assertion signature is verified against.
    pub keys: Jwks,
    /// Subject-to-principal bindings this issuer authorizes.
    pub bindings: Vec<WorkloadBinding>,
    /// Whether exchanges from this issuer are currently allowed.
    pub enabled: bool,
}

impl TrustedIssuer {
    fn binding_for(&self, subject: &str) -> Option<&WorkloadBinding> {
        self.bindings
            .iter()
            .find(|binding| binding.subject == subject)
    }

    fn accepts_audience(&self, audience: &AudienceClaim) -> bool {
        self.audiences
            .iter()
            .any(|allowed| audience.contains(allowed))
    }
}

/// Request to exchange an upstream assertion for an IAM access token.
///
/// Mirrors the RFC 8693 token-exchange parameters the HTTP layer parses from a
/// `POST /v1/oauth/token` form body, plus the wall-clock the validation and the
/// issued token are stamped against. Times are unix seconds, matching the
/// `exp`/`nbf`/`iat` of the JWTs on both sides of the exchange.
#[derive(Debug, Clone)]
pub struct TokenExchangeRequest {
    /// RFC 8693 `grant_type`; must be [`TOKEN_EXCHANGE_GRANT_TYPE`].
    pub grant_type: String,
    /// The upstream assertion presented as the subject token.
    pub subject_token: String,
    /// RFC 8693 `subject_token_type`; must be a JWT-family URN.
    pub subject_token_type: String,
    /// Optional requested audience for the issued IAM token. When present it
    /// must equal the binding's audience; when absent the binding's audience is
    /// used.
    pub audience: Option<String>,
    /// Current time as unix seconds, for assertion `exp`/`nbf` validation and
    /// the issued token's `iat`/`exp`.
    pub now: i64,
    /// Lifetime of the issued IAM access token, in seconds.
    pub issued_token_lifetime_secs: i64,
}

/// A successful token-exchange result (RFC 8693 token-exchange response).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TokenExchangeResponse {
    /// The minted IAM access token (compact `EdDSA` JWT).
    pub access_token: String,
    /// Type of the issued token: [`ISSUED_TOKEN_TYPE_ACCESS_TOKEN`].
    pub issued_token_type: String,
    /// OAuth token type: `Bearer`.
    pub token_type: String,
    /// Lifetime of the issued token in seconds.
    pub expires_in: i64,
    /// Scopes granted to the issued token.
    pub scope: Vec<String>,
    /// The service principal the issued token authenticates as.
    pub principal: PrincipalRef,
    /// Workspace roles the issued token is treated as holding (ADR-0008
    /// decision 5), resolved from the federation rule's `workspace:<role>`
    /// scopes. Empty when the rule grants only plain capability scopes.
    pub workspace_roles: Vec<RoleBinding>,
}

/// Stable machine-readable reason a token exchange was rejected.
///
/// Recorded in the audit trail. The public OAuth surface collapses these into
/// the coarse RFC 8693 error codes via [`oauth_error_code`](TokenExchangeError::oauth_error_code)
/// so a caller cannot distinguish an unknown issuer from a missing binding.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum TokenExchangeError {
    /// The `grant_type` was not the token-exchange grant.
    #[error("unsupported grant type for token exchange")]
    UnsupportedGrantType,
    /// The `subject_token_type` was not a supported JWT-family URN.
    #[error("unsupported subject token type")]
    UnsupportedSubjectTokenType,
    /// The subject token was not a well-formed JWT.
    #[error("subject token is malformed")]
    MalformedSubjectToken,
    /// No enabled trusted issuer matches the assertion's `iss`.
    #[error("subject token issuer is not trusted")]
    UntrustedIssuer,
    /// The assertion signature did not verify against the issuer's keys.
    #[error("subject token signature is invalid")]
    InvalidSignature,
    /// The verified `iss` did not match the selected issuer (token confusion).
    #[error("subject token issuer mismatch")]
    IssuerMismatch,
    /// The assertion audience was not accepted by the issuer.
    #[error("subject token audience is not accepted")]
    AudienceRejected,
    /// The assertion was expired or not yet valid at `now`.
    #[error("subject token is expired or not yet valid")]
    AssertionNotActive,
    /// No workload binding maps the verified subject to a service principal.
    #[error("no workload binding for the verified subject")]
    NoBinding,
    /// A requested `audience` disagreed with the binding's audience.
    #[error("requested audience is not permitted for this binding")]
    RequestedAudienceRejected,
    /// Minting the IAM access token failed.
    #[error(transparent)]
    Mint(#[from] AccessTokenError),
}

impl TokenExchangeError {
    /// The coarse RFC 8693 / RFC 6749 OAuth error code for this failure.
    ///
    /// The mapping is intentionally lossy so the wire response never reveals
    /// which internal check failed.
    pub fn oauth_error_code(&self) -> &'static str {
        match self {
            TokenExchangeError::UnsupportedGrantType => "unsupported_grant_type",
            TokenExchangeError::UnsupportedSubjectTokenType => "invalid_request",
            TokenExchangeError::MalformedSubjectToken
            | TokenExchangeError::UntrustedIssuer
            | TokenExchangeError::InvalidSignature
            | TokenExchangeError::IssuerMismatch
            | TokenExchangeError::AudienceRejected
            | TokenExchangeError::AssertionNotActive
            | TokenExchangeError::NoBinding => "invalid_grant",
            TokenExchangeError::RequestedAudienceRejected => "invalid_target",
            TokenExchangeError::Mint(_) => "server_error",
        }
    }
}

/// Verified upstream assertion claims a binding is resolved against.
#[derive(Debug)]
pub(crate) struct VerifiedAssertion {
    /// Issuer that signed the assertion.
    pub issuer: String,
    /// Subject the assertion authenticates.
    pub subject: String,
}

/// An upstream issuer's assertion claim set (a JWT payload).
///
/// `aud` is accepted as a single string or an array per RFC 7519, and `nbf`/
/// `iat` are optional. Only the coordinates IAM needs to broker the exchange are
/// modeled; unknown claims are ignored.
#[derive(Debug, Clone, Deserialize)]
struct UpstreamAssertionClaims {
    iss: String,
    sub: String,
    #[serde(default)]
    aud: Option<AudienceClaim>,
    exp: i64,
    #[serde(default)]
    nbf: Option<i64>,
}

/// The `iss` claim read from an unverified assertion to route key selection.
#[derive(Debug, Clone, Deserialize)]
struct IssuerHint {
    iss: String,
}

/// JWT `aud`: a single audience or an array of them (RFC 7519 §4.1.3).
#[derive(Debug, Clone, Deserialize)]
#[serde(untagged)]
enum AudienceClaim {
    One(String),
    Many(Vec<String>),
}

impl AudienceClaim {
    fn contains(&self, audience: &str) -> bool {
        match self {
            AudienceClaim::One(value) => value == audience,
            AudienceClaim::Many(values) => values.iter().any(|value| value == audience),
        }
    }
}

/// Registry of trusted external issuers backing federated token exchange.
///
/// Held by [`AuthApi`](crate::AuthApi); the minting itself reuses the API's
/// access-token signing authority so issued tokens verify against the same
/// published JWKS as every other IAM access token.
#[derive(Debug, Clone, Default)]
pub struct TrustedIssuerRegistry {
    issuers: Vec<TrustedIssuer>,
}

impl TrustedIssuerRegistry {
    /// An empty registry that trusts no external issuer.
    pub fn new() -> Self {
        Self::default()
    }

    /// Register (or replace, by `issuer`) a trusted external issuer.
    pub fn upsert(&mut self, issuer: TrustedIssuer) {
        self.issuers
            .retain(|existing| existing.issuer != issuer.issuer);
        self.issuers.push(issuer);
    }

    /// Whether any trusted issuer is registered.
    pub fn is_empty(&self) -> bool {
        self.issuers.is_empty()
    }

    /// Verify a token-exchange request's subject token and resolve the binding
    /// it authorizes, leaving the actual IAM-token minting to the caller.
    ///
    /// Returns the resolved [`WorkloadBinding`] and the [`VerifiedAssertion`] it
    /// was matched on. All cryptographic and value-claim checks happen here; the
    /// caller only needs to mint and audit.
    pub(crate) fn authorize(
        &self,
        request: &TokenExchangeRequest,
    ) -> Result<(&WorkloadBinding, VerifiedAssertion), TokenExchangeError> {
        if request.grant_type != TOKEN_EXCHANGE_GRANT_TYPE {
            return Err(TokenExchangeError::UnsupportedGrantType);
        }
        if !is_supported_subject_token_type(&request.subject_token_type) {
            return Err(TokenExchangeError::UnsupportedSubjectTokenType);
        }

        // Read the untrusted `iss` only to select which issuer's keys verify the
        // signature; nothing here is trusted until the signature checks out.
        let hint: IssuerHint = decode_unverified_claims(&request.subject_token)
            .map_err(|_| TokenExchangeError::MalformedSubjectToken)?;
        let issuer = self
            .issuers
            .iter()
            .find(|candidate| candidate.enabled && candidate.issuer == hint.iss)
            .ok_or(TokenExchangeError::UntrustedIssuer)?;

        let claims: UpstreamAssertionClaims =
            verify_signed_claims(&request.subject_token, &issuer.keys).map_err(
                |err| match err {
                    AccessTokenError::SignatureInvalid => TokenExchangeError::InvalidSignature,
                    AccessTokenError::UnknownKid(_) | AccessTokenError::UnsupportedKey => {
                        TokenExchangeError::InvalidSignature
                    }
                    _ => TokenExchangeError::MalformedSubjectToken,
                },
            )?;

        // Defense in depth: the verified `iss` must match the issuer whose keys
        // we just trusted, so a key shared across issuers cannot be confused.
        if claims.iss != issuer.issuer {
            return Err(TokenExchangeError::IssuerMismatch);
        }

        match &claims.aud {
            Some(audience) if issuer.accepts_audience(audience) => {}
            _ => return Err(TokenExchangeError::AudienceRejected),
        }

        if request.now >= claims.exp {
            return Err(TokenExchangeError::AssertionNotActive);
        }
        if let Some(nbf) = claims.nbf
            && request.now < nbf
        {
            return Err(TokenExchangeError::AssertionNotActive);
        }

        let binding = issuer
            .binding_for(&claims.sub)
            .ok_or(TokenExchangeError::NoBinding)?;

        if let Some(requested) = request.audience.as_deref()
            && requested != binding.audience
        {
            return Err(TokenExchangeError::RequestedAudienceRejected);
        }

        Ok((
            binding,
            VerifiedAssertion {
                issuer: claims.iss,
                subject: claims.sub,
            },
        ))
    }
}

fn is_supported_subject_token_type(token_type: &str) -> bool {
    matches!(
        token_type,
        SUBJECT_TOKEN_TYPE_JWT | SUBJECT_TOKEN_TYPE_ID_TOKEN | SUBJECT_TOKEN_TYPE_ACCESS_TOKEN
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::access_token::{AccessTokenAuthority, LocalSeedSigner};
    use serde::Serialize;

    /// An external issuer's assertion, signed for a contract test.
    #[derive(Serialize)]
    struct UpstreamClaims {
        iss: String,
        sub: String,
        aud: String,
        exp: i64,
        #[serde(skip_serializing_if = "Option::is_none")]
        nbf: Option<i64>,
    }

    fn issuer_authority() -> AccessTokenAuthority {
        AccessTokenAuthority::new(LocalSeedSigner::new("ext-key-1", [9u8; 32]))
    }

    fn registry(keys: Jwks) -> TrustedIssuerRegistry {
        let mut registry = TrustedIssuerRegistry::new();
        registry.upsert(TrustedIssuer {
            issuer: "https://sts.ci.example".into(),
            audiences: vec!["https://iam.example".into()],
            keys,
            bindings: vec![WorkloadBinding {
                subject: "repo:acme/app:ref:refs/heads/main".into(),
                service_id: "svc_ci_publisher".into(),
                audience: "packs-service".into(),
                scopes: vec!["pack.publish".into()],
                workspace: WorkspaceId("wrkspc_default".into()),
            }],
            enabled: true,
        });
        registry
    }

    async fn assertion(authority: &AccessTokenAuthority, claims: &UpstreamClaims) -> String {
        authority.sign_claims(claims).await.unwrap()
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

    fn valid_claims() -> UpstreamClaims {
        UpstreamClaims {
            iss: "https://sts.ci.example".into(),
            sub: "repo:acme/app:ref:refs/heads/main".into(),
            aud: "https://iam.example".into(),
            exp: 2_000,
            nbf: None,
        }
    }

    #[tokio::test]
    async fn authorizes_a_trusted_assertion_to_its_bound_principal() {
        let authority = issuer_authority();
        let registry = registry(authority.jwks());
        let token = assertion(&authority, &valid_claims()).await;

        let (binding, verified) = registry.authorize(&request(token)).unwrap();
        assert_eq!(binding.service_id, "svc_ci_publisher");
        assert_eq!(binding.scopes, vec!["pack.publish".to_owned()]);
        assert_eq!(verified.issuer, "https://sts.ci.example");
        assert_eq!(verified.subject, "repo:acme/app:ref:refs/heads/main");
    }

    #[tokio::test]
    async fn an_untrusted_issuer_fails_closed() {
        let authority = issuer_authority();
        let registry = registry(authority.jwks());
        let mut claims = valid_claims();
        claims.iss = "https://sts.evil.example".into();
        let token = assertion(&authority, &claims).await;

        let err = registry.authorize(&request(token)).unwrap_err();
        assert_eq!(err, TokenExchangeError::UntrustedIssuer);
        assert_eq!(err.oauth_error_code(), "invalid_grant");
    }

    #[tokio::test]
    async fn an_assertion_signed_by_an_unknown_key_fails_closed() {
        let registry = registry(issuer_authority().jwks());
        // A forger signs a well-formed assertion with a different key.
        let forger = AccessTokenAuthority::new(LocalSeedSigner::new("ext-key-1", [1u8; 32]));
        let token = assertion(&forger, &valid_claims()).await;

        let err = registry.authorize(&request(token)).unwrap_err();
        assert_eq!(err, TokenExchangeError::InvalidSignature);
    }

    #[tokio::test]
    async fn a_rejected_audience_fails_closed() {
        let authority = issuer_authority();
        let registry = registry(authority.jwks());
        let mut claims = valid_claims();
        claims.aud = "https://other.example".into();
        let token = assertion(&authority, &claims).await;

        let err = registry.authorize(&request(token)).unwrap_err();
        assert_eq!(err, TokenExchangeError::AudienceRejected);
    }

    #[tokio::test]
    async fn an_expired_or_not_yet_valid_assertion_fails_closed() {
        let authority = issuer_authority();
        let registry = registry(authority.jwks());

        let mut expired = valid_claims();
        expired.exp = 500; // now is 1_000
        let token = assertion(&authority, &expired).await;
        assert_eq!(
            registry.authorize(&request(token)).unwrap_err(),
            TokenExchangeError::AssertionNotActive
        );

        let mut future = valid_claims();
        future.nbf = Some(1_500); // now is 1_000
        let token = assertion(&authority, &future).await;
        assert_eq!(
            registry.authorize(&request(token)).unwrap_err(),
            TokenExchangeError::AssertionNotActive
        );
    }

    #[tokio::test]
    async fn a_verified_subject_without_a_binding_fails_closed() {
        let authority = issuer_authority();
        let registry = registry(authority.jwks());
        let mut claims = valid_claims();
        claims.sub = "repo:acme/app:ref:refs/heads/feature".into();
        let token = assertion(&authority, &claims).await;

        assert_eq!(
            registry.authorize(&request(token)).unwrap_err(),
            TokenExchangeError::NoBinding
        );
    }

    #[tokio::test]
    async fn an_unsupported_grant_or_subject_token_type_fails_closed() {
        let authority = issuer_authority();
        let registry = registry(authority.jwks());
        let token = assertion(&authority, &valid_claims()).await;

        let mut wrong_grant = request(token.clone());
        wrong_grant.grant_type = "authorization_code".into();
        let err = registry.authorize(&wrong_grant).unwrap_err();
        assert_eq!(err, TokenExchangeError::UnsupportedGrantType);
        assert_eq!(err.oauth_error_code(), "unsupported_grant_type");

        let mut wrong_type = request(token);
        wrong_type.subject_token_type = "urn:ietf:params:oauth:token-type:saml2".into();
        assert_eq!(
            registry.authorize(&wrong_type).unwrap_err(),
            TokenExchangeError::UnsupportedSubjectTokenType
        );
    }

    #[tokio::test]
    async fn a_disabled_issuer_is_not_trusted() {
        let authority = issuer_authority();
        let mut registry = registry(authority.jwks());
        registry.upsert(TrustedIssuer {
            issuer: "https://sts.ci.example".into(),
            audiences: vec!["https://iam.example".into()],
            keys: authority.jwks(),
            bindings: vec![],
            enabled: false,
        });
        let token = assertion(&authority, &valid_claims()).await;
        assert_eq!(
            registry.authorize(&request(token)).unwrap_err(),
            TokenExchangeError::UntrustedIssuer
        );
    }

    #[tokio::test]
    async fn a_requested_audience_must_match_the_binding() {
        let authority = issuer_authority();
        let registry = registry(authority.jwks());
        let token = assertion(&authority, &valid_claims()).await;
        let mut req = request(token);
        req.audience = Some("other-service".into());
        let err = registry.authorize(&req).unwrap_err();
        assert_eq!(err, TokenExchangeError::RequestedAudienceRejected);
        assert_eq!(err.oauth_error_code(), "invalid_target");
    }

    #[test]
    fn a_malformed_subject_token_fails_closed() {
        let registry = registry(issuer_authority().jwks());
        assert_eq!(
            registry
                .authorize(&request("not-a-jwt".into()))
                .unwrap_err(),
            TokenExchangeError::MalformedSubjectToken
        );
    }

    #[test]
    fn each_workspace_scope_maps_to_its_seeded_workspace_role() {
        // Every seeded workspace role is reachable by its `workspace:<suffix>`
        // scope, matching the ADR-0008 decision-5 example `workspace:developer`.
        for (scope, role) in [
            ("workspace:admin", "workspace_admin"),
            ("workspace:developer", "workspace_developer"),
            ("workspace:limited_developer", "workspace_limited_developer"),
            ("workspace:user", "workspace_user"),
            ("workspace:billing", "workspace_billing"),
        ] {
            assert_eq!(
                workspace_role_for_scope(scope),
                Some(RoleId(role.into())),
                "scope {scope} should map to {role}"
            );
        }
    }

    #[test]
    fn non_workspace_scopes_do_not_map_to_a_role() {
        // A plain capability, a bare prefix, an unknown role, and an org-role
        // name (org roles are not workspace roles) all map to nothing.
        for scope in [
            "pack.publish",
            "workspace:",
            "workspace:superuser",
            "workspace:admin:extra",
            "developer",
            "admin",
        ] {
            assert_eq!(
                workspace_role_for_scope(scope),
                None,
                "scope {scope} must not map to a workspace role"
            );
        }
    }

    #[test]
    fn workspace_role_bindings_project_only_workspace_scopes_to_the_service() {
        let binding = WorkloadBinding {
            subject: "repo:acme/app:ref:refs/heads/main".into(),
            service_id: "svc_ci_publisher".into(),
            audience: "packs-service".into(),
            // Mixes a capability scope, two distinct workspace roles, an unknown
            // workspace role, and a duplicate of the first role.
            scopes: vec![
                "pack.publish".into(),
                "workspace:developer".into(),
                "workspace:superuser".into(),
                "workspace:admin".into(),
                "workspace:developer".into(),
            ],
            workspace: WorkspaceId("wrkspc_acme".into()),
        };

        // Only the two known workspace roles survive, de-duplicated and in
        // first-seen order, each bound to the service principal at the rule's
        // workspace; the capability and unknown role contribute nothing.
        assert_eq!(
            binding.workspace_role_bindings(),
            vec![
                RoleBinding {
                    principal: PrincipalRef::Service {
                        service_id: "svc_ci_publisher".into()
                    },
                    role: RoleId("workspace_developer".into()),
                    scope: ScopeRef::Workspace {
                        workspace_id: WorkspaceId("wrkspc_acme".into())
                    },
                },
                RoleBinding {
                    principal: PrincipalRef::Service {
                        service_id: "svc_ci_publisher".into()
                    },
                    role: RoleId("workspace_admin".into()),
                    scope: ScopeRef::Workspace {
                        workspace_id: WorkspaceId("wrkspc_acme".into())
                    },
                },
            ]
        );
    }

    #[test]
    fn a_capability_only_rule_holds_no_workspace_role() {
        let binding = WorkloadBinding {
            subject: "repo:acme/app:ref:refs/heads/main".into(),
            service_id: "svc_ci_publisher".into(),
            audience: "packs-service".into(),
            scopes: vec!["pack.publish".into()],
            workspace: WorkspaceId("wrkspc_default".into()),
        };
        assert!(binding.workspace_role_bindings().is_empty());
    }
}
