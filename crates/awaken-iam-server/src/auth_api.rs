//! Third-party authentication HTTP API surface.
//!
//! This module is the framework-agnostic seam that exposes the browser-facing
//! auth endpoints on top of the login loop primitives in
//! [`awaken_iam_core`]. It deliberately speaks in logical request/response
//! values (URLs, `Set-Cookie` header strings, view DTOs) rather than binding to
//! a concrete HTTP framework, matching the MVP in-process shape used elsewhere
//! in the server crate. A deployment maps these onto its router of choice.
//!
//! The routes form one canonical `/v1` auth tree (plus the well-known discovery
//! paths), as specified by the auth-server design — never two paths for one job:
//!
//! | Route | Method on [`AuthApi`] |
//! |---|---|
//! | `GET /.well-known/openid-configuration` | [`AuthApi::openid_configuration`] |
//! | `GET /.well-known/jwks.json` | [`AuthApi::jwks`] |
//! | `POST /v1/tokens` (access) | [`AuthApi::mint_access_token`] |
//! | `GET /v1/oauth/authorize` (downstream OP) | [`AuthApi::authorize`] |
//! | `POST /v1/oauth/token` (`authorization_code`) | [`AuthApi::redeem_authorization_code`] |
//! | `POST /v1/oauth/token` (initial grant) | [`AuthApi::issue_token_grant`] |
//! | `POST /v1/oauth/token` (`refresh_token`) | [`AuthApi::refresh_token_grant`] |
//! | `POST /v1/oauth/token` (`refresh_token`, OP client) | [`AuthApi::op_refresh_token_grant`] |
//! | `POST /v1/oauth/revoke` (RFC 7009) | [`AuthApi::revoke_token`] |
//! | `GET /v1/auth/providers` | [`AuthApi::list_providers`] |
//! | `GET /v1/auth/login/{provider}` | [`AuthApi::start_login`] |
//! | `GET /v1/auth/callback/{provider}` | [`AuthApi::complete_callback`] |
//! | `GET /v1/session` | [`AuthApi::current_session`] |
//! | `DELETE /v1/session` | [`AuthApi::logout`] |
//! | `GET /v1/oauth/userinfo` | [`AuthApi::userinfo`] |
//! | `GET /v1/account/identities` | [`AuthApi::list_identities`] |
//! | `POST /v1/account/identities` | [`AuthApi::link_identity`] |
//! | `DELETE /v1/account/identities/{provider}/{subject}` | [`AuthApi::unlink_identity`] |
//!
//! Product services (Oversight Cloud, Pack Hub, Awaken Next Cloud) consume this
//! API as their authentication seam: rather than parsing a Google or GitHub
//! token, a product forwards the opaque IAM session cookie to
//! [`AuthApi::resolve_principal`] and receives the account [`PrincipalRef`] that
//! backs the live session. It then drives its own grant and entitlement checks
//! against [`AuthzApi`](crate::AuthzApi) with that principal. Resolution fails
//! closed for a missing, unknown, revoked, or expired session, and for a session
//! whose account is disabled, so a product can never manufacture a principal of
//! its own.
//!
//! The front half of the login loop mints a challenge whose hashes are persisted
//! through the authoritative [`LoginFlowRepo`]. The one-time cleartext PKCE
//! verifier and OIDC nonce are returned only in a second hardened, HttpOnly
//! correlation cookie; their hashes bind them to the shared challenge row, so
//! callback processing is stateless and any replica can complete it without
//! persisting the cleartext values. `return_to` is constrained by an allowlist so a crafted link cannot
//! turn login into an open redirect, and every transition emits an
//! [`AuthAuditEvent`].

use std::sync::Arc;

use crate::access_token::{
    AccessTokenAuthority, AccessTokenClaims, AccessTokenError, AccessTokenRevocations,
    LocalSeedSigner,
};
use crate::auth_redirect::build_authorize_redirect;
use crate::op_id_token::{IdTokenError, MintIdToken, mint_id_token};
use crate::token_exchange::{
    BEARER_TOKEN_TYPE, ISSUED_TOKEN_TYPE_ACCESS_TOKEN, TokenExchangeError, TokenExchangeRequest,
    TokenExchangeResponse, TrustedIssuer, TrustedIssuerRegistry,
};
use crate::{SessionCookieConfig, SessionGateway};
use awaken_iam_contract::{
    Account, AccountId, AccountStatus, ExternalIdentity, ExternalIdentityClaims,
    ExternalIdentityId, ExternalSubject, IdentityProviderConfig, IdentityProviderKey,
    IdentityProviderKind, Jwks, OAuthLoginStateId, OpenIdProviderMetadata, PrincipalRef,
    RefreshTokenChainId, RefreshTokenId, RefreshTokenView, SessionId, SessionView, Timestamp,
    UserInfo,
};
use awaken_iam_core::{
    AuthCodeRepo, AuthorizationUrlRequest, AuthorizedGrant, BeginLogin, CallbackExchange,
    EntropySource, EstablishSession, IamError, IdentityDirectory, IdentityProviderAdapter,
    LoginAttempt, LoginFlowRepo, MintRefreshToken, OAuthAuthorizationRequest,
    OAuthAuthorizationServer, OAuthChallengeService, OAuthClientRegistry, OAuthClientRepo,
    OAuthProviderError, OsEntropy, ProviderError, RefreshTokenDirectory, RefreshTokenMinter,
    RegisteredClient, RotateRefreshToken, SessionRepo, TokenRedemption,
    parse_presented_refresh_token,
};
use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use serde::{Deserialize, Serialize};

mod builder;

/// Default key id minted for the bootstrap access-token signing key.
const DEFAULT_SIGNING_KID: &str = "iam-access-key-1";
/// Number of random bytes drawn for each generated id (256 bits).
const ID_BYTES: usize = 32;

/// Default name of the short-lived login correlation cookie.
///
/// The `__Host-` prefix binds it to `Secure`, `Path=/`, and no `Domain`, which
/// the default [`SessionCookieConfig`] satisfies.
pub const DEFAULT_LOGIN_COOKIE_NAME: &str = "__Host-awaken_login";
/// Default name for the callback proof paired with the login-id cookie.
pub const DEFAULT_LOGIN_PROOF_COOKIE_NAME: &str = "__Host-awaken_login_proof";

/// Allowlist policy constraining post-login `return_to` destinations.
///
/// A `return_to` is honoured only when it is a same-site relative path that
/// begins with one of the configured prefixes; anything else (an absolute URL,
/// a protocol-relative `//host` value, or a path outside the allowlist) falls
/// back to [`ReturnToPolicy::default_return_to`] so login can never be coerced
/// into an open redirect.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReturnToPolicy {
    default_return_to: String,
    allowed_prefixes: Vec<String>,
}

impl Default for ReturnToPolicy {
    fn default() -> Self {
        Self {
            default_return_to: "/".to_owned(),
            allowed_prefixes: vec!["/".to_owned()],
        }
    }
}

/// Outcome of resolving a requested `return_to` against the allowlist.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ReturnToDecision {
    /// The requested destination was honoured verbatim.
    Allowed(String),
    /// The request was missing or rejected; the safe default is used instead.
    RejectedFallback(String),
}

impl ReturnToDecision {
    /// The destination to actually redirect to.
    pub fn destination(&self) -> &str {
        match self {
            ReturnToDecision::Allowed(value) | ReturnToDecision::RejectedFallback(value) => value,
        }
    }

    /// Whether a non-empty requested destination was rejected by the allowlist.
    pub fn was_rejected(&self) -> bool {
        matches!(self, ReturnToDecision::RejectedFallback(_))
    }
}

impl ReturnToPolicy {
    /// Build a policy with an explicit default and prefix allowlist.
    pub fn new(
        default_return_to: impl Into<String>,
        allowed_prefixes: impl IntoIterator<Item = String>,
    ) -> Self {
        Self {
            default_return_to: default_return_to.into(),
            allowed_prefixes: allowed_prefixes.into_iter().collect(),
        }
    }

    /// The destination used when no allowed `return_to` was supplied.
    pub fn default_return_to(&self) -> &str {
        &self.default_return_to
    }

    /// Resolve a requested `return_to` against the allowlist.
    pub fn resolve(&self, requested: Option<&str>) -> ReturnToDecision {
        match requested {
            Some(candidate) if self.is_allowed(candidate) => {
                ReturnToDecision::Allowed(candidate.to_owned())
            }
            _ => ReturnToDecision::RejectedFallback(self.default_return_to.clone()),
        }
    }

    fn is_allowed(&self, candidate: &str) -> bool {
        // Reject protocol-relative (`//host`) and backslash-smuggled values that
        // browsers may treat as cross-origin even though they start with `/`.
        if candidate.starts_with("//") || candidate.starts_with("/\\") {
            return false;
        }
        self.allowed_prefixes
            .iter()
            .any(|prefix| candidate.starts_with(prefix))
    }
}

/// Audit event emitted as the auth API drives the login session loop.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AuthAuditEvent {
    /// A login challenge was started for a provider.
    LoginStarted {
        /// Provider the login targets.
        provider_key: IdentityProviderKey,
        /// Persisted login-state id correlating start and callback.
        login_state_id: OAuthLoginStateId,
        /// When the challenge was started.
        at: Timestamp,
    },
    /// A login callback resolved to an authenticated session.
    LoginSucceeded {
        /// Provider that authenticated the subject.
        provider_key: IdentityProviderKey,
        /// Account the session authenticates.
        account_id: AccountId,
        /// Established session id.
        session_id: SessionId,
        /// External identity used to establish the session.
        external_identity_id: ExternalIdentityId,
        /// Whether a new account was provisioned on this login.
        registered: bool,
        /// When the session was established.
        at: Timestamp,
    },
    /// A login attempt failed before a session could be established.
    LoginFailed {
        /// Provider the failed login targeted.
        provider_key: IdentityProviderKey,
        /// Stable machine-readable failure reason.
        reason: AuthFailureReason,
        /// When the failure was observed.
        at: Timestamp,
    },
    /// A requested `return_to` was rejected and replaced with the safe default.
    ReturnToRejected {
        /// Provider whose login carried the rejected destination.
        provider_key: IdentityProviderKey,
        /// The rejected destination, verbatim.
        rejected: String,
        /// When the rejection happened.
        at: Timestamp,
    },
    /// A session was revoked through logout.
    LoggedOut {
        /// Session that was revoked.
        session_id: SessionId,
        /// When logout happened.
        at: Timestamp,
    },
    /// An external identity was linked to an account.
    IdentityLinked {
        /// Account the identity was attached to.
        account_id: AccountId,
        /// New external identity id.
        external_identity_id: ExternalIdentityId,
        /// Provider that issued the subject.
        provider_key: IdentityProviderKey,
        /// When the link was created.
        at: Timestamp,
    },
    /// An external identity was unlinked from an account.
    IdentityUnlinked {
        /// Account the identity was detached from.
        account_id: AccountId,
        /// Provider that issued the subject.
        provider_key: IdentityProviderKey,
        /// Detached provider subject.
        subject: ExternalSubject,
        /// When the link was removed.
        at: Timestamp,
    },
    /// A product service resolved a session principal at the authentication
    /// seam, ready to drive its own grant and entitlement checks.
    PrincipalResolved {
        /// Account principal resolved from the presented IAM session.
        principal: PrincipalRef,
        /// When the principal was resolved.
        at: Timestamp,
    },
    /// A product service presented a session that could not be resolved to an
    /// active account principal, so the request failed closed.
    PrincipalResolutionFailed {
        /// Stable machine-readable reason resolution failed.
        reason: PrincipalResolutionFailure,
        /// When the failure was observed.
        at: Timestamp,
    },
    /// A new refresh-token chain was issued (e.g. on an OAuth grant).
    RefreshTokenIssued {
        /// Account the chain authenticates.
        account_id: AccountId,
        /// Chain id of the new lineage.
        chain_id: RefreshTokenChainId,
        /// Id of the first token in the chain.
        refresh_token_id: RefreshTokenId,
        /// When the chain was issued.
        at: Timestamp,
    },
    /// A refresh token was rotated: the presented token retired, a successor
    /// issued, and a fresh access token minted.
    RefreshTokenRotated {
        /// Account the chain authenticates.
        account_id: AccountId,
        /// Chain id shared by the retired and issued tokens.
        chain_id: RefreshTokenChainId,
        /// The retired (presented) token.
        retired_token_id: RefreshTokenId,
        /// The newly issued successor token.
        issued_token_id: RefreshTokenId,
        /// `jti` of the access token minted alongside the rotation.
        access_token_jti: String,
        /// When the rotation happened.
        at: Timestamp,
    },
    /// A retired refresh token was replayed — a theft signal. The whole chain is
    /// revoked in response.
    RefreshTokenReuseDetected {
        /// Chain revoked because of the replay.
        chain_id: RefreshTokenChainId,
        /// When the reuse was observed.
        at: Timestamp,
    },
    /// A refresh-token chain was revoked (RFC 7009 revoke or a reuse signal).
    RefreshChainRevoked {
        /// Chain that was revoked.
        chain_id: RefreshTokenChainId,
        /// Number of tokens whose revocation stamp was newly set.
        revoked_count: usize,
        /// When the chain was revoked.
        at: Timestamp,
    },
    /// An access token was revoked by `jti` (RFC 7009 revoke).
    AccessTokenRevoked {
        /// The revoked token's `jti`.
        jti: String,
        /// When the revocation was recorded.
        at: Timestamp,
    },
    /// An upstream workload assertion was exchanged for an IAM access token.
    WorkloadIdentityFederated {
        /// Trusted external issuer that signed the accepted assertion.
        issuer: String,
        /// Verified upstream subject the assertion authenticated.
        subject: String,
        /// Service principal the issued IAM token authenticates as.
        principal: PrincipalRef,
        /// Unique id of the issued token, enabling per-token revocation.
        jti: String,
        /// When the token was issued, as unix seconds.
        at: i64,
    },
    /// A token-exchange request was rejected before a token could be issued.
    WorkloadIdentityRejected {
        /// Stable machine-readable reason the exchange failed.
        reason: TokenExchangeError,
        /// When the failure was observed, as unix seconds.
        at: i64,
    },
    /// IAM (as the downstream OpenID Provider) issued an authorization code to a
    /// product client for an authenticated end-user (`GET /v1/oauth/authorize`).
    DownstreamCodeIssued {
        /// Product client the code was issued to.
        client_id: String,
        /// Account the end-user authenticated as.
        account_id: AccountId,
        /// When the code was issued.
        at: Timestamp,
    },
    /// A product client redeemed an authorization code for a token grant at the
    /// token endpoint (`POST /v1/oauth/token`, `authorization_code`).
    DownstreamCodeRedeemed {
        /// Product client that redeemed the code.
        client_id: String,
        /// Account the resulting grant authenticates.
        account_id: AccountId,
        /// `jti` of the access token minted for the grant.
        access_token_jti: String,
        /// When the code was redeemed.
        at: Timestamp,
    },
}

/// Stable machine-readable reason a session could not be resolved to an active
/// account principal at the product authentication seam.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PrincipalResolutionFailure {
    /// No live session backed the presented cookie (missing, unknown, revoked,
    /// or expired).
    Unauthenticated,
    /// The session resolved to an account that is disabled or unknown.
    AccountDisabled,
}

/// Stable machine-readable reason a login attempt failed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AuthFailureReason {
    /// The login correlation cookie was absent or unparseable.
    MissingCorrelation,
    /// The presented OAuth `state` did not match the minted challenge.
    StateMismatch,
    /// The challenge was expired, replayed, or otherwise unusable.
    ChallengeRejected,
    /// The provider exchange rejected the callback.
    ProviderRejected,
}

/// Compact provider descriptor returned by `GET /v1/auth/providers`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProviderSummary {
    /// Stable provider key used in login routes.
    pub provider_key: IdentityProviderKey,
    /// Provider implementation family.
    pub kind: IdentityProviderKind,
    /// Human-readable provider name.
    pub display_name: String,
}

/// Inputs to register a provider with the auth API.
pub struct ProviderRegistration {
    /// Shared provider configuration.
    pub config: IdentityProviderConfig,
    /// Provider-specific URL/exchange adapter.
    pub adapter: Box<dyn IdentityProviderAdapter + Send + Sync>,
    /// Absolute callback URL the provider redirects back to.
    pub redirect_uri: String,
    /// OAuth scopes requested at the authorization endpoint.
    pub scopes: Vec<String>,
    /// Whether to mint an OIDC nonce for this provider.
    pub include_nonce: bool,
    /// Whether to mint a PKCE verifier/challenge for this provider.
    pub include_pkce: bool,
}

struct RegisteredProvider {
    config: IdentityProviderConfig,
    adapter: Box<dyn IdentityProviderAdapter + Send + Sync>,
    redirect_uri: String,
    scopes: Vec<String>,
    include_nonce: bool,
    include_pkce: bool,
}

/// Browser-held, one-time callback proof. The shared login row stores only the
/// hashes of these values, so cookie tampering fails closed during consumption.
#[derive(Debug, Serialize, Deserialize)]
struct LoginCorrelationProof {
    login_state_id: OAuthLoginStateId,
    nonce: Option<String>,
    pkce_verifier: Option<String>,
}

impl LoginCorrelationProof {
    fn encode(&self) -> Result<String, AuthApiError> {
        serde_json::to_vec(self)
            .map(|bytes| URL_SAFE_NO_PAD.encode(bytes))
            .map_err(|_| AuthApiError::MissingCorrelation)
    }

    fn decode(value: &str) -> Result<Self, AuthApiError> {
        let bytes = URL_SAFE_NO_PAD
            .decode(value)
            .map_err(|_| AuthApiError::MissingCorrelation)?;
        serde_json::from_slice(&bytes).map_err(|_| AuthApiError::MissingCorrelation)
    }
}

/// Request to begin a login (`GET /v1/auth/login/{provider}`).
#[derive(Debug, Clone)]
pub struct StartLogin {
    /// Provider selected for the login.
    pub provider_key: IdentityProviderKey,
    /// Requested post-login destination, validated against the allowlist.
    pub return_to: Option<String>,
    /// Challenge creation timestamp.
    pub created_at: Timestamp,
    /// Challenge expiration timestamp; must be strictly after `created_at`.
    pub expires_at: Timestamp,
    /// Optional `Max-Age` (seconds) bounding the login correlation cookie.
    pub cookie_max_age_secs: Option<u64>,
}

/// Result of beginning a login.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StartLoginOutcome {
    /// Provider authorization URL to redirect the browser to.
    pub redirect_url: String,
    /// `Set-Cookie` header value carrying the login correlation cookie.
    pub set_cookie: String,
    /// `Set-Cookie` header carrying the one-time nonce/PKCE callback proof.
    pub set_proof_cookie: String,
    /// Resolved `return_to` destination after allowlist enforcement.
    pub return_to: ReturnToDecision,
}

/// Request to complete a login (`GET /v1/auth/callback/{provider}`).
#[derive(Debug, Clone)]
pub struct CallbackRequest {
    /// Provider key from the callback route.
    pub provider_key: IdentityProviderKey,
    /// Raw request `Cookie` header carrying the login correlation cookie.
    pub cookie_header: String,
    /// Authorization `code` returned by the provider.
    pub code: String,
    /// OAuth `state` echoed by the provider.
    pub state: String,
    /// Callback observation timestamp.
    pub now: Timestamp,
    /// Session expiration timestamp.
    pub session_expires_at: Timestamp,
    /// Optional `Max-Age` (seconds) bounding the session cookie.
    pub session_cookie_max_age_secs: Option<u64>,
}

/// Result of completing a login.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CallbackOutcome {
    /// Destination to redirect the browser to after login.
    pub redirect_to: String,
    /// `Set-Cookie` header value establishing the session cookie.
    pub set_session_cookie: String,
    /// `Set-Cookie` header value clearing the login correlation cookie.
    pub clear_login_cookie: String,
    /// `Set-Cookie` header value clearing the callback-proof cookie.
    pub clear_login_proof_cookie: String,
    /// Public, token-free view of the new session.
    pub session: SessionView,
    /// Whether a new account was provisioned on this login.
    pub registered: bool,
}

/// Result of logging out.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LogoutOutcome {
    /// `Set-Cookie` header value clearing the browser session cookie.
    pub clear_session_cookie: String,
}

/// Request to mint an asymmetric bearer access token (`POST /v1/tokens`).
///
/// The caller supplies the principal and validity window; IAM mints a unique
/// `jti` (so the token is individually revocable) and signs the JWT with the
/// active rotation key, stamping its `kid` into the header.
#[derive(Debug, Clone)]
pub struct MintAccessToken {
    /// Issuer identifier stamped into the `iss` claim.
    pub issuer: String,
    /// Subject the token authenticates (the IAM account/principal id).
    pub subject: String,
    /// Audience: the service the token is presented to.
    pub audience: String,
    /// Issued-at time as a Unix timestamp (seconds).
    pub issued_at: i64,
    /// Expiration time as a Unix timestamp (seconds); short-lived (≈1h).
    pub expires_at: i64,
    /// Scopes granted to the bearer.
    pub scopes: Vec<String>,
}

/// Request to issue a fresh access + refresh token pair for an authenticated
/// account (the initial OAuth grant from which later refreshes rotate).
///
/// The grant coordinates (`subject`, `audience`, `scopes`) are stamped into the
/// access token and stored on the refresh chain so a later rotation never trusts
/// client-supplied claims. Access-token times are Unix seconds (`issued_at` /
/// `access_expires_at`), while the refresh window is canonical RFC 3339
/// (`now` / `refresh_expires_at`), matching each subsystem's existing form.
#[derive(Debug, Clone)]
pub struct IssueTokenGrant {
    /// Account the tokens authenticate.
    pub account_id: AccountId,
    /// Issuer stamped into the access token's `iss` claim.
    pub issuer: String,
    /// Subject stamped into the access token and the refresh chain.
    pub subject: String,
    /// Audience the tokens are presented to.
    pub audience: String,
    /// Scopes granted to the bearer.
    pub scopes: Vec<String>,
    /// Access-token issued-at (Unix seconds).
    pub issued_at: i64,
    /// Access-token expiry (Unix seconds); short-lived (≈1h).
    pub access_expires_at: i64,
    /// Refresh-token issue time (RFC 3339).
    pub now: Timestamp,
    /// Refresh-token expiry (RFC 3339); must be strictly after `now`.
    pub refresh_expires_at: Timestamp,
}

/// Request for the `refresh_token` grant on `POST /v1/oauth/token`.
///
/// Only the presented token and the new validity windows are supplied: the
/// rotated successor and the freshly minted access token inherit subject,
/// audience, and scope from the stored refresh chain.
#[derive(Debug, Clone)]
pub struct RefreshGrant {
    /// The cleartext refresh token presented by the client.
    pub presented_refresh_token: String,
    /// Issuer stamped into the new access token's `iss` claim.
    pub issuer: String,
    /// Access-token issued-at (Unix seconds).
    pub issued_at: i64,
    /// Access-token expiry (Unix seconds).
    pub access_expires_at: i64,
    /// Rotation time and the successor's issue time (RFC 3339).
    pub now: Timestamp,
    /// Successor refresh-token expiry (RFC 3339); must be strictly after `now`.
    pub refresh_expires_at: Timestamp,
}

/// Result of an OAuth token grant: a bearer access token plus the rotated
/// refresh token to use next.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TokenGrant {
    /// Signed compact-JWT access token (the `access_token` field).
    pub access_token: String,
    /// `jti` of the issued access token, enabling later revocation.
    pub access_token_jti: String,
    /// One-time cleartext refresh token (the `refresh_token` field).
    pub refresh_token: String,
    /// Public, secret-free view of the issued refresh token.
    pub refresh_token_view: RefreshTokenView,
}

/// Request to redeem a downstream authorization code at IAM's OIDC token
/// endpoint (`POST /v1/oauth/token`, `authorization_code`), minting a signed
/// access token and an OIDC `id_token` from the resolved grant.
///
/// The code redemption itself (single-use, expiry, client authentication,
/// redirect-URI match, PKCE) is carried by [`TokenRedemption`]; this request
/// supplies only the claim-stamping coordinates layered on top of the grant the
/// redemption resolves to. `subject`/`scope` are never taken from the request —
/// the subject is the account the code was issued to and the scopes are the
/// grant's down-scoped set, so a client can never widen its own authority here.
#[derive(Debug, Clone)]
pub struct OpCodeRedemption {
    /// Issuer stamped into both tokens' `iss` claim.
    pub issuer: String,
    /// Audience stamped into the access token (the service it is presented to).
    /// The `id_token` audience is always the redeeming client's `client_id`.
    pub access_audience: String,
    /// Issued-at time for both tokens as a Unix timestamp (seconds).
    pub issued_at: i64,
    /// Access-token expiry as a Unix timestamp (seconds); short-lived (≈1h).
    pub access_expires_at: i64,
    /// `id_token` expiry as a Unix timestamp (seconds); must be after `issued_at`.
    pub id_token_expires_at: i64,
    /// Wall-clock used for the code's single-use/expiry checks (RFC 3339).
    pub now: Timestamp,
}

/// Result of redeeming a downstream authorization code: the minted access token
/// and the OIDC `id_token`, plus the grant coordinates they were stamped from.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OpTokenGrant {
    /// Signed compact-JWT access token for IAM's service APIs.
    pub access_token: String,
    /// `jti` of the issued access token, enabling later revocation.
    pub access_token_jti: String,
    /// Signed compact-JWT OIDC `id_token` asserting the subject to the client.
    pub id_token: String,
    /// Account the redeemed code authenticated (the tokens' `sub`).
    pub account_id: AccountId,
    /// Granted scopes (the authorization request's down-scoped set).
    pub scopes: Vec<String>,
}

/// Hint about which token family an RFC 7009 revoke targets.
///
/// The hint only orders the lookup; revocation falls through to the other family
/// if the hint is wrong, as RFC 7009 §2.1 allows.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RevokeTokenHint {
    /// The token is expected to be an access token (revoke by `jti`).
    AccessToken,
    /// The token is expected to be a refresh token (revoke the chain).
    RefreshToken,
}

/// Request to revoke a token (`POST /v1/oauth/revoke`, RFC 7009).
#[derive(Debug, Clone)]
pub struct RevokeToken {
    /// The token to revoke (an access JWT or an opaque refresh token).
    pub token: String,
    /// Optional hint about the token family.
    pub token_type_hint: Option<RevokeTokenHint>,
    /// Revocation timestamp.
    pub now: Timestamp,
}

/// Outcome of an RFC 7009 revoke.
///
/// RFC 7009 §2.2 mandates a `200 OK` even for an unknown or invalid token, so the
/// HTTP layer always succeeds; `revoked` reports whether a live token actually
/// matched, for auditing and tests — it is never leaked to the caller.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RevokeOutcome {
    /// Whether a token (access or refresh) was actually matched and revoked.
    pub revoked: bool,
}

/// Request to authorize a downstream product client (`GET /v1/oauth/authorize`).
///
/// IAM is the OpenID Provider here: the end-user is authenticated by their live
/// IAM session cookie, and the resolved account becomes the subject the issued
/// single-use code is bound to. The authorization parameters (client id, redirect
/// URI, requested scopes, PKCE challenge, OIDC `nonce`, opaque `state`) are
/// validated by the core [`OAuthAuthorizationServer`].
#[derive(Debug, Clone)]
pub struct DownstreamAuthorizeRequest {
    /// Raw request `Cookie` header carrying the IAM session cookie that
    /// authenticates the end-user being authorized.
    pub cookie_header: String,
    /// The OAuth authorization-request parameters from the query string.
    pub authorization: OAuthAuthorizationRequest,
    /// Authorization-time timestamp; the code expiry must be strictly after it.
    pub now: Timestamp,
    /// Single-use code expiry; must be strictly after `now`.
    pub code_expires_at: Timestamp,
}

/// Result of a successful downstream authorization.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DownstreamAuthorizeOutcome {
    /// Absolute redirect back to the client's registered redirect URI carrying
    /// the `code` (and the echoed `state`, when present).
    pub redirect_to: String,
}

/// Request to redeem an authorization code at the token endpoint
/// (`POST /v1/oauth/token`, `authorization_code` grant).
///
/// The core [`OAuthAuthorizationServer`] validates the redemption (client
/// authentication, redirect-URI match, single-use/expiry, PKCE) and resolves it
/// to an [`AuthorizedGrant`]; IAM then mints an opaque access token plus a fresh
/// refresh-token chain for the granted account and scopes.
#[derive(Debug, Clone)]
pub struct RedeemAuthorizationCode {
    /// The token-endpoint redemption parameters.
    pub redemption: TokenRedemption,
    /// Issuer stamped into the minted access token's `iss` claim.
    pub issuer: String,
    /// Access-token issued-at (Unix seconds).
    pub issued_at: i64,
    /// Access-token expiry (Unix seconds); short-lived (≈1h).
    pub access_expires_at: i64,
    /// Refresh-token issue time (RFC 3339).
    pub now: Timestamp,
    /// Refresh-token expiry (RFC 3339); must be strictly after `now`.
    pub refresh_expires_at: Timestamp,
}

/// Request to link an already-verified external identity to an account.
#[derive(Debug, Clone)]
pub struct LinkIdentity {
    /// Account to attach the identity to.
    pub account_id: AccountId,
    /// Provider that issued the subject.
    pub provider_key: IdentityProviderKey,
    /// Verified normalized claims for the subject.
    pub claims: ExternalIdentityClaims,
    /// Link timestamp.
    pub now: Timestamp,
}

/// Request to unlink an external identity from an account.
#[derive(Debug, Clone)]
pub struct UnlinkIdentity {
    /// Account the identity is attached to.
    pub account_id: AccountId,
    /// Provider that issued the subject.
    pub provider_key: IdentityProviderKey,
    /// Provider subject to detach.
    pub subject: ExternalSubject,
    /// Unlink timestamp.
    pub now: Timestamp,
}

/// Errors surfaced by the auth API.
#[derive(Debug, PartialEq, Eq, thiserror::Error)]
pub enum AuthApiError {
    /// No provider is registered for the requested key.
    #[error("unknown identity provider: {0:?}")]
    UnknownProvider(IdentityProviderKey),
    /// The provider exists but is disabled for new logins.
    #[error("identity provider is disabled: {0:?}")]
    ProviderDisabled(IdentityProviderKey),
    /// The callback provider key disagreed with the started challenge.
    #[error("callback provider does not match the started login")]
    ProviderMismatch,
    /// The login correlation cookie was missing or unusable.
    #[error("login correlation cookie is missing")]
    MissingCorrelation,
    /// The login-state invariants rejected the operation.
    #[error(transparent)]
    Login(#[from] IamError),
    /// The provider adapter rejected the exchange.
    #[error(transparent)]
    Provider(#[from] ProviderError),
    /// The external identity is linked to a different account.
    #[error("external identity is linked to a different account")]
    IdentityAccountMismatch,
    /// The presented IAM session could not be resolved to a live session.
    #[error("request is not authenticated by a live IAM session")]
    Unauthenticated,
    /// The session resolved to an account that is disabled or no longer exists.
    #[error("session principal account is disabled")]
    AccountDisabled,
    /// Minting an asymmetric access token failed.
    #[error(transparent)]
    AccessToken(#[from] AccessTokenError),
    /// A federated token exchange (RFC 8693) was rejected.
    #[error(transparent)]
    TokenExchange(#[from] TokenExchangeError),
    /// The downstream OAuth provider rejected an authorize or token-redemption
    /// request (unknown client, bad redirect URI, PKCE failure, expired code, …).
    #[error(transparent)]
    OAuthProvider(#[from] OAuthProviderError),
    /// Assembling the OIDC `id_token` for a redeemed grant failed.
    #[error(transparent)]
    IdToken(#[from] IdTokenError),
}

/// Browser-facing third-party auth API over the login session loop.
pub struct AuthApi<E: EntropySource + Clone = OsEntropy> {
    providers: Vec<RegisteredProvider>,
    challenge: OAuthChallengeService<E>,
    login_flows: Arc<dyn LoginFlowRepo>,
    sessions: SessionGateway<E>,
    directory: IdentityDirectory,
    return_to: ReturnToPolicy,
    login_cookie: SessionCookieConfig,
    login_proof_cookie: SessionCookieConfig,
    tokens: AccessTokenAuthority,
    refresh_tokens: RefreshTokenDirectory,
    refresh_minter: RefreshTokenMinter<E>,
    access_revocations: AccessTokenRevocations,
    trusted_issuers: TrustedIssuerRegistry,
    iam_issuer: String,
    oauth_provider: OAuthAuthorizationServer<E>,
    audit: Vec<AuthAuditEvent>,
    ids: E,
}

impl<E: EntropySource + Clone> AuthApi<E> {
    /// Register (or replace, by issuer id) a trusted external issuer whose
    /// assertions IAM will exchange for IAM tokens via RFC 8693 token exchange.
    pub fn register_trusted_issuer(&mut self, issuer: TrustedIssuer) {
        self.trusted_issuers.upsert(issuer);
    }

    /// Register a provider with its adapter and flow configuration.
    pub fn register_provider(&mut self, registration: ProviderRegistration) {
        self.providers.push(RegisteredProvider {
            config: registration.config,
            adapter: registration.adapter,
            redirect_uri: registration.redirect_uri,
            scopes: registration.scopes,
            include_nonce: registration.include_nonce,
            include_pkce: registration.include_pkce,
        });
    }

    /// Register a downstream product client that integrates against IAM as an
    /// OpenID Provider (the `/v1/oauth/authorize` + `/v1/oauth/token` flow).
    pub fn register_oauth_client(
        &mut self,
        client: RegisteredClient,
    ) -> Result<(), OAuthProviderError> {
        self.oauth_provider.register_client(client)
    }

    /// Borrow the identity directory backing account/identity reads.
    pub fn directory(&self) -> &IdentityDirectory {
        &self.directory
    }

    /// The accumulated audit trail for this API instance.
    pub fn audit_log(&self) -> &[AuthAuditEvent] {
        &self.audit
    }

    /// `GET /v1/auth/providers`: list providers currently enabled for login.
    pub fn list_providers(&self) -> Vec<ProviderSummary> {
        self.providers
            .iter()
            .filter(|provider| provider.config.enabled)
            .map(|provider| ProviderSummary {
                provider_key: provider.config.provider_key.clone(),
                kind: provider.config.kind,
                display_name: provider.config.display_name.clone(),
            })
            .collect()
    }

    /// `GET /v1/auth/login/{provider}`: mint a challenge and build the provider
    /// authorization redirect plus its correlation cookie.
    pub fn start_login(&mut self, request: StartLogin) -> Result<StartLoginOutcome, AuthApiError> {
        let index = self.provider_index(&request.provider_key)?;
        if !self.providers[index].config.enabled {
            return Err(AuthApiError::ProviderDisabled(request.provider_key));
        }

        let return_to = self.return_to.resolve(request.return_to.as_deref());
        if return_to.was_rejected()
            && let Some(rejected) = request.return_to.clone()
        {
            self.audit.push(AuthAuditEvent::ReturnToRejected {
                provider_key: request.provider_key.clone(),
                rejected,
                at: request.created_at.clone(),
            });
        }

        let login_state_id = OAuthLoginStateId(self.mint_id("login"));
        let (include_nonce, include_pkce) = {
            let provider = &self.providers[index];
            (provider.include_nonce, provider.include_pkce)
        };

        let issued = self.challenge.begin_login(
            self.login_flows.as_ref(),
            BeginLogin {
                id: login_state_id.clone(),
                provider_key: request.provider_key.clone(),
                return_to: Some(return_to.destination().to_owned()),
                include_nonce,
                include_pkce,
                created_at: request.created_at.clone(),
                expires_at: request.expires_at,
            },
        )?;

        let provider = &self.providers[index];
        let url_request = AuthorizationUrlRequest {
            redirect_uri: provider.redirect_uri.clone(),
            state: issued.secrets.state.clone(),
            nonce: issued.secrets.nonce.clone(),
            pkce_challenge: issued.secrets.pkce_challenge.clone(),
            scopes: provider.scopes.clone(),
        };
        let redirect = provider
            .adapter
            .authorization_url(&provider.config, &url_request)?;

        let set_cookie = self
            .login_cookie
            .render_set_cookie(&login_state_id.0, request.cookie_max_age_secs);
        let proof = LoginCorrelationProof {
            login_state_id: login_state_id.clone(),
            nonce: issued.secrets.nonce.clone(),
            pkce_verifier: issued.secrets.pkce_verifier.clone(),
        };
        let set_proof_cookie = self
            .login_proof_cookie
            .render_set_cookie(&proof.encode()?, request.cookie_max_age_secs);

        self.audit.push(AuthAuditEvent::LoginStarted {
            provider_key: request.provider_key,
            login_state_id,
            at: request.created_at,
        });

        Ok(StartLoginOutcome {
            redirect_url: redirect.url,
            set_cookie,
            set_proof_cookie,
            return_to,
        })
    }

    /// `GET /v1/auth/callback/{provider}`: verify the challenge, exchange the
    /// code for claims, resolve or provision the account, and establish a
    /// session.
    pub fn complete_callback(
        &mut self,
        request: CallbackRequest,
    ) -> Result<CallbackOutcome, AuthApiError> {
        let index = self.provider_index(&request.provider_key)?;

        let login_state_id = match self.login_cookie.extract_token(&request.cookie_header) {
            Some(token) if !token.is_empty() => OAuthLoginStateId(token),
            _ => {
                self.record_failure(
                    &request.provider_key,
                    AuthFailureReason::MissingCorrelation,
                    &request.now,
                );
                return Err(AuthApiError::MissingCorrelation);
            }
        };

        let proof = match self
            .login_proof_cookie
            .extract_token(&request.cookie_header)
            .ok_or(AuthApiError::MissingCorrelation)
            .and_then(|value| LoginCorrelationProof::decode(&value))
        {
            Ok(proof) if proof.login_state_id == login_state_id => proof,
            Ok(_) | Err(_) => {
                self.record_failure(
                    &request.provider_key,
                    AuthFailureReason::MissingCorrelation,
                    &request.now,
                );
                return Err(AuthApiError::MissingCorrelation);
            }
        };

        let attempt = LoginAttempt {
            id: login_state_id.clone(),
            state: request.state.clone(),
            nonce: proof.nonce.clone(),
            pkce_verifier: proof.pkce_verifier.clone(),
        };
        let consumed = match self.challenge.complete_login(
            self.login_flows.as_ref(),
            &attempt,
            request.now.clone(),
        ) {
            Ok(consumed) => consumed,
            Err(err) => {
                let reason = match err {
                    IamError::LoginStateMismatch { .. } => AuthFailureReason::StateMismatch,
                    _ => AuthFailureReason::ChallengeRejected,
                };
                self.record_failure(&request.provider_key, reason, &request.now);
                return Err(AuthApiError::Login(err));
            }
        };

        if consumed.provider_key != request.provider_key {
            self.record_failure(
                &request.provider_key,
                AuthFailureReason::StateMismatch,
                &request.now,
            );
            return Err(AuthApiError::ProviderMismatch);
        }
        let return_to = consumed
            .return_to
            .clone()
            .unwrap_or_else(|| self.return_to.default_return_to().to_owned());

        let claims = {
            let provider = &self.providers[index];
            let exchange = CallbackExchange {
                redirect_uri: provider.redirect_uri.clone(),
                code: request.code.clone(),
                pkce_verifier: proof.pkce_verifier.clone(),
            };
            match provider
                .adapter
                .exchange_callback(&provider.config, &exchange)
            {
                Ok(claims) => claims,
                Err(err) => {
                    self.record_failure(
                        &request.provider_key,
                        AuthFailureReason::ProviderRejected,
                        &request.now,
                    );
                    return Err(AuthApiError::Provider(err));
                }
            }
        };

        let (account_id, external_identity_id, registered) =
            self.resolve_account(&request.provider_key, claims, &request.now)?;

        let session_id = SessionId(self.mint_id("sess"));
        let established = self.sessions.establish_session(
            EstablishSession {
                id: session_id.clone(),
                account_id: account_id.clone(),
                external_identity_id: Some(external_identity_id.clone()),
                created_at: request.now.clone(),
                expires_at: request.session_expires_at,
            },
            request.session_cookie_max_age_secs,
        )?;

        self.audit.push(AuthAuditEvent::LoginSucceeded {
            provider_key: request.provider_key,
            account_id,
            session_id,
            external_identity_id,
            registered,
            at: request.now,
        });

        Ok(CallbackOutcome {
            redirect_to: return_to,
            set_session_cookie: established.set_cookie,
            clear_login_cookie: self.login_cookie.render_clear_cookie(),
            clear_login_proof_cookie: self.login_proof_cookie.render_clear_cookie(),
            session: established.view,
            registered,
        })
    }

    /// `GET /v1/session`: resolve the live session from the request cookie.
    pub fn current_session(
        &mut self,
        cookie_header: &str,
        now: Timestamp,
    ) -> Result<SessionView, AuthApiError> {
        Ok(self
            .sessions
            .current_session_from_cookie(cookie_header, now)?)
    }

    /// Resolve the account principal backing the presented IAM session.
    ///
    /// This is the shared authentication seam product services consume: rather
    /// than parsing a Google or GitHub token, Oversight Cloud, Pack Hub, and
    /// Awaken Next Cloud forward the opaque IAM session cookie and let IAM
    /// resolve the live session to its [`PrincipalRef::Account`]. The product
    /// then drives its own grant and entitlement checks against
    /// [`AuthzApi`](crate::AuthzApi) with that principal — IAM resolves *who*,
    /// never *what* the product domain decides.
    ///
    /// Resolution fails closed: it returns [`AuthApiError::Unauthenticated`]
    /// when the cookie does not back a live session (missing, unknown, revoked,
    /// or expired), and [`AuthApiError::AccountDisabled`] when the session
    /// resolves to a disabled or unknown account. The product can therefore
    /// never manufacture a principal of its own. Every outcome is audited.
    pub fn resolve_principal(
        &mut self,
        cookie_header: &str,
        now: Timestamp,
    ) -> Result<PrincipalRef, AuthApiError> {
        let account_id = match self
            .sessions
            .current_session_from_cookie(cookie_header, now.clone())
        {
            Ok(view) => view.account_id,
            Err(_) => {
                self.audit.push(AuthAuditEvent::PrincipalResolutionFailed {
                    reason: PrincipalResolutionFailure::Unauthenticated,
                    at: now,
                });
                return Err(AuthApiError::Unauthenticated);
            }
        };

        match self.directory.account(&account_id) {
            Some(account) if account.status == AccountStatus::Active => {
                let principal = PrincipalRef::Account { account_id };
                self.audit.push(AuthAuditEvent::PrincipalResolved {
                    principal: principal.clone(),
                    at: now,
                });
                Ok(principal)
            }
            _ => {
                self.audit.push(AuthAuditEvent::PrincipalResolutionFailed {
                    reason: PrincipalResolutionFailure::AccountDisabled,
                    at: now,
                });
                Err(AuthApiError::AccountDisabled)
            }
        }
    }

    /// `GET /.well-known/openid-configuration`: advertise this provider's
    /// canonical endpoints for the `issuer` base URL.
    ///
    /// IAM is the OpenID Provider; the document lets relying parties discover
    /// the `/v1` auth tree rather than hardcoding paths.
    pub fn openid_configuration(&self, issuer: &str) -> OpenIdProviderMetadata {
        OpenIdProviderMetadata::for_issuer(issuer)
    }

    /// `GET /.well-known/jwks.json`: publish the public access-token signing keys.
    ///
    /// Verifiers fetch this set and check tokens locally — IAM never shares a
    /// secret. The set holds the active key plus any rotated-but-unpruned
    /// predecessors so a token minted just before a rotation still verifies.
    pub fn jwks(&self) -> Jwks {
        self.tokens.jwks()
    }

    /// The `kid` of the active access-token signing key.
    pub fn active_signing_kid(&self) -> String {
        self.tokens.active_kid()
    }

    /// `POST /v1/tokens`: mint a signed asymmetric bearer access token.
    ///
    /// The token is a compact JWT signed with the active key (EdDSA/Ed25519),
    /// carrying that key's `kid` in the header and a freshly minted `jti` so it
    /// can be revoked individually. Verifiers validate it against [`jwks`](Self::jwks).
    pub async fn mint_access_token(
        &mut self,
        request: MintAccessToken,
    ) -> Result<String, AuthApiError> {
        let claims = AccessTokenClaims {
            iss: request.issuer,
            sub: request.subject,
            subject_kind: crate::AccessTokenSubjectKind::Account,
            aud: request.audience,
            exp: request.expires_at,
            iat: request.issued_at,
            jti: self.mint_id("jti"),
            scope: request.scopes,
        };
        Ok(self.tokens.mint(&claims).await?)
    }

    /// `POST /v1/oauth/token` (`grant_type=…:token-exchange`): exchange an
    /// upstream workload assertion for a short-lived IAM access token.
    ///
    /// This is the federated workload-identity seam (RFC 8693): an external
    /// workload presents an assertion it already holds from a trusted external
    /// issuer, and IAM — after verifying the assertion's signature against that
    /// issuer's published keys and validating its issuer, audience, and validity
    /// window — mints its own access token for the **service principal** the
    /// verified subject is bound to. The issued token is signed by the same key
    /// IAM publishes at [`jwks`](Self::jwks), so it verifies identically to every
    /// other IAM access token. No long-lived secret is exchanged or stored.
    ///
    /// Every outcome is audited. The error fails closed and collapses to a coarse
    /// OAuth error code (see [`TokenExchangeError::oauth_error_code`]) so the wire
    /// response never distinguishes an unknown issuer from a missing binding.
    pub async fn exchange_token(
        &mut self,
        request: TokenExchangeRequest,
    ) -> Result<TokenExchangeResponse, AuthApiError> {
        let (service_id, audience, scopes, workspace_roles, issuer, subject) =
            match self.trusted_issuers.authorize(&request) {
                Ok((binding, verified)) => (
                    binding.service_id.clone(),
                    binding.audience.clone(),
                    binding.scopes.clone(),
                    binding.workspace_role_bindings(),
                    verified.issuer,
                    verified.subject,
                ),
                Err(err) => {
                    self.audit.push(AuthAuditEvent::WorkloadIdentityRejected {
                        reason: err.clone(),
                        at: request.now,
                    });
                    return Err(AuthApiError::TokenExchange(err));
                }
            };

        let jti = self.mint_id("jti");
        let claims = AccessTokenClaims {
            iss: self.iam_issuer.clone(),
            sub: service_id.clone(),
            subject_kind: crate::AccessTokenSubjectKind::Service,
            aud: audience,
            exp: request.now + request.issued_token_lifetime_secs,
            iat: request.now,
            jti: jti.clone(),
            scope: scopes.clone(),
        };
        let access_token = match self.tokens.mint(&claims).await {
            Ok(token) => token,
            Err(err) => {
                let err = TokenExchangeError::from(err);
                self.audit.push(AuthAuditEvent::WorkloadIdentityRejected {
                    reason: err.clone(),
                    at: request.now,
                });
                return Err(AuthApiError::TokenExchange(err));
            }
        };

        let principal = PrincipalRef::Service {
            service_id: service_id.clone(),
        };
        self.audit.push(AuthAuditEvent::WorkloadIdentityFederated {
            issuer,
            subject,
            principal: principal.clone(),
            jti,
            at: request.now,
        });

        Ok(TokenExchangeResponse {
            access_token,
            issued_token_type: ISSUED_TOKEN_TYPE_ACCESS_TOKEN.to_owned(),
            token_type: BEARER_TOKEN_TYPE.to_owned(),
            expires_in: request.issued_token_lifetime_secs,
            scope: scopes,
            principal,
            workspace_roles,
        })
    }

    /// Rotate the active access-token signing key, drawing a fresh seed from the
    /// entropy source. The previous key stays published for verification until
    /// [`prune_signing_key`](Self::prune_signing_key) retires it.
    pub fn rotate_signing_key(&mut self, kid: impl Into<String>) {
        let mut seed = [0u8; 32];
        self.ids.fill_bytes(&mut seed);
        self.tokens.rotate(LocalSeedSigner::new(kid, seed));
    }

    /// Prune a retired signing key by `kid` so tokens it signed no longer verify.
    ///
    /// The active key cannot be pruned. Returns whether a key was removed.
    pub fn prune_signing_key(&mut self, kid: &str) -> bool {
        self.tokens.prune(kid)
    }

    /// Borrow the refresh-token directory backing rotation and chain revocation.
    pub fn refresh_tokens(&self) -> &RefreshTokenDirectory {
        &self.refresh_tokens
    }

    /// Borrow the access-token `jti` revocation denylist.
    pub fn access_revocations(&self) -> &AccessTokenRevocations {
        &self.access_revocations
    }

    /// Whether an access-token `jti` has been revoked.
    pub fn is_access_token_revoked(&self, jti: &str) -> bool {
        self.access_revocations.is_revoked(jti)
    }

    /// Verify a presented access token against the published JWKS **and** the
    /// `jti` revocation denylist.
    ///
    /// This is the IAM-side introspection path: a token that is cryptographically
    /// valid and unexpired but whose `jti` was revoked fails closed with
    /// [`AccessTokenError::Revoked`]. Stateless verifiers that only hold the JWKS
    /// can still revoke by mirroring the denylist.
    pub fn verify_access_token(&self, token: &str) -> Result<AccessTokenClaims, AccessTokenError> {
        crate::access_token::verify_active_access_token(
            token,
            &self.tokens.jwks(),
            &self.access_revocations,
        )
    }

    /// `POST /v1/oauth/token` (initial grant): issue a fresh access token and a
    /// new refresh-token chain for an already-authenticated account.
    ///
    /// The access token carries a freshly minted `jti` (so it is individually
    /// revocable) and the refresh token opens a new chain that later refreshes
    /// rotate. Both are returned once; only hashes are retained.
    pub async fn issue_token_grant(
        &mut self,
        request: IssueTokenGrant,
    ) -> Result<TokenGrant, AuthApiError> {
        let chain_id = RefreshTokenChainId(self.mint_id("rtc"));
        let refresh_token_id = RefreshTokenId(self.mint_id("rt"));
        let issued = self.refresh_minter.issue(
            &mut self.refresh_tokens,
            MintRefreshToken {
                id: refresh_token_id.clone(),
                chain_id: chain_id.clone(),
                account_id: request.account_id.clone(),
                subject: request.subject.clone(),
                audience: request.audience.clone(),
                scope: request.scopes.clone(),
                created_at: request.now.clone(),
                expires_at: request.refresh_expires_at,
            },
        )?;

        let (access_token, jti) = self
            .mint_access_with_jti(
                request.issuer,
                request.subject,
                request.audience,
                request.issued_at,
                request.access_expires_at,
                request.scopes,
            )
            .await?;

        self.audit.push(AuthAuditEvent::RefreshTokenIssued {
            account_id: request.account_id,
            chain_id,
            refresh_token_id,
            at: request.now,
        });

        Ok(TokenGrant {
            access_token,
            access_token_jti: jti,
            refresh_token: issued.secret,
            refresh_token_view: RefreshTokenView::from(&issued.token),
        })
    }

    /// `POST /v1/oauth/token` (`authorization_code` grant, IAM as OpenID Provider):
    /// redeem a downstream authorization code for a signed access token and an
    /// OIDC `id_token`.
    ///
    /// The downstream [`OAuthAuthorizationServer`] enforces the security-critical
    /// redemption (single-use/expiry, client authentication, redirect-URI match,
    /// PKCE) and resolves the [`AuthorizedGrant`](awaken_iam_core::AuthorizedGrant)
    /// — the account, its down-scoped scopes, and any bound `nonce`. This method
    /// joins that grant to the asymmetric signing authority: it mints an access
    /// token with a fresh `jti` (so it is individually revocable) and assembles an
    /// `id_token` whose `iss`/`sub`/`aud`/`exp`/`iat`/`nonce` assert the subject to
    /// the redeeming client. Subject and scope come from the grant, never the
    /// request, so a client cannot widen its own authority. Both tokens are signed
    /// by the active key and verify against [`jwks`](Self::jwks).
    pub async fn redeem_op_code<C: EntropySource>(
        &mut self,
        provider: &mut OAuthAuthorizationServer<C>,
        redemption: &TokenRedemption,
        request: OpCodeRedemption,
    ) -> Result<OpTokenGrant, AuthApiError> {
        let grant = provider.redeem_code(redemption, request.now)?;
        let subject = grant.account_id.0.clone();

        let (access_token, access_token_jti) = self
            .mint_access_with_jti(
                request.issuer.clone(),
                subject.clone(),
                request.access_audience,
                request.issued_at,
                request.access_expires_at,
                grant.scopes.clone(),
            )
            .await?;

        let id_token = mint_id_token(
            &self.tokens,
            MintIdToken {
                iss: request.issuer,
                sub: subject,
                // OIDC: the id_token audience is the client it was issued to.
                aud: redemption.client_id.clone(),
                iat: request.issued_at,
                exp: request.id_token_expires_at,
                nonce: grant.nonce,
            },
        )
        .await?;

        Ok(OpTokenGrant {
            access_token,
            access_token_jti,
            id_token,
            account_id: grant.account_id,
            scopes: grant.scopes,
        })
    }

    /// `POST /v1/oauth/token` (`refresh_token` grant): rotate the presented
    /// refresh token and mint a fresh access token.
    ///
    /// The presented token is retired and a successor issued under the same
    /// chain; replay of an already-retired token revokes the whole chain as a
    /// theft signal and fails closed. The new access token inherits the chain's
    /// stored subject/audience/scope — never client-supplied claims.
    pub async fn refresh_token_grant(
        &mut self,
        request: RefreshGrant,
    ) -> Result<TokenGrant, AuthApiError> {
        let successor_id = RefreshTokenId(self.mint_id("rt"));
        let rotated = match self.refresh_minter.rotate(
            &mut self.refresh_tokens,
            RotateRefreshToken {
                presented: request.presented_refresh_token.clone(),
                successor_id: successor_id.clone(),
                now: request.now.clone(),
                expires_at: request.refresh_expires_at,
            },
        ) {
            Ok(rotated) => rotated,
            Err(IamError::RefreshTokenReuseDetected { chain_id }) => {
                // The chain was revoked inside `rotate`; surface the theft signal.
                let revoked_count = self
                    .refresh_tokens
                    .chain(&chain_id)
                    .iter()
                    .filter(|token| token.is_revoked())
                    .count();
                self.audit.push(AuthAuditEvent::RefreshTokenReuseDetected {
                    chain_id: chain_id.clone(),
                    at: request.now.clone(),
                });
                self.audit.push(AuthAuditEvent::RefreshChainRevoked {
                    chain_id: chain_id.clone(),
                    revoked_count,
                    at: request.now,
                });
                return Err(AuthApiError::Login(IamError::RefreshTokenReuseDetected {
                    chain_id,
                }));
            }
            Err(err) => return Err(AuthApiError::Login(err)),
        };

        // The presented (now retired) token is still in the directory; resolve
        // its id from the presented secret's hash for the audit record.
        let retired_token_id = parse_presented_refresh_token(&request.presented_refresh_token)
            .map(awaken_iam_core::hash_session_token)
            .and_then(|hash| self.refresh_tokens.id_by_hash(&hash).cloned())
            .unwrap_or_else(|| RefreshTokenId(String::new()));

        let token = &rotated.token;
        let (access_token, jti) = self
            .mint_access_with_jti(
                request.issuer,
                token.subject.clone(),
                token.audience.clone(),
                request.issued_at,
                request.access_expires_at,
                token.scope.clone(),
            )
            .await?;

        self.audit.push(AuthAuditEvent::RefreshTokenRotated {
            account_id: token.account_id.clone(),
            chain_id: token.chain_id.clone(),
            retired_token_id,
            issued_token_id: successor_id,
            access_token_jti: jti.clone(),
            at: request.now,
        });

        Ok(TokenGrant {
            access_token,
            access_token_jti: jti,
            refresh_token: rotated.secret,
            refresh_token_view: RefreshTokenView::from(&rotated.token),
        })
    }

    /// Authenticate an OP client, then rotate its refresh-token chain.
    pub async fn op_refresh_token_grant<C: EntropySource>(
        &mut self,
        provider: &OAuthAuthorizationServer<C>,
        client_id: &str,
        client_secret: Option<&str>,
        request: RefreshGrant,
    ) -> Result<TokenGrant, AuthApiError> {
        provider.authenticate_client(client_id, client_secret)?;
        self.refresh_token_grant(request).await
    }

    /// Authenticate a client from this API's registered OP client registry and
    /// rotate its refresh-token chain.
    pub async fn refresh_registered_client(
        &mut self,
        client_id: &str,
        client_secret: Option<&str>,
        request: RefreshGrant,
    ) -> Result<TokenGrant, AuthApiError> {
        self.oauth_provider
            .authenticate_client(client_id, client_secret)?;
        let token_matches_client = parse_presented_refresh_token(&request.presented_refresh_token)
            .map(awaken_iam_core::hash_session_token)
            .and_then(|hash| self.refresh_tokens.token_by_hash(&hash))
            .is_some_and(|token| token.audience == client_id);
        if !token_matches_client {
            return Err(AuthApiError::OAuthProvider(
                OAuthProviderError::InvalidGrant,
            ));
        }
        self.refresh_token_grant(request).await
    }

    /// `POST /v1/oauth/revoke` (RFC 7009): revoke a presented token.
    ///
    /// A refresh token revokes its entire chain; an access token revokes its
    /// `jti`. The `token_type_hint` only orders the lookup — revocation falls
    /// through to the other family when the hint is wrong. Per RFC 7009 the
    /// operation is best-effort and never errors on an unknown token; the
    /// returned [`RevokeOutcome::revoked`] reports whether anything matched, for
    /// auditing, and is never leaked to the caller.
    pub fn revoke_token(&mut self, request: RevokeToken) -> RevokeOutcome {
        let revoked = match request.token_type_hint {
            Some(RevokeTokenHint::AccessToken) => {
                self.revoke_access(&request.token, &request.now)
                    || self.revoke_refresh(&request.token, &request.now)
            }
            _ => {
                self.revoke_refresh(&request.token, &request.now)
                    || self.revoke_access(&request.token, &request.now)
            }
        };
        RevokeOutcome { revoked }
    }

    /// Revoke a presented refresh token's chain. Returns whether a chain matched.
    fn revoke_refresh(&mut self, token: &str, now: &Timestamp) -> bool {
        let Some(secret) = parse_presented_refresh_token(token) else {
            return false;
        };
        let hash = awaken_iam_core::hash_session_token(secret);
        let Some(chain_id) = self
            .refresh_tokens
            .token_by_hash(&hash)
            .map(|token| token.chain_id.clone())
        else {
            return false;
        };
        let revoked_count = self.refresh_tokens.revoke_chain(&chain_id, now);
        self.audit.push(AuthAuditEvent::RefreshChainRevoked {
            chain_id,
            revoked_count,
            at: now.clone(),
        });
        true
    }

    /// Revoke a presented access token by `jti`. Returns whether the token
    /// verified and is now revoked (idempotent on a repeat revoke).
    fn revoke_access(&mut self, token: &str, now: &Timestamp) -> bool {
        let jwks = self.tokens.jwks();
        let Ok(claims) = crate::access_token::verify_access_token(token, &jwks) else {
            return false;
        };
        self.access_revocations.revoke(claims.jti.clone());
        self.audit.push(AuthAuditEvent::AccessTokenRevoked {
            jti: claims.jti,
            at: now.clone(),
        });
        true
    }

    /// `GET /v1/oauth/authorize`: issue a single-use authorization code to a
    /// product client for the authenticated end-user.
    ///
    /// IAM is the OpenID Provider: the end-user is authenticated by their live
    /// IAM session cookie (resolution fails closed with
    /// [`AuthApiError::Unauthenticated`] when the cookie does not back a live
    /// session), and the resolved account is bound to the code the core
    /// [`OAuthAuthorizationServer`] mints after validating the registered client,
    /// redirect-URI allowlist, down-scoping, and PKCE. The returned
    /// [`DownstreamAuthorizeOutcome::redirect_to`] is the client's registered
    /// redirect URI carrying the `code` and the echoed `state`.
    pub fn authorize(
        &mut self,
        request: DownstreamAuthorizeRequest,
    ) -> Result<DownstreamAuthorizeOutcome, AuthApiError> {
        let view = self.current_session(&request.cookie_header, request.now.clone())?;
        let account_id = view.account_id;

        let issued = self.oauth_provider.issue_code(
            account_id.clone(),
            &request.authorization,
            request.now.clone(),
            request.code_expires_at,
        )?;

        let redirect_to = build_authorize_redirect(
            &request.authorization.redirect_uri,
            &issued.code,
            issued.state.as_deref(),
        );

        self.audit.push(AuthAuditEvent::DownstreamCodeIssued {
            client_id: request.authorization.client_id,
            account_id,
            at: request.now,
        });

        Ok(DownstreamAuthorizeOutcome { redirect_to })
    }

    /// `POST /v1/oauth/token` (`authorization_code` grant): redeem a code for a
    /// fresh access token and refresh-token chain.
    ///
    /// The core [`OAuthAuthorizationServer`] validates the redemption — client
    /// authentication, redirect-URI match, single-use/expiry, and PKCE — and
    /// resolves it to an [`AuthorizedGrant`]. IAM then mints an opaque access
    /// token (with a fresh `jti`, so it is individually revocable) and opens a new
    /// refresh-token chain for the granted account and scopes; the access token's
    /// audience is the redeeming client. Both secrets are returned once.
    pub async fn redeem_authorization_code(
        &mut self,
        request: RedeemAuthorizationCode,
    ) -> Result<TokenGrant, AuthApiError> {
        let AuthorizedGrant {
            account_id, scopes, ..
        } = self
            .oauth_provider
            .redeem_code(&request.redemption, request.now.clone())?;

        let audience = request.redemption.client_id.clone();
        let chain_id = RefreshTokenChainId(self.mint_id("rtc"));
        let refresh_token_id = RefreshTokenId(self.mint_id("rt"));
        let issued = self.refresh_minter.issue(
            &mut self.refresh_tokens,
            MintRefreshToken {
                id: refresh_token_id.clone(),
                chain_id: chain_id.clone(),
                account_id: account_id.clone(),
                subject: account_id.0.clone(),
                audience: audience.clone(),
                scope: scopes.clone(),
                created_at: request.now.clone(),
                expires_at: request.refresh_expires_at,
            },
        )?;

        let (access_token, jti) = self
            .mint_access_with_jti(
                request.issuer,
                account_id.0.clone(),
                audience,
                request.issued_at,
                request.access_expires_at,
                scopes,
            )
            .await?;

        self.audit.push(AuthAuditEvent::RefreshTokenIssued {
            account_id: account_id.clone(),
            chain_id,
            refresh_token_id,
            at: request.now.clone(),
        });
        self.audit.push(AuthAuditEvent::DownstreamCodeRedeemed {
            client_id: request.redemption.client_id,
            account_id,
            access_token_jti: jti.clone(),
            at: request.now,
        });

        Ok(TokenGrant {
            access_token,
            access_token_jti: jti,
            refresh_token: issued.secret,
            refresh_token_view: RefreshTokenView::from(&issued.token),
        })
    }

    /// Mint a signed access token and return it alongside its minted `jti`.
    async fn mint_access_with_jti(
        &mut self,
        issuer: String,
        subject: String,
        audience: String,
        issued_at: i64,
        expires_at: i64,
        scopes: Vec<String>,
    ) -> Result<(String, String), AuthApiError> {
        let jti = self.mint_id("jti");
        let claims = AccessTokenClaims {
            iss: issuer,
            sub: subject,
            subject_kind: crate::AccessTokenSubjectKind::Account,
            aud: audience,
            exp: expires_at,
            iat: issued_at,
            jti: jti.clone(),
            scope: scopes,
        };
        let token = self.tokens.mint(&claims).await?;
        Ok((token, jti))
    }

    /// `GET /v1/oauth/userinfo`: return the authenticated subject's OIDC claims.
    ///
    /// Resolves the live session from the request cookie (failing closed when it
    /// is missing, revoked, or expired), then projects the account and its
    /// latest linked provider claims into [`UserInfo`]. `sub` is IAM's own
    /// account subject, never the upstream provider subject.
    pub fn userinfo(
        &mut self,
        cookie_header: &str,
        now: Timestamp,
    ) -> Result<UserInfo, AuthApiError> {
        let view = self.current_session(cookie_header, now)?;
        let identity = view.external_identity_id.as_ref().and_then(|external_id| {
            self.directory
                .identities_for_account(&view.account_id)
                .into_iter()
                .find(|identity| &identity.id == external_id)
        });
        let userinfo = UserInfo::project(
            &view.account_id,
            identity.map(|identity| &identity.claims),
            identity.map(|identity| &identity.last_seen_at),
        );
        Ok(userinfo)
    }

    /// Resolve OIDC UserInfo from a verified, unrevoked IAM bearer token.
    pub fn userinfo_for_access_token(&self, token: &str) -> Result<UserInfo, AuthApiError> {
        let claims = self.verify_access_token(token)?;
        let account_id = AccountId(claims.sub);
        let identity = self
            .directory
            .identities_for_account(&account_id)
            .into_iter()
            .max_by(|left, right| left.last_seen_at.0.cmp(&right.last_seen_at.0));
        Ok(UserInfo::project(
            &account_id,
            identity.map(|value| &value.claims),
            identity.map(|value| &value.last_seen_at),
        ))
    }

    /// `DELETE /v1/session`: revoke the presented session and clear its cookie.
    pub fn logout(
        &mut self,
        cookie_header: &str,
        now: Timestamp,
    ) -> Result<LogoutOutcome, AuthApiError> {
        let token = self
            .sessions
            .cookie_config()
            .extract_token(cookie_header)
            .ok_or(AuthApiError::Login(IamError::SessionNotFound {
                id: SessionId(String::new()),
            }))?;
        let session_id = self.sessions.session_id_for_token(&token)?;
        let clear_session_cookie = self.sessions.logout(&token, now.clone())?;
        if let Some(session_id) = session_id {
            self.audit.push(AuthAuditEvent::LoggedOut {
                session_id,
                at: now,
            });
        }
        Ok(LogoutOutcome {
            clear_session_cookie,
        })
    }

    /// `GET /v1/account/identities`: list the identities linked to an account.
    pub fn list_identities(&self, account_id: &AccountId) -> Vec<ExternalIdentity> {
        self.directory
            .identities_for_account(account_id)
            .into_iter()
            .cloned()
            .collect()
    }

    /// `POST /v1/account/identities`: link a verified external identity to an
    /// account.
    pub fn link_identity(
        &mut self,
        request: LinkIdentity,
    ) -> Result<ExternalIdentity, AuthApiError> {
        let external_identity_id = ExternalIdentityId(self.mint_id("ext"));
        let identity = ExternalIdentity {
            id: external_identity_id.clone(),
            account_id: request.account_id.clone(),
            provider_key: request.provider_key.clone(),
            claims: request.claims,
            first_seen_at: request.now.clone(),
            last_seen_at: request.now.clone(),
        };
        self.directory.link_external_identity(identity.clone())?;
        self.audit.push(AuthAuditEvent::IdentityLinked {
            account_id: request.account_id,
            external_identity_id,
            provider_key: request.provider_key,
            at: request.now,
        });
        Ok(identity)
    }

    /// `DELETE /v1/account/identities/{provider}/{subject}`: detach an identity
    /// owned by the account.
    pub fn unlink_identity(&mut self, request: UnlinkIdentity) -> Result<(), AuthApiError> {
        let owned = self
            .directory
            .external_identity(&request.provider_key, &request.subject)
            .map(|identity| identity.account_id == request.account_id);
        match owned {
            None => Err(AuthApiError::Login(IamError::ExternalIdentityNotFound {
                provider_key: request.provider_key,
                subject: request.subject,
            })),
            Some(false) => Err(AuthApiError::IdentityAccountMismatch),
            Some(true) => {
                self.directory
                    .remove_external_identity(&request.provider_key, &request.subject)?;
                self.audit.push(AuthAuditEvent::IdentityUnlinked {
                    account_id: request.account_id,
                    provider_key: request.provider_key,
                    subject: request.subject,
                    at: request.now,
                });
                Ok(())
            }
        }
    }

    /// Resolve the account for a set of verified claims, provisioning a new
    /// account and link on first login.
    fn resolve_account(
        &mut self,
        provider_key: &IdentityProviderKey,
        claims: ExternalIdentityClaims,
        now: &Timestamp,
    ) -> Result<(AccountId, ExternalIdentityId, bool), AuthApiError> {
        if let Some(existing) = self
            .directory
            .external_identity(provider_key, &claims.subject)
        {
            let account_id = existing.account_id.clone();
            let external_identity_id = existing.id.clone();
            self.directory.update_external_identity_claims(
                provider_key.clone(),
                claims,
                now.clone(),
            )?;
            return Ok((account_id, external_identity_id, false));
        }

        let account_id = AccountId(self.mint_id("acct"));
        self.directory.upsert_account(Account {
            id: account_id.clone(),
            status: AccountStatus::Active,
            display_name: claims.display_name.clone(),
            created_at: now.clone(),
            updated_at: now.clone(),
        });
        let external_identity_id = ExternalIdentityId(self.mint_id("ext"));
        self.directory.link_external_identity(ExternalIdentity {
            id: external_identity_id.clone(),
            account_id: account_id.clone(),
            provider_key: provider_key.clone(),
            claims,
            first_seen_at: now.clone(),
            last_seen_at: now.clone(),
        })?;
        Ok((account_id, external_identity_id, true))
    }

    fn provider_index(&self, provider_key: &IdentityProviderKey) -> Result<usize, AuthApiError> {
        self.providers
            .iter()
            .position(|provider| &provider.config.provider_key == provider_key)
            .ok_or_else(|| AuthApiError::UnknownProvider(provider_key.clone()))
    }

    fn record_failure(
        &mut self,
        provider_key: &IdentityProviderKey,
        reason: AuthFailureReason,
        at: &Timestamp,
    ) {
        self.audit.push(AuthAuditEvent::LoginFailed {
            provider_key: provider_key.clone(),
            reason,
            at: at.clone(),
        });
    }

    fn mint_id(&mut self, prefix: &str) -> String {
        let mut buf = [0u8; ID_BYTES];
        self.ids.fill_bytes(&mut buf);
        format!("{prefix}_{}", URL_SAFE_NO_PAD.encode(buf))
    }
}

#[cfg(test)]
#[path = "auth_api_tests.rs"]
mod tests;
