use serde::{Deserialize, Serialize};

use crate::{AccountId, ActionKey, PrincipalRef};

/// Identity provider configuration identifier.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct IdentityProviderConfigId(pub String);

/// Stable identity provider key, for example `fake` or `github`.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct IdentityProviderKey(pub String);

/// External subject identifier assigned by an identity provider.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct ExternalSubject(pub String);

/// External identity row identifier.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct ExternalIdentityId(pub String);

/// OAuth login-state row identifier.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct OAuthLoginStateId(pub String);

/// Browser/API session row identifier.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct SessionId(pub String);

/// RFC 3339 timestamp serialized as a string.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct Timestamp(pub String);

/// Lifecycle state for a platform account.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AccountStatus {
    /// Account can authenticate and act according to grants.
    Active,
    /// Account exists but cannot authenticate.
    Disabled,
}

/// Global human account.
///
/// Provider email addresses are intentionally not stored here as identity keys.
/// Email is a mutable claim on [`ExternalIdentityClaims`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Account {
    /// Stable internal account identifier.
    pub id: AccountId,
    /// Account lifecycle status.
    pub status: AccountStatus,
    /// Optional local display name chosen by the account holder or admin.
    pub display_name: Option<String>,
    /// Creation timestamp.
    pub created_at: Timestamp,
    /// Last account metadata update timestamp.
    pub updated_at: Timestamp,
}

/// Supported identity-provider families.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum IdentityProviderKind {
    /// Deterministic non-production provider used by local/dev login flows.
    Fake,
    /// OAuth 2.0 provider.
    OAuth2,
    /// OpenID Connect provider.
    Oidc,
}

/// Identity provider configuration safe to expose in shared contracts.
///
/// Client secrets and signing keys are deployment secrets and do not belong in
/// this DTO.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct IdentityProviderConfig {
    /// Stable config identifier.
    pub id: IdentityProviderConfigId,
    /// Provider key used in login routes and external identity uniqueness.
    pub provider_key: IdentityProviderKey,
    /// Provider implementation family.
    pub kind: IdentityProviderKind,
    /// Human-readable provider name.
    pub display_name: String,
    /// Optional issuer URL for OAuth/OIDC providers.
    pub issuer_url: Option<String>,
    /// Optional authorization endpoint URL.
    pub authorization_endpoint: Option<String>,
    /// Optional token endpoint URL.
    pub token_endpoint: Option<String>,
    /// Public OAuth client id, when applicable.
    pub client_id: Option<String>,
    /// Whether login through this provider is currently allowed.
    pub enabled: bool,
}

/// Normalized claims received from an external identity provider.
///
/// `subject` is the provider-scoped immutable identity coordinate. Email and
/// profile fields are mutable claims and may change on later logins.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ExternalIdentityClaims {
    /// Provider-scoped immutable subject.
    pub subject: ExternalSubject,
    /// Mutable email claim, if supplied by the provider.
    pub email: Option<String>,
    /// Provider assertion about the current email claim.
    pub email_verified: Option<bool>,
    /// Mutable display-name claim.
    pub display_name: Option<String>,
    /// Mutable username / handle claim.
    pub username: Option<String>,
    /// Mutable avatar URL claim.
    pub avatar_url: Option<String>,
    /// Mutable locale claim.
    pub locale: Option<String>,
}

/// Unique coordinate for an external identity.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct ExternalIdentityKey {
    /// Provider that issued the subject.
    pub provider_key: IdentityProviderKey,
    /// Provider-scoped subject.
    pub subject: ExternalSubject,
}

impl ExternalIdentityKey {
    /// Build a uniqueness key from provider and normalized claims.
    pub fn from_claims(provider_key: IdentityProviderKey, claims: &ExternalIdentityClaims) -> Self {
        Self {
            provider_key,
            subject: claims.subject.clone(),
        }
    }
}

/// Link between an internal account and a provider subject.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ExternalIdentity {
    /// Stable external identity row id.
    pub id: ExternalIdentityId,
    /// Account this provider subject resolves to.
    pub account_id: AccountId,
    /// Provider that issued the subject.
    pub provider_key: IdentityProviderKey,
    /// Latest normalized provider claims.
    pub claims: ExternalIdentityClaims,
    /// First successful login/link timestamp.
    pub first_seen_at: Timestamp,
    /// Last successful login/claim refresh timestamp.
    pub last_seen_at: Timestamp,
}

impl ExternalIdentity {
    /// Return the provider+subject uniqueness key for this identity.
    pub fn key(&self) -> ExternalIdentityKey {
        ExternalIdentityKey::from_claims(self.provider_key.clone(), &self.claims)
    }
}

/// Public view of the current session returned by `GET /v1/session`.
///
/// This is the safe projection of a [`Session`] for clients: it exposes the
/// session and account coordinates and lifecycle timestamps, but never the
/// bearer `token_hash`. The opaque session token lives only in the session
/// cookie and is never echoed back in a response body.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SessionView {
    /// Stable session row id.
    pub session_id: SessionId,
    /// Account authenticated by this session.
    pub account_id: AccountId,
    /// Identity used to establish the session, when applicable.
    pub external_identity_id: Option<ExternalIdentityId>,
    /// Session creation timestamp.
    pub created_at: Timestamp,
    /// Last observed activity timestamp.
    pub last_seen_at: Timestamp,
    /// Session expiration timestamp.
    pub expires_at: Timestamp,
}

impl SessionView {
    /// Project a stored [`Session`] into its public, token-free view.
    pub fn from_session(session: &Session) -> Self {
        Self {
            session_id: session.id.clone(),
            account_id: session.account_id.clone(),
            external_identity_id: session.external_identity_id.clone(),
            created_at: session.created_at.clone(),
            last_seen_at: session.last_seen_at.clone(),
            expires_at: session.expires_at.clone(),
        }
    }
}

impl From<&Session> for SessionView {
    fn from(session: &Session) -> Self {
        Self::from_session(session)
    }
}

/// OpenID Provider metadata served at `/.well-known/openid-configuration`.
///
/// IAM is the OpenID Provider (OP) to product clients; this document advertises
/// the canonical `/v1` endpoints of that provider so relying parties can
/// discover them rather than hardcoding paths. Endpoint URLs are absolute and
/// derived from the deployment `issuer`. Field names follow the OpenID Connect
/// Discovery wire format verbatim.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct OpenIdProviderMetadata {
    /// Issuer identifier; the base URL the provider is reachable at.
    pub issuer: String,
    /// Authorization endpoint that begins a federated login.
    pub authorization_endpoint: String,
    /// Token endpoint for the `authorization_code` and `refresh_token` grants.
    pub token_endpoint: String,
    /// UserInfo endpoint returning the authenticated subject's claims.
    pub userinfo_endpoint: String,
    /// JWKS endpoint exposing the access-token signing keys.
    pub jwks_uri: String,
    /// OAuth `response_type` values supported (authorization-code flow only).
    pub response_types_supported: Vec<String>,
    /// Subject identifier types supported.
    pub subject_types_supported: Vec<String>,
    /// Signing algorithms used for issued `id_token`s.
    pub id_token_signing_alg_values_supported: Vec<String>,
    /// OIDC/OAuth scopes the provider recognizes.
    pub scopes_supported: Vec<String>,
    /// Grant types the token endpoint accepts.
    pub grant_types_supported: Vec<String>,
}

impl OpenIdProviderMetadata {
    /// Build provider metadata for an `issuer` base URL.
    ///
    /// Any trailing `/` on `issuer` is trimmed so the advertised endpoints never
    /// contain a doubled separator. Endpoints mirror the canonical auth tree:
    /// `/v1/auth/login`, `/v1/oauth/token`, `/v1/oauth/userinfo`, and
    /// `/.well-known/jwks.json`.
    pub fn for_issuer(issuer: &str) -> Self {
        let base = issuer.trim_end_matches('/');
        Self {
            issuer: base.to_owned(),
            authorization_endpoint: format!("{base}/v1/auth/login"),
            token_endpoint: format!("{base}/v1/oauth/token"),
            userinfo_endpoint: format!("{base}/v1/oauth/userinfo"),
            jwks_uri: format!("{base}/.well-known/jwks.json"),
            response_types_supported: vec!["code".to_owned()],
            subject_types_supported: vec!["public".to_owned()],
            id_token_signing_alg_values_supported: vec!["RS256".to_owned(), "EdDSA".to_owned()],
            scopes_supported: vec![
                "openid".to_owned(),
                "email".to_owned(),
                "profile".to_owned(),
            ],
            grant_types_supported: vec![
                "authorization_code".to_owned(),
                "refresh_token".to_owned(),
            ],
        }
    }
}

/// A single public signing key published in the [`Jwks`] document.
///
/// IAM signs access tokens asymmetrically and exposes only the public half here,
/// so verifiers (product services) fetch keys from `/.well-known/jwks.json`
/// rather than sharing a secret. This is the RFC 7517 JWK shape for the
/// `OKP`/`Ed25519` curve used by the `EdDSA` access-token algorithm; the private
/// seed never leaves the signing store. `kid` selects the key a token was signed
/// with so the publisher can rotate keys while old tokens still verify.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct JsonWebKey {
    /// Key type. `OKP` (octet key pair) for Edwards-curve keys.
    pub kty: String,
    /// Curve identifier. `Ed25519` for the access-token signing curve.
    pub crv: String,
    /// Base64url (no padding) encoding of the 32-byte public key.
    pub x: String,
    /// Key id matching the `kid` header of tokens signed with this key.
    pub kid: String,
    /// Intended key use. `sig` for signature verification.
    #[serde(rename = "use")]
    pub key_use: String,
    /// Algorithm the key is used with. `EdDSA` for Ed25519 access tokens.
    pub alg: String,
}

/// JSON Web Key Set served at `GET /.well-known/jwks.json` (RFC 7517).
///
/// Carries every signing key still trusted for verification — the active key
/// plus any rotated-but-not-yet-pruned predecessors — so a verifier can check a
/// token minted just before a rotation. Pruning a key drops it from this set and
/// retires the tokens it signed.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Jwks {
    /// The published public keys, newest first.
    pub keys: Vec<JsonWebKey>,
}

/// OIDC UserInfo claims returned by `GET /v1/oauth/userinfo`.
///
/// `sub` is IAM's own stable subject for the authenticated account, never the
/// upstream provider subject — products federate through IAM and see one
/// identity coordinate regardless of which provider was used. The profile
/// fields are the latest normalized [`ExternalIdentityClaims`] and are omitted
/// from the response when absent.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct UserInfo {
    /// Stable IAM subject identifier (the account id).
    pub sub: String,
    /// Email claim, if known.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub email: Option<String>,
    /// Whether the provider asserted the email is verified.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub email_verified: Option<bool>,
    /// Display name claim, if known.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    /// Username / handle claim, if known.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub preferred_username: Option<String>,
    /// Avatar URL claim, if known.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub picture: Option<String>,
    /// Locale claim, if known.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub locale: Option<String>,
    /// Timestamp the claims were last refreshed, if known.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub updated_at: Option<String>,
}

impl UserInfo {
    /// Project the authenticated `account_id` and its latest provider claims
    /// into OIDC UserInfo claims. With no linked identity claims, only `sub` is
    /// populated.
    pub fn project(
        account_id: &AccountId,
        claims: Option<&ExternalIdentityClaims>,
        updated_at: Option<&Timestamp>,
    ) -> Self {
        Self {
            sub: account_id.0.clone(),
            email: claims.and_then(|claims| claims.email.clone()),
            email_verified: claims.and_then(|claims| claims.email_verified),
            name: claims.and_then(|claims| claims.display_name.clone()),
            preferred_username: claims.and_then(|claims| claims.username.clone()),
            picture: claims.and_then(|claims| claims.avatar_url.clone()),
            locale: claims.and_then(|claims| claims.locale.clone()),
            updated_at: updated_at.map(|stamp| stamp.0.clone()),
        }
    }
}

/// Stored OAuth login-state challenge.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct OAuthLoginState {
    /// Stable login-state row id.
    pub id: OAuthLoginStateId,
    /// Provider selected for the pending login.
    pub provider_key: IdentityProviderKey,
    /// Hash of the OAuth `state` value.
    pub state_hash: String,
    /// Optional hash of the OIDC nonce value.
    pub nonce_hash: Option<String>,
    /// Optional hash of the PKCE verifier.
    pub pkce_verifier_hash: Option<String>,
    /// Post-login return path after the session is established.
    pub return_to: Option<String>,
    /// Creation timestamp.
    pub created_at: Timestamp,
    /// Expiration timestamp.
    pub expires_at: Timestamp,
    /// Consumption timestamp. Consumed states cannot be reused.
    pub consumed_at: Option<Timestamp>,
}

/// Login session for an authenticated account.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Session {
    /// Stable session row id.
    pub id: SessionId,
    /// Account authenticated by this session.
    pub account_id: AccountId,
    /// Hash of the bearer session token.
    pub token_hash: String,
    /// Identity used to establish the session, when applicable.
    pub external_identity_id: Option<ExternalIdentityId>,
    /// Session creation timestamp.
    pub created_at: Timestamp,
    /// Last observed activity timestamp.
    pub last_seen_at: Timestamp,
    /// Session expiration timestamp.
    pub expires_at: Timestamp,
    /// Logout/revocation timestamp.
    pub revoked_at: Option<Timestamp>,
}

/// API token row identifier.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct ApiTokenId(pub String);

/// Public, non-secret lookup prefix of an API token.
///
/// A presented token carries this prefix in cleartext so the row can be located
/// without scanning, while the secret half is verified against the stored
/// argon2id hash. The prefix is safe to display in token-management UIs.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct ApiTokenPrefix(pub String);

/// A long-lived, principal-scoped API token, persisted only as a hash.
///
/// API tokens authenticate machine and automation callers
/// ([`PrincipalRef::Service`] / [`PrincipalRef::ApiToken`]) whose authority is a
/// fixed [`scope`](ApiToken::scope) set of [`ActionKey`]s. Only the public
/// [`prefix`](ApiToken::prefix) and the argon2id [`secret_hash`](ApiToken::secret_hash)
/// are stored; the cleartext token is shown exactly once at mint time and never
/// again. Liveness is the conjunction of "not revoked" and "not past
/// `expires_at`"; a token with no `expires_at` never expires and lives until it
/// is revoked.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ApiToken {
    /// Stable token row id.
    pub id: ApiTokenId,
    /// Public lookup prefix presented alongside the secret.
    pub prefix: ApiTokenPrefix,
    /// Principal this token authenticates as.
    pub principal: PrincipalRef,
    /// Argon2id PHC hash of the token's secret half.
    pub secret_hash: String,
    /// Action scope this token may exercise; an empty set authorizes nothing.
    pub scope: Vec<ActionKey>,
    /// Token mint timestamp.
    pub created_at: Timestamp,
    /// Optional expiration timestamp; `None` never expires.
    pub expires_at: Option<Timestamp>,
    /// Revocation timestamp; once set the token can no longer authenticate.
    pub revoked_at: Option<Timestamp>,
}

impl ApiToken {
    /// Whether the token authenticates at `now`: unrevoked and, when an
    /// expiration is set, strictly before it. Timestamps compare as canonical
    /// RFC 3339 UTC strings, whose lexical order matches chronological order.
    pub fn is_live(&self, now: &Timestamp) -> bool {
        if self.revoked_at.is_some() {
            return false;
        }
        match &self.expires_at {
            Some(expires_at) => now.0 < expires_at.0,
            None => true,
        }
    }

    /// Whether `action` is within this token's scope set (exact match).
    pub fn authorizes(&self, action: &ActionKey) -> bool {
        self.scope.contains(action)
    }
}

/// Public view of an [`ApiToken`] safe to return to clients.
///
/// It exposes the token's coordinates, scope, and lifecycle timestamps but never
/// the `secret_hash`. The cleartext token itself is only ever returned once, at
/// mint time, and is not part of this view.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ApiTokenView {
    /// Stable token row id.
    pub id: ApiTokenId,
    /// Public lookup prefix.
    pub prefix: ApiTokenPrefix,
    /// Principal this token authenticates as.
    pub principal: PrincipalRef,
    /// Action scope this token may exercise.
    pub scope: Vec<ActionKey>,
    /// Token mint timestamp.
    pub created_at: Timestamp,
    /// Optional expiration timestamp.
    pub expires_at: Option<Timestamp>,
    /// Revocation timestamp, when revoked.
    pub revoked_at: Option<Timestamp>,
}

impl ApiTokenView {
    /// Project a stored [`ApiToken`] into its public, hash-free view.
    pub fn from_token(token: &ApiToken) -> Self {
        Self {
            id: token.id.clone(),
            prefix: token.prefix.clone(),
            principal: token.principal.clone(),
            scope: token.scope.clone(),
            created_at: token.created_at.clone(),
            expires_at: token.expires_at.clone(),
            revoked_at: token.revoked_at.clone(),
        }
    }
}

impl From<&ApiToken> for ApiTokenView {
    fn from(token: &ApiToken) -> Self {
        Self::from_token(token)
    }
}
