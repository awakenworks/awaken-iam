use serde::{Deserialize, Serialize};

use crate::AccountId;

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
