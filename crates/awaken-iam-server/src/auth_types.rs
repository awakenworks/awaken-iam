//! Small provider/session result types shared by authentication transports.

use awaken_iam_contract::{
    AccountId, ExternalIdentityId, IdentityProviderKey, IdentityProviderKind,
};

/// Stable machine-readable reason a session could not resolve an active account.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PrincipalResolutionFailure {
    /// No live session backed the presented cookie.
    Unauthenticated,
    /// The session resolved to a disabled or unknown account.
    AccountDisabled,
}

/// Stable machine-readable reason a login attempt failed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AuthFailureReason {
    /// Login correlation was absent or unparseable.
    MissingCorrelation,
    /// OAuth state did not match the challenge.
    StateMismatch,
    /// Challenge was expired, replayed, or unusable.
    ChallengeRejected,
    /// Provider exchange rejected the callback.
    ProviderRejected,
}

/// Compact provider descriptor returned by `GET /v1/auth/providers`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProviderSummary {
    /// Stable provider key.
    pub provider_key: IdentityProviderKey,
    /// Provider implementation family.
    pub kind: IdentityProviderKind,
    /// Human-readable provider name.
    pub display_name: String,
}

/// Account resolution after a trusted provider verifies external claims.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExternalLoginResolution {
    /// Resolved IAM account.
    pub account_id: AccountId,
    /// Durable provider-subject link.
    pub external_identity_id: ExternalIdentityId,
    /// Whether this exchange provisioned the account.
    pub registered: bool,
}
