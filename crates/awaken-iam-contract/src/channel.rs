//! Message-bound authentication at a deployment-registered channel verifier.
use crate::PrincipalRef;
use serde::{Deserialize, Serialize};
/// Dedicated message evidence, never an OAuth Account access-token family.
pub const CHANNEL_MESSAGE_PROOF_TYP: &str = "awaken-channel-message-proof+jwt";
pub const CHANNEL_MESSAGE_PROOF_TOKEN_TYPE: &str = "AwakenChannelProof";

/// The intentionally distinct payload cannot decode as ordinary Account claims.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ChannelMessageProofClaims {
    pub iss: String,
    pub aud: String,
    pub principal: PrincipalRef,
    pub evidence_id: String,
    pub issued_at: i64,
    pub expires_at: i64,
    pub installation_id: String,
    pub connector_id: String,
    pub message_id: String,
    pub body_sha256: String,
}

pub const CHANNEL_ASSERTION_GRANT_TYPE: &str =
    "urn:awaken:params:oauth:grant-type:channel-assertion";
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ChannelAssertionClaims {
    pub iss: String,
    pub aud: String,
    pub sub: String,
    pub jti: String,
    pub iat: i64,
    pub exp: i64,
    pub installation_id: String,
    pub connector_id: String,
    pub message_id: String,
    pub body_sha256: String,
}
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ChannelPrincipalGrant {
    /// Compatibility field carrying the dedicated signed message proof.
    /// It is not an Account access token and must never be sent as Bearer.
    /// Consumers authenticate actual product operations independently.
    pub access_token: String,
    pub token_type: String,
    pub expires_in: i64,
    pub scope: String,
    pub principal: PrincipalRef,
    pub evidence_id: String,
    pub installation_id: String,
    pub connector_id: String,
    pub message_id: String,
    pub body_sha256: String,
    pub expires_at: i64,
    /// A routing observation only. Consumers still authorize every actual call.
    pub group_refs: Vec<String>,
}

impl std::fmt::Debug for ChannelPrincipalGrant {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ChannelPrincipalGrant")
            .field("principal", &self.principal)
            .field("evidence_id", &self.evidence_id)
            .field("access_token", &"[redacted]")
            .finish_non_exhaustive()
    }
}
