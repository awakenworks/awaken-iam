//! OIDC `id_token` issuance for IAM-as-OpenID-Provider.
//!
//! When a product redeems an authorization code at IAM's token endpoint (the
//! downstream authorization server in
//! [`oauth_provider`](awaken_iam_core::OAuthAuthorizationServer)), it receives
//! two artifacts: an opaque-to-the-client but cryptographically real **access
//! token** for IAM's own service APIs, and — when the grant requested `openid` —
//! an **`id_token`**: a compact JWT asserting *who* the end-user is to the
//! relying party. This module mints that `id_token`.
//!
//! The `id_token` is signed by the same asymmetric key as an access token
//! ([`AccessTokenAuthority`]) and verified against the same published
//! [`Jwks`](awaken_iam_contract::Jwks), but it carries a **distinct `typ`** so it
//! cannot be replayed where an access token (or a capability token) is expected,
//! and vice versa — the same family-fencing discipline the access-token and
//! capability-token families already use. Its claims are the OIDC core subset the
//! relying party authenticates the subject from: `iss`/`sub`/`aud`/`exp`/`iat`
//! and the `nonce` echoed from the authorization request to bind the token to the
//! initiating user agent.

use awaken_iam_contract::Jwks;
use serde::{Deserialize, Serialize};

use crate::access_token::{AccessTokenAuthority, AccessTokenError, verify_jwt};

/// JOSE `typ` header marking the OIDC `id_token` family apart from access and
/// capability tokens, so an `id_token` presented where one of those is expected
/// (or the reverse) fails closed even though every family is signed by the same
/// key and published under the same JWKS.
pub const ID_TOKEN_TYP: &str = "id+jwt";

/// Claims carried in an IAM-issued OIDC `id_token` payload (the OIDC core subset).
///
/// `aud` is the relying party's `client_id` (per OIDC, the `id_token` audience is
/// the client it was issued to, distinct from an access token's service
/// audience); `sub` is IAM's own account subject, never an upstream provider
/// subject; `nonce` is echoed from the authorization request when one was
/// supplied so the relying party can bind the token to its session.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OidcIdTokenClaims {
    /// Issuer: the IAM deployment that minted the token.
    pub iss: String,
    /// Subject: the IAM account the end-user authenticated as.
    pub sub: String,
    /// Audience: the relying party's `client_id` the token was issued to.
    pub aud: String,
    /// Expiration time as a Unix timestamp (seconds).
    pub exp: i64,
    /// Issued-at time as a Unix timestamp (seconds).
    pub iat: i64,
    /// OIDC `nonce` echoed from the authorization request; omitted on the wire
    /// when the request carried none.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub nonce: Option<String>,
}

/// Request to mint an OIDC `id_token` for a redeemed authorization grant.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MintIdToken {
    /// Issuer identifier stamped into the `iss` claim.
    pub iss: String,
    /// Subject: the IAM account the end-user authenticated as.
    pub sub: String,
    /// Audience: the relying party's `client_id`.
    pub aud: String,
    /// Issued-at Unix timestamp (seconds).
    pub iat: i64,
    /// Expiration Unix timestamp (seconds); must be strictly after `iat`.
    pub exp: i64,
    /// OIDC `nonce` to bind into the token, when the authorization request carried
    /// one.
    pub nonce: Option<String>,
}

/// Errors raised while minting an OIDC `id_token`.
#[derive(Debug, PartialEq, Eq, thiserror::Error)]
pub enum IdTokenError {
    /// Signing the token failed (no key, encoding).
    #[error(transparent)]
    Crypto(#[from] AccessTokenError),
    /// The validity window was not strictly forward (`exp <= iat`).
    #[error("id_token expiry must be strictly after issued-at")]
    InvalidWindow,
}

/// Mint an OIDC `id_token` signed by the authority's active key.
///
/// The token is fenced into the `id_token` family by its `typ` header and carries
/// the OIDC core claims a relying party verifies the subject from. The window is
/// validated as strictly forward so a token can never be born already expired.
pub fn mint_id_token(
    authority: &AccessTokenAuthority,
    request: MintIdToken,
) -> Result<String, IdTokenError> {
    if request.exp <= request.iat {
        return Err(IdTokenError::InvalidWindow);
    }
    let claims = OidcIdTokenClaims {
        iss: request.iss,
        sub: request.sub,
        aud: request.aud,
        exp: request.exp,
        iat: request.iat,
        nonce: request.nonce,
    };
    Ok(authority.sign_jwt(ID_TOKEN_TYP, &claims)?)
}

/// Verify an IAM-issued OIDC `id_token` against a published [`Jwks`], returning
/// its claims.
///
/// This is the relying-party path: the `kid` selects the published key, the `typ`
/// fences the `id_token` family apart, and an unknown `kid`, a foreign algorithm,
/// a wrong `typ`, or a bad signature all fail closed. It does not decide
/// audience/nonce/expiry — those are the relying party's policy checks layered on
/// the recovered claims.
pub fn verify_id_token(token: &str, jwks: &Jwks) -> Result<OidcIdTokenClaims, AccessTokenError> {
    verify_jwt(token, jwks, ID_TOKEN_TYP)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::access_token::{AccessTokenClaims, LocalSeedSigner, verify_access_token};
    use base64::Engine as _;

    fn authority() -> AccessTokenAuthority {
        AccessTokenAuthority::new(LocalSeedSigner::new("key-1", [7u8; 32]))
    }

    fn request() -> MintIdToken {
        MintIdToken {
            iss: "https://iam.example".into(),
            sub: "acct_ada".into(),
            aud: "product-web".into(),
            iat: 1_899_996_400,
            exp: 1_900_000_000,
            nonce: Some("nonce-1".into()),
        }
    }

    #[test]
    fn id_token_is_signed_and_verifies_against_published_jwks() {
        let authority = authority();
        let token = mint_id_token(&authority, request()).expect("mint");
        // header.payload.signature.
        assert_eq!(token.split('.').count(), 3);

        let claims = verify_id_token(&token, &authority.jwks()).expect("verify");
        assert_eq!(claims.iss, "https://iam.example");
        assert_eq!(claims.sub, "acct_ada");
        assert_eq!(claims.aud, "product-web");
        assert_eq!(claims.exp, 1_900_000_000);
        assert_eq!(claims.iat, 1_899_996_400);
        assert_eq!(claims.nonce.as_deref(), Some("nonce-1"));
    }

    #[test]
    fn a_nonceless_request_omits_nonce_from_the_wire() {
        let authority = authority();
        let mut req = request();
        req.nonce = None;
        let token = mint_id_token(&authority, req).expect("mint");
        let payload = token.split('.').nth(1).unwrap();
        let bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .decode(payload)
            .unwrap();
        let json = String::from_utf8(bytes).unwrap();
        assert!(
            !json.contains("nonce"),
            "absent nonce must not be serialized"
        );
    }

    #[test]
    fn a_zero_width_window_is_rejected() {
        let authority = authority();
        let mut req = request();
        req.exp = req.iat;
        assert_eq!(
            mint_id_token(&authority, req),
            Err(IdTokenError::InvalidWindow)
        );
    }

    #[test]
    fn an_id_token_does_not_verify_as_an_access_token() {
        // Family fence: the distinct `typ` means an id_token presented to the
        // access-token verifier fails closed, never authenticating a service call.
        let authority = authority();
        let token = mint_id_token(&authority, request()).expect("mint");
        let err = verify_access_token(&token, &authority.jwks()).unwrap_err();
        assert!(matches!(err, AccessTokenError::UnexpectedType { .. }));
    }

    #[test]
    fn an_access_token_does_not_verify_as_an_id_token() {
        // The reverse fence: an access token presented as an id_token is rejected
        // on its `typ` before any claim is trusted.
        let authority = authority();
        let access = authority
            .mint(&AccessTokenClaims {
                iss: "https://iam.example".into(),
                sub: "acct_ada".into(),
                aud: "packs-service".into(),
                exp: 1_900_000_000,
                iat: 1_899_996_400,
                jti: "jti-1".into(),
                scope: vec!["pack.read".into()],
            })
            .expect("mint access");
        let err = verify_id_token(&access, &authority.jwks()).unwrap_err();
        assert!(matches!(err, AccessTokenError::UnexpectedType { .. }));
    }

    #[test]
    fn a_tampered_id_token_fails_closed() {
        let authority = authority();
        let token = mint_id_token(&authority, request()).expect("mint");
        let mut parts: Vec<&str> = token.split('.').collect();
        let forged = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(
            serde_json::to_vec(&OidcIdTokenClaims {
                iss: "https://iam.example".into(),
                sub: "acct_evil".into(),
                aud: "product-web".into(),
                exp: 1_900_000_000,
                iat: 1_899_996_400,
                nonce: Some("nonce-1".into()),
            })
            .unwrap(),
        );
        parts[1] = &forged;
        let tampered = parts.join(".");
        assert_eq!(
            verify_id_token(&tampered, &authority.jwks()).unwrap_err(),
            AccessTokenError::SignatureInvalid
        );
    }
}
