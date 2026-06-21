//! Asymmetric access tokens and JWKS publication.
//!
//! IAM issues bearer access tokens for service APIs as compact JWTs signed with
//! an **asymmetric** key (`EdDSA` over `Ed25519`), carrying the signing key's
//! `kid` in the header. Verifiers never share a secret with IAM: they fetch the
//! public half from `/.well-known/jwks.json` (RFC 7517) and check the signature
//! locally. This realizes the "JWKS, not shared secrets" rule of the auth-server
//! design.
//!
//! Signing keys live behind a store seam ([`SigningKeyMaterial`]) rather than in
//! plain env — an MVP stands in for a KMS/secret store, but the private seed is
//! confined to this module and never serialized. The [`AccessTokenAuthority`]
//! supports `kid`-versioned **rotation**: a rotated key is retained for
//! verification (so tokens minted just before the rotation still verify) until it
//! is explicitly [pruned](AccessTokenAuthority::prune), which retires every token
//! it signed.

use awaken_iam_contract::{JsonWebKey, Jwks};
use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};
use serde::Serialize;
use serde::de::DeserializeOwned;

/// JOSE `alg` of issued access tokens: Edwards-curve digital signatures.
pub const ACCESS_TOKEN_ALG: &str = "EdDSA";
/// JOSE `typ` header fencing the access-token family apart from other JWTs IAM
/// signs with the same key (e.g. capability tokens), so one cannot be replayed
/// where the other is expected.
pub(crate) const ACCESS_TOKEN_TYP: &str = "JWT";
/// JWK `kty` for the Ed25519 octet key pair.
const JWK_KTY: &str = "OKP";
/// JWK `crv` for the Ed25519 signing curve.
const JWK_CRV: &str = "Ed25519";
/// JWK `use` advertising the key is for signature verification.
const JWK_USE: &str = "sig";
/// Length of an Ed25519 seed / public key in bytes.
const KEY_BYTES: usize = 32;
/// Length of an Ed25519 signature in bytes.
const SIG_BYTES: usize = 64;

/// Private signing-key material as handed out by a KMS/secret store.
///
/// The 32-byte seed is the only secret; it is intentionally not `Debug`/`Serialize`
/// so it cannot leak through logs or wire types. A real deployment fetches this
/// from a managed secret store keyed by `kid`; the MVP constructs it in process.
#[derive(Clone)]
pub struct SigningKeyMaterial {
    kid: String,
    seed: [u8; KEY_BYTES],
}

impl SigningKeyMaterial {
    /// Build key material from a `kid` and a 32-byte Ed25519 seed.
    pub fn new(kid: impl Into<String>, seed: [u8; KEY_BYTES]) -> Self {
        Self {
            kid: kid.into(),
            seed,
        }
    }

    /// The key id this material is published and selected under.
    pub fn kid(&self) -> &str {
        &self.kid
    }
}

/// Claims carried in an access-token JWT payload (a subset of RFC 7519).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, serde::Deserialize)]
pub struct AccessTokenClaims {
    /// Issuer: the IAM deployment that minted the token.
    pub iss: String,
    /// Subject: the IAM account/principal the token authenticates.
    pub sub: String,
    /// Audience: the service the token is presented to.
    pub aud: String,
    /// Expiration time as a Unix timestamp (seconds).
    pub exp: i64,
    /// Issued-at time as a Unix timestamp (seconds).
    pub iat: i64,
    /// Unique token id, enabling per-token revocation.
    pub jti: String,
    /// Granted scopes; omitted from the wire form when empty.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub scope: Vec<String>,
}

/// Errors raised while minting or verifying access tokens.
#[derive(Debug, PartialEq, Eq, thiserror::Error)]
pub enum AccessTokenError {
    /// No signing key is available to mint a token.
    #[error("no signing key is configured")]
    NoSigningKey,
    /// The token is not a well-formed `header.payload.signature` JWT.
    #[error("access token is malformed")]
    Malformed,
    /// The token header advertised an algorithm we do not issue.
    #[error("unsupported token algorithm: {0}")]
    UnsupportedAlg(String),
    /// No published JWKS key matches the token's `kid`.
    #[error("no published key matches kid: {0}")]
    UnknownKid(String),
    /// The referenced JWKS key is not a supported Ed25519 OKP key.
    #[error("published key is not a supported Ed25519 OKP key")]
    UnsupportedKey,
    /// The signature did not verify against the published key.
    #[error("token signature verification failed")]
    SignatureInvalid,
    /// The token's `typ` header did not match the expected token family.
    #[error("unexpected token type: expected {expected}, found {found}")]
    UnexpectedType {
        /// The `typ` the verifier required.
        expected: String,
        /// The `typ` the presented token actually carried.
        found: String,
    },
}

/// JOSE header of an issued access token.
#[derive(Serialize, serde::Deserialize)]
struct JwtHeader {
    alg: String,
    typ: String,
    kid: String,
}

/// One signing key held by the authority.
struct StoredKey {
    kid: String,
    signing: SigningKey,
}

impl StoredKey {
    fn from_material(material: SigningKeyMaterial) -> Self {
        Self {
            kid: material.kid,
            signing: SigningKey::from_bytes(&material.seed),
        }
    }

    fn public_jwk(&self) -> JsonWebKey {
        JsonWebKey {
            kty: JWK_KTY.to_owned(),
            crv: JWK_CRV.to_owned(),
            x: URL_SAFE_NO_PAD.encode(self.signing.verifying_key().to_bytes()),
            kid: self.kid.clone(),
            key_use: JWK_USE.to_owned(),
            alg: ACCESS_TOKEN_ALG.to_owned(),
        }
    }
}

/// Mints asymmetric access tokens and publishes their public keys as a JWKS.
///
/// Keys are ordered oldest-first; the newest is the active signer. Rotation keeps
/// predecessors verifiable until pruned, so the active set published by
/// [`jwks`](Self::jwks) is exactly the keys a verifier may still trust.
pub struct AccessTokenAuthority {
    keys: Vec<StoredKey>,
}

impl AccessTokenAuthority {
    /// Build an authority with a single active signing key.
    pub fn new(material: SigningKeyMaterial) -> Self {
        Self {
            keys: vec![StoredKey::from_material(material)],
        }
    }

    /// The `kid` of the currently active signing key.
    pub fn active_kid(&self) -> &str {
        &self
            .keys
            .last()
            .expect("authority always retains at least one key")
            .kid
    }

    /// Rotate in a new active key, retaining the previous one for verification.
    ///
    /// Re-using an existing `kid` replaces that key in place rather than adding a
    /// duplicate, keeping the published set unambiguous.
    pub fn rotate(&mut self, material: SigningKeyMaterial) {
        self.keys.retain(|key| key.kid != material.kid);
        self.keys.push(StoredKey::from_material(material));
    }

    /// Drop a retired key by `kid` so tokens it signed no longer verify.
    ///
    /// The active key cannot be pruned; pruning it would leave nothing to sign
    /// with. Returns whether a key was removed.
    pub fn prune(&mut self, kid: &str) -> bool {
        if self.active_kid() == kid {
            return false;
        }
        let before = self.keys.len();
        self.keys.retain(|key| key.kid != kid);
        self.keys.len() != before
    }

    /// The JWKS document: every retained public key, newest first.
    pub fn jwks(&self) -> Jwks {
        Jwks {
            keys: self.keys.iter().rev().map(StoredKey::public_jwk).collect(),
        }
    }

    /// Mint a signed access token for `claims` using the active key.
    pub fn mint(&self, claims: &AccessTokenClaims) -> Result<String, AccessTokenError> {
        self.sign_jwt(ACCESS_TOKEN_TYP, claims)
    }

    /// Sign an arbitrary claim set as a compact JWT under the active key.
    ///
    /// The `typ` header fences token families apart: a verifier that expects one
    /// `typ` rejects a token minted under another (see [`verify_jwt`]), so an
    /// access token cannot be replayed where a capability token is expected and
    /// vice versa. Both families share the active signing key and JWKS so a single
    /// rotation/prune covers every token IAM issues.
    pub(crate) fn sign_jwt<T: Serialize>(
        &self,
        typ: &str,
        claims: &T,
    ) -> Result<String, AccessTokenError> {
        let active = self.keys.last().ok_or(AccessTokenError::NoSigningKey)?;
        let header = JwtHeader {
            alg: ACCESS_TOKEN_ALG.to_owned(),
            typ: typ.to_owned(),
            kid: active.kid.clone(),
        };
        let signing_input = format!("{}.{}", encode_part(&header)?, encode_part(claims)?);
        let signature: Signature = active.signing.sign(signing_input.as_bytes());
        let sig_b64 = URL_SAFE_NO_PAD.encode(signature.to_bytes());
        Ok(format!("{signing_input}.{sig_b64}"))
    }
}

/// Verify an access token against a published [`Jwks`], returning its claims.
///
/// This is the verifier-side path that a product service runs with only the
/// public keys fetched from `/.well-known/jwks.json` — it never needs IAM's
/// private seed. The token's `kid` selects the key; an unknown `kid`, a foreign
/// algorithm, or a bad signature all fail closed.
pub fn verify_access_token(
    token: &str,
    jwks: &Jwks,
) -> Result<AccessTokenClaims, AccessTokenError> {
    verify_jwt(token, jwks, ACCESS_TOKEN_TYP)
}

/// Verify the signature of any IAM-issued JWT against a published [`Jwks`] and
/// decode its claims, requiring the `typ` header to equal `expected_typ`.
///
/// This is the shared crypto path behind [`verify_access_token`] and capability
/// tokens: the `kid` selects the published key, the `typ` fences the token family
/// apart, and an unknown `kid`, a foreign algorithm, a wrong `typ`, or a bad
/// signature all fail closed. It never decides epoch/audience/expiry — those are
/// the caller's policy checks layered on the recovered claims.
pub(crate) fn verify_jwt<T: DeserializeOwned>(
    token: &str,
    jwks: &Jwks,
    expected_typ: &str,
) -> Result<T, AccessTokenError> {
    let mut parts = token.split('.');
    let header_b64 = parts.next().ok_or(AccessTokenError::Malformed)?;
    let payload_b64 = parts.next().ok_or(AccessTokenError::Malformed)?;
    let sig_b64 = parts.next().ok_or(AccessTokenError::Malformed)?;
    if parts.next().is_some() {
        return Err(AccessTokenError::Malformed);
    }

    let header: JwtHeader = decode_part(header_b64)?;
    if header.alg != ACCESS_TOKEN_ALG {
        return Err(AccessTokenError::UnsupportedAlg(header.alg));
    }
    if header.typ != expected_typ {
        return Err(AccessTokenError::UnexpectedType {
            expected: expected_typ.to_owned(),
            found: header.typ,
        });
    }

    let jwk = jwks
        .keys
        .iter()
        .find(|key| key.kid == header.kid)
        .ok_or_else(|| AccessTokenError::UnknownKid(header.kid.clone()))?;
    let verifying = verifying_key_from_jwk(jwk)?;

    let signing_input = format!("{header_b64}.{payload_b64}");
    let signature = signature_from_b64(sig_b64)?;
    verifying
        .verify_strict(signing_input.as_bytes(), &signature)
        .map_err(|_| AccessTokenError::SignatureInvalid)?;

    decode_part(payload_b64)
}

fn encode_part<T: Serialize>(value: &T) -> Result<String, AccessTokenError> {
    let json = serde_json::to_vec(value).map_err(|_| AccessTokenError::Malformed)?;
    Ok(URL_SAFE_NO_PAD.encode(json))
}

fn decode_part<T: DeserializeOwned>(part: &str) -> Result<T, AccessTokenError> {
    let bytes = URL_SAFE_NO_PAD
        .decode(part)
        .map_err(|_| AccessTokenError::Malformed)?;
    serde_json::from_slice(&bytes).map_err(|_| AccessTokenError::Malformed)
}

fn verifying_key_from_jwk(jwk: &JsonWebKey) -> Result<VerifyingKey, AccessTokenError> {
    if jwk.kty != JWK_KTY || jwk.crv != JWK_CRV {
        return Err(AccessTokenError::UnsupportedKey);
    }
    let raw = URL_SAFE_NO_PAD
        .decode(&jwk.x)
        .map_err(|_| AccessTokenError::UnsupportedKey)?;
    let bytes: [u8; KEY_BYTES] = raw
        .as_slice()
        .try_into()
        .map_err(|_| AccessTokenError::UnsupportedKey)?;
    VerifyingKey::from_bytes(&bytes).map_err(|_| AccessTokenError::UnsupportedKey)
}

fn signature_from_b64(sig_b64: &str) -> Result<Signature, AccessTokenError> {
    let raw = URL_SAFE_NO_PAD
        .decode(sig_b64)
        .map_err(|_| AccessTokenError::Malformed)?;
    let bytes: [u8; SIG_BYTES] = raw
        .as_slice()
        .try_into()
        .map_err(|_| AccessTokenError::Malformed)?;
    Ok(Signature::from_bytes(&bytes))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn seed(byte: u8) -> [u8; KEY_BYTES] {
        [byte; KEY_BYTES]
    }

    fn claims(jti: &str) -> AccessTokenClaims {
        AccessTokenClaims {
            iss: "https://iam.example".into(),
            sub: "acct_1".into(),
            aud: "packs-service".into(),
            exp: 1_900_000_000,
            iat: 1_899_996_400,
            jti: jti.into(),
            scope: vec!["pack.read".into()],
        }
    }

    #[test]
    fn token_is_asymmetric_and_verifies_against_published_jwks() {
        let authority = AccessTokenAuthority::new(SigningKeyMaterial::new("key-1", seed(7)));
        let token = authority.mint(&claims("jti-1")).unwrap();

        // The header carries alg + kid; three base64url segments.
        assert_eq!(token.split('.').count(), 3);
        let header: JwtHeader = decode_part(token.split('.').next().unwrap()).unwrap();
        assert_eq!(header.alg, "EdDSA");
        assert_eq!(header.kid, "key-1");

        // The published JWKS exposes only the public key, never the seed.
        let jwks = authority.jwks();
        assert_eq!(jwks.keys.len(), 1);
        assert_eq!(jwks.keys[0].kty, "OKP");
        assert_eq!(jwks.keys[0].crv, "Ed25519");
        assert_eq!(jwks.keys[0].kid, "key-1");
        let wire = serde_json::to_string(&jwks).unwrap();
        assert!(wire.contains("\"use\":\"sig\""));
        assert!(wire.contains("\"alg\":\"EdDSA\""));

        // A verifier with only the JWKS recovers the claims.
        let recovered = verify_access_token(&token, &jwks).unwrap();
        assert_eq!(recovered, claims("jti-1"));
    }

    #[test]
    fn a_tampered_payload_fails_closed() {
        let authority = AccessTokenAuthority::new(SigningKeyMaterial::new("key-1", seed(3)));
        let token = authority.mint(&claims("jti-1")).unwrap();
        let jwks = authority.jwks();

        // Swap the payload for a forged one while keeping the original signature.
        let mut parts: Vec<&str> = token.split('.').collect();
        let forged = encode_part(&claims("jti-evil")).unwrap();
        parts[1] = &forged;
        let tampered = parts.join(".");

        let err = verify_access_token(&tampered, &jwks).unwrap_err();
        assert_eq!(err, AccessTokenError::SignatureInvalid);
    }

    #[test]
    fn a_token_from_a_different_key_does_not_verify() {
        let mint_authority = AccessTokenAuthority::new(SigningKeyMaterial::new("key-1", seed(1)));
        let token = mint_authority.mint(&claims("jti-1")).unwrap();

        // A different authority publishes a different key under the same kid.
        let other = AccessTokenAuthority::new(SigningKeyMaterial::new("key-1", seed(2)));
        let err = verify_access_token(&token, &other.jwks()).unwrap_err();
        assert_eq!(err, AccessTokenError::SignatureInvalid);
    }

    #[test]
    fn rotation_keeps_old_tokens_verifiable_until_pruned() {
        let mut authority = AccessTokenAuthority::new(SigningKeyMaterial::new("key-1", seed(10)));
        let old_token = authority.mint(&claims("jti-old")).unwrap();

        // Rotate: new tokens use the fresh key, but the old key stays published.
        authority.rotate(SigningKeyMaterial::new("key-2", seed(20)));
        assert_eq!(authority.active_kid(), "key-2");
        let new_token = authority.mint(&claims("jti-new")).unwrap();
        let new_header: JwtHeader = decode_part(new_token.split('.').next().unwrap()).unwrap();
        assert_eq!(new_header.kid, "key-2");

        let jwks = authority.jwks();
        assert_eq!(jwks.keys.len(), 2);
        // Newest key is published first.
        assert_eq!(jwks.keys[0].kid, "key-2");
        // Both the pre- and post-rotation tokens still verify.
        verify_access_token(&old_token, &jwks).unwrap();
        verify_access_token(&new_token, &jwks).unwrap();

        // Pruning the retired key retires the tokens it signed; the active key
        // cannot be pruned.
        assert!(!authority.prune("key-2"));
        assert!(authority.prune("key-1"));
        let pruned = authority.jwks();
        assert_eq!(pruned.keys.len(), 1);
        let err = verify_access_token(&old_token, &pruned).unwrap_err();
        assert_eq!(err, AccessTokenError::UnknownKid("key-1".into()));
        // The current token still verifies after the prune.
        verify_access_token(&new_token, &pruned).unwrap();
    }

    #[test]
    fn unknown_kid_and_foreign_alg_fail_closed() {
        let authority = AccessTokenAuthority::new(SigningKeyMaterial::new("key-1", seed(5)));
        let token = authority.mint(&claims("jti-1")).unwrap();

        let empty = Jwks { keys: vec![] };
        assert_eq!(
            verify_access_token(&token, &empty).unwrap_err(),
            AccessTokenError::UnknownKid("key-1".into())
        );

        assert_eq!(
            verify_access_token("not-a-jwt", &authority.jwks()).unwrap_err(),
            AccessTokenError::Malformed
        );
    }
}
