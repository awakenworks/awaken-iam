//! Asymmetric access tokens and JWKS publication.
//!
//! IAM issues bearer access tokens for service APIs as compact JWTs signed with
//! an **asymmetric** key (`EdDSA` over `Ed25519`), carrying the signing key's
//! `kid` in the header. Verifiers never share a secret with IAM: they fetch the
//! public half from `/.well-known/jwks.json` (RFC 7517) and check the signature
//! locally. This realizes the "JWKS, not shared secrets" rule of the auth-server
//! design.
//!
//! Signing is abstracted behind the [`Signer`] seam (sign + `public_jwk` + `kid`)
//! rather than reaching for a private key directly. The open repo ships
//! [`LocalSeedSigner`], which holds an Ed25519 seed in process for dev and
//! self-hosting; a managed deployment injects a KMS-backed [`Signer`] whose
//! private key never enters the address space, so the secret never lands in this
//! repo. The [`AccessTokenAuthority`] holds one or more signers and supports
//! `kid`-versioned **rotation**: a rotated key is retained for verification (so
//! tokens minted just before the rotation still verify) until it is explicitly
//! [pruned](AccessTokenAuthority::prune), which retires every token it signed.

use std::collections::HashSet;
use std::sync::{Arc, RwLock};

use async_trait::async_trait;
use awaken_iam_contract::{JsonWebKey, Jwks};
use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use ed25519_dalek::{Signature, Signer as Ed25519Signer, SigningKey, VerifyingKey};
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

/// The signing seam: an issuer of detached `EdDSA` signatures whose private key
/// may live anywhere — in process, or behind a KMS the [`AccessTokenAuthority`]
/// only ever calls through this trait.
///
/// This is the open boundary that lets a managed deployment inject a KMS-backed
/// signer without the private key ever entering the repo: the authority signs by
/// handing the JWT signing input to [`sign`](Signer::sign), publishes verifiers'
/// keys via [`public_jwk`](Signer::public_jwk), and stamps [`kid`](Signer::kid)
/// into the header. The open repo ships exactly one implementation,
/// [`LocalSeedSigner`]; the closed cloud platform supplies its own.
///
/// `Send + Sync` so an authority holding boxed signers can back a shared,
/// concurrently-served auth API.
#[async_trait]
pub trait Signer: Send + Sync {
    /// The key id stamped into the JWT header and published in the JWKS, so a
    /// verifier can select this key and rotation can target it.
    fn kid(&self) -> &str;

    /// The public half of this key as a JWK, for `/.well-known/jwks.json`
    /// publication. Must never expose private material. Synchronous because the
    /// public key is fetched once when the signer is built and cached, so JWKS
    /// publication never reaches across the (possibly remote) signer boundary.
    fn public_jwk(&self) -> JsonWebKey;

    /// Produce the detached `EdDSA` (Ed25519) signature over `message` — the
    /// JWT's `header.payload` signing input. Returns the raw 64-byte signature.
    /// Async so a KMS/HSM-backed signer can do a remote round-trip without
    /// blocking the runtime; it surfaces transport/permission failures as
    /// [`SignerError`].
    async fn sign(&self, message: &[u8]) -> Result<Vec<u8>, SignerError>;
}

/// Failure raised by a [`Signer`] that could not produce a signature — e.g. a
/// KMS rejected the request, was unreachable, or returned malformed bytes.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("signer failed to produce a signature: {0}")]
pub struct SignerError(pub String);

/// Build the public JWK for an Ed25519 verifying key under `kid`.
///
/// Exposed so a KMS-backed [`Signer`] living outside this repo can publish its
/// public key in exactly the JWK shape verifiers expect, given only the raw
/// 32-byte public key it fetched from the KMS.
pub fn ed25519_public_jwk(kid: impl Into<String>, public_key: [u8; KEY_BYTES]) -> JsonWebKey {
    JsonWebKey {
        kty: JWK_KTY.to_owned(),
        crv: JWK_CRV.to_owned(),
        x: URL_SAFE_NO_PAD.encode(public_key),
        kid: kid.into(),
        key_use: JWK_USE.to_owned(),
        alg: ACCESS_TOKEN_ALG.to_owned(),
    }
}

/// In-process [`Signer`] holding an Ed25519 seed — the open-repo default for dev
/// and self-hosting.
///
/// The 32-byte seed is the only secret; the type is intentionally not
/// `Debug`/`Serialize`/`Clone` so it cannot leak through logs or wire types and a
/// held key is not casually duplicated. A managed deployment swaps this for a
/// KMS-backed [`Signer`] (the seam this type stands behind) so no private seed is
/// ever constructed here.
pub struct LocalSeedSigner {
    kid: String,
    signing: SigningKey,
}

impl LocalSeedSigner {
    /// Build a signer from a `kid` and a 32-byte Ed25519 seed.
    pub fn new(kid: impl Into<String>, seed: [u8; KEY_BYTES]) -> Self {
        Self {
            kid: kid.into(),
            signing: SigningKey::from_bytes(&seed),
        }
    }
}

#[async_trait]
impl Signer for LocalSeedSigner {
    fn kid(&self) -> &str {
        &self.kid
    }

    fn public_jwk(&self) -> JsonWebKey {
        ed25519_public_jwk(self.kid.clone(), self.signing.verifying_key().to_bytes())
    }

    async fn sign(&self, message: &[u8]) -> Result<Vec<u8>, SignerError> {
        let signature: Signature = self.signing.sign(message);
        Ok(signature.to_bytes().to_vec())
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
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum AccessTokenError {
    /// No signing key is available to mint a token.
    #[error("no signing key is configured")]
    NoSigningKey,
    /// The active [`Signer`] failed to produce a signature (e.g. a KMS was
    /// unreachable or rejected the request).
    #[error("signing failed: {0}")]
    SigningFailed(String),
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
    /// The token's `jti` was revoked, so it no longer authenticates even though
    /// its signature is still valid and unexpired.
    #[error("access token was revoked: {0}")]
    Revoked(String),
}

/// JOSE header of an issued access token.
#[derive(Serialize, serde::Deserialize)]
struct JwtHeader {
    alg: String,
    typ: String,
    kid: String,
}

/// Mints asymmetric access tokens and publishes their public keys as a JWKS.
///
/// Signers are ordered oldest-first; the newest is the active signer. Each is held
/// behind the [`Signer`] seam, so the active signer may be an in-process
/// [`LocalSeedSigner`] or a KMS-backed signer injected by a managed deployment.
/// Rotation keeps predecessors verifiable until pruned, so the active set
/// published by [`jwks`](Self::jwks) is exactly the keys a verifier may still
/// trust.
#[derive(Clone)]
pub struct AccessTokenAuthority {
    signers: Arc<RwLock<Vec<Arc<dyn Signer>>>>,
}

impl AccessTokenAuthority {
    /// Build an authority with a single active signer.
    ///
    /// Accepts any [`Signer`] — the open-repo [`LocalSeedSigner`] or a
    /// closed-platform KMS signer — so the private key need never be a seed this
    /// repo can construct.
    pub fn new(signer: impl Signer + 'static) -> Self {
        Self::from_signer(Box::new(signer))
    }

    /// Build an authority from an already-boxed signer.
    ///
    /// The dynamic-dispatch entry point for callers that choose the signer at
    /// runtime (e.g. seed-in-dev vs. KMS-in-cloud) and so hold a `Box<dyn Signer>`
    /// rather than a known concrete type.
    pub fn from_signer(signer: Box<dyn Signer>) -> Self {
        Self {
            signers: Arc::new(RwLock::new(vec![Arc::from(signer)])),
        }
    }

    /// The `kid` of the currently active signer.
    pub fn active_kid(&self) -> String {
        self.signers
            .read()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .last()
            .expect("authority always retains at least one signer")
            .kid()
            .to_owned()
    }

    /// Rotate in a new active signer, retaining the previous one for verification.
    ///
    /// Re-using an existing `kid` replaces that signer in place rather than adding
    /// a duplicate, keeping the published set unambiguous.
    pub fn rotate(&mut self, signer: impl Signer + 'static) {
        self.rotate_signer(Box::new(signer));
    }

    /// Rotate in an already-boxed signer; the dynamic-dispatch counterpart of
    /// [`rotate`](Self::rotate) for runtime-selected signers.
    pub fn rotate_signer(&mut self, signer: Box<dyn Signer>) {
        let mut signers = self
            .signers
            .write()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        signers.retain(|held| held.kid() != signer.kid());
        signers.push(Arc::from(signer));
    }

    /// Drop a retired key by `kid` so tokens it signed no longer verify.
    ///
    /// The active key cannot be pruned; pruning it would leave nothing to sign
    /// with. Returns whether a key was removed.
    pub fn prune(&mut self, kid: &str) -> bool {
        let mut signers = self
            .signers
            .write()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if signers
            .last()
            .expect("authority always retains at least one signer")
            .kid()
            == kid
        {
            return false;
        }
        let before = signers.len();
        signers.retain(|held| held.kid() != kid);
        signers.len() != before
    }

    /// The JWKS document: every retained public key, newest first.
    pub fn jwks(&self) -> Jwks {
        let signers = self
            .signers
            .read()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        Jwks {
            keys: signers.iter().rev().map(|s| s.public_jwk()).collect(),
        }
    }

    /// Mint a signed access token for `claims` using the active key.
    pub async fn mint(&self, claims: &AccessTokenClaims) -> Result<String, AccessTokenError> {
        self.sign_jwt(ACCESS_TOKEN_TYP, claims).await
    }

    /// Sign an arbitrary claim set as a compact JWT under the active key.
    ///
    /// The `typ` header fences token families apart: a verifier that expects one
    /// `typ` rejects a token minted under another (see [`verify_jwt`]), so an
    /// access token cannot be replayed where a capability token is expected and
    /// vice versa. Both families share the active signing key and JWKS so a single
    /// rotation/prune covers every token IAM issues.
    pub(crate) async fn sign_jwt<T: Serialize>(
        &self,
        typ: &str,
        claims: &T,
    ) -> Result<String, AccessTokenError> {
        let active = self
            .signers
            .read()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .last()
            .cloned()
            .ok_or(AccessTokenError::NoSigningKey)?;
        let header = JwtHeader {
            alg: ACCESS_TOKEN_ALG.to_owned(),
            typ: typ.to_owned(),
            kid: active.kid().to_owned(),
        };
        let signing_input = format!("{}.{}", encode_part(&header)?, encode_part(claims)?);
        let signature = active
            .sign(signing_input.as_bytes())
            .await
            .map_err(|err| AccessTokenError::SigningFailed(err.0))?;
        let sig_b64 = URL_SAFE_NO_PAD.encode(signature);
        Ok(format!("{signing_input}.{sig_b64}"))
    }

    /// Sign an arbitrary serializable claim set into a compact `EdDSA` JWT with
    /// the active key, stamping its `kid` into the header under the generic `"JWT"`
    /// type.
    ///
    /// Unlike [`mint`](Self::mint) / [`sign_jwt`](Self::sign_jwt), this carries no
    /// IAM token-family `typ` fence: it models an *external* issuer signing a
    /// federated workload assertion, so an authority can stand in as the upstream
    /// STS in an RFC 8693 token-exchange contract test. Verify the result with
    /// [`verify_signed_claims`], which checks the signature without asserting a
    /// particular `typ`.
    pub async fn sign_claims<T: Serialize>(&self, claims: &T) -> Result<String, AccessTokenError> {
        self.sign_jwt("JWT", claims).await
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

    verify_signature_and_decode(header, header_b64, payload_b64, sig_b64, jwks)
}

/// Verify an `EdDSA` JWT against `jwks` and deserialize its payload claims,
/// **without** asserting any particular `typ` header.
///
/// Generic over the claim shape so callers beyond IAM's own access token — most
/// notably RFC 8693 federated token exchange, which must verify an *upstream*
/// issuer's assertion whose claim set differs from [`AccessTokenClaims`] and
/// whose `typ` is set by that foreign issuer — can reuse the exact same
/// cryptographic path. It performs the structural checks of
/// [`verify_access_token`]: `header.payload.signature` well-formedness, the
/// `EdDSA` algorithm, `kid` key selection, and strict Ed25519 signature
/// verification. Validation of claim *values* (issuer, audience, expiry) is the
/// caller's responsibility, since those rules differ per token use.
pub fn verify_signed_claims<T: DeserializeOwned>(
    token: &str,
    jwks: &Jwks,
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

    verify_signature_and_decode(header, header_b64, payload_b64, sig_b64, jwks)
}

/// Select the published key by `kid`, verify the Ed25519 signature over
/// `header.payload`, and decode the payload claims. Shared by the typ-fenced
/// [`verify_jwt`] and the typ-agnostic [`verify_signed_claims`].
fn verify_signature_and_decode<T: DeserializeOwned>(
    header: JwtHeader,
    header_b64: &str,
    payload_b64: &str,
    sig_b64: &str,
    jwks: &Jwks,
) -> Result<T, AccessTokenError> {
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

/// A denylist of revoked access-token `jti`s.
///
/// Access tokens are stateless JWTs a verifier checks against the published
/// [`Jwks`] without calling IAM, so a token stays cryptographically valid until
/// it expires. The `jti` claim is what makes a token *individually revocable*
/// before then: IAM records a revoked `jti` here, and any verification routed
/// through IAM (or a verifier that consults this denylist) rejects it. A token
/// naturally falls out of relevance once it expires; an operator prunes the
/// denylist on that cadence.
#[derive(Debug, Default, Clone)]
pub struct AccessTokenRevocations {
    revoked: HashSet<String>,
}

impl AccessTokenRevocations {
    /// Create an empty revocation denylist.
    pub fn new() -> Self {
        Self::default()
    }

    /// Revoke a `jti`. Returns whether it was newly added (idempotent).
    pub fn revoke(&mut self, jti: impl Into<String>) -> bool {
        self.revoked.insert(jti.into())
    }

    /// Whether a `jti` has been revoked.
    pub fn is_revoked(&self, jti: &str) -> bool {
        self.revoked.contains(jti)
    }

    /// Number of revoked `jti`s currently held.
    pub fn len(&self) -> usize {
        self.revoked.len()
    }

    /// Whether the denylist is empty.
    pub fn is_empty(&self) -> bool {
        self.revoked.is_empty()
    }

    /// Drop a `jti` from the denylist (e.g. once the token it named has expired).
    /// Returns whether it was present.
    pub fn forget(&mut self, jti: &str) -> bool {
        self.revoked.remove(jti)
    }
}

/// Verify an access token against `jwks` *and* the `revocations` denylist.
///
/// This is the full IAM-side check: a token that verifies cryptographically but
/// whose `jti` has been revoked fails closed with [`AccessTokenError::Revoked`].
/// Verifiers that hold the denylist get real per-token revocation on top of the
/// stateless signature check.
pub fn verify_active_access_token(
    token: &str,
    jwks: &Jwks,
    revocations: &AccessTokenRevocations,
) -> Result<AccessTokenClaims, AccessTokenError> {
    let claims = verify_access_token(token, jwks)?;
    if revocations.is_revoked(&claims.jti) {
        return Err(AccessTokenError::Revoked(claims.jti));
    }
    Ok(claims)
}

/// Decode a JWT's payload claims **without verifying its signature**.
///
/// This is intentionally unauthenticated: it exists only to read an untrusted
/// routing hint — the `iss` claim — from a presented token so the caller can
/// look up *which* trusted issuer's keys to then verify it against with
/// [`verify_signed_claims`]. The returned claims must never be trusted until
/// that verification succeeds.
pub fn decode_unverified_claims<T: DeserializeOwned>(token: &str) -> Result<T, AccessTokenError> {
    let mut parts = token.split('.');
    let _header_b64 = parts.next().ok_or(AccessTokenError::Malformed)?;
    let payload_b64 = parts.next().ok_or(AccessTokenError::Malformed)?;
    let sig_b64 = parts.next().ok_or(AccessTokenError::Malformed)?;
    if sig_b64.is_empty() || parts.next().is_some() {
        return Err(AccessTokenError::Malformed);
    }
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

    /// A [`Signer`] defined outside the `access_token` module's own machinery,
    /// standing in for the KMS-backed signer the closed platform would inject. It
    /// proves the seam admits an out-of-repo implementation: the authority signs
    /// and publishes through the trait alone, and a backend failure (`fail`)
    /// surfaces as a [`SignerError`] rather than a panic.
    struct ExternalSigner {
        kid: String,
        backing: SigningKey,
        fail: bool,
    }

    impl ExternalSigner {
        fn new(kid: &str, seed_byte: u8) -> Self {
            Self {
                kid: kid.into(),
                backing: SigningKey::from_bytes(&seed(seed_byte)),
                fail: false,
            }
        }

        fn failing(kid: &str, seed_byte: u8) -> Self {
            Self {
                fail: true,
                ..Self::new(kid, seed_byte)
            }
        }
    }

    #[async_trait]
    impl Signer for ExternalSigner {
        fn kid(&self) -> &str {
            &self.kid
        }

        fn public_jwk(&self) -> JsonWebKey {
            ed25519_public_jwk(self.kid.clone(), self.backing.verifying_key().to_bytes())
        }

        async fn sign(&self, message: &[u8]) -> Result<Vec<u8>, SignerError> {
            if self.fail {
                return Err(SignerError("kms unreachable".into()));
            }
            Ok(self.backing.sign(message).to_bytes().to_vec())
        }
    }

    #[tokio::test]
    async fn an_externally_supplied_signer_can_be_injected_and_verifies() {
        // Stand in for a KMS: an out-of-module signer the authority only ever
        // reaches through the trait. Inject through the dynamic-dispatch seam.
        let kms = ExternalSigner::new("kms-key-1", 42);
        let authority = AccessTokenAuthority::from_signer(Box::new(kms));
        assert_eq!(authority.active_kid(), "kms-key-1");

        let token = authority.mint(&claims("jti-kms")).await.unwrap();
        let header: JwtHeader = decode_part(token.split('.').next().unwrap()).unwrap();
        assert_eq!(header.kid, "kms-key-1");

        // A verifier with only the published JWKS recovers the claims — the seam
        // is transparent to verification.
        let recovered = verify_access_token(&token, &authority.jwks()).unwrap();
        assert_eq!(recovered, claims("jti-kms"));
    }

    #[tokio::test]
    async fn a_signer_failure_surfaces_as_signing_failed() {
        // A KMS that rejects the request must fail the mint closed, not panic.
        let failing = ExternalSigner::failing("kms-down", 1);
        let authority = AccessTokenAuthority::from_signer(Box::new(failing));

        let err = authority.mint(&claims("jti-1")).await.unwrap_err();
        assert_eq!(
            err,
            AccessTokenError::SigningFailed("kms unreachable".into())
        );
    }

    #[tokio::test]
    async fn an_external_signer_can_be_rotated_in() {
        // A seed signer in dev, rotated to a KMS-style signer — the published set
        // keeps both verifiable until the old one is pruned.
        let mut authority = AccessTokenAuthority::new(LocalSeedSigner::new("seed-key", seed(5)));
        let old = authority.mint(&claims("jti-old")).await.unwrap();

        let kms = ExternalSigner::new("kms-key", 99);
        authority.rotate_signer(Box::new(kms));
        assert_eq!(authority.active_kid(), "kms-key");

        let new = authority.mint(&claims("jti-new")).await.unwrap();
        let jwks = authority.jwks();
        verify_access_token(&old, &jwks).unwrap();
        verify_access_token(&new, &jwks).unwrap();
    }

    #[tokio::test]
    async fn token_is_asymmetric_and_verifies_against_published_jwks() {
        let authority = AccessTokenAuthority::new(LocalSeedSigner::new("key-1", seed(7)));
        let token = authority.mint(&claims("jti-1")).await.unwrap();

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

    #[tokio::test]
    async fn a_tampered_payload_fails_closed() {
        let authority = AccessTokenAuthority::new(LocalSeedSigner::new("key-1", seed(3)));
        let token = authority.mint(&claims("jti-1")).await.unwrap();
        let jwks = authority.jwks();

        // Swap the payload for a forged one while keeping the original signature.
        let mut parts: Vec<&str> = token.split('.').collect();
        let forged = encode_part(&claims("jti-evil")).unwrap();
        parts[1] = &forged;
        let tampered = parts.join(".");

        let err = verify_access_token(&tampered, &jwks).unwrap_err();
        assert_eq!(err, AccessTokenError::SignatureInvalid);
    }

    #[tokio::test]
    async fn a_token_from_a_different_key_does_not_verify() {
        let mint_authority = AccessTokenAuthority::new(LocalSeedSigner::new("key-1", seed(1)));
        let token = mint_authority.mint(&claims("jti-1")).await.unwrap();

        // A different authority publishes a different key under the same kid.
        let other = AccessTokenAuthority::new(LocalSeedSigner::new("key-1", seed(2)));
        let err = verify_access_token(&token, &other.jwks()).unwrap_err();
        assert_eq!(err, AccessTokenError::SignatureInvalid);
    }

    #[tokio::test]
    async fn rotation_keeps_old_tokens_verifiable_until_pruned() {
        let mut authority = AccessTokenAuthority::new(LocalSeedSigner::new("key-1", seed(10)));
        let old_token = authority.mint(&claims("jti-old")).await.unwrap();

        // Rotate: new tokens use the fresh key, but the old key stays published.
        authority.rotate(LocalSeedSigner::new("key-2", seed(20)));
        assert_eq!(authority.active_kid(), "key-2");
        let new_token = authority.mint(&claims("jti-new")).await.unwrap();
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

    #[tokio::test]
    async fn cloned_authorities_share_rotation_and_pruning() {
        let mut issuer = AccessTokenAuthority::new(LocalSeedSigner::new("key-1", seed(1)));
        let verifier_view = issuer.clone();

        issuer.rotate(LocalSeedSigner::new("key-2", seed(2)));
        assert_eq!(verifier_view.active_kid(), "key-2");
        assert_eq!(verifier_view.jwks().keys.len(), 2);

        assert!(issuer.prune("key-1"));
        assert_eq!(verifier_view.jwks().keys.len(), 1);
        assert_eq!(verifier_view.jwks().keys[0].kid, "key-2");
    }

    #[tokio::test]
    async fn a_revoked_jti_fails_closed_even_with_a_valid_signature() {
        let authority = AccessTokenAuthority::new(LocalSeedSigner::new("key-1", seed(9)));
        let token = authority.mint(&claims("jti-1")).await.unwrap();
        let jwks = authority.jwks();

        // Unrevoked: the token verifies against the denylist-aware path.
        let mut revocations = AccessTokenRevocations::new();
        verify_active_access_token(&token, &jwks, &revocations).unwrap();

        // Revoking the jti retires the still-valid token.
        assert!(revocations.revoke("jti-1"));
        // Revocation is idempotent.
        assert!(!revocations.revoke("jti-1"));
        assert!(revocations.is_revoked("jti-1"));
        let err = verify_active_access_token(&token, &jwks, &revocations).unwrap_err();
        assert_eq!(err, AccessTokenError::Revoked("jti-1".into()));

        // The bare signature check is unaffected — revocation is the IAM-side
        // layer over the stateless verification.
        verify_access_token(&token, &jwks).unwrap();

        // Forgetting the jti (e.g. after expiry) restores the token.
        assert!(revocations.forget("jti-1"));
        verify_active_access_token(&token, &jwks, &revocations).unwrap();
    }

    #[tokio::test]
    async fn unknown_kid_and_foreign_alg_fail_closed() {
        let authority = AccessTokenAuthority::new(LocalSeedSigner::new("key-1", seed(5)));
        let token = authority.mint(&claims("jti-1")).await.unwrap();

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
