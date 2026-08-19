//! License-claim wire shape and its offline verification primitive.
//!
//! A [`LicenseClaim`] is the open, signed entitlement document a licensed
//! deployment presents to unlock paid features and numeric ceilings. Two halves
//! of the licensing story are deliberately split:
//!
//! - **Closed** — minting and signing a claim (the issuer's private signing
//!   store, plan catalog, and billing) live in the commercial platform
//!   (`awaken-cloud`) and never appear here.
//! - **Open** — the claim *shape* and its *offline verification* against a pinned
//!   [`Jwks`] live here, so any self-hosted build can check a license without
//!   calling home. A build with no license is fully functional and unlicensed.
//!
//! Verification is offline by construction: it takes the pinned public keys and a
//! caller-supplied notion of "now" and an epoch floor, and never performs I/O.

use std::collections::BTreeMap;

use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use ed25519_dalek::{Signature, VerifyingKey};
use serde::{Deserialize, Serialize};

use crate::Timestamp;
use crate::identity::{JsonWebKey, Jwks};

/// Curve / algorithm constants the verifier accepts.
const LICENSE_KTY: &str = "OKP";
const LICENSE_CRV: &str = "Ed25519";
const LICENSE_ALG: &str = "EdDSA";
const LICENSE_USE: &str = "sig";

/// Current wire/signature schema accepted by the offline verifier.
pub const LICENSE_CLAIM_SCHEMA_VERSION: u16 = 2;

/// A detached signature binding a [`LicenseClaim`] to the key that minted it.
///
/// The issuer is closed; the open repo only ever *checks* this value. `kid`
/// selects which key in the pinned [`Jwks`] signed the claim so the issuer can
/// rotate signing keys while previously issued licenses still verify.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LicenseSignature {
    /// Key id, matching the `kid` of the [`JsonWebKey`] that signed the claim.
    pub kid: String,
    /// Base64url (no padding) of the 64-byte Ed25519 signature over
    /// [`LicenseClaim::signing_input`].
    pub value: String,
}

/// An open, signed license claim.
///
/// The claim is intentionally permissive in what it can carry: `features` and
/// `limits` are free-form keys a product names, so new entitlements ship without
/// an IAM schema break. Absence is the unlicensed default — a deployment with no
/// claim simply has no extra features and no ceilings.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LicenseClaim {
    /// Wire/signature schema. Version 2 binds the claim to one customer and
    /// deployment so a valid license cannot be copied to another installation.
    pub schema_version: u16,
    /// Stable issuer-selected identifier used for audit and support.
    pub license_id: String,
    /// Customer or Organization that purchased the entitlement.
    pub customer_id: String,
    /// Exact installation that may consume the entitlement.
    pub deployment_id: String,
    /// Immutable commercial catalog release used to derive this claim.
    pub catalog_release: String,
    /// Subscription ledger version projected into this claim.
    pub billing_version: u64,
    /// Feature / SKU keys this license entitles (for example `pack.publish`,
    /// `model.strong_access`). Order is preserved as issued and is part of the
    /// signed payload.
    pub features: Vec<String>,
    /// Optional inclusive numeric ceilings keyed by feature. A present entry is a
    /// finite ceiling (`Limited`); a feature with no entry is unlimited. Keys are
    /// ordered by the map so the signed payload is deterministic.
    #[serde(default)]
    pub limits: BTreeMap<String, u64>,
    /// When the license was issued (RFC 3339, UTC).
    pub issued_at: Timestamp,
    /// Instant at or after which the license is no longer honored (RFC 3339,
    /// UTC). Verification past this instant is [`LicenseVerifyError::Expired`].
    pub not_after: Timestamp,
    /// Monotonic issuing epoch. A verifier pins a floor and rejects any claim
    /// minted under an older epoch, so rotating the floor fences stale licenses
    /// out without revocation lists.
    pub epoch: u64,
    /// Detached signature produced by the closed issuer.
    pub sig: LicenseSignature,
}

/// The signed payload of a [`LicenseClaim`] — every field except the signature.
///
/// Serialized in declaration order with `limits` ordered by its [`BTreeMap`], so
/// the issuer and the verifier agree on the canonical bytes byte-for-byte.
#[derive(Debug, Serialize)]
struct LicensePayload<'a> {
    schema_version: u16,
    license_id: &'a str,
    customer_id: &'a str,
    deployment_id: &'a str,
    catalog_release: &'a str,
    billing_version: u64,
    features: &'a [String],
    limits: &'a BTreeMap<String, u64>,
    issued_at: &'a Timestamp,
    not_after: &'a Timestamp,
    epoch: u64,
}

impl LicenseClaim {
    /// Canonical bytes the issuer signs and the verifier checks.
    ///
    /// Excludes [`LicenseClaim::sig`] and is fully deterministic, so a signature
    /// produced over these bytes by the closed issuer verifies here.
    pub fn signing_input(&self) -> Vec<u8> {
        let payload = LicensePayload {
            schema_version: self.schema_version,
            license_id: &self.license_id,
            customer_id: &self.customer_id,
            deployment_id: &self.deployment_id,
            catalog_release: &self.catalog_release,
            billing_version: self.billing_version,
            features: &self.features,
            limits: &self.limits,
            issued_at: &self.issued_at,
            not_after: &self.not_after,
            epoch: self.epoch,
        };
        serde_json::to_vec(&payload).expect("license payload always serializes")
    }

    /// Whether this license entitles `feature`.
    pub fn entitles(&self, feature: &str) -> bool {
        self.features.iter().any(|f| f == feature)
    }

    /// The inclusive numeric ceiling for `feature`, or `None` when the feature is
    /// entitled without a finite ceiling (unlimited) or is not entitled at all.
    pub fn limit(&self, feature: &str) -> Option<u64> {
        self.limits.get(feature).copied()
    }

    /// Whether `now` falls within `[issued_at, not_after)`.
    ///
    /// Timestamps are compared as RFC 3339 UTC strings, which orders
    /// chronologically for the fixed-width `Z` form IAM emits.
    pub fn is_current(&self, now: &Timestamp) -> bool {
        self.issued_at.0.as_str() <= now.0.as_str() && now.0.as_str() < self.not_after.0.as_str()
    }

    /// Verify the claim offline against the pinned `jwks`.
    ///
    /// Checks, in order: this is the current schema and all binding fields are
    /// present; the signing key is present in `jwks` and is a usable Ed25519
    /// verification key; the Ed25519 signature is valid over
    /// [`LicenseClaim::signing_input`]; `now` is within the validity window; and
    /// the claim's [`LicenseClaim::epoch`] is at least `min_epoch`. This proves
    /// claim integrity, but a deployment must call [`Self::verify_for`] to also
    /// authorize the claim for its expected customer and installation. No
    /// network or clock access happens — the caller supplies `now` and the epoch
    /// floor.
    pub fn verify(
        &self,
        jwks: &Jwks,
        now: &Timestamp,
        min_epoch: u64,
    ) -> Result<(), LicenseVerifyError> {
        if self.schema_version != LICENSE_CLAIM_SCHEMA_VERSION {
            return Err(LicenseVerifyError::UnsupportedSchemaVersion);
        }
        if [
            self.license_id.as_str(),
            self.customer_id.as_str(),
            self.deployment_id.as_str(),
            self.catalog_release.as_str(),
        ]
        .iter()
        .any(|value| value.trim().is_empty())
        {
            return Err(LicenseVerifyError::MissingBinding);
        }
        let jwk = jwks
            .keys
            .iter()
            .find(|k| k.kid == self.sig.kid)
            .ok_or(LicenseVerifyError::UnknownKey)?;

        let verifying_key = verifying_key_from_jwk(jwk)?;
        let signature = signature_from_claim(&self.sig)?;
        verifying_key
            .verify_strict(&self.signing_input(), &signature)
            .map_err(|_| LicenseVerifyError::BadSignature)?;

        if now.0.as_str() < self.issued_at.0.as_str() {
            return Err(LicenseVerifyError::NotYetValid);
        }
        if now.0.as_str() >= self.not_after.0.as_str() {
            return Err(LicenseVerifyError::Expired);
        }
        if self.epoch < min_epoch {
            return Err(LicenseVerifyError::EpochFenced);
        }
        Ok(())
    }

    /// Verify integrity/lifecycle and require the exact installation binding.
    pub fn verify_for(
        &self,
        jwks: &Jwks,
        now: &Timestamp,
        min_epoch: u64,
        expected_customer_id: &str,
        expected_deployment_id: &str,
    ) -> Result<(), LicenseVerifyError> {
        self.verify(jwks, now, min_epoch)?;
        if self.customer_id != expected_customer_id {
            return Err(LicenseVerifyError::CustomerMismatch);
        }
        if self.deployment_id != expected_deployment_id {
            return Err(LicenseVerifyError::DeploymentMismatch);
        }
        Ok(())
    }
}

/// Why an offline [`LicenseClaim::verify`] rejected a claim.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LicenseVerifyError {
    /// Only the current bound claim schema is accepted.
    UnsupportedSchemaVersion,
    /// A required customer/deployment/audit binding is absent.
    MissingBinding,
    /// The claim belongs to a different customer.
    CustomerMismatch,
    /// The claim belongs to a different deployment.
    DeploymentMismatch,
    /// No key in the pinned JWKS matches the signature's `kid`.
    UnknownKey,
    /// The selected key is not a usable Ed25519 verification key (wrong
    /// `kty`/`crv`/`alg`/`use`, or malformed key material).
    UnsupportedKey,
    /// The signature value is not a well-formed 64-byte base64url Ed25519
    /// signature.
    MalformedSignature,
    /// The signature does not verify against the claim payload.
    BadSignature,
    /// `now` is before the claim's `issued_at`.
    NotYetValid,
    /// `now` is at or after the claim's `not_after`.
    Expired,
    /// The claim's epoch is below the verifier's pinned floor.
    EpochFenced,
}

impl std::fmt::Display for LicenseVerifyError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let message = match self {
            LicenseVerifyError::UnsupportedSchemaVersion => {
                "license claim schema version is unsupported"
            }
            LicenseVerifyError::MissingBinding => "license claim is missing a required binding",
            LicenseVerifyError::CustomerMismatch => "license claim belongs to a different customer",
            LicenseVerifyError::DeploymentMismatch => {
                "license claim belongs to a different deployment"
            }
            LicenseVerifyError::UnknownKey => "no pinned key matches the license signature kid",
            LicenseVerifyError::UnsupportedKey => "license signing key is not a usable Ed25519 key",
            LicenseVerifyError::MalformedSignature => "license signature is not well-formed",
            LicenseVerifyError::BadSignature => "license signature does not verify",
            LicenseVerifyError::NotYetValid => "license is not yet valid",
            LicenseVerifyError::Expired => "license has expired",
            LicenseVerifyError::EpochFenced => "license epoch is below the pinned floor",
        };
        f.write_str(message)
    }
}

impl std::error::Error for LicenseVerifyError {}

fn verifying_key_from_jwk(jwk: &JsonWebKey) -> Result<VerifyingKey, LicenseVerifyError> {
    if jwk.kty != LICENSE_KTY
        || jwk.crv != LICENSE_CRV
        || jwk.alg != LICENSE_ALG
        || jwk.key_use != LICENSE_USE
    {
        return Err(LicenseVerifyError::UnsupportedKey);
    }
    let raw = URL_SAFE_NO_PAD
        .decode(jwk.x.as_bytes())
        .map_err(|_| LicenseVerifyError::UnsupportedKey)?;
    let bytes: [u8; 32] = raw
        .try_into()
        .map_err(|_| LicenseVerifyError::UnsupportedKey)?;
    VerifyingKey::from_bytes(&bytes).map_err(|_| LicenseVerifyError::UnsupportedKey)
}

fn signature_from_claim(sig: &LicenseSignature) -> Result<Signature, LicenseVerifyError> {
    let raw = URL_SAFE_NO_PAD
        .decode(sig.value.as_bytes())
        .map_err(|_| LicenseVerifyError::MalformedSignature)?;
    let bytes: [u8; 64] = raw
        .try_into()
        .map_err(|_| LicenseVerifyError::MalformedSignature)?;
    Ok(Signature::from_bytes(&bytes))
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::{Signer, SigningKey};

    fn signing_key() -> SigningKey {
        SigningKey::from_bytes(&[7u8; 32])
    }

    fn jwks_for(key: &SigningKey, kid: &str) -> Jwks {
        Jwks {
            keys: vec![JsonWebKey {
                kty: LICENSE_KTY.into(),
                crv: LICENSE_CRV.into(),
                x: URL_SAFE_NO_PAD.encode(key.verifying_key().to_bytes()),
                kid: kid.into(),
                key_use: LICENSE_USE.into(),
                alg: LICENSE_ALG.into(),
            }],
        }
    }

    fn signed_claim(key: &SigningKey, kid: &str) -> LicenseClaim {
        let mut limits = BTreeMap::new();
        limits.insert("namespace.private".to_owned(), 5);
        let mut claim = LicenseClaim {
            schema_version: LICENSE_CLAIM_SCHEMA_VERSION,
            license_id: "license_1".into(),
            customer_id: "customer_1".into(),
            deployment_id: "deployment_1".into(),
            catalog_release: "catalog_2026_06".into(),
            billing_version: 7,
            features: vec!["pack.publish".into(), "model.strong_access".into()],
            limits,
            issued_at: Timestamp("2026-06-01T00:00:00Z".into()),
            not_after: Timestamp("2026-12-01T00:00:00Z".into()),
            epoch: 3,
            sig: LicenseSignature {
                kid: kid.into(),
                value: String::new(),
            },
        };
        let signature = key.sign(&claim.signing_input());
        claim.sig.value = URL_SAFE_NO_PAD.encode(signature.to_bytes());
        claim
    }

    #[test]
    fn round_trips_through_json_with_an_absent_limits_map() {
        let json = r#"{
            "schema_version": 2,
            "license_id": "license_1",
            "customer_id": "customer_1",
            "deployment_id": "deployment_1",
            "catalog_release": "catalog_2026_06",
            "billing_version": 7,
            "features": ["pack.read"],
            "issued_at": "2026-06-01T00:00:00Z",
            "not_after": "2026-12-01T00:00:00Z",
            "epoch": 1,
            "sig": {"kid": "lic-1", "value": "AAAA"}
        }"#;
        let claim: LicenseClaim = serde_json::from_str(json).unwrap();
        assert!(claim.limits.is_empty());
        assert!(claim.entitles("pack.read"));
        assert_eq!(claim.limit("pack.read"), None);
    }

    #[test]
    fn entitlement_and_limit_lookups_read_the_payload() {
        let claim = signed_claim(&signing_key(), "lic-1");
        assert!(claim.entitles("pack.publish"));
        assert!(!claim.entitles("pack.yank"));
        assert_eq!(claim.limit("namespace.private"), Some(5));
        assert_eq!(claim.limit("pack.publish"), None);
    }

    #[test]
    fn a_well_formed_claim_verifies_against_the_pinned_jwks() {
        // Cause/effect decision table for claim verification:
        // C1=schema V2, C2=bindings present, C3=signature/key valid,
        // C4=current, C5=epoch admitted, C6=customer matches,
        // C7=deployment matches. R1 all true -> verified. R2 !C1 or !C2 ->
        // structural rejection; R3 !C3 -> cryptographic rejection; R4 !C4 or
        // !C5 -> lifecycle rejection; R5 !C6 or !C7 -> target rejection.
        // This test covers R1; the focused tests below cover every false cause.
        let key = signing_key();
        let claim = signed_claim(&key, "lic-1");
        let now = Timestamp("2026-07-01T00:00:00Z".into());
        assert_eq!(
            claim.verify_for(
                &jwks_for(&key, "lic-1"),
                &now,
                3,
                "customer_1",
                "deployment_1"
            ),
            Ok(())
        );
        // An equal-or-lower floor still admits the claim.
        assert_eq!(claim.verify(&jwks_for(&key, "lic-1"), &now, 0), Ok(()));
    }

    #[test]
    fn unsupported_or_unbound_claims_are_rejected_before_signature_use() {
        // Decision-table R2: each required structural cause independently false
        // produces its precise fail-closed effect. Re-sign after mutation so this
        // test proves schema/binding validation, not an incidental bad signature.
        let key = signing_key();
        let now = Timestamp("2026-07-01T00:00:00Z".into());
        let jwks = jwks_for(&key, "lic-1");

        let mut legacy = signed_claim(&key, "lic-1");
        legacy.schema_version = 1;
        legacy.sig.value = URL_SAFE_NO_PAD.encode(key.sign(&legacy.signing_input()).to_bytes());
        assert_eq!(
            legacy.verify(&jwks, &now, 0),
            Err(LicenseVerifyError::UnsupportedSchemaVersion)
        );

        for clear_binding in 0..4 {
            let mut claim = signed_claim(&key, "lic-1");
            match clear_binding {
                0 => claim.license_id.clear(),
                1 => claim.customer_id = "  ".into(),
                2 => claim.deployment_id.clear(),
                3 => claim.catalog_release.clear(),
                _ => unreachable!(),
            }
            claim.sig.value = URL_SAFE_NO_PAD.encode(key.sign(&claim.signing_input()).to_bytes());
            assert_eq!(
                claim.verify(&jwks, &now, 0),
                Err(LicenseVerifyError::MissingBinding)
            );
        }
    }

    #[test]
    fn a_claim_is_authorized_only_for_its_bound_customer_and_deployment() {
        // Decision-table R5: the integrity-valid claim must still match both
        // installation coordinates; either mismatch denies the paid unlock.
        let key = signing_key();
        let claim = signed_claim(&key, "lic-1");
        let now = Timestamp("2026-07-01T00:00:00Z".into());
        let jwks = jwks_for(&key, "lic-1");
        assert_eq!(
            claim.verify_for(&jwks, &now, 0, "other_customer", "deployment_1"),
            Err(LicenseVerifyError::CustomerMismatch)
        );
        assert_eq!(
            claim.verify_for(&jwks, &now, 0, "customer_1", "other_deployment"),
            Err(LicenseVerifyError::DeploymentMismatch)
        );
    }

    #[test]
    fn an_unknown_kid_is_rejected() {
        let key = signing_key();
        let claim = signed_claim(&key, "lic-1");
        let now = Timestamp("2026-07-01T00:00:00Z".into());
        assert_eq!(
            claim.verify(&jwks_for(&key, "other"), &now, 0),
            Err(LicenseVerifyError::UnknownKey)
        );
    }

    #[test]
    fn a_tampered_payload_fails_the_signature_check() {
        let key = signing_key();
        let mut claim = signed_claim(&key, "lic-1");
        claim.features.push("model.strong_access.smuggled".into());
        let now = Timestamp("2026-07-01T00:00:00Z".into());
        assert_eq!(
            claim.verify(&jwks_for(&key, "lic-1"), &now, 0),
            Err(LicenseVerifyError::BadSignature)
        );
    }

    #[test]
    fn a_signature_from_a_different_key_fails() {
        let claim = signed_claim(&signing_key(), "lic-1");
        let attacker = SigningKey::from_bytes(&[9u8; 32]);
        let now = Timestamp("2026-07-01T00:00:00Z".into());
        assert_eq!(
            claim.verify(&jwks_for(&attacker, "lic-1"), &now, 0),
            Err(LicenseVerifyError::BadSignature)
        );
    }

    #[test]
    fn the_validity_window_is_enforced() {
        let key = signing_key();
        let claim = signed_claim(&key, "lic-1");
        let jwks = jwks_for(&key, "lic-1");
        assert_eq!(
            claim.verify(&jwks, &Timestamp("2026-05-01T00:00:00Z".into()), 0),
            Err(LicenseVerifyError::NotYetValid)
        );
        assert_eq!(
            claim.verify(&jwks, &Timestamp("2026-12-01T00:00:00Z".into()), 0),
            Err(LicenseVerifyError::Expired)
        );
        assert!(claim.is_current(&Timestamp("2026-07-01T00:00:00Z".into())));
    }

    #[test]
    fn an_epoch_below_the_floor_is_fenced() {
        let key = signing_key();
        let claim = signed_claim(&key, "lic-1");
        let now = Timestamp("2026-07-01T00:00:00Z".into());
        assert_eq!(
            claim.verify(&jwks_for(&key, "lic-1"), &now, 4),
            Err(LicenseVerifyError::EpochFenced)
        );
    }

    #[test]
    fn a_malformed_signature_value_is_reported() {
        let key = signing_key();
        let mut claim = signed_claim(&key, "lic-1");
        claim.sig.value = "not-base64url!!".into();
        let now = Timestamp("2026-07-01T00:00:00Z".into());
        assert_eq!(
            claim.verify(&jwks_for(&key, "lic-1"), &now, 0),
            Err(LicenseVerifyError::MalformedSignature)
        );
    }
}
