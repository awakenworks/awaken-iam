//! License → entitlement-plane boot wiring.
//!
//! The open repo carries the license-claim shape, its offline
//! [`verify`](awaken_iam_contract::LicenseClaim::verify), and the claim →
//! [`EntitlementProvider`](awaken_iam_core::EntitlementProvider) bridge
//! ([`EntitlementEngine::from_license`]). This module is the assembly-time seam
//! that ties them together: it pins the platform JWKS and an epoch floor, loads
//! the deployment's claim (from an inline string or a file), verifies it offline
//! at a caller-supplied instant, and resolves the entitlement provider to install
//! through the existing `with_entitlements` injection point.
//!
//! The policy is fail-open toward *functionality*, fail-closed toward *unlocks*:
//!
//! - **No claim configured** ⇒ [`EntitlementEngine::unlicensed`]: ordinary open
//!   functionality remains available, while explicit commercial entitlement
//!   checks fail closed.
//! - **A claim that verifies** ⇒ [`EntitlementEngine::from_license`]: its features
//!   and limits become the entitlement policy.
//! - **A claim that fails verification** (expired, epoch-fenced, bad signature,
//!   unreadable, malformed) ⇒ falls back to [`EntitlementEngine::unlicensed`]
//!   and records why, never panicking. A rejected claim can never unlock a
//!   commercial entitlement.
//!
//! Verification is offline: the caller supplies "now", so the host re-resolves on
//! a cadence (claims expire at their `not_after`) and re-installs the resolved
//! provider via [`set_entitlements`](crate::IamAssembly::set_entitlements).

use std::path::PathBuf;

use awaken_iam_contract::{Jwks, LicenseClaim, LicenseVerifyError, Timestamp};
use awaken_iam_core::{EntitlementEngine, EntitlementProvider};

/// Where the deployment's license claim is loaded from.
///
/// A claim is the JSON wire form of a [`LicenseClaim`]. Absence is the
/// unlicensed default — [`LicenseSource::None`] keeps explicit commercial
/// checks denied.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub enum LicenseSource {
    /// No license: the deployment is unlicensed and commercial checks deny.
    #[default]
    None,
    /// A claim supplied inline as its JSON wire form (for example from an
    /// environment variable).
    Inline(String),
    /// A claim read from a JSON file at this path.
    File(PathBuf),
}

impl LicenseSource {
    /// Resolve a source from the environment: the inline JSON in
    /// `AWAKEN_IAM_LICENSE` takes precedence, else the path in
    /// `AWAKEN_IAM_LICENSE_FILE`, else [`LicenseSource::None`].
    pub fn from_env() -> Self {
        if let Ok(inline) = std::env::var(ENV_LICENSE_INLINE)
            && !inline.trim().is_empty()
        {
            return LicenseSource::Inline(inline);
        }
        if let Ok(path) = std::env::var(ENV_LICENSE_FILE)
            && !path.trim().is_empty()
        {
            return LicenseSource::File(PathBuf::from(path));
        }
        LicenseSource::None
    }
}

/// Environment variable carrying an inline license claim (JSON).
pub const ENV_LICENSE_INLINE: &str = "AWAKEN_IAM_LICENSE";
/// Environment variable carrying a path to a license claim file (JSON).
pub const ENV_LICENSE_FILE: &str = "AWAKEN_IAM_LICENSE_FILE";

/// Why a configured license claim could not be turned into a [`LicenseClaim`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LicenseLoadError {
    /// The claim file could not be read.
    Read(String),
    /// The claim JSON did not parse into a [`LicenseClaim`].
    Parse(String),
}

impl std::fmt::Display for LicenseLoadError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            LicenseLoadError::Read(why) => write!(f, "could not read license claim: {why}"),
            LicenseLoadError::Parse(why) => write!(f, "could not parse license claim: {why}"),
        }
    }
}

impl std::error::Error for LicenseLoadError {}

/// Why a present claim did not yield a licensed provider.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LicenseRejection {
    /// The configured claim source could not be read or parsed.
    Load(LicenseLoadError),
    /// The claim was read but failed offline verification.
    Verify(LicenseVerifyError),
}

impl std::fmt::Display for LicenseRejection {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            LicenseRejection::Load(err) => err.fmt(f),
            LicenseRejection::Verify(err) => err.fmt(f),
        }
    }
}

impl std::error::Error for LicenseRejection {}

/// Why the resolved provider is what it is, for boot logging and the re-verify
/// cadence.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LicenseStatus {
    /// No claim was configured; the provider denies commercial entitlements.
    Unlicensed,
    /// A claim verified and was bridged into a licensed provider. The
    /// `not_after` instant tells the host when to re-resolve.
    Licensed {
        /// The claim's expiry; re-resolve before this instant.
        not_after: Timestamp,
    },
    /// A claim was present but rejected; commercial entitlements fail closed.
    Rejected(LicenseRejection),
}

impl LicenseStatus {
    /// Whether a verified license is installed.
    pub fn is_licensed(&self) -> bool {
        matches!(self, LicenseStatus::Licensed { .. })
    }
}

/// Outcome of resolving a [`LicenseConfig`] at one instant: the provider to
/// install plus the status that explains it.
pub struct LicenseResolution {
    /// The entitlement provider to install via `with_entitlements` /
    /// `set_entitlements`.
    pub provider: Box<dyn EntitlementProvider>,
    /// Why the provider is what it is.
    pub status: LicenseStatus,
}

/// Assembly-time configuration for the open licensing seam.
///
/// Pins the platform's public verification keys and an epoch floor, and names
/// where the claim is loaded from. Build it once on boot and call
/// [`resolve`](LicenseConfig::resolve) with the current time; re-call on a
/// cadence to honour `not_after`.
#[derive(Debug, Clone)]
pub struct LicenseConfig {
    /// Pinned platform JWKS the claim signature is checked against.
    pub jwks: Jwks,
    /// Epoch floor: claims minted below this are fenced out.
    pub min_epoch: u64,
    /// Where to load the claim from.
    pub source: LicenseSource,
}

impl LicenseConfig {
    /// An unlicensed configuration: no keys, no claim. [`resolve`](Self::resolve)
    /// always yields [`EntitlementEngine::unlicensed`].
    pub fn unlicensed() -> Self {
        Self {
            jwks: Jwks { keys: Vec::new() },
            min_epoch: 0,
            source: LicenseSource::None,
        }
    }

    /// Build a configuration that verifies a claim against `jwks` with the given
    /// epoch floor, loading the claim from `source`.
    pub fn new(jwks: Jwks, min_epoch: u64, source: LicenseSource) -> Self {
        Self {
            jwks,
            min_epoch,
            source,
        }
    }

    /// Load the configured claim, if any.
    ///
    /// Returns `Ok(None)` for [`LicenseSource::None`], `Ok(Some(claim))` when a
    /// claim is read and parses, and [`LicenseLoadError`] when the source is
    /// present but unreadable or malformed. No verification happens here.
    pub fn load_claim(&self) -> Result<Option<LicenseClaim>, LicenseLoadError> {
        let json = match &self.source {
            LicenseSource::None => return Ok(None),
            LicenseSource::Inline(json) => json.clone(),
            LicenseSource::File(path) => std::fs::read_to_string(path)
                .map_err(|err| LicenseLoadError::Read(err.to_string()))?,
        };
        serde_json::from_str(&json)
            .map(Some)
            .map_err(|err| LicenseLoadError::Parse(err.to_string()))
    }

    /// Resolve the entitlement provider to install at instant `now`.
    ///
    /// Never errors and never panics: a missing, unreadable, malformed, or
    /// unverifiable claim resolves to [`EntitlementEngine::unlicensed`] with a
    /// [`LicenseStatus`] explaining why. A claim that verifies resolves to
    /// [`EntitlementEngine::from_license`].
    pub fn resolve(&self, now: &Timestamp) -> LicenseResolution {
        let claim = match self.load_claim() {
            Ok(None) => {
                return LicenseResolution {
                    provider: Box::new(EntitlementEngine::unlicensed()),
                    status: LicenseStatus::Unlicensed,
                };
            }
            Ok(Some(claim)) => claim,
            Err(err) => {
                return LicenseResolution {
                    provider: Box::new(EntitlementEngine::unlicensed()),
                    status: LicenseStatus::Rejected(LicenseRejection::Load(err)),
                };
            }
        };

        match claim.verify(&self.jwks, now, self.min_epoch) {
            Ok(()) => LicenseResolution {
                provider: Box::new(EntitlementEngine::from_license(&claim)),
                status: LicenseStatus::Licensed {
                    not_after: claim.not_after.clone(),
                },
            },
            Err(err) => LicenseResolution {
                provider: Box::new(EntitlementEngine::unlicensed()),
                status: LicenseStatus::Rejected(LicenseRejection::Verify(err)),
            },
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use awaken_iam_contract::{
        EntitlementDecision, EntitlementRequest, JsonWebKey, LicenseSignature, PrincipalRef,
    };
    use base64::Engine;
    use base64::engine::general_purpose::URL_SAFE_NO_PAD;
    use ed25519_dalek::{Signer, SigningKey};
    use std::collections::BTreeMap;

    fn account(id: &str) -> PrincipalRef {
        PrincipalRef::Account {
            account_id: awaken_iam_contract::AccountId(id.into()),
        }
    }

    fn request(entitlement: &str) -> EntitlementRequest {
        EntitlementRequest {
            principal: account("acct_1"),
            entitlement: entitlement.into(),
            resource: None,
        }
    }

    fn signing_key() -> SigningKey {
        SigningKey::from_bytes(&[7u8; 32])
    }

    fn jwks_for(key: &SigningKey, kid: &str) -> Jwks {
        Jwks {
            keys: vec![JsonWebKey {
                kty: "OKP".into(),
                crv: "Ed25519".into(),
                x: URL_SAFE_NO_PAD.encode(key.verifying_key().to_bytes()),
                kid: kid.into(),
                key_use: "sig".into(),
                alg: "EdDSA".into(),
            }],
        }
    }

    fn signed_claim(key: &SigningKey, kid: &str, epoch: u64, not_after: &str) -> LicenseClaim {
        let mut limits = BTreeMap::new();
        limits.insert("namespace.private".to_owned(), 5);
        let mut claim = LicenseClaim {
            features: vec!["pack.publish".into(), "namespace.private".into()],
            limits,
            issued_at: Timestamp("2026-06-01T00:00:00Z".into()),
            not_after: Timestamp(not_after.into()),
            epoch,
            sig: LicenseSignature {
                kid: kid.into(),
                value: String::new(),
            },
        };
        let signature = key.sign(&claim.signing_input());
        claim.sig.value = URL_SAFE_NO_PAD.encode(signature.to_bytes());
        claim
    }

    fn inline_config(claim: &LicenseClaim, jwks: Jwks, min_epoch: u64) -> LicenseConfig {
        LicenseConfig::new(
            jwks,
            min_epoch,
            LicenseSource::Inline(serde_json::to_string(claim).unwrap()),
        )
    }

    #[test]
    fn no_claim_denies_explicit_commercial_entitlements() {
        // Cause/effect decision table: C1=claim configured, C2=claim verifies.
        // R1 !C1 -> unlicensed status + deny; R2 C1+C2 -> licensed policy
        // (covered below); R3 C1+!C2 -> rejected status + deny (covered by the
        // expired, fenced, and malformed cases). Open product functionality has
        // no entitlement request and is therefore outside this gate.
        let config = LicenseConfig::unlicensed();
        let resolved = config.resolve(&Timestamp("2026-07-01T00:00:00Z".into()));
        assert_eq!(resolved.status, LicenseStatus::Unlicensed);
        // Absence must never unlock a commercial feature.
        assert_eq!(
            resolved.provider.evaluate(&request("anything")).decision,
            EntitlementDecision::Deny
        );
        assert_eq!(
            resolved.provider.quota(&account("acct_1"), "anything"),
            None
        );
    }

    #[test]
    fn a_verifying_claim_installs_a_licensed_provider() {
        let key = signing_key();
        let claim = signed_claim(&key, "lic-1", 3, "2026-12-01T00:00:00Z");
        let config = inline_config(&claim, jwks_for(&key, "lic-1"), 3);
        let resolved = config.resolve(&Timestamp("2026-07-01T00:00:00Z".into()));

        assert!(resolved.status.is_licensed());
        assert_eq!(
            resolved.status,
            LicenseStatus::Licensed {
                not_after: Timestamp("2026-12-01T00:00:00Z".into()),
            }
        );
        // Entitled feature is allowed; unlisted feature is denied.
        assert_eq!(
            resolved
                .provider
                .evaluate(&request("pack.publish"))
                .decision,
            EntitlementDecision::Allow
        );
        assert_eq!(
            resolved
                .provider
                .evaluate(&request("model.strong_access"))
                .decision,
            EntitlementDecision::Deny
        );
        use awaken_iam_core::Quota;
        assert_eq!(
            resolved
                .provider
                .quota(&account("acct_1"), "namespace.private"),
            Some(Quota::Limited(5))
        );
    }

    #[test]
    fn an_expired_claim_falls_back_to_unlicensed_denial() {
        let key = signing_key();
        let claim = signed_claim(&key, "lic-1", 3, "2026-06-15T00:00:00Z");
        let config = inline_config(&claim, jwks_for(&key, "lic-1"), 3);
        // now is past not_after.
        let resolved = config.resolve(&Timestamp("2026-07-01T00:00:00Z".into()));

        assert_eq!(
            resolved.status,
            LicenseStatus::Rejected(LicenseRejection::Verify(LicenseVerifyError::Expired))
        );
        // No panic; open functionality remains, but paid unlocks fail closed.
        assert_eq!(
            resolved
                .provider
                .evaluate(&request("pack.publish"))
                .decision,
            EntitlementDecision::Deny
        );
    }

    #[test]
    fn an_epoch_fenced_claim_falls_back_to_unlicensed_denial() {
        let key = signing_key();
        let claim = signed_claim(&key, "lic-1", 2, "2026-12-01T00:00:00Z");
        // Floor above the claim's epoch fences it out.
        let config = inline_config(&claim, jwks_for(&key, "lic-1"), 5);
        let resolved = config.resolve(&Timestamp("2026-07-01T00:00:00Z".into()));

        assert_eq!(
            resolved.status,
            LicenseStatus::Rejected(LicenseRejection::Verify(LicenseVerifyError::EpochFenced))
        );
        assert_eq!(
            resolved.provider.evaluate(&request("anything")).decision,
            EntitlementDecision::Deny
        );
    }

    #[test]
    fn malformed_claim_json_falls_back_to_unlicensed_denial() {
        let config = LicenseConfig::new(
            Jwks { keys: Vec::new() },
            0,
            LicenseSource::Inline("{ not a claim".into()),
        );
        let resolved = config.resolve(&Timestamp("2026-07-01T00:00:00Z".into()));
        assert!(matches!(
            resolved.status,
            LicenseStatus::Rejected(LicenseRejection::Load(LicenseLoadError::Parse(_)))
        ));
        assert_eq!(
            resolved.provider.evaluate(&request("anything")).decision,
            EntitlementDecision::Deny
        );
    }

    #[test]
    fn a_cloud_claim_and_a_self_host_claim_apply_identically() {
        // Same payload, different issuance metadata and signing keys: a
        // cloud-issued claim (higher epoch) and a self-hosted local-seed claim.
        let cloud_key = SigningKey::from_bytes(&[1u8; 32]);
        let cloud = signed_claim(&cloud_key, "cloud-key", 9, "2026-12-01T00:00:00Z");
        let cloud_resolved = inline_config(&cloud, jwks_for(&cloud_key, "cloud-key"), 0)
            .resolve(&Timestamp("2026-07-01T00:00:00Z".into()));

        let seed_key = SigningKey::from_bytes(&[2u8; 32]);
        let seed = signed_claim(&seed_key, "local-seed", 1, "2026-12-01T00:00:00Z");
        let seed_resolved = inline_config(&seed, jwks_for(&seed_key, "local-seed"), 0)
            .resolve(&Timestamp("2026-07-01T00:00:00Z".into()));

        assert!(cloud_resolved.status.is_licensed());
        assert!(seed_resolved.status.is_licensed());
        for feature in ["pack.publish", "namespace.private", "absent.feature"] {
            assert_eq!(
                cloud_resolved.provider.evaluate(&request(feature)).decision,
                seed_resolved.provider.evaluate(&request(feature)).decision,
                "feature {feature} must resolve identically"
            );
            assert_eq!(
                cloud_resolved.provider.quota(&account("acct_1"), feature),
                seed_resolved.provider.quota(&account("acct_1"), feature),
            );
        }
    }
}
