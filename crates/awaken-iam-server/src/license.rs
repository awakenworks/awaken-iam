//! License → entitlement-plane boot wiring.
//!
//! The open repo carries the license-claim shape, its offline
//! [`verify`](awaken_iam_contract::LicenseClaim::verify), and the claim →
//! [`EntitlementProvider`](awaken_iam_core::EntitlementProvider) bridge
//! ([`EntitlementEngine::from_license`]). This module is the assembly-time seam
//! that ties them together: it pins the platform JWKS, an epoch floor, and the
//! expected customer/deployment binding; loads the deployment's claim (from an
//! inline string or a file); verifies it offline at a caller-supplied instant;
//! and resolves the entitlement provider to install through the existing
//! `with_entitlements` injection point.
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

use std::fs::{self, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};

use awaken_iam_contract::{
    EntitlementRequest, Jwks, LicenseClaim, LicenseVerifyError, PrincipalRef, Timestamp,
};
use awaken_iam_core::{
    EntitlementEngine, EntitlementOutcome, EntitlementProvider, Quota, RateLimit,
};
use serde::{Deserialize, Serialize};
use time::{OffsetDateTime, format_description::well_known::Rfc3339};

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
/// Environment variable carrying the pinned license-verification JWKS (JSON).
pub const ENV_LICENSE_JWKS: &str = "AWAKEN_IAM_LICENSE_JWKS";
/// Environment variable carrying a path to the pinned JWKS (JSON).
pub const ENV_LICENSE_JWKS_FILE: &str = "AWAKEN_IAM_LICENSE_JWKS_FILE";
/// Customer binding provisioned for this installation.
pub const ENV_LICENSE_CUSTOMER_ID: &str = "AWAKEN_IAM_LICENSE_CUSTOMER_ID";
/// Stable deployment fingerprint provisioned for this installation.
pub const ENV_LICENSE_DEPLOYMENT_ID: &str = "AWAKEN_IAM_LICENSE_DEPLOYMENT_ID";

/// Why a configured license claim could not be turned into a [`LicenseClaim`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LicenseLoadError {
    /// A configured deployment is missing or has invalid verifier settings.
    Configuration(String),
    /// The claim file could not be read.
    Read(String),
    /// The claim JSON did not parse into a [`LicenseClaim`].
    Parse(String),
}

impl std::fmt::Display for LicenseLoadError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            LicenseLoadError::Configuration(why) => {
                write!(f, "invalid license verifier configuration: {why}")
            }
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
    /// Durable anti-rollback state could not be trusted or advanced.
    State(LicenseStateError),
}

impl std::fmt::Display for LicenseRejection {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            LicenseRejection::Load(err) => err.fmt(f),
            LicenseRejection::Verify(err) => err.fmt(f),
            LicenseRejection::State(err) => err.fmt(f),
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
        /// Monotonic issuer epoch accepted by this installation.
        epoch: u64,
        /// Billing projection version bound into the accepted claim.
        billing_version: u64,
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
    /// Customer id provisioned for this installation.
    pub expected_customer_id: String,
    /// Stable id of this exact installation.
    pub expected_deployment_id: String,
    /// Where to load the claim from.
    pub source: LicenseSource,
}

impl LicenseConfig {
    /// Resolve the canonical deployment configuration from environment.
    ///
    /// With no claim configured this returns the unlicensed baseline. Once a
    /// claim is present, JWKS and both installation bindings are mandatory;
    /// incomplete configuration is rejected instead of silently weakening the
    /// verification contract.
    pub fn from_env() -> Result<Self, LicenseLoadError> {
        let source = LicenseSource::from_env();
        if source == LicenseSource::None {
            return Ok(Self::unlicensed());
        }
        let jwks_json = env_inline_or_file(ENV_LICENSE_JWKS, ENV_LICENSE_JWKS_FILE)?;
        let jwks = serde_json::from_str(&jwks_json).map_err(|error| {
            LicenseLoadError::Configuration(format!("invalid JWKS JSON: {error}"))
        })?;
        let expected_customer_id = required_env(ENV_LICENSE_CUSTOMER_ID)?;
        let expected_deployment_id = required_env(ENV_LICENSE_DEPLOYMENT_ID)?;
        Ok(Self::new(
            jwks,
            0,
            source,
            expected_customer_id,
            expected_deployment_id,
        ))
    }

    /// An unlicensed configuration: no keys, no claim. [`resolve`](Self::resolve)
    /// always yields [`EntitlementEngine::unlicensed`].
    pub fn unlicensed() -> Self {
        Self {
            jwks: Jwks { keys: Vec::new() },
            min_epoch: 0,
            expected_customer_id: String::new(),
            expected_deployment_id: String::new(),
            source: LicenseSource::None,
        }
    }

    /// Build a configuration that verifies a claim against `jwks` with the given
    /// epoch floor and installation binding, loading the claim from `source`.
    pub fn new(
        jwks: Jwks,
        min_epoch: u64,
        source: LicenseSource,
        expected_customer_id: impl Into<String>,
        expected_deployment_id: impl Into<String>,
    ) -> Self {
        Self {
            jwks,
            min_epoch,
            expected_customer_id: expected_customer_id.into(),
            expected_deployment_id: expected_deployment_id.into(),
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
        self.resolve_with_floor(now, None)
    }

    /// Resolve against a durable monotonic floor. A previously accepted higher
    /// epoch or billing version can never be replaced by an older claim.
    pub fn resolve_with_store(
        &self,
        now: &Timestamp,
        store: &LicenseFloorStore,
    ) -> LicenseResolution {
        self.resolve_with_floor(now, Some(store))
    }

    /// Install a provider that re-loads and re-verifies the claim on every
    /// commercial entitlement decision. This makes expiry and file rotation
    /// effective without a process restart and keeps the refresh behavior in
    /// IAM rather than duplicating timers in each product.
    pub fn resolve_live_with_store(&self, store: LicenseFloorStore) -> LicenseResolution {
        let now = current_timestamp();
        let initial = self.resolve_with_store(&now, &store);
        LicenseResolution {
            provider: Box::new(LiveLicenseProvider {
                config: self.clone(),
                store,
            }),
            status: initial.status,
        }
    }

    fn resolve_with_floor(
        &self,
        now: &Timestamp,
        store: Option<&LicenseFloorStore>,
    ) -> LicenseResolution {
        let floor = match store.map(LicenseFloorStore::load).transpose() {
            Ok(value) => value,
            Err(error) => return rejected_state(error),
        };
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

        let min_epoch = floor
            .as_ref()
            .map_or(self.min_epoch, |record| self.min_epoch.max(record.epoch));
        match claim.verify_for(
            &self.jwks,
            now,
            min_epoch,
            &self.expected_customer_id,
            &self.expected_deployment_id,
        ) {
            Ok(()) => {
                if let Some(record) = floor.as_ref()
                    && claim.billing_version < record.billing_version
                {
                    return rejected_state(LicenseStateError::Rollback {
                        stored_epoch: record.epoch,
                        stored_billing_version: record.billing_version,
                        claim_epoch: claim.epoch,
                        claim_billing_version: claim.billing_version,
                    });
                }
                if let Some(store) = store
                    && let Err(error) = store.advance(&LicenseFloorRecord::from_claim(&claim))
                {
                    return rejected_state(error);
                }
                LicenseResolution {
                    provider: Box::new(EntitlementEngine::from_license(&claim)),
                    status: LicenseStatus::Licensed {
                        not_after: claim.not_after.clone(),
                        epoch: claim.epoch,
                        billing_version: claim.billing_version,
                    },
                }
            }
            Err(err) => LicenseResolution {
                provider: Box::new(EntitlementEngine::unlicensed()),
                status: LicenseStatus::Rejected(LicenseRejection::Verify(err)),
            },
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct LicenseFloorRecord {
    customer_id: String,
    deployment_id: String,
    epoch: u64,
    billing_version: u64,
}

impl LicenseFloorRecord {
    fn from_claim(claim: &LicenseClaim) -> Self {
        Self {
            customer_id: claim.customer_id.clone(),
            deployment_id: claim.deployment_id.clone(),
            epoch: claim.epoch,
            billing_version: claim.billing_version,
        }
    }
}

/// Durable high-water mark for accepted license claims.
#[derive(Debug, Clone)]
pub struct LicenseFloorStore {
    path: PathBuf,
    customer_id: String,
    deployment_id: String,
}

impl LicenseFloorStore {
    #[must_use]
    pub fn new(
        path: impl Into<PathBuf>,
        customer_id: impl Into<String>,
        deployment_id: impl Into<String>,
    ) -> Self {
        Self {
            path: path.into(),
            customer_id: customer_id.into(),
            deployment_id: deployment_id.into(),
        }
    }

    fn load(&self) -> Result<LicenseFloorRecord, LicenseStateError> {
        match fs::symlink_metadata(&self.path) {
            Ok(metadata) => {
                if !metadata.file_type().is_file() {
                    return Err(LicenseStateError::UnsafeFileType);
                }
                #[cfg(unix)]
                {
                    use std::os::unix::fs::PermissionsExt;
                    let mode = metadata.permissions().mode() & 0o777;
                    if mode & 0o077 != 0 {
                        return Err(LicenseStateError::InsecurePermissions(mode));
                    }
                }
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => return Err(LicenseStateError::Read(error.to_string())),
        }
        let json = match fs::read_to_string(&self.path) {
            Ok(json) => json,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                return Ok(LicenseFloorRecord {
                    customer_id: self.customer_id.clone(),
                    deployment_id: self.deployment_id.clone(),
                    epoch: 0,
                    billing_version: 0,
                });
            }
            Err(error) => return Err(LicenseStateError::Read(error.to_string())),
        };
        let record: LicenseFloorRecord = serde_json::from_str(&json)
            .map_err(|error| LicenseStateError::Parse(error.to_string()))?;
        if record.customer_id != self.customer_id || record.deployment_id != self.deployment_id {
            return Err(LicenseStateError::BindingMismatch);
        }
        Ok(record)
    }

    fn advance(&self, next: &LicenseFloorRecord) -> Result<(), LicenseStateError> {
        let current = self.load()?;
        if next.epoch < current.epoch || next.billing_version < current.billing_version {
            return Err(LicenseStateError::Rollback {
                stored_epoch: current.epoch,
                stored_billing_version: current.billing_version,
                claim_epoch: next.epoch,
                claim_billing_version: next.billing_version,
            });
        }
        if next.epoch == current.epoch && next.billing_version == current.billing_version {
            return Ok(());
        }
        if let Some(parent) = self.path.parent() {
            fs::create_dir_all(parent)
                .map_err(|error| LicenseStateError::Write(error.to_string()))?;
        }
        let mut nonce = [0_u8; 8];
        getrandom::fill(&mut nonce).map_err(|error| LicenseStateError::Write(error.to_string()))?;
        let suffix = nonce
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect::<String>();
        let temporary = self.path.with_extension(format!("tmp-{suffix}"));
        let result = write_owner_only(&temporary, next)
            .and_then(|()| {
                fs::rename(&temporary, &self.path)
                    .map_err(|error| LicenseStateError::Write(error.to_string()))
            })
            .and_then(|()| sync_parent(&self.path));
        if result.is_err() {
            let _ = fs::remove_file(&temporary);
        }
        result
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LicenseStateError {
    Read(String),
    Parse(String),
    Write(String),
    UnsafeFileType,
    InsecurePermissions(u32),
    BindingMismatch,
    Rollback {
        stored_epoch: u64,
        stored_billing_version: u64,
        claim_epoch: u64,
        claim_billing_version: u64,
    },
}

impl std::fmt::Display for LicenseStateError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Read(error) => write!(f, "could not read license rollback floor: {error}"),
            Self::Parse(error) => write!(f, "could not parse license rollback floor: {error}"),
            Self::Write(error) => write!(f, "could not persist license rollback floor: {error}"),
            Self::UnsafeFileType => {
                f.write_str("license rollback floor must be a regular file, not a symlink")
            }
            Self::InsecurePermissions(mode) => write!(
                f,
                "license rollback floor permissions {mode:o} expose it to group or other users"
            ),
            Self::BindingMismatch => {
                f.write_str("license rollback floor belongs to another installation")
            }
            Self::Rollback { .. } => {
                f.write_str("license claim is older than the accepted rollback floor")
            }
        }
    }
}

impl std::error::Error for LicenseStateError {}

#[derive(Debug)]
struct LiveLicenseProvider {
    config: LicenseConfig,
    store: LicenseFloorStore,
}

impl LiveLicenseProvider {
    fn current(&self) -> LicenseResolution {
        self.config
            .resolve_with_store(&current_timestamp(), &self.store)
    }
}

impl EntitlementProvider for LiveLicenseProvider {
    fn evaluate(&self, request: &EntitlementRequest) -> EntitlementOutcome {
        self.current().provider.evaluate(request)
    }

    fn quota(&self, principal: &PrincipalRef, feature: &str) -> Option<Quota> {
        self.current().provider.quota(principal, feature)
    }

    fn rate_limit(&self, principal: &PrincipalRef, feature: &str) -> Option<RateLimit> {
        self.current().provider.rate_limit(principal, feature)
    }

    fn check_quota(&self, request: &EntitlementRequest, observed_usage: u64) -> EntitlementOutcome {
        self.current().provider.check_quota(request, observed_usage)
    }
}

fn current_timestamp() -> Timestamp {
    Timestamp(
        OffsetDateTime::now_utc()
            .format(&Rfc3339)
            .expect("UTC time always formats as RFC 3339"),
    )
}

fn rejected_state(error: LicenseStateError) -> LicenseResolution {
    LicenseResolution {
        provider: Box::new(EntitlementEngine::unlicensed()),
        status: LicenseStatus::Rejected(LicenseRejection::State(error)),
    }
}

fn required_env(name: &'static str) -> Result<String, LicenseLoadError> {
    std::env::var(name)
        .ok()
        .filter(|value| !value.trim().is_empty())
        .ok_or_else(|| LicenseLoadError::Configuration(format!("{name} is required")))
}

fn env_inline_or_file(
    inline_name: &'static str,
    file_name: &'static str,
) -> Result<String, LicenseLoadError> {
    if let Ok(value) = std::env::var(inline_name)
        && !value.trim().is_empty()
    {
        return Ok(value);
    }
    let path = required_env(file_name)?;
    fs::read_to_string(path).map_err(|error| LicenseLoadError::Configuration(error.to_string()))
}

fn write_owner_only(path: &Path, record: &LicenseFloorRecord) -> Result<(), LicenseStateError> {
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let mut file = options
        .open(path)
        .map_err(|error| LicenseStateError::Write(error.to_string()))?;
    let bytes =
        serde_json::to_vec(record).map_err(|error| LicenseStateError::Write(error.to_string()))?;
    file.write_all(&bytes)
        .and_then(|()| file.sync_all())
        .map_err(|error| LicenseStateError::Write(error.to_string()))
}

fn sync_parent(path: &Path) -> Result<(), LicenseStateError> {
    let Some(parent) = path.parent() else {
        return Ok(());
    };
    fs::File::open(parent)
        .and_then(|directory| directory.sync_all())
        .map_err(|error| LicenseStateError::Write(error.to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use awaken_iam_contract::{
        EntitlementDecision, EntitlementRequest, JsonWebKey, LICENSE_CLAIM_SCHEMA_VERSION,
        LicenseSignature, PrincipalRef,
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
            schema_version: LICENSE_CLAIM_SCHEMA_VERSION,
            license_id: "license_1".into(),
            customer_id: "customer_1".into(),
            deployment_id: "deployment_1".into(),
            catalog_release: "catalog_2026_06".into(),
            billing_version: 7,
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
            "customer_1",
            "deployment_1",
        )
    }

    fn test_path(name: &str) -> PathBuf {
        let mut nonce = [0_u8; 8];
        getrandom::fill(&mut nonce).unwrap();
        let suffix = nonce
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect::<String>();
        std::env::temp_dir().join(format!("awaken-license-{name}-{suffix}"))
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
                epoch: 3,
                billing_version: 7,
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
    fn a_claim_for_another_installation_falls_back_to_unlicensed_denial() {
        // Cause/effect decision table extension: C1=claim verifies structurally
        // and cryptographically, C2=customer binding matches, C3=deployment
        // binding matches. R1 C1+C2+C3 -> licensed (covered above); R2 C1+!C2
        // or R3 C1+C2+!C3 -> rejected + unlicensed provider. These two rules
        // prevent a copied, otherwise-valid license from unlocking this host.
        let key = signing_key();
        let claim = signed_claim(&key, "lic-1", 3, "2026-12-01T00:00:00Z");
        let source = LicenseSource::Inline(serde_json::to_string(&claim).unwrap());

        for (customer, deployment, expected_error) in [
            (
                "other_customer",
                "deployment_1",
                LicenseVerifyError::CustomerMismatch,
            ),
            (
                "customer_1",
                "other_deployment",
                LicenseVerifyError::DeploymentMismatch,
            ),
        ] {
            let config = LicenseConfig::new(
                jwks_for(&key, "lic-1"),
                0,
                source.clone(),
                customer,
                deployment,
            );
            let resolved = config.resolve(&Timestamp("2026-07-01T00:00:00Z".into()));
            assert_eq!(
                resolved.status,
                LicenseStatus::Rejected(LicenseRejection::Verify(expected_error))
            );
            assert_eq!(
                resolved
                    .provider
                    .evaluate(&request("pack.publish"))
                    .decision,
                EntitlementDecision::Deny
            );
        }
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
            "customer_1",
            "deployment_1",
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
    fn durable_floor_rejects_epoch_and_billing_rollbacks() {
        // Cause/effect graph: C1=signature/binding/current claim, C2=epoch is at
        // least the persisted epoch, C3=billing version is at least the
        // persisted billing version, C4=floor can be persisted. E1=paid
        // entitlements unlock only for C1∧C2∧C3∧C4; every false cause denies.
        //
        // Decision table:
        // | rule | C1 | C2 | C3 | C4 | outcome |
        // | R1   | T  | T  | T  | T  | allow + advance floor |
        // | R2   | T  | F  | -  | -  | EpochFenced + deny |
        // | R3   | T  | T  | F  | -  | State::Rollback + deny |
        // | R4   | T  | T  | T  | F  | State error + deny |
        // This test covers R1-R3; corrupt/unwritable state coverage below owns R4.
        let key = signing_key();
        let now = Timestamp("2026-07-01T00:00:00Z".into());
        let floor_path = test_path("floor");
        let store = LicenseFloorStore::new(&floor_path, "customer_1", "deployment_1");

        let current = signed_claim(&key, "lic-1", 3, "2026-12-01T00:00:00Z");
        let accepted =
            inline_config(&current, jwks_for(&key, "lic-1"), 0).resolve_with_store(&now, &store);
        assert!(accepted.status.is_licensed());
        assert_eq!(store.load().unwrap().epoch, 3);
        assert_eq!(store.load().unwrap().billing_version, 7);

        let old_epoch = signed_claim(&key, "lic-1", 2, "2026-12-01T00:00:00Z");
        assert_eq!(
            inline_config(&old_epoch, jwks_for(&key, "lic-1"), 0)
                .resolve_with_store(&now, &store)
                .status,
            LicenseStatus::Rejected(LicenseRejection::Verify(LicenseVerifyError::EpochFenced))
        );

        let mut old_billing = signed_claim(&key, "lic-1", 3, "2026-12-01T00:00:00Z");
        old_billing.billing_version = 6;
        old_billing.sig.value =
            URL_SAFE_NO_PAD.encode(key.sign(&old_billing.signing_input()).to_bytes());
        assert!(matches!(
            inline_config(&old_billing, jwks_for(&key, "lic-1"), 0)
                .resolve_with_store(&now, &store)
                .status,
            LicenseStatus::Rejected(LicenseRejection::State(LicenseStateError::Rollback { .. }))
        ));
        let _ = fs::remove_file(floor_path);
    }

    #[test]
    fn untrusted_floor_state_fails_closed() {
        // Cause/effect R4: corrupt, rebound, symlinked, or otherwise untrusted
        // state must never be treated as an empty floor because that would turn
        // deletion/tampering into a rollback bypass. Representative malformed
        // and cross-deployment records both yield a denied provider.
        let key = signing_key();
        let claim = signed_claim(&key, "lic-1", 3, "2026-12-01T00:00:00Z");
        let config = inline_config(&claim, jwks_for(&key, "lic-1"), 0);
        let now = Timestamp("2026-07-01T00:00:00Z".into());
        let floor_path = test_path("untrusted-floor");
        let store = LicenseFloorStore::new(&floor_path, "customer_1", "deployment_1");

        fs::write(&floor_path, "not-json").unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(&floor_path, fs::Permissions::from_mode(0o600)).unwrap();
        }
        assert!(matches!(
            config.resolve_with_store(&now, &store).status,
            LicenseStatus::Rejected(LicenseRejection::State(LicenseStateError::Parse(_)))
        ));

        fs::remove_file(&floor_path).unwrap();
        let rebound = LicenseFloorRecord {
            customer_id: "customer_1".into(),
            deployment_id: "copied_deployment".into(),
            epoch: 99,
            billing_version: 99,
        };
        write_owner_only(&floor_path, &rebound).unwrap();
        let resolution = config.resolve_with_store(&now, &store);
        assert_eq!(
            resolution.status,
            LicenseStatus::Rejected(LicenseRejection::State(LicenseStateError::BindingMismatch))
        );
        assert_eq!(
            resolution
                .provider
                .evaluate(&request("pack.publish"))
                .decision,
            EntitlementDecision::Deny
        );
        let _ = fs::remove_file(floor_path);
    }

    #[test]
    fn live_provider_reloads_and_reverifies_rotated_claims() {
        // Cause/effect: C1=current file remains signed and bound -> allow;
        // C2=file is replaced by a tampered claim -> immediate deny on the next
        // decision. This covers the dynamic path that enforces expiry/rotation
        // without a separate product-owned refresh timer.
        let key = signing_key();
        let claim = signed_claim(&key, "lic-1", 3, "2030-12-01T00:00:00Z");
        let claim_path = test_path("live-claim");
        let floor_path = test_path("live-floor");
        fs::write(&claim_path, serde_json::to_vec(&claim).unwrap()).unwrap();
        let config = LicenseConfig::new(
            jwks_for(&key, "lic-1"),
            0,
            LicenseSource::File(claim_path.clone()),
            "customer_1",
            "deployment_1",
        );
        let live = config.resolve_live_with_store(LicenseFloorStore::new(
            &floor_path,
            "customer_1",
            "deployment_1",
        ));
        assert_eq!(
            live.provider.evaluate(&request("pack.publish")).decision,
            EntitlementDecision::Allow
        );

        let mut tampered = claim;
        tampered.features.push("forged.unlock".into());
        fs::write(&claim_path, serde_json::to_vec(&tampered).unwrap()).unwrap();
        assert_eq!(
            live.provider.evaluate(&request("pack.publish")).decision,
            EntitlementDecision::Deny
        );
        let _ = fs::remove_file(claim_path);
        let _ = fs::remove_file(floor_path);
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
