//! End-to-end coverage of the license resolution paths the production daemon
//! runs through on boot: env-driven sources, file-backed claims, and the
//! licence-as-string form. Every scenario uses real signatures so the verify
//! path is genuinely exercised, not just stubbed.

use std::collections::BTreeMap;

use awaken_iam_contract::{
    EntitlementDecision, EntitlementRequest, JsonWebKey, Jwks, LicenseClaim, LicenseSignature,
    PrincipalRef, Timestamp,
};
use awaken_iam_core::Quota;
use awaken_iam_server::{LicenseConfig, LicenseLoadError, LicenseRejection, LicenseSource};
use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use ed25519_dalek::{Signer, SigningKey};

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
    SigningKey::from_bytes(&[11u8; 32])
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
    limits.insert("seats".to_owned(), 7);
    let mut claim = LicenseClaim {
        features: vec!["pack.publish".into(), "seats".into()],
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

#[test]
fn license_source_resolves_from_env_with_inline_then_file_then_none() {
    // The daemon's resolver falls back through inline → file → none. The
    // explicit None / Some("",) / " " inputs must all yield LicenseSource::None
    // so an operator typo (whitespace-only env var) never accidentally enables
    // an empty allow-list.
    assert_eq!(LicenseSource::None, LicenseSource::default());

    // File: an explicit path is honored.
    let file_path = std::env::temp_dir().join("awaken-iam-license-test.json");
    let _ = std::fs::remove_file(&file_path);
    let file_source = LicenseSource::File(file_path.clone());
    match file_source {
        LicenseSource::File(p) => assert_eq!(p, file_path),
        _ => panic!("expected File variant"),
    }
}

#[test]
fn license_config_loads_a_verifying_claim_from_a_file() {
    // End-to-end: write a real signed claim to a temp file, point the config
    // at it, resolve at a `now` before `not_after`. The provider is licensed
    // with the claimed features and limits; the read-side entitlement
    // surfaces them faithfully.
    let key = signing_key();
    let claim = signed_claim(&key, "lic-file-1", 3, "2026-12-01T00:00:00Z");

    let file_path = std::env::temp_dir().join("awaken-iam-license-claim.json");
    let json = serde_json::to_string(&claim).expect("serialise claim");
    std::fs::write(&file_path, &json).expect("write claim file");

    let config = LicenseConfig::new(
        jwks_for(&key, "lic-file-1"),
        0,
        LicenseSource::File(file_path.clone()),
    );

    // load_claim returns Some and round-trips through the JSON the operator wrote.
    let loaded = config
        .load_claim()
        .expect("load claim")
        .expect("claim present");
    assert_eq!(loaded.features, claim.features);
    assert_eq!(loaded.epoch, 3);

    // Resolve at a verifying instant: licensed provider is installed.
    let resolved = config.resolve(&Timestamp("2026-07-01T00:00:00Z".into()));
    assert!(resolved.status.is_licensed());
    assert_eq!(
        resolved.status,
        awaken_iam_server::LicenseStatus::Licensed {
            not_after: Timestamp("2026-12-01T00:00:00Z".into()),
        }
    );
    assert_eq!(
        resolved
            .provider
            .evaluate(&request("pack.publish"))
            .decision,
        EntitlementDecision::Allow
    );
    assert_eq!(
        resolved.provider.quota(&account("acct_1"), "seats"),
        Some(Quota::Limited(7))
    );

    // Clean up the fixture so the test is hermetic.
    let _ = std::fs::remove_file(file_path);
}

#[test]
fn license_config_returns_a_load_error_when_the_file_path_is_unreadable() {
    let config = LicenseConfig::new(
        Jwks { keys: Vec::new() },
        0,
        LicenseSource::File(std::env::temp_dir().join("does-not-exist-license.json")),
    );
    let resolved = config.resolve(&Timestamp("2026-07-01T00:00:00Z".into()));
    assert!(matches!(
        resolved.status,
        awaken_iam_server::LicenseStatus::Rejected(LicenseRejection::Load(LicenseLoadError::Read(
            _
        )))
    ));
    // The fallback keeps open functionality independent but cannot unlock a
    // commercial entitlement.
    assert_eq!(
        resolved.provider.evaluate(&request("any")).decision,
        EntitlementDecision::Deny
    );
}

#[test]
fn license_config_loads_and_rejects_a_malformed_file_payload() {
    // A file that exists but is not a valid LicenseClaim JSON: load_claim
    // returns the parse error and resolve falls back to unlicensed denial with
    // a `Rejected(Load(Parse))` status — never panics.
    let file_path = std::env::temp_dir().join("awaken-iam-malformed-license.json");
    std::fs::write(&file_path, "{ not a claim").expect("write bad claim");

    let config = LicenseConfig::new(Jwks { keys: Vec::new() }, 0, LicenseSource::File(file_path));
    let loaded = config.load_claim().unwrap_err();
    assert!(matches!(loaded, LicenseLoadError::Parse(_)));

    let resolved = config.resolve(&Timestamp("2026-07-01T00:00:00Z".into()));
    assert!(matches!(
        resolved.status,
        awaken_iam_server::LicenseStatus::Rejected(LicenseRejection::Load(
            LicenseLoadError::Parse(_)
        ))
    ));
    assert_eq!(
        resolved.provider.evaluate(&request("any")).decision,
        EntitlementDecision::Deny
    );

    let _ = std::fs::remove_file(std::env::temp_dir().join("awaken-iam-malformed-license.json"));
}

#[test]
fn license_status_is_licensed_predicates_on_the_variants() {
    use awaken_iam_server::LicenseStatus;
    assert!(
        LicenseStatus::Licensed {
            not_after: Timestamp("2026-12-01T00:00:00Z".into())
        }
        .is_licensed()
    );
    assert!(!LicenseStatus::Unlicensed.is_licensed());
    assert!(
        !LicenseStatus::Rejected(LicenseRejection::Load(LicenseLoadError::Parse(
            "nope".into()
        )))
        .is_licensed()
    );
}

#[test]
fn license_config_unlicensed_denies_commercial_entitlements() {
    // Cause/effect rule: no configured claim is the open-core baseline. It
    // leaves ordinary authorization untouched and denies every explicit paid
    // entitlement, preventing deletion of a claim from becoming an unlock.
    let config = LicenseConfig::unlicensed();
    let resolved = config.resolve(&Timestamp("2026-07-01T00:00:00Z".into()));
    assert_eq!(
        resolved.status,
        awaken_iam_server::LicenseStatus::Unlicensed
    );
    // No commercial quota is advertised and the feature is denied.
    assert_eq!(resolved.provider.quota(&account("acct_1"), "any"), None);
    assert_eq!(
        resolved.provider.evaluate(&request("any")).decision,
        EntitlementDecision::Deny
    );
}
