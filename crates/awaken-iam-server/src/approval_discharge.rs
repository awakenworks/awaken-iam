//! Approval discharge: convert a `RequireApproval` obligation into a
//! scope-narrowed, epoch-fenced capability token (ADR-0004 #3).
//!
//! When the authorization engine returns
//! [`AuthorizationDecision::RequireApproval`] it hands the caller an
//! [`ApprovalObligation`](awaken_iam_contract::ApprovalObligation) carrying a
//! content-addressed `obligation_id`. The obligation is discharged by calling
//! [`ApprovalDischargeService::discharge`], which mints a capability token
//! bound to that `obligation_id` — not by re-querying `authorize` and not by
//! adding a per-instance allow grant.
//!
//! ## Idempotency
//!
//! The service tracks every `obligation_id` it has already discharged. A
//! second call for the same `obligation_id` returns
//! [`DischargeOutcome::AlreadyDischarged`] without minting a new token, so no
//! second grant is ever issued.
//!
//! ## Epoch fencing
//!
//! Every minted token is stamped with the [`LeaseEpoch`] provided in the
//! [`DischargeRequest`]. Verification via [`verify_capability`] requires the
//! token's epoch to equal the current epoch; advancing the lease (on a grant
//! change, revocation, or sandbox re-provision) invalidates all outstanding
//! tokens in one step — no per-token bookkeeping is needed here.

use std::collections::HashSet;
use std::sync::Mutex;

use crate::access_token::AccessTokenAuthority;
use crate::capability_token::{CapabilityError, LeaseEpoch, MintCapability, mint_capability};

/// Request to discharge a `RequireApproval` obligation as a capability token.
#[derive(Debug, Clone)]
pub struct DischargeRequest {
    /// Content-addressed obligation id from the `RequireApproval` outcome.
    pub obligation_id: String,
    /// Issuer identifier of the minting deployment.
    pub iss: String,
    /// Principal the capability acts as.
    pub sub: String,
    /// Audience the capability is bound to.
    pub aud: String,
    /// Unique token id for this mint.
    pub jti: String,
    /// Issued-at Unix timestamp (seconds).
    pub iat: i64,
    /// Expiration Unix timestamp; must be strictly after `iat`.
    pub exp: i64,
    /// Lease epoch to stamp the token with; verification later requires an
    /// exact match against the current epoch.
    pub epoch: LeaseEpoch,
    /// Narrowed action scope set the token authorizes.
    pub scope: Vec<String>,
}

/// Outcome of a discharge attempt.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DischargeOutcome {
    /// The obligation was discharged for the first time; the signed capability
    /// token is the bearer that proves the discharge.
    Minted(String),
    /// The obligation was already discharged; no new grant was issued.
    AlreadyDischarged,
}

/// Errors raised during a discharge attempt.
#[derive(Debug, PartialEq, Eq, thiserror::Error)]
pub enum DischargeError {
    /// The capability token could not be minted.
    #[error(transparent)]
    Capability(#[from] CapabilityError),
}

/// Service that converts `RequireApproval` obligations into scope-narrowed,
/// epoch-fenced capability tokens.
///
/// The service enforces two invariants:
///
/// - **No double-grant.** The same `obligation_id` is discharged at most once.
///   A second call returns [`DischargeOutcome::AlreadyDischarged`].
/// - **Epoch fencing.** Every token is stamped with the [`LeaseEpoch`] in the
///   [`DischargeRequest`]. Verification via [`verify_capability`] rejects a
///   token whose epoch does not match the current lease, so advancing the
///   epoch (e.g. on a grant revocation) invalidates all outstanding tokens at
///   once — with no per-token state managed here.
///
/// [`verify_capability`]: crate::verify_capability
pub struct ApprovalDischargeService {
    authority: AccessTokenAuthority,
    discharged: Mutex<HashSet<String>>,
}

impl ApprovalDischargeService {
    /// Create a new service backed by the given signing authority.
    pub fn new(authority: AccessTokenAuthority) -> Self {
        Self {
            authority,
            discharged: Mutex::new(HashSet::new()),
        }
    }

    /// Discharge a `RequireApproval` obligation as a scope-narrowed,
    /// epoch-fenced capability token.
    ///
    /// On the **first** call for a given `obligation_id` the service mints a
    /// JWT capability token bound to the obligation and returns
    /// [`DischargeOutcome::Minted`]. On any **subsequent** call for the same
    /// `obligation_id` it returns [`DischargeOutcome::AlreadyDischarged`]
    /// without signing a new token — no second grant is ever issued.
    ///
    /// The returned token carries the `obligation_id` in its `obligation`
    /// claim and is stamped with `request.epoch`. Presenting the token to
    /// [`verify_capability`] with the same epoch proves the obligation was
    /// discharged; an epoch advance fences the token out without any action
    /// here.
    ///
    /// [`verify_capability`]: crate::verify_capability
    pub async fn discharge(
        &self,
        request: DischargeRequest,
    ) -> Result<DischargeOutcome, DischargeError> {
        let already = {
            let mut set = self.discharged.lock().unwrap();
            !set.insert(request.obligation_id.clone())
        };
        if already {
            return Ok(DischargeOutcome::AlreadyDischarged);
        }
        let token = mint_capability(
            &self.authority,
            MintCapability {
                iss: request.iss,
                sub: request.sub,
                aud: request.aud,
                jti: request.jti,
                iat: request.iat,
                exp: request.exp,
                epoch: request.epoch,
                scope: request.scope,
                obligation: Some(request.obligation_id),
            },
        )
        .await?;
        Ok(DischargeOutcome::Minted(token))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::access_token::{AccessTokenAuthority, LocalSeedSigner};
    use crate::capability_token::{CapabilityCheck, CapabilityError, verify_capability};

    fn authority() -> AccessTokenAuthority {
        AccessTokenAuthority::new(LocalSeedSigner::new("discharge-key", [7u8; 32]))
    }

    fn service() -> ApprovalDischargeService {
        ApprovalDischargeService::new(authority())
    }

    fn request(obligation_id: &str) -> DischargeRequest {
        DischargeRequest {
            obligation_id: obligation_id.into(),
            iss: "https://iam.example".into(),
            sub: "agent-1".into(),
            aud: "oversight".into(),
            jti: format!("jti-{obligation_id}"),
            iat: 1_900_000_000,
            exp: 1_900_003_600,
            epoch: LeaseEpoch::initial(),
            scope: vec!["oversight.approve".into()],
        }
    }

    #[tokio::test]
    async fn first_discharge_mints_a_token_bound_to_the_obligation() {
        let svc = service();
        let outcome = svc.discharge(request("obl_abc123")).await.unwrap();
        let token = match outcome {
            DischargeOutcome::Minted(t) => t,
            DischargeOutcome::AlreadyDischarged => panic!("expected Minted"),
        };

        let claims = verify_capability(
            &token,
            &authority().jwks(),
            CapabilityCheck {
                audience: "oversight",
                epoch: LeaseEpoch::initial(),
                now: 1_900_000_001,
            },
        )
        .unwrap();

        // The token is bound to the obligation.
        assert_eq!(claims.obligation.as_deref(), Some("obl_abc123"));
        // Scope and subject are carried through unchanged.
        assert_eq!(claims.scope, vec!["oversight.approve".to_owned()]);
        assert_eq!(claims.sub, "agent-1");
        assert_eq!(claims.epoch, LeaseEpoch::initial());
    }

    #[tokio::test]
    async fn same_obligation_id_discharged_twice_is_idempotent() {
        let svc = service();

        let first = svc.discharge(request("obl_idempotent")).await.unwrap();
        assert!(matches!(first, DischargeOutcome::Minted(_)));

        // Second call for the same obligation_id must not issue a new grant.
        let second = svc.discharge(request("obl_idempotent")).await.unwrap();
        assert_eq!(second, DischargeOutcome::AlreadyDischarged);
    }

    #[tokio::test]
    async fn different_obligation_ids_are_discharged_independently() {
        let svc = service();

        let first = svc.discharge(request("obl_one")).await.unwrap();
        assert!(matches!(first, DischargeOutcome::Minted(_)));

        // A different obligation id is a separate discharge — not blocked.
        let second = svc.discharge(request("obl_two")).await.unwrap();
        assert!(matches!(second, DischargeOutcome::Minted(_)));

        // But a third call for the first id is still blocked.
        let third = svc.discharge(request("obl_one")).await.unwrap();
        assert_eq!(third, DischargeOutcome::AlreadyDischarged);
    }

    #[tokio::test]
    async fn epoch_change_invalidates_outstanding_discharged_tokens() {
        let svc = service();
        let outcome = svc.discharge(request("obl_epoch_test")).await.unwrap();
        let token = match outcome {
            DischargeOutcome::Minted(t) => t,
            DischargeOutcome::AlreadyDischarged => panic!("expected Minted"),
        };
        let jwks = authority().jwks();

        // Token is valid at the epoch it was minted under.
        verify_capability(
            &token,
            &jwks,
            CapabilityCheck {
                audience: "oversight",
                epoch: LeaseEpoch::initial(),
                now: 1_900_000_001,
            },
        )
        .unwrap();

        // After the epoch advances the outstanding token is fenced out.
        let advanced = LeaseEpoch::initial().next();
        let err = verify_capability(
            &token,
            &jwks,
            CapabilityCheck {
                audience: "oversight",
                epoch: advanced,
                now: 1_900_000_001,
            },
        )
        .unwrap_err();
        assert_eq!(err, CapabilityError::EpochFenced);
    }

    #[tokio::test]
    async fn verification_checks_signature_audience_and_epoch() {
        let svc = service();
        let outcome = svc.discharge(request("obl_verify")).await.unwrap();
        let token = match outcome {
            DischargeOutcome::Minted(t) => t,
            DischargeOutcome::AlreadyDischarged => panic!("expected Minted"),
        };
        let jwks = authority().jwks();
        let epoch = LeaseEpoch::initial();
        let now = 1_900_000_001;

        // Wrong audience fails.
        let err = verify_capability(
            &token,
            &jwks,
            CapabilityCheck {
                audience: "wrong-service",
                epoch,
                now,
            },
        )
        .unwrap_err();
        assert_eq!(err, CapabilityError::AudienceMismatch);

        // Wrong epoch fails.
        let err = verify_capability(
            &token,
            &jwks,
            CapabilityCheck {
                audience: "oversight",
                epoch: epoch.next(),
                now,
            },
        )
        .unwrap_err();
        assert_eq!(err, CapabilityError::EpochFenced);

        // A token signed by a different key fails the signature check.
        let foreign_svc = ApprovalDischargeService::new(AccessTokenAuthority::new(
            LocalSeedSigner::new("discharge-key", [99u8; 32]),
        ));
        let foreign = match foreign_svc.discharge(request("obl_foreign")).await.unwrap() {
            DischargeOutcome::Minted(t) => t,
            DischargeOutcome::AlreadyDischarged => panic!("expected Minted"),
        };
        // Verify against the original authority's JWKS — the foreign key is not trusted.
        let err = verify_capability(
            &foreign,
            &jwks,
            CapabilityCheck {
                audience: "oversight",
                epoch,
                now,
            },
        )
        .unwrap_err();
        assert!(matches!(err, CapabilityError::Crypto(_)));
    }

    #[tokio::test]
    async fn discharge_never_re_queries_authorize_or_issues_per_instance_grant() {
        // Structural guarantee: the service holds only a signing authority; it
        // has no reference to an authorization engine or policy store, so it
        // cannot re-query authorize or add a grant — the type signature enforces
        // the invariant.
        //
        // We exercise the discharge path end-to-end to confirm the obligation
        // claim is the only authorization artifact produced.
        let svc = service();
        let outcome = svc.discharge(request("obl_structural")).await.unwrap();
        let token = match outcome {
            DischargeOutcome::Minted(t) => t,
            DischargeOutcome::AlreadyDischarged => panic!("expected Minted"),
        };
        let claims = verify_capability(
            &token,
            &authority().jwks(),
            CapabilityCheck {
                audience: "oversight",
                epoch: LeaseEpoch::initial(),
                now: 1_900_000_001,
            },
        )
        .unwrap();
        // The token's authorization artifact is the obligation binding, not a
        // grant id or a re-authorized decision.
        assert_eq!(claims.obligation.as_deref(), Some("obl_structural"));
        // No parent: this is a root capability (not an attenuated re-delegation).
        assert!(claims.parent.is_none());
    }
}
