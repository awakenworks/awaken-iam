//! Attenuated capability tokens (permission mechanism 7).
//!
//! A capability token is a short-lived, **scope-narrowed**, epoch-**fenced**
//! bearer that a parent grants a child for sub-process / sandbox / worker
//! delegation. It is a compact JWT signed by the same asymmetric IAM key as an
//! access token ([`AccessTokenAuthority`]) and verified against the same
//! published [`Jwks`] — but it carries a distinct `typ` so the two families
//! cannot be replayed for one another, plus two extra fences over a plain access
//! token:
//!
//! - **Attenuation.** [`attenuate`] derives a child token whose authority is
//!   never more than its parent's: its scope set must be a subset, its audience
//!   identical, its epoch inherited, and its expiry no later. A parent therefore
//!   hands a sandbox *strictly less* authority for a *bounded* time, and can do
//!   so transitively (a child attenuates further).
//! - **Epoch fencing.** Every token is stamped with the issuing [`LeaseEpoch`].
//!   Verification ([`verify_capability`]) requires the token epoch to equal the
//!   current epoch, so advancing the lease ([`LeaseEpoch::next`]) — on a grant
//!   change, revocation, or sandbox re-provision — invalidates every outstanding
//!   token at once, without tracking them individually.
//!
//! Verification is the holder-independent path a delegate enforces with only the
//! public JWKS: it checks signature, audience, epoch, and expiry, and fails
//! closed on any mismatch. See [auth server](../../../docs/design/auth-server.md)
//! `#sessions-and-tokens` and [permission mechanisms].

use serde::{Deserialize, Serialize};
use std::collections::HashSet;

use awaken_iam_contract::Jwks;

use crate::access_token::{AccessTokenAuthority, AccessTokenError, verify_jwt};

/// JOSE `typ` header marking the capability-token family apart from access
/// tokens, so a capability token presented to an access-token verifier (or the
/// reverse) fails closed even though both are signed by the same key.
const CAPABILITY_TYP: &str = "cap+jwt";

/// Monotonic lease fence stamped into every capability token.
///
/// A capability is only valid while its epoch equals the lease's current epoch.
/// Advancing the epoch ([`next`](LeaseEpoch::next)) — when the underlying lease,
/// grant, or sandbox changes — invalidates all tokens minted under the prior
/// epoch in one step, with no per-token bookkeeping.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct LeaseEpoch(pub u64);

impl LeaseEpoch {
    /// The epoch a freshly provisioned lease starts at.
    pub fn initial() -> Self {
        Self(0)
    }

    /// The next epoch after a lease change; invalidates tokens at the old epoch.
    pub fn next(self) -> Self {
        Self(self.0 + 1)
    }
}

/// Claims carried in a capability-token JWT payload.
///
/// `exp`/`iat` are Unix-second timestamps as in an access token; `epoch` is the
/// [`LeaseEpoch`] the token is fenced to; `scope` is the granted action-scope
/// set; `parent` records the `jti` this token was attenuated from (absent for a
/// root capability) so a delegation chain is auditable.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CapabilityClaims {
    /// Issuer: the IAM deployment that minted the token.
    pub iss: String,
    /// Subject: the principal the capability acts as.
    pub sub: String,
    /// Audience: the service the capability may be presented to.
    pub aud: String,
    /// Expiration time as a Unix timestamp (seconds).
    pub exp: i64,
    /// Issued-at time as a Unix timestamp (seconds).
    pub iat: i64,
    /// Unique token id, enabling per-token audit and parent linkage.
    pub jti: String,
    /// Lease epoch the token is fenced to; verification requires an exact match.
    pub epoch: LeaseEpoch,
    /// Granted action scopes; an empty set authorizes nothing.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub scope: Vec<String>,
    /// `jti` of the parent this token was attenuated from; absent for a root.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub parent: Option<String>,
    /// `obligation_id` this capability discharges, when it was minted to satisfy
    /// a `RequireApproval` decision. Absent for a capability not tied to an
    /// approval. It binds the token to one obligation so the approval is
    /// discharged by presenting the token — never by re-querying authorize — and
    /// it is inherited unchanged by any attenuated child.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub obligation: Option<String>,
}

/// Request to mint a **root** capability token directly from the authority.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MintCapability {
    /// Issuer identifier of the minting deployment.
    pub iss: String,
    /// Principal the capability acts as.
    pub sub: String,
    /// Audience the capability is bound to.
    pub aud: String,
    /// Unique token id.
    pub jti: String,
    /// Issued-at Unix timestamp (seconds).
    pub iat: i64,
    /// Expiration Unix timestamp (seconds); must be strictly after `iat`.
    pub exp: i64,
    /// Lease epoch to fence the token to.
    pub epoch: LeaseEpoch,
    /// Granted action scopes.
    pub scope: Vec<String>,
    /// `obligation_id` this capability discharges, when minted to satisfy a
    /// `RequireApproval` decision; `None` for a capability not tied to one.
    pub obligation: Option<String>,
}

/// Request to derive an attenuated **child** capability from a parent token.
///
/// The child inherits the parent's issuer, audience, and epoch; the request may
/// only *narrow* — its `scope` must be a subset of the parent's and its `exp` no
/// later than the parent's. `sub` defaults to the parent's subject when `None`,
/// or names the delegate sub-process principal.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AttenuateCapability {
    /// Unique id for the child token.
    pub jti: String,
    /// Issued-at Unix timestamp (seconds) for the child.
    pub iat: i64,
    /// Child expiration Unix timestamp; must be `> iat` and `<= parent.exp`.
    pub exp: i64,
    /// Narrowed scope set; must be a subset of the parent's scope.
    pub scope: Vec<String>,
    /// Optional delegate subject; defaults to the parent's subject.
    pub sub: Option<String>,
}

/// Context a verifier checks a presented capability token against.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CapabilityCheck<'a> {
    /// Audience the verifier serves; the token's `aud` must equal it.
    pub audience: &'a str,
    /// Current lease epoch; the token's `epoch` must equal it.
    pub epoch: LeaseEpoch,
    /// Current Unix timestamp (seconds) used for the expiry check.
    pub now: i64,
}

/// Errors raised while minting, attenuating, or verifying capability tokens.
#[derive(Debug, PartialEq, Eq, thiserror::Error)]
pub enum CapabilityError {
    /// A signature, `kid`, algorithm, `typ`, or encoding check failed.
    #[error(transparent)]
    Crypto(#[from] AccessTokenError),
    /// The mint/attenuation window was not strictly forward (`exp <= iat`).
    #[error("capability expiry must be strictly after issued-at")]
    InvalidWindow,
    /// A child requested a scope not held by its parent (attenuation only narrows).
    #[error("attenuated scope must be a subset of the parent capability")]
    ScopeNotSubset,
    /// A child requested an expiry later than its parent's (delegation is bounded).
    #[error("attenuated expiry must not outlast the parent capability")]
    ExpiryNotBounded,
    /// The presented audience did not match the verifier's audience.
    #[error("capability audience mismatch")]
    AudienceMismatch,
    /// The token's epoch is not the current lease epoch; the lease has advanced.
    #[error("capability epoch is fenced out by a lease change")]
    EpochFenced,
    /// The token is past its expiry at the checked time.
    #[error("capability token has expired")]
    Expired,
}

/// Mint a root capability token signed by the authority's active key.
pub fn mint_capability(
    authority: &AccessTokenAuthority,
    request: MintCapability,
) -> Result<String, CapabilityError> {
    if request.exp <= request.iat {
        return Err(CapabilityError::InvalidWindow);
    }
    let claims = CapabilityClaims {
        iss: request.iss,
        sub: request.sub,
        aud: request.aud,
        exp: request.exp,
        iat: request.iat,
        jti: request.jti,
        epoch: request.epoch,
        scope: request.scope,
        parent: None,
        obligation: request.obligation,
    };
    Ok(authority.sign_jwt(CAPABILITY_TYP, &claims)?)
}

/// Derive an attenuated child capability from a presented `parent_token`.
///
/// The parent is first verified for signature and liveness against the current
/// lease (`current_epoch`, `now`); a parent that is epoch-fenced or expired
/// cannot delegate. The request may only narrow authority — scope must be a
/// subset and expiry no later than the parent's — and the child inherits the
/// parent's issuer, audience, and epoch. The child is signed afresh by the
/// authority and records the parent's `jti`.
pub fn attenuate(
    authority: &AccessTokenAuthority,
    parent_token: &str,
    current_epoch: LeaseEpoch,
    now: i64,
    request: AttenuateCapability,
) -> Result<String, CapabilityError> {
    let parent: CapabilityClaims = verify_jwt(parent_token, &authority.jwks(), CAPABILITY_TYP)?;

    if parent.epoch != current_epoch {
        return Err(CapabilityError::EpochFenced);
    }
    if now >= parent.exp {
        return Err(CapabilityError::Expired);
    }
    if request.exp <= request.iat {
        return Err(CapabilityError::InvalidWindow);
    }
    if request.exp > parent.exp {
        return Err(CapabilityError::ExpiryNotBounded);
    }
    let held: HashSet<&str> = parent.scope.iter().map(String::as_str).collect();
    if !request
        .scope
        .iter()
        .all(|scope| held.contains(scope.as_str()))
    {
        return Err(CapabilityError::ScopeNotSubset);
    }

    let child = CapabilityClaims {
        iss: parent.iss,
        sub: request.sub.unwrap_or(parent.sub),
        aud: parent.aud,
        exp: request.exp,
        iat: request.iat,
        jti: request.jti,
        epoch: parent.epoch,
        scope: request.scope,
        parent: Some(parent.jti),
        // A child cannot retarget the obligation it was minted under; the
        // approval binding is inherited unchanged down the delegation chain.
        obligation: parent.obligation,
    };
    Ok(authority.sign_jwt(CAPABILITY_TYP, &child)?)
}

/// Verify a presented capability token against `check`, returning its claims.
///
/// Runs the holder-independent fences in order: signature + `typ` (against the
/// published JWKS), audience, epoch, then expiry. Any mismatch fails closed. A
/// caller still enforces that the action it is about to perform is within the
/// returned [`CapabilityClaims::scope`].
pub fn verify_capability(
    token: &str,
    jwks: &Jwks,
    check: CapabilityCheck<'_>,
) -> Result<CapabilityClaims, CapabilityError> {
    let claims: CapabilityClaims = verify_jwt(token, jwks, CAPABILITY_TYP)?;
    if claims.aud != check.audience {
        return Err(CapabilityError::AudienceMismatch);
    }
    if claims.epoch != check.epoch {
        return Err(CapabilityError::EpochFenced);
    }
    if check.now >= claims.exp {
        return Err(CapabilityError::Expired);
    }
    Ok(claims)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::access_token::{SigningKeyMaterial, verify_access_token};

    fn authority() -> AccessTokenAuthority {
        AccessTokenAuthority::new(SigningKeyMaterial::new("cap-key-1", [9u8; 32]))
    }

    fn root_request() -> MintCapability {
        MintCapability {
            iss: "https://iam.example".into(),
            sub: "agent-parent".into(),
            aud: "sandbox-runner".into(),
            jti: "cap-root".into(),
            iat: 1_900_000_000,
            exp: 1_900_003_600,
            epoch: LeaseEpoch::initial(),
            scope: vec!["fs.read".into(), "fs.write".into(), "net.fetch".into()],
            obligation: None,
        }
    }

    fn check_at(epoch: LeaseEpoch, now: i64) -> CapabilityCheck<'static> {
        CapabilityCheck {
            audience: "sandbox-runner",
            epoch,
            now,
        }
    }

    #[test]
    fn root_capability_verifies_against_published_jwks() {
        let authority = authority();
        let token = mint_capability(&authority, root_request()).unwrap();

        let claims = verify_capability(
            &token,
            &authority.jwks(),
            check_at(LeaseEpoch::initial(), 1_900_000_001),
        )
        .unwrap();
        assert_eq!(claims.sub, "agent-parent");
        assert_eq!(claims.scope.len(), 3);
        assert_eq!(claims.parent, None);
        assert_eq!(claims.epoch, LeaseEpoch::initial());
    }

    #[test]
    fn attenuation_narrows_scope_and_records_the_parent() {
        let authority = authority();
        let parent = mint_capability(&authority, root_request()).unwrap();

        let child = attenuate(
            &authority,
            &parent,
            LeaseEpoch::initial(),
            1_900_000_001,
            AttenuateCapability {
                jti: "cap-child".into(),
                iat: 1_900_000_001,
                exp: 1_900_001_000,
                scope: vec!["fs.read".into()],
                sub: Some("sandbox-child".into()),
            },
        )
        .unwrap();

        let claims = verify_capability(
            &child,
            &authority.jwks(),
            check_at(LeaseEpoch::initial(), 1_900_000_002),
        )
        .unwrap();
        assert_eq!(claims.scope, vec!["fs.read".to_owned()]);
        assert_eq!(claims.sub, "sandbox-child");
        assert_eq!(claims.parent.as_deref(), Some("cap-root"));
        // The child never outlasts the parent.
        assert!(claims.exp <= root_request().exp);
    }

    #[test]
    fn capability_binds_to_an_obligation_and_a_child_inherits_it() {
        let authority = authority();
        // A capability minted to discharge a RequireApproval decision carries the
        // obligation id, so presenting the token is the approval — no re-query.
        let bound = mint_capability(
            &authority,
            MintCapability {
                obligation: Some("obl_2f9c1a".into()),
                ..root_request()
            },
        )
        .unwrap();
        let claims = verify_capability(
            &bound,
            &authority.jwks(),
            check_at(LeaseEpoch::initial(), 1_900_000_001),
        )
        .unwrap();
        assert_eq!(claims.obligation.as_deref(), Some("obl_2f9c1a"));

        // A delegated child inherits the same obligation binding unchanged.
        let child = attenuate(
            &authority,
            &bound,
            LeaseEpoch::initial(),
            1_900_000_001,
            AttenuateCapability {
                jti: "cap-child".into(),
                iat: 1_900_000_001,
                exp: 1_900_001_000,
                scope: vec!["fs.read".into()],
                sub: None,
            },
        )
        .unwrap();
        let child_claims = verify_capability(
            &child,
            &authority.jwks(),
            check_at(LeaseEpoch::initial(), 1_900_000_002),
        )
        .unwrap();
        assert_eq!(child_claims.obligation.as_deref(), Some("obl_2f9c1a"));

        // A capability not tied to an approval carries no obligation binding.
        let unbound = mint_capability(&authority, root_request()).unwrap();
        let unbound_claims = verify_capability(
            &unbound,
            &authority.jwks(),
            check_at(LeaseEpoch::initial(), 1_900_000_001),
        )
        .unwrap();
        assert!(unbound_claims.obligation.is_none());
    }

    #[test]
    fn attenuation_cannot_widen_scope_or_extend_expiry() {
        let authority = authority();
        let parent = mint_capability(&authority, root_request()).unwrap();

        // A scope the parent does not hold is refused.
        let widened = attenuate(
            &authority,
            &parent,
            LeaseEpoch::initial(),
            1_900_000_001,
            AttenuateCapability {
                jti: "cap-child".into(),
                iat: 1_900_000_001,
                exp: 1_900_001_000,
                scope: vec!["fs.read".into(), "admin.all".into()],
                sub: None,
            },
        )
        .unwrap_err();
        assert_eq!(widened, CapabilityError::ScopeNotSubset);

        // An expiry beyond the parent's is refused.
        let extended = attenuate(
            &authority,
            &parent,
            LeaseEpoch::initial(),
            1_900_000_001,
            AttenuateCapability {
                jti: "cap-child".into(),
                iat: 1_900_000_001,
                exp: root_request().exp + 1,
                scope: vec!["fs.read".into()],
                sub: None,
            },
        )
        .unwrap_err();
        assert_eq!(extended, CapabilityError::ExpiryNotBounded);
    }

    #[test]
    fn a_lease_epoch_change_invalidates_outstanding_tokens() {
        let authority = authority();
        let token = mint_capability(&authority, root_request()).unwrap();
        let jwks = authority.jwks();

        // Valid at the epoch it was minted under.
        verify_capability(
            &token,
            &jwks,
            check_at(LeaseEpoch::initial(), 1_900_000_001),
        )
        .unwrap();

        // The lease advances; the outstanding token is fenced out at once.
        let advanced = LeaseEpoch::initial().next();
        let err = verify_capability(&token, &jwks, check_at(advanced, 1_900_000_001)).unwrap_err();
        assert_eq!(err, CapabilityError::EpochFenced);

        // A stale parent can no longer delegate either.
        let err = attenuate(
            &authority,
            &token,
            advanced,
            1_900_000_001,
            AttenuateCapability {
                jti: "cap-child".into(),
                iat: 1_900_000_001,
                exp: 1_900_001_000,
                scope: vec!["fs.read".into()],
                sub: None,
            },
        )
        .unwrap_err();
        assert_eq!(err, CapabilityError::EpochFenced);
    }

    #[test]
    fn audience_and_expiry_are_enforced() {
        let authority = authority();
        let token = mint_capability(&authority, root_request()).unwrap();
        let jwks = authority.jwks();

        let wrong_aud = verify_capability(
            &token,
            &jwks,
            CapabilityCheck {
                audience: "other-service",
                epoch: LeaseEpoch::initial(),
                now: 1_900_000_001,
            },
        )
        .unwrap_err();
        assert_eq!(wrong_aud, CapabilityError::AudienceMismatch);

        // At or past expiry the token is rejected.
        let expired = verify_capability(
            &token,
            &jwks,
            check_at(LeaseEpoch::initial(), root_request().exp),
        )
        .unwrap_err();
        assert_eq!(expired, CapabilityError::Expired);
    }

    #[test]
    fn a_capability_token_is_not_accepted_as_an_access_token() {
        let authority = authority();
        let token = mint_capability(&authority, root_request()).unwrap();

        // The shared key signs both families, but the `typ` fence keeps a
        // capability token from being replayed at an access-token verifier.
        let err = verify_access_token(&token, &authority.jwks()).unwrap_err();
        assert_eq!(
            err,
            AccessTokenError::UnexpectedType {
                expected: "JWT".into(),
                found: "cap+jwt".into(),
            }
        );
    }

    #[test]
    fn a_tampered_capability_fails_the_signature_check() {
        let authority = authority();
        let token = mint_capability(&authority, root_request()).unwrap();
        let jwks = authority.jwks();

        // Flipping the last byte of the signature breaks verification.
        let mut tampered = token.clone();
        let last = tampered.pop().unwrap();
        tampered.push(if last == 'A' { 'B' } else { 'A' });
        let err = verify_capability(
            &tampered,
            &jwks,
            check_at(LeaseEpoch::initial(), 1_900_000_001),
        )
        .unwrap_err();
        assert!(matches!(err, CapabilityError::Crypto(_)));

        // A capability minted by a different key does not verify here.
        let other = AccessTokenAuthority::new(SigningKeyMaterial::new("cap-key-1", [3u8; 32]));
        let forged = mint_capability(&other, root_request()).unwrap();
        let err = verify_capability(
            &forged,
            &jwks,
            check_at(LeaseEpoch::initial(), 1_900_000_001),
        )
        .unwrap_err();
        assert_eq!(
            err,
            CapabilityError::Crypto(AccessTokenError::SignatureInvalid)
        );

        // A non-forward window is refused at mint time.
        let mut bad = root_request();
        bad.exp = bad.iat;
        assert_eq!(
            mint_capability(&authority, bad).unwrap_err(),
            CapabilityError::InvalidWindow
        );
    }

    #[test]
    fn attenuation_can_be_chained_transitively() {
        let authority = authority();
        let parent = mint_capability(&authority, root_request()).unwrap();

        let child = attenuate(
            &authority,
            &parent,
            LeaseEpoch::initial(),
            1_900_000_001,
            AttenuateCapability {
                jti: "cap-child".into(),
                iat: 1_900_000_001,
                exp: 1_900_002_000,
                scope: vec!["fs.read".into(), "net.fetch".into()],
                sub: None,
            },
        )
        .unwrap();

        // The grandchild narrows further and stays within the child's bound.
        let grandchild = attenuate(
            &authority,
            &child,
            LeaseEpoch::initial(),
            1_900_000_002,
            AttenuateCapability {
                jti: "cap-grandchild".into(),
                iat: 1_900_000_002,
                exp: 1_900_001_500,
                scope: vec!["fs.read".into()],
                sub: None,
            },
        )
        .unwrap();

        let claims = verify_capability(
            &grandchild,
            &authority.jwks(),
            check_at(LeaseEpoch::initial(), 1_900_000_003),
        )
        .unwrap();
        assert_eq!(claims.scope, vec!["fs.read".to_owned()]);
        assert_eq!(claims.parent.as_deref(), Some("cap-child"));

        // A grandchild may not re-widen beyond its immediate parent.
        let err = attenuate(
            &authority,
            &child,
            LeaseEpoch::initial(),
            1_900_000_002,
            AttenuateCapability {
                jti: "cap-bad".into(),
                iat: 1_900_000_002,
                exp: 1_900_001_500,
                scope: vec!["fs.write".into()],
                sub: None,
            },
        )
        .unwrap_err();
        assert_eq!(err, CapabilityError::ScopeNotSubset);
    }
}
