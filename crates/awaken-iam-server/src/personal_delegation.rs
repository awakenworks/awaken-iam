//! Action-bound, short credentials backed by durable personal consent.
use crate::{AccessTokenAuthority, AccessTokenError};
use awaken_iam_contract::{
    Jwks, MintPersonalDelegationToken, PersonalDelegation, PersonalDelegationPurpose,
    PersonalDelegationTokenClaims,
};
pub const PERSONAL_DELEGATION_TOKEN_TYP: &str = "iam-personal-delegation+jwt";
pub const PERSONAL_DELEGATION_CLIENT_SCOPE: &str = "iam.personal-delegation";
pub const PERSONAL_DELEGATION_CONSENT_AUDIENCE: &str = "iam-personal-delegations";
pub const PERSONAL_DELEGATION_CONSENT_SCOPE: &str = "iam.personal-delegation.manage";

/// Signature and claim-family validation only. A consumer must additionally
/// bind its native route/target and ask IAM to evaluate current consent/policy.
pub fn verify_personal_delegation_token(
    token: &str,
    jwks: &Jwks,
    issuer: &str,
    audience: &str,
    now: i64,
) -> Result<PersonalDelegationTokenClaims, AccessTokenError> {
    let claims: PersonalDelegationTokenClaims =
        crate::access_token::verify_jwt(token, jwks, PERSONAL_DELEGATION_TOKEN_TYP)?;
    let binding = &claims.binding;
    if claims.iss != issuer
        || claims.aud != audience
        || claims.iat > now
        || claims.iat < 0
        || claims.exp <= now
        || claims.exp <= claims.iat
        || claims.exp > 253_402_300_799
        || claims.exp - claims.iat > 300
        || [
            &claims.sub,
            &claims.service_id,
            &claims.client_id,
            &claims.grant_id,
            &binding.target.id,
            &binding.action.0,
        ]
        .iter()
        .any(|s| s.trim().is_empty() || s.len() > 500)
        || binding.grant_id != claims.grant_id
        || binding.target.revision == 0
        || match binding.purpose {
            PersonalDelegationPurpose::Execute => binding.original_key.is_some(),
            PersonalDelegationPurpose::OriginalOutcome => binding
                .original_key
                .as_ref()
                .is_none_or(|s| s.trim().is_empty() || s.len() > 500),
        }
    {
        return Err(AccessTokenError::Malformed);
    }
    Ok(claims)
}

pub(crate) async fn mint(
    authority: &AccessTokenAuthority,
    grant: &PersonalDelegation,
    binding: MintPersonalDelegationToken,
    issuer: &str,
    now: i64,
) -> Result<String, AccessTokenError> {
    let exp = if binding.purpose == PersonalDelegationPurpose::Execute {
        (now + 300).min(grant.consent.valid_until)
    } else {
        now + 300
    };
    let claims = PersonalDelegationTokenClaims {
        iss: issuer.to_owned(),
        aud: grant.consent.audience.clone(),
        sub: grant.owner.0.clone(),
        service_id: grant.service_id.clone(),
        client_id: grant.consent.recipient_client_id.clone(),
        grant_id: grant.id.clone(),
        iat: now,
        exp,
        binding,
    };
    let token = authority
        .sign_jwt(PERSONAL_DELEGATION_TOKEN_TYP, &claims)
        .await?;
    verify_personal_delegation_token(&token, &authority.jwks(), issuer, &claims.aud, now)?;
    Ok(token)
}
