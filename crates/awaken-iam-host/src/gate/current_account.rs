//! Current direct-Account admission through the original remote IAM client.

use awaken_iam_contract::{AccountId, PrincipalRef};

use super::{AuthReject, GateInner, IamGate, remote_authentication_failure};

impl IamGate {
    /// Authenticate one direct Account JWT against this host's exact issuer and
    /// audience and observe its current native Account through UserInfo.
    ///
    /// Only a remote gate with both constraints installed can prove current
    /// Account identity. UserInfo receives the original bearer, and its subject
    /// must agree with the verified credential. API keys, Service subjects and
    /// delegated credentials are rejected before UserInfo. This synchronous
    /// method does not cache admission or supply membership, consent or PDP
    /// authority. Async hosts call it through their blocking boundary.
    pub fn authenticate_current_account(
        &self,
        token: &str,
        now_unix: i64,
    ) -> Result<AccountId, AuthReject> {
        let GateInner::Remote {
            client,
            jwks: Some(jwks),
        } = self.inner.as_ref()
        else {
            return Err(AuthReject::Unavailable);
        };
        if self.issuer.as_deref().is_none_or(str::is_empty)
            || self.audience.as_deref().is_none_or(str::is_empty)
        {
            return Err(AuthReject::Unavailable);
        }
        let verified = self.verify_jwt(token, jwks, now_unix)?;
        if verified.actor.is_some()
            || verified
                .access_token
                .is_none_or(|claims| claims.iat > now_unix)
        {
            return Err(AuthReject::Invalid);
        }
        let PrincipalRef::Account { account_id } = verified.principal else {
            return Err(AuthReject::Invalid);
        };
        let info = client
            .userinfo(token)
            .map_err(remote_authentication_failure)?;
        if info.sub != account_id.0 {
            return Err(AuthReject::Unavailable);
        }
        Ok(account_id)
    }
}

#[cfg(test)]
mod tests;
