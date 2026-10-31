//! RFC 8693 token exchange between IAM's own access tokens (ADR-0017).
//!
//! Two uses are admitted, both selected by an administrator-owned
//! [`ClientTokenExchangePolicy`] on the authenticated client and both issuing
//! an ordinary IAM access token that relying parties verify with the same
//! JWKS and exact-audience rule as every other access token:
//!
//! | use | client | subject token `aud` | issued `sub` | issued `act` | lifetime |
//! |---|---|---|---|---|---|
//! | audience exchange | any registered client | the client itself | unchanged | none | ≤ 1 h and ≤ subject `exp` |
//! | delegation | confidential client with a delegation grant | the client, or a listed subject audience | unchanged | the client's service principal | ≤ 300 s and ≤ subject `exp` |
//!
//! The actor of a delegation is the **authenticated confidential client**
//! itself (RFC 8693 §1.1 allows client authentication to identify the actor).
//! No `actor_token` is accepted: IAM has no separate service credential a
//! command service could present, and a second proof would only duplicate the
//! client authentication. Everything else — other token types, nested
//! delegation, widened scopes, foreign or expired subject tokens — is refused
//! with the RFC 6749 / RFC 8693 error codes, and every outcome is audited.

use std::collections::BTreeSet;

use awaken_iam_contract::{AccountId, AccountStatus};
use awaken_iam_core::{
    ClientDelegation, ClientTokenExchangePolicy, EntropySource, OAuthProviderError,
    RegisteredClient,
};

use super::{AuthApi, AuthAuditEvent};
use crate::access_token::{
    AccessTokenActor, AccessTokenClaims, AccessTokenError, AccessTokenSubjectKind,
};
use crate::token_exchange::{
    BEARER_TOKEN_TYPE, ISSUED_TOKEN_TYPE_ACCESS_TOKEN, SUBJECT_TOKEN_TYPE_ACCESS_TOKEN,
};

/// Upper bound on an audience-exchanged token's lifetime, in seconds.
pub const AUDIENCE_EXCHANGE_MAX_LIFETIME_SECS: i64 = 3_600;
/// Upper bound on a delegated (`act`-bearing) token's lifetime, in seconds.
pub const DELEGATED_TOKEN_MAX_LIFETIME_SECS: i64 = 300;

/// RFC 8693 token-exchange request between IAM access tokens, as parsed from
/// the `POST /v1/oauth/token` form.
#[derive(Debug, Clone)]
pub struct AccessTokenExchange {
    /// Issuer this deployment stamps and requires in `iss`.
    pub issuer: String,
    /// Authenticating client id.
    pub client_id: String,
    /// Client secret; required for confidential clients.
    pub client_secret: Option<String>,
    /// The user's IAM access token.
    pub subject_token: String,
    /// Must be [`SUBJECT_TOKEN_TYPE_ACCESS_TOKEN`].
    pub subject_token_type: String,
    /// Refused when present: the authenticated client is the actor.
    pub actor_token: Option<String>,
    /// Refused when present, for the same reason as `actor_token`.
    pub actor_token_type: Option<String>,
    /// Optional; when present must be [`ISSUED_TOKEN_TYPE_ACCESS_TOKEN`].
    pub requested_token_type: Option<String>,
    /// Required single target audience.
    pub audience: Option<String>,
    /// RFC 8707 resource indicator; IAM targets by `audience` only.
    pub resource: Option<String>,
    /// Requested scopes; `None` inherits the subject token's scopes.
    pub scope: Option<Vec<String>>,
    /// Current time as unix seconds.
    pub now: i64,
}

/// A successfully exchanged IAM access token (RFC 8693 §2.2.1 response).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExchangedAccessToken {
    /// The issued compact `EdDSA` JWT.
    pub access_token: String,
    /// Always [`ISSUED_TOKEN_TYPE_ACCESS_TOKEN`].
    pub issued_token_type: &'static str,
    /// Always `Bearer`.
    pub token_type: &'static str,
    /// Remaining lifetime of the issued token, in seconds.
    pub expires_in: i64,
    /// Scopes carried by the issued token.
    pub scope: Vec<String>,
    /// `jti` of the issued token.
    pub jti: String,
    /// Actor recorded in the issued token, for a delegation.
    pub act: Option<AccessTokenActor>,
}

/// Why an access-token exchange was refused. Recorded verbatim in the audit
/// trail; the wire collapses it to [`oauth_error_code`](Self::oauth_error_code).
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum AccessTokenExchangeError {
    /// Unknown client or failed client authentication.
    #[error("client authentication failed")]
    InvalidClient,
    /// The authoritative client or account store was unavailable.
    #[error("token exchange storage is unavailable")]
    StorageUnavailable,
    /// The subject token type is not an IAM access token.
    #[error("unsupported subject_token_type")]
    UnsupportedSubjectTokenType,
    /// A token type other than an access token was requested.
    #[error("unsupported requested_token_type")]
    UnsupportedRequestedTokenType,
    /// An `actor_token` was presented; the authenticated client is the actor.
    #[error("actor_token is not supported; the authenticated client is the actor")]
    ActorTokenUnsupported,
    /// No target audience was requested.
    #[error("audience is required")]
    MissingAudience,
    /// A `resource` indicator was presented.
    #[error("resource indicators are not supported; use audience")]
    ResourceUnsupported,
    /// The client is not admitted to any token exchange.
    #[error("client is not admitted to token exchange")]
    ExchangeNotAdmitted,
    /// The requested audience is outside the client's exchange allowlists.
    #[error("requested audience is not admitted for this client")]
    AudienceNotAllowed,
    /// The requested scope is not a subset of the subject token and client.
    #[error("requested scope exceeds the subject token or client")]
    ScopeNotAllowed,
    /// The subject token did not verify or was not issued by this IAM.
    #[error("subject token is invalid")]
    SubjectTokenInvalid,
    /// The subject token is expired.
    #[error("subject token is expired")]
    SubjectTokenExpired,
    /// The subject token was revoked.
    #[error("subject token is revoked")]
    SubjectTokenRevoked,
    /// The subject token was not issued to an audience this exchange accepts.
    #[error("subject token audience is not accepted for this exchange")]
    SubjectAudienceMismatch,
    /// The subject token authenticates a service, not an end-user account.
    #[error("subject token does not authenticate an account")]
    SubjectNotAccount,
    /// The subject token is already delegated; chains are single-level.
    #[error("subject token is already delegated")]
    NestedDelegation,
    /// The subject account is missing or not active.
    #[error("subject account is not active")]
    SubjectAccountInactive,
    /// The signer could not mint the issued token.
    #[error("issued token could not be signed")]
    SigningFailed,
}

impl AccessTokenExchangeError {
    /// RFC 6749 §5.2 / RFC 8693 §2.2.2 error code for the wire.
    pub fn oauth_error_code(self) -> &'static str {
        match self {
            Self::InvalidClient => "invalid_client",
            Self::StorageUnavailable => "temporarily_unavailable",
            Self::SigningFailed => "server_error",
            Self::UnsupportedSubjectTokenType
            | Self::UnsupportedRequestedTokenType
            | Self::ActorTokenUnsupported
            | Self::MissingAudience => "invalid_request",
            Self::ResourceUnsupported | Self::AudienceNotAllowed => "invalid_target",
            Self::ExchangeNotAdmitted => "unauthorized_client",
            Self::ScopeNotAllowed => "invalid_scope",
            Self::SubjectTokenInvalid
            | Self::SubjectTokenExpired
            | Self::SubjectTokenRevoked
            | Self::SubjectAudienceMismatch
            | Self::SubjectNotAccount
            | Self::NestedDelegation
            | Self::SubjectAccountInactive => "invalid_grant",
        }
    }

    /// HTTP status paired with [`oauth_error_code`](Self::oauth_error_code).
    pub fn http_status(self) -> u16 {
        match self {
            Self::InvalidClient => 401,
            Self::StorageUnavailable => 503,
            Self::SigningFailed => 500,
            _ => 400,
        }
    }
}

/// The admitted use selected by the target audience.
enum ExchangeUse<'a> {
    Audience,
    Delegation(&'a ClientDelegation),
}

impl ExchangeUse<'_> {
    fn select<'p>(
        policy: &'p ClientTokenExchangePolicy,
        audience: &str,
    ) -> Result<ExchangeUse<'p>, AccessTokenExchangeError> {
        if policy.is_empty() {
            return Err(AccessTokenExchangeError::ExchangeNotAdmitted);
        }
        if let Some(delegation) = &policy.delegation
            && delegation.audiences.contains(audience)
        {
            return Ok(ExchangeUse::Delegation(delegation));
        }
        if policy.audiences.contains(audience) {
            return Ok(ExchangeUse::Audience);
        }
        Err(AccessTokenExchangeError::AudienceNotAllowed)
    }

    fn accepts_subject_audience(&self, client_id: &str, subject_audience: &str) -> bool {
        subject_audience == client_id
            || matches!(self, ExchangeUse::Delegation(delegation)
                if delegation.subject_audiences.contains(subject_audience))
    }

    fn max_lifetime(&self) -> i64 {
        match self {
            ExchangeUse::Audience => AUDIENCE_EXCHANGE_MAX_LIFETIME_SECS,
            ExchangeUse::Delegation(_) => DELEGATED_TOKEN_MAX_LIFETIME_SECS,
        }
    }

    fn actor(&self) -> Option<AccessTokenActor> {
        match self {
            ExchangeUse::Audience => None,
            ExchangeUse::Delegation(delegation) => Some(AccessTokenActor {
                sub: delegation.service_id.clone(),
                subject_kind: AccessTokenSubjectKind::Service,
            }),
        }
    }
}

/// The scopes the issued token carries, or `ScopeNotAllowed`.
///
/// An explicit request must be a subset of both the subject token and the
/// client's registered scopes. An omitted request inherits the subject
/// token's scopes narrowed to the client's registration, so an exchange can
/// never widen authority.
fn issued_scope(
    requested: Option<&[String]>,
    subject: &[String],
    client: &RegisteredClient,
) -> Result<Vec<String>, AccessTokenExchangeError> {
    let admitted =
        |scope: &String| subject.contains(scope) && client.allowed_scopes.contains(scope);
    match requested {
        Some(requested) if requested.iter().all(admitted) => {
            let mut seen = BTreeSet::new();
            Ok(requested
                .iter()
                .filter(|scope| seen.insert(scope.as_str()))
                .cloned()
                .collect())
        }
        Some(_) => Err(AccessTokenExchangeError::ScopeNotAllowed),
        None => Ok(subject
            .iter()
            .filter(|scope| admitted(scope))
            .cloned()
            .collect()),
    }
}

impl<E: EntropySource + Clone> AuthApi<E> {
    /// `POST /v1/oauth/token` (`grant_type=…:token-exchange`) between IAM
    /// access tokens: audience exchange or single-level delegation, selected by
    /// the authenticated client's administrator-owned policy.
    ///
    /// Every outcome is appended to the audit trail as
    /// [`AuthAuditEvent::AccessTokenExchanged`] or
    /// [`AuthAuditEvent::AccessTokenExchangeRejected`].
    pub async fn exchange_access_token(
        &mut self,
        request: AccessTokenExchange,
    ) -> Result<ExchangedAccessToken, AccessTokenExchangeError> {
        let client_id = request.client_id.clone();
        let now = request.now;
        let result = self.admit_and_mint(request).await;
        match &result {
            Ok((issued, claims)) => self.audit.push(AuthAuditEvent::AccessTokenExchanged {
                client_id,
                subject: claims.sub.clone(),
                actor: issued.act.as_ref().map(|actor| actor.sub.clone()),
                audience: claims.aud.clone(),
                scope: issued.scope.clone(),
                jti: issued.jti.clone(),
                subject_jti: claims.subject_jti.clone(),
                at: now,
            }),
            Err(reason) => self
                .audit
                .push(AuthAuditEvent::AccessTokenExchangeRejected {
                    client_id,
                    reason: *reason,
                    at: now,
                }),
        }
        result.map(|(issued, _)| issued)
    }

    async fn admit_and_mint(
        &mut self,
        request: AccessTokenExchange,
    ) -> Result<(ExchangedAccessToken, AuditCoordinates), AccessTokenExchangeError> {
        let client = self
            .oauth_provider
            .authenticate_client(&request.client_id, request.client_secret.as_deref())
            .map_err(|error| match error {
                OAuthProviderError::StorageUnavailable => {
                    AccessTokenExchangeError::StorageUnavailable
                }
                _ => AccessTokenExchangeError::InvalidClient,
            })?;
        if request.actor_token.is_some() || request.actor_token_type.is_some() {
            return Err(AccessTokenExchangeError::ActorTokenUnsupported);
        }
        if request.subject_token_type != SUBJECT_TOKEN_TYPE_ACCESS_TOKEN {
            return Err(AccessTokenExchangeError::UnsupportedSubjectTokenType);
        }
        if request
            .requested_token_type
            .as_deref()
            .is_some_and(|requested| requested != ISSUED_TOKEN_TYPE_ACCESS_TOKEN)
        {
            return Err(AccessTokenExchangeError::UnsupportedRequestedTokenType);
        }
        if request.resource.is_some() {
            return Err(AccessTokenExchangeError::ResourceUnsupported);
        }
        let audience = request
            .audience
            .clone()
            .filter(|audience| !audience.is_empty())
            .ok_or(AccessTokenExchangeError::MissingAudience)?;
        let exchange = ExchangeUse::select(&client.token_exchange, &audience)?;

        let subject = self.verified_subject(&request)?;
        if !exchange.accepts_subject_audience(&client.client_id, &subject.aud) {
            return Err(AccessTokenExchangeError::SubjectAudienceMismatch);
        }
        match self.accounts.get(&AccountId(subject.sub.clone())) {
            Ok(Some(account)) if account.status == AccountStatus::Active => {}
            Ok(_) => return Err(AccessTokenExchangeError::SubjectAccountInactive),
            Err(_) => return Err(AccessTokenExchangeError::StorageUnavailable),
        }
        let scope = issued_scope(request.scope.as_deref(), &subject.scope, &client)?;

        let exp = subject.exp.min(request.now + exchange.max_lifetime());
        let jti = self.mint_id("jti");
        let act = exchange.actor();
        let claims = AccessTokenClaims {
            iss: request.issuer,
            sub: subject.sub.clone(),
            subject_kind: AccessTokenSubjectKind::Account,
            aud: audience.clone(),
            exp,
            iat: request.now,
            jti: jti.clone(),
            scope: scope.clone(),
            act: act.clone(),
        };
        let access_token = self
            .tokens
            .mint(&claims)
            .await
            .map_err(|_| AccessTokenExchangeError::SigningFailed)?;
        Ok((
            ExchangedAccessToken {
                access_token,
                issued_token_type: ISSUED_TOKEN_TYPE_ACCESS_TOKEN,
                token_type: BEARER_TOKEN_TYPE,
                expires_in: exp - request.now,
                scope,
                jti,
                act,
            },
            AuditCoordinates {
                sub: subject.sub,
                aud: audience,
                subject_jti: subject.jti,
            },
        ))
    }

    /// Verify the subject token with IAM's own signature, revocation, issuer,
    /// validity-window, principal-kind and single-level delegation rules.
    fn verified_subject(
        &self,
        request: &AccessTokenExchange,
    ) -> Result<AccessTokenClaims, AccessTokenExchangeError> {
        let subject =
            self.verify_access_token(&request.subject_token)
                .map_err(|error| match error {
                    AccessTokenError::Revoked(_) => AccessTokenExchangeError::SubjectTokenRevoked,
                    _ => AccessTokenExchangeError::SubjectTokenInvalid,
                })?;
        if subject.iss != request.issuer || subject.iat > request.now {
            return Err(AccessTokenExchangeError::SubjectTokenInvalid);
        }
        if subject.exp <= request.now {
            return Err(AccessTokenExchangeError::SubjectTokenExpired);
        }
        if subject.subject_kind != AccessTokenSubjectKind::Account {
            return Err(AccessTokenExchangeError::SubjectNotAccount);
        }
        if subject.act.is_some() {
            return Err(AccessTokenExchangeError::NestedDelegation);
        }
        Ok(subject)
    }
}

/// Coordinates of a successful exchange recorded in the audit trail.
struct AuditCoordinates {
    sub: String,
    aud: String,
    subject_jti: String,
}

#[cfg(test)]
mod tests {
    use super::*;

    fn strings(values: &[&str]) -> Vec<String> {
        values.iter().map(|value| (*value).to_owned()).collect()
    }

    /// Scope decision table: issued = requested ⊆ subject ∩ client, or the
    /// subject's scopes narrowed to the client when nothing is requested.
    #[test]
    fn issued_scope_only_ever_narrows() {
        let client = RegisteredClient::public(
            "spa",
            vec!["https://spa.example/cb".into()],
            ["openid", "flow.read"],
        );
        let subject = strings(&["openid", "flow.read", "flow.write"]);
        assert_eq!(
            issued_scope(None, &subject, &client),
            Ok(strings(&["openid", "flow.read"]))
        );
        assert_eq!(
            issued_scope(
                Some(&strings(&["flow.read", "flow.read"])),
                &subject,
                &client
            ),
            Ok(strings(&["flow.read"]))
        );
        assert_eq!(issued_scope(Some(&[]), &subject, &client), Ok(Vec::new()));
        assert_eq!(
            issued_scope(Some(&strings(&["flow.write"])), &subject, &client),
            Err(AccessTokenExchangeError::ScopeNotAllowed),
            "outside the client registration"
        );
        assert_eq!(
            issued_scope(Some(&strings(&["flow.admin"])), &subject, &client),
            Err(AccessTokenExchangeError::ScopeNotAllowed),
            "outside the subject token"
        );
    }

    #[test]
    fn refusals_map_to_rfc_error_codes_and_statuses() {
        use AccessTokenExchangeError as E;
        for (error, code, status) in [
            (E::InvalidClient, "invalid_client", 401),
            (E::StorageUnavailable, "temporarily_unavailable", 503),
            (E::SigningFailed, "server_error", 500),
            (E::ActorTokenUnsupported, "invalid_request", 400),
            (E::MissingAudience, "invalid_request", 400),
            (E::UnsupportedSubjectTokenType, "invalid_request", 400),
            (E::UnsupportedRequestedTokenType, "invalid_request", 400),
            (E::ResourceUnsupported, "invalid_target", 400),
            (E::AudienceNotAllowed, "invalid_target", 400),
            (E::ExchangeNotAdmitted, "unauthorized_client", 400),
            (E::ScopeNotAllowed, "invalid_scope", 400),
            (E::SubjectTokenExpired, "invalid_grant", 400),
            (E::SubjectTokenRevoked, "invalid_grant", 400),
            (E::NestedDelegation, "invalid_grant", 400),
            (E::SubjectNotAccount, "invalid_grant", 400),
            (E::SubjectAudienceMismatch, "invalid_grant", 400),
            (E::SubjectAccountInactive, "invalid_grant", 400),
            (E::SubjectTokenInvalid, "invalid_grant", 400),
        ] {
            assert_eq!(error.oauth_error_code(), code, "{error:?}");
            assert_eq!(error.http_status(), status, "{error:?}");
        }
    }

    /// Use selection: the target audience alone picks the use; delegation
    /// subjects may come from listed audiences, audience exchange only from
    /// the client itself.
    #[test]
    fn target_audience_selects_exactly_one_use() {
        let policy = ClientTokenExchangePolicy {
            audiences: ["reports".to_owned()].into(),
            delegation: Some(ClientDelegation {
                service_id: "svc".into(),
                audiences: ["flow".to_owned()].into(),
                subject_audiences: ["web".to_owned()].into(),
            }),
        };
        let delegation = ExchangeUse::select(&policy, "flow").ok().unwrap();
        assert!(delegation.actor().is_some());
        assert_eq!(delegation.max_lifetime(), DELEGATED_TOKEN_MAX_LIFETIME_SECS);
        assert!(delegation.accepts_subject_audience("business", "web"));
        let audience = ExchangeUse::select(&policy, "reports").ok().unwrap();
        assert!(audience.actor().is_none());
        assert!(!audience.accepts_subject_audience("business", "web"));
        assert!(audience.accepts_subject_audience("business", "business"));
        assert_eq!(
            ExchangeUse::select(&policy, "billing").err(),
            Some(AccessTokenExchangeError::AudienceNotAllowed)
        );
        assert_eq!(
            ExchangeUse::select(&ClientTokenExchangePolicy::default(), "flow").err(),
            Some(AccessTokenExchangeError::ExchangeNotAdmitted)
        );
    }
}
