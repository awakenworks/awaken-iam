//! Convenience facade for Awaken IAM library users.

pub use awaken_iam_client::IamClient;
pub use awaken_iam_contract::{
    Account, AccountId, AccountStatus, ActionKey, AuthorizationDecision, AuthorizationRequest,
    EntitlementDecision, EntitlementRequest, ExternalIdentity, ExternalIdentityClaims,
    ExternalIdentityId, ExternalIdentityKey, ExternalSubject, IdentityProviderConfig,
    IdentityProviderConfigId, IdentityProviderKey, IdentityProviderKind, NamespaceId,
    OAuthLoginState, OAuthLoginStateId, OrgId, PrincipalRef, ProjectId, ScopeRef, Session,
    SessionId, SessionView, Timestamp, WorkspaceId,
};
pub use awaken_iam_core::{
    BeginLogin, EntropySource, EstablishSession, IamCore, IamError, IdentityDirectory, IssuedLogin,
    IssuedSession, LoginAttempt, LoginBinding, LoginSecrets, OAuthChallengeService, OsEntropy,
    PkceChallenge, PkceMethod, SessionDirectory, SessionMinter, hash_session_token,
};
pub use awaken_iam_server::{
    AuthApi, AuthApiError, AuthAuditEvent, AuthFailureReason, CallbackOutcome, CallbackRequest,
    DEFAULT_LOGIN_COOKIE_NAME, DEFAULT_SESSION_COOKIE_NAME, EstablishedSession, IamServer,
    LinkIdentity, LogoutOutcome, ProviderRegistration, ProviderSummary, ReturnToDecision,
    ReturnToPolicy, SameSite, SessionCookieConfig, SessionGateway, StartLogin, StartLoginOutcome,
    UnlinkIdentity,
};

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn facade_reexports_server_and_contract() {
        let server = IamServer::new();
        let decision = server.authorize(AuthorizationRequest {
            principal: PrincipalRef::Service {
                service_id: "svc".into(),
            },
            action: ActionKey("pack.publish".into()),
            scope: ScopeRef::Global,
        });
        assert_eq!(decision, AuthorizationDecision::Deny);
    }
}
