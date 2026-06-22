//! Convenience facade for Awaken IAM library users.

pub use awaken_iam_client::IamClient;
pub use awaken_iam_contract::{
    Account, AccountId, AccountStatus, ActionKey, AuthorizationDecision, AuthorizationRequest,
    EntitlementDecision, EntitlementRequest, ExternalIdentity, ExternalIdentityClaims,
    ExternalIdentityId, ExternalIdentityKey, ExternalSubject, IdentityProviderConfig,
    IdentityProviderConfigId, IdentityProviderKey, IdentityProviderKind, NamespaceId,
    OAuthLoginState, OAuthLoginStateId, OrgId, PrincipalRef, ProjectId, ScopeRef, Session,
    SessionId, Timestamp, WorkspaceId,
};
pub use awaken_iam_core::{IamCore, IamError, IdentityDirectory};
pub use awaken_iam_server::IamServer;

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
