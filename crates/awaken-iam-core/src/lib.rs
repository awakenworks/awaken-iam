//! Core IAM evaluation primitives.

mod authorization;
mod entitlement;
mod fake_provider;
mod github;
mod login;
mod provider;
mod session;

use std::collections::HashMap;
use std::collections::hash_map::Entry;

pub use authorization::{
    ActionPattern, AuthorizationTrace, DecisionReason, Effect, Grant, GrantId, GrantSubject,
    PolicySet, RoleBinding, RoleId, ScopeGraph,
};
pub use entitlement::{
    EntitlementCatalog, EntitlementEngine, EntitlementMode, EntitlementOutcome, EntitlementReason,
    EntitlementResolver, Plan, PlanId, PlanTier,
};
pub use fake_provider::{
    AuthorizeRedirect, AuthorizeRequest, FailureMode, FakeOidcProvider, FakeUser, IdTokenClaims,
    JsonWebKey, JsonWebKeySet, OidcDiscoveryDocument, OidcError, TokenRequest, TokenResponse,
    UserInfoResponse,
};
pub use github::{
    DEFAULT_AUTHORIZE_ENDPOINT, DEFAULT_TOKEN_ENDPOINT, GithubAccessToken, GithubEmail,
    GithubProviderAdapter, GithubTransport, GithubTransportError, GithubUser, SelectedEmail,
    TokenRequest as GithubTokenRequest, select_email,
};
pub use login::{
    BeginLogin, EntropySource, IssuedLogin, LoginAttempt, LoginSecrets, OAuthChallengeService,
    OsEntropy, PkceChallenge, PkceMethod,
};
pub use provider::{
    AuthorizationRedirect, AuthorizationUrlRequest, CallbackExchange, IdentityProviderAdapter,
    ProviderError,
};
pub use session::{EstablishSession, IssuedSession, SessionMinter, hash_session_token};

use awaken_iam_contract::{
    Account, AccountId, AuthorizationDecision, AuthorizationRequest, ExternalIdentity,
    ExternalIdentityClaims, ExternalIdentityKey, ExternalSubject, IdentityProviderKey,
    OAuthLoginState, OAuthLoginStateId, Session, SessionId, Timestamp,
};

/// Identifies which bound login value failed verification on callback.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LoginBinding {
    /// The opaque OAuth `state` value.
    State,
    /// The OIDC `nonce` value.
    Nonce,
    /// The PKCE code verifier.
    PkceVerifier,
}

/// Errors returned by IAM evaluation.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum IamError {
    /// The request could not be evaluated because required identity data is missing.
    #[error("missing principal")]
    MissingPrincipal,
    /// An external provider subject is already linked to an account.
    #[error("external identity is already linked")]
    DuplicateExternalIdentity {
        /// Provider key that issued the subject.
        provider_key: IdentityProviderKey,
        /// Provider-scoped subject.
        subject: ExternalSubject,
        /// Account already linked to this provider subject.
        existing_account_id: AccountId,
    },
    /// The requested external identity does not exist.
    #[error("external identity was not found")]
    ExternalIdentityNotFound {
        /// Provider key that issued the subject.
        provider_key: IdentityProviderKey,
        /// Provider-scoped subject.
        subject: ExternalSubject,
    },
    /// A login-state challenge with this id was already started.
    #[error("login state is already started")]
    DuplicateLoginState {
        /// Conflicting login-state id.
        id: OAuthLoginStateId,
    },
    /// The referenced login-state challenge does not exist.
    #[error("login state was not found")]
    LoginStateNotFound {
        /// Missing login-state id.
        id: OAuthLoginStateId,
    },
    /// The login-state challenge has already been consumed and cannot be reused.
    #[error("login state was already consumed")]
    LoginStateAlreadyConsumed {
        /// Consumed login-state id.
        id: OAuthLoginStateId,
    },
    /// The OIDC provider returned a validation error.
    #[error("provider validation error")]
    ProviderValidationError {
        /// The original error returned by the provider.
        error: String,
    },
    /// The login-state challenge failed to verify at least one of its OIDC bindings.
    #[error("login state binding verification failed")]
    LoginStateBindingFailed {
        /// Binding that failed.
        binding: LoginBinding,
    },
}

/// Authorization evaluator over an in-process [`PolicySet`].
///
/// Evaluation is default-deny: an empty policy denies every request. Grants and
/// role bindings are added to the [`PolicySet`] and resolved through the scope
/// graph, with deny effects taking precedence over allow.
#[derive(Debug, Default)]
pub struct IamCore {
    policy: PolicySet,
}

impl IamCore {
    /// Create an IAM core evaluator with an empty (default-deny) policy.
    pub fn new() -> Self {
        Self::default()
    }

    /// Create an IAM core evaluator backed by `policy`.
    pub fn with_policy(policy: PolicySet) -> Self {
        Self { policy }
    }

    /// Mutable access to the policy for registering grants, role bindings, and
    /// scope-graph links.
    pub fn policy_mut(&mut self) -> &mut PolicySet {
        &mut self.policy
    }

    /// Read-only access to the policy.
    pub fn policy(&self) -> &PolicySet {
        &self.policy
    }

    /// Evaluate authorization and return only the allow/deny decision.
    pub fn authorize(&self, request: &AuthorizationRequest) -> AuthorizationDecision {
        self.evaluate(request).decision
    }

    /// Evaluate authorization and return the full decision trace (decision,
    /// reason code, and matched grant/role ids).
    pub fn evaluate(&self, request: &AuthorizationRequest) -> AuthorizationTrace {
        self.policy.evaluate(request)
    }

    /// Evaluate entitlement. v1 starts as default-allow seam until billing / SKU
    /// management and true entitlement controls are wired in downstream.
    pub fn entitle(&self) -> EntitlementEngine {
        EntitlementEngine::default()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn authorize_denies_empty_policy_by_default() {
        let core = IamCore::new();
        let request = AuthorizationRequest {
            principal: awaken_iam_contract::PrincipalRef::Account {
                account_id: AccountId("test".into()),
            },
            action: awaken_iam_contract::ActionKey("pack.read".into()),
            scope: awaken_iam_contract::ScopeRef::Global,
        };
        assert_eq!(core.authorize(&request), AuthorizationDecision::Deny);
    }

    #[test]
    fn authorize_allows_through_a_loaded_policy() {
        let mut core = IamCore::new();
        core.policy_mut().add_grant(Grant {
            id: GrantId("g1".into()),
            subject: GrantSubject::Principal(awaken_iam_contract::PrincipalRef::Service {
                service_id: "svc".into(),
            }),
            action_pattern: ActionPattern("pack.publish".into()),
            scope: awaken_iam_contract::ScopeRef::Global,
            effect: Effect::Allow,
        });
        let request = AuthorizationRequest {
            principal: awaken_iam_contract::PrincipalRef::Service {
                service_id: "svc".into(),
            },
            action: awaken_iam_contract::ActionKey("pack.publish".into()),
            scope: awaken_iam_contract::ScopeRef::Global,
        };

        assert_eq!(core.authorize(&request), AuthorizationDecision::Allow);
        let trace = core.evaluate(&request);
        assert_eq!(trace.reason, DecisionReason::AllowedByGrant);
        assert_eq!(trace.matched_grants, vec![GrantId("g1".into())]);
    }

    #[test]
    fn entitlement_seam_defaults_allow() {
        assert_eq!(
            IamCore::new().entitle().resolve(&mut EntitlementResolver::default()),
            EntitlementOutcome::Allow
        );
    }
}
