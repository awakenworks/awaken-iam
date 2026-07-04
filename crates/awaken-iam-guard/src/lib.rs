//! Framework-neutral IAM guard for cross-product reuse.
//!
//! Products (Oversight, awaken-next, managed-agents) all drive auth through
//! the same three steps:
//!
//! 1. **Resolve** a bearer credential to an [`Identity`] (principal + workspace)
//!    via token introspection — remote or embedded.
//! 2. **Authorize** a principal chain against an [`ActionKey`] and [`ScopeRef`],
//!    returning a three-valued [`Enforcement`] that is **fail-closed**: a
//!    transport outage yields [`Enforcement::Deny`], never a silent allow.
//! 3. **Provision** the IAM store: run schema migrations and seed the preset
//!    role catalog (enabled by the `provision` feature; embedded deployments only).
//!
//! The guard is generic over [`IamClient`] so the same call sites work for both
//! embedded (local) and remote deployments via [`IamClientMode`]. It carries no
//! axum or HTTP-framework types, so framework/version differences between
//! products never reach it.
//!
//! Per-product residue (stays **outside** this crate):
//! - The HTTP-framework binding (axum middleware / `Authorizer` impl).
//! - The product's action/scope → `ActionKey`/`ScopeRef` mapping.

mod enforcement;
mod error;
mod identity;
mod provision;

pub use enforcement::{Enforcement, authorize};
pub use error::ApiError;
pub use identity::{Identity, ResolveError, TokenResolver, resolve};
pub use provision::{ProvisionError, provision};

pub use awaken_iam_client::{IamClient, IamClientMode, RemoteIamClient};
pub use awaken_iam_contract::{ActionKey, PrincipalRef, ScopeRef, WorkspaceId};

#[cfg(test)]
mod tests {
    use super::*;
    use awaken_iam_contract::{
        AccountId, AuthorizationDecision, AuthorizationRequest, EntitlementDecision,
        EntitlementRequest,
    };

    struct AllowAll;

    impl IamClient for AllowAll {
        fn authorize(&self, _request: AuthorizationRequest) -> AuthorizationDecision {
            AuthorizationDecision::Allow
        }
        fn check_entitlement(&self, _request: EntitlementRequest) -> EntitlementDecision {
            EntitlementDecision::Allow
        }
    }

    impl TokenResolver for AllowAll {
        fn resolve_token(&self, _token: &str) -> Result<Identity, ResolveError> {
            Ok(Identity {
                principal: PrincipalRef::Account {
                    account_id: AccountId("acct_1".into()),
                },
                workspace: WorkspaceId("ws_1".into()),
            })
        }
    }

    struct DenyAll;

    impl IamClient for DenyAll {
        fn authorize(&self, _request: AuthorizationRequest) -> AuthorizationDecision {
            AuthorizationDecision::Deny
        }
        fn check_entitlement(&self, _request: EntitlementRequest) -> EntitlementDecision {
            EntitlementDecision::Deny
        }
    }

    impl TokenResolver for DenyAll {
        fn resolve_token(&self, _token: &str) -> Result<Identity, ResolveError> {
            Err(ResolveError::Invalid)
        }
    }

    #[test]
    fn resolve_returns_identity_from_token_resolver() {
        let client = AllowAll;
        let identity = resolve("sk-ant-test.token", &client).unwrap();
        assert_eq!(identity.workspace, WorkspaceId("ws_1".into()));
        assert!(matches!(
            identity.principal,
            PrincipalRef::Account { account_id } if account_id == AccountId("acct_1".into())
        ));
    }

    #[test]
    fn resolve_returns_error_for_invalid_credential() {
        let client = DenyAll;
        let err = resolve("bad-token", &client).unwrap_err();
        assert_eq!(err, ResolveError::Invalid);
    }

    #[test]
    fn authorize_allow_client_yields_allow_enforcement() {
        let client = AllowAll;
        let enforcement = authorize(
            &PrincipalRef::Account {
                account_id: AccountId("acct_1".into()),
            },
            &[],
            ActionKey("issue.read".into()),
            ScopeRef::Global,
            &client,
        );
        assert_eq!(enforcement, Enforcement::Allow);
        assert!(enforcement.is_allowed());
    }

    #[test]
    fn authorize_deny_client_yields_deny_enforcement() {
        let client = DenyAll;
        let enforcement = authorize(
            &PrincipalRef::Account {
                account_id: AccountId("acct_1".into()),
            },
            &[],
            ActionKey("issue.delete".into()),
            ScopeRef::Global,
            &client,
        );
        assert_eq!(enforcement, Enforcement::Deny);
        assert!(!enforcement.is_allowed());
    }

    #[test]
    fn deny_enforcement_converts_to_api_error_403() {
        let api_err = Enforcement::Deny.into_api_error();
        assert!(api_err.is_some());
        let err = api_err.unwrap();
        assert_eq!(err.status, 403);
        assert!(!err.r#type.is_empty());
    }

    #[test]
    fn allow_enforcement_produces_no_api_error() {
        assert!(Enforcement::Allow.into_api_error().is_none());
    }

    #[test]
    fn require_approval_enforcement_converts_to_api_error_403() {
        let api_err = Enforcement::RequireApproval.into_api_error();
        assert!(api_err.is_some());
        let err = api_err.unwrap();
        assert_eq!(err.status, 403);
    }

    #[test]
    fn iam_client_mode_dispatches_through_both_arms() {
        struct NoopTransport;
        impl awaken_iam_client::AuthzTransport for NoopTransport {
            fn authorize(
                &self,
                _: &awaken_iam_contract::AuthorizationRequest,
            ) -> Result<awaken_iam_contract::AuthorizationOutcome, awaken_iam_client::RemoteError>
            {
                unreachable!()
            }
            fn authorize_batch(
                &self,
                _: &awaken_iam_contract::BatchAuthorizationRequest,
            ) -> Result<
                awaken_iam_contract::BatchAuthorizationResponse,
                awaken_iam_client::RemoteError,
            > {
                unreachable!()
            }
            fn check_entitlement(
                &self,
                _: &awaken_iam_contract::EntitlementRequest,
            ) -> Result<awaken_iam_contract::EntitlementCheckResponse, awaken_iam_client::RemoteError>
            {
                unreachable!()
            }
            fn register_resource_model(
                &self,
                _: &awaken_iam_contract::ResourceModelRegistration,
            ) -> Result<awaken_iam_contract::ResourceModelRegistered, awaken_iam_client::RemoteError>
            {
                unreachable!()
            }
            fn fetch_snapshot(
                &self,
            ) -> Result<awaken_iam_contract::PolicySnapshot, awaken_iam_client::RemoteError>
            {
                unreachable!()
            }
            fn fetch_signers(
                &self,
                _: &awaken_iam_contract::NamespaceId,
            ) -> Result<awaken_iam_contract::SignerSetSnapshot, awaken_iam_client::RemoteError>
            {
                unreachable!()
            }
        }
        let local: IamClientMode<AllowAll, RemoteIamClient<NoopTransport>> =
            IamClientMode::Local(AllowAll);
        let enforcement = authorize(
            &PrincipalRef::Account {
                account_id: AccountId("acct_1".into()),
            },
            &[],
            ActionKey("issue.read".into()),
            ScopeRef::Global,
            &local,
        );
        assert_eq!(enforcement, Enforcement::Allow);
    }
}
