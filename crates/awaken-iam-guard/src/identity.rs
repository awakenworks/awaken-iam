//! Credential resolution: bearer token → principal + workspace.
//!
//! [`resolve`] is the framework-neutral entry point. It accepts any
//! [`TokenResolver`] — the guard's seam over token introspection — so the same
//! call site compiles for both the remote arm (delegates to
//! `POST /v1/tokens/introspect` via [`RemoteIamClient`](awaken_iam_client::RemoteIamClient))
//! and the embedded arm (delegates to an in-process [`IamServer`](awaken_iam_server::IamServer)
//! or equivalent).
//!
//! Token verification (argon2id hash comparison) always stays in IAM — a
//! product that calls `resolve` never holds the `secret_hash` and never
//! re-implements the check.

use awaken_iam_client::{AuthzTransport, IamClientMode, RemoteIamClient};
use awaken_iam_contract::{PrincipalRef, TokenIntrospectionRequest, WorkspaceId};

/// Principal + workspace resolved from a live bearer credential.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Identity {
    /// Principal the credential authenticates as.
    pub principal: PrincipalRef,
    /// Workspace the credential is bound to.
    pub workspace: WorkspaceId,
}

/// Error returned when a credential cannot be resolved to an [`Identity`].
///
/// The error is intentionally opaque: the caller learns only that the
/// credential does not authenticate — never whether it was syntactically
/// invalid, unknown, revoked, or expired. This mirrors the behaviour of the
/// introspection endpoint itself, which returns `401 Unauthorized` for all
/// failure branches.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum ResolveError {
    /// The credential is invalid, unknown, revoked, or expired.
    #[error("the credential does not authenticate")]
    Invalid,
}

/// Seam over token introspection used by [`resolve`].
///
/// Implement this trait for any type that can verify a bearer credential and
/// return the resulting [`Identity`]:
///
/// - [`RemoteIamClient<T>`] already implements it via
///   [`AuthzTransport::introspect_token`].
/// - [`IamClientMode<L, R>`] dispatches to whichever arm is selected, provided
///   both arms implement `TokenResolver`.
/// - Embedded deployments implement it against the in-process policy engine.
pub trait TokenResolver {
    /// Verify `token` and resolve it to an [`Identity`].
    ///
    /// Returns [`ResolveError::Invalid`] for any failure (invalid format,
    /// unknown prefix, wrong secret, revoked, expired) — the caller never
    /// learns which branch.
    fn resolve_token(&self, token: &str) -> Result<Identity, ResolveError>;
}

/// Resolve a bearer credential to an [`Identity`] via `resolver`.
///
/// This is the framework-neutral entry point for the resolve step. The
/// resolver is typically a [`RemoteIamClient`](awaken_iam_client::RemoteIamClient)
/// for remote deployments or an in-process engine wrapper for embedded
/// deployments.
///
/// # Errors
///
/// Returns [`ResolveError::Invalid`] when the credential does not authenticate
/// for any reason (network failure included) — resolution is fail-closed.
pub fn resolve<R: TokenResolver>(credential: &str, resolver: &R) -> Result<Identity, ResolveError> {
    resolver.resolve_token(credential)
}

impl<T: AuthzTransport> TokenResolver for RemoteIamClient<T> {
    fn resolve_token(&self, token: &str) -> Result<Identity, ResolveError> {
        self.introspect_token(&TokenIntrospectionRequest {
            token: token.to_owned(),
        })
        .map(|response| Identity {
            principal: response.principal,
            workspace: response.workspace,
        })
        .map_err(|_| ResolveError::Invalid)
    }
}

impl<L: TokenResolver, R: TokenResolver> TokenResolver for IamClientMode<L, R> {
    fn resolve_token(&self, token: &str) -> Result<Identity, ResolveError> {
        match self {
            IamClientMode::Local(local) => local.resolve_token(token),
            IamClientMode::Remote(remote) => remote.resolve_token(token),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use awaken_iam_client::RemoteError;
    use awaken_iam_contract::{
        AccountId, ApiTokenStatus, AuthorizationOutcome, AuthorizationRequest,
        BatchAuthorizationRequest, BatchAuthorizationResponse, EntitlementCheckResponse,
        EntitlementRequest, NamespaceId, PolicySnapshot, PrincipalRef, ResourceModelRegistered,
        ResourceModelRegistration, SignerSetSnapshot, TokenIntrospectionRequest,
        TokenIntrospectionResponse, WorkspaceId,
    };

    struct OkTransport;

    impl AuthzTransport for OkTransport {
        fn authorize(&self, _: &AuthorizationRequest) -> Result<AuthorizationOutcome, RemoteError> {
            unreachable!()
        }
        fn authorize_batch(
            &self,
            _: &BatchAuthorizationRequest,
        ) -> Result<BatchAuthorizationResponse, RemoteError> {
            unreachable!()
        }
        fn check_entitlement(
            &self,
            _: &EntitlementRequest,
        ) -> Result<EntitlementCheckResponse, RemoteError> {
            unreachable!()
        }
        fn register_resource_model(
            &self,
            _: &ResourceModelRegistration,
        ) -> Result<ResourceModelRegistered, RemoteError> {
            unreachable!()
        }
        fn fetch_snapshot(&self) -> Result<PolicySnapshot, RemoteError> {
            unreachable!()
        }
        fn fetch_signers(&self, _: &NamespaceId) -> Result<SignerSetSnapshot, RemoteError> {
            unreachable!()
        }
        fn introspect_token(
            &self,
            _request: &TokenIntrospectionRequest,
        ) -> Result<TokenIntrospectionResponse, RemoteError> {
            Ok(TokenIntrospectionResponse {
                principal: PrincipalRef::Account {
                    account_id: AccountId("acct_1".into()),
                },
                workspace: WorkspaceId("ws_1".into()),
                status: ApiTokenStatus::Active,
            })
        }
    }

    struct ErrTransport;

    impl AuthzTransport for ErrTransport {
        fn authorize(&self, _: &AuthorizationRequest) -> Result<AuthorizationOutcome, RemoteError> {
            unreachable!()
        }
        fn authorize_batch(
            &self,
            _: &BatchAuthorizationRequest,
        ) -> Result<BatchAuthorizationResponse, RemoteError> {
            unreachable!()
        }
        fn check_entitlement(
            &self,
            _: &EntitlementRequest,
        ) -> Result<EntitlementCheckResponse, RemoteError> {
            unreachable!()
        }
        fn register_resource_model(
            &self,
            _: &ResourceModelRegistration,
        ) -> Result<ResourceModelRegistered, RemoteError> {
            unreachable!()
        }
        fn fetch_snapshot(&self) -> Result<PolicySnapshot, RemoteError> {
            unreachable!()
        }
        fn fetch_signers(&self, _: &NamespaceId) -> Result<SignerSetSnapshot, RemoteError> {
            unreachable!()
        }
        fn introspect_token(
            &self,
            _request: &TokenIntrospectionRequest,
        ) -> Result<TokenIntrospectionResponse, RemoteError> {
            Err(RemoteError("token invalid".into()))
        }
    }

    #[test]
    fn remote_client_resolves_valid_token_to_identity() {
        let client = RemoteIamClient::new(OkTransport);
        let identity = resolve("sk-awaken-valid.token", &client).unwrap();
        assert_eq!(identity.workspace, WorkspaceId("ws_1".into()));
        assert!(matches!(
            identity.principal,
            PrincipalRef::Account { account_id } if account_id == AccountId("acct_1".into())
        ));
    }

    #[test]
    fn remote_client_fails_closed_on_transport_error() {
        let client = RemoteIamClient::new(ErrTransport);
        let err = resolve("sk-awaken-bad.token", &client).unwrap_err();
        assert_eq!(err, ResolveError::Invalid);
    }

    #[test]
    fn mode_switch_routes_to_remote_resolver() {
        let remote: IamClientMode<RemoteIamClient<ErrTransport>, RemoteIamClient<OkTransport>> =
            IamClientMode::Remote(RemoteIamClient::new(OkTransport));
        let identity = resolve("sk-awaken-valid.token", &remote).unwrap();
        assert_eq!(identity.workspace, WorkspaceId("ws_1".into()));
    }

    #[test]
    fn mode_switch_routes_to_local_resolver() {
        struct LocalResolver;
        impl TokenResolver for LocalResolver {
            fn resolve_token(&self, _token: &str) -> Result<Identity, ResolveError> {
                Ok(Identity {
                    principal: PrincipalRef::Service {
                        service_id: "local-svc".into(),
                    },
                    workspace: WorkspaceId("ws_local".into()),
                })
            }
        }
        let local: IamClientMode<LocalResolver, RemoteIamClient<ErrTransport>> =
            IamClientMode::Local(LocalResolver);
        let identity = resolve("any-token", &local).unwrap();
        assert_eq!(identity.workspace, WorkspaceId("ws_local".into()));
    }

    #[test]
    fn resolve_error_is_opaque() {
        // The error message must not reveal which branch failed (invalid/revoked/expired).
        let err = ResolveError::Invalid;
        let msg = err.to_string();
        assert!(!msg.contains("revoked"));
        assert!(!msg.contains("expired"));
        assert!(!msg.contains("invalid format"));
    }

    #[test]
    fn authorization_decision_is_deny_for_all_failure_branches() {
        // ErrTransport's error (transport failure) must also resolve to Invalid,
        // not to an Allow or a different variant.
        let client = RemoteIamClient::new(ErrTransport);
        assert_eq!(
            resolve("sk-awaken-anything.x", &client),
            Err(ResolveError::Invalid)
        );
    }
}
