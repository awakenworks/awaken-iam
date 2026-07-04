//! Three-valued enforcement decision and the fail-closed authorize entry point.
//!
//! [`authorize`] is the framework-neutral entry point for the authorization
//! step. It wraps the [`IamClient`] call and maps the
//! [`AuthorizationDecision`] into an [`Enforcement`] value. Because
//! [`IamClient::authorize`] already fails closed (a transport outage returns
//! [`AuthorizationDecision::Deny`]), [`Enforcement`] inherits that guarantee —
//! a transport failure always yields [`Enforcement::Deny`].
//!
//! [`Enforcement`] converts to [`ApiError`](crate::ApiError) at the product's
//! HTTP boundary. The two aliases [`Enforcement::to_ai_sdk`] and
//! [`Enforcement::to_ag_ui`] are dialect shims that exist so product adapters
//! can call the right name for their wire dialect; both currently delegate to
//! [`Enforcement::into_api_error`].

use awaken_iam_client::IamClient;
use awaken_iam_contract::{
    ActionKey, AuthorizationDecision, AuthorizationRequest, PrincipalRef, ScopeRef,
};

use crate::error::ApiError;

/// Three-valued IAM enforcement outcome.
///
/// Matches [`AuthorizationDecision`] one-for-one; the wrapper type lives here
/// so the guard owns the HTTP/error conversion and products do not reach into
/// the contract directly.
///
/// `deny > require_approval > allow > default-deny` is the precedence rule.
/// Transport errors map to [`Enforcement::Deny`] (fail-closed).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Enforcement {
    /// The action is permitted.
    Allow,
    /// The action is denied.
    Deny,
    /// The action is permitted only after the caller completes an approval step.
    RequireApproval,
}

impl Enforcement {
    /// Whether the action is unconditionally allowed (no approval gate).
    pub fn is_allowed(self) -> bool {
        self == Enforcement::Allow
    }

    /// Whether the action is denied.
    pub fn is_denied(self) -> bool {
        self == Enforcement::Deny
    }

    /// Whether the action requires an approval step before proceeding.
    pub fn requires_approval(self) -> bool {
        self == Enforcement::RequireApproval
    }

    /// Convert a non-Allow enforcement to a problem+JSON [`ApiError`].
    ///
    /// Returns `None` for [`Enforcement::Allow`] (no error needed) and `Some`
    /// for [`Enforcement::Deny`] and [`Enforcement::RequireApproval`] (both
    /// produce a `403 Forbidden`).
    pub fn into_api_error(self) -> Option<ApiError> {
        match self {
            Enforcement::Allow => None,
            Enforcement::Deny => Some(ApiError {
                r#type: "https://iam.awakenworks.io/problems/forbidden".into(),
                title: "Forbidden".into(),
                status: 403,
                detail: "The principal does not hold a grant for this action.".into(),
            }),
            Enforcement::RequireApproval => Some(ApiError {
                r#type: "https://iam.awakenworks.io/problems/approval-required".into(),
                title: "Approval Required".into(),
                status: 403,
                detail: "The action requires an approval step before it may proceed.".into(),
            }),
        }
    }

    /// Dialect alias for [`into_api_error`](Self::into_api_error) used by the
    /// AI SDK wire surface. Both currently resolve to the same structure.
    pub fn to_ai_sdk(self) -> Option<ApiError> {
        self.into_api_error()
    }

    /// Dialect alias for [`into_api_error`](Self::into_api_error) used by the
    /// AG-UI wire surface. Both currently resolve to the same structure.
    pub fn to_ag_ui(self) -> Option<ApiError> {
        self.into_api_error()
    }
}

impl From<AuthorizationDecision> for Enforcement {
    fn from(decision: AuthorizationDecision) -> Self {
        match decision {
            AuthorizationDecision::Allow => Enforcement::Allow,
            AuthorizationDecision::Deny => Enforcement::Deny,
            AuthorizationDecision::RequireApproval => Enforcement::RequireApproval,
        }
    }
}

/// Authorize a principal chain against `action` at `scope`, returning a
/// three-valued [`Enforcement`].
///
/// The chain is conjunctive: every link must be authorized for the result to be
/// [`Enforcement::Allow`]. Pass an empty `on_behalf_of` for a direct
/// (single-principal) call — the common case.
///
/// Fail-closed: a transport outage in the remote arm yields
/// [`Enforcement::Deny`] because [`IamClient::authorize`] never silently widens
/// access to allow.
pub fn authorize<C: IamClient>(
    principal: &PrincipalRef,
    on_behalf_of: &[PrincipalRef],
    action: ActionKey,
    scope: ScopeRef,
    client: &C,
) -> Enforcement {
    let request = AuthorizationRequest {
        principal: principal.clone(),
        on_behalf_of: on_behalf_of.to_vec(),
        action,
        scope,
    };
    Enforcement::from(client.authorize(request))
}

#[cfg(test)]
mod tests {
    use super::*;
    use awaken_iam_contract::{AccountId, EntitlementDecision, EntitlementRequest};

    struct AllowClient;
    impl IamClient for AllowClient {
        fn authorize(&self, _: AuthorizationRequest) -> AuthorizationDecision {
            AuthorizationDecision::Allow
        }
        fn check_entitlement(&self, _: EntitlementRequest) -> EntitlementDecision {
            EntitlementDecision::Allow
        }
    }

    struct DenyClient;
    impl IamClient for DenyClient {
        fn authorize(&self, _: AuthorizationRequest) -> AuthorizationDecision {
            AuthorizationDecision::Deny
        }
        fn check_entitlement(&self, _: EntitlementRequest) -> EntitlementDecision {
            EntitlementDecision::Deny
        }
    }

    struct ApprovalClient;
    impl IamClient for ApprovalClient {
        fn authorize(&self, _: AuthorizationRequest) -> AuthorizationDecision {
            AuthorizationDecision::RequireApproval
        }
        fn check_entitlement(&self, _: EntitlementRequest) -> EntitlementDecision {
            EntitlementDecision::Allow
        }
    }

    fn principal() -> PrincipalRef {
        PrincipalRef::Account {
            account_id: AccountId("acct_1".into()),
        }
    }

    #[test]
    fn allow_client_yields_allow() {
        let e = authorize(
            &principal(),
            &[],
            ActionKey("issue.read".into()),
            ScopeRef::Global,
            &AllowClient,
        );
        assert_eq!(e, Enforcement::Allow);
        assert!(e.is_allowed());
        assert!(!e.is_denied());
        assert!(!e.requires_approval());
    }

    #[test]
    fn deny_client_yields_deny() {
        let e = authorize(
            &principal(),
            &[],
            ActionKey("issue.delete".into()),
            ScopeRef::Global,
            &DenyClient,
        );
        assert_eq!(e, Enforcement::Deny);
        assert!(!e.is_allowed());
        assert!(e.is_denied());
    }

    #[test]
    fn approval_client_yields_require_approval() {
        let e = authorize(
            &principal(),
            &[],
            ActionKey("issue.close".into()),
            ScopeRef::Global,
            &ApprovalClient,
        );
        assert_eq!(e, Enforcement::RequireApproval);
        assert!(e.requires_approval());
    }

    #[test]
    fn deny_to_api_error_is_403_forbidden() {
        let err = Enforcement::Deny.into_api_error().unwrap();
        assert_eq!(err.status, 403);
        assert!(err.r#type.contains("forbidden"));
        assert!(!err.detail.is_empty());
    }

    #[test]
    fn approval_to_api_error_is_403_approval_required() {
        let err = Enforcement::RequireApproval.into_api_error().unwrap();
        assert_eq!(err.status, 403);
        assert!(err.r#type.contains("approval-required"));
    }

    #[test]
    fn allow_to_api_error_is_none() {
        assert!(Enforcement::Allow.into_api_error().is_none());
        assert!(Enforcement::Allow.to_ai_sdk().is_none());
        assert!(Enforcement::Allow.to_ag_ui().is_none());
    }

    #[test]
    fn to_ai_sdk_and_to_ag_ui_are_same_as_into_api_error() {
        for variant in [
            Enforcement::Allow,
            Enforcement::Deny,
            Enforcement::RequireApproval,
        ] {
            assert_eq!(variant.to_ai_sdk(), variant.into_api_error());
            assert_eq!(variant.to_ag_ui(), variant.into_api_error());
        }
    }

    #[test]
    fn from_authorization_decision_maps_all_variants() {
        assert_eq!(
            Enforcement::from(AuthorizationDecision::Allow),
            Enforcement::Allow
        );
        assert_eq!(
            Enforcement::from(AuthorizationDecision::Deny),
            Enforcement::Deny
        );
        assert_eq!(
            Enforcement::from(AuthorizationDecision::RequireApproval),
            Enforcement::RequireApproval
        );
    }

    #[test]
    fn delegation_chain_passes_through_to_client() {
        let agent = PrincipalRef::Service {
            service_id: "agent-1".into(),
        };
        let human = PrincipalRef::Account {
            account_id: AccountId("human".into()),
        };
        // AllowClient allows everything regardless of chain length.
        let e = authorize(
            &agent,
            &[human],
            ActionKey("issue.read".into()),
            ScopeRef::Global,
            &AllowClient,
        );
        assert_eq!(e, Enforcement::Allow);
    }
}
