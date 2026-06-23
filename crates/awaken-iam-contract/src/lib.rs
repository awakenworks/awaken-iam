//! Shared IAM contract types.
//!
//! This crate is the stable seam used by product services. It contains DTOs and
//! identifiers only; evaluation, persistence, and server code live elsewhere.

mod identity;
mod protocol;
mod trust;

use serde::{Deserialize, Serialize};

pub use identity::{
    Account, AccountStatus, ApiToken, ApiTokenId, ApiTokenPrefix, ApiTokenView, ExternalIdentity,
    ExternalIdentityClaims, ExternalIdentityId, ExternalIdentityKey, ExternalSubject,
    IdentityProviderConfig, IdentityProviderConfigId, IdentityProviderKey, IdentityProviderKind,
    JsonWebKey, Jwks, OAuthLoginState, OAuthLoginStateId, OpenIdProviderMetadata, RefreshToken,
    RefreshTokenChainId, RefreshTokenId, RefreshTokenView, Session, SessionId, SessionView,
    Timestamp, UserInfo,
};
pub use protocol::{
    AuthorizationOutcome, BatchAuthorizationRequest, BatchAuthorizationResponse,
    EntitlementCheckResponse, GrantEffect, GrantSnapshot, GrantSubjectRef, NamespaceOrgEdge,
    PolicySnapshot, ResourceParentEdge, RoleBindingSnapshot, ScopeGraphSnapshot, WorkspaceOrgEdge,
};
pub use trust::{
    NamespaceOwner, SignerKey, SignerKeyAlgorithm, SignerKeyFingerprint, SignerKeyId,
    SignerKeyStatus,
};

/// Global account identifier.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct AccountId(pub String);

/// Organization / owner identifier.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct OrgId(pub String);

/// Namespace identifier used for package publishing.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct NamespaceId(pub String);

/// Product workspace identifier.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct WorkspaceId(pub String);

/// Product project identifier.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct ProjectId(pub String);

/// Open resource-type discriminator registered by a product's resource model.
///
/// IAM never enumerates resource types; a product names its own (`"issue"`,
/// `"document"`, `"deployment"`, ...) and registers their scope edges as data,
/// so deep product hierarchies resolve through the same scope-graph walk without
/// the core depending on the product.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct ResourceType(pub String);

/// Identifier of a single resource instance within its [`ResourceType`].
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct ResourceId(pub String);

/// Actor making a request.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum PrincipalRef {
    /// A human/global account principal.
    Account { account_id: AccountId },
    /// A service account principal.
    Service { service_id: String },
    /// An API token principal.
    ApiToken { token_id: String },
}

/// Authorization scope.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum ScopeRef {
    /// Global platform scope.
    Global,
    /// Organization / owner scope.
    Org { org_id: OrgId },
    /// Package namespace scope.
    Namespace { namespace_id: NamespaceId },
    /// Workspace scope.
    Workspace { workspace_id: WorkspaceId },
    /// Project scope.
    Project {
        workspace_id: WorkspaceId,
        project_id: ProjectId,
    },
    /// Open product-resource scope.
    ///
    /// Anchors a grant at an arbitrary product resource (`issue:42`,
    /// `document:readme`, ...). Its place in the hierarchy is not inferred from
    /// the ids; it comes from parent edges a product registers through its
    /// resource model, so the scope-graph walk resolves arbitrarily deep
    /// hierarchies (leaf resource -> ... -> tenant root) without the core
    /// knowing the product.
    Resource {
        resource_type: ResourceType,
        resource_id: ResourceId,
    },
}

/// Action key checked by IAM.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct ActionKey(pub String);

/// Authorization request.
///
/// A request carries a principal *chain*: [`AuthorizationRequest::principal`] is
/// the acting caller, and [`AuthorizationRequest::on_behalf_of`] holds any
/// further links for delegated / on-behalf-of dispatch (for example an agent
/// acting for a human, `[human, agent]`). The chain is conjunctive — every link
/// must be authorized for the request to be allowed. A direct caller leaves
/// `on_behalf_of` empty, which is the common case.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AuthorizationRequest {
    /// Acting principal (the head of the principal chain).
    pub principal: PrincipalRef,
    /// Additional principals the caller acts on behalf of, evaluated
    /// conjunctively with `principal`. Empty for a direct caller.
    #[serde(default)]
    pub on_behalf_of: Vec<PrincipalRef>,
    /// Action being performed.
    pub action: ActionKey,
    /// Target scope.
    pub scope: ScopeRef,
}

impl AuthorizationRequest {
    /// Build a direct (single-principal) request with an empty delegation chain.
    pub fn direct(principal: PrincipalRef, action: ActionKey, scope: ScopeRef) -> Self {
        Self {
            principal,
            on_behalf_of: Vec::new(),
            action,
            scope,
        }
    }

    /// Iterate the full principal chain, acting principal first followed by each
    /// on-behalf-of link in order.
    pub fn principal_chain(&self) -> impl Iterator<Item = &PrincipalRef> {
        std::iter::once(&self.principal).chain(self.on_behalf_of.iter())
    }
}

/// Authorization decision.
///
/// The decision is three-valued. [`AuthorizationDecision::RequireApproval`] is a
/// real outcome distinct from allow and deny: IAM decides that the action is
/// permitted only once an approval step completes, and the caller executes that
/// approval (prompt, pause, resume). Precedence is
/// `deny > require_approval > allow > default-deny`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AuthorizationDecision {
    /// The operation is allowed.
    Allow,
    /// The operation is denied.
    Deny,
    /// The operation is permitted only after the caller completes an approval.
    RequireApproval,
}

/// Entitlement request for account-tier/product-plan checks.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EntitlementRequest {
    /// Requesting principal.
    pub principal: PrincipalRef,
    /// Operation, feature, or SKU key.
    pub entitlement: String,
    /// Optional resource coordinate.
    pub resource: Option<String>,
}

/// Entitlement decision.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EntitlementDecision {
    /// Entitlement permits the operation.
    Allow,
    /// Entitlement blocks the operation.
    Deny,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn authorization_request_defaults_to_an_empty_delegation_chain() {
        // A payload written before on-behalf-of existed still deserializes, and
        // the principal chain is just the acting principal.
        let json = r#"{"principal":{"kind":"account","account_id":"ada"},
            "action":"pack.read","scope":{"kind":"global"}}"#;
        let request: AuthorizationRequest = serde_json::from_str(json).unwrap();
        assert!(request.on_behalf_of.is_empty());
        let chain: Vec<&PrincipalRef> = request.principal_chain().collect();
        assert_eq!(chain, vec![&request.principal]);
    }

    #[test]
    fn principal_chain_orders_caller_before_delegates() {
        let human = PrincipalRef::Account {
            account_id: AccountId("ada".into()),
        };
        let agent = PrincipalRef::Service {
            service_id: "agent".into(),
        };
        let request = AuthorizationRequest {
            principal: agent.clone(),
            on_behalf_of: vec![human.clone()],
            action: ActionKey("issue.close".into()),
            scope: ScopeRef::Global,
        };
        let chain: Vec<&PrincipalRef> = request.principal_chain().collect();
        assert_eq!(chain, vec![&agent, &human]);
    }

    #[test]
    fn authorization_decision_is_three_valued() {
        let json = serde_json::to_string(&AuthorizationDecision::RequireApproval).unwrap();
        assert_eq!(json, "\"require_approval\"");
        let restored: AuthorizationDecision = serde_json::from_str(&json).unwrap();
        assert_eq!(restored, AuthorizationDecision::RequireApproval);
    }

    #[test]
    fn scope_ref_serializes_with_kind_tag() {
        let scope = ScopeRef::Namespace {
            namespace_id: NamespaceId("acme".into()),
        };
        let json = serde_json::to_string(&scope).unwrap();
        assert!(json.contains("namespace"));
        assert!(json.contains("acme"));
    }

    #[test]
    fn resource_scope_round_trips_with_kind_tag() {
        let scope = ScopeRef::Resource {
            resource_type: ResourceType("issue".into()),
            resource_id: ResourceId("42".into()),
        };
        let json = serde_json::to_string(&scope).unwrap();
        assert!(json.contains("\"kind\":\"resource\""));
        assert!(json.contains("issue"));
        assert!(json.contains("42"));

        let restored: ScopeRef = serde_json::from_str(&json).unwrap();
        assert_eq!(restored, scope);
    }

    #[test]
    fn account_has_no_email_identity_key() {
        let account = Account {
            id: AccountId("acct_1".into()),
            status: AccountStatus::Active,
            display_name: Some("Ada".into()),
            created_at: Timestamp("2026-06-19T00:00:00Z".into()),
            updated_at: Timestamp("2026-06-19T00:00:00Z".into()),
        };
        let json = serde_json::to_value(account).unwrap();
        assert!(json.get("email").is_none());
    }

    #[test]
    fn session_view_omits_token_hash() {
        let session = Session {
            id: SessionId("sess_1".into()),
            account_id: AccountId("acct_1".into()),
            token_hash: "secret-token-hash".into(),
            external_identity_id: Some(ExternalIdentityId("ext_1".into())),
            created_at: Timestamp("2026-06-19T00:00:00Z".into()),
            last_seen_at: Timestamp("2026-06-19T00:05:00Z".into()),
            expires_at: Timestamp("2026-06-20T00:00:00Z".into()),
            revoked_at: None,
        };
        let view = SessionView::from(&session);
        assert_eq!(view.session_id, session.id);
        assert_eq!(view.account_id, session.account_id);

        let json = serde_json::to_string(&view).unwrap();
        assert!(!json.contains("secret-token-hash"));
        assert!(!json.contains("token_hash"));
        assert!(json.contains("sess_1"));
    }

    #[test]
    fn api_token_view_omits_the_secret_hash() {
        let token = ApiToken {
            id: ApiTokenId("tok_1".into()),
            prefix: ApiTokenPrefix("pfx_abc".into()),
            principal: PrincipalRef::Service {
                service_id: "ci".into(),
            },
            secret_hash: "argon2id$secret-hash".into(),
            scope: vec![ActionKey("pack.publish".into())],
            created_at: Timestamp("2026-06-19T00:00:00Z".into()),
            expires_at: Some(Timestamp("2026-07-19T00:00:00Z".into())),
            revoked_at: None,
        };
        let view = ApiTokenView::from(&token);
        assert_eq!(view.id, token.id);
        assert_eq!(view.prefix, token.prefix);

        let json = serde_json::to_string(&view).unwrap();
        assert!(!json.contains("argon2id$secret-hash"));
        assert!(!json.contains("secret_hash"));
        assert!(json.contains("pfx_abc"));
    }

    #[test]
    fn api_token_liveness_tracks_revocation_and_expiry() {
        let mut token = ApiToken {
            id: ApiTokenId("tok_1".into()),
            prefix: ApiTokenPrefix("pfx_abc".into()),
            principal: PrincipalRef::Service {
                service_id: "ci".into(),
            },
            secret_hash: "hash".into(),
            scope: vec![ActionKey("pack.publish".into())],
            created_at: Timestamp("2026-06-19T00:00:00Z".into()),
            expires_at: Some(Timestamp("2026-06-20T00:00:00Z".into())),
            revoked_at: None,
        };
        assert!(token.is_live(&Timestamp("2026-06-19T12:00:00Z".into())));
        // At or past expiry the token is no longer live.
        assert!(!token.is_live(&Timestamp("2026-06-20T00:00:00Z".into())));

        // A token without an expiry only dies on revocation.
        token.expires_at = None;
        assert!(token.is_live(&Timestamp("2030-01-01T00:00:00Z".into())));
        token.revoked_at = Some(Timestamp("2026-06-19T06:00:00Z".into()));
        assert!(!token.is_live(&Timestamp("2026-06-19T12:00:00Z".into())));

        // Scope membership is an exact action match.
        assert!(token.authorizes(&ActionKey("pack.publish".into())));
        assert!(!token.authorizes(&ActionKey("pack.yank".into())));
    }

    #[test]
    fn external_identity_key_uses_provider_and_subject_not_email() {
        let claims = ExternalIdentityClaims {
            subject: ExternalSubject("sub_123".into()),
            email: Some("first@example.com".into()),
            email_verified: Some(true),
            display_name: Some("First Name".into()),
            username: None,
            avatar_url: None,
            locale: None,
        };
        let key = ExternalIdentityKey::from_claims(IdentityProviderKey("fake".into()), &claims);

        let mut changed_claims = claims.clone();
        changed_claims.email = Some("second@example.com".into());

        assert_eq!(
            key,
            ExternalIdentityKey::from_claims(IdentityProviderKey("fake".into()), &changed_claims)
        );
    }
}
