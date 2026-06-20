//! Identity provider adapter interface.
//!
//! Core IAM owns the login *loop* — minting and verifying challenges, resolving
//! provider subjects to accounts, and establishing sessions — but it must never
//! hardcode a specific provider's wire flow. Each provider family (fake, OAuth2,
//! OIDC) speaks its own dialect of authorization-URL parameters and token/userinfo
//! exchange, and those details live behind [`IdentityProviderAdapter`].
//!
//! An adapter answers exactly two questions for the front and back halves of the
//! login loop:
//!
//! 1. *Where do we send the browser?* — [`IdentityProviderAdapter::authorization_url`]
//!    turns a [`IdentityProviderConfig`] plus the freshly minted, cleartext
//!    [`AuthorizationUrlRequest`] (state, optional nonce, optional PKCE challenge)
//!    into the provider's authorization redirect.
//! 2. *Who came back?* — [`IdentityProviderAdapter::exchange_callback`] turns the
//!    provider callback ([`CallbackExchange`]) into normalized
//!    [`ExternalIdentityClaims`], so the rest of IAM only ever sees the
//!    provider-agnostic claim shape.
//!
//! Challenge generation, single-use/expiry enforcement, and constant-time binding
//! verification stay in [`crate::OAuthChallengeService`]; the adapter is the only
//! place provider-specific construction and exchange may occur. The trait is
//! object-safe so a deployment can hold a registry of `dyn` adapters keyed by
//! [`IdentityProviderKey`].

use awaken_iam_contract::{ExternalIdentityClaims, IdentityProviderConfig, IdentityProviderKind};

use crate::PkceChallenge;

/// Inputs needed to construct a provider authorization redirect.
///
/// Every field is the *cleartext* value minted for this pending login. The state,
/// nonce, and PKCE verifier hashes are persisted separately in the
/// [`OAuthLoginState`](awaken_iam_contract::OAuthLoginState); the adapter only
/// receives the cleartext so it can place it on the wire.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuthorizationUrlRequest {
    /// Absolute callback URL the provider redirects back to after consent.
    pub redirect_uri: String,
    /// Cleartext OAuth `state` value to embed and echo back.
    pub state: String,
    /// Cleartext OIDC `nonce`, when the flow minted one.
    pub nonce: Option<String>,
    /// PKCE challenge derived from the minted verifier, when the flow minted one.
    pub pkce_challenge: Option<PkceChallenge>,
    /// OAuth scopes to request from the provider.
    pub scopes: Vec<String>,
}

/// The redirect an adapter produces to begin a login.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuthorizationRedirect {
    /// Fully constructed authorization endpoint URL including query parameters.
    pub url: String,
}

/// Values presented by the provider on the callback, exchanged for claims.
///
/// The `state` echoed on the callback is verified by
/// [`crate::OAuthChallengeService::complete_login`], not the adapter; the adapter
/// is responsible only for turning the authorization `code` (and, for PKCE flows,
/// the verifier) into normalized claims.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CallbackExchange {
    /// Callback URL registered for this flow; some providers require it to match.
    pub redirect_uri: String,
    /// Authorization `code` returned by the provider.
    pub code: String,
    /// Cleartext PKCE verifier to redeem the code, when the flow used PKCE.
    pub pkce_verifier: Option<String>,
}

/// Errors an [`IdentityProviderAdapter`] can return.
///
/// These are provider-flow failures kept distinct from [`crate::IamError`], which
/// governs the login-loop invariants. A deployment maps adapter failures to its
/// own callback responses.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum ProviderError {
    /// The provider configuration lacked a field this adapter requires (for
    /// example a missing authorization endpoint or client id).
    #[error("provider configuration is missing required field: {field}")]
    MissingConfiguration {
        /// Name of the absent configuration field.
        field: &'static str,
    },
    /// The adapter was handed a configuration for a provider family it does not
    /// serve.
    #[error("provider kind mismatch: adapter serves {expected:?} but config is {actual:?}")]
    UnsupportedProviderKind {
        /// Provider family this adapter implements.
        expected: IdentityProviderKind,
        /// Provider family declared by the supplied configuration.
        actual: IdentityProviderKind,
    },
    /// The provider rejected the callback exchange (bad code, expired grant, ...).
    #[error("provider rejected the callback exchange: {reason}")]
    ExchangeRejected {
        /// Human-readable reason reported by the adapter.
        reason: String,
    },
    /// The provider returned a response that could not be normalized into claims.
    #[error("provider returned claims that could not be normalized: {reason}")]
    MalformedClaims {
        /// Human-readable description of what failed to normalize.
        reason: String,
    },
}

/// Provider-specific construction and exchange seam for the login loop.
///
/// Implementors are constructed without per-login state and receive the
/// deployment's [`IdentityProviderConfig`] on each call, so one adapter instance
/// can serve every configuration of its family. Implementations must keep all
/// provider-specific URL and exchange logic inside these methods; no other part
/// of core IAM may branch on provider kind.
pub trait IdentityProviderAdapter {
    /// Provider family this adapter serves. Used to reject mismatched configs.
    fn provider_kind(&self) -> IdentityProviderKind;

    /// Build the authorization redirect for the start of a login.
    fn authorization_url(
        &self,
        config: &IdentityProviderConfig,
        request: &AuthorizationUrlRequest,
    ) -> Result<AuthorizationRedirect, ProviderError>;

    /// Exchange a provider callback into normalized external identity claims.
    fn exchange_callback(
        &self,
        config: &IdentityProviderConfig,
        callback: &CallbackExchange,
    ) -> Result<ExternalIdentityClaims, ProviderError>;

    /// Verify the supplied configuration belongs to this adapter's family.
    ///
    /// Provided so implementations get a uniform kind guard; call it first in
    /// [`authorization_url`](IdentityProviderAdapter::authorization_url) and
    /// [`exchange_callback`](IdentityProviderAdapter::exchange_callback).
    fn ensure_kind(&self, config: &IdentityProviderConfig) -> Result<(), ProviderError> {
        let expected = self.provider_kind();
        if config.kind == expected {
            Ok(())
        } else {
            Err(ProviderError::UnsupportedProviderKind {
                expected,
                actual: config.kind,
            })
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::PkceMethod;
    use awaken_iam_contract::{ExternalSubject, IdentityProviderConfigId, IdentityProviderKey};

    /// Minimal deterministic adapter that exercises the interface end to end. It
    /// builds a standard OAuth authorization query and decodes a `code` shaped as
    /// `subject:email` into normalized claims — enough to prove the seam without
    /// any network I/O.
    struct StubAdapter;

    impl IdentityProviderAdapter for StubAdapter {
        fn provider_kind(&self) -> IdentityProviderKind {
            IdentityProviderKind::OAuth2
        }

        fn authorization_url(
            &self,
            config: &IdentityProviderConfig,
            request: &AuthorizationUrlRequest,
        ) -> Result<AuthorizationRedirect, ProviderError> {
            self.ensure_kind(config)?;
            let endpoint = config.authorization_endpoint.as_deref().ok_or(
                ProviderError::MissingConfiguration {
                    field: "authorization_endpoint",
                },
            )?;
            let client_id = config
                .client_id
                .as_deref()
                .ok_or(ProviderError::MissingConfiguration { field: "client_id" })?;

            let mut url = format!(
                "{endpoint}?response_type=code&client_id={client_id}&redirect_uri={}&state={}&scope={}",
                request.redirect_uri,
                request.state,
                request.scopes.join("+"),
            );
            if let Some(nonce) = request.nonce.as_deref() {
                url.push_str(&format!("&nonce={nonce}"));
            }
            if let Some(pkce) = request.pkce_challenge.as_ref() {
                let method = match pkce.method {
                    PkceMethod::S256 => "S256",
                };
                url.push_str(&format!(
                    "&code_challenge={}&code_challenge_method={method}",
                    pkce.challenge
                ));
            }
            Ok(AuthorizationRedirect { url })
        }

        fn exchange_callback(
            &self,
            config: &IdentityProviderConfig,
            callback: &CallbackExchange,
        ) -> Result<ExternalIdentityClaims, ProviderError> {
            self.ensure_kind(config)?;
            if callback.code.is_empty() {
                return Err(ProviderError::ExchangeRejected {
                    reason: "empty authorization code".into(),
                });
            }
            let (subject, email) =
                callback
                    .code
                    .split_once(':')
                    .ok_or_else(|| ProviderError::MalformedClaims {
                        reason: "code is not in subject:email form".into(),
                    })?;
            Ok(ExternalIdentityClaims {
                subject: ExternalSubject(subject.to_owned()),
                email: Some(email.to_owned()),
                email_verified: Some(true),
                display_name: None,
                username: None,
                avatar_url: None,
                locale: None,
            })
        }
    }

    fn oauth_config(kind: IdentityProviderKind) -> IdentityProviderConfig {
        IdentityProviderConfig {
            id: IdentityProviderConfigId("cfg_1".into()),
            provider_key: IdentityProviderKey("acme".into()),
            kind,
            display_name: "Acme".into(),
            issuer_url: Some("https://issuer.example".into()),
            authorization_endpoint: Some("https://issuer.example/authorize".into()),
            token_endpoint: Some("https://issuer.example/token".into()),
            client_id: Some("client-123".into()),
            enabled: true,
        }
    }

    #[test]
    fn authorization_url_embeds_state_nonce_and_pkce() {
        let adapter = StubAdapter;
        let request = AuthorizationUrlRequest {
            redirect_uri: "https://app.example/callback".into(),
            state: "state-token".into(),
            nonce: Some("nonce-token".into()),
            pkce_challenge: Some(PkceChallenge {
                method: PkceMethod::S256,
                challenge: "challenge-value".into(),
            }),
            scopes: vec!["openid".into(), "email".into()],
        };

        let redirect = adapter
            .authorization_url(&oauth_config(IdentityProviderKind::OAuth2), &request)
            .unwrap();

        assert!(
            redirect
                .url
                .starts_with("https://issuer.example/authorize?")
        );
        assert!(redirect.url.contains("client_id=client-123"));
        assert!(redirect.url.contains("state=state-token"));
        assert!(redirect.url.contains("nonce=nonce-token"));
        assert!(redirect.url.contains("code_challenge=challenge-value"));
        assert!(redirect.url.contains("code_challenge_method=S256"));
        assert!(redirect.url.contains("scope=openid+email"));
    }

    #[test]
    fn authorization_url_reports_missing_configuration() {
        let adapter = StubAdapter;
        let mut config = oauth_config(IdentityProviderKind::OAuth2);
        config.authorization_endpoint = None;
        let request = AuthorizationUrlRequest {
            redirect_uri: "https://app.example/callback".into(),
            state: "state-token".into(),
            nonce: None,
            pkce_challenge: None,
            scopes: vec!["openid".into()],
        };

        let err = adapter.authorization_url(&config, &request).unwrap_err();
        assert_eq!(
            err,
            ProviderError::MissingConfiguration {
                field: "authorization_endpoint",
            }
        );
    }

    #[test]
    fn exchange_callback_normalizes_claims() {
        let adapter = StubAdapter;
        let callback = CallbackExchange {
            redirect_uri: "https://app.example/callback".into(),
            code: "subject-42:user@example.com".into(),
            pkce_verifier: Some("verifier".into()),
        };

        let claims = adapter
            .exchange_callback(&oauth_config(IdentityProviderKind::OAuth2), &callback)
            .unwrap();

        assert_eq!(claims.subject, ExternalSubject("subject-42".into()));
        assert_eq!(claims.email.as_deref(), Some("user@example.com"));
        assert_eq!(claims.email_verified, Some(true));
    }

    #[test]
    fn exchange_callback_rejects_empty_code() {
        let adapter = StubAdapter;
        let callback = CallbackExchange {
            redirect_uri: "https://app.example/callback".into(),
            code: String::new(),
            pkce_verifier: None,
        };

        let err = adapter
            .exchange_callback(&oauth_config(IdentityProviderKind::OAuth2), &callback)
            .unwrap_err();
        assert_eq!(
            err,
            ProviderError::ExchangeRejected {
                reason: "empty authorization code".into(),
            }
        );
    }

    #[test]
    fn adapter_rejects_mismatched_provider_kind() {
        let adapter = StubAdapter;
        let request = AuthorizationUrlRequest {
            redirect_uri: "https://app.example/callback".into(),
            state: "state-token".into(),
            nonce: None,
            pkce_challenge: None,
            scopes: vec!["openid".into()],
        };

        let err = adapter
            .authorization_url(&oauth_config(IdentityProviderKind::Oidc), &request)
            .unwrap_err();
        assert_eq!(
            err,
            ProviderError::UnsupportedProviderKind {
                expected: IdentityProviderKind::OAuth2,
                actual: IdentityProviderKind::Oidc,
            }
        );
    }

    #[test]
    fn adapter_is_object_safe_for_a_registry() {
        // A deployment holds heterogeneous adapters behind `dyn`, keyed by
        // provider key. This compiles only if the trait stays object-safe.
        let registry: Vec<Box<dyn IdentityProviderAdapter>> = vec![Box::new(StubAdapter)];
        assert_eq!(registry[0].provider_kind(), IdentityProviderKind::OAuth2);
    }
}
