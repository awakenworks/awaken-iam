use super::*;
use crate::DEFAULT_SESSION_COOKIE_NAME;
use awaken_iam_contract::IdentityProviderConfigId;

/// Deterministic entropy so minted ids and secrets are reproducible.
#[derive(Clone, Default)]
struct SequentialEntropy {
    next: u8,
}

impl EntropySource for SequentialEntropy {
    fn fill_bytes(&mut self, buf: &mut [u8]) {
        for byte in buf.iter_mut() {
            *byte = self.next;
            self.next = self.next.wrapping_add(1);
        }
    }
}

/// Minimal deterministic adapter: embeds `state` in the authorization URL and
/// decodes a `subject:email` callback code into normalized claims.
struct FakeAdapter;

impl IdentityProviderAdapter for FakeAdapter {
    fn provider_kind(&self) -> IdentityProviderKind {
        IdentityProviderKind::Fake
    }

    fn authorization_url(
        &self,
        config: &IdentityProviderConfig,
        request: &AuthorizationUrlRequest,
    ) -> Result<awaken_iam_core::AuthorizationRedirect, ProviderError> {
        self.ensure_kind(config)?;
        Ok(awaken_iam_core::AuthorizationRedirect {
            url: format!(
                "https://provider.example/authorize?redirect_uri={}&state={}",
                request.redirect_uri, request.state
            ),
        })
    }

    fn exchange_callback(
        &self,
        config: &IdentityProviderConfig,
        callback: &CallbackExchange,
    ) -> Result<ExternalIdentityClaims, ProviderError> {
        self.ensure_kind(config)?;
        let (subject, email) =
            callback
                .code
                .split_once(':')
                .ok_or_else(|| ProviderError::MalformedClaims {
                    reason: "code is not subject:email".into(),
                })?;
        Ok(ExternalIdentityClaims {
            subject: ExternalSubject(subject.to_owned()),
            email: Some(email.to_owned()),
            email_verified: Some(true),
            display_name: Some("Fake User".into()),
            username: None,
            avatar_url: None,
            locale: None,
        })
    }
}

fn config(enabled: bool) -> IdentityProviderConfig {
    IdentityProviderConfig {
        id: IdentityProviderConfigId("cfg_fake".into()),
        provider_key: IdentityProviderKey("fake".into()),
        kind: IdentityProviderKind::Fake,
        display_name: "Fake".into(),
        issuer_url: Some("https://provider.example".into()),
        authorization_endpoint: Some("https://provider.example/authorize".into()),
        token_endpoint: Some("https://provider.example/token".into()),
        client_id: Some("client-fake".into()),
        enabled,
    }
}

fn api() -> AuthApi<SequentialEntropy> {
    let mut api = AuthApi::with_entropy(SequentialEntropy::default()).with_return_to_policy(
        ReturnToPolicy::new("/home", ["/dashboard".to_owned(), "/home".to_owned()]),
    );
    api.register_provider(ProviderRegistration {
        config: config(true),
        adapter: Box::new(FakeAdapter),
        redirect_uri: "https://app.example/v1/auth/callback/fake".into(),
        scopes: vec!["openid".into(), "email".into()],
        include_nonce: true,
        include_pkce: true,
    });
    api
}

fn start(api: &mut AuthApi<SequentialEntropy>, return_to: Option<&str>) -> StartLoginOutcome {
    api.start_login(StartLogin {
        provider_key: IdentityProviderKey("fake".into()),
        return_to: return_to.map(str::to_owned),
        created_at: Timestamp("2026-06-19T00:00:00Z".into()),
        expires_at: Timestamp("2026-06-19T00:05:00Z".into()),
        cookie_max_age_secs: Some(300),
    })
    .unwrap()
}

fn login_cookie_header(outcome: &StartLoginOutcome) -> String {
    let cfg = SessionCookieConfig {
        name: DEFAULT_LOGIN_COOKIE_NAME.to_owned(),
        ..SessionCookieConfig::default()
    };
    let id = cfg.extract_token(&outcome.set_cookie).unwrap();
    format!("{DEFAULT_LOGIN_COOKIE_NAME}={id}")
}

fn state_from_redirect(outcome: &StartLoginOutcome) -> String {
    outcome
        .redirect_url
        .split("state=")
        .nth(1)
        .unwrap()
        .to_owned()
}

fn callback(
    api: &mut AuthApi<SequentialEntropy>,
    outcome: &StartLoginOutcome,
    code: &str,
) -> Result<CallbackOutcome, AuthApiError> {
    api.complete_callback(CallbackRequest {
        provider_key: IdentityProviderKey("fake".into()),
        cookie_header: login_cookie_header(outcome),
        code: code.into(),
        state: state_from_redirect(outcome),
        now: Timestamp("2026-06-19T00:01:00Z".into()),
        session_expires_at: Timestamp("2026-06-20T00:00:00Z".into()),
        session_cookie_max_age_secs: Some(3600),
    })
}

#[test]
fn list_providers_hides_disabled_providers() {
    let mut api = api();
    api.register_provider(ProviderRegistration {
        config: IdentityProviderConfig {
            provider_key: IdentityProviderKey("github".into()),
            enabled: false,
            ..config(false)
        },
        adapter: Box::new(FakeAdapter),
        redirect_uri: "https://app.example/v1/auth/callback/github".into(),
        scopes: vec![],
        include_nonce: false,
        include_pkce: true,
    });

    let providers = api.list_providers();
    assert_eq!(providers.len(), 1);
    assert_eq!(
        providers[0].provider_key,
        IdentityProviderKey("fake".into())
    );
    assert_eq!(providers[0].kind, IdentityProviderKind::Fake);
}

#[test]
fn start_login_unknown_provider_fails_closed() {
    let mut api = api();
    let err = api
        .start_login(StartLogin {
            provider_key: IdentityProviderKey("nope".into()),
            return_to: None,
            created_at: Timestamp("2026-06-19T00:00:00Z".into()),
            expires_at: Timestamp("2026-06-19T00:05:00Z".into()),
            cookie_max_age_secs: None,
        })
        .unwrap_err();
    assert_eq!(
        err,
        AuthApiError::UnknownProvider(IdentityProviderKey("nope".into()))
    );
}

#[test]
fn full_login_loop_provisions_account_and_establishes_session() {
    let mut api = api();
    let outcome = start(&mut api, Some("/dashboard"));
    assert!(outcome.set_cookie.contains(DEFAULT_LOGIN_COOKIE_NAME));
    assert!(outcome.set_cookie.contains("; HttpOnly"));
    assert!(outcome.set_cookie.contains("; Secure"));
    assert_eq!(
        outcome.return_to,
        ReturnToDecision::Allowed("/dashboard".into())
    );

    let result = callback(&mut api, &outcome, "subject-1:user@example.com").unwrap();
    assert!(result.registered);
    assert_eq!(result.redirect_to, "/dashboard");
    assert!(
        result
            .set_session_cookie
            .contains(DEFAULT_SESSION_COOKIE_NAME)
    );
    assert!(result.clear_login_cookie.contains("; Max-Age=0"));

    // The new session resolves from its cookie.
    let session_cookie = {
        let token = SessionCookieConfig::default()
            .extract_token(&result.set_session_cookie)
            .unwrap();
        format!("{DEFAULT_SESSION_COOKIE_NAME}={token}")
    };
    let view = api
        .current_session(&session_cookie, Timestamp("2026-06-19T01:00:00Z".into()))
        .unwrap();
    assert_eq!(view.session_id, result.session.session_id);

    // A second login for the same provider subject reuses the account.
    let outcome2 = start(&mut api, None);
    let result2 = callback(&mut api, &outcome2, "subject-1:new@example.com").unwrap();
    assert!(!result2.registered);
    assert_eq!(result2.session.account_id, result.session.account_id);
    // Default return_to applies when none was requested.
    assert_eq!(result2.redirect_to, "/home");

    // The audit trail records both login transitions.
    let succeeded = api
        .audit_log()
        .iter()
        .filter(|event| matches!(event, AuthAuditEvent::LoginSucceeded { .. }))
        .count();
    assert_eq!(succeeded, 2);
}

#[test]
fn return_to_open_redirect_is_rejected_and_audited() {
    let mut api = api();
    let outcome = start(&mut api, Some("https://evil.example/steal"));
    assert_eq!(
        outcome.return_to,
        ReturnToDecision::RejectedFallback("/home".into())
    );
    assert!(
        api.audit_log()
            .iter()
            .any(|event| matches!(event, AuthAuditEvent::ReturnToRejected { .. }))
    );

    // The callback honours the safe default, not the crafted destination.
    let result = callback(&mut api, &outcome, "subject-1:user@example.com").unwrap();
    assert_eq!(result.redirect_to, "/home");
}

#[test]
fn protocol_relative_return_to_is_rejected() {
    let policy = ReturnToPolicy::default();
    assert_eq!(
        policy.resolve(Some("//evil.example")),
        ReturnToDecision::RejectedFallback("/".into())
    );
    assert_eq!(
        policy.resolve(Some("/safe/path")),
        ReturnToDecision::Allowed("/safe/path".into())
    );
}

#[test]
fn callback_without_correlation_cookie_fails_and_audits() {
    let mut api = api();
    let outcome = start(&mut api, Some("/dashboard"));
    let err = api
        .complete_callback(CallbackRequest {
            provider_key: IdentityProviderKey("fake".into()),
            cookie_header: "unrelated=1".into(),
            code: "subject-1:user@example.com".into(),
            state: state_from_redirect(&outcome),
            now: Timestamp("2026-06-19T00:01:00Z".into()),
            session_expires_at: Timestamp("2026-06-20T00:00:00Z".into()),
            session_cookie_max_age_secs: None,
        })
        .unwrap_err();
    assert_eq!(err, AuthApiError::MissingCorrelation);
    assert!(api.audit_log().iter().any(|event| matches!(
        event,
        AuthAuditEvent::LoginFailed {
            reason: AuthFailureReason::MissingCorrelation,
            ..
        }
    )));
}

#[test]
fn forged_state_fails_closed_and_burns_challenge() {
    let mut api = api();
    let outcome = start(&mut api, Some("/dashboard"));
    let err = api
        .complete_callback(CallbackRequest {
            provider_key: IdentityProviderKey("fake".into()),
            cookie_header: login_cookie_header(&outcome),
            code: "subject-1:user@example.com".into(),
            state: "forged-state".into(),
            now: Timestamp("2026-06-19T00:01:00Z".into()),
            session_expires_at: Timestamp("2026-06-20T00:00:00Z".into()),
            session_cookie_max_age_secs: None,
        })
        .unwrap_err();
    assert!(matches!(
        err,
        AuthApiError::Login(IamError::LoginStateMismatch { .. })
    ));
    assert!(api.audit_log().iter().any(|event| matches!(
        event,
        AuthAuditEvent::LoginFailed {
            reason: AuthFailureReason::StateMismatch,
            ..
        }
    )));

    // The burned challenge cannot be replayed even with the correct state.
    let replay = callback(&mut api, &outcome, "subject-1:user@example.com").unwrap_err();
    assert!(matches!(replay, AuthApiError::MissingCorrelation));
}

#[test]
fn logout_revokes_session_and_clears_cookie() {
    let mut api = api();
    let outcome = start(&mut api, Some("/dashboard"));
    let result = callback(&mut api, &outcome, "subject-1:user@example.com").unwrap();
    let token = SessionCookieConfig::default()
        .extract_token(&result.set_session_cookie)
        .unwrap();
    let cookie = format!("{DEFAULT_SESSION_COOKIE_NAME}={token}");

    let logout = api
        .logout(&cookie, Timestamp("2026-06-19T02:00:00Z".into()))
        .unwrap();
    assert!(logout.clear_session_cookie.contains("; Max-Age=0"));
    assert!(
        api.audit_log()
            .iter()
            .any(|event| matches!(event, AuthAuditEvent::LoggedOut { .. }))
    );

    // After logout the session no longer authenticates.
    let err = api
        .current_session(&cookie, Timestamp("2026-06-19T03:00:00Z".into()))
        .unwrap_err();
    assert!(matches!(
        err,
        AuthApiError::Login(IamError::SessionRevoked { .. })
    ));
}

#[test]
fn link_list_and_unlink_external_identities() {
    let mut api = api();
    let outcome = start(&mut api, Some("/dashboard"));
    let result = callback(&mut api, &outcome, "subject-1:user@example.com").unwrap();
    let account_id = result.session.account_id.clone();

    // Link a second provider identity to the same account.
    let linked = api
        .link_identity(LinkIdentity {
            account_id: account_id.clone(),
            provider_key: IdentityProviderKey("github".into()),
            claims: ExternalIdentityClaims {
                subject: ExternalSubject("gh-1".into()),
                email: Some("user@github.test".into()),
                email_verified: Some(true),
                display_name: None,
                username: Some("octocat".into()),
                avatar_url: None,
                locale: None,
            },
            now: Timestamp("2026-06-19T04:00:00Z".into()),
        })
        .unwrap();
    assert_eq!(linked.account_id, account_id);

    let identities = api.list_identities(&account_id);
    assert_eq!(identities.len(), 2);

    // Unlinking an identity owned by a different account fails closed.
    let mismatch = api
        .unlink_identity(UnlinkIdentity {
            account_id: AccountId("acct_other".into()),
            provider_key: IdentityProviderKey("github".into()),
            subject: ExternalSubject("gh-1".into()),
            now: Timestamp("2026-06-19T05:00:00Z".into()),
        })
        .unwrap_err();
    assert_eq!(mismatch, AuthApiError::IdentityAccountMismatch);

    // Unlinking the owned identity removes it and audits the change.
    api.unlink_identity(UnlinkIdentity {
        account_id: account_id.clone(),
        provider_key: IdentityProviderKey("github".into()),
        subject: ExternalSubject("gh-1".into()),
        now: Timestamp("2026-06-19T05:00:00Z".into()),
    })
    .unwrap();
    assert_eq!(api.list_identities(&account_id).len(), 1);
    assert!(
        api.audit_log()
            .iter()
            .any(|event| matches!(event, AuthAuditEvent::IdentityUnlinked { .. }))
    );
}

#[test]
fn linking_a_subject_twice_is_rejected() {
    let mut api = api();
    let link = || LinkIdentity {
        account_id: AccountId("acct_1".into()),
        provider_key: IdentityProviderKey("github".into()),
        claims: ExternalIdentityClaims {
            subject: ExternalSubject("gh-1".into()),
            email: None,
            email_verified: None,
            display_name: None,
            username: None,
            avatar_url: None,
            locale: None,
        },
        now: Timestamp("2026-06-19T04:00:00Z".into()),
    };
    api.link_identity(link()).unwrap();
    let err = api.link_identity(link()).unwrap_err();
    assert!(matches!(
        err,
        AuthApiError::Login(IamError::DuplicateExternalIdentity { .. })
    ));
}

#[test]
fn openid_configuration_advertises_canonical_endpoints() {
    let api = api();
    // A trailing slash on the issuer must not double the path separator.
    let metadata = api.openid_configuration("https://iam.example/");
    assert_eq!(metadata.issuer, "https://iam.example");
    assert_eq!(
        metadata.authorization_endpoint,
        "https://iam.example/v1/auth/login"
    );
    assert_eq!(
        metadata.token_endpoint,
        "https://iam.example/v1/oauth/token"
    );
    assert_eq!(
        metadata.userinfo_endpoint,
        "https://iam.example/v1/oauth/userinfo"
    );
    assert_eq!(
        metadata.jwks_uri,
        "https://iam.example/.well-known/jwks.json"
    );
    assert_eq!(metadata.response_types_supported, vec!["code".to_owned()]);
    assert!(metadata.scopes_supported.contains(&"openid".to_owned()));

    // The discovery document round-trips through the OIDC wire field names.
    let json = serde_json::to_value(&metadata).unwrap();
    assert_eq!(json["issuer"], "https://iam.example");
    assert_eq!(
        json["userinfo_endpoint"],
        "https://iam.example/v1/oauth/userinfo"
    );
}

#[test]
fn userinfo_projects_session_subject_and_claims() {
    let mut api = api();
    let outcome = start(&mut api, Some("/dashboard"));
    let result = callback(&mut api, &outcome, "subject-1:user@example.com").unwrap();
    let session_cookie = {
        let token = SessionCookieConfig::default()
            .extract_token(&result.set_session_cookie)
            .unwrap();
        format!("{DEFAULT_SESSION_COOKIE_NAME}={token}")
    };

    let userinfo = api
        .userinfo(&session_cookie, Timestamp("2026-06-19T01:30:00Z".into()))
        .unwrap();
    // `sub` is IAM's account subject, not the upstream provider subject.
    assert_eq!(userinfo.sub, result.session.account_id.0);
    assert_ne!(userinfo.sub, "subject-1");
    assert_eq!(userinfo.email.as_deref(), Some("user@example.com"));
    assert_eq!(userinfo.email_verified, Some(true));
    assert_eq!(userinfo.name.as_deref(), Some("Fake User"));
    assert!(userinfo.updated_at.is_some());

    // Absent claims are omitted from the serialized response.
    let json = serde_json::to_value(&userinfo).unwrap();
    assert!(json.get("picture").is_none());
    assert_eq!(json["email"], "user@example.com");
}

#[test]
fn userinfo_fails_closed_without_a_session() {
    let mut api = api();
    let err = api
        .userinfo("unrelated=1", Timestamp("2026-06-19T01:30:00Z".into()))
        .unwrap_err();
    assert!(matches!(
        err,
        AuthApiError::Login(IamError::SessionNotFound { .. })
    ));
}

#[test]
fn userinfo_fails_closed_after_logout() {
    let mut api = api();
    let outcome = start(&mut api, Some("/dashboard"));
    let result = callback(&mut api, &outcome, "subject-1:user@example.com").unwrap();
    let token = SessionCookieConfig::default()
        .extract_token(&result.set_session_cookie)
        .unwrap();
    let cookie = format!("{DEFAULT_SESSION_COOKIE_NAME}={token}");

    api.logout(&cookie, Timestamp("2026-06-19T02:00:00Z".into()))
        .unwrap();

    let err = api
        .userinfo(&cookie, Timestamp("2026-06-19T03:00:00Z".into()))
        .unwrap_err();
    assert!(matches!(
        err,
        AuthApiError::Login(IamError::SessionRevoked { .. })
    ));
}

/// Drive a full login and return the live session cookie header a product
/// service forwards to IAM on a subsequent request.
fn logged_in_session(api: &mut AuthApi<SequentialEntropy>) -> (CallbackOutcome, String) {
    let outcome = start(api, Some("/dashboard"));
    let result = callback(api, &outcome, "subject-1:user@example.com").unwrap();
    let token = SessionCookieConfig::default()
        .extract_token(&result.set_session_cookie)
        .unwrap();
    let cookie = format!("{DEFAULT_SESSION_COOKIE_NAME}={token}");
    (result, cookie)
}

#[test]
fn product_resolves_principal_from_iam_session() {
    let mut api = api();
    let (result, cookie) = logged_in_session(&mut api);

    // The product forwards only the opaque IAM session cookie — never a
    // Google or GitHub token — and IAM resolves the account principal.
    let principal = api
        .resolve_principal(&cookie, Timestamp("2026-06-19T01:00:00Z".into()))
        .unwrap();
    assert_eq!(
        principal,
        PrincipalRef::Account {
            account_id: result.session.account_id.clone(),
        }
    );
    assert!(
        api.audit_log()
            .iter()
            .any(|event| matches!(event, AuthAuditEvent::PrincipalResolved { .. }))
    );
}

#[test]
fn session_principal_drives_remote_authorize() {
    use crate::AuthzApi;
    use awaken_iam_contract::{ActionKey, AuthorizationDecision, AuthorizationRequest, ScopeRef};
    use awaken_iam_core::{ActionPattern, Effect, Grant, GrantId, GrantSubject};

    let mut api = api();
    let (_result, cookie) = logged_in_session(&mut api);
    let principal = api
        .resolve_principal(&cookie, Timestamp("2026-06-19T01:00:00Z".into()))
        .unwrap();

    // The product takes the session-resolved principal to the authorization
    // seam (`POST /v1/authorize`). Default-deny without a grant.
    let publish = AuthorizationRequest::direct(
        principal.clone(),
        ActionKey("pack.publish".into()),
        ScopeRef::Global,
    );
    let mut authz = AuthzApi::new();
    assert_eq!(
        authz.authorize(&publish).decision,
        AuthorizationDecision::Deny
    );

    // Granting the action to the session principal flips the decision —
    // proving the product authorizes the principal IAM resolved, not one it
    // asserts on its own.
    authz.policy_mut().add_grant(Grant {
        id: GrantId("g1".into()),
        subject: GrantSubject::Principal(principal.clone()),
        action_pattern: ActionPattern("pack.publish".into()),
        scope: ScopeRef::Global,
        effect: Effect::Allow,
    });
    assert_eq!(
        authz.authorize(&publish).decision,
        AuthorizationDecision::Allow
    );
}

#[test]
fn resolve_principal_without_session_fails_closed() {
    let mut api = api();
    let err = api
        .resolve_principal("unrelated=1", Timestamp("2026-06-19T01:00:00Z".into()))
        .unwrap_err();
    assert_eq!(err, AuthApiError::Unauthenticated);
    assert!(api.audit_log().iter().any(|event| matches!(
        event,
        AuthAuditEvent::PrincipalResolutionFailed {
            reason: PrincipalResolutionFailure::Unauthenticated,
            ..
        }
    )));
}

#[test]
fn resolve_principal_after_logout_fails_closed() {
    let mut api = api();
    let (_result, cookie) = logged_in_session(&mut api);
    api.logout(&cookie, Timestamp("2026-06-19T02:00:00Z".into()))
        .unwrap();

    // A revoked session cannot be replayed to resolve a principal.
    let err = api
        .resolve_principal(&cookie, Timestamp("2026-06-19T03:00:00Z".into()))
        .unwrap_err();
    assert_eq!(err, AuthApiError::Unauthenticated);
}

#[test]
fn resolve_principal_for_disabled_account_fails_closed() {
    let mut api = api();
    let (result, cookie) = logged_in_session(&mut api);
    let account_id = result.session.account_id.clone();

    // Disable the account behind the otherwise-live session.
    let mut account = api.directory().account(&account_id).unwrap().clone();
    account.status = AccountStatus::Disabled;
    account.updated_at = Timestamp("2026-06-19T02:00:00Z".into());
    api.directory.upsert_account(account);

    let err = api
        .resolve_principal(&cookie, Timestamp("2026-06-19T03:00:00Z".into()))
        .unwrap_err();
    assert_eq!(err, AuthApiError::AccountDisabled);
    assert!(api.audit_log().iter().any(|event| matches!(
        event,
        AuthAuditEvent::PrincipalResolutionFailed {
            reason: PrincipalResolutionFailure::AccountDisabled,
            ..
        }
    )));
}

fn mint_request() -> MintAccessToken {
    MintAccessToken {
        issuer: "https://iam.example".into(),
        subject: "acct_1".into(),
        audience: "packs-service".into(),
        issued_at: 1_899_996_400,
        expires_at: 1_900_000_000,
        scopes: vec!["pack.read".into()],
    }
}

#[test]
fn minted_access_token_is_asymmetric_and_verifies_against_published_jwks() {
    let mut api = api();
    let token = api.mint_access_token(mint_request()).unwrap();

    // The token is signed by the active key and verifies against the JWKS
    // alone — no shared secret is needed by the verifier.
    let jwks = api.jwks();
    assert_eq!(jwks.keys.len(), 1);
    assert_eq!(jwks.keys[0].kid, api.active_signing_kid());
    let claims = crate::verify_access_token(&token, &jwks).unwrap();
    assert_eq!(claims.sub, "acct_1");
    assert_eq!(claims.aud, "packs-service");
    assert_eq!(claims.scope, vec!["pack.read".to_owned()]);
    // A unique jti is minted so the token can be revoked individually.
    assert!(claims.jti.starts_with("jti_"));

    // Two mints get distinct jti values.
    let other = api.mint_access_token(mint_request()).unwrap();
    let other_claims = crate::verify_access_token(&other, &api.jwks()).unwrap();
    assert_ne!(claims.jti, other_claims.jti);
}

#[test]
fn rotating_the_signing_key_keeps_old_tokens_verifiable_until_pruned() {
    let mut api = api();
    let old_kid = api.active_signing_kid().to_owned();
    let old_token = api.mint_access_token(mint_request()).unwrap();

    api.rotate_signing_key("iam-access-key-2");
    assert_eq!(api.active_signing_kid(), "iam-access-key-2");
    let new_token = api.mint_access_token(mint_request()).unwrap();

    // Both tokens verify while the old key is still published.
    let jwks = api.jwks();
    assert_eq!(jwks.keys.len(), 2);
    crate::verify_access_token(&old_token, &jwks).unwrap();
    crate::verify_access_token(&new_token, &jwks).unwrap();

    // Pruning the retired key retires the tokens it signed.
    assert!(api.prune_signing_key(&old_kid));
    let pruned = api.jwks();
    assert_eq!(pruned.keys.len(), 1);
    assert!(crate::verify_access_token(&old_token, &pruned).is_err());
    crate::verify_access_token(&new_token, &pruned).unwrap();
}

fn issue_grant(api: &mut AuthApi<SequentialEntropy>) -> TokenGrant {
    api.issue_token_grant(IssueTokenGrant {
        account_id: AccountId("acct_1".into()),
        issuer: "https://iam.example".into(),
        subject: "acct_1".into(),
        audience: "packs-service".into(),
        scopes: vec!["pack.read".into()],
        issued_at: 1_899_996_400,
        access_expires_at: 1_900_000_000,
        now: Timestamp("2026-06-19T00:00:00Z".into()),
        refresh_expires_at: Timestamp("2026-07-19T00:00:00Z".into()),
    })
    .unwrap()
}

fn refresh_grant(presented: &str, now: &str) -> RefreshGrant {
    RefreshGrant {
        presented_refresh_token: presented.into(),
        issuer: "https://iam.example".into(),
        issued_at: 1_899_996_400,
        access_expires_at: 1_900_000_000,
        now: Timestamp(now.into()),
        refresh_expires_at: Timestamp("2026-08-19T00:00:00Z".into()),
    }
}

/// A downstream OP registry with one confidential and one public product client.
fn op_provider() -> OAuthAuthorizationServer<SequentialEntropy> {
    let mut registry = awaken_iam_core::OAuthClientRegistry::new();
    registry.register(awaken_iam_core::RegisteredClient::confidential(
        "packs-web",
        "client-secret",
        vec!["https://packs.example/cb".into()],
        ["pack.read"],
    ));
    registry.register(awaken_iam_core::RegisteredClient::public(
        "packs-spa",
        vec!["https://packs.example/spa".into()],
        ["pack.read"],
    ));
    OAuthAuthorizationServer::new(registry, SequentialEntropy::default())
}

#[test]
fn op_refresh_grant_authenticates_the_client_then_rotates() {
    let mut api = api();
    let provider = op_provider();
    let first = issue_grant(&mut api);

    let rotated = api
        .op_refresh_token_grant(
            &provider,
            "packs-web",
            Some("client-secret"),
            refresh_grant(&first.refresh_token, "2026-06-20T00:00:00Z"),
        )
        .unwrap();

    // The presented token is rotated under the same chain and a fresh, verifiable
    // access token is minted from the chain's stored coordinates.
    assert_ne!(first.refresh_token, rotated.refresh_token);
    assert_eq!(
        first.refresh_token_view.chain_id,
        rotated.refresh_token_view.chain_id
    );
    assert_eq!(rotated.refresh_token_view.subject, "acct_1");
    api.verify_access_token(&rotated.access_token).unwrap();
    assert!(
        api.audit_log()
            .iter()
            .any(|event| matches!(event, AuthAuditEvent::RefreshTokenRotated { .. }))
    );
}

#[test]
fn op_refresh_grant_accepts_a_public_client_without_a_secret() {
    let mut api = api();
    let provider = op_provider();
    let first = issue_grant(&mut api);

    let rotated = api
        .op_refresh_token_grant(
            &provider,
            "packs-spa",
            None,
            refresh_grant(&first.refresh_token, "2026-06-20T00:00:00Z"),
        )
        .unwrap();
    assert_ne!(first.refresh_token, rotated.refresh_token);
}

#[test]
fn op_refresh_grant_rejects_a_wrong_client_secret_without_rotating() {
    let mut api = api();
    let provider = op_provider();
    let first = issue_grant(&mut api);

    let err = api
        .op_refresh_token_grant(
            &provider,
            "packs-web",
            Some("wrong"),
            refresh_grant(&first.refresh_token, "2026-06-20T00:00:00Z"),
        )
        .unwrap_err();
    assert!(matches!(
        err,
        AuthApiError::OAuthProvider(OAuthProviderError::InvalidClientSecret)
    ));

    // Failed client authentication never touched the chain: an authenticated
    // rotation of the still-current token then succeeds.
    let rotated = api
        .op_refresh_token_grant(
            &provider,
            "packs-web",
            Some("client-secret"),
            refresh_grant(&first.refresh_token, "2026-06-20T01:00:00Z"),
        )
        .unwrap();
    assert_ne!(first.refresh_token, rotated.refresh_token);
}

#[test]
fn op_refresh_grant_rejects_an_unknown_client() {
    let mut api = api();
    let provider = op_provider();
    let first = issue_grant(&mut api);

    let err = api
        .op_refresh_token_grant(
            &provider,
            "ghost",
            Some("anything"),
            refresh_grant(&first.refresh_token, "2026-06-20T00:00:00Z"),
        )
        .unwrap_err();
    assert!(matches!(
        err,
        AuthApiError::OAuthProvider(OAuthProviderError::UnknownClient)
    ));
}

#[test]
fn op_refresh_grant_revokes_the_chain_on_replay() {
    let mut api = api();
    let provider = op_provider();
    let first = issue_grant(&mut api);

    // Legitimate rotation through the OP endpoint.
    let _second = api
        .op_refresh_token_grant(
            &provider,
            "packs-web",
            Some("client-secret"),
            refresh_grant(&first.refresh_token, "2026-06-20T00:00:00Z"),
        )
        .unwrap();

    // Replaying the retired token — even with valid client auth — is a theft
    // signal that revokes the whole chain and fails closed.
    let err = api
        .op_refresh_token_grant(
            &provider,
            "packs-web",
            Some("client-secret"),
            refresh_grant(&first.refresh_token, "2026-06-20T01:00:00Z"),
        )
        .unwrap_err();
    assert!(matches!(
        err,
        AuthApiError::Login(awaken_iam_core::IamError::RefreshTokenReuseDetected { .. })
    ));
}

#[test]
fn issuing_a_grant_returns_a_verifiable_access_token_and_a_refresh_token() {
    let mut api = api();
    let grant = issue_grant(&mut api);

    // The access token verifies against the published JWKS and the denylist.
    let claims = api.verify_access_token(&grant.access_token).unwrap();
    assert_eq!(claims.sub, "acct_1");
    assert_eq!(claims.jti, grant.access_token_jti);

    // The refresh token is opaque, scheme-tagged, and never echoes its hash.
    assert!(grant.refresh_token.starts_with("oiamr_"));
    assert!(grant.refresh_token_view.rotated_at.is_none());
    assert!(grant.refresh_token_view.revoked_at.is_none());

    // The chain issuance is audited.
    assert!(
        api.audit_log()
            .iter()
            .any(|event| matches!(event, AuthAuditEvent::RefreshTokenIssued { .. }))
    );
}

#[test]
fn refreshing_rotates_the_token_and_mints_a_fresh_access_token() {
    let mut api = api();
    let first = issue_grant(&mut api);

    let rotated = api
        .refresh_token_grant(refresh_grant(&first.refresh_token, "2026-06-20T00:00:00Z"))
        .unwrap();

    // A new refresh token is issued and differs from the presented one.
    assert_ne!(first.refresh_token, rotated.refresh_token);
    assert_ne!(first.access_token_jti, rotated.access_token_jti);
    // Same chain, inherited grant coordinates.
    assert_eq!(
        first.refresh_token_view.chain_id,
        rotated.refresh_token_view.chain_id
    );
    assert_eq!(rotated.refresh_token_view.subject, "acct_1");
    assert_eq!(
        rotated.refresh_token_view.scope,
        vec!["pack.read".to_owned()]
    );

    // The rotation is audited and the new access token verifies.
    api.verify_access_token(&rotated.access_token).unwrap();
    assert!(
        api.audit_log()
            .iter()
            .any(|event| matches!(event, AuthAuditEvent::RefreshTokenRotated { .. }))
    );
}

#[test]
fn replaying_a_retired_refresh_token_revokes_the_chain() {
    let mut api = api();
    let first = issue_grant(&mut api);

    // Legitimate rotation: the client now holds the successor.
    let _second = api
        .refresh_token_grant(refresh_grant(&first.refresh_token, "2026-06-20T00:00:00Z"))
        .unwrap();

    // Replaying the now-retired first token is a theft signal.
    let err = api
        .refresh_token_grant(refresh_grant(&first.refresh_token, "2026-06-20T01:00:00Z"))
        .unwrap_err();
    assert!(matches!(
        err,
        AuthApiError::Login(awaken_iam_core::IamError::RefreshTokenReuseDetected { .. })
    ));

    // The reuse and the chain revocation are both audited.
    assert!(
        api.audit_log()
            .iter()
            .any(|event| matches!(event, AuthAuditEvent::RefreshTokenReuseDetected { .. }))
    );
    assert!(
        api.audit_log()
            .iter()
            .any(|event| matches!(event, AuthAuditEvent::RefreshChainRevoked { .. }))
    );

    // The leaked successor can no longer rotate either: the chain is dead.
    let dead = api
        .refresh_token_grant(refresh_grant(
            &_second.refresh_token,
            "2026-06-20T02:00:00Z",
        ))
        .unwrap_err();
    assert!(matches!(
        dead,
        AuthApiError::Login(awaken_iam_core::IamError::RefreshTokenInvalid)
    ));
}

#[test]
fn rfc7009_revoke_kills_the_refresh_chain() {
    let mut api = api();
    let grant = issue_grant(&mut api);

    let outcome = api.revoke_token(RevokeToken {
        token: grant.refresh_token.clone(),
        token_type_hint: Some(RevokeTokenHint::RefreshToken),
        now: Timestamp("2026-06-20T00:00:00Z".into()),
    });
    assert!(outcome.revoked);
    assert!(
        api.audit_log()
            .iter()
            .any(|event| matches!(event, AuthAuditEvent::RefreshChainRevoked { .. }))
    );

    // A revoked refresh token can no longer be rotated.
    let err = api
        .refresh_token_grant(refresh_grant(&grant.refresh_token, "2026-06-20T01:00:00Z"))
        .unwrap_err();
    assert!(matches!(
        err,
        AuthApiError::Login(awaken_iam_core::IamError::RefreshTokenInvalid)
    ));
}

#[test]
fn rfc7009_revoke_kills_an_access_token_by_jti() {
    let mut api = api();
    let grant = issue_grant(&mut api);

    // Before revocation the token verifies.
    api.verify_access_token(&grant.access_token).unwrap();

    let outcome = api.revoke_token(RevokeToken {
        token: grant.access_token.clone(),
        token_type_hint: Some(RevokeTokenHint::AccessToken),
        now: Timestamp("2026-06-20T00:00:00Z".into()),
    });
    assert!(outcome.revoked);
    assert!(api.is_access_token_revoked(&grant.access_token_jti));

    // The still-signed token now fails closed on the IAM-side check.
    let err = api.verify_access_token(&grant.access_token).unwrap_err();
    assert_eq!(
        err,
        AccessTokenError::Revoked(grant.access_token_jti.clone())
    );
    assert!(
        api.audit_log()
            .iter()
            .any(|event| matches!(event, AuthAuditEvent::AccessTokenRevoked { .. }))
    );
}

#[test]
fn rfc7009_revoke_of_an_unknown_token_is_a_silent_noop() {
    let mut api = api();
    // RFC 7009 §2.2: an unknown/invalid token still yields a success response.
    let bogus = "oiamr_unregistered-value".to_owned();
    let outcome = api.revoke_token(RevokeToken {
        token: bogus,
        token_type_hint: None,
        now: Timestamp("2026-06-20T00:00:00Z".into()),
    });
    assert!(!outcome.revoked);
}

/// Register a confidential downstream product client integrating against IAM as
/// the OpenID Provider.
fn register_downstream_client(api: &mut AuthApi<SequentialEntropy>) {
    api.register_oauth_client(RegisteredClient::confidential(
        "product-web",
        "client-secret",
        vec!["https://product.example/callback".into()],
        ["openid", "email"],
    ));
}

fn downstream_authorize(cookie: &str) -> DownstreamAuthorizeRequest {
    DownstreamAuthorizeRequest {
        cookie_header: cookie.to_owned(),
        authorization: OAuthAuthorizationRequest {
            client_id: "product-web".into(),
            redirect_uri: "https://product.example/callback".into(),
            scopes: vec!["openid".into(), "email".into()],
            code_challenge: None,
            code_challenge_method: None,
            nonce: Some("nonce-xyz".into()),
            state: Some("state abc".into()),
        },
        now: Timestamp("2026-06-19T01:00:00Z".into()),
        code_expires_at: Timestamp("2026-06-19T01:05:00Z".into()),
    }
}

fn code_from_redirect(redirect_to: &str) -> String {
    redirect_to
        .split("code=")
        .nth(1)
        .unwrap()
        .split('&')
        .next()
        .unwrap()
        .to_owned()
}

fn redeem(code: &str) -> RedeemAuthorizationCode {
    RedeemAuthorizationCode {
        redemption: TokenRedemption {
            client_id: "product-web".into(),
            client_secret: Some("client-secret".into()),
            code: code.to_owned(),
            redirect_uri: "https://product.example/callback".into(),
            code_verifier: None,
        },
        issuer: "https://iam.example".into(),
        issued_at: 1_899_996_400,
        access_expires_at: 1_900_000_000,
        now: Timestamp("2026-06-19T01:01:00Z".into()),
        refresh_expires_at: Timestamp("2026-07-19T00:00:00Z".into()),
    }
}

/// Stand up a downstream provider with a single confidential client registered
/// for the `product.example` callback, and issue a code for `acct_ada`.
fn op_provider_with_issued_code(
    nonce: Option<&str>,
) -> (
    awaken_iam_core::OAuthAuthorizationServer<SequentialEntropy>,
    awaken_iam_core::IssuedAuthorizationCode,
) {
    let mut registry = awaken_iam_core::OAuthClientRegistry::new();
    registry.register(awaken_iam_core::RegisteredClient::confidential(
        "product-web",
        "top-secret",
        vec!["https://product.example/cb".into()],
        ["openid", "email", "profile"],
    ));
    let mut provider =
        awaken_iam_core::OAuthAuthorizationServer::new(registry, SequentialEntropy::default());
    let issued = provider
        .issue_code(
            AccountId("acct_ada".into()),
            &awaken_iam_core::OAuthAuthorizationRequest {
                client_id: "product-web".into(),
                redirect_uri: "https://product.example/cb".into(),
                scopes: vec!["openid".into(), "email".into()],
                code_challenge: None,
                code_challenge_method: None,
                nonce: nonce.map(Into::into),
                state: Some("state-1".into()),
            },
            Timestamp("2026-06-21T00:00:00Z".into()),
            Timestamp("2026-06-21T00:05:00Z".into()),
        )
        .expect("issue code");
    (provider, issued)
}

fn redemption(code: &str) -> awaken_iam_core::TokenRedemption {
    awaken_iam_core::TokenRedemption {
        client_id: "product-web".into(),
        client_secret: Some("top-secret".into()),
        code: code.into(),
        redirect_uri: "https://product.example/cb".into(),
        code_verifier: None,
    }
}

fn op_request() -> OpCodeRedemption {
    OpCodeRedemption {
        issuer: "https://iam.example".into(),
        access_audience: "packs-service".into(),
        issued_at: 1_899_996_400,
        access_expires_at: 1_900_000_000,
        id_token_expires_at: 1_899_999_999,
        now: Timestamp("2026-06-21T00:01:00Z".into()),
    }
}

#[test]
fn downstream_authorization_code_flow_issues_and_redeems_tokens() {
    let mut api = api();
    register_downstream_client(&mut api);
    let (result, cookie) = logged_in_session(&mut api);
    let account_id = result.session.account_id.clone();

    // `GET /v1/oauth/authorize`: the authenticated end-user's session backs a
    // code bound to the product client, returned on its registered redirect URI.
    let authorized = api.authorize(downstream_authorize(&cookie)).unwrap();
    assert!(
        authorized
            .redirect_to
            .starts_with("https://product.example/callback?code=")
    );
    // The opaque `state` is echoed back, percent-encoded so it cannot break out.
    assert!(authorized.redirect_to.contains("&state=state%20abc"));
    assert!(
        api.audit_log()
            .iter()
            .any(|event| matches!(event, AuthAuditEvent::DownstreamCodeIssued { .. }))
    );

    // `POST /v1/oauth/token` (authorization_code): redeem the code for a grant.
    let code = code_from_redirect(&authorized.redirect_to);
    let grant = api.redeem_authorization_code(redeem(&code)).unwrap();

    // The minted access token authenticates the end-user's account and carries
    // the granted scopes; it verifies against the published JWKS.
    let claims = api.verify_access_token(&grant.access_token).unwrap();
    assert_eq!(claims.sub, account_id.0);
    assert_eq!(claims.aud, "product-web");
    assert_eq!(claims.scope, vec!["openid".to_owned(), "email".to_owned()]);
    assert!(grant.refresh_token.starts_with("oiamr_"));
    assert!(
        api.audit_log()
            .iter()
            .any(|event| matches!(event, AuthAuditEvent::DownstreamCodeRedeemed { .. }))
    );
}

#[test]
fn downstream_authorize_fails_closed_without_a_session() {
    let mut api = api();
    register_downstream_client(&mut api);
    // No live IAM session backs the request, so no code is issued.
    let err = api
        .authorize(downstream_authorize("unrelated=1"))
        .unwrap_err();
    assert!(matches!(err, AuthApiError::Login(_)));
    assert!(
        !api.audit_log()
            .iter()
            .any(|event| matches!(event, AuthAuditEvent::DownstreamCodeIssued { .. }))
    );
}

#[test]
fn downstream_authorize_rejects_an_unregistered_client() {
    let mut api = api();
    let (_result, cookie) = logged_in_session(&mut api);
    // The client was never registered with the OpenID Provider.
    let err = api.authorize(downstream_authorize(&cookie)).unwrap_err();
    assert_eq!(
        err,
        AuthApiError::OAuthProvider(awaken_iam_core::OAuthProviderError::UnknownClient)
    );
}

#[test]
fn downstream_authorization_code_is_single_use() {
    let mut api = api();
    register_downstream_client(&mut api);
    let (_result, cookie) = logged_in_session(&mut api);
    let authorized = api.authorize(downstream_authorize(&cookie)).unwrap();
    let code = code_from_redirect(&authorized.redirect_to);

    api.redeem_authorization_code(redeem(&code)).unwrap();
    // Replaying the consumed code fails closed; it can never mint a second grant.
    let err = api.redeem_authorization_code(redeem(&code)).unwrap_err();
    assert_eq!(
        err,
        AuthApiError::OAuthProvider(awaken_iam_core::OAuthProviderError::InvalidGrant)
    );
}

#[test]
fn redeeming_a_code_mints_a_signed_access_token_and_an_id_token() {
    let mut api = api();
    let (mut provider, issued) = op_provider_with_issued_code(Some("nonce-xyz"));

    let grant = api
        .redeem_op_code(&mut provider, &redemption(&issued.code), op_request())
        .expect("redeem");

    // The grant carries the down-scoped set and the authenticated account.
    assert_eq!(grant.account_id, AccountId("acct_ada".into()));
    assert_eq!(grant.scopes, vec!["openid".to_owned(), "email".to_owned()]);

    // The access token verifies against the published JWKS + denylist and stamps
    // the grant's subject and scopes — never client-supplied claims.
    let access = api.verify_access_token(&grant.access_token).unwrap();
    assert_eq!(access.iss, "https://iam.example");
    assert_eq!(access.sub, "acct_ada");
    assert_eq!(access.aud, "packs-service");
    assert_eq!(access.scope, vec!["openid".to_owned(), "email".to_owned()]);
    assert_eq!(access.jti, grant.access_token_jti);

    // The id_token verifies against the same JWKS and asserts the OIDC subject to
    // the redeeming client: its audience is the client_id, and the request nonce
    // is bound in.
    let id = crate::verify_id_token(&grant.id_token, &api.jwks()).unwrap();
    assert_eq!(id.iss, "https://iam.example");
    assert_eq!(id.sub, "acct_ada");
    assert_eq!(id.aud, "product-web");
    assert_eq!(id.iat, 1_899_996_400);
    assert_eq!(id.exp, 1_899_999_999);
    assert_eq!(id.nonce.as_deref(), Some("nonce-xyz"));

    // Family fence on the real artifacts: the id_token cannot be replayed as an
    // access token.
    assert!(api.verify_access_token(&grant.id_token).is_err());
}

#[test]
fn redeeming_without_a_request_nonce_omits_the_id_token_nonce() {
    let mut api = api();
    let (mut provider, issued) = op_provider_with_issued_code(None);

    let grant = api
        .redeem_op_code(&mut provider, &redemption(&issued.code), op_request())
        .expect("redeem");

    let id = crate::verify_id_token(&grant.id_token, &api.jwks()).unwrap();
    assert_eq!(id.nonce, None);
}

#[test]
fn a_replayed_code_fails_closed_through_the_provider() {
    let mut api = api();
    let (mut provider, issued) = op_provider_with_issued_code(Some("nonce-xyz"));

    // First redemption succeeds and consumes the single-use code.
    api.redeem_op_code(&mut provider, &redemption(&issued.code), op_request())
        .expect("first redeem");

    // A second redemption surfaces the provider's invalid-grant error and mints
    // nothing.
    let err = api
        .redeem_op_code(&mut provider, &redemption(&issued.code), op_request())
        .unwrap_err();
    assert_eq!(
        err,
        AuthApiError::OAuthProvider(awaken_iam_core::OAuthProviderError::InvalidGrant)
    );
}
