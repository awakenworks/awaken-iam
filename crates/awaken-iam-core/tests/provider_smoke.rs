//! Provider login smoke tests.
//!
//! The fake-provider smoke always runs; it is what CI exercises by default and
//! covers the same provider+subject identity model the real providers feed.
//!
//! The real Google/GitHub smokes are opt-in. They run only when the provider's
//! `IAM_E2E_REAL_*` flag is set and its client id, secret, and redirect URI are
//! present in the environment; otherwise the gate reports a skip and the body
//! returns without failing, keeping a default CI run on the fake provider alone.
//! When enabled, each builds the real provider adapter from the environment and
//! smoke-checks the front half of the login loop — the authorization redirect —
//! which is where a misconfigured client id or redirect URI surfaces, without
//! standing up a browser or reaching a live endpoint.

use std::collections::HashMap;

use awaken_iam_contract::{
    Account, AccountId, AccountStatus, ExternalIdentity, ExternalIdentityClaims,
    ExternalIdentityId, ExternalSubject, IdentityProviderKey, Timestamp,
};
use awaken_iam_core::smoke::{
    RealProvider, SmokeGate, SmokeProviderConfig, evaluate_gate_from_env, provider_config_from_env,
};
use awaken_iam_core::{
    AuthorizationUrlRequest, GithubAccessToken, GithubEmail, GithubProviderAdapter,
    GithubTokenRequest, GithubTransport, GithubTransportError, GithubUser, GoogleOidcProvider,
    GoogleProviderSecrets, HttpRequest, HttpTransport, IdentityDirectory, IdentityProviderAdapter,
    Jwk,
};

#[test]
fn fake_provider_login_smoke() {
    // CI default: a deterministic fake provider links and resolves an identity.
    let provider_key = IdentityProviderKey("fake".into());
    let subject = ExternalSubject("fake-subject-1".into());

    let mut directory = IdentityDirectory::new();
    directory.upsert_account(account("acct_fake"));
    directory
        .link_external_identity(external_identity(
            "ext_fake",
            "acct_fake",
            &provider_key,
            &subject,
            Some("ada@example.com"),
        ))
        .expect("fake identity links cleanly");

    let resolved = directory
        .external_identity(&provider_key, &subject)
        .expect("linked fake identity resolves");
    assert_eq!(resolved.account_id, AccountId("acct_fake".into()));

    // A later login refreshes the mutable email claim without re-linking.
    let refreshed = directory
        .update_external_identity_claims(
            provider_key.clone(),
            claims(&subject, Some("ada+new@example.com")),
            Timestamp("2026-06-20T01:00:00Z".into()),
        )
        .expect("claim refresh succeeds");
    assert_eq!(
        refreshed.claims.email.as_deref(),
        Some("ada+new@example.com")
    );
}

#[test]
fn google_real_login_smoke() {
    if let Some(built) = gated_config(RealProvider::Google) {
        let provider = GoogleOidcProvider::new(
            GoogleProviderSecrets::new("unused-for-authorization-url"),
            UnusedHttp,
            UnusedVerifier,
        );
        let url = authorization_url(&provider, &built);
        assert_authorization_url(&url, &built, "https://accounts.google.com/o/oauth2/v2/auth");
        // OIDC carries a nonce on the wire; this redirect must echo it.
        assert!(url.contains("&nonce="), "google redirect must carry nonce");
    }
}

#[test]
fn github_real_login_smoke() {
    if let Some(built) = gated_config(RealProvider::GitHub) {
        let adapter = GithubProviderAdapter::new(UnusedGithub);
        let url = authorization_url(&adapter, &built);
        assert_authorization_url(&url, &built, "https://github.com/login/oauth/authorize");
        // Classic GitHub OAuth apps support neither OIDC nonce nor PKCE.
        assert!(
            !url.contains("nonce=") && !url.contains("code_challenge="),
            "github redirect must not carry nonce or pkce"
        );
    }
}

/// Resolve the opt-in gate for `provider`, returning the built config when the
/// real smoke should run, or `None` (after logging the skip reason) otherwise.
fn gated_config(provider: RealProvider) -> Option<SmokeProviderConfig> {
    let gate = evaluate_gate_from_env(provider);
    if !gate.should_run() {
        let reason = gate
            .skip_reason(provider)
            .unwrap_or_else(|| "gate not satisfied".to_owned());
        eprintln!(
            "skipping {:?} real provider smoke: {reason}",
            provider.provider_key()
        );
        assert!(matches!(
            gate,
            SmokeGate::OptedOut | SmokeGate::MissingConfig { .. }
        ));
        return None;
    }
    let built = provider_config_from_env(provider)
        .expect("gate confirmed the client id and redirect URI are present");
    assert_eq!(built.config.provider_key, provider.provider_key());
    assert_eq!(built.config.kind, provider.kind());
    assert!(built.config.enabled, "real provider config must be enabled");
    Some(built)
}

/// Build the authorization redirect for `built` through a real `adapter`.
fn authorization_url<A: IdentityProviderAdapter>(
    adapter: &A,
    built: &SmokeProviderConfig,
) -> String {
    adapter
        .authorization_url(
            &built.config,
            &AuthorizationUrlRequest {
                redirect_uri: built.redirect_uri.clone(),
                state: "smoke-state-token".to_owned(),
                nonce: Some("smoke-nonce".to_owned()),
                pkce_challenge: None,
                scopes: built.scopes.clone(),
            },
        )
        .expect("real adapter builds an authorization redirect")
        .url
}

/// Assert the redirect targets `endpoint` and round-trips the configured client
/// id, redirect URI, and state through the query string.
fn assert_authorization_url(url: &str, built: &SmokeProviderConfig, endpoint: &str) {
    assert!(
        url.starts_with(&format!("{endpoint}?")),
        "redirect must target {endpoint}, got {url}"
    );
    let params = parse_query(url);
    assert_eq!(
        params.get("response_type").map(String::as_str),
        Some("code")
    );
    assert_eq!(
        params.get("client_id").cloned(),
        built.config.client_id,
        "client id must round-trip on the wire"
    );
    assert_eq!(
        params.get("redirect_uri"),
        Some(&built.redirect_uri),
        "redirect URI must round-trip byte-for-byte"
    );
    assert_eq!(
        params.get("state").map(String::as_str),
        Some("smoke-state-token")
    );
    assert_eq!(
        params.get("scope"),
        Some(&built.scopes.join(" ")),
        "requested scopes must round-trip on the wire"
    );
}

fn parse_query(url: &str) -> HashMap<String, String> {
    let query = url.split_once('?').map(|(_, q)| q).unwrap_or("");
    query
        .split('&')
        .filter(|pair| !pair.is_empty())
        .filter_map(|pair| pair.split_once('='))
        .map(|(name, value)| (name.to_owned(), percent_decode(value)))
        .collect()
}

fn percent_decode(value: &str) -> String {
    let bytes = value.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut index = 0;
    while index < bytes.len() {
        match bytes[index] {
            b'%' if index + 2 < bytes.len() => {
                match (hex_value(bytes[index + 1]), hex_value(bytes[index + 2])) {
                    (Some(high), Some(low)) => {
                        out.push((high << 4) | low);
                        index += 3;
                    }
                    _ => {
                        out.push(b'%');
                        index += 1;
                    }
                }
            }
            b'+' => {
                out.push(b' ');
                index += 1;
            }
            byte => {
                out.push(byte);
                index += 1;
            }
        }
    }
    String::from_utf8(out).expect("decoded query value is valid utf8")
}

fn hex_value(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        b'A'..=b'F' => Some(byte - b'A' + 10),
        _ => None,
    }
}

/// Transport seams below are required to satisfy the adapter trait bounds, but
/// building an authorization redirect never reaches the network, so they panic
/// if a future change accidentally invokes them during this smoke.
struct UnusedHttp;

impl HttpTransport for UnusedHttp {
    fn execute(&self, _request: &HttpRequest) -> Result<Vec<u8>, String> {
        unreachable!("authorization-url smoke must not perform network I/O")
    }
}

struct UnusedVerifier;

impl awaken_iam_core::JwsVerifier for UnusedVerifier {
    fn verify(&self, _alg: &str, _jwk: &Jwk, _signing_input: &[u8], _signature: &[u8]) -> bool {
        unreachable!("authorization-url smoke must not verify signatures")
    }
}

struct UnusedGithub;

impl GithubTransport for UnusedGithub {
    fn exchange_code(
        &self,
        _request: &GithubTokenRequest<'_>,
    ) -> Result<GithubAccessToken, GithubTransportError> {
        unreachable!("authorization-url smoke must not exchange codes")
    }

    fn fetch_user(&self, _access_token: &str) -> Result<GithubUser, GithubTransportError> {
        unreachable!("authorization-url smoke must not fetch users")
    }

    fn fetch_emails(&self, _access_token: &str) -> Result<Vec<GithubEmail>, GithubTransportError> {
        unreachable!("authorization-url smoke must not fetch emails")
    }
}

fn account(id: &str) -> Account {
    Account {
        id: AccountId(id.into()),
        status: AccountStatus::Active,
        display_name: None,
        created_at: Timestamp("2026-06-20T00:00:00Z".into()),
        updated_at: Timestamp("2026-06-20T00:00:00Z".into()),
    }
}

fn external_identity(
    id: &str,
    account_id: &str,
    provider_key: &IdentityProviderKey,
    subject: &ExternalSubject,
    email: Option<&str>,
) -> ExternalIdentity {
    ExternalIdentity {
        id: ExternalIdentityId(id.into()),
        account_id: AccountId(account_id.into()),
        provider_key: provider_key.clone(),
        claims: claims(subject, email),
        first_seen_at: Timestamp("2026-06-20T00:00:00Z".into()),
        last_seen_at: Timestamp("2026-06-20T00:00:00Z".into()),
    }
}

fn claims(subject: &ExternalSubject, email: Option<&str>) -> ExternalIdentityClaims {
    ExternalIdentityClaims {
        subject: subject.clone(),
        email: email.map(str::to_owned),
        email_verified: email.map(|_| true),
        display_name: None,
        username: None,
        avatar_url: None,
        locale: None,
    }
}
