//! Opt-in real-provider smoke-test gating.
//!
//! CI exercises the deterministic fake provider by default. Real Google and
//! GitHub smoke tests are opt-in: a run must set the provider's `IAM_E2E_REAL_*`
//! flag *and* supply that provider's client credentials and redirect URI before
//! the real test body executes. Without both the gate keeps the run on the fake
//! provider only, so an unconfigured CI never depends on a live third-party app.
//!
//! The environment variables are exactly the ones an operator already populates
//! to run a real provider (`GOOGLE_CLIENT_ID`, `GITHUB_REDIRECT_URI`, ...), as
//! documented in the provider setup runbook; opting a smoke run in is then just
//! adding the matching `IAM_E2E_REAL_*` flag. Secrets stay in the environment —
//! the client secret is read only to confirm availability and is never copied
//! onto the public [`IdentityProviderConfig`] contract (guardrail G5).
//!
//! The decision logic is pure and takes an environment lookup closure, which
//! keeps it deterministic and unit-testable without mutating process state.

use awaken_iam_contract::{
    IdentityProviderConfig, IdentityProviderConfigId, IdentityProviderKey, IdentityProviderKind,
};

/// A real (non-fake) identity provider that exposes an opt-in smoke test.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum RealProvider {
    /// Google sign-in (OpenID Connect).
    Google,
    /// GitHub sign-in (OAuth 2.0).
    GitHub,
}

impl RealProvider {
    /// Every real provider that has an opt-in smoke test.
    pub const ALL: [RealProvider; 2] = [RealProvider::Google, RealProvider::GitHub];

    /// Stable provider key used in login routes and identity uniqueness.
    pub fn provider_key(self) -> IdentityProviderKey {
        IdentityProviderKey(
            match self {
                RealProvider::Google => "google",
                RealProvider::GitHub => "github",
            }
            .to_owned(),
        )
    }

    /// Provider implementation family.
    pub fn kind(self) -> IdentityProviderKind {
        match self {
            RealProvider::Google => IdentityProviderKind::Oidc,
            RealProvider::GitHub => IdentityProviderKind::OAuth2,
        }
    }

    /// Environment variable that opts a run into this provider's real smoke test.
    pub fn opt_in_var(self) -> &'static str {
        match self {
            RealProvider::Google => "IAM_E2E_REAL_GOOGLE",
            RealProvider::GitHub => "IAM_E2E_REAL_GITHUB",
        }
    }

    /// Environment variable holding the public OAuth client id.
    pub fn client_id_var(self) -> &'static str {
        match self {
            RealProvider::Google => "GOOGLE_CLIENT_ID",
            RealProvider::GitHub => "GITHUB_CLIENT_ID",
        }
    }

    /// Environment variable holding the OAuth client secret (deployment secret).
    pub fn client_secret_var(self) -> &'static str {
        match self {
            RealProvider::Google => "GOOGLE_CLIENT_SECRET",
            RealProvider::GitHub => "GITHUB_CLIENT_SECRET",
        }
    }

    /// Environment variable holding the absolute callback (redirect) URI.
    pub fn redirect_uri_var(self) -> &'static str {
        match self {
            RealProvider::Google => "GOOGLE_REDIRECT_URI",
            RealProvider::GitHub => "GITHUB_REDIRECT_URI",
        }
    }

    /// Environment variable holding optional space-separated scope overrides.
    pub fn scopes_var(self) -> &'static str {
        match self {
            RealProvider::Google => "GOOGLE_SCOPES",
            RealProvider::GitHub => "GITHUB_SCOPES",
        }
    }

    /// Default scopes requested when [`scopes_var`](Self::scopes_var) is unset.
    pub fn default_scopes(self) -> Vec<String> {
        match self {
            RealProvider::Google => ["openid", "email", "profile"],
            RealProvider::GitHub => ["read:user", "user:email", ""],
        }
        .into_iter()
        .filter(|scope| !scope.is_empty())
        .map(str::to_owned)
        .collect()
    }

    /// Configuration environment variables that must be present to run the real
    /// test: the public client id, the client secret, and the redirect URI.
    pub fn required_vars(self) -> [&'static str; 3] {
        [
            self.client_id_var(),
            self.client_secret_var(),
            self.redirect_uri_var(),
        ]
    }

    /// Canonical, non-secret endpoints baked into the provider config.
    fn endpoints(
        self,
    ) -> (
        &'static str,
        Option<&'static str>,
        &'static str,
        &'static str,
    ) {
        match self {
            // (display, issuer, authorize, token)
            RealProvider::Google => (
                "Google",
                Some("https://accounts.google.com"),
                "https://accounts.google.com/o/oauth2/v2/auth",
                "https://oauth2.googleapis.com/token",
            ),
            RealProvider::GitHub => (
                "GitHub",
                None,
                "https://github.com/login/oauth/authorize",
                "https://github.com/login/oauth/access_token",
            ),
        }
    }
}

/// Outcome of evaluating the real-provider smoke-test gate.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SmokeGate {
    /// Opt-in flag enabled and all configuration present: run the real smoke.
    Run,
    /// Opt-in flag absent or disabled: keep the run on the fake provider only.
    OptedOut,
    /// Opt-in flag enabled but one or more required variables are missing.
    MissingConfig {
        /// Variable names that were expected but not provided.
        missing: Vec<String>,
    },
}

impl SmokeGate {
    /// Whether the real smoke test should execute.
    pub fn should_run(&self) -> bool {
        matches!(self, SmokeGate::Run)
    }

    /// A human-readable reason a real smoke test was skipped, if it was.
    pub fn skip_reason(&self, provider: RealProvider) -> Option<String> {
        match self {
            SmokeGate::Run => None,
            SmokeGate::OptedOut => Some(format!(
                "opted out: set {} to a truthy value to enable",
                provider.opt_in_var()
            )),
            SmokeGate::MissingConfig { missing } => Some(format!(
                "missing required variable(s): {}",
                missing.join(", ")
            )),
        }
    }
}

/// Evaluate the smoke gate for `provider` using `lookup` to read environment.
///
/// `lookup` returns the raw value of an environment variable, or `None` when it
/// is unset. This indirection keeps the decision pure and unit-testable.
pub fn evaluate_gate<F>(provider: RealProvider, lookup: F) -> SmokeGate
where
    F: Fn(&str) -> Option<String>,
{
    if !flag_enabled(lookup(provider.opt_in_var()).as_deref()) {
        return SmokeGate::OptedOut;
    }
    let missing: Vec<String> = provider
        .required_vars()
        .into_iter()
        .filter(|var| !value_present(lookup(var).as_deref()))
        .map(str::to_owned)
        .collect();
    if missing.is_empty() {
        SmokeGate::Run
    } else {
        SmokeGate::MissingConfig { missing }
    }
}

/// Evaluate the gate for `provider` against the process environment.
pub fn evaluate_gate_from_env(provider: RealProvider) -> SmokeGate {
    evaluate_gate(provider, |var| std::env::var(var).ok())
}

/// A real provider's configuration assembled from the environment.
///
/// Carries the public [`IdentityProviderConfig`] contract plus the redirect URI and
/// resolved scopes needed to build an authorization redirect. The client secret
/// is deliberately absent: the gate confirms it is present, but it stays in the
/// environment for the deployment's transport to read (guardrail G5).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SmokeProviderConfig {
    /// Public provider configuration contract (no secret material).
    pub config: IdentityProviderConfig,
    /// Absolute callback URL registered with the upstream provider.
    pub redirect_uri: String,
    /// Scopes to request, resolved from the environment or the default set.
    pub scopes: Vec<String>,
}

/// Assemble a [`SmokeProviderConfig`] for `provider` from supplied values.
///
/// Returns `None` when the client id or redirect URI is missing or blank, so a
/// caller that bypasses the gate still fails closed rather than building a
/// half-configured provider.
pub fn provider_config_from<F>(provider: RealProvider, lookup: F) -> Option<SmokeProviderConfig>
where
    F: Fn(&str) -> Option<String>,
{
    let client_id = non_blank(lookup(provider.client_id_var()))?;
    let redirect_uri = non_blank(lookup(provider.redirect_uri_var()))?;
    let scopes = match non_blank(lookup(provider.scopes_var())) {
        Some(raw) => raw.split_whitespace().map(str::to_owned).collect(),
        None => provider.default_scopes(),
    };

    let (display_name, issuer, authorize, token) = provider.endpoints();
    let key = provider.provider_key();
    let config = IdentityProviderConfig {
        id: IdentityProviderConfigId(format!("idp_{}", key.0)),
        provider_key: key,
        kind: provider.kind(),
        display_name: display_name.to_owned(),
        issuer_url: issuer.map(str::to_owned),
        authorization_endpoint: Some(authorize.to_owned()),
        token_endpoint: Some(token.to_owned()),
        client_id: Some(client_id),
        enabled: true,
    };
    Some(SmokeProviderConfig {
        config,
        redirect_uri,
        scopes,
    })
}

/// Assemble a [`SmokeProviderConfig`] for `provider` from the process
/// environment.
pub fn provider_config_from_env(provider: RealProvider) -> Option<SmokeProviderConfig> {
    provider_config_from(provider, |var| std::env::var(var).ok())
}

/// Whether an opt-in flag value counts as enabled.
///
/// Enabled values are non-empty and not an explicit disable token (`0`,
/// `false`, `no`, `off`, case-insensitive).
fn flag_enabled(value: Option<&str>) -> bool {
    match value.map(str::trim) {
        None | Some("") => false,
        Some(v) => !matches!(
            v.to_ascii_lowercase().as_str(),
            "0" | "false" | "no" | "off"
        ),
    }
}

/// Whether a value is present (set and non-empty after trimming).
fn value_present(value: Option<&str>) -> bool {
    matches!(value.map(str::trim), Some(v) if !v.is_empty())
}

/// Trim a looked-up value and keep it only when non-blank.
fn non_blank(value: Option<String>) -> Option<String> {
    let trimmed = value?.trim().to_owned();
    if trimmed.is_empty() {
        None
    } else {
        Some(trimmed)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    fn lookup_from(pairs: &[(&str, &str)]) -> impl Fn(&str) -> Option<String> + use<> {
        let map: HashMap<String, String> = pairs
            .iter()
            .map(|(k, v)| ((*k).to_owned(), (*v).to_owned()))
            .collect();
        move |var: &str| map.get(var).cloned()
    }

    #[test]
    fn opt_in_and_config_vars_match_the_documented_names() {
        assert_eq!(RealProvider::Google.opt_in_var(), "IAM_E2E_REAL_GOOGLE");
        assert_eq!(RealProvider::GitHub.opt_in_var(), "IAM_E2E_REAL_GITHUB");
        assert_eq!(RealProvider::Google.client_id_var(), "GOOGLE_CLIENT_ID");
        assert_eq!(
            RealProvider::GitHub.redirect_uri_var(),
            "GITHUB_REDIRECT_URI"
        );
        assert_ne!(
            RealProvider::Google.required_vars(),
            RealProvider::GitHub.required_vars()
        );
    }

    #[test]
    fn gate_opts_out_when_flag_absent_even_with_config() {
        let lookup = lookup_from(&[
            ("GOOGLE_CLIENT_ID", "id"),
            ("GOOGLE_CLIENT_SECRET", "secret"),
            (
                "GOOGLE_REDIRECT_URI",
                "https://app.test/v1/auth/callback/google",
            ),
        ]);
        assert_eq!(
            evaluate_gate(RealProvider::Google, lookup),
            SmokeGate::OptedOut
        );
    }

    #[test]
    fn gate_opts_out_for_explicit_disable_tokens() {
        for token in ["0", "false", "no", "off", "OFF", " false ", ""] {
            let lookup = lookup_from(&[
                ("IAM_E2E_REAL_GITHUB", token),
                ("GITHUB_CLIENT_ID", "id"),
                ("GITHUB_CLIENT_SECRET", "secret"),
                (
                    "GITHUB_REDIRECT_URI",
                    "https://app.test/v1/auth/callback/github",
                ),
            ]);
            assert_eq!(
                evaluate_gate(RealProvider::GitHub, lookup),
                SmokeGate::OptedOut,
                "token {token:?} should opt out"
            );
        }
    }

    #[test]
    fn gate_reports_missing_config_when_opted_in() {
        let lookup = lookup_from(&[
            ("IAM_E2E_REAL_GOOGLE", "1"),
            ("GOOGLE_CLIENT_ID", "id"),
            // client secret blank, redirect URI absent
            ("GOOGLE_CLIENT_SECRET", "   "),
        ]);
        assert_eq!(
            evaluate_gate(RealProvider::Google, lookup),
            SmokeGate::MissingConfig {
                missing: vec![
                    "GOOGLE_CLIENT_SECRET".to_owned(),
                    "GOOGLE_REDIRECT_URI".to_owned(),
                ],
            }
        );
    }

    #[test]
    fn gate_runs_when_opted_in_with_all_config() {
        let lookup = lookup_from(&[
            ("IAM_E2E_REAL_GITHUB", "true"),
            ("GITHUB_CLIENT_ID", "id"),
            ("GITHUB_CLIENT_SECRET", "secret"),
            (
                "GITHUB_REDIRECT_URI",
                "https://app.test/v1/auth/callback/github",
            ),
        ]);
        let gate = evaluate_gate(RealProvider::GitHub, lookup);
        assert_eq!(gate, SmokeGate::Run);
        assert!(gate.should_run());
        assert!(gate.skip_reason(RealProvider::GitHub).is_none());
    }

    #[test]
    fn google_config_carries_oidc_endpoints_and_default_scopes() {
        let lookup = lookup_from(&[
            ("GOOGLE_CLIENT_ID", " client-123 "),
            (
                "GOOGLE_REDIRECT_URI",
                " https://app.test/v1/auth/callback/google ",
            ),
        ]);
        let built = provider_config_from(RealProvider::Google, lookup).expect("config built");
        assert_eq!(
            built.config.provider_key,
            RealProvider::Google.provider_key()
        );
        assert_eq!(built.config.kind, IdentityProviderKind::Oidc);
        assert_eq!(built.config.client_id.as_deref(), Some("client-123"));
        assert_eq!(
            built.redirect_uri,
            "https://app.test/v1/auth/callback/google"
        );
        assert_eq!(built.scopes, vec!["openid", "email", "profile"]);
        assert!(built.config.enabled);
        assert_eq!(
            built.config.authorization_endpoint.as_deref(),
            Some("https://accounts.google.com/o/oauth2/v2/auth")
        );
    }

    #[test]
    fn github_config_honors_scope_override_and_omits_issuer() {
        let lookup = lookup_from(&[
            ("GITHUB_CLIENT_ID", "gh-client"),
            (
                "GITHUB_REDIRECT_URI",
                "https://app.test/v1/auth/callback/github",
            ),
            ("GITHUB_SCOPES", "read:user  user:email  repo"),
        ]);
        let built = provider_config_from(RealProvider::GitHub, lookup).expect("config built");
        assert_eq!(built.config.kind, IdentityProviderKind::OAuth2);
        assert!(built.config.issuer_url.is_none());
        assert_eq!(built.scopes, vec!["read:user", "user:email", "repo"]);
    }

    #[test]
    fn config_is_none_without_client_id_or_redirect() {
        let no_redirect = lookup_from(&[("GITHUB_CLIENT_ID", "id")]);
        assert!(provider_config_from(RealProvider::GitHub, no_redirect).is_none());
        let no_id = lookup_from(&[(
            "GITHUB_REDIRECT_URI",
            "https://app.test/v1/auth/callback/github",
        )]);
        assert!(provider_config_from(RealProvider::GitHub, no_id).is_none());
    }
}
