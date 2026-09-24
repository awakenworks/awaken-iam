//! Standalone composition of the existing generic OIDC adapter and HTTP port.

use std::collections::HashSet;

use awaken_iam_contract::{
    IdentityProviderConfig, IdentityProviderConfigId, IdentityProviderKey, IdentityProviderKind,
};
use awaken_iam_core::{GenericOAuthProvider, GenericOAuthSecrets};
use awaken_iam_server::{AuthApi, ProviderRegistration, ReqwestHttpTransport};
use serde::Deserialize;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct OidcProviderFileEntry {
    provider_key: String,
    display_name: String,
    issuer_url: String,
    client_id: String,
    client_secret_file: String,
    authorization_endpoint: String,
    token_endpoint: String,
    userinfo_endpoint: String,
    #[serde(default = "default_scopes")]
    scopes: Vec<String>,
}

fn default_scopes() -> Vec<String> {
    vec!["openid".into(), "email".into(), "profile".into()]
}

fn safe_endpoint(value: &str) -> bool {
    let Ok(url) = url::Url::parse(value) else {
        return false;
    };
    let loopback = url.scheme() == "http"
        && matches!(url.host_str(), Some("127.0.0.1" | "[::1]" | "localhost"));
    (url.scheme() == "https" || loopback)
        && url.fragment().is_none()
        && url.username().is_empty()
        && url.password().is_none()
}

fn valid_provider_key(key: &str) -> bool {
    !key.is_empty()
        && key.len() <= 64
        && key.bytes().all(|byte| {
            byte.is_ascii_lowercase() || byte.is_ascii_digit() || matches!(byte, b'-' | b'_')
        })
}

fn read_secret(path: &str) -> Result<String, String> {
    let metadata = std::fs::metadata(path)
        .map_err(|error| format!("OIDC secret file unavailable: {error}"))?;
    if !metadata.is_file() {
        return Err("OIDC secret path is not a regular file".into());
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        if metadata.permissions().mode() & 0o077 != 0 {
            return Err("OIDC secret file must be owner-only".into());
        }
    }
    let secret = std::fs::read_to_string(path)
        .map_err(|error| format!("OIDC secret file unreadable: {error}"))?;
    let secret = secret.trim_end_matches(['\r', '\n']);
    if secret.is_empty() || secret != secret.trim() {
        return Err("OIDC client secret is empty or padded".into());
    }
    Ok(secret.to_owned())
}

pub(super) fn register_from_file(
    auth: &mut AuthApi,
    iam_issuer: &str,
    config_file: Option<&str>,
) -> Result<usize, String> {
    let registrations = load_registrations(iam_issuer, config_file)?;
    let count = registrations.len();
    for registration in registrations {
        auth.register_provider(registration);
    }
    Ok(count)
}

fn load_registrations(
    iam_issuer: &str,
    config_file: Option<&str>,
) -> Result<Vec<ProviderRegistration>, String> {
    let Some(config_file) = config_file.filter(|path| !path.trim().is_empty()) else {
        return Ok(Vec::new());
    };
    if !safe_endpoint(iam_issuer) {
        return Err("IAM_ISSUER must be HTTPS or a loopback HTTP origin".into());
    }
    let parsed_issuer =
        url::Url::parse(iam_issuer).map_err(|_| "IAM_ISSUER is invalid".to_string())?;
    if parsed_issuer.path() != "/" || parsed_issuer.query().is_some() {
        return Err("IAM_ISSUER must be an origin without path or query".into());
    }
    let bytes = std::fs::read(config_file)
        .map_err(|error| format!("OIDC provider configuration unavailable: {error}"))?;
    let entries: Vec<OidcProviderFileEntry> = serde_json::from_slice(&bytes)
        .map_err(|error| format!("OIDC provider configuration is invalid: {error}"))?;
    if entries.is_empty() {
        return Err("OIDC provider configuration is empty".into());
    }
    let mut seen = HashSet::new();
    let transport = ReqwestHttpTransport::new()?;
    let mut registrations = Vec::with_capacity(entries.len());
    for entry in entries {
        if !valid_provider_key(&entry.provider_key) || !seen.insert(entry.provider_key.clone()) {
            return Err("OIDC provider keys must be unique lowercase path segments".into());
        }
        if entry.display_name.trim().is_empty()
            || entry.client_id.trim().is_empty()
            || entry.scopes.is_empty()
            || entry.scopes.iter().any(|scope| scope.trim().is_empty())
            || !safe_endpoint(&entry.issuer_url)
            || !safe_endpoint(&entry.authorization_endpoint)
            || !safe_endpoint(&entry.token_endpoint)
            || !safe_endpoint(&entry.userinfo_endpoint)
        {
            return Err(format!(
                "OIDC provider {} has incomplete or unsafe coordinates",
                entry.provider_key
            ));
        }
        let secret = read_secret(&entry.client_secret_file)?;
        let callback = format!(
            "{}/v1/auth/callback/{}",
            iam_issuer.trim_end_matches('/'),
            entry.provider_key
        );
        let config = IdentityProviderConfig {
            id: IdentityProviderConfigId(format!("oidc_{}", entry.provider_key)),
            provider_key: IdentityProviderKey(entry.provider_key),
            kind: IdentityProviderKind::Oidc,
            display_name: entry.display_name,
            issuer_url: Some(entry.issuer_url),
            authorization_endpoint: Some(entry.authorization_endpoint),
            token_endpoint: Some(entry.token_endpoint),
            client_id: Some(entry.client_id),
            enabled: true,
        };
        registrations.push(ProviderRegistration {
            config,
            adapter: Box::new(GenericOAuthProvider::new(
                GenericOAuthSecrets::new(secret, entry.userinfo_endpoint)
                    .with_default_scopes(entry.scopes.clone()),
                transport.clone(),
            )),
            redirect_uri: callback,
            scopes: entry.scopes,
            include_nonce: true,
            include_pkce: true,
        });
    }
    Ok(registrations)
}

#[cfg(test)]
mod tests {
    use super::*;
    use awaken_iam_core::AuthorizationUrlRequest;
    use std::path::PathBuf;

    fn root() -> PathBuf {
        let nonce = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let root =
            std::env::temp_dir().join(format!("iam-oidc-config-{}-{nonce}", std::process::id()));
        std::fs::create_dir(&root).unwrap();
        root
    }

    fn secret(root: &std::path::Path) -> PathBuf {
        let path = root.join("upstream-secret");
        std::fs::write(&path, "upstream-test-secret\n").unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
        }
        path
    }

    fn entry(secret_file: &std::path::Path) -> serde_json::Value {
        serde_json::json!({
            "provider_key":"local", "display_name":"Local OIDC",
            "issuer_url":"http://127.0.0.1:19001",
            "client_id":"iam-upstream-local",
            "client_secret_file":secret_file,
            "authorization_endpoint":"http://127.0.0.1:19001/authorize",
            "token_endpoint":"http://127.0.0.1:19001/token",
            "userinfo_endpoint":"http://127.0.0.1:19001/userinfo"
        })
    }

    #[test]
    fn valid_upstream_config_uses_the_existing_adapter_and_one_derived_callback() {
        // Decision rule O1: C1 owner-only client secret and complete loopback
        // endpoint coordinates => E1 one enabled OIDC provider with IAM-derived
        // callback, nonce/PKCE enabled and no network call during registration.
        let root = root();
        let secret_file = secret(&root);
        let config_file = root.join("providers.json");
        std::fs::write(
            &config_file,
            serde_json::to_vec(&vec![entry(&secret_file)]).unwrap(),
        )
        .unwrap();
        let mut registrations =
            load_registrations("http://127.0.0.1:18180", config_file.to_str()).unwrap();
        assert_eq!(registrations.len(), 1, "O1");
        let registration = registrations.pop().unwrap();
        assert_eq!(
            registration.redirect_uri,
            "http://127.0.0.1:18180/v1/auth/callback/local"
        );
        assert!(
            registration.include_nonce && registration.include_pkce,
            "O1"
        );
        let redirect = registration
            .adapter
            .authorization_url(
                &registration.config,
                &AuthorizationUrlRequest {
                    redirect_uri: registration.redirect_uri.clone(),
                    state: "state-a".into(),
                    nonce: Some("nonce-a".into()),
                    pkce_challenge: None,
                    scopes: registration.scopes.clone(),
                },
            )
            .unwrap();
        let url = url::Url::parse(&redirect.url).unwrap();
        assert_eq!(url.host_str(), Some("127.0.0.1"));
        assert_eq!(
            url.query_pairs()
                .find(|(key, _)| key == "client_id")
                .unwrap()
                .1,
            "iam-upstream-local"
        );
        assert_eq!(
            url.query_pairs().find(|(key, _)| key == "nonce").unwrap().1,
            "nonce-a"
        );
        let mut auth = AuthApi::new();
        assert_eq!(
            register_from_file(&mut auth, "http://127.0.0.1:18180", config_file.to_str()).unwrap(),
            1
        );
        assert_eq!(auth.list_providers().len(), 1);
        std::fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn malformed_or_unreadable_config_registers_no_partial_provider() {
        // Decision table: C1 no config file selected => E1 no provider; C2 a
        // second duplicate key, unsafe remote HTTP endpoint or bad secret mode
        // => E2 startup refusal before any provider is registered. R1 C1=>E1;
        // R2 C2=>E2. Secret bytes never enter a diagnostic.
        let root = root();
        let secret_file = secret(&root);
        let config_file = root.join("providers.json");
        let mut auth = AuthApi::new();
        assert_eq!(
            register_from_file(&mut auth, "http://127.0.0.1:18180", None).unwrap(),
            0,
            "R1"
        );
        std::fs::write(
            &config_file,
            serde_json::to_vec(&vec![entry(&secret_file), entry(&secret_file)]).unwrap(),
        )
        .unwrap();
        assert!(
            register_from_file(&mut auth, "http://127.0.0.1:18180", config_file.to_str()).is_err(),
            "R2 duplicate"
        );
        assert!(auth.list_providers().is_empty(), "R2 atomic registration");
        let mut unsafe_entry = entry(&secret_file);
        unsafe_entry["token_endpoint"] = "http://foreign.example/token".into();
        std::fs::write(
            &config_file,
            serde_json::to_vec(&vec![unsafe_entry]).unwrap(),
        )
        .unwrap();
        assert!(
            register_from_file(&mut auth, "http://127.0.0.1:18180", config_file.to_str()).is_err(),
            "R2 endpoint"
        );
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&secret_file, std::fs::Permissions::from_mode(0o644)).unwrap();
            std::fs::write(
                &config_file,
                serde_json::to_vec(&vec![entry(&secret_file)]).unwrap(),
            )
            .unwrap();
            assert!(
                register_from_file(&mut auth, "http://127.0.0.1:18180", config_file.to_str())
                    .is_err(),
                "R2 secret mode"
            );
        }
        assert!(auth.list_providers().is_empty(), "R2");
        std::fs::remove_dir_all(root).unwrap();
    }
}
