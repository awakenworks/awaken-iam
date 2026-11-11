//! Institution connection identities and secret-free views of authoritative broker records.

use super::ConnectionView;
use awaken_iam_contract::{OrgId, ProductId};
use base64::Engine;
use sha2::{Digest, Sha256};

#[derive(Clone)]
pub struct BrokerConnection {
    pub id: String,
    pub kind: String,
    pub name: String,
    pub config: Vec<u8>,
    pub grant_types: Vec<String>,
}

impl std::fmt::Debug for BrokerConnection {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("BrokerConnection")
            .field("id", &self.id)
            .field("kind", &self.kind)
            .field("name", &self.name)
            .field("config", &"REDACTED")
            .finish()
    }
}

impl BrokerConnection {
    pub fn version(&self) -> String {
        let mut digest = Sha256::new();
        for value in [
            self.id.as_bytes(),
            self.kind.as_bytes(),
            self.name.as_bytes(),
            &self.config,
        ] {
            digest.update(value);
            digest.update([0]);
        }
        for grant in &self.grant_types {
            digest.update(grant.as_bytes());
            digest.update([0]);
        }
        base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(digest.finalize())
    }
}

/// Provider-neutral OIDC configuration passed to the injected broker codec.
/// Vendor field spellings and wire validation belong to that adapter.
#[derive(Clone, PartialEq, Eq)]
#[cfg_attr(test, derive(serde::Serialize, serde::Deserialize))]
pub struct OidcLoginConfiguration {
    pub issuer: String,
    pub client_id: String,
    pub client_secret: String,
    pub redirect_uri: String,
    pub scopes: Vec<String>,
}

#[cfg(test)]
pub(crate) fn default_scopes() -> Vec<String> {
    vec!["openid".into(), "profile".into(), "email".into()]
}

pub(super) fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|value| format!("{value:02x}")).collect()
}

pub(crate) fn scope_prefix(product: &ProductId, org: &OrgId) -> String {
    let value = Sha256::digest(org.0.as_bytes());
    format!("{}-{}-", product.as_str(), hex(&value[..16]))
}

pub(crate) fn connection_id(
    product: &ProductId,
    org: &OrgId,
    issuer: &str,
    client: &str,
) -> String {
    let mut digest = Sha256::new();
    digest.update(issuer.as_bytes());
    digest.update([0]);
    digest.update(client.as_bytes());
    let value = digest.finalize();
    format!("{}{}", scope_prefix(product, org), hex(&value[..12]))
}

pub fn valid_issuer(issuer: &str) -> bool {
    valid_provider_url(issuer, false)
}

pub fn valid_endpoint(endpoint: &str) -> bool {
    valid_provider_url(endpoint, true)
}

fn valid_provider_url(value: &str, allow_query: bool) -> bool {
    if value.len() > 2048 || value.trim() != value {
        return false;
    }
    let Ok(url) = url::Url::parse(value) else {
        return false;
    };
    url.scheme() == "https"
        && url.host_str().is_some()
        && url.username().is_empty()
        && url.password().is_none()
        && url.fragment().is_none()
        && (allow_query || url.query().is_none())
}

pub(crate) fn valid_text(value: &str, max: usize) -> bool {
    !value.is_empty()
        && value.len() <= max
        && value.trim() == value
        && !value.chars().any(char::is_control)
}

pub(crate) fn valid_scopes(scopes: &[String]) -> bool {
    !scopes.is_empty()
        && scopes.len() <= 16
        && scopes.iter().any(|value| value == "openid")
        && scopes
            .iter()
            .all(|value| valid_text(value, 128) && !value.chars().any(char::is_whitespace))
}

impl OidcLoginConfiguration {
    pub fn view(&self, connection: &BrokerConnection) -> ConnectionView {
        ConnectionView {
            id: connection.id.clone(),
            name: connection.name.clone(),
            issuer: self.issuer.clone(),
            client_id: self.client_id.clone(),
            scopes: self.scopes.clone(),
            callback_uri: self.redirect_uri.clone(),
            credential_configured: !self.client_secret.is_empty(),
            version: connection.version(),
        }
    }
}
