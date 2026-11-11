//! Product-scoped organization login commands over the existing broker authority.

mod http;
mod model;
pub use http::{OrganizationLoginAccess, OrganizationLoginProduct, organization_login_router};

use std::sync::Arc;

use awaken_iam_contract::{
    CreateOrganizationLoginConnection as CreateConnection,
    OrganizationLoginConfiguration as LoginConfigurationView,
    OrganizationLoginConnection as ConnectionView, OrganizationLoginOption as LoginOption,
    UpdateOrganizationLoginConnection as UpdateConnection,
};
use awaken_iam_contract::{OrgId, ProductId};
pub use model::{BrokerConnection, OidcLoginConfiguration, valid_endpoint, valid_issuer};
use model::{connection_id, scope_prefix, valid_scopes, valid_text};

#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum OrganizationLoginError {
    #[error("organization login configuration is invalid")]
    Invalid,
    #[error("organization login connection was not found")]
    NotFound,
    #[error("organization login connection changed; reload it")]
    Conflict,
    #[error("organization login mutation is already in progress")]
    Busy,
    #[error("identity broker is unavailable")]
    Unavailable,
    #[error("identity broker mutation outcome needs confirmation")]
    Uncertain,
}

/// The outbound broker port has no account, session or application permission operations.
pub trait IdentityBroker: Send + Sync {
    /// Encode/decode the provider's opaque record without moving its wire
    /// format or credential custody into IAM's connection rules.
    fn encode_oidc(
        &self,
        value: &OidcLoginConfiguration,
    ) -> Result<Vec<u8>, OrganizationLoginError>;
    fn decode_oidc(&self, bytes: &[u8]) -> Result<OidcLoginConfiguration, OrganizationLoginError>;
    fn list(&self) -> Result<Vec<BrokerConnection>, OrganizationLoginError>;
    fn create(&self, value: &BrokerConnection) -> Result<bool, OrganizationLoginError>;
    fn replace(&self, value: &BrokerConnection) -> Result<(), OrganizationLoginError>;
    fn remove(&self, id: &str) -> Result<(), OrganizationLoginError>;
}

pub trait DiscoveryCheck: Send + Sync {
    fn check(&self, issuer: &str) -> Result<(), OrganizationLoginError>;
}

pub trait MutationLease {
    fn verify(&mut self) -> Result<(), OrganizationLoginError>;
}

pub trait MutationAdmission: Send + Sync {
    fn acquire(&self, key: &str) -> Result<Box<dyn MutationLease>, OrganizationLoginError>;
}

#[derive(Clone)]
pub struct OrganizationLoginService {
    product: ProductId,
    broker: Arc<dyn IdentityBroker>,
    discovery: Arc<dyn DiscoveryCheck>,
    admission: Arc<dyn MutationAdmission>,
    callback_uri: String,
    provider_key: String,
}

pub struct VerifiedLoginHint {
    connector_id: String,
    authorization_endpoint: url::Url,
}

impl VerifiedLoginHint {
    pub fn apply(&self, target: &str) -> Result<String, OrganizationLoginError> {
        let mut url = url::Url::parse(target).map_err(|_| OrganizationLoginError::Invalid)?;
        if url.origin() != self.authorization_endpoint.origin()
            || url.path() != self.authorization_endpoint.path()
            || !url.username().is_empty()
            || url.password().is_some()
            || url.fragment().is_some()
        {
            return Err(OrganizationLoginError::Invalid);
        }
        for required in ["state", "client_id", "redirect_uri", "code_challenge"] {
            if !url
                .query_pairs()
                .any(|(key, value)| key == required && !value.is_empty())
            {
                return Err(OrganizationLoginError::Invalid);
            }
        }
        if !url
            .query_pairs()
            .any(|(key, value)| key == "code_challenge_method" && value == "S256")
            || url
                .query_pairs()
                .any(|(key, _)| matches!(key.as_ref(), "connector_id" | "prompt"))
        {
            return Err(OrganizationLoginError::Invalid);
        }
        url.query_pairs_mut()
            .append_pair("connector_id", &self.connector_id)
            .append_pair("prompt", "login");
        Ok(url.into())
    }
}

impl OrganizationLoginService {
    pub fn product_id(&self) -> &ProductId {
        &self.product
    }

    pub fn settings(&self, org: &OrgId) -> Result<LoginConfigurationView, OrganizationLoginError> {
        Ok(LoginConfigurationView {
            callback_uri: self.callback_uri.clone(),
            connections: self.list(org)?,
        })
    }
    pub fn new(
        broker: Arc<dyn IdentityBroker>,
        discovery: Arc<dyn DiscoveryCheck>,
        admission: Arc<dyn MutationAdmission>,
        broker_issuer: &str,
        provider_key: &str,
        product: ProductId,
    ) -> Result<Self, OrganizationLoginError> {
        if !valid_issuer(broker_issuer)
            || provider_key.is_empty()
            || provider_key.len() > 64
            || !provider_key.bytes().all(|byte| {
                byte.is_ascii_lowercase() || byte.is_ascii_digit() || matches!(byte, b'-' | b'_')
            })
        {
            return Err(OrganizationLoginError::Invalid);
        }
        Ok(Self {
            product,
            broker,
            discovery,
            admission,
            callback_uri: format!("{}/callback", broker_issuer.trim_end_matches('/')),
            provider_key: provider_key.into(),
        })
    }

    pub fn list(&self, org: &OrgId) -> Result<Vec<ConnectionView>, OrganizationLoginError> {
        self.connections(org)?
            .iter()
            .map(|entry| Ok(self.configuration(org, entry)?.view(entry)))
            .collect()
    }

    pub fn options(&self, org: &OrgId) -> Result<Vec<LoginOption>, OrganizationLoginError> {
        self.connections(org)?
            .iter()
            .map(|entry| {
                self.configuration(org, entry)?;
                let mut path = url::Url::parse("https://iam.invalid/v1/auth/login/")
                    .map_err(|_| OrganizationLoginError::Unavailable)?;
                path.path_segments_mut()
                    .map_err(|_| OrganizationLoginError::Unavailable)?
                    .pop_if_empty()
                    .push(&self.provider_key);
                path.query_pairs_mut()
                    .append_pair("product_id", self.product.as_str())
                    .append_pair("organization_id", &org.0)
                    .append_pair("connector_id", &entry.id);
                Ok(LoginOption {
                    id: entry.id.clone(),
                    name: entry.name.clone(),
                    login_path: format!("{}?{}", path.path(), path.query().unwrap_or_default()),
                })
            })
            .collect()
    }

    pub fn create(
        &self,
        org: &OrgId,
        request: CreateConnection,
    ) -> Result<ConnectionView, OrganizationLoginError> {
        validate_org(org)?;
        if !valid_text(&request.name, 160)
            || !valid_issuer(&request.issuer)
            || !valid_text(&request.client_id, 256)
            || !valid_text(&request.client_secret, 4096)
            || !valid_scopes(&request.scopes)
        {
            return Err(OrganizationLoginError::Invalid);
        }
        self.discovery.check(&request.issuer)?;
        let config = OidcLoginConfiguration {
            issuer: request.issuer,
            client_id: request.client_id,
            client_secret: request.client_secret,
            redirect_uri: self.callback_uri.clone(),
            scopes: request.scopes,
        };
        let entry = BrokerConnection {
            id: connection_id(&self.product, org, &config.issuer, &config.client_id),
            kind: "oidc".into(),
            name: request.name,
            config: self.broker.encode_oidc(&config)?,
            grant_types: vec!["authorization_code".into(), "refresh_token".into()],
        };
        let mut lease = self
            .admission
            .acquire(&format!("institution-login:{}", entry.id))?;
        if let Some(existing) = self.find(org, &entry.id)? {
            return if same_configuration(self.broker.as_ref(), &existing, &entry) {
                Ok(config.view(&existing))
            } else {
                Err(OrganizationLoginError::Conflict)
            };
        }
        lease.verify()?;
        let _result = self.broker.create(&entry);
        self.confirm(org, &entry, &mut *lease)
    }

    pub fn update(
        &self,
        org: &OrgId,
        id: &str,
        request: UpdateConnection,
    ) -> Result<ConnectionView, OrganizationLoginError> {
        validate_org(org)?;
        if !valid_text(&request.name, 160)
            || !valid_text(&request.version, 128)
            || request
                .client_secret
                .as_ref()
                .is_some_and(|value| !valid_text(value, 4096))
        {
            return Err(OrganizationLoginError::Invalid);
        }
        self.require_id_scope(org, id)?;
        let mut lease = self.admission.acquire(&format!("institution-login:{id}"))?;
        let existing = self
            .find(org, id)?
            .ok_or(OrganizationLoginError::NotFound)?;
        let mut config = self.configuration(org, &existing)?;
        if let Some(secret) = request.client_secret {
            config.client_secret = secret;
        }
        let desired = BrokerConnection {
            name: request.name,
            config: self.broker.encode_oidc(&config)?,
            ..existing.clone()
        };
        // An acknowledged or uncertain prior PUT may already have published exactly this request.
        if same_configuration(self.broker.as_ref(), &existing, &desired) {
            return Ok(config.view(&existing));
        }
        if existing.version() != request.version {
            return Err(OrganizationLoginError::Conflict);
        }
        lease.verify()?;
        let _result = self.broker.replace(&desired);
        self.confirm(org, &desired, &mut *lease)
    }

    pub fn remove(
        &self,
        org: &OrgId,
        id: &str,
        version: &str,
    ) -> Result<(), OrganizationLoginError> {
        validate_org(org)?;
        self.require_id_scope(org, id)?;
        if !valid_text(version, 128) {
            return Err(OrganizationLoginError::Invalid);
        }
        let mut lease = self.admission.acquire(&format!("institution-login:{id}"))?;
        let Some(existing) = self.find(org, id)? else {
            return Ok(());
        };
        if existing.version() != version {
            return Err(OrganizationLoginError::Conflict);
        }
        lease.verify()?;
        let _result = self.broker.remove(id);
        if self.find(org, id)?.is_some() {
            return Err(OrganizationLoginError::Uncertain);
        }
        lease
            .verify()
            .map_err(|_| OrganizationLoginError::Uncertain)
    }

    pub fn selected(&self, org: &OrgId, id: &str) -> Result<(), OrganizationLoginError> {
        let entry = self
            .find(org, id)?
            .ok_or(OrganizationLoginError::NotFound)?;
        self.configuration(org, &entry)?;
        Ok(())
    }

    pub fn login_hint(
        &self,
        org: &OrgId,
        id: &str,
    ) -> Result<VerifiedLoginHint, OrganizationLoginError> {
        self.selected(org, id)?;
        let issuer = self
            .callback_uri
            .strip_suffix("/callback")
            .ok_or(OrganizationLoginError::Unavailable)?;
        Ok(VerifiedLoginHint {
            connector_id: id.into(),
            authorization_endpoint: url::Url::parse(&format!("{issuer}/auth"))
                .map_err(|_| OrganizationLoginError::Unavailable)?,
        })
    }

    pub fn provider_key(&self) -> &str {
        &self.provider_key
    }

    fn confirm(
        &self,
        org: &OrgId,
        desired: &BrokerConnection,
        lease: &mut dyn MutationLease,
    ) -> Result<ConnectionView, OrganizationLoginError> {
        let actual = self
            .find(org, &desired.id)
            .map_err(|_| OrganizationLoginError::Uncertain)?
            .filter(|value| same_configuration(self.broker.as_ref(), value, desired))
            .ok_or(OrganizationLoginError::Uncertain)?;
        lease
            .verify()
            .map_err(|_| OrganizationLoginError::Uncertain)?;
        Ok(self.configuration(org, &actual)?.view(&actual))
    }

    fn connections(&self, org: &OrgId) -> Result<Vec<BrokerConnection>, OrganizationLoginError> {
        validate_org(org)?;
        let prefix = scope_prefix(&self.product, org);
        let mut values: Vec<_> = self
            .broker
            .list()?
            .into_iter()
            .filter(|value| value.id.starts_with(&prefix))
            .collect();
        values.sort_by(|a, b| a.id.cmp(&b.id));
        Ok(values)
    }

    fn find(
        &self,
        org: &OrgId,
        id: &str,
    ) -> Result<Option<BrokerConnection>, OrganizationLoginError> {
        self.require_id_scope(org, id)?;
        self.connections(org)
            .map(|values| values.into_iter().find(|value| value.id == id))
    }

    fn require_id_scope(&self, org: &OrgId, id: &str) -> Result<(), OrganizationLoginError> {
        if id.len() != scope_prefix(&self.product, org).len() + 24
            || !id.starts_with(&scope_prefix(&self.product, org))
            || !id[scope_prefix(&self.product, org).len()..]
                .bytes()
                .all(|byte| byte.is_ascii_hexdigit())
        {
            return Err(OrganizationLoginError::NotFound);
        }
        Ok(())
    }

    fn configuration(
        &self,
        org: &OrgId,
        entry: &BrokerConnection,
    ) -> Result<OidcLoginConfiguration, OrganizationLoginError> {
        let config = self.broker.decode_oidc(&entry.config)?;
        if entry.kind != "oidc"
            || !valid_issuer(&config.issuer)
            || !valid_text(&config.client_id, 256)
            || !valid_text(&config.client_secret, 4096)
            || entry.id != connection_id(&self.product, org, &config.issuer, &config.client_id)
            || config.redirect_uri != self.callback_uri
            || !valid_scopes(&config.scopes)
        {
            return Err(OrganizationLoginError::Unavailable);
        }
        Ok(config)
    }
}

fn validate_org(org: &OrgId) -> Result<(), OrganizationLoginError> {
    if valid_text(&org.0, 160) {
        Ok(())
    } else {
        Err(OrganizationLoginError::Invalid)
    }
}

fn same_configuration(
    broker: &dyn IdentityBroker,
    left: &BrokerConnection,
    right: &BrokerConnection,
) -> bool {
    left.id == right.id
        && left.kind == right.kind
        && left.name == right.name
        && left.grant_types == right.grant_types
        && broker
            .decode_oidc(&left.config)
            .ok()
            .zip(broker.decode_oidc(&right.config).ok())
            .is_some_and(|(a, b)| a == b)
}

#[cfg(test)]
mod tests;
