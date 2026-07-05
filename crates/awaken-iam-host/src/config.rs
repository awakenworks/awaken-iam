//! Host configuration: environment → IAM deployment mode.

use std::path::PathBuf;

/// IAM deployment mode selected by the host configuration.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HostMode {
    /// No authentication or authorization. Every request is permitted.
    ///
    /// Safe only for local development and unit tests.
    Open,
    /// IAM runs in-process, backed by a SQLite database.
    ///
    /// The host owns the database file at [`HostConfig::data_dir`]; IAM
    /// migrates its schema under the `iam` prefix and seeds preset roles on
    /// first startup. API tokens are verified by the in-process
    /// [`ApiTokenDirectory`](awaken_iam_core::ApiTokenDirectory).
    Local,
    /// IAM runs as a remote daemon; this host is a consumer.
    ///
    /// Authorization decisions are delegated to the daemon at
    /// [`HostConfig::base_url`]. Bearer tokens that carry an EdDSA JWT are
    /// verified locally against JWKS fetched from the daemon.
    Remote,
}

/// Configuration for the IAM host layer.
///
/// Construct programmatically or deserialize from environment / config files.
/// The defaults are safe for local development (`Open` mode, in-memory storage).
#[derive(Debug, Clone)]
pub struct HostConfig {
    /// Deployment mode.
    pub mode: HostMode,
    /// Directory for IAM state (SQLite file, bootstrap token) in `Local` mode.
    ///
    /// Defaults to the current working directory when `None`. Ignored in
    /// `Open` and `Remote` modes.
    pub data_dir: Option<PathBuf>,
    /// 32-byte seed for the local Ed25519 signing key, hex-encoded.
    ///
    /// Required in `Local` mode when JWT bearer tokens are to be issued or
    /// verified locally. When `None` in `Local` mode, no JWT authority is
    /// configured (API tokens only).
    pub seal_key: Option<[u8; 32]>,
    /// Root URL of the remote IAM daemon (e.g. `https://iam.example.com`).
    ///
    /// Required in `Remote` mode; ignored otherwise.
    pub base_url: Option<String>,
    /// Audience claim expected in bearer JWTs.
    ///
    /// When set, [`auth_layer`](crate::auth_layer) rejects tokens whose `aud`
    /// claim does not match. When `None`, audience validation is skipped.
    pub audience: Option<String>,
    /// Expected JWT `iss` (issuer) claim.
    ///
    /// When set, [`auth_layer`](crate::auth_layer) rejects tokens whose `iss`
    /// claim does not match. When `None`, issuer validation is skipped.
    pub issuer: Option<String>,
    /// Service-principal bearer token sent to the remote daemon.
    ///
    /// Used only in `Remote` mode as the `Authorization: Bearer` credential
    /// for calls the host makes to the IAM daemon as a service principal.
    pub service_token: Option<String>,
}

impl HostConfig {
    /// Open mode: no authentication, no authorization.
    pub fn open() -> Self {
        Self {
            mode: HostMode::Open,
            data_dir: None,
            seal_key: None,
            base_url: None,
            audience: None,
            issuer: None,
            service_token: None,
        }
    }

    /// Local embedded mode backed by a file-based SQLite database.
    pub fn local(data_dir: PathBuf) -> Self {
        Self {
            mode: HostMode::Local,
            data_dir: Some(data_dir),
            seal_key: None,
            base_url: None,
            audience: None,
            issuer: None,
            service_token: None,
        }
    }

    /// Local embedded mode backed by an in-memory SQLite database.
    pub fn local_in_memory() -> Self {
        Self {
            mode: HostMode::Local,
            data_dir: None,
            seal_key: None,
            base_url: None,
            audience: None,
            issuer: None,
            service_token: None,
        }
    }

    /// Remote mode pointing at a daemon at `base_url`.
    pub fn remote(base_url: impl Into<String>) -> Self {
        Self {
            mode: HostMode::Remote,
            data_dir: None,
            seal_key: None,
            base_url: Some(base_url.into()),
            audience: None,
            issuer: None,
            service_token: None,
        }
    }

    /// Attach an audience claim to validate.
    pub fn with_audience(mut self, audience: impl Into<String>) -> Self {
        self.audience = Some(audience.into());
        self
    }

    /// Attach an issuer claim to validate.
    pub fn with_issuer(mut self, issuer: impl Into<String>) -> Self {
        self.issuer = Some(issuer.into());
        self
    }

    /// Attach the Ed25519 seed used for local JWT signing and verification.
    pub fn with_seal_key(mut self, seed: [u8; 32]) -> Self {
        self.seal_key = Some(seed);
        self
    }
}

/// Error constructing a [`HostConfig`] from environment variables or
/// validating it for a specific mode.
#[derive(Debug, thiserror::Error)]
pub enum HostConfigError {
    /// A required field was absent for the selected mode.
    #[error("required field `{0}` is missing for mode `{1:?}`")]
    MissingField(&'static str, HostMode),
    /// A field value was syntactically invalid.
    #[error("invalid value for `{0}`: {1}")]
    InvalidValue(&'static str, String),
}
