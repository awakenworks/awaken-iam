//! Remote IAM connection: `RemoteIamClient` + JWKS for JWT pre-verification.
//!
//! [`connect_remote`] builds a [`RemoteHandle`] pointing at a live IAM daemon.
//! The caller supplies the base URL; the JWKS is fetched once at connection time
//! so the returned gate can verify EdDSA JWT tokens locally without a round-trip
//! per request.

use awaken_iam_client::{HttpAuthzTransport, HttpTransportConfig, RemoteIamClient};

use crate::{HostConfig, HostConfigError, HostMode, gate::IamGate};

/// Error returned by [`connect_remote`].
#[derive(Debug, thiserror::Error)]
pub enum ConnectError {
    /// A required field was absent or invalid.
    #[error("configuration error: {0}")]
    Config(#[from] HostConfigError),
    /// The JWKS could not be fetched from the remote daemon.
    #[error("JWKS fetch failed: {0}")]
    JwksFetch(String),
}

/// Handle returned by [`connect_remote`].
pub struct RemoteHandle {
    /// Authorization and authentication gate — pass to [`auth_layer`](crate::auth_layer).
    pub gate: IamGate,
}

/// Connect to a remote IAM daemon described by `cfg`.
///
/// Fetches the JWKS from `<base_url>/.well-known/jwks.json` so the gate can
/// verify EdDSA JWT tokens locally. Fails if `cfg.mode` is not
/// [`HostMode::Remote`] or `base_url` is absent.
///
/// # Errors
///
/// Returns [`ConnectError`] when the configuration is invalid or the JWKS
/// cannot be fetched.
pub fn connect_remote(cfg: &HostConfig) -> Result<RemoteHandle, ConnectError> {
    if cfg.mode != HostMode::Remote {
        return Err(ConnectError::Config(HostConfigError::MissingField(
            "mode == Remote",
            cfg.mode.clone(),
        )));
    }
    let base_url =
        cfg.base_url
            .as_deref()
            .ok_or(ConnectError::Config(HostConfigError::MissingField(
                "base_url",
                HostMode::Remote,
            )))?;

    let mut transport_cfg = HttpTransportConfig::new(base_url);
    if let Some(ref token) = cfg.service_token {
        transport_cfg = transport_cfg.with_service_token(token);
    }
    if let Some(ref aud) = cfg.audience {
        transport_cfg = transport_cfg.with_audience(aud);
    }
    let transport = HttpAuthzTransport::new(transport_cfg).map_err(|e| {
        ConnectError::Config(HostConfigError::InvalidValue("base_url", e.to_string()))
    })?;
    let client = RemoteIamClient::new(transport);

    let jwks = fetch_jwks(base_url)?;

    let gate = IamGate::remote(client, Some(jwks))
        .with_audience_opt(cfg.audience.clone())
        .with_issuer_opt(cfg.issuer.clone());

    Ok(RemoteHandle { gate })
}

fn fetch_jwks(base_url: &str) -> Result<awaken_iam_contract::Jwks, ConnectError> {
    let url = format!("{base_url}/.well-known/jwks.json");
    let resp = reqwest::blocking::get(&url).map_err(|e| ConnectError::JwksFetch(e.to_string()))?;
    let jwks = resp
        .json::<awaken_iam_contract::Jwks>()
        .map_err(|e| ConnectError::JwksFetch(e.to_string()))?;
    Ok(jwks)
}
