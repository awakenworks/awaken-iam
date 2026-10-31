//! Token-endpoint client authentication (RFC 6749 §2.3.1).
//!
//! A client presents its credentials either with HTTP Basic
//! (`client_secret_basic`, which every server must support) or in the form
//! body (`client_secret_post`); a public client presents only its
//! `client_id` (`none`). Using two methods in one request is refused.

use axum::http::{HeaderMap, header};
use base64::Engine as _;
use base64::engine::general_purpose::STANDARD;

/// Credentials resolved from one token request.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct ClientCredentials {
    pub(super) client_id: String,
    pub(super) client_secret: Option<String>,
    /// Whether the client authenticated through the `Authorization` header,
    /// which selects a `WWW-Authenticate` challenge on `invalid_client`.
    pub(super) via_basic: bool,
}

/// Why credentials could not be resolved, as an OAuth error code.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum CredentialError {
    /// Missing client id, or conflicting/duplicated methods (`invalid_request`).
    InvalidRequest,
    /// A malformed `Authorization: Basic` header (`invalid_client`).
    InvalidClient,
}

/// Resolve the client's credentials from the `Authorization` header and the
/// form body.
pub(super) fn resolve(
    headers: &HeaderMap,
    form_client_id: Option<String>,
    form_client_secret: Option<String>,
) -> Result<ClientCredentials, CredentialError> {
    let Some(authorization) = headers.get(header::AUTHORIZATION) else {
        let client_id = form_client_id
            .filter(|id| !id.is_empty())
            .ok_or(CredentialError::InvalidRequest)?;
        return Ok(ClientCredentials {
            client_id,
            client_secret: form_client_secret,
            via_basic: false,
        });
    };
    let (client_id, client_secret) = authorization
        .to_str()
        .ok()
        .and_then(parse_basic)
        .ok_or(CredentialError::InvalidClient)?;
    if form_client_secret.is_some()
        || form_client_id
            .as_deref()
            .is_some_and(|form_id| form_id != client_id)
    {
        return Err(CredentialError::InvalidRequest);
    }
    Ok(ClientCredentials {
        client_id,
        client_secret: Some(client_secret),
        via_basic: true,
    })
}

/// Parse `Basic base64(urlencode(id) ":" urlencode(secret))`.
fn parse_basic(value: &str) -> Option<(String, String)> {
    let (scheme, encoded) = value.split_once(' ')?;
    if !scheme.eq_ignore_ascii_case("basic") {
        return None;
    }
    let decoded = String::from_utf8(STANDARD.decode(encoded.trim()).ok()?).ok()?;
    let (id, secret) = decoded.split_once(':')?;
    let id = form_decode(id)?;
    let secret = form_decode(secret)?;
    (!id.is_empty()).then_some((id, secret))
}

/// Decode one `application/x-www-form-urlencoded` component.
fn form_decode(component: &str) -> Option<String> {
    let bytes = component.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut index = 0;
    while index < bytes.len() {
        match bytes[index] {
            b'+' => out.push(b' '),
            b'%' => {
                let hex = component.get(index + 1..index + 3)?;
                out.push(u8::from_str_radix(hex, 16).ok()?);
                index += 2;
            }
            byte => out.push(byte),
        }
        index += 1;
    }
    String::from_utf8(out).ok()
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::http::HeaderValue;

    fn basic(raw: &str) -> HeaderMap {
        let mut headers = HeaderMap::new();
        headers.insert(
            header::AUTHORIZATION,
            HeaderValue::from_str(&format!("Basic {}", STANDARD.encode(raw))).unwrap(),
        );
        headers
    }

    /// Decision table:
    ///
    /// | header | body id | body secret | result |
    /// |---|---|---|---|
    /// | none | id | secret | post credentials |
    /// | none | id | none | public client |
    /// | none | none | any | InvalidRequest |
    /// | Basic id:secret (form-encoded) | none | none | decoded basic credentials |
    /// | Basic | same id | none | basic credentials |
    /// | Basic | other id | none | InvalidRequest |
    /// | Basic | any | secret | InvalidRequest (two methods) |
    /// | malformed / non-Basic | any | any | InvalidClient |
    #[test]
    fn credentials_follow_the_decision_table() {
        let none = HeaderMap::new();
        assert_eq!(
            resolve(&none, Some("web".into()), Some("s".into())),
            Ok(ClientCredentials {
                client_id: "web".into(),
                client_secret: Some("s".into()),
                via_basic: false
            })
        );
        assert_eq!(
            resolve(&none, Some("spa".into()), None)
                .unwrap()
                .client_secret,
            None
        );
        assert_eq!(
            resolve(&none, None, Some("s".into())),
            Err(CredentialError::InvalidRequest)
        );
        let encoded = basic("svc%3Aone:p%40ss+word%25");
        assert_eq!(
            resolve(&encoded, None, None),
            Ok(ClientCredentials {
                client_id: "svc:one".into(),
                client_secret: Some("p@ss word%".into()),
                via_basic: true
            })
        );
        let header = basic("svc:secret");
        assert!(resolve(&header, Some("svc".into()), None).is_ok());
        assert_eq!(
            resolve(&header, Some("other".into()), None),
            Err(CredentialError::InvalidRequest)
        );
        assert_eq!(
            resolve(&header, None, Some("secret".into())),
            Err(CredentialError::InvalidRequest)
        );
        for malformed in ["Basic !!!", "Bearer abc"] {
            let mut headers = HeaderMap::new();
            headers.insert(header::AUTHORIZATION, HeaderValue::from_static(malformed));
            assert_eq!(
                resolve(&headers, None, None),
                Err(CredentialError::InvalidClient)
            );
        }
        assert_eq!(
            resolve(&basic("no-colon"), None, None),
            Err(CredentialError::InvalidClient)
        );
        assert_eq!(
            resolve(&basic("bad%zz:secret"), None, None),
            Err(CredentialError::InvalidClient)
        );
    }
}
