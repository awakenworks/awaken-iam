//! Product-independent organization identity-federation wire contracts.

use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct OrganizationLoginConnection {
    pub id: String,
    pub name: String,
    pub issuer: String,
    pub client_id: String,
    pub scopes: Vec<String>,
    pub callback_uri: String,
    pub credential_configured: bool,
    pub version: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct OrganizationLoginOption {
    pub id: String,
    pub name: String,
    pub login_path: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct OrganizationLoginConfiguration {
    pub callback_uri: String,
    pub connections: Vec<OrganizationLoginConnection>,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CreateOrganizationLoginConnection {
    pub name: String,
    pub issuer: String,
    pub client_id: String,
    pub client_secret: String,
    #[serde(default = "organization_login_default_scopes")]
    pub scopes: Vec<String>,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct UpdateOrganizationLoginConnection {
    pub name: String,
    pub client_secret: Option<String>,
    pub version: String,
}

fn organization_login_default_scopes() -> Vec<String> {
    vec!["openid".into(), "profile".into(), "email".into()]
}

#[cfg(test)]
mod tests {
    use crate::ProductId;
    #[test]
    fn product_action_boundary_uses_exact_configured_identity() {
        // A1 exact product + nonempty concrete action => admit. A2 a shared
        // textual prefix, foreign product, empty action, wildcard, internal
        // namespace separator or whitespace => refuse. Two arbitrary products
        // use the same rule; registration and decision transport reuse it.
        for name in ["tutor", "another-product"] {
            let product = ProductId::new(name).unwrap();
            for (action, expected) in [
                (format!("{name}.campus.manage"), true),
                (format!("{name}-other.manage"), false),
                (format!("{name}."), false),
                (format!("{name}.*"), false),
                (format!("{name}.x::y"), false),
                (format!("{name}.has space"), false),
                ("foreign.read".into(), false),
            ] {
                assert_eq!(product.owns_action(&action), expected, "{action}");
            }
        }
    }
}
