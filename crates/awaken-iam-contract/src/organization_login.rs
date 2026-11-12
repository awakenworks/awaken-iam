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
    use crate::{ActionKey, NamespaceId, ProductId};

    #[test]
    fn product_action_boundary_uses_exact_configured_identity() {
        // Existing dotted actions retain their full concrete-suffix range.
        // Product-owned profile actions also use their published namespace delimiter.
        for name in ["tutor", "another-product", "acme.service", "p_9"] {
            let product = ProductId::new(name).unwrap();
            for (action, expected) in [
                (format!("{name}.campus.manage"), true),
                (format!("{name}..campus.manage"), true),
                (format!("{name}.campus/read+manage"), true),
                (format!("{name}.\u{03bb}.read"), true),
                (format!("{name}-other.manage"), false),
                (format!("{name}other.manage"), false),
                (format!("{name}."), false),
                (format!("{name}.*"), false),
                (format!("{name}.x::y"), true),
                (format!("{name}.x::y::z"), false),
                (format!("{name}.resource:read"), false),
                (format!("{name}.has space"), false),
                (format!("{name}.has\tspace"), false),
                ("foreign.read".into(), false),
            ] {
                assert_eq!(product.owns_action(&action), expected, "{action}");
            }
        }
    }

    #[test]
    fn product_action_boundary_accepts_published_profile_syntax() {
        for name in ["awaken", "acme.service"] {
            let product = ProductId::new(name).unwrap();
            for namespace in [
                name.to_owned(),
                format!("{name}.workspace"),
                format!("{name}.Runtime_9-ops"),
                format!("{name}..nested"),
                format!("{name}."),
            ] {
                let action = ActionKey::in_namespace(&NamespaceId(namespace), "agent.use");
                assert!(product.owns_action(&action.0), "{}", action.0);
            }
            let unicode_action = ActionKey::in_namespace(
                &NamespaceId(format!("{name}.workspace")),
                "\u{5de5}\u{5177}.read",
            );
            assert!(product.owns_action(&unicode_action.0));
            for action in [
                name.to_owned(),
                format!("{name}::"),
                format!("{name}.workspace::"),
                format!("{name}:agent.use"),
                format!("{name}.workspace:agent.use"),
                format!("{name}:::agent.use"),
                format!("{name}::agent:use"),
                format!("{name}::agent::use"),
                format!("{name}.workspace::agent.*"),
                format!("{name}.workspace::agent use"),
                format!("{name}.workspace::agent\tuse"),
                format!("{name}.workspace::agent\nuse"),
                format!("{name}.workspace/part::agent.use"),
                format!("{name}.\u{03bb}::agent.use"),
                format!("{name}.workspace+part::agent.use"),
                format!("{name}.work space::agent.use"),
                format!("{name}-other.workspace::agent.use"),
                format!("{name}other.workspace::agent.use"),
                format!("foreign.{name}::agent.use"),
                format!("::{name}.agent.use"),
                "foreign.workspace::agent.use".into(),
            ] {
                assert!(!product.owns_action(&action), "{action}");
            }
        }
    }
}
