//! The named consumer conventions from ADR-0008 decision 8.
//!
//! The product-neutral [`ConsumerNamespaces`] mechanism lives in
//! [`awaken_iam_core`]; this module names the two specific consumers the ADR
//! calls out — managed agents (`agent.*`) and Oversight (`oversight.*` /
//! `issue.*`) — as policy data. A different deployment declares its own
//! consumers the same way without this crate.

use awaken_iam_core::ConsumerNamespaces;

/// Action-key namespace the managed-agents consumer owns.
pub const MANAGED_AGENTS_NAMESPACES: [&str; 1] = ["agent"];

/// Action-key namespaces the Oversight consumer owns.
///
/// Sorted, so it lines up with [`ConsumerNamespaces::namespaces`].
pub const OVERSIGHT_NAMESPACES: [&str; 2] = ["issue", "oversight"];

/// The managed-agents consumer convention: the `agent.*` namespace.
pub fn managed_agents() -> ConsumerNamespaces {
    ConsumerNamespaces::new("managed-agents", MANAGED_AGENTS_NAMESPACES)
}

/// The Oversight consumer convention: the `oversight.*` and `issue.*` namespaces.
pub fn oversight() -> ConsumerNamespaces {
    ConsumerNamespaces::new("oversight", OVERSIGHT_NAMESPACES)
}

#[cfg(test)]
mod tests {
    use super::*;
    use awaken_iam_contract::{ActionKey, ResourceType};
    use awaken_iam_core::{ActionPattern, ResourceModel, ResourceTypeDef};

    #[test]
    fn the_named_consumers_own_their_adr_namespaces() {
        let agents = managed_agents();
        assert_eq!(agents.namespaces(), ["agent"]);
        assert!(agents.owns_action(&ActionKey("agent.run".into())));
        assert!(!agents.owns_action(&ActionKey("oversight.approval.grant".into())));

        let oversight = oversight();
        // Sorted, de-duplicated: issue before oversight.
        assert_eq!(oversight.namespaces(), ["issue", "oversight"]);
        assert!(oversight.owns_action(&ActionKey("issue.advance".into())));
        assert!(oversight.owns_action(&ActionKey("oversight.approval.grant".into())));
        assert!(!oversight.owns_action(&ActionKey("agent.run".into())));
    }

    #[test]
    fn glob_patterns_render_one_glob_per_namespace() {
        assert_eq!(
            managed_agents().glob_patterns(),
            vec![ActionPattern("agent.*".into())]
        );
        assert_eq!(
            oversight().glob_patterns(),
            vec![
                ActionPattern("issue.*".into()),
                ActionPattern("oversight.*".into()),
            ]
        );
        // A glob reaches the product's whole surface, including the bare key.
        let glob = &managed_agents().glob_patterns()[0];
        assert!(glob.matches(&ActionKey("agent".into())));
        assert!(glob.matches(&ActionKey("agent.run".into())));
        assert!(!glob.matches(&ActionKey("oversight.read".into())));
    }

    #[test]
    fn a_cross_product_role_carries_both_namespace_globs() {
        // Decision 8's cross-product key: one role whose grants cross both
        // namespaces is just the union of the two consumers' glob sets.
        let mut crossing: Vec<ActionPattern> = managed_agents().glob_patterns();
        crossing.extend(oversight().glob_patterns());
        assert!(crossing.contains(&ActionPattern("agent.*".into())));
        assert!(crossing.contains(&ActionPattern("oversight.*".into())));
        assert!(crossing.contains(&ActionPattern("issue.*".into())));
        // Every action either product registers is reached by some pattern;
        // a foreign namespace is reached by none (default-deny holds).
        let reaches = |action: &str| {
            let key = ActionKey(action.into());
            crossing.iter().any(|pattern| pattern.matches(&key))
        };
        assert!(reaches("agent.run"));
        assert!(reaches("oversight.approval.grant"));
        assert!(reaches("issue.advance"));
        assert!(!reaches("pack.publish"));
    }

    fn agent_model() -> ResourceModel {
        let mut model = ResourceModel::new();
        model.register_resource_type(ResourceTypeDef {
            resource_type: ResourceType("agent".into()),
            parent_type: None,
            actions: vec![
                ActionKey("agent.run".into()),
                ActionKey("agent.configure".into()),
            ],
        });
        model
    }

    #[test]
    fn confines_accepts_a_model_inside_the_product_surface() {
        assert_eq!(managed_agents().confines(&agent_model()), Ok(()));
        assert!(managed_agents().foreign_actions(&agent_model()).is_empty());
    }

    #[test]
    fn confines_reports_an_action_that_leaked_into_a_sibling_surface() {
        let mut model = agent_model();
        // A stray Oversight action registered under the managed-agents model.
        model.register_action(ActionKey("oversight.approval.grant".into()));

        assert_eq!(
            managed_agents().confines(&model),
            Err(vec![ActionKey("oversight.approval.grant".into())])
        );
        // The Oversight consumer would, of course, accept it.
        assert!(oversight().owns_action(&ActionKey("oversight.approval.grant".into())));
    }
}
