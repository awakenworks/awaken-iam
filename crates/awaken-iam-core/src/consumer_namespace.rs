//! Per-consumer action-namespace convention (ADR-0008 decision 8).
//!
//! There is **no per-product configuration surface**. A consumer distinguishes
//! its product purely by the [`ResourceModel`] it registers — its resource types
//! and an **action-key namespace**: `agent.*` for managed agents,
//! `oversight.*`/`issue.*` for Oversight. Since every request runs the same
//! [`PolicySet::evaluate`](crate::PolicySet::evaluate), a key reaches a product's
//! action iff its principal holds a covering `Allow` grant for that action's key
//! — nothing binds a key to one product. One key therefore spans both products by
//! holding a role whose grants cross both namespaces (or one bound at a covering
//! `Org` scope), and is confined to one by a narrower role — a *binding* choice,
//! never a second config.
//!
//! This module is the **convention as data** (matching the role-catalog seed,
//! ADR-0002 #3): the kernel stays neutral and pattern matching is unchanged. A
//! [`ConsumerNamespaces`] names the namespaces a product owns and offers the two
//! operations the convention needs — render the grant set that reaches the whole
//! product surface ([`ConsumerNamespaces::glob_patterns`]) and check that a
//! registered model keeps its actions inside that surface
//! ([`ConsumerNamespaces::confines`]).

use awaken_iam_contract::ActionKey;

use crate::ActionPattern;
use crate::resource_model::ResourceModel;

/// Action-key namespace the managed-agents consumer owns.
pub const MANAGED_AGENTS_NAMESPACES: [&str; 1] = ["agent"];

/// Action-key namespaces the Oversight consumer owns.
///
/// Sorted, so it lines up with [`ConsumerNamespaces::namespaces`].
pub const OVERSIGHT_NAMESPACES: [&str; 2] = ["issue", "oversight"];

/// Action-key namespaces the awaken-runtime consumer owns.
///
/// The runtime orchestrates agents (`agent`), manages interactive sessions
/// (`session`), and controls tool invocations (`tool`). These three namespaces
/// are the complete runtime surface; `agent` is shared with the managed-agents
/// consumer declaration, which is intentional — the runtime product subsumes
/// agent orchestration rather than delegating to a separate consumer.
///
/// Sorted, so it lines up with [`ConsumerNamespaces::namespaces`].
pub const AWAKEN_RUNTIME_NAMESPACES: [&str; 3] = ["agent", "session", "tool"];

/// The namespace (leading dotted segment) of an action key.
///
/// `agent.run` -> `agent`, `oversight.approval.grant` -> `oversight`, and a
/// segmentless key is its own namespace (`ping` -> `ping`). This is the single
/// rule that decides which product an action belongs to.
pub fn action_namespace(action: &ActionKey) -> &str {
    match action.0.split_once('.') {
        Some((namespace, _rest)) => namespace,
        None => action.0.as_str(),
    }
}

/// A consumer's declared action-key namespaces — the product surface it owns.
///
/// Construct one for a product (or use [`managed_agents`] / [`oversight`] for the
/// two ADR-named consumers) and use it to render the product's grant set or to
/// assert a registered [`ResourceModel`] stays within the product's surface.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConsumerNamespaces {
    consumer: String,
    namespaces: Vec<String>,
}

impl ConsumerNamespaces {
    /// Declare the namespaces a consumer owns.
    ///
    /// Namespaces are de-duplicated and sorted for a stable rendering order, so
    /// two declarations of the same set compare equal regardless of input order.
    pub fn new(
        consumer: impl Into<String>,
        namespaces: impl IntoIterator<Item = impl Into<String>>,
    ) -> Self {
        let mut namespaces: Vec<String> = namespaces.into_iter().map(Into::into).collect();
        namespaces.sort();
        namespaces.dedup();
        Self {
            consumer: consumer.into(),
            namespaces,
        }
    }

    /// The consumer this declaration belongs to.
    pub fn consumer(&self) -> &str {
        &self.consumer
    }

    /// The owned namespaces, sorted and de-duplicated.
    pub fn namespaces(&self) -> &[String] {
        &self.namespaces
    }

    /// Whether `namespace` is one this consumer owns.
    pub fn owns_namespace(&self, namespace: &str) -> bool {
        self.namespaces.iter().any(|owned| owned == namespace)
    }

    /// Whether `action` falls within one of this consumer's namespaces.
    pub fn owns_action(&self, action: &ActionKey) -> bool {
        self.owns_namespace(action_namespace(action))
    }

    /// One `<namespace>.*` glob [`ActionPattern`] per owned namespace.
    ///
    /// This is the grant set that reaches the consumer's **whole** product
    /// surface: a role carrying these patterns (bound at a covering scope) lets a
    /// principal reach every action the product registers. A role carrying the
    /// glob sets of *several* consumers is the cross-product key of decision 8.
    pub fn glob_patterns(&self) -> Vec<ActionPattern> {
        self.namespaces
            .iter()
            .map(|namespace| ActionPattern(format!("{namespace}.*")))
            .collect()
    }

    /// The actions in `model` that fall **outside** this consumer's namespaces.
    ///
    /// Empty when the model is confined to the product surface. The list is
    /// sorted (the model already sorts its catalog), so the result is stable.
    pub fn foreign_actions(&self, model: &ResourceModel) -> Vec<ActionKey> {
        model
            .actions()
            .into_iter()
            .filter(|action| !self.owns_action(action))
            .collect()
    }

    /// Assert a registered [`ResourceModel`] keeps every action inside this
    /// consumer's namespaces.
    ///
    /// Returns the offending actions on failure. A product registers its actions
    /// under its own namespace; this is the check that a model has not leaked an
    /// action into a sibling product's surface, which would blur the
    /// one-key-spans-by-role boundary the convention rests on.
    pub fn confines(&self, model: &ResourceModel) -> Result<(), Vec<ActionKey>> {
        let foreign = self.foreign_actions(model);
        if foreign.is_empty() {
            Ok(())
        } else {
            Err(foreign)
        }
    }
}

/// The managed-agents consumer convention: the `agent.*` namespace.
pub fn managed_agents() -> ConsumerNamespaces {
    ConsumerNamespaces::new("managed-agents", MANAGED_AGENTS_NAMESPACES)
}

/// The Oversight consumer convention: the `oversight.*` and `issue.*` namespaces.
pub fn oversight() -> ConsumerNamespaces {
    ConsumerNamespaces::new("oversight", OVERSIGHT_NAMESPACES)
}

/// The awaken-runtime consumer convention: the `agent.*`, `session.*`, and
/// `tool.*` namespaces.
///
/// awaken-1.0.0-dev startup provisioning calls this to obtain the runtime's
/// declared surface and seed the corresponding role preset via
/// [`crate::seed_runtime_roles`]. The runtime owns the full agent-session-tool
/// surface; callers that only need the agent sub-surface may continue using
/// [`managed_agents`] instead.
pub fn awaken_runtime() -> ConsumerNamespaces {
    ConsumerNamespaces::new("awaken-runtime", AWAKEN_RUNTIME_NAMESPACES)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::resource_model::ResourceTypeDef;
    use awaken_iam_contract::ResourceType;

    #[test]
    fn action_namespace_is_the_leading_segment() {
        assert_eq!(action_namespace(&ActionKey("agent.run".into())), "agent");
        assert_eq!(
            action_namespace(&ActionKey("oversight.approval.grant".into())),
            "oversight"
        );
        // A segmentless key is its own namespace.
        assert_eq!(action_namespace(&ActionKey("ping".into())), "ping");
    }

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

        let runtime = awaken_runtime();
        // Sorted, de-duplicated: agent, session, tool.
        assert_eq!(runtime.namespaces(), ["agent", "session", "tool"]);
        assert!(runtime.owns_action(&ActionKey("agent.run".into())));
        assert!(runtime.owns_action(&ActionKey("session.create".into())));
        assert!(runtime.owns_action(&ActionKey("tool.invoke".into())));
        assert!(!runtime.owns_action(&ActionKey("oversight.approval.grant".into())));
    }

    #[test]
    fn declarations_normalize_to_a_stable_set() {
        // Input order and duplicates do not change the declared set.
        let one = ConsumerNamespaces::new("oversight", ["oversight", "issue", "issue"]);
        let two = ConsumerNamespaces::new("oversight", ["issue", "oversight"]);
        assert_eq!(one, two);
        assert_eq!(one.namespaces(), ["issue", "oversight"]);
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
        assert_eq!(
            awaken_runtime().glob_patterns(),
            vec![
                ActionPattern("agent.*".into()),
                ActionPattern("session.*".into()),
                ActionPattern("tool.*".into()),
            ]
        );
        // A glob reaches the product's whole surface, including the bare key.
        let glob = &managed_agents().glob_patterns()[0];
        assert!(glob.matches(&ActionKey("agent".into())));
        assert!(glob.matches(&ActionKey("agent.run".into())));
        assert!(!glob.matches(&ActionKey("oversight.read".into())));
    }

    #[test]
    fn awaken_runtime_subsumes_managed_agents_namespace() {
        // The runtime declares `agent` in addition to its own namespaces; a role
        // whose grants span the runtime surface also covers the agent namespace
        // that managed_agents() declares — the two consumer declarations overlap
        // intentionally: the runtime product subsumes agent orchestration.
        let runtime = awaken_runtime();
        assert!(runtime.owns_action(&ActionKey("agent.run".into())));
        assert!(runtime.owns_action(&ActionKey("agent.configure".into())));
        // managed_agents() is the narrower declaration; awaken_runtime() is the
        // full runtime surface.
        assert_eq!(managed_agents().namespaces(), ["agent"]);
        assert!(awaken_runtime().namespaces().contains(&"agent".to_owned()));
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
