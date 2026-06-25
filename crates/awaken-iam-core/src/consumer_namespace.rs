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
//! This module is the **product-neutral mechanism** (matching the role-catalog
//! split, ADR-0002 #3): the kernel stays neutral and pattern matching is
//! unchanged. A [`ConsumerNamespaces`] names the namespaces a product owns and
//! offers the two operations the convention needs — render the grant set that
//! reaches the whole product surface ([`ConsumerNamespaces::glob_patterns`]) and
//! check that a registered model keeps its actions inside that surface
//! ([`ConsumerNamespaces::confines`]). The specific ADR-named consumers
//! (`managed_agents`, `oversight`) live in the `awaken-iam-preset` crate as
//! policy data, declared through this same mechanism.

use awaken_iam_contract::ActionKey;

use crate::ActionPattern;
use crate::resource_model::ResourceModel;

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
/// Construct one for a product (the `awaken-iam-preset` crate ships the two
/// ADR-named consumers, `managed_agents` and `oversight`, built this way) and
/// use it to render the product's grant set or to assert a registered
/// [`ResourceModel`] stays within the product's surface.
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::resource_model::ResourceTypeDef;
    use awaken_iam_contract::ResourceType;

    /// A throwaway two-namespace consumer, standing in for any product that
    /// declares its surface through this mechanism (the named Anthropic
    /// consumers are tested in `awaken-iam-preset`).
    fn sample() -> ConsumerNamespaces {
        ConsumerNamespaces::new("sample", ["beta", "alpha"])
    }

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
    fn declarations_normalize_to_a_stable_set() {
        // Input order and duplicates do not change the declared set.
        let one = ConsumerNamespaces::new("sample", ["beta", "alpha", "alpha"]);
        let two = ConsumerNamespaces::new("sample", ["alpha", "beta"]);
        assert_eq!(one, two);
        assert_eq!(one.namespaces(), ["alpha", "beta"]);
    }

    #[test]
    fn glob_patterns_render_one_sorted_glob_per_namespace() {
        assert_eq!(
            sample().glob_patterns(),
            vec![
                ActionPattern("alpha.*".into()),
                ActionPattern("beta.*".into()),
            ]
        );
        // A glob reaches the product's whole surface, including the bare key.
        let glob = &sample().glob_patterns()[0];
        assert!(glob.matches(&ActionKey("alpha".into())));
        assert!(glob.matches(&ActionKey("alpha.run".into())));
        assert!(!glob.matches(&ActionKey("beta.read".into())));
    }

    fn alpha_model() -> ResourceModel {
        let mut model = ResourceModel::new();
        model.register_resource_type(ResourceTypeDef {
            resource_type: ResourceType("alpha".into()),
            parent_type: None,
            actions: vec![
                ActionKey("alpha.run".into()),
                ActionKey("alpha.configure".into()),
            ],
        });
        model
    }

    #[test]
    fn confines_accepts_a_model_inside_the_product_surface() {
        assert_eq!(sample().confines(&alpha_model()), Ok(()));
        assert!(sample().foreign_actions(&alpha_model()).is_empty());
    }

    #[test]
    fn confines_reports_an_action_that_leaked_into_a_sibling_surface() {
        let mut model = alpha_model();
        // A stray action outside the consumer's declared namespaces.
        model.register_action(ActionKey("gamma.approve".into()));

        assert_eq!(
            sample().confines(&model),
            Err(vec![ActionKey("gamma.approve".into())])
        );
        assert!(!sample().owns_action(&ActionKey("gamma.approve".into())));
    }
}
