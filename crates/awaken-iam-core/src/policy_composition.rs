//! Composition of dynamic repository policy and immutable profile revisions.

use awaken_iam_contract::{AuthorizationProfile, PolicySnapshot};

use crate::{PolicySet, ResourceModel};

impl PolicySet {
    /// Build a complete policy from one immutable profile revision.
    pub fn from_profile(profile: &AuthorizationProfile) -> Self {
        Self::from_profiles(std::slice::from_ref(profile))
    }

    /// Build one evaluator from every consumer namespace's active profile.
    pub fn from_profiles(profiles: &[AuthorizationProfile]) -> Self {
        Self::from_snapshot_and_profiles(&PolicySnapshot::default(), profiles)
    }

    /// Layer immutable profile documents over a repository-backed base.
    ///
    /// Keeping this composition in the core prevents server adapters from each
    /// inventing a subtly different merge order.
    pub fn from_snapshot_and_profiles(
        base: &PolicySnapshot,
        profiles: &[AuthorizationProfile],
    ) -> Self {
        let mut snapshot = base.clone();
        snapshot.active_profiles = profiles.to_vec();
        snapshot.version = snapshot.version.max(
            profiles
                .iter()
                .map(|profile| profile.revision)
                .max()
                .unwrap_or(0),
        );
        for profile in profiles {
            let document = &profile.document;
            snapshot.grants.extend(document.grants.clone());
            snapshot
                .role_bindings
                .extend(document.role_bindings.clone());
            snapshot
                .group_rosters
                .extend(document.group_rosters.clone());
            snapshot
                .group_role_bindings
                .extend(document.group_role_bindings.clone());
            snapshot
                .scope_graph
                .resource_parents
                .extend(document.resource_model.edges.clone());
        }
        let mut policy = Self::from_snapshot(&snapshot);
        for profile in profiles {
            let model = ResourceModel::from_registration(&profile.document.resource_model);
            policy.register_resource_model(&model);
        }
        policy
    }
}
