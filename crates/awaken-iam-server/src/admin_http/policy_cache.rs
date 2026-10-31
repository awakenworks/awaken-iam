//! Incremental refresh of the live PDP after this node's own admin commits.
//!
//! A full refresh re-reads every grant, binding, roster, resource edge and the
//! active profiles, then recomposes the evaluator. Doing that after every admin
//! mutation made one write cost O(policy size) in store reads. This module keeps
//! the repository base and the active profiles the PDP was last composed from,
//! applies a committed mutation's delta to that base, and recomposes in memory.
//!
//! | rule | condition                                                        | refresh |
//! |------|------------------------------------------------------------------|---------|
//! | R1   | no composed base yet, or this node's last admin mutation failed  | full |
//! | R2   | the mutation has no known delta                                  | full |
//! | R3   | committed version != observed version + 1 (another writer moved) | full |
//! | R4   | the PDP was replaced outside this cache (profile lifecycle)      | full |
//! | R5   | base composed at the observed version and R1-R4 do not hold      | delta |
//!
//! R3 keeps the cross-replica fence law: a delta is applied only when this
//! commit is the single version step after what the node already serves, so no
//! other writer's committed version can be skipped. Any doubt falls back to the
//! original full refresh.

use awaken_iam_contract::{AuthorizationProfile, PrincipalRef};
use awaken_iam_core::{Grant, GrantId, GroupId, PolicySet, RoleBinding};

/// The policy effect of one committed admin mutation.
#[derive(Debug, Clone)]
pub(super) enum PolicyDelta {
    /// The mutation changes no evaluator input (organization or role metadata).
    Unchanged,
    /// Grants inserted or replaced by id.
    UpsertGrants(Vec<Grant>),
    /// A grant removed by id.
    RemoveGrant(GrantId),
    /// A principal bound to a role at a scope.
    BindRole(RoleBinding),
    /// An exact role binding removed.
    UnbindRole(RoleBinding),
    /// A group roster created or replaced.
    SetGroupRoster(GroupId, Vec<PrincipalRef>),
}

impl PolicyDelta {
    /// Apply this delta exactly as rehydrating the stored rows would.
    fn apply(self, base: &mut PolicySet) {
        match self {
            Self::Unchanged => {}
            Self::UpsertGrants(grants) => {
                for grant in grants {
                    base.upsert_grant(grant);
                }
            }
            Self::RemoveGrant(id) => {
                base.remove_grant(&id);
            }
            Self::BindRole(binding) => {
                base.bind_role_once(binding);
            }
            Self::UnbindRole(binding) => {
                base.unbind_role(&binding);
            }
            Self::SetGroupRoster(group, members) => {
                base.set_group_roster(group, members);
            }
        }
    }
}

/// The repository base and active profiles the live PDP was composed from.
pub(super) struct ComposedPolicy {
    base: PolicySet,
    profiles: Vec<AuthorizationProfile>,
    version: u64,
}

impl ComposedPolicy {
    /// Compose the evaluator for `version` and remember its inputs.
    pub(super) fn compose(
        base: PolicySet,
        profiles: Vec<AuthorizationProfile>,
        version: u64,
    ) -> (Self, PolicySet) {
        let policy = PolicySet::from_snapshot_and_profiles(&base.snapshot(version), &profiles);
        (
            Self {
                base,
                profiles,
                version,
            },
            policy,
        )
    }

    /// Apply `delta` committed at `version` and return the recomposed
    /// evaluator, or `None` when the rules above require a full refresh.
    pub(super) fn advance(
        &mut self,
        observed: u64,
        served: u64,
        version: u64,
        delta: Option<PolicyDelta>,
    ) -> Option<PolicySet> {
        let delta = delta?;
        if self.version != observed
            || served != observed
            || observed.checked_add(1) != Some(version)
        {
            return None;
        }
        delta.apply(&mut self.base);
        self.version = version;
        Some(PolicySet::from_snapshot_and_profiles(
            &self.base.snapshot(version),
            &self.profiles,
        ))
    }
}
