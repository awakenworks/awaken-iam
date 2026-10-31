//! Fenced, atomic replacement of one principal's Team access (ADR-0018).
//!
//! | rule | stored fence                     | command fence            | outcome |
//! |------|----------------------------------|--------------------------|---------|
//! | F1   | none                             | any                      | apply |
//! | F2   | `(g, p)`                         | generation > g           | apply |
//! | F3   | `(g, p)`                         | `(g, p)`                 | apply again (idempotent resume) |
//! | F4   | `(g, p)`                         | `(g, q)` with q != p     | `Conflict`, nothing changes |
//! | F5   | `(g, p)`                         | generation < g           | `Conflict`, nothing changes |
//!
//! Applying sets the principal's membership of every managed group to exactly
//! the target set, keeps one Workspace deny exactly when `suspended`, records
//! the fence and advances the policy version, all in one store transaction.

use std::collections::{BTreeMap, BTreeSet};

use awaken_iam_contract::{
    AccessFence, OrgId, PrincipalRef, ScopeRef, TeamAccessReceipt, TeamAccessReplacement, Timestamp,
};
use awaken_iam_core::{
    ActionPattern, AuditEvent, Effect, Grant, GrantId, GrantSubject, Group, GroupId,
    RepositoryError, RepositoryResult,
};
use sha2::{Digest, Sha256};

use super::{AdminError, AdminResult, PolicyAdminApi, PolicyStore};

/// Audit action recorded for every applied replacement.
pub const TEAM_ACCESS_REPLACED: &str = "principal_access.team_replaced";
/// IAM action a service account needs at the Workspace to send the command.
pub const ACTION_PRINCIPAL_ACCESS_REPLACE: &str = "iam.principal_access.replace";
/// IAM action a service account needs at a business namespace to read it.
pub const ACTION_AUTHZ_PROFILE_READ: &str = "iam.authz_profile.read";

/// Atomic persistence boundary for one fenced Team access replacement.
pub trait PrincipalAccessStore: Send + Sync {
    fn replace_team_access(
        &self,
        command: &TeamAccessReplacement,
        at: &Timestamp,
        audit: AuditEvent,
    ) -> RepositoryResult<TeamAccessReceipt>;
}

/// What a store read inside its transaction before deciding.
pub(crate) struct TeamAccessCurrent {
    pub(crate) groups: BTreeMap<String, Option<Group>>,
    pub(crate) suspended: bool,
    pub(crate) fence: Option<AccessFence>,
    pub(crate) workspace_org: Option<OrgId>,
}

/// The writes one replacement needs; empty `groups` means no roster change.
pub(crate) struct TeamAccessPlan {
    pub(crate) groups: Vec<Group>,
    pub(crate) suspension: Option<bool>,
    pub(crate) teams: Vec<String>,
}

/// Stable key of the per-(Workspace, principal) fence row.
pub(crate) fn fence_key(command: &TeamAccessReplacement) -> RepositoryResult<String> {
    let material = serde_json::to_vec(&(&command.workspace_id, &command.principal))
        .map_err(|error| RepositoryError::Backend(error.to_string()))?;
    Ok(format!("{:x}", Sha256::digest(material)))
}

/// The Workspace deny kept while the principal is suspended.
pub(crate) fn suspension_grant(command: &TeamAccessReplacement) -> RepositoryResult<Grant> {
    Ok(Grant {
        id: GrantId(format!(
            "principal-access-suspended:{}",
            fence_key(command)?
        )),
        subject: GrantSubject::Principal(command.principal.clone()),
        action_pattern: ActionPattern("*".into()),
        scope: workspace_scope(command),
        effect: Effect::Deny,
    })
}

pub(crate) fn workspace_scope(command: &TeamAccessReplacement) -> ScopeRef {
    ScopeRef::Workspace {
        workspace_id: command.workspace_id.clone(),
    }
}

/// Decide the writes, or refuse a stale fence (F4/F5) before any write.
pub(crate) fn plan_team_access(
    command: &TeamAccessReplacement,
    current: &TeamAccessCurrent,
    at: &Timestamp,
) -> RepositoryResult<TeamAccessPlan> {
    if let Some(stored) = &current.fence {
        let resumes = stored.generation == command.fence.generation
            && stored.plan_id == command.fence.plan_id;
        if !resumes && command.fence.generation <= stored.generation {
            return Err(RepositoryError::Conflict(format!(
                "stale_access_fence: stored generation {} for plan {}",
                stored.generation, stored.plan_id
            )));
        }
    }
    let targets: BTreeSet<&str> = command.teams.iter().map(String::as_str).collect();
    let mut groups = Vec::new();
    let mut teams = Vec::new();
    for id in &command.managed {
        let wanted = targets.contains(id.as_str());
        let mut group = match current.groups.get(id).cloned().flatten() {
            Some(group) => group,
            None if wanted => Group {
                id: GroupId(id.clone()),
                org: current.workspace_org.clone().ok_or_else(|| {
                    RepositoryError::NotFound(format!(
                        "workspace {} has no organization for group {id}",
                        command.workspace_id.0
                    ))
                })?,
                display_name: None,
                members: Vec::new(),
                created_at: at.clone(),
                updated_at: at.clone(),
            },
            None => continue,
        };
        let changed = if wanted {
            group.add_member(command.principal.clone())
        } else {
            group.remove_member(&command.principal)
        };
        if wanted {
            teams.push(id.clone());
        }
        if changed {
            group.updated_at = at.clone();
            groups.push(group);
        }
    }
    teams.sort();
    Ok(TeamAccessPlan {
        groups,
        suspension: (current.suspended != command.suspended).then_some(command.suspended),
        teams,
    })
}

pub(crate) fn receipt(
    command: &TeamAccessReplacement,
    plan: &TeamAccessPlan,
    version: u64,
) -> TeamAccessReceipt {
    TeamAccessReceipt {
        workspace_id: command.workspace_id.clone(),
        principal: command.principal.clone(),
        teams: plan.teams.clone(),
        suspended: command.suspended,
        fence: command.fence.clone(),
        version,
    }
}

fn validate(command: &TeamAccessReplacement) -> AdminResult<()> {
    let bounded = |value: &str| !value.trim().is_empty() && value.len() <= 200;
    let mut managed = BTreeSet::new();
    let valid = bounded(&command.workspace_id.0)
        && bounded(&command.fence.plan_id)
        && command.fence.generation > 0
        && command.fence.generation <= i64::MAX as u64
        && !command.managed.is_empty()
        && command.managed.len() <= 64
        && command
            .managed
            .iter()
            .all(|id| bounded(id) && managed.insert(id.as_str()))
        && command.teams.iter().collect::<BTreeSet<_>>().len() == command.teams.len()
        && command.teams.iter().all(|id| managed.contains(id.as_str()));
    if !valid {
        return Err(AdminError::Invalid(
            "team access replacement requires a Workspace, positive fence, plan id, \
             unique managed groups and targets inside them"
                .into(),
        ));
    }
    if matches!(command.principal, PrincipalRef::ApiToken { .. }) {
        return Err(AdminError::Invalid(
            "team access belongs to an account or service principal".into(),
        ));
    }
    Ok(())
}

impl<S: PolicyStore + PrincipalAccessStore> PolicyAdminApi<S> {
    /// Apply one fenced Team access replacement as a single IAM commit.
    pub fn replace_team_access(
        &mut self,
        command: TeamAccessReplacement,
        actor: Option<PrincipalRef>,
        at: Timestamp,
    ) -> AdminResult<TeamAccessReceipt> {
        validate(&command)?;
        let audit = AuditEvent {
            at: at.clone(),
            actor,
            action: TEAM_ACCESS_REPLACED.into(),
            detail: format!(
                "workspace={} principal={:?} teams={:?} suspended={} generation={} plan={}",
                command.workspace_id.0,
                command.principal,
                command.teams,
                command.suspended,
                command.fence.generation,
                command.fence.plan_id
            ),
        };
        let receipt = self.store.replace_team_access(&command, &at, audit)?;
        self.version = receipt.version;
        Ok(receipt)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use awaken_iam_contract::{AccountId, WorkspaceId};

    fn command(teams: &[&str], generation: u64, plan: &str) -> TeamAccessReplacement {
        TeamAccessReplacement {
            workspace_id: WorkspaceId("w1".into()),
            principal: PrincipalRef::Account {
                account_id: AccountId("alice".into()),
            },
            managed: vec!["sales".into(), "support".into()],
            teams: teams.iter().map(|team| (*team).into()).collect(),
            suspended: false,
            fence: AccessFence {
                generation,
                plan_id: plan.into(),
            },
        }
    }

    fn current(fence: Option<(u64, &str)>) -> TeamAccessCurrent {
        TeamAccessCurrent {
            groups: BTreeMap::new(),
            suspended: true,
            fence: fence.map(|(generation, plan)| AccessFence {
                generation,
                plan_id: plan.into(),
            }),
            workspace_org: Some(OrgId("o1".into())),
        }
    }

    #[test]
    fn fence_decision_table() {
        let at = Timestamp("2026-10-31T00:00:00Z".into());
        for (rule, stored, generation, plan, applies) in [
            ("F1", None, 1, "p", true),
            ("F2", Some((3, "p")), 4, "q", true),
            ("F3", Some((3, "p")), 3, "p", true),
            ("F4", Some((3, "p")), 3, "q", false),
            ("F5", Some((3, "p")), 2, "q", false),
        ] {
            let result = plan_team_access(
                &command(&["sales"], generation, plan),
                &current(stored),
                &at,
            );
            assert_eq!(result.is_ok(), applies, "{rule}");
            if let Err(error) = result {
                assert!(matches!(error, RepositoryError::Conflict(_)), "{rule}");
            }
        }
    }

    #[test]
    fn plan_creates_missing_targets_and_lifts_a_suspension() {
        let at = Timestamp("2026-10-31T00:00:00Z".into());
        let plan = plan_team_access(&command(&["sales"], 1, "p"), &current(None), &at).unwrap();
        assert_eq!(plan.teams, ["sales"]);
        assert_eq!(plan.groups.len(), 1, "only the created target changes");
        assert_eq!(plan.groups[0].org, OrgId("o1".into()));
        assert_eq!(plan.suspension, Some(false));
        let mut orphan = current(None);
        orphan.workspace_org = None;
        assert!(matches!(
            plan_team_access(&command(&["sales"], 1, "p"), &orphan, &at),
            Err(RepositoryError::NotFound(_))
        ));
    }

    /// The in-memory store applies the same table atomically: F1 applies,
    /// F5 changes nothing, and the deny follows `suspended`.
    #[test]
    fn in_memory_store_applies_and_fences() {
        use awaken_iam_core::{GrantRepository, GroupRepository, ResourceModelRepository};
        let store = crate::InMemoryStore::new();
        store
            .put_workspace_org(awaken_iam_contract::WorkspaceOrgEdge {
                workspace_id: WorkspaceId("w1".into()),
                org_id: OrgId("o1".into()),
            })
            .unwrap();
        let mut admin = PolicyAdminApi::new(store.clone());
        let at = Timestamp("2026-10-31T00:00:00Z".into());
        let mut leave = command(&[], 2, "leave");
        leave.suspended = true;
        let receipt = admin
            .replace_team_access(leave.clone(), None, at.clone())
            .unwrap();
        assert!(receipt.teams.is_empty() && receipt.suspended);
        let deny = suspension_grant(&leave).unwrap();
        assert!(GrantRepository::get(&store, &deny.id).unwrap().is_some());
        assert!(matches!(
            admin.replace_team_access(command(&["sales"], 1, "join"), None, at.clone()),
            Err(AdminError::AlreadyExists(message)) if message.starts_with("stale_access_fence")
        ));
        assert!(
            GroupRepository::get(&store, &GroupId("sales".into()))
                .unwrap()
                .is_none()
        );
        let rejoin = admin
            .replace_team_access(command(&["sales"], 3, "rejoin"), None, at)
            .unwrap();
        assert_eq!(rejoin.teams, ["sales"]);
        assert!(GrantRepository::get(&store, &deny.id).unwrap().is_none());
    }

    #[test]
    fn validation_refuses_targets_outside_the_managed_set() {
        let mut outside = command(&["finance"], 1, "p");
        assert!(validate(&outside).is_err());
        outside.teams.clear();
        outside.fence.generation = 0;
        assert!(validate(&outside).is_err());
        assert!(validate(&command(&["sales"], 1, "p")).is_ok());
    }
}
