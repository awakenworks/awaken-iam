//! Seeded named role catalog (ADR-0008 decision 2).
//!
//! Ships two distinct seeded catalogs of [`RoleDef`]s, both as **seed data, not
//! engine code** (ADR-0002 #3): the kernel in [`awaken_iam_core`] stays neutral,
//! the names live here as data, and a deployment may extend either catalog with
//! custom roles after seeding.
//!
//! ## Anthropic platform catalog ([`named_role_catalog`] / [`seed_named_roles`])
//!
//! The platform-level roles whose ids are the Anthropic Claude platform role names
//! and whose action patterns encode each role's authority over the IAM structural
//! and platform namespaces — `developer ⇒ apikey.*`, `billing ⇒ billing.*`, and
//! so on. This catalog is product-agnostic: it covers only the structural action
//! domains IAM owns (`org`, `workspace`, `apikey`, etc.) and carries no
//! consumer-owned runtime verbs.
//!
//! Anthropic's two-level role inheritance is not modelled here — it falls out of
//! [`ScopeGraph::covers`](awaken_iam_core::ScopeGraph) at evaluation, where an
//! `Org`-scoped [`RoleBinding`](awaken_iam_core::RoleBinding) is held at every
//! workspace beneath it. This catalog only supplies the *grant sets*; the binding
//! scope decides reach.
//!
//! ## awaken-runtime consumer catalog ([`runtime_role_catalog`] / [`seed_runtime_roles`])
//!
//! The awaken-runtime consumer's preset roles (`runtime_admin`, `runtime_user`)
//! whose action patterns encode authority over the runtime's consumer-owned action
//! namespaces (`agent.*`, `session.*`, `tool.*`) declared by
//! [`crate::awaken_runtime`]. These roles are consumer-specific — they map the
//! runtime's declared surface, not an IAM structural domain — and are kept separate
//! from [`ANTHROPIC_ROLE_IDS`] so the platform catalog stays clean. awaken-1.0.0-dev
//! startup provisioning seeds this catalog independently via [`seed_runtime_roles`].
//!
//! ## Shared constraint
//!
//! The model forbids a [`RoleDef`] from carrying the catch-all `*` pattern
//! ([`RoleDef::validate`](awaken_iam_core::RoleDef)), so the org `admin` role is
//! seeded as the union of every namespace the catalog touches rather than a
//! literal `*` — it is a superuser over the seeded action surface without a
//! hidden global wildcard.

use awaken_iam_contract::Timestamp;

use awaken_iam_core::{
    ActionPattern, RepositoryResult, RoleDef, RoleId, RoleRepository, seed_roles,
};

/// The two awaken-runtime preset role ids — seeded by [`seed_runtime_roles`]
/// during awaken-1.0.0-dev startup provisioning.
///
/// These roles map workspace-level authority over the runtime's action surface
/// (`agent.*`, `session.*`, `tool.*`). They are separate from
/// [`ANTHROPIC_ROLE_IDS`] so the Anthropic platform catalog stays clean; a
/// deployment seeds both catalogs independently.
pub const AWAKEN_RUNTIME_ROLE_IDS: [&str; 2] = ["runtime_admin", "runtime_user"];

/// Action-key namespaces the seeded catalog grants authority over.
///
/// Each entry is a top-level prefix; a role carries it as a `"<ns>.*"`
/// single-glob [`ActionPattern`]. The org `admin` role is the union of all of
/// them. Deployments register their product actions under these namespaces (or
/// add their own with a custom role).
pub const ROLE_NAMESPACES: [&str; 10] = [
    "org",
    "member",
    "workspace",
    "apikey",
    "service_account",
    "federation",
    "billing",
    "file",
    "skill",
    "claude_code",
];

/// The ten Anthropic role names this catalog seeds, org roles first then
/// workspace roles, in a stable order.
pub const ANTHROPIC_ROLE_IDS: [&str; 10] = [
    "admin",
    "developer",
    "billing",
    "user",
    "claude_code_user",
    "workspace_admin",
    "workspace_developer",
    "workspace_restricted_developer",
    "workspace_user",
    "workspace_billing",
];

/// One seed entry: the role id, its human-readable name, and the action patterns
/// it carries.
struct SeedRole {
    id: &'static str,
    display_name: &'static str,
    patterns: &'static [&'static str],
}

/// The org `admin` grant set: every namespace as a single-glob, i.e. full
/// authority over the seeded action surface without the forbidden `*`.
const ADMIN_PATTERNS: [&str; 10] = [
    "org.*",
    "member.*",
    "workspace.*",
    "apikey.*",
    "service_account.*",
    "federation.*",
    "billing.*",
    "file.*",
    "skill.*",
    "claude_code.*",
];

/// Static seed table mapping each Anthropic role name to its grant set.
///
/// Authority follows the Anthropic model: org roles are administrative
/// (`developer` manages API keys, `billing` manages billing, `admin` is
/// org-wide), and workspace roles confine the same kinds of authority to the
/// workspace they are bound at.
const SEED_ROLES: &[SeedRole] = &[
    // --- Org roles ---
    SeedRole {
        id: "admin",
        display_name: "Organization Admin",
        patterns: &ADMIN_PATTERNS,
    },
    SeedRole {
        id: "developer",
        display_name: "Developer",
        patterns: &["apikey.*"],
    },
    SeedRole {
        id: "billing",
        display_name: "Billing",
        patterns: &["billing.*"],
    },
    SeedRole {
        id: "user",
        display_name: "Member",
        patterns: &["workspace.read", "project.read"],
    },
    SeedRole {
        id: "claude_code_user",
        display_name: "Claude Code User",
        patterns: &["claude_code.*"],
    },
    // --- Workspace roles ---
    SeedRole {
        id: "workspace_admin",
        display_name: "Workspace Admin",
        patterns: &[
            "workspace.*",
            "project.*",
            "apikey.*",
            "service_account.*",
            "file.*",
            "skill.*",
        ],
    },
    SeedRole {
        id: "workspace_developer",
        display_name: "Workspace Developer",
        patterns: &[
            "apikey.*",
            "file.*",
            "skill.*",
            "workspace.read",
            "project.*",
        ],
    },
    SeedRole {
        id: "workspace_restricted_developer",
        display_name: "Workspace Restricted Developer",
        patterns: &[
            "apikey.read",
            "file.*",
            "skill.*",
            "workspace.read",
            "project.read",
        ],
    },
    SeedRole {
        id: "workspace_user",
        display_name: "Workspace User",
        patterns: &["file.read", "skill.read", "workspace.read", "project.read"],
    },
    SeedRole {
        id: "workspace_billing",
        display_name: "Workspace Billing",
        patterns: &["billing.*"],
    },
];

/// Build the seeded named role catalog, stamping every role with `now`.
///
/// The result is pure data — ordered as [`ANTHROPIC_ROLE_IDS`] — that a
/// deployment loads into its [`RoleRepository`] (see [`seed_named_roles`]). Every role
/// satisfies [`RoleDef::validate`](awaken_iam_core::RoleDef): each carries at
/// least one pattern and none carries the catch-all `*`.
pub fn named_role_catalog(now: &Timestamp) -> Vec<RoleDef> {
    SEED_ROLES
        .iter()
        .map(|seed| RoleDef {
            id: RoleId(seed.id.to_owned()),
            display_name: Some(seed.display_name.to_owned()),
            action_patterns: seed
                .patterns
                .iter()
                .map(|pattern| ActionPattern((*pattern).to_owned()))
                .collect(),
            created_at: now.clone(),
            updated_at: now.clone(),
        })
        .collect()
}

/// Seed (upsert) the named role catalog into `repo`, stamping `now`.
///
/// Idempotent: re-seeding overwrites each role in place, so a deployment can call
/// this on every boot without duplicating or drifting roles. Custom roles a
/// deployment adds under other ids are untouched. The upsert loop itself is the
/// kernel's product-neutral [`seed_roles`] mechanism; this function only chooses
/// the Anthropic catalog as its policy input.
pub fn seed_named_roles(repo: &dyn RoleRepository, now: &Timestamp) -> RepositoryResult<()> {
    seed_roles(repo, named_role_catalog(now))
}

/// The grant sets for the awaken-runtime preset roles.
///
/// - `runtime_admin`: full authority over the runtime surface (`agent.*`,
///   `session.*`, `tool.*`). Appropriate for a workspace admin binding on the
///   runtime control plane.
/// - `runtime_user`: basic runtime access — run an agent, open a session, and
///   invoke a tool. Appropriate for a developer or end-user workspace binding.
const RUNTIME_SEED_ROLES: &[SeedRole] = &[
    SeedRole {
        id: "runtime_admin",
        display_name: "Runtime Admin",
        patterns: &["agent.*", "session.*", "tool.*"],
    },
    SeedRole {
        id: "runtime_user",
        display_name: "Runtime User",
        patterns: &["agent.run", "session.create", "tool.invoke"],
    },
];

/// Build the awaken-runtime preset role catalog, stamping every role with `now`.
///
/// The result is pure data — ordered as [`AWAKEN_RUNTIME_ROLE_IDS`] — that
/// awaken-1.0.0-dev startup provisioning loads into its [`RoleRepository`] (see
/// [`seed_runtime_roles`]). Every role satisfies [`RoleDef::validate`].
pub fn runtime_role_catalog(now: &Timestamp) -> Vec<RoleDef> {
    RUNTIME_SEED_ROLES
        .iter()
        .map(|seed| RoleDef {
            id: RoleId(seed.id.to_owned()),
            display_name: Some(seed.display_name.to_owned()),
            action_patterns: seed
                .patterns
                .iter()
                .map(|pattern| ActionPattern((*pattern).to_owned()))
                .collect(),
            created_at: now.clone(),
            updated_at: now.clone(),
        })
        .collect()
}

/// Seed (upsert) the awaken-runtime preset roles into `repo`, stamping `now`.
///
/// Called during awaken-1.0.0-dev startup provisioning so the runtime does not
/// hand-roll its vocab. Idempotent: re-seeding overwrites each role in place.
/// Custom roles a deployment adds under other ids are untouched. The upsert loop
/// itself is the kernel's product-neutral [`seed_roles`] mechanism; this function
/// only chooses the runtime catalog as its policy input.
pub fn seed_runtime_roles(repo: &dyn RoleRepository, now: &Timestamp) -> RepositoryResult<()> {
    seed_roles(repo, runtime_role_catalog(now))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ts() -> Timestamp {
        Timestamp("2026-06-23T00:00:00Z".into())
    }

    #[test]
    fn catalog_ids_are_exactly_the_anthropic_role_names() {
        let catalog = named_role_catalog(&ts());
        let ids: Vec<String> = catalog.iter().map(|role| role.id.0.clone()).collect();
        assert_eq!(ids, ANTHROPIC_ROLE_IDS);
    }

    #[test]
    fn every_seeded_role_satisfies_its_invariants() {
        for role in named_role_catalog(&ts()) {
            assert_eq!(
                role.validate(),
                Ok(()),
                "seeded role {} must validate",
                role.id.0
            );
            // No role carries the catch-all `*`, including admin.
            assert!(
                role.action_patterns.iter().all(|p| p.0 != "*"),
                "seeded role {} carries the forbidden `*`",
                role.id.0
            );
        }
    }

    #[test]
    fn grant_sets_match_the_adr_examples() {
        let catalog = named_role_catalog(&ts());
        let patterns = |id: &str| -> Vec<String> {
            catalog
                .iter()
                .find(|role| role.id.0 == id)
                .unwrap()
                .action_patterns
                .iter()
                .map(|p| p.0.clone())
                .collect()
        };

        // ADR-0008 decision 2 worked examples.
        assert_eq!(patterns("developer"), vec!["apikey.*"]);
        assert_eq!(patterns("billing"), vec!["billing.*"]);
        // `admin` is the union of every namespace, not the forbidden `*`.
        let admin = patterns("admin");
        for ns in ROLE_NAMESPACES {
            assert!(
                admin.contains(&format!("{ns}.*")),
                "admin must cover {ns}.*"
            );
        }
        assert_eq!(admin.len(), ADMIN_PATTERNS.len());
        for pattern in ADMIN_PATTERNS {
            assert!(admin.contains(&pattern.to_owned()));
        }
    }

    #[test]
    fn admin_authorizes_every_namespace_and_no_role_is_a_global_wildcard() {
        use awaken_iam_contract::ActionKey;

        let catalog = named_role_catalog(&ts());
        let admin = catalog.iter().find(|r| r.id.0 == "admin").unwrap();
        // Admin reaches an action in each namespace...
        for ns in ROLE_NAMESPACES {
            let action = ActionKey(format!("{ns}.anything"));
            assert!(
                admin.action_patterns.iter().any(|p| p.matches(&action)),
                "admin must authorize {ns}.anything"
            );
        }
        // ...but not an action in an unseeded namespace (default-deny holds).
        let foreign = ActionKey("pack.publish".into());
        assert!(
            !admin.action_patterns.iter().any(|p| p.matches(&foreign)),
            "admin must not authorize an unseeded namespace via a hidden wildcard"
        );
    }

    #[test]
    fn runtime_catalog_ids_are_exactly_the_preset_names() {
        let catalog = runtime_role_catalog(&ts());
        let ids: Vec<String> = catalog.iter().map(|role| role.id.0.clone()).collect();
        assert_eq!(ids, AWAKEN_RUNTIME_ROLE_IDS);
    }

    #[test]
    fn every_runtime_role_satisfies_its_invariants() {
        for role in runtime_role_catalog(&ts()) {
            assert_eq!(
                role.validate(),
                Ok(()),
                "runtime role {} must validate",
                role.id.0
            );
            assert!(
                role.action_patterns.iter().all(|p| p.0 != "*"),
                "runtime role {} carries the forbidden `*`",
                role.id.0
            );
        }
    }

    #[test]
    fn runtime_admin_covers_full_runtime_surface() {
        use awaken_iam_contract::ActionKey;

        let catalog = runtime_role_catalog(&ts());
        let admin = catalog.iter().find(|r| r.id.0 == "runtime_admin").unwrap();
        for action in [
            "agent.run",
            "agent.configure",
            "session.create",
            "tool.invoke",
        ] {
            let key = ActionKey(action.into());
            assert!(
                admin.action_patterns.iter().any(|p| p.matches(&key)),
                "runtime_admin must cover {action}"
            );
        }
        // Must not cover a foreign namespace.
        let foreign = ActionKey("oversight.approval.grant".into());
        assert!(
            !admin.action_patterns.iter().any(|p| p.matches(&foreign)),
            "runtime_admin must not cover oversight namespace"
        );
    }

    #[test]
    fn runtime_user_covers_basic_runtime_actions() {
        use awaken_iam_contract::ActionKey;

        let catalog = runtime_role_catalog(&ts());
        let user = catalog.iter().find(|r| r.id.0 == "runtime_user").unwrap();
        for action in ["agent.run", "session.create", "tool.invoke"] {
            let key = ActionKey(action.into());
            assert!(
                user.action_patterns.iter().any(|p| p.matches(&key)),
                "runtime_user must cover {action}"
            );
        }
        // runtime_user does not carry wildcard admin authority.
        let admin_action = ActionKey("agent.configure".into());
        assert!(
            !user
                .action_patterns
                .iter()
                .any(|p| p.matches(&admin_action)),
            "runtime_user must not cover agent.configure"
        );
    }

    #[test]
    fn seeding_runtime_roles_is_idempotent() {
        use awaken_iam_core::RoleId as Id;
        use std::collections::BTreeMap;
        use std::sync::Mutex;

        #[derive(Default)]
        struct MemRoles(Mutex<BTreeMap<String, RoleDef>>);
        impl RoleRepository for MemRoles {
            fn get(&self, id: &Id) -> RepositoryResult<Option<RoleDef>> {
                Ok(self.0.lock().unwrap().get(&id.0).cloned())
            }
            fn upsert(&self, role: RoleDef) -> RepositoryResult<()> {
                self.0.lock().unwrap().insert(role.id.0.clone(), role);
                Ok(())
            }
            fn list(&self) -> RepositoryResult<Vec<RoleDef>> {
                Ok(self.0.lock().unwrap().values().cloned().collect())
            }
            fn remove(&self, id: &Id) -> RepositoryResult<()> {
                self.0.lock().unwrap().remove(&id.0);
                Ok(())
            }
        }

        let repo = MemRoles::default();
        seed_runtime_roles(&repo, &ts()).unwrap();
        assert_eq!(repo.list().unwrap().len(), AWAKEN_RUNTIME_ROLE_IDS.len());

        seed_runtime_roles(&repo, &ts()).unwrap();
        assert_eq!(repo.list().unwrap().len(), AWAKEN_RUNTIME_ROLE_IDS.len());

        for id in AWAKEN_RUNTIME_ROLE_IDS {
            assert!(repo.get(&Id(id.to_owned())).unwrap().is_some());
        }
    }

    #[test]
    fn seeding_a_repo_is_idempotent_and_loads_every_role() {
        // A minimal in-memory RoleRepository to exercise the loader without the server.
        use std::collections::BTreeMap;
        use std::sync::Mutex;

        #[derive(Default)]
        struct MemRoles(Mutex<BTreeMap<String, RoleDef>>);
        impl RoleRepository for MemRoles {
            fn get(&self, id: &RoleId) -> RepositoryResult<Option<RoleDef>> {
                Ok(self.0.lock().unwrap().get(&id.0).cloned())
            }
            fn upsert(&self, role: RoleDef) -> RepositoryResult<()> {
                self.0.lock().unwrap().insert(role.id.0.clone(), role);
                Ok(())
            }
            fn list(&self) -> RepositoryResult<Vec<RoleDef>> {
                Ok(self.0.lock().unwrap().values().cloned().collect())
            }
            fn remove(&self, id: &RoleId) -> RepositoryResult<()> {
                self.0.lock().unwrap().remove(&id.0);
                Ok(())
            }
        }

        let repo = MemRoles::default();
        seed_named_roles(&repo, &ts()).unwrap();
        assert_eq!(repo.list().unwrap().len(), ANTHROPIC_ROLE_IDS.len());

        // Re-seeding overwrites in place rather than duplicating.
        seed_named_roles(&repo, &ts()).unwrap();
        assert_eq!(repo.list().unwrap().len(), ANTHROPIC_ROLE_IDS.len());

        for id in ANTHROPIC_ROLE_IDS {
            assert!(repo.get(&RoleId(id.to_owned())).unwrap().is_some());
        }
    }
}
