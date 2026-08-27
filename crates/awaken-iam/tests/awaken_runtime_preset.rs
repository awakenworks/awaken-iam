//! awaken-runtime consumer namespace + preset role contract tests, exercised
//! end-to-end through the public `awaken-iam` facade.
//!
//! Pins three load-bearing claims for the awaken-1.0.0-dev startup provisioning:
//!
//! - **Runtime namespaces are declared.** `awaken_runtime()` exposes the full
//!   `agent.*`, `session.*`, `tool.*` surface as a [`ConsumerNamespaces`] so the
//!   runtime does not hand-roll its vocab.
//! - **Preset roles map to those namespaces.** `runtime_role_catalog()` /
//!   `seed_runtime_roles()` seed catalog-owned role definitions whose grant sets
//!   cover the runtime surface (G16), separate from the Anthropic platform catalog.
//! - **Roles authorize through the real engine.** A principal bound to a preset
//!   role is allowed on runtime actions and denied on unrelated namespaces, proving
//!   the preset integrates correctly with the `PolicySet` evaluation path.

use awaken_iam::{
    AWAKEN_RUNTIME_NAMESPACES, AWAKEN_RUNTIME_ROLE_IDS, AccountId, ActionKey, ActionPattern,
    AuthorizationDecision, AuthorizationRequest, Effect, Grant, GrantId, GrantSubject, OrgId,
    PolicySet, PrincipalRef, ResourceModel, ResourceType, ResourceTypeDef, RoleBinding, RoleId,
    ScopeRef, WorkspaceId, awaken_runtime, managed_agents, runtime_role_catalog,
    seed_runtime_roles,
};
use awaken_iam_contract::Timestamp;

fn ts() -> Timestamp {
    Timestamp("2026-07-04T00:00:00Z".into())
}

fn account(id: &str) -> PrincipalRef {
    PrincipalRef::Account {
        account_id: AccountId(id.into()),
    }
}

/// The awaken-runtime resource model: agent, session, and tool resource types
/// whose actions all live under the runtime's declared namespaces.
fn runtime_model() -> ResourceModel {
    let mut model = ResourceModel::new();
    model
        .register_resource_type(ResourceTypeDef {
            resource_type: ResourceType("agent".into()),
            parent_type: None,
            actions: vec![
                ActionKey("agent.run".into()),
                ActionKey("agent.configure".into()),
            ],
        })
        .register_resource_type(ResourceTypeDef {
            resource_type: ResourceType("session".into()),
            parent_type: None,
            actions: vec![
                ActionKey("session.create".into()),
                ActionKey("session.destroy".into()),
            ],
        })
        .register_resource_type(ResourceTypeDef {
            resource_type: ResourceType("tool".into()),
            parent_type: None,
            actions: vec![
                ActionKey("tool.invoke".into()),
                ActionKey("tool.configure".into()),
            ],
        });
    model
}

/// `awaken_runtime()` declares the three runtime namespaces and its
/// [`ConsumerNamespaces::confines`] check validates the runtime model.
#[test]
fn runtime_namespaces_are_declared_and_confine_the_model() {
    let runtime = awaken_runtime();
    assert_eq!(
        runtime.namespaces(),
        AWAKEN_RUNTIME_NAMESPACES,
        "namespace order must match the constant"
    );
    assert_eq!(
        runtime.namespaces(),
        ["agent", "session", "tool"],
        "namespaces are sorted"
    );
    assert_eq!(runtime.consumer(), "awaken-runtime");

    // The runtime model stays inside its declared surface.
    assert_eq!(runtime.confines(&runtime_model()), Ok(()));

    // Glob patterns cover the full surface.
    assert_eq!(
        runtime.glob_patterns(),
        vec![
            ActionPattern("agent.*".into()),
            ActionPattern("session.*".into()),
            ActionPattern("tool.*".into()),
        ]
    );
}

/// The runtime consumer declaration is a superset of the managed-agents
/// declaration: awaken_runtime() subsumes the agent namespace.
#[test]
fn awaken_runtime_subsumes_managed_agents_namespace() {
    let runtime = awaken_runtime();
    let agents = managed_agents();
    for ns in agents.namespaces() {
        assert!(
            runtime.owns_namespace(ns),
            "awaken_runtime must own the managed-agents namespace {ns}"
        );
    }
    // The runtime adds session and tool on top.
    assert!(runtime.owns_namespace("session"));
    assert!(runtime.owns_namespace("tool"));
}

/// The preset role catalog produces exactly the declared role ids and every
/// role satisfies its invariants (non-empty, no `*`).
#[test]
fn preset_role_catalog_matches_the_declared_ids_and_validates() {
    let catalog = runtime_role_catalog(&ts());
    let ids: Vec<&str> = catalog.iter().map(|r| r.id.0.as_str()).collect();
    assert_eq!(ids, AWAKEN_RUNTIME_ROLE_IDS);

    for role in &catalog {
        assert_eq!(
            role.validate(),
            Ok(()),
            "preset role {} must validate",
            role.id.0
        );
    }
}

/// `runtime_admin` authorizes every action in the runtime surface via the real
/// `PolicySet` evaluation, and is denied on unrelated namespaces.
#[test]
fn runtime_admin_role_authorizes_the_full_runtime_surface() {
    let ws = WorkspaceId("ws_acme".into());
    let org = OrgId("org_acme".into());

    let mut policy = PolicySet::new();
    policy.register_resource_model(&runtime_model());
    policy.scope_graph_mut().assign_workspace(ws.clone(), org);

    let admin_role = RoleId("runtime_admin".into());
    for pattern in awaken_runtime().glob_patterns() {
        policy.add_grant(Grant {
            id: GrantId(format!("g_admin_{}", pattern.0)),
            subject: GrantSubject::Role(admin_role.clone()),
            action_pattern: pattern,
            scope: ScopeRef::Workspace {
                workspace_id: ws.clone(),
            },
            effect: Effect::Allow,
        });
    }

    let admin = account("acct_admin");
    policy.bind_role(RoleBinding {
        principal: admin.clone(),
        role: admin_role,
        scope: ScopeRef::Workspace {
            workspace_id: ws.clone(),
        },
    });

    let at_ws = |who: &PrincipalRef, action: &str| {
        policy
            .evaluate(&AuthorizationRequest::direct(
                who.clone(),
                ActionKey(action.into()),
                ScopeRef::Workspace {
                    workspace_id: ws.clone(),
                },
            ))
            .decision
    };

    // Full runtime surface is reachable.
    for action in [
        "agent.run",
        "agent.configure",
        "session.create",
        "session.destroy",
        "tool.invoke",
        "tool.configure",
    ] {
        assert_eq!(
            at_ws(&admin, action),
            AuthorizationDecision::Allow,
            "runtime_admin must allow {action}"
        );
    }

    // Foreign namespace is denied — default-deny holds.
    assert_eq!(
        at_ws(&admin, "oversight.approval.grant"),
        AuthorizationDecision::Deny,
        "runtime_admin must not reach the oversight namespace"
    );
}

/// `runtime_user` is confined to the basic runtime actions it declares and
/// does not carry admin-level authority over the runtime surface.
#[test]
fn runtime_user_role_is_confined_to_basic_actions() {
    let ws = WorkspaceId("ws_acme".into());
    let org = OrgId("org_acme".into());

    let catalog = runtime_role_catalog(&ts());
    let user_role_def = catalog
        .iter()
        .find(|r| r.id.0 == "runtime_user")
        .unwrap()
        .clone();

    let mut policy = PolicySet::new();
    policy.register_resource_model(&runtime_model());
    policy.scope_graph_mut().assign_workspace(ws.clone(), org);

    for pattern in &user_role_def.action_patterns {
        policy.add_grant(Grant {
            id: GrantId(format!("g_user_{}", pattern.0)),
            subject: GrantSubject::Role(user_role_def.id.clone()),
            action_pattern: pattern.clone(),
            scope: ScopeRef::Workspace {
                workspace_id: ws.clone(),
            },
            effect: Effect::Allow,
        });
    }

    let user = account("acct_user");
    policy.bind_role(RoleBinding {
        principal: user.clone(),
        role: user_role_def.id.clone(),
        scope: ScopeRef::Workspace {
            workspace_id: ws.clone(),
        },
    });

    let at_ws = |who: &PrincipalRef, action: &str| {
        policy
            .evaluate(&AuthorizationRequest::direct(
                who.clone(),
                ActionKey(action.into()),
                ScopeRef::Workspace {
                    workspace_id: ws.clone(),
                },
            ))
            .decision
    };

    // Basic runtime actions are allowed.
    for action in ["agent.run", "session.create", "tool.invoke"] {
        assert_eq!(
            at_ws(&user, action),
            AuthorizationDecision::Allow,
            "runtime_user must allow {action}"
        );
    }

    // Admin-only actions are denied — role does not carry a wildcard.
    for action in ["agent.configure", "session.destroy", "tool.configure"] {
        assert_eq!(
            at_ws(&user, action),
            AuthorizationDecision::Deny,
            "runtime_user must deny {action}"
        );
    }
}

/// `seed_runtime_roles` is idempotent and distinct from `seed_named_roles`:
/// seeding both catalogs populates each independently without collision.
#[test]
fn seed_runtime_roles_is_idempotent_and_independent_of_named_catalog() {
    use awaken_iam::{ANTHROPIC_ROLE_IDS, RepositoryResult, RoleDef, seed_named_roles};
    use awaken_iam_core::RoleRepository;
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
    seed_runtime_roles(&repo, &ts()).unwrap();

    let total = ANTHROPIC_ROLE_IDS.len() + AWAKEN_RUNTIME_ROLE_IDS.len();
    assert_eq!(repo.list().unwrap().len(), total);

    // Re-seeding is idempotent: count does not change.
    seed_runtime_roles(&repo, &ts()).unwrap();
    assert_eq!(repo.list().unwrap().len(), total);

    // Every runtime role id is present.
    for id in AWAKEN_RUNTIME_ROLE_IDS {
        assert!(
            repo.get(&RoleId(id.to_owned())).unwrap().is_some(),
            "runtime role {id} must be seeded"
        );
    }
}
