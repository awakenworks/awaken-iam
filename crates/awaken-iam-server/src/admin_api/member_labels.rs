//! Exact-Org account presentation over the original PAP and identity rows.
use std::collections::BTreeSet;

use awaken_iam_contract::{AccountId, OrgId, OrganizationMemberLabel, PrincipalRef, ScopeRef};
use awaken_iam_core::AccountRepository;

use super::{AdminResult, PolicyAdminApi, PolicyStore};

impl<S: PolicyStore + AccountRepository> PolicyAdminApi<S> {
    /// Observe labels for Accounts with an exact Org binding, never global identities.
    /// This is not a policy fence or authorization/membership receipt.
    pub fn organization_member_labels(
        &self,
        org_id: &OrgId,
    ) -> AdminResult<Vec<OrganizationMemberLabel>> {
        let accounts: BTreeSet<String> = self
            .memberships_for_scope(&ScopeRef::Org {
                org_id: org_id.clone(),
            })?
            .into_iter()
            .filter_map(|binding| match binding.principal {
                PrincipalRef::Account { account_id } => Some(account_id.0),
                _ => None,
            })
            .collect();
        accounts
            .into_iter()
            .map(|id| {
                let account_id = AccountId(id);
                let display_name = AccountRepository::get(self.store(), &account_id)?
                    .and_then(|account| account.display_name)
                    .map(|name| name.trim().to_owned())
                    .filter(|name| !name.is_empty());
                Ok(OrganizationMemberLabel {
                    account_id,
                    display_name,
                })
            })
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{InMemoryStore, SqlConn, SqlStore, SqliteBackend, sqlite_migrated_store};
    use awaken_iam_contract::{Account, AccountStatus, Timestamp, WorkspaceId};
    use awaken_iam_core::{RoleBinding, RoleBindingRepository, RoleId};

    fn account(id: &str, name: Option<&str>) -> Account {
        Account {
            id: AccountId(id.into()),
            status: AccountStatus::Active,
            display_name: name.map(str::to_owned),
            created_at: Timestamp("2026-11-14T00:00:00Z".into()),
            updated_at: Timestamp("2026-11-14T00:00:00Z".into()),
        }
    }

    fn binding(id: &str, role: &str, scope: ScopeRef) -> RoleBinding {
        RoleBinding {
            principal: PrincipalRef::Account {
                account_id: AccountId(id.into()),
            },
            role: RoleId(role.into()),
            scope,
        }
    }

    #[test]
    fn organization_member_labels_are_exact_deduplicated_and_non_authoritative() {
        // L1 exact Org + two roles -> one id, stable order. L2 Workspace/foreign
        // Org or non-Account binding -> excluded. L3 missing/blank labels -> None;
        // equal names remain distinct identities. L7 removed binding -> absent on
        // the next observation. No profile status or name grants membership.
        let store = InMemoryStore::new();
        let org = ScopeRef::Org {
            org_id: OrgId("acme".into()),
        };
        for (id, name) in [
            ("ada", Some(" Ada ")),
            ("bob", Some("Ada")),
            ("blank", Some("  ")),
            ("foreign", Some("Hidden")),
        ] {
            AccountRepository::upsert(&store, account(id, name)).unwrap();
        }
        for (id, role) in [
            ("ada", "member"),
            ("ada", "billing"),
            ("bob", "member"),
            ("blank", "member"),
            ("missing", "member"),
        ] {
            RoleBindingRepository::add(&store, binding(id, role, org.clone())).unwrap();
        }
        RoleBindingRepository::add(
            &store,
            binding(
                "foreign",
                "member",
                ScopeRef::Org {
                    org_id: OrgId("other".into()),
                },
            ),
        )
        .unwrap();
        RoleBindingRepository::add(
            &store,
            binding(
                "workspace-only",
                "member",
                ScopeRef::Workspace {
                    workspace_id: WorkspaceId("child".into()),
                },
            ),
        )
        .unwrap();
        RoleBindingRepository::add(
            &store,
            RoleBinding {
                principal: PrincipalRef::Service {
                    service_id: "service".into(),
                },
                role: RoleId("member".into()),
                scope: org.clone(),
            },
        )
        .unwrap();
        let pap = PolicyAdminApi::new(store.clone());
        let labels = pap
            .organization_member_labels(&OrgId("acme".into()))
            .unwrap();
        assert_eq!(
            labels,
            vec![
                OrganizationMemberLabel {
                    account_id: AccountId("ada".into()),
                    display_name: Some("Ada".into())
                },
                OrganizationMemberLabel {
                    account_id: AccountId("blank".into()),
                    display_name: None
                },
                OrganizationMemberLabel {
                    account_id: AccountId("bob".into()),
                    display_name: Some("Ada".into())
                },
                OrganizationMemberLabel {
                    account_id: AccountId("missing".into()),
                    display_name: None
                },
            ]
        );
        RoleBindingRepository::remove(&store, &binding("bob", "member", org)).unwrap();
        assert!(
            !pap.organization_member_labels(&OrgId("acme".into()))
                .unwrap()
                .iter()
                .any(|label| label.account_id.0 == "bob")
        );
        assert!(
            pap.organization_member_labels(&OrgId("other".into()))
                .unwrap()
                .iter()
                .all(|label| label.account_id.0 == "foreign")
        );
    }

    #[test]
    fn organization_member_labels_fail_the_whole_read_on_repository_error() {
        // L5 real original SQLite storage: first Account decodes, the next row
        // is invalid -> no partial Vec success. Missing account table is an I/O
        // failure, not the L3 absent-profile case; missing role table also fails.
        // These faults use original SqlConn; no alternate Account/PAP adapter.
        let backend = SqliteBackend::open_in_memory().unwrap();
        let store: SqlStore<_> = sqlite_migrated_store(backend.clone(), "member_labels").unwrap();
        let org = ScopeRef::Org {
            org_id: OrgId("acme".into()),
        };
        for id in ["a", "z"] {
            AccountRepository::upsert(&store, account(id, Some("Visible"))).unwrap();
            RoleBindingRepository::add(&store, binding(id, "member", org.clone())).unwrap();
        }
        backend
            .execute(
                "UPDATE member_labels_accounts SET status = ? WHERE id = ?",
                &[Some("invalid".into()), Some("z".into())],
            )
            .unwrap();
        let pap = PolicyAdminApi::new(store);
        assert!(
            pap.organization_member_labels(&OrgId("acme".into()))
                .is_err()
        );
        backend
            .execute("DROP TABLE member_labels_accounts", &[])
            .unwrap();
        assert!(
            pap.organization_member_labels(&OrgId("acme".into()))
                .is_err()
        );
        backend
            .execute("DROP TABLE member_labels_role_bindings", &[])
            .unwrap();
        assert!(
            pap.organization_member_labels(&OrgId("acme".into()))
                .is_err()
        );
    }
}
