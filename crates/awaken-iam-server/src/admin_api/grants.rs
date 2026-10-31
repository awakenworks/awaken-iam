//! Atomic batch issuance of grants.
//!
//! | rule | batch                                   | outcome |
//! |------|-----------------------------------------|---------|
//! | B1   | empty                                   | `Invalid`, nothing changes |
//! | B2   | one grant id appears twice              | `Invalid`, nothing changes |
//! | B3   | any grant fails `GrantRepository::put`  | that error, nothing changes |
//! | B4   | every grant admitted                    | all stored, one audit event per grant, one version advance |

use std::collections::BTreeSet;

use awaken_iam_contract::Timestamp;
use awaken_iam_core::{AuditEvent, Grant, RepositoryError};

use super::{AdminError, AdminResult, DomainEvent, PolicyAdminApi, PolicyStore};

/// Atomic persistence boundary for issuing several grants at once.
pub trait GrantBatchStore: Send + Sync {
    /// Insert or replace every grant under the exact admission rules of
    /// [`GrantRepository::put`](awaken_iam_core::GrantRepository::put), append
    /// `audits` and advance the policy version once, all in one transaction.
    /// Returns the advanced version; on any error nothing is written.
    fn put_grants(&self, grants: &[Grant], audits: Vec<AuditEvent>)
    -> Result<u64, RepositoryError>;
}

impl<S: PolicyStore> PolicyAdminApi<S> {
    /// Issue every grant in `grants` atomically under one version advance.
    ///
    /// Each grant is validated and audited exactly as
    /// [`issue_grant`](Self::issue_grant) would; see the module table.
    pub fn issue_grants(&mut self, grants: Vec<Grant>, at: Timestamp) -> AdminResult<u64> {
        if grants.is_empty() {
            return Err(AdminError::Invalid("grant batch must not be empty".into()));
        }
        let mut seen = BTreeSet::new();
        for grant in &grants {
            if !seen.insert(grant.id.0.as_str()) {
                return Err(AdminError::Invalid(format!(
                    "grant batch repeats grant id {}",
                    grant.id.0
                )));
            }
        }
        let events: Vec<DomainEvent> = grants
            .iter()
            .map(|grant| DomainEvent::GrantIssued(grant.id.clone()))
            .collect();
        let audits = events
            .iter()
            .map(|event| AuditEvent {
                at: at.clone(),
                actor: None,
                action: event.action().to_owned(),
                detail: event.detail(),
            })
            .collect();
        self.version = self.store.put_grants(&grants, audits)?;
        self.events.extend(events);
        Ok(self.version)
    }
}

#[cfg(test)]
mod tests {
    use awaken_iam_contract::{AccountId, OrgId, PrincipalRef, ScopeRef};
    use awaken_iam_core::{
        ActionPattern, AuditSink, Effect, GrantId, GrantRepository, GrantSubject, Organization,
    };

    use super::*;
    use crate::{FenceStore, InMemoryStore};

    fn at() -> Timestamp {
        Timestamp("2026-11-01T00:00:00Z".into())
    }

    fn grant(id: &str, scope: ScopeRef) -> Grant {
        Grant {
            id: GrantId(id.into()),
            subject: GrantSubject::Principal(PrincipalRef::Account {
                account_id: AccountId("ada".into()),
            }),
            action_pattern: ActionPattern("pack.read".into()),
            scope,
            effect: Effect::Allow,
        }
    }

    fn issued(store: &InMemoryStore) -> usize {
        AuditSink::events(store)
            .unwrap()
            .iter()
            .filter(|event| event.action == "grant.issue")
            .count()
    }

    #[test]
    fn batch_table_holds_on_the_memory_store() {
        let store = InMemoryStore::default();
        let mut pap = PolicyAdminApi::new(store.clone());
        let owner = PrincipalRef::Account {
            account_id: AccountId("ada".into()),
        };
        pap.create_org(
            Organization {
                id: OrgId("gone".into()),
                display_name: None,
                owner,
                created_at: at(),
                updated_at: at(),
            },
            at(),
        )
        .unwrap();
        pap.delete_org(&OrgId("gone".into()), at()).unwrap();
        let version = store.fence().unwrap().version;
        let erased = ScopeRef::Org {
            org_id: OrgId("gone".into()),
        };

        // B1, B2, B3: rejected batches change nothing.
        assert!(matches!(
            pap.issue_grants(Vec::new(), at()),
            Err(AdminError::Invalid(_))
        ));
        assert!(matches!(
            pap.issue_grants(
                vec![grant("x", ScopeRef::Global), grant("x", ScopeRef::Global)],
                at()
            ),
            Err(AdminError::Invalid(_))
        ));
        assert!(
            pap.issue_grants(
                vec![grant("ok", ScopeRef::Global), grant("bad", erased)],
                at()
            )
            .is_err()
        );
        assert!(GrantRepository::list(&store).unwrap().is_empty());
        assert_eq!(store.fence().unwrap().version, version);
        assert_eq!(issued(&store), 0);

        // B4: every grant, one audit each, one version advance.
        let advanced = pap
            .issue_grants(
                vec![grant("a", ScopeRef::Global), grant("b", ScopeRef::Global)],
                at(),
            )
            .unwrap();
        assert_eq!(advanced, version + 1);
        assert_eq!(pap.version(), version + 1);
        assert_eq!(GrantRepository::list(&store).unwrap().len(), 2);
        assert_eq!(issued(&store), 2);
    }
}
