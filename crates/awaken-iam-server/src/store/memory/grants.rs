//! Grant admission shared by single and batch issuance.

use awaken_iam_core::{AuditEvent, Grant, GrantSubject, RepositoryResult};

use super::privacy::ensure_admitted;
use super::support::checked_lock;
use super::{Authz, InMemoryStore};
use crate::GrantBatchStore;

/// Whether `grant` may be stored: its own and any replaced grant's scope and
/// group must still be admitted.
pub(super) fn admit_grant(authz: &Authz, grant: &Grant) -> RepositoryResult<()> {
    let mut scopes = vec![grant.scope.clone()];
    let mut groups = Vec::new();
    if let GrantSubject::Group(group) = &grant.subject {
        groups.push(group.0.clone());
    }
    if let Some(previous) = authz.grants.get(&grant.id.0) {
        scopes.push(previous.scope.clone());
        if let GrantSubject::Group(group) = &previous.subject {
            groups.push(group.0.clone());
        }
    }
    ensure_admitted(authz, &scopes, &groups)
}

impl GrantBatchStore for InMemoryStore {
    fn put_grants(&self, grants: &[Grant], audits: Vec<AuditEvent>) -> RepositoryResult<u64> {
        let mut authz = checked_lock(&self.authz, "authz")?;
        // Admission reads only stored state, so checking every grant before the
        // first write keeps the batch all-or-nothing.
        for grant in grants {
            admit_grant(&authz, grant)?;
        }
        let mut audit = checked_lock(&self.audit, "audit")?;
        let mut fence = checked_lock(&self.fence, "fence")?;
        for grant in grants {
            authz.grants.insert(grant.id.0.clone(), grant.clone());
        }
        audit.extend(audits);
        fence.version += 1;
        Ok(fence.version)
    }
}
