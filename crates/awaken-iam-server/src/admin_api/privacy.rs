//! PAP projection of the original organization privacy transaction.
//! Core owns publication/replay decisions; this module creates the original
//! audit input and projects the canonical result without another write/version.
use super::*;

pub(crate) fn organization_erasure_audit(id: &OrgId, at: Timestamp) -> AuditEvent {
    let event = DomainEvent::OrganizationDeleted(id.clone());
    AuditEvent {
        at,
        actor: None,
        action: event.action().to_owned(),
        detail: event.detail(),
    }
}

impl<S: PolicyStore> PolicyAdminApi<S> {
    /// Idempotently erase an organization and every IAM-owned projection in
    /// its authoritative scope closure.
    pub fn delete_org(&mut self, id: &OrgId, at: Timestamp) -> AdminResult<u64> {
        Ok(self
            .delete_org_with_receipt(id, at)?
            .observed_policy_version)
    }

    /// Exact participant data from the original atomic privacy owner. An old
    /// AdminMutationAck exposes only observed_policy_version, never this proof.
    pub fn delete_org_with_receipt(
        &mut self,
        id: &OrgId,
        at: Timestamp,
    ) -> AdminResult<awaken_iam_contract::OrgPrivacyCommitReceipt> {
        let receipt = self
            .store
            .erase_org_privacy_with_audit(id, organization_erasure_audit(id, at))?;
        self.version = receipt.observed_policy_version;
        if receipt.admission_changed {
            self.events
                .push(DomainEvent::OrganizationDeleted(id.clone()));
        }
        Ok(receipt)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn exact_receipt_replay_refreshes_current_version_without_republishing_erasure() {
        // CF2 PAP cause/effect table: first unknown -> negative fact published
        // but unconfirmed; unrelated policy advance -> replay observes newer
        // version while retaining the original erasure coordinate; no extra
        // audit/event and old delete projects CURRENT, not the old receipt.
        let store = crate::InMemoryStore::new();
        let mut pap = PolicyAdminApi::new(store.clone());
        let org = OrgId("unknown".into());
        let at = crate::clock::timestamp(1);
        let first = pap.delete_org_with_receipt(&org, at.clone()).unwrap();
        assert!(!first.changed && first.admission_changed && !first.confirmed_organization);
        let newer = store.advance_version().unwrap();
        let repeated = pap.delete_org_with_receipt(&org, at.clone()).unwrap();
        assert_eq!(repeated.erasure_version, first.erasure_version);
        assert_eq!(repeated.observed_policy_version, newer);
        assert_eq!(pap.version(), newer);
        assert_eq!(pap.events().len(), 1);
        assert_eq!(AuditSink::events(&store).unwrap().len(), 1);
        assert_eq!(pap.delete_org(&org, at).unwrap(), newer);
    }
}
