//! Atomic product-resource provisioning command.

use std::collections::BTreeSet;

use awaken_iam_contract::{
    ResourceProvision, ResourceProvisionDisposition, ResourceProvisionReceipt, ScopeRef, Timestamp,
};
use awaken_iam_core::{AuditEvent, OrgRepository};
use sha2::{Digest, Sha256};

use super::{AdminError, AdminResult, DomainEvent, PolicyAdminApi, PolicyStore};

impl<S: PolicyStore> PolicyAdminApi<S> {
    /// Apply one remote consumer outbox delivery as a single IAM commit.
    pub fn provision_resource(
        &mut self,
        provision: ResourceProvision,
        at: Timestamp,
    ) -> AdminResult<ResourceProvisionReceipt> {
        if provision.idempotency_key.trim().is_empty()
            || provision.idempotency_key.len() > 200
            || provision.epoch == 0
            || provision.scope_edges.is_empty()
        {
            return Err(AdminError::Invalid(
                "resource provision requires a bounded key, positive epoch, and scope edge".into(),
            ));
        }
        let mut edge_keys = BTreeSet::new();
        if provision.scope_edges.iter().any(|edge| {
            !edge_keys.insert((edge.resource_type.0.clone(), edge.resource_id.0.clone()))
        }) {
            return Err(AdminError::Invalid("duplicate resource edge".into()));
        }
        let mut grant_ids = BTreeSet::new();
        if provision
            .grants
            .iter()
            .any(|grant| !grant_ids.insert(grant.id.clone()))
        {
            return Err(AdminError::Invalid("duplicate resource grant".into()));
        }
        if OrgRepository::get(&self.store, &provision.org_id)?.is_none() {
            return Err(AdminError::NotFound(format!(
                "organization {}",
                provision.org_id.0
            )));
        }
        let mut projected = self.policy()?;
        for edge in &provision.scope_edges {
            projected.scope_graph_mut().assign_resource_parent(
                edge.resource_type.clone(),
                edge.resource_id.clone(),
                edge.parent.clone(),
            );
        }
        let org_scope = ScopeRef::Org {
            org_id: provision.org_id.clone(),
        };
        let outside_org = provision.scope_edges.iter().any(|edge| {
            !projected.scope_graph().covers(
                &org_scope,
                &ScopeRef::Resource {
                    resource_type: edge.resource_type.clone(),
                    resource_id: edge.resource_id.clone(),
                },
            )
        }) || provision
            .grants
            .iter()
            .any(|grant| !projected.scope_graph().covers(&org_scope, &grant.scope));
        if outside_org {
            return Err(AdminError::Invalid(
                "resource provision escapes its organization scope".into(),
            ));
        }
        let encoded = serde_json::to_vec(&provision)
            .map_err(|error| AdminError::Backend(error.to_string()))?;
        let fingerprint = format!("{:x}", Sha256::digest(encoded));
        let event = DomainEvent::ResourceProvisioned(provision.idempotency_key.clone());
        let audit = AuditEvent {
            at,
            actor: None,
            action: event.action().to_owned(),
            detail: event.detail(),
        };
        let receipt = self
            .store
            .provision_resource(&provision, &fingerprint, audit)?;
        self.version = receipt.version;
        if receipt.disposition == ResourceProvisionDisposition::Applied {
            self.events.push(event);
        }
        Ok(receipt)
    }
}
