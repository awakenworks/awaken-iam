//! Resource-create consistency: the remote transactional outbox.
//!
//! When a consumer reuses the IAM authorization plane, creating a domain object
//! (Workspace/Project/Issue) must also write the scope edges and grants that
//! make it authorizable ([ADR-0004](../../../docs/adr/0004-consumers-reuse-iam-authz.md)
//! #4). How that stays consistent depends on the deployment mode:
//!
//! - **Embedded** consumers hold IAM's prefixed tables in their own database, so
//!   they write the domain row and the grant/edge in **one shared-database
//!   transaction** — nothing here is needed.
//! - **Remote** consumers cannot transact against IAM's database, so two writes
//!   to two systems would risk a torn state (domain row without grants, or the
//!   reverse). The fix is a **transactional outbox**: the consumer writes the
//!   domain row *and* a [`ResourceProvision`] outbox record in its own single
//!   local transaction, then a relay drains the outbox and propagates each
//!   record to IAM asynchronously.
//!
//! Three properties make the asynchronous gap safe with no two-phase commit:
//!
//! 1. **Fail-closed.** Until a record lands in IAM, a request against the new
//!    resource matches no grant and is denied. The window over-denies, never
//!    over-permits, so eventual consistency cannot leak access.
//! 2. **Idempotent.** The relay is at-least-once — a crash between propagating a
//!    record and marking it delivered redelivers it. Every record carries an
//!    `idempotency_key`, and its grants upsert by id, so a redelivery is a
//!    no-op.
//! 3. **Epoch-fenced.** Each record carries the consumer's monotonic resource
//!    `epoch`; a stale redelivery cannot resurrect a grant that a later
//!    revocation already retired under the `version`/`epoch` fence.
//!
//! This module owns the consumer-side mechanism: the [`OutboxStore`] port (with
//! an in-memory adapter), the [`ProvisionTransport`] seam to IAM, and the
//! [`OutboxRelay`] that drains pending records. The single-transaction enqueue
//! itself is the consumer's, since only the consumer owns the domain
//! transaction; this crate provides the record shape and the drain logic it
//! wraps.

use awaken_iam_contract::ResourceProvision;

use crate::RemoteError;

/// Delivery state of one outbox record.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OutboxStatus {
    /// Written locally but not yet confirmed propagated to IAM.
    Pending,
    /// Confirmed applied by IAM; retained for audit, never re-sent.
    Delivered,
}

/// A single outbox record: a [`ResourceProvision`] plus its local delivery
/// state, addressed by a store-assigned monotonic sequence number.
///
/// The sequence number orders propagation (a child resource's edge must not be
/// applied before its parent's) and identifies the record for `mark_delivered`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OutboxRecord {
    /// Store-assigned monotonic sequence number, ascending in enqueue order.
    pub seq: u64,
    /// The grant/edge payload to propagate to IAM.
    pub provision: ResourceProvision,
    /// Whether this record has been confirmed delivered.
    pub status: OutboxStatus,
}

/// Failure surface for the local outbox store.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum OutboxError {
    /// `mark_delivered` named a sequence number the store does not hold.
    #[error("outbox record not found: {0}")]
    NotFound(u64),
    /// The backing store failed for a reason outside the domain's control.
    #[error("outbox store error: {0}")]
    Backend(String),
}

/// Local persistence for the transactional outbox.
///
/// The consumer's adapter writes the [`OutboxRecord`] in the **same local
/// transaction** as the domain row — that single-transaction atomicity is what
/// makes the outbox transactional, and it is the consumer's responsibility
/// because only the consumer owns the domain database. The relay then reads
/// [`OutboxStore::pending`] and confirms each with [`OutboxStore::mark_delivered`].
pub trait OutboxStore {
    /// Append a record and return its assigned sequence number.
    ///
    /// In a remote consumer this call participates in the domain write's
    /// transaction, so a rolled-back domain create discards the outbox record
    /// too and nothing is ever propagated for a resource that does not exist.
    fn enqueue(&self, provision: ResourceProvision) -> Result<u64, OutboxError>;

    /// List undelivered records in ascending sequence order.
    fn pending(&self) -> Result<Vec<OutboxRecord>, OutboxError>;

    /// Mark a record delivered. Idempotent: re-marking a delivered record is a
    /// no-op, so a duplicated confirmation never errors.
    fn mark_delivered(&self, seq: u64) -> Result<(), OutboxError>;
}

/// The seam over which a drained record reaches IAM.
///
/// A remote consumer supplies an HTTP implementation (`POST` the
/// [`ResourceProvision`] to IAM's provisioning endpoint); tests supply a fake.
/// The implementation must apply the payload **idempotently** keyed on
/// [`ResourceProvision::idempotency_key`], because the relay is at-least-once.
pub trait ProvisionTransport {
    /// Apply one resource-create provision to IAM, idempotently.
    fn provision(&self, provision: &ResourceProvision) -> Result<(), RemoteError>;
}

/// Outcome of one [`OutboxRelay::drain`] pass.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct DrainReport {
    /// Records confirmed delivered to IAM this pass.
    pub delivered: usize,
    /// Records still pending after this pass (the failed record and everything
    /// queued behind it).
    pub remaining: usize,
    /// The transport error that halted the pass, if any.
    pub error: Option<RemoteError>,
}

impl DrainReport {
    /// Whether the pass drained the whole backlog with no error.
    pub fn is_complete(&self) -> bool {
        self.remaining == 0 && self.error.is_none()
    }
}

/// Drains a [`OutboxStore`] to IAM through a [`ProvisionTransport`].
///
/// A consumer runs [`OutboxRelay::drain`] on a schedule (or after each domain
/// write). The relay propagates pending records **in sequence order** and stops
/// at the first transport failure, leaving that record and everything behind it
/// pending so order is preserved and the next pass retries from exactly there.
/// Because propagation is idempotent, a record propagated but not yet marked
/// delivered (a crash in the gap) is simply re-sent next pass with no double
/// effect.
#[derive(Debug, Clone)]
pub struct OutboxRelay<S, T> {
    store: S,
    transport: T,
}

impl<S, T> OutboxRelay<S, T> {
    /// Build a relay over a store and transport.
    pub fn new(store: S, transport: T) -> Self {
        Self { store, transport }
    }

    /// Borrow the backing store.
    pub fn store(&self) -> &S {
        &self.store
    }

    /// Borrow the transport.
    pub fn transport(&self) -> &T {
        &self.transport
    }
}

impl<S: OutboxStore, T: ProvisionTransport> OutboxRelay<S, T> {
    /// Propagate every pending record to IAM, in order, until one fails.
    ///
    /// Returns a [`DrainReport`] of how many were delivered and how many remain.
    /// A transport error halts the pass (preserving order) and is reported, not
    /// returned as the call's error, so a partial drain is observable; a store
    /// error does propagate as `Err`, since a broken local store is not a
    /// recoverable per-record condition.
    pub fn drain(&self) -> Result<DrainReport, OutboxError> {
        let pending = self.store.pending()?;
        let total = pending.len();
        let mut delivered = 0;
        for record in pending {
            match self.transport.provision(&record.provision) {
                Ok(()) => {
                    self.store.mark_delivered(record.seq)?;
                    delivered += 1;
                }
                Err(error) => {
                    return Ok(DrainReport {
                        delivered,
                        remaining: total - delivered,
                        error: Some(error),
                    });
                }
            }
        }
        Ok(DrainReport {
            delivered,
            remaining: total - delivered,
            error: None,
        })
    }
}

/// In-memory [`OutboxStore`] for tests and the embedded/single-process arm.
///
/// Records are kept in append order behind a mutex; sequence numbers are a
/// 1-based counter that never reuses a value, so a delivered record's slot is
/// never recycled.
#[derive(Debug, Default)]
pub struct InMemoryOutbox {
    inner: std::sync::Mutex<Vec<OutboxRecord>>,
}

impl InMemoryOutbox {
    /// Create an empty in-memory outbox.
    pub fn new() -> Self {
        Self::default()
    }

    /// Snapshot every record, delivered and pending, in sequence order.
    pub fn records(&self) -> Vec<OutboxRecord> {
        self.inner.lock().expect("outbox mutex poisoned").clone()
    }
}

impl OutboxStore for InMemoryOutbox {
    fn enqueue(&self, provision: ResourceProvision) -> Result<u64, OutboxError> {
        let mut records = self.inner.lock().expect("outbox mutex poisoned");
        let seq = records.len() as u64 + 1;
        records.push(OutboxRecord {
            seq,
            provision,
            status: OutboxStatus::Pending,
        });
        Ok(seq)
    }

    fn pending(&self) -> Result<Vec<OutboxRecord>, OutboxError> {
        let records = self.inner.lock().expect("outbox mutex poisoned");
        Ok(records
            .iter()
            .filter(|record| record.status == OutboxStatus::Pending)
            .cloned()
            .collect())
    }

    fn mark_delivered(&self, seq: u64) -> Result<(), OutboxError> {
        let mut records = self.inner.lock().expect("outbox mutex poisoned");
        let record = records
            .iter_mut()
            .find(|record| record.seq == seq)
            .ok_or(OutboxError::NotFound(seq))?;
        record.status = OutboxStatus::Delivered;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use awaken_iam_contract::{
        AccountId, GrantEffect, GrantSnapshot, GrantSubjectRef, PrincipalRef, ResourceId,
        ResourceParentEdge, ResourceType, ScopeRef,
    };
    use std::cell::RefCell;

    fn provision(key: &str, epoch: u64) -> ResourceProvision {
        ResourceProvision {
            idempotency_key: key.into(),
            epoch,
            grants: vec![GrantSnapshot {
                id: format!("g_{key}"),
                subject: GrantSubjectRef::Principal {
                    principal: PrincipalRef::Account {
                        account_id: AccountId("ada".into()),
                    },
                },
                action_pattern: "issue.*".into(),
                scope: ScopeRef::Resource {
                    resource_type: ResourceType("issue".into()),
                    resource_id: ResourceId(key.into()),
                },
                effect: GrantEffect::Allow,
            }],
            scope_edges: vec![ResourceParentEdge {
                resource_type: ResourceType("issue".into()),
                resource_id: ResourceId(key.into()),
                parent: ScopeRef::Global,
            }],
        }
    }

    /// Transport that records every payload it receives, and can be switched to
    /// fail to model a transport outage.
    struct RecordingTransport {
        seen: RefCell<Vec<ResourceProvision>>,
        fail: std::cell::Cell<bool>,
    }

    impl RecordingTransport {
        fn new() -> Self {
            Self {
                seen: RefCell::new(Vec::new()),
                fail: std::cell::Cell::new(false),
            }
        }

        /// Distinct idempotency keys applied, in first-seen order.
        fn applied_keys(&self) -> Vec<String> {
            let mut keys = Vec::new();
            for provision in self.seen.borrow().iter() {
                if !keys.contains(&provision.idempotency_key) {
                    keys.push(provision.idempotency_key.clone());
                }
            }
            keys
        }
    }

    impl ProvisionTransport for RecordingTransport {
        fn provision(&self, provision: &ResourceProvision) -> Result<(), RemoteError> {
            if self.fail.get() {
                return Err(RemoteError("transport down".into()));
            }
            self.seen.borrow_mut().push(provision.clone());
            Ok(())
        }
    }

    #[test]
    fn drain_propagates_pending_records_then_marks_them_delivered() {
        let store = InMemoryOutbox::new();
        store.enqueue(provision("issue_1", 1)).unwrap();
        store.enqueue(provision("issue_2", 2)).unwrap();
        let relay = OutboxRelay::new(store, RecordingTransport::new());

        let report = relay.drain().unwrap();
        assert!(report.is_complete());
        assert_eq!(report.delivered, 2);
        assert_eq!(report.remaining, 0);
        assert_eq!(
            relay.transport().applied_keys(),
            vec!["issue_1".to_string(), "issue_2".to_string()]
        );
        // Every record is now delivered, so a second drain is a no-op — the
        // backlog is not re-sent.
        let second = relay.drain().unwrap();
        assert_eq!(second.delivered, 0);
        assert!(second.is_complete());
        assert_eq!(relay.transport().seen.borrow().len(), 2);
    }

    #[test]
    fn drain_fails_closed_leaving_records_pending_on_transport_outage() {
        let store = InMemoryOutbox::new();
        store.enqueue(provision("issue_1", 1)).unwrap();
        let transport = RecordingTransport::new();
        transport.fail.set(true);
        let relay = OutboxRelay::new(store, transport);

        let report = relay.drain().unwrap();
        // Nothing propagated: the grant never lands, so authorization keeps
        // denying — the window over-denies, never over-permits.
        assert_eq!(report.delivered, 0);
        assert_eq!(report.remaining, 1);
        assert!(report.error.is_some());
        assert!(!report.is_complete());
        assert_eq!(relay.store().pending().unwrap().len(), 1);

        // Once the transport recovers, the retained record drains cleanly.
        relay.transport().fail.set(false);
        let recovered = relay.drain().unwrap();
        assert!(recovered.is_complete());
        assert_eq!(recovered.delivered, 1);
    }

    #[test]
    fn drain_preserves_sequence_order_and_stops_at_the_first_failure() {
        let store = InMemoryOutbox::new();
        store.enqueue(provision("issue_1", 1)).unwrap();
        store.enqueue(provision("issue_2", 2)).unwrap();
        store.enqueue(provision("issue_3", 3)).unwrap();
        // Deliver only the first record, then simulate an outage mid-backlog.
        let relay = OutboxRelay::new(store, FailAfter::new(1));

        let report = relay.drain().unwrap();
        assert_eq!(report.delivered, 1);
        assert_eq!(report.remaining, 2);
        assert!(report.error.is_some());
        // The unfinished tail stays pending in order, so the next pass resumes
        // at issue_2 — a later record is never applied before an earlier one.
        let still_pending: Vec<u64> = relay
            .store()
            .pending()
            .unwrap()
            .into_iter()
            .map(|record| record.seq)
            .collect();
        assert_eq!(still_pending, vec![2, 3]);
    }

    #[test]
    fn redelivery_after_a_crash_is_idempotent() {
        // Model a crash in the gap between propagating a record and marking it
        // delivered: the record is still pending, so the next drain re-sends the
        // identical payload. The transport must see it as the same logical event.
        let store = InMemoryOutbox::new();
        let seq = store.enqueue(provision("issue_1", 1)).unwrap();
        let transport = RecordingTransport::new();
        // First "attempt": propagate but never mark delivered (the crash).
        transport.provision(&store.records()[0].provision).unwrap();
        assert_eq!(store.pending().unwrap().len(), 1);
        assert_eq!(seq, 1);

        // Recovery drain re-sends the same record and now marks it delivered.
        let relay = OutboxRelay::new(store, transport);
        let report = relay.drain().unwrap();
        assert!(report.is_complete());
        // The payload reached the transport twice, but it is one idempotent
        // event — a single distinct idempotency key, collapsed downstream.
        assert_eq!(relay.transport().seen.borrow().len(), 2);
        assert_eq!(
            relay.transport().applied_keys(),
            vec!["issue_1".to_string()]
        );
    }

    #[test]
    fn in_memory_store_assigns_ascending_sequence_numbers() {
        let store = InMemoryOutbox::new();
        assert_eq!(store.enqueue(provision("a", 1)).unwrap(), 1);
        assert_eq!(store.enqueue(provision("b", 2)).unwrap(), 2);
        store.mark_delivered(1).unwrap();
        // Marking is idempotent; re-marking a delivered record does not error.
        store.mark_delivered(1).unwrap();
        assert_eq!(store.pending().unwrap().len(), 1);
        assert_eq!(store.pending().unwrap()[0].seq, 2);
        assert_eq!(store.mark_delivered(99), Err(OutboxError::NotFound(99)));
    }

    /// Transport that succeeds for the first `n` calls, then fails — to drive
    /// the stop-at-first-failure ordering test.
    struct FailAfter {
        budget: std::cell::Cell<usize>,
    }

    impl FailAfter {
        fn new(n: usize) -> Self {
            Self {
                budget: std::cell::Cell::new(n),
            }
        }
    }

    impl ProvisionTransport for FailAfter {
        fn provision(&self, _provision: &ResourceProvision) -> Result<(), RemoteError> {
            let left = self.budget.get();
            if left == 0 {
                return Err(RemoteError("transport down".into()));
            }
            self.budget.set(left - 1);
            Ok(())
        }
    }
}
