//! Local-mode snapshot cache and in-process authorization evaluation.
//!
//! High-throughput consumers — Oversight authorizes on every read, write, and
//! list — cannot afford a remote round trip per decision. Mechanism #12 (see
//! `docs/design/permission-mechanisms.md`) lets such a consumer fetch the
//! versioned [`PolicySnapshot`], rebuild the policy in-process with
//! [`PolicySet::from_snapshot`], and evaluate locally. Decisions computed this
//! way are byte-identical to a remote `POST /v1/authorize`, because the
//! evaluation code is shared — only the transport differs.
//!
//! [`SnapshotCache`] owns that lifecycle:
//!
//! - **Fetch + cache.** [`SnapshotCache::sync`] pulls the snapshot over the
//!   [`AuthzTransport`] seam and rebuilds the cached [`PolicySet`].
//! - **Re-sync on the version bump.** A monotonic `version` fences the policy.
//!   `sync` rebuilds only when the served version advances past the cached one
//!   (using [`AuthzTransport::fetch_snapshot_since`] to skip an unchanged
//!   payload), so a no-op sync is cheap.
//! - **Invalidate on the epoch fence.** When a consumer learns the policy epoch
//!   has rolled — a revocation or lease change that must drop cached authority
//!   at once — [`SnapshotCache::invalidate`] clears the cache so the next sync
//!   re-fetches and rebuilds unconditionally, even at an unchanged version.
//!
//! Evaluation **fails closed**: a cache that has never synced (or was just
//! invalidated) denies every request rather than widening access. This matches
//! the engine's default-deny posture and the remote client's fail-closed
//! contract.

use awaken_iam_contract::{
    ActionKey, AuthorizationDecision, AuthorizationOutcome, AuthorizationRequest, PrincipalRef,
    ScopeRef,
};
use awaken_iam_core::{AuthorizationTrace, PolicySet};

use crate::remote::{AuthzTransport, RemoteError};

/// Stable reason code reported when a decision is requested before any snapshot
/// has been synced into the cache (or after an [`SnapshotCache::invalidate`]).
///
/// It is distinct from the engine's `default_deny`: the policy was never
/// consulted at all, the cache simply had nothing to evaluate against and failed
/// closed.
pub const REASON_UNSYNCED: &str = "snapshot_unsynced";

/// Outcome of a [`SnapshotCache::sync`] call.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SyncStatus {
    /// The served policy advanced past the cached version (or this was the first
    /// sync); the cached [`PolicySet`] was rebuilt. Carries the new version.
    Updated {
        /// Version now cached.
        version: u64,
    },
    /// The served version matched the cache; nothing was rebuilt. Carries the
    /// unchanged version.
    Unchanged {
        /// Version that remains cached.
        version: u64,
    },
}

impl SyncStatus {
    /// The policy version the cache holds after the sync.
    pub fn version(&self) -> u64 {
        match self {
            SyncStatus::Updated { version } | SyncStatus::Unchanged { version } => *version,
        }
    }

    /// Whether the sync rebuilt the cached policy.
    pub fn is_updated(&self) -> bool {
        matches!(self, SyncStatus::Updated { .. })
    }
}

/// A synced policy snapshot rebuilt into an evaluable [`PolicySet`].
struct Cached {
    version: u64,
    policy: PolicySet,
}

/// Caches a synced [`PolicySnapshot`](awaken_iam_contract::PolicySnapshot) and
/// evaluates authorization in-process.
///
/// Generic over the [`AuthzTransport`] seam so a deployment injects its HTTP
/// client while tests inject a deterministic fake. [`sync`](Self::sync) takes
/// `&mut self` (it mutates the cache); the read-only evaluation methods take
/// `&self`, so a synced cache can be shared and queried on the hot path without
/// touching the transport.
pub struct SnapshotCache<T> {
    transport: T,
    cached: Option<Cached>,
}

impl<T> SnapshotCache<T> {
    /// Build an empty cache over the given transport. No snapshot is fetched
    /// until [`sync`](Self::sync) is called, so the cache fails closed until
    /// then.
    pub fn new(transport: T) -> Self {
        Self {
            transport,
            cached: None,
        }
    }

    /// Borrow the underlying transport.
    pub fn transport(&self) -> &T {
        &self.transport
    }

    /// The cached policy version, or `None` when nothing has been synced yet.
    pub fn version(&self) -> Option<u64> {
        self.cached.as_ref().map(|cached| cached.version)
    }

    /// Whether a snapshot has been synced and is available for evaluation.
    pub fn is_synced(&self) -> bool {
        self.cached.is_some()
    }

    /// Borrow the cached policy set, or `None` when nothing has been synced.
    pub fn policy(&self) -> Option<&PolicySet> {
        self.cached.as_ref().map(|cached| &cached.policy)
    }

    /// Drop the cached policy so the next [`sync`](Self::sync) re-fetches and
    /// rebuilds unconditionally — the epoch-fence invalidation.
    ///
    /// Use this when a consumer learns out of band that outstanding authority
    /// must be dropped now (a lease/epoch roll), rather than waiting for the
    /// next version bump to be observed. Until the following sync completes, the
    /// cache fails closed.
    pub fn invalidate(&mut self) {
        self.cached = None;
    }
}

impl<T: AuthzTransport> SnapshotCache<T> {
    /// Fetch the snapshot and rebuild the cached policy when the version has
    /// advanced.
    ///
    /// On the first sync (or after [`invalidate`](Self::invalidate)) the full
    /// snapshot is fetched and the policy is built. On a subsequent sync the
    /// cache asks the transport only for a snapshot newer than the cached
    /// version; an unchanged policy returns [`SyncStatus::Unchanged`] without
    /// rebuilding. A transport error is surfaced to the caller and leaves the
    /// existing cache intact.
    pub fn sync(&mut self) -> Result<SyncStatus, RemoteError> {
        match self.version() {
            Some(current) => match self.transport.fetch_snapshot_since(current)? {
                Some(snapshot) => {
                    let version = snapshot.version;
                    self.cached = Some(Cached {
                        version,
                        policy: PolicySet::from_snapshot(&snapshot),
                    });
                    Ok(SyncStatus::Updated { version })
                }
                None => Ok(SyncStatus::Unchanged { version: current }),
            },
            None => {
                let snapshot = self.transport.fetch_snapshot()?;
                let version = snapshot.version;
                self.cached = Some(Cached {
                    version,
                    policy: PolicySet::from_snapshot(&snapshot),
                });
                Ok(SyncStatus::Updated { version })
            }
        }
    }

    /// Evaluate `request` against the cached policy, returning the full decision
    /// trace, or `None` when no snapshot has been synced.
    ///
    /// Callers that want a fail-closed answer regardless of sync state should
    /// use [`authorize`](Self::authorize) or
    /// [`authorize_outcome`](Self::authorize_outcome) instead.
    pub fn evaluate(&self, request: &AuthorizationRequest) -> Option<AuthorizationTrace> {
        self.policy().map(|policy| policy.evaluate(request))
    }

    /// Resolve `request` into the reasoned [`AuthorizationOutcome`], failing
    /// closed to a deny ([`REASON_UNSYNCED`]) when the cache holds no snapshot.
    ///
    /// When synced, the outcome is byte-identical to a remote `authorize` for
    /// the same request and policy version.
    pub fn authorize_outcome(&self, request: &AuthorizationRequest) -> AuthorizationOutcome {
        match self.evaluate(request) {
            Some(trace) => trace.to_outcome(),
            None => AuthorizationOutcome {
                decision: AuthorizationDecision::Deny,
                reason: REASON_UNSYNCED.to_owned(),
                matched_grants: Vec::new(),
                matched_roles: Vec::new(),
                obligation: None,
            },
        }
    }

    /// Resolve `request` into a bare [`AuthorizationDecision`], failing closed to
    /// [`AuthorizationDecision::Deny`] when the cache holds no snapshot.
    pub fn authorize(&self, request: &AuthorizationRequest) -> AuthorizationDecision {
        self.authorize_outcome(request).decision
    }

    /// Filter `candidates` to the scopes on which `principal` may perform
    /// `action`, in input order — a single-pass list filter over the cached
    /// policy.
    ///
    /// An unsynced cache fails closed: it returns no visible scopes.
    pub fn visible(
        &self,
        principal: &PrincipalRef,
        action: &ActionKey,
        candidates: &[ScopeRef],
    ) -> Vec<ScopeRef> {
        match self.policy() {
            Some(policy) => policy.visible(principal, action, candidates),
            None => Vec::new(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use awaken_iam_contract::{
        AccountId, GrantEffect, GrantSnapshot, GrantSubjectRef, PolicySnapshot,
    };
    use std::cell::Cell;

    fn principal() -> PrincipalRef {
        PrincipalRef::Account {
            account_id: AccountId("acct_1".into()),
        }
    }

    fn request(action: &str) -> AuthorizationRequest {
        AuthorizationRequest::direct(principal(), ActionKey(action.into()), ScopeRef::Global)
    }

    /// A snapshot at `version` granting the account `pack.read` at global scope.
    fn snapshot(version: u64) -> PolicySnapshot {
        PolicySnapshot {
            version,
            grants: vec![GrantSnapshot {
                id: "g1".into(),
                subject: GrantSubjectRef::Principal {
                    principal: principal(),
                },
                action_pattern: "pack.read".into(),
                scope: ScopeRef::Global,
                effect: GrantEffect::Allow,
            }],
            ..PolicySnapshot::default()
        }
    }

    /// Transport serving a configurable snapshot, counting how many times the
    /// snapshot was actually built/fetched so tests can assert the version-fence
    /// skip and the epoch-fence rebuild.
    struct StubTransport {
        version: Cell<u64>,
        full_fetches: Cell<u32>,
        since_fetches: Cell<u32>,
        fail: Cell<bool>,
    }

    impl StubTransport {
        fn new(version: u64) -> Self {
            Self {
                version: Cell::new(version),
                full_fetches: Cell::new(0),
                since_fetches: Cell::new(0),
                fail: Cell::new(false),
            }
        }
    }

    impl AuthzTransport for StubTransport {
        fn authorize(
            &self,
            _request: &AuthorizationRequest,
        ) -> Result<AuthorizationOutcome, RemoteError> {
            unimplemented!("snapshot cache evaluates locally")
        }

        fn authorize_batch(
            &self,
            _request: &awaken_iam_contract::BatchAuthorizationRequest,
        ) -> Result<awaken_iam_contract::BatchAuthorizationResponse, RemoteError> {
            unimplemented!("snapshot cache evaluates locally")
        }

        fn check_entitlement(
            &self,
            _request: &awaken_iam_contract::EntitlementRequest,
        ) -> Result<awaken_iam_contract::EntitlementCheckResponse, RemoteError> {
            unimplemented!("snapshot cache is authorization-only")
        }

        fn fetch_snapshot(&self) -> Result<PolicySnapshot, RemoteError> {
            if self.fail.get() {
                return Err(RemoteError("boom".into()));
            }
            self.full_fetches.set(self.full_fetches.get() + 1);
            Ok(snapshot(self.version.get()))
        }

        fn fetch_snapshot_since(&self, since: u64) -> Result<Option<PolicySnapshot>, RemoteError> {
            if self.fail.get() {
                return Err(RemoteError("boom".into()));
            }
            self.since_fetches.set(self.since_fetches.get() + 1);
            let current = self.version.get();
            Ok((current > since).then(|| snapshot(current)))
        }

        fn register_resource_model(
            &self,
            _registration: &awaken_iam_contract::ResourceModelRegistration,
        ) -> Result<awaken_iam_contract::ResourceModelRegistered, RemoteError> {
            unimplemented!("snapshot cache is authorization-only")
        }

        fn fetch_signers(
            &self,
            _namespace_id: &awaken_iam_contract::NamespaceId,
        ) -> Result<awaken_iam_contract::SignerSetSnapshot, RemoteError> {
            unimplemented!("snapshot cache is authorization-only")
        }
    }

    #[test]
    fn unsynced_cache_fails_closed() {
        let cache = SnapshotCache::new(StubTransport::new(1));
        assert!(!cache.is_synced());
        assert_eq!(cache.version(), None);
        assert!(cache.evaluate(&request("pack.read")).is_none());

        let outcome = cache.authorize_outcome(&request("pack.read"));
        assert_eq!(outcome.decision, AuthorizationDecision::Deny);
        assert_eq!(outcome.reason, REASON_UNSYNCED);
        assert_eq!(
            cache.authorize(&request("pack.read")),
            AuthorizationDecision::Deny
        );
        assert!(
            cache
                .visible(
                    &principal(),
                    &ActionKey("pack.read".into()),
                    &[ScopeRef::Global]
                )
                .is_empty()
        );
    }

    #[test]
    fn first_sync_builds_policy_and_evaluates_locally() {
        let mut cache = SnapshotCache::new(StubTransport::new(3));
        let status = cache.sync().unwrap();
        assert_eq!(status, SyncStatus::Updated { version: 3 });
        assert!(status.is_updated());
        assert_eq!(cache.version(), Some(3));

        // The granted action allows; an ungranted one defaults to deny.
        assert_eq!(
            cache.authorize(&request("pack.read")),
            AuthorizationDecision::Allow
        );
        assert_eq!(
            cache.authorize(&request("pack.delete")),
            AuthorizationDecision::Deny
        );
    }

    #[test]
    fn local_outcome_is_byte_identical_to_server_evaluation() {
        let mut cache = SnapshotCache::new(StubTransport::new(5));
        cache.sync().unwrap();

        // Rebuild the same policy independently (as the server would) and
        // confirm the reasoned outcome matches field for field.
        let server_policy = PolicySet::from_snapshot(&snapshot(5));
        for action in ["pack.read", "pack.delete"] {
            let local = cache.authorize_outcome(&request(action));
            let server = server_policy.evaluate(&request(action)).to_outcome();
            assert_eq!(local, server, "mismatch for {action}");
        }
    }

    #[test]
    fn resync_skips_rebuild_when_version_is_unchanged() {
        let transport = StubTransport::new(2);
        let mut cache = SnapshotCache::new(transport);
        assert!(cache.sync().unwrap().is_updated());
        assert_eq!(cache.transport().full_fetches.get(), 1);

        // A second sync at the same version asks `since` and rebuilds nothing.
        let status = cache.sync().unwrap();
        assert_eq!(status, SyncStatus::Unchanged { version: 2 });
        assert_eq!(cache.transport().since_fetches.get(), 1);
        assert_eq!(cache.version(), Some(2));
    }

    #[test]
    fn resync_rebuilds_when_version_advances() {
        let mut cache = SnapshotCache::new(StubTransport::new(1));
        cache.sync().unwrap();

        // The policy advances on the server; the next sync picks it up.
        cache.transport().version.set(4);
        let status = cache.sync().unwrap();
        assert_eq!(status, SyncStatus::Updated { version: 4 });
        assert_eq!(cache.version(), Some(4));
    }

    #[test]
    fn invalidate_forces_unconditional_resync_at_same_version() {
        let mut cache = SnapshotCache::new(StubTransport::new(7));
        cache.sync().unwrap();
        assert_eq!(cache.transport().full_fetches.get(), 1);

        // Epoch fence: drop the cache. It fails closed until the next sync.
        cache.invalidate();
        assert!(!cache.is_synced());
        assert_eq!(
            cache.authorize(&request("pack.read")),
            AuthorizationDecision::Deny
        );

        // The next sync re-fetches the FULL snapshot even though the version did
        // not change, and evaluation is live again.
        let status = cache.sync().unwrap();
        assert_eq!(status, SyncStatus::Updated { version: 7 });
        assert_eq!(cache.transport().full_fetches.get(), 2);
        assert_eq!(
            cache.authorize(&request("pack.read")),
            AuthorizationDecision::Allow
        );
    }

    #[test]
    fn transport_error_leaves_existing_cache_intact() {
        let mut cache = SnapshotCache::new(StubTransport::new(2));
        cache.sync().unwrap();

        // A transient transport failure surfaces but does not poison the cache:
        // the previously synced policy keeps answering.
        cache.transport().fail.set(true);
        assert!(cache.sync().is_err());
        assert_eq!(cache.version(), Some(2));
        assert_eq!(
            cache.authorize(&request("pack.read")),
            AuthorizationDecision::Allow
        );
    }

    #[test]
    fn first_sync_error_leaves_cache_unsynced() {
        let transport = StubTransport::new(2);
        transport.fail.set(true);
        let mut cache = SnapshotCache::new(transport);
        assert_eq!(cache.sync(), Err(RemoteError("boom".into())));
        assert!(!cache.is_synced());
        assert_eq!(
            cache.authorize(&request("pack.read")),
            AuthorizationDecision::Deny
        );
    }
}
