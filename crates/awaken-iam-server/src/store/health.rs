//! Liveness and readiness probes for the stateless node.
//!
//! HA routes traffic only to healthy nodes (see
//! [high availability](../../../../docs/design/high-availability.md), "Health and
//! rollout"). The two probes answer different questions:
//!
//! - `/healthz` — **liveness**: the process is up. It never consults the store,
//!   so a liveness check stays green during a transient store outage and the
//!   orchestrator does not needlessly restart an otherwise-fine process.
//! - `/readyz` — **readiness**: the store is reachable *and* this node's own
//!   migrations are applied. The balancer and orchestrator route only ready
//!   nodes; a node failing readiness is drained, and its in-flight requests fail
//!   closed rather than degrade open.
//!
//! Both are computed at the server edge over the migrated [`IamStore`]; the
//! probe results are framework-agnostic so a deployment maps them onto its router
//! (a `200`/`503` for `/readyz`, a `200` for `/healthz`).

/// Liveness: the process is up and serving.
///
/// Liveness is deliberately store-independent — it is the orchestrator's signal
/// to *restart* a wedged process, not to drain a node that is merely waiting on
/// the store. Returned by `/healthz` and always [`Liveness::Up`] for a running
/// process.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Liveness {
    /// The process is up.
    Up,
}

impl Liveness {
    /// Whether the process should be considered live (always true here).
    pub const fn is_live(self) -> bool {
        matches!(self, Liveness::Up)
    }
}

/// Readiness: whether this node may receive traffic.
///
/// A node is ready only when the store is reachable and its migrations are
/// applied; otherwise it carries a human-readable `detail` for the operator and
/// is removed from the load balancer. Readiness fails closed — any uncertainty
/// (store unreachable, ledger incomplete) reports *not ready*, never a hopeful
/// ready.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Readiness {
    ready: bool,
    detail: Option<String>,
}

impl Readiness {
    /// The node is ready to receive traffic.
    pub fn ready() -> Self {
        Self {
            ready: true,
            detail: None,
        }
    }

    /// The node is not ready; `detail` explains why for the operator.
    pub fn not_ready(detail: impl Into<String>) -> Self {
        Self {
            ready: false,
            detail: Some(detail.into()),
        }
    }

    /// Whether the node may receive traffic.
    pub fn is_ready(&self) -> bool {
        self.ready
    }

    /// The reason the node is not ready, if any.
    pub fn detail(&self) -> Option<&str> {
        self.detail.as_deref()
    }
}
