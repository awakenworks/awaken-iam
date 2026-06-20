//! Capability-migration shadow / dual-run harness.
//!
//! Implements the strangler-fig safety net described in the migration strategy:
//! before a consumer cuts a capability over to IAM, the enforcement point runs
//! both the *incumbent* decision and the *IAM* decision for every request,
//! compares them, and logs divergence. The incumbent stays authoritative the
//! whole time the harness is in use — the IAM side is shadowed, never enforced —
//! so wrapping a call site changes no observable behavior and the flag flips
//! back instantly. Cutover happens only once divergence has been burned down to
//! zero over a sustained window, and a divergence spike can auto-hold the flag.
//!
//! Both decisions come from a [`DecisionSource`]. The incumbent is the
//! consumer's existing engine (adapted through a closure or a newtype) and the
//! candidate is IAM ([`crate::IamCore`] implements [`DecisionSource`] directly).
//! Evaluation is pure and side-effect free on both sides, so the harness can run
//! them in either order; the MVP runs them sequentially in-process and the
//! result is identical to a parallel dispatch.

use std::collections::VecDeque;

use awaken_iam_contract::{AuthorizationDecision, AuthorizationRequest};

/// A source of an authorization decision the shadow harness can evaluate.
///
/// Implemented for any `Fn(&AuthorizationRequest) -> AuthorizationDecision`, so
/// a consumer can wrap its existing engine without defining a newtype, and for
/// [`crate::IamCore`] so the IAM side plugs in directly.
pub trait DecisionSource {
    /// Evaluate `request` and return its three-valued decision.
    fn decide(&self, request: &AuthorizationRequest) -> AuthorizationDecision;
}

impl<F> DecisionSource for F
where
    F: Fn(&AuthorizationRequest) -> AuthorizationDecision,
{
    fn decide(&self, request: &AuthorizationRequest) -> AuthorizationDecision {
        self(request)
    }
}

impl DecisionSource for crate::IamCore {
    fn decide(&self, request: &AuthorizationRequest) -> AuthorizationDecision {
        self.authorize(request)
    }
}

/// Outcome of a single dual run.
///
/// [`ShadowOutcome::authoritative`] is always the incumbent decision — the value
/// the enforcement point must act on while shadowing — and
/// [`ShadowOutcome::candidate`] is the shadowed IAM decision. The harness never
/// substitutes the candidate for the incumbent.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ShadowOutcome {
    /// The decision the caller enforces (the incumbent's).
    pub authoritative: AuthorizationDecision,
    /// The shadowed IAM decision, compared but not enforced.
    pub candidate: AuthorizationDecision,
    /// Whether the two sides disagreed.
    pub diverged: bool,
}

/// A recorded disagreement between the incumbent and the IAM candidate.
///
/// Carries the originating request alongside both decisions so the divergence
/// can be reproduced and reconciled during burn-down.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Divergence {
    /// The request both sides evaluated.
    pub request: AuthorizationRequest,
    /// The incumbent (authoritative) decision.
    pub incumbent: AuthorizationDecision,
    /// The IAM (candidate) decision.
    pub candidate: AuthorizationDecision,
}

/// Aggregate view of what a [`ShadowAuthorizer`] has observed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ShadowReport {
    /// Total dual runs observed.
    pub observations: u64,
    /// Runs where both sides agreed.
    pub agreements: u64,
    /// Runs where the sides diverged.
    pub divergences: u64,
}

impl ShadowReport {
    /// Fraction of observations that diverged, in `0.0..=1.0`. With no
    /// observations the rate is `0.0`.
    pub fn divergence_rate(&self) -> f64 {
        if self.observations == 0 {
            return 0.0;
        }
        self.divergences as f64 / self.observations as f64
    }

    /// Whether the candidate has reached measured parity: zero divergence over a
    /// window of at least `min_observations` runs.
    ///
    /// The minimum guards against declaring parity on a handful (or zero) of
    /// requests — parity must be *measured*, not merely unobserved.
    pub fn at_parity(&self, min_observations: u64) -> bool {
        self.divergences == 0 && self.observations >= min_observations
    }

    /// Whether the divergence rate is within `max_rate`, used to decide if a
    /// shadow flag should stay open or auto-hold on a divergence spike.
    pub fn within_threshold(&self, max_rate: f64) -> bool {
        self.divergence_rate() <= max_rate
    }
}

/// Default number of divergence samples retained for inspection.
const DEFAULT_SAMPLE_CAPACITY: usize = 256;

/// Runs an incumbent decision and the IAM decision in parallel, compares them,
/// and logs divergence to drive a safe strangler-fig cutover.
///
/// Counts are exact and retained for the harness's lifetime; the diverging
/// *samples* are kept in a bounded ring (see
/// [`ShadowAuthorizer::with_sample_capacity`]) so a long-running enforcement
/// point cannot grow unbounded while still surfacing recent disagreements for
/// reconciliation.
#[derive(Debug)]
pub struct ShadowAuthorizer<I, C> {
    incumbent: I,
    candidate: C,
    observations: u64,
    agreements: u64,
    divergence_count: u64,
    samples: VecDeque<Divergence>,
    sample_capacity: usize,
}

impl<I, C> ShadowAuthorizer<I, C>
where
    I: DecisionSource,
    C: DecisionSource,
{
    /// Wrap an `incumbent` and an IAM `candidate` for dual running.
    pub fn new(incumbent: I, candidate: C) -> Self {
        Self::with_sample_capacity(incumbent, candidate, DEFAULT_SAMPLE_CAPACITY)
    }

    /// Wrap an `incumbent` and a `candidate`, retaining up to `sample_capacity`
    /// of the most recent divergence samples (a capacity of zero keeps exact
    /// counts but no samples).
    pub fn with_sample_capacity(incumbent: I, candidate: C, sample_capacity: usize) -> Self {
        Self {
            incumbent,
            candidate,
            observations: 0,
            agreements: 0,
            divergence_count: 0,
            samples: VecDeque::new(),
            sample_capacity,
        }
    }

    /// Evaluate `request` on both sides, record the comparison, and return the
    /// outcome. The returned [`ShadowOutcome::authoritative`] decision is the
    /// incumbent's and is what the caller must enforce.
    pub fn run(&mut self, request: &AuthorizationRequest) -> ShadowOutcome {
        let incumbent = self.incumbent.decide(request);
        let candidate = self.candidate.decide(request);
        let diverged = incumbent != candidate;

        self.observations += 1;
        if diverged {
            self.divergence_count += 1;
            self.record_sample(Divergence {
                request: request.clone(),
                incumbent,
                candidate,
            });
        } else {
            self.agreements += 1;
        }

        ShadowOutcome {
            authoritative: incumbent,
            candidate,
            diverged,
        }
    }

    fn record_sample(&mut self, divergence: Divergence) {
        if self.sample_capacity == 0 {
            return;
        }
        if self.samples.len() == self.sample_capacity {
            self.samples.pop_front();
        }
        self.samples.push_back(divergence);
    }

    /// Snapshot the aggregate counters.
    pub fn report(&self) -> ShadowReport {
        ShadowReport {
            observations: self.observations,
            agreements: self.agreements,
            divergences: self.divergence_count,
        }
    }

    /// The retained divergence samples, oldest first.
    pub fn divergences(&self) -> impl Iterator<Item = &Divergence> {
        self.samples.iter()
    }

    /// Drop the retained samples while preserving the exact counters, so a
    /// reconciliation pass can clear what it has triaged without resetting the
    /// burn-down history.
    pub fn clear_samples(&mut self) {
        self.samples.clear();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{ActionPattern, Effect, Grant, GrantId, GrantSubject, IamCore};
    use awaken_iam_contract::{AccountId, ActionKey, PrincipalRef, ScopeRef};

    fn request(action: &str) -> AuthorizationRequest {
        AuthorizationRequest::direct(
            PrincipalRef::Account {
                account_id: AccountId("ada".into()),
            },
            ActionKey(action.into()),
            ScopeRef::Global,
        )
    }

    fn always(
        decision: AuthorizationDecision,
    ) -> impl Fn(&AuthorizationRequest) -> AuthorizationDecision {
        move |_request| decision
    }

    #[test]
    fn agreement_is_recorded_and_does_not_diverge() {
        let mut shadow = ShadowAuthorizer::new(
            always(AuthorizationDecision::Allow),
            always(AuthorizationDecision::Allow),
        );

        let outcome = shadow.run(&request("pack.read"));

        assert_eq!(outcome.authoritative, AuthorizationDecision::Allow);
        assert_eq!(outcome.candidate, AuthorizationDecision::Allow);
        assert!(!outcome.diverged);

        let report = shadow.report();
        assert_eq!(report.observations, 1);
        assert_eq!(report.agreements, 1);
        assert_eq!(report.divergences, 0);
        assert_eq!(report.divergence_rate(), 0.0);
        assert_eq!(shadow.divergences().count(), 0);
    }

    #[test]
    fn divergence_enforces_incumbent_and_logs_the_candidate() {
        // Incumbent allows; IAM would deny. The caller must keep enforcing the
        // incumbent decision, but the disagreement is captured for burn-down.
        let mut shadow = ShadowAuthorizer::new(
            always(AuthorizationDecision::Allow),
            always(AuthorizationDecision::Deny),
        );

        let outcome = shadow.run(&request("pack.publish"));

        assert_eq!(outcome.authoritative, AuthorizationDecision::Allow);
        assert_eq!(outcome.candidate, AuthorizationDecision::Deny);
        assert!(outcome.diverged);

        let report = shadow.report();
        assert_eq!(report.observations, 1);
        assert_eq!(report.agreements, 0);
        assert_eq!(report.divergences, 1);

        let logged: Vec<&Divergence> = shadow.divergences().collect();
        assert_eq!(logged.len(), 1);
        assert_eq!(logged[0].incumbent, AuthorizationDecision::Allow);
        assert_eq!(logged[0].candidate, AuthorizationDecision::Deny);
        assert_eq!(logged[0].request, request("pack.publish"));
    }

    #[test]
    fn iam_core_plugs_in_as_the_candidate_source() {
        // A real IAM evaluator drives the candidate side directly.
        let mut iam = IamCore::new();
        iam.policy_mut().add_grant(Grant {
            id: GrantId("g1".into()),
            subject: GrantSubject::Principal(PrincipalRef::Account {
                account_id: AccountId("ada".into()),
            }),
            action_pattern: ActionPattern("pack.read".into()),
            scope: ScopeRef::Global,
            effect: Effect::Allow,
        });

        // Incumbent allows everything; IAM only allows the granted action.
        let mut shadow = ShadowAuthorizer::new(always(AuthorizationDecision::Allow), iam);

        let agree = shadow.run(&request("pack.read"));
        assert!(!agree.diverged);

        let diverge = shadow.run(&request("pack.publish"));
        assert!(diverge.diverged);
        assert_eq!(diverge.authoritative, AuthorizationDecision::Allow);
        assert_eq!(diverge.candidate, AuthorizationDecision::Deny);

        let report = shadow.report();
        assert_eq!(report.observations, 2);
        assert_eq!(report.divergences, 1);
        assert_eq!(report.divergence_rate(), 0.5);
    }

    #[test]
    fn parity_requires_a_measured_window_of_agreement() {
        let mut shadow = ShadowAuthorizer::new(
            always(AuthorizationDecision::Allow),
            always(AuthorizationDecision::Allow),
        );

        // A positive minimum is never met before any request is observed, so
        // parity cannot be declared on an empty window.
        assert!(!shadow.report().at_parity(1));

        for _ in 0..3 {
            shadow.run(&request("pack.read"));
        }
        let report = shadow.report();
        assert!(report.at_parity(3));
        assert!(!report.at_parity(4));
    }

    #[test]
    fn a_single_divergence_breaks_parity_and_trips_the_threshold() {
        let mut shadow = ShadowAuthorizer::new(
            always(AuthorizationDecision::Allow),
            // Deny only `pack.publish`; allow the rest.
            |request: &AuthorizationRequest| {
                if request.action == ActionKey("pack.publish".into()) {
                    AuthorizationDecision::Deny
                } else {
                    AuthorizationDecision::Allow
                }
            },
        );

        for _ in 0..9 {
            shadow.run(&request("pack.read"));
        }
        shadow.run(&request("pack.publish"));

        let report = shadow.report();
        assert_eq!(report.observations, 10);
        assert_eq!(report.divergences, 1);
        assert!((report.divergence_rate() - 0.1).abs() < f64::EPSILON);
        assert!(!report.at_parity(10));
        // A 10% spike auto-holds a flag gated at 5% but not one gated at 20%.
        assert!(!report.within_threshold(0.05));
        assert!(report.within_threshold(0.20));
    }

    #[test]
    fn divergence_samples_are_bounded_while_counts_stay_exact() {
        let mut shadow = ShadowAuthorizer::with_sample_capacity(
            always(AuthorizationDecision::Allow),
            always(AuthorizationDecision::Deny),
            2,
        );

        for index in 0..5 {
            shadow.run(&request(&format!("pack.action_{index}")));
        }

        // Every divergence is counted, but only the last two are retained.
        let report = shadow.report();
        assert_eq!(report.observations, 5);
        assert_eq!(report.divergences, 5);

        let retained: Vec<&Divergence> = shadow.divergences().collect();
        assert_eq!(retained.len(), 2);
        assert_eq!(
            retained[0].request.action,
            ActionKey("pack.action_3".into())
        );
        assert_eq!(
            retained[1].request.action,
            ActionKey("pack.action_4".into())
        );

        // Clearing samples keeps the burn-down counters intact.
        shadow.clear_samples();
        assert_eq!(shadow.divergences().count(), 0);
        assert_eq!(shadow.report().divergences, 5);
    }

    #[test]
    fn zero_sample_capacity_keeps_counts_without_retaining_samples() {
        let mut shadow = ShadowAuthorizer::with_sample_capacity(
            always(AuthorizationDecision::Deny),
            always(AuthorizationDecision::Allow),
            0,
        );

        shadow.run(&request("pack.read"));

        assert_eq!(shadow.report().divergences, 1);
        assert_eq!(shadow.divergences().count(), 0);
    }
}
