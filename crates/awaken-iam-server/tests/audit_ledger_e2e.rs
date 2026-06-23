//! End-to-end coverage for the domain-event audit spine over the real
//! in-memory storage adapter.
//!
//! Proves the model's invariant from `docs/design/domain-model.md`: every domain
//! event feeds the append-only audit trail, and every event except a pure
//! authorization decision advances the snapshot version fence. The sink here is
//! the same [`InMemoryStore`] adapter that backs local mode and tests, so the
//! ledger is exercised against a production adapter rather than a fixture.

use awaken_iam_contract::{
    AccountId, ActionKey, AuthorizationDecision, AuthorizationRequest, ExternalIdentityId,
    PrincipalRef, ScopeRef, SessionId, Timestamp,
};
use awaken_iam_core::{
    ActionPattern, AuditLedger, DecisionTrace, DomainEvent, Effect, Grant, GrantId, GrantSubject,
    IamCore,
};
use awaken_iam_server::InMemoryStore;

fn ts(value: &str) -> Timestamp {
    Timestamp(value.into())
}

fn service(id: &str) -> PrincipalRef {
    PrincipalRef::Service {
        service_id: id.into(),
    }
}

#[test]
fn identity_and_authorization_events_feed_audit_and_fence_the_snapshot() {
    let mut ledger = AuditLedger::new(InMemoryStore::new());
    assert_eq!(ledger.version(), 1);

    // Identity events are audited and each advances the fence.
    ledger
        .emit(
            ts("2026-06-21T00:00:00Z"),
            DomainEvent::AccountRegistered {
                account: AccountId("ada".into()),
            },
        )
        .unwrap();
    ledger
        .emit(
            ts("2026-06-21T00:00:01Z"),
            DomainEvent::ExternalIdentityLinked {
                account: AccountId("ada".into()),
                identity: ExternalIdentityId("fake:ada".into()),
            },
        )
        .unwrap();
    ledger
        .emit(
            ts("2026-06-21T00:00:02Z"),
            DomainEvent::SessionEstablished {
                account: AccountId("ada".into()),
                session: SessionId("s1".into()),
            },
        )
        .unwrap();
    assert_eq!(ledger.version(), 4);

    // An authorization grant change is audited and fences the snapshot, so a
    // synced consumer re-pulls policy.
    ledger
        .emit(
            ts("2026-06-21T00:00:03Z"),
            DomainEvent::GrantIssued {
                grant: GrantId("g1".into()),
            },
        )
        .unwrap();
    assert_eq!(ledger.version(), 5);

    // A live authorization decision is recorded as a trace but never moves the
    // fence: deciding a request changes no state.
    let mut core = IamCore::new();
    core.policy_mut().add_grant(Grant {
        id: GrantId("g1".into()),
        subject: GrantSubject::Principal(service("svc")),
        action_pattern: ActionPattern("pack.publish".into()),
        scope: ScopeRef::Global,
        effect: Effect::Allow,
    });
    let request = AuthorizationRequest::direct(
        service("svc"),
        ActionKey("pack.publish".into()),
        ScopeRef::Global,
    );
    let trace = core.evaluate(&request);
    assert_eq!(trace.decision, AuthorizationDecision::Allow);

    let fence_before_decision = ledger.version();
    ledger
        .emit(
            ts("2026-06-21T00:00:04Z"),
            DomainEvent::AuthorizationDecided {
                trace: DecisionTrace::capture(&request, &trace),
            },
        )
        .unwrap();
    assert_eq!(ledger.version(), fence_before_decision);

    // Every event — identity, authorization, and the decision trace — is in the
    // append-only trail in order.
    let events = ledger.events().unwrap();
    let actions: Vec<&str> = events.iter().map(|e| e.action.as_str()).collect();
    assert_eq!(
        actions,
        vec![
            "account.registered",
            "external_identity.linked",
            "session.established",
            "grant.issued",
            "authorization.decided",
        ]
    );

    // The recorded decision trace carries the reasoned outcome for forensics.
    let decided = events.last().unwrap();
    assert_eq!(
        decided.actor,
        Some(service("svc")),
        "the decided request's caller is the attributable actor"
    );
    assert!(decided.detail.contains("decision=allow"));
    assert!(decided.detail.contains("reason=allowed_by_grant"));
    assert!(decided.detail.contains("action=pack.publish"));
}
