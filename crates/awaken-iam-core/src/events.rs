//! Domain events: the append-only spine that feeds the audit trail and the
//! snapshot version fence.
//!
//! Every state change in the model emits a [`DomainEvent`]. An event does two
//! things, captured here in one place so the two never drift apart:
//!
//! 1. **It feeds the audit trail.** Each event renders to the append-only
//!    [`AuditEvent`](crate::AuditEvent) the [`AuditSink`] port persists, so an
//!    identity or authorization change leaves a durable, attributable record.
//! 2. **It moves the snapshot version fence.** A state change that alters the
//!    authorization policy bumps the monotonic `version` that invalidates
//!    consumer caches (see [`PolicySnapshot`](awaken_iam_contract::PolicySnapshot)
//!    and `docs/design/domain-model.md`). A pure
//!    [`DomainEvent::AuthorizationDecided`] decision trace changes no state, so
//!    it is recorded for audit but never moves the fence.
//!
//! The [`AuditLedger`] binds those two responsibilities to a concrete sink: a
//! single `emit` records the event and, when the event fences, advances the
//! version. Keeping the rule in one type is what lets a consumer trust that a
//! version it has already synced reflects every policy-affecting event recorded
//! before it.

use awaken_iam_contract::{
    AccountId, ActionKey, AuthorizationDecision, AuthorizationRequest, ExternalIdentityId,
    NamespaceId, PrincipalRef, ScopeRef, SessionId, Timestamp,
};

use crate::authorization::{AuthorizationTrace, DecisionReason};
use crate::ports::{AuditEvent, AuditSink, RepoResult};
use crate::{GrantId, PlanId, RoleId};

/// The reasoned record of one authorization evaluation.
///
/// This is the decision trace the audit trail keeps for an
/// [`DomainEvent::AuthorizationDecided`] event: who asked, what they asked for,
/// the engine's three-valued answer, the stable reason code, and the ids of the
/// grants and roles that produced the deciding effect. It mirrors the
/// [`AuthorizationTrace`] returned by the engine but is owned (carries the
/// request subject) and is the audit-facing shape.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DecisionTrace {
    /// Acting principal whose request was evaluated (chain head).
    pub principal: PrincipalRef,
    /// Action that was requested.
    pub action: ActionKey,
    /// Scope the action targeted.
    pub scope: ScopeRef,
    /// The three-valued decision the engine reached.
    pub decision: AuthorizationDecision,
    /// Stable reason code explaining the decision.
    pub reason: DecisionReason,
    /// Ids of the grants that produced the deciding effect, in policy order.
    pub matched_grants: Vec<GrantId>,
    /// Ids of the roles whose grants contributed to the deciding effect.
    pub matched_roles: Vec<RoleId>,
}

impl DecisionTrace {
    /// Capture a decision trace from the engine's [`AuthorizationTrace`] and the
    /// request it answered.
    pub fn capture(request: &AuthorizationRequest, trace: &AuthorizationTrace) -> Self {
        Self {
            principal: request.principal.clone(),
            action: request.action.clone(),
            scope: request.scope.clone(),
            decision: trace.decision,
            reason: trace.reason,
            matched_grants: trace.matched_grants.clone(),
            matched_roles: trace.matched_roles.clone(),
        }
    }
}

/// An identity, authorization, or decision event the model emits on a state
/// change.
///
/// The variants are the ubiquitous-language events from
/// `docs/design/domain-model.md`. Every variant feeds the audit trail; every
/// variant except [`DomainEvent::AuthorizationDecided`] also fences the snapshot
/// version (see [`DomainEvent::fences_snapshot`]).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DomainEvent {
    /// A new account was registered.
    AccountRegistered {
        /// The registered account.
        account: AccountId,
    },
    /// A provider subject was linked to an account.
    ExternalIdentityLinked {
        /// Account the identity was linked to.
        account: AccountId,
        /// Linked external identity.
        identity: ExternalIdentityId,
    },
    /// A login session was established.
    SessionEstablished {
        /// Account the session authenticates.
        account: AccountId,
        /// Established session.
        session: SessionId,
    },
    /// A login session was revoked.
    SessionRevoked {
        /// Revoked session.
        session: SessionId,
    },
    /// An API token was issued to a principal.
    ApiTokenIssued {
        /// Principal the token authenticates as.
        principal: PrincipalRef,
        /// Stable id of the issued token.
        token_id: String,
    },
    /// An API token was revoked.
    ApiTokenRevoked {
        /// Stable id of the revoked token.
        token_id: String,
    },
    /// A role was defined.
    RoleDefined {
        /// Defined role.
        role: RoleId,
    },
    /// An authorization grant was issued.
    GrantIssued {
        /// Issued grant.
        grant: GrantId,
    },
    /// An authorization grant was revoked.
    GrantRevoked {
        /// Revoked grant.
        grant: GrantId,
    },
    /// A principal was granted a role at a scope.
    MembershipGranted {
        /// Member principal.
        principal: PrincipalRef,
        /// Role granted.
        role: RoleId,
        /// Scope the role applies at.
        scope: ScopeRef,
    },
    /// A principal's role membership at a scope was revoked.
    MembershipRevoked {
        /// Member principal.
        principal: PrincipalRef,
        /// Role revoked.
        role: RoleId,
        /// Scope the role applied at.
        scope: ScopeRef,
    },
    /// A signer was registered for a namespace.
    SignerRegistered {
        /// Namespace the signer was registered for.
        namespace: NamespaceId,
        /// Stable id of the signer (public key fingerprint).
        signer: String,
    },
    /// A namespace signer was revoked.
    SignerRevoked {
        /// Namespace the signer was revoked from.
        namespace: NamespaceId,
        /// Stable id of the signer.
        signer: String,
    },
    /// A principal's subscription (plan assignment) changed.
    SubscriptionChanged {
        /// Subscribing principal.
        principal: PrincipalRef,
        /// Plan now in effect.
        plan: PlanId,
    },
    /// An authorization request was decided. Audit only: it records a decision
    /// trace but changes no state, so it never fences the snapshot version.
    AuthorizationDecided {
        /// The reasoned decision trace.
        trace: DecisionTrace,
    },
}

impl DomainEvent {
    /// Stable snake_case action key recorded with the audit event, suitable for
    /// log filtering and UIs.
    pub fn action(&self) -> &'static str {
        match self {
            DomainEvent::AccountRegistered { .. } => "account.registered",
            DomainEvent::ExternalIdentityLinked { .. } => "external_identity.linked",
            DomainEvent::SessionEstablished { .. } => "session.established",
            DomainEvent::SessionRevoked { .. } => "session.revoked",
            DomainEvent::ApiTokenIssued { .. } => "api_token.issued",
            DomainEvent::ApiTokenRevoked { .. } => "api_token.revoked",
            DomainEvent::RoleDefined { .. } => "role.defined",
            DomainEvent::GrantIssued { .. } => "grant.issued",
            DomainEvent::GrantRevoked { .. } => "grant.revoked",
            DomainEvent::MembershipGranted { .. } => "membership.granted",
            DomainEvent::MembershipRevoked { .. } => "membership.revoked",
            DomainEvent::SignerRegistered { .. } => "signer.registered",
            DomainEvent::SignerRevoked { .. } => "signer.revoked",
            DomainEvent::SubscriptionChanged { .. } => "subscription.changed",
            DomainEvent::AuthorizationDecided { .. } => "authorization.decided",
        }
    }

    /// Whether this event advances the snapshot version fence.
    ///
    /// Every state-changing event fences so consumer caches re-sync; the pure
    /// [`DomainEvent::AuthorizationDecided`] decision trace changes no state and
    /// is audit only.
    pub fn fences_snapshot(&self) -> bool {
        !matches!(self, DomainEvent::AuthorizationDecided { .. })
    }

    /// The principal the event intrinsically concerns, when one is attributable
    /// from the event alone (the account, token principal, member, or the caller
    /// whose request was decided). Administrative actor attribution, when needed,
    /// is layered on by the application service.
    pub fn actor(&self) -> Option<PrincipalRef> {
        match self {
            DomainEvent::AccountRegistered { account }
            | DomainEvent::ExternalIdentityLinked { account, .. }
            | DomainEvent::SessionEstablished { account, .. } => Some(PrincipalRef::Account {
                account_id: account.clone(),
            }),
            DomainEvent::ApiTokenIssued { principal, .. }
            | DomainEvent::MembershipGranted { principal, .. }
            | DomainEvent::MembershipRevoked { principal, .. }
            | DomainEvent::SubscriptionChanged { principal, .. } => Some(principal.clone()),
            DomainEvent::AuthorizationDecided { trace } => Some(trace.principal.clone()),
            DomainEvent::SessionRevoked { .. }
            | DomainEvent::ApiTokenRevoked { .. }
            | DomainEvent::RoleDefined { .. }
            | DomainEvent::GrantIssued { .. }
            | DomainEvent::GrantRevoked { .. }
            | DomainEvent::SignerRegistered { .. }
            | DomainEvent::SignerRevoked { .. } => None,
        }
    }

    /// Human-readable detail naming the subjects the event touched.
    pub fn detail(&self) -> String {
        match self {
            DomainEvent::AccountRegistered { account } => format!("account={}", account.0),
            DomainEvent::ExternalIdentityLinked { account, identity } => {
                format!("account={} identity={}", account.0, identity.0)
            }
            DomainEvent::SessionEstablished { account, session } => {
                format!("account={} session={}", account.0, session.0)
            }
            DomainEvent::SessionRevoked { session } => format!("session={}", session.0),
            DomainEvent::ApiTokenIssued {
                principal,
                token_id,
            } => format!(
                "principal={} token={}",
                render_principal(principal),
                token_id
            ),
            DomainEvent::ApiTokenRevoked { token_id } => format!("token={token_id}"),
            DomainEvent::RoleDefined { role } => format!("role={}", role.0),
            DomainEvent::GrantIssued { grant } => format!("grant={}", grant.0),
            DomainEvent::GrantRevoked { grant } => format!("grant={}", grant.0),
            DomainEvent::MembershipGranted {
                principal,
                role,
                scope,
            }
            | DomainEvent::MembershipRevoked {
                principal,
                role,
                scope,
            } => format!(
                "principal={} role={} scope={}",
                render_principal(principal),
                role.0,
                render_scope(scope)
            ),
            DomainEvent::SignerRegistered { namespace, signer }
            | DomainEvent::SignerRevoked { namespace, signer } => {
                format!("namespace={} signer={}", namespace.0, signer)
            }
            DomainEvent::SubscriptionChanged { principal, plan } => {
                format!("principal={} plan={}", render_principal(principal), plan.0)
            }
            DomainEvent::AuthorizationDecided { trace } => format!(
                "principal={} action={} scope={} decision={} reason={} grants=[{}] roles=[{}]",
                render_principal(&trace.principal),
                trace.action.0,
                render_scope(&trace.scope),
                render_decision(trace.decision),
                trace.reason.code(),
                join_ids(trace.matched_grants.iter().map(|id| id.0.as_str())),
                join_ids(trace.matched_roles.iter().map(|id| id.0.as_str())),
            ),
        }
    }

    /// Render the event into the append-only [`AuditEvent`] the [`AuditSink`]
    /// persists, stamped at `at`.
    pub fn to_audit(&self, at: Timestamp) -> AuditEvent {
        AuditEvent {
            at,
            actor: self.actor(),
            action: self.action().to_owned(),
            detail: self.detail(),
        }
    }
}

/// Binds the domain-event spine to a concrete [`AuditSink`]: a single
/// [`AuditLedger::emit`] records the event and advances the snapshot version
/// fence when the event fences.
///
/// The ledger owns the monotonic `version` so the two responsibilities of a
/// domain event — being audited and moving the fence — are applied together and
/// never drift. A consumer that has synced `version` can trust it reflects every
/// policy-affecting event recorded up to that point.
#[derive(Debug)]
pub struct AuditLedger<S: AuditSink> {
    sink: S,
    version: u64,
}

impl<S: AuditSink> AuditLedger<S> {
    /// Open a ledger over `sink`, starting the snapshot version fence at 1.
    pub fn new(sink: S) -> Self {
        Self { sink, version: 1 }
    }

    /// Open a ledger over `sink` resuming from an existing fence `version`.
    pub fn resume(sink: S, version: u64) -> Self {
        Self { sink, version }
    }

    /// Record `event` at `at` and advance the fence when the event fences,
    /// returning the version in effect afterward.
    pub fn emit(&mut self, at: Timestamp, event: DomainEvent) -> RepoResult<u64> {
        self.sink.record(event.to_audit(at))?;
        if event.fences_snapshot() {
            self.version += 1;
        }
        Ok(self.version)
    }

    /// The current snapshot version fence.
    pub fn version(&self) -> u64 {
        self.version
    }

    /// The recorded audit events in append order.
    pub fn events(&self) -> RepoResult<Vec<AuditEvent>> {
        self.sink.events()
    }

    /// Borrow the underlying sink.
    pub fn sink(&self) -> &S {
        &self.sink
    }

    /// Consume the ledger, returning the underlying sink.
    pub fn into_sink(self) -> S {
        self.sink
    }
}

fn render_principal(principal: &PrincipalRef) -> String {
    match principal {
        PrincipalRef::Account { account_id } => format!("account:{}", account_id.0),
        PrincipalRef::Service { service_id } => format!("service:{service_id}"),
        PrincipalRef::ApiToken { token_id } => format!("api_token:{token_id}"),
    }
}

fn render_scope(scope: &ScopeRef) -> String {
    match scope {
        ScopeRef::Global => "global".to_owned(),
        ScopeRef::Org { org_id } => format!("org:{}", org_id.0),
        ScopeRef::Namespace { namespace_id } => format!("namespace:{}", namespace_id.0),
        ScopeRef::Workspace { workspace_id } => format!("workspace:{}", workspace_id.0),
        ScopeRef::Project {
            workspace_id,
            project_id,
        } => format!("project:{}/{}", workspace_id.0, project_id.0),
        ScopeRef::Resource {
            resource_type,
            resource_id,
        } => format!("resource:{}/{}", resource_type.0, resource_id.0),
    }
}

fn render_decision(decision: AuthorizationDecision) -> &'static str {
    match decision {
        AuthorizationDecision::Allow => "allow",
        AuthorizationDecision::Deny => "deny",
        AuthorizationDecision::RequireApproval => "require_approval",
    }
}

fn join_ids<'a>(ids: impl Iterator<Item = &'a str>) -> String {
    ids.collect::<Vec<_>>().join(",")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ports::RepoError;
    use std::sync::Mutex;

    use awaken_iam_contract::ActionKey;

    /// Minimal append-only sink for exercising the ledger without the server's
    /// storage adapter.
    #[derive(Default)]
    struct VecSink {
        events: Mutex<Vec<AuditEvent>>,
    }

    impl AuditSink for VecSink {
        fn record(&self, event: AuditEvent) -> RepoResult<()> {
            self.events.lock().unwrap().push(event);
            Ok(())
        }

        fn events(&self) -> RepoResult<Vec<AuditEvent>> {
            Ok(self.events.lock().unwrap().clone())
        }
    }

    /// A sink that always fails, to prove a sink failure aborts the emit before
    /// the fence advances.
    struct FailingSink;

    impl AuditSink for FailingSink {
        fn record(&self, _event: AuditEvent) -> RepoResult<()> {
            Err(RepoError::Backend("sink down".into()))
        }

        fn events(&self) -> RepoResult<Vec<AuditEvent>> {
            Err(RepoError::Backend("sink down".into()))
        }
    }

    fn ts(value: &str) -> Timestamp {
        Timestamp(value.into())
    }

    fn account(id: &str) -> AccountId {
        AccountId(id.into())
    }

    fn request(action: &str) -> AuthorizationRequest {
        AuthorizationRequest::direct(
            PrincipalRef::Service {
                service_id: "svc".into(),
            },
            ActionKey(action.into()),
            ScopeRef::Global,
        )
    }

    #[test]
    fn action_keys_are_stable() {
        assert_eq!(
            DomainEvent::AccountRegistered {
                account: account("a")
            }
            .action(),
            "account.registered"
        );
        assert_eq!(
            DomainEvent::GrantIssued {
                grant: GrantId("g1".into())
            }
            .action(),
            "grant.issued"
        );
        assert_eq!(
            DomainEvent::AuthorizationDecided {
                trace: DecisionTrace::capture(
                    &request("pack.read"),
                    &AuthorizationTrace {
                        decision: AuthorizationDecision::Deny,
                        reason: DecisionReason::DefaultDeny,
                        matched_grants: Vec::new(),
                        matched_roles: Vec::new(),
                        obligation: None,
                    },
                ),
            }
            .action(),
            "authorization.decided"
        );
    }

    #[test]
    fn only_decisions_are_audit_only() {
        let decided = DomainEvent::AuthorizationDecided {
            trace: DecisionTrace::capture(
                &request("pack.read"),
                &AuthorizationTrace {
                    decision: AuthorizationDecision::Allow,
                    reason: DecisionReason::AllowedByGrant,
                    matched_grants: vec![GrantId("g1".into())],
                    matched_roles: Vec::new(),
                    obligation: None,
                },
            ),
        };
        assert!(!decided.fences_snapshot());

        for event in [
            DomainEvent::AccountRegistered {
                account: account("a"),
            },
            DomainEvent::GrantIssued {
                grant: GrantId("g1".into()),
            },
            DomainEvent::SessionEstablished {
                account: account("a"),
                session: SessionId("s1".into()),
            },
        ] {
            assert!(event.fences_snapshot(), "{} should fence", event.action());
        }
    }

    #[test]
    fn audit_record_carries_actor_action_and_detail() {
        let event = DomainEvent::ExternalIdentityLinked {
            account: account("ada"),
            identity: ExternalIdentityId("fake:sub".into()),
        };
        let record = event.to_audit(ts("2026-06-21T00:00:00Z"));
        assert_eq!(record.action, "external_identity.linked");
        assert_eq!(
            record.actor,
            Some(PrincipalRef::Account {
                account_id: account("ada")
            })
        );
        assert_eq!(record.detail, "account=ada identity=fake:sub");
        assert_eq!(record.at, ts("2026-06-21T00:00:00Z"));
    }

    #[test]
    fn decision_detail_renders_the_full_trace() {
        let event = DomainEvent::AuthorizationDecided {
            trace: DecisionTrace::capture(
                &request("pack.publish"),
                &AuthorizationTrace {
                    decision: AuthorizationDecision::Allow,
                    reason: DecisionReason::AllowedByGrant,
                    matched_grants: vec![GrantId("g1".into()), GrantId("g2".into())],
                    matched_roles: vec![RoleId("publisher".into())],
                    obligation: None,
                },
            ),
        };
        let record = event.to_audit(ts("2026-06-21T00:00:00Z"));
        assert_eq!(
            record.detail,
            "principal=service:svc action=pack.publish scope=global \
             decision=allow reason=allowed_by_grant grants=[g1,g2] roles=[publisher]"
        );
        assert_eq!(
            record.actor,
            Some(PrincipalRef::Service {
                service_id: "svc".into()
            })
        );
    }

    #[test]
    fn ledger_records_every_event_and_fences_only_state_changes() {
        let mut ledger = AuditLedger::new(VecSink::default());
        assert_eq!(ledger.version(), 1);

        // A state change advances the fence.
        let after_grant = ledger
            .emit(
                ts("2026-06-21T00:00:00Z"),
                DomainEvent::GrantIssued {
                    grant: GrantId("g1".into()),
                },
            )
            .unwrap();
        assert_eq!(after_grant, 2);
        assert_eq!(ledger.version(), 2);

        // A decision trace is recorded but does not move the fence.
        let after_decision = ledger
            .emit(
                ts("2026-06-21T00:01:00Z"),
                DomainEvent::AuthorizationDecided {
                    trace: DecisionTrace::capture(
                        &request("pack.read"),
                        &AuthorizationTrace {
                            decision: AuthorizationDecision::Deny,
                            reason: DecisionReason::DefaultDeny,
                            matched_grants: Vec::new(),
                            matched_roles: Vec::new(),
                            obligation: None,
                        },
                    ),
                },
            )
            .unwrap();
        assert_eq!(after_decision, 2);
        assert_eq!(ledger.version(), 2);

        // Another state change advances the fence again.
        ledger
            .emit(
                ts("2026-06-21T00:02:00Z"),
                DomainEvent::GrantRevoked {
                    grant: GrantId("g1".into()),
                },
            )
            .unwrap();
        assert_eq!(ledger.version(), 3);

        // Both state changes and the decision are in the append-only trail.
        let events = ledger.events().unwrap();
        assert_eq!(events.len(), 3);
        assert_eq!(events[0].action, "grant.issued");
        assert_eq!(events[1].action, "authorization.decided");
        assert_eq!(events[2].action, "grant.revoked");
    }

    #[test]
    fn sink_failure_aborts_emit_without_moving_the_fence() {
        let mut ledger = AuditLedger::new(FailingSink);
        let result = ledger.emit(
            ts("2026-06-21T00:00:00Z"),
            DomainEvent::GrantIssued {
                grant: GrantId("g1".into()),
            },
        );
        assert_eq!(result, Err(RepoError::Backend("sink down".into())));
        // The fence never advances on a sink that failed to persist the event.
        assert_eq!(ledger.version(), 1);
    }

    /// Every variant's stable action key, audit detail, and intrinsic actor,
    /// asserted together so a new variant cannot silently skip one of the three.
    #[test]
    fn every_variant_renders_action_detail_and_actor() {
        use crate::PlanId;
        use awaken_iam_contract::{
            NamespaceId, OrgId, ProjectId, ResourceId, ResourceType, WorkspaceId,
        };

        let svc = PrincipalRef::Service {
            service_id: "svc".into(),
        };
        let cases: Vec<(DomainEvent, &str, &str, Option<PrincipalRef>)> = vec![
            (
                DomainEvent::SessionRevoked {
                    session: SessionId("s1".into()),
                },
                "session.revoked",
                "session=s1",
                None,
            ),
            (
                DomainEvent::ApiTokenIssued {
                    principal: PrincipalRef::ApiToken {
                        token_id: "tok".into(),
                    },
                    token_id: "tok".into(),
                },
                "api_token.issued",
                "principal=api_token:tok token=tok",
                Some(PrincipalRef::ApiToken {
                    token_id: "tok".into(),
                }),
            ),
            (
                DomainEvent::ApiTokenRevoked {
                    token_id: "tok".into(),
                },
                "api_token.revoked",
                "token=tok",
                None,
            ),
            (
                DomainEvent::RoleDefined {
                    role: RoleId("admin".into()),
                },
                "role.defined",
                "role=admin",
                None,
            ),
            (
                DomainEvent::MembershipGranted {
                    principal: svc.clone(),
                    role: RoleId("admin".into()),
                    scope: ScopeRef::Org {
                        org_id: OrgId("acme".into()),
                    },
                },
                "membership.granted",
                "principal=service:svc role=admin scope=org:acme",
                Some(svc.clone()),
            ),
            (
                DomainEvent::MembershipRevoked {
                    principal: svc.clone(),
                    role: RoleId("admin".into()),
                    scope: ScopeRef::Namespace {
                        namespace_id: NamespaceId("ns".into()),
                    },
                },
                "membership.revoked",
                "principal=service:svc role=admin scope=namespace:ns",
                Some(svc.clone()),
            ),
            (
                DomainEvent::SignerRegistered {
                    namespace: NamespaceId("ns".into()),
                    signer: "fp".into(),
                },
                "signer.registered",
                "namespace=ns signer=fp",
                None,
            ),
            (
                DomainEvent::SignerRevoked {
                    namespace: NamespaceId("ns".into()),
                    signer: "fp".into(),
                },
                "signer.revoked",
                "namespace=ns signer=fp",
                None,
            ),
            (
                DomainEvent::SubscriptionChanged {
                    principal: svc.clone(),
                    plan: PlanId("pro".into()),
                },
                "subscription.changed",
                "principal=service:svc plan=pro",
                Some(svc.clone()),
            ),
        ];

        for (event, action, detail, actor) in cases {
            assert_eq!(event.action(), action, "action for {action}");
            assert_eq!(event.detail(), detail, "detail for {action}");
            assert_eq!(event.actor(), actor, "actor for {action}");
            // Each non-decision variant fences the snapshot version.
            assert!(event.fences_snapshot(), "{action} should fence");
        }

        // The remaining scope shapes render through the detail path.
        let workspace = DomainEvent::MembershipGranted {
            principal: PrincipalRef::Account {
                account_id: account("ada"),
            },
            role: RoleId("viewer".into()),
            scope: ScopeRef::Workspace {
                workspace_id: WorkspaceId("w1".into()),
            },
        };
        assert_eq!(
            workspace.detail(),
            "principal=account:ada role=viewer scope=workspace:w1"
        );

        let project = DomainEvent::MembershipGranted {
            principal: PrincipalRef::Account {
                account_id: account("ada"),
            },
            role: RoleId("viewer".into()),
            scope: ScopeRef::Project {
                workspace_id: WorkspaceId("w1".into()),
                project_id: ProjectId("p1".into()),
            },
        };
        assert_eq!(
            project.detail(),
            "principal=account:ada role=viewer scope=project:w1/p1"
        );

        let resource = DomainEvent::MembershipGranted {
            principal: PrincipalRef::Account {
                account_id: account("ada"),
            },
            role: RoleId("viewer".into()),
            scope: ScopeRef::Resource {
                resource_type: ResourceType("pack".into()),
                resource_id: ResourceId("r1".into()),
            },
        };
        assert_eq!(
            resource.detail(),
            "principal=account:ada role=viewer scope=resource:pack/r1"
        );
    }

    #[test]
    fn require_approval_decision_renders_in_the_trace_detail() {
        let event = DomainEvent::AuthorizationDecided {
            trace: DecisionTrace::capture(
                &request("pack.publish"),
                &AuthorizationTrace {
                    decision: AuthorizationDecision::RequireApproval,
                    reason: DecisionReason::DefaultDeny,
                    matched_grants: Vec::new(),
                    matched_roles: Vec::new(),
                    obligation: None,
                },
            ),
        };
        assert!(event.detail().contains("decision=require_approval"));
        // An empty grant/role set renders as empty bracket lists.
        assert!(event.detail().contains("grants=[] roles=[]"));
        // A decision is the only audit-only event.
        assert!(!event.fences_snapshot());
    }

    #[test]
    fn resume_starts_the_fence_at_the_given_version_and_exposes_the_sink() {
        let mut ledger = AuditLedger::resume(VecSink::default(), 7);
        assert_eq!(ledger.version(), 7);
        let after = ledger
            .emit(
                ts("2026-06-21T00:00:00Z"),
                DomainEvent::RoleDefined {
                    role: RoleId("admin".into()),
                },
            )
            .unwrap();
        assert_eq!(after, 8);

        // The sink is borrowable while the ledger lives...
        assert_eq!(ledger.sink().events().unwrap().len(), 1);
        // ...and recoverable by consuming the ledger.
        let sink = ledger.into_sink();
        assert_eq!(sink.events().unwrap().len(), 1);
    }
}
