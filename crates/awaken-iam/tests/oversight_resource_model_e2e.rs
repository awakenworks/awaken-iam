//! Consumer integration contract test: ResourceModel registration →
//! authorize / visible / approval / token / outbox E2E.
//!
//! Mirrors the managed-agents greenfield path but for an Oversight-style consumer
//! that **owns and registers** its ResourceModel and role catalog from scratch —
//! IAM core ships none of this; it is consumer data registered at runtime.
//!
//! Covers the full consumer-facing surface mandated by the issue:
//!
//! - **authorize** (allow / deny / default-deny)
//! - **principal chain** \[human, agent\] — conjunctive evaluation
//! - **visible()** list filtering
//! - **RequireApproval** + obligation discharge via [`ApprovalDischargeService`]
//! - **capability token** — minted from the discharged obligation, verified
//! - **resource-create consistency** — both the remote (transactional outbox)
//!   path and the embedded single-transaction path yield identical authorization
//!   behaviour after the provision lands
//!
//! Architecture note: the consumer's resource types (`issue`, `deployment`) and
//! their action catalogs live in THIS file — not in IAM core.  IAM stays
//! product-agnostic; the consumer teaches IAM its vocabulary through
//! `AuthzApi::register_resource_model` and its own grant/role setup.

use std::sync::Mutex;

use awaken_iam::{
    AccessTokenAuthority, AccountId, ActionKey, ActionPattern, ApprovalDischargeService,
    AuthorizationDecision, AuthorizationRequest, AuthzApi, CapabilityCheck, CapabilityError,
    DischargeOutcome, DischargeRequest, Effect, Grant, GrantEffect, GrantId, GrantSnapshot,
    GrantSubject, GrantSubjectRef, InMemoryOutbox, LeaseEpoch, LocalSeedSigner, OutboxRelay,
    OutboxStore, PolicySet, PrincipalRef, ProjectId, ProvisionTransport, RemoteError, ResourceId,
    ResourceModel, ResourceModelRegistration, ResourceParentEdge, ResourceProvision, ResourceType,
    ResourceTypeRegistration, RoleBinding, RoleId, ScopeRef, WorkspaceId, oversight,
    verify_capability,
};

// ---------------------------------------------------------------------------
// Consumer-owned vocabulary: Oversight's resource types and actions
//
// These are NEVER shipped in awaken-iam-core.  The consumer registers them at
// startup via AuthzApi::register_resource_model, teaching IAM its hierarchy.
// ---------------------------------------------------------------------------

/// Resource types and their action catalogs owned by the Oversight consumer.
/// Registered as data, not as code changes in IAM core.
fn oversight_resource_model_registration() -> ResourceModelRegistration {
    ResourceModelRegistration {
        resource_types: vec![
            ResourceTypeRegistration {
                resource_type: ResourceType("issue".into()),
                parent_type: None,
                actions: vec![
                    ActionKey("issue.read".into()),
                    ActionKey("issue.write".into()),
                    ActionKey("issue.advance".into()),
                    ActionKey("issue.close".into()),
                ],
            },
            // `run` is a sub-type of `issue`; its actions live in the `oversight`
            // namespace so the model stays within Oversight's declared surface.
            ResourceTypeRegistration {
                resource_type: ResourceType("run".into()),
                parent_type: Some(ResourceType("issue".into())),
                actions: vec![
                    ActionKey("oversight.run.create".into()),
                    ActionKey("oversight.run.cancel".into()),
                ],
            },
        ],
        // Standalone oversight-namespaced actions (not bound to a resource type).
        actions: vec![
            ActionKey("oversight.read".into()),
            ActionKey("oversight.configure".into()),
        ],
        // Per-instance parent edges: registered by the consumer as domain
        // objects are created.  Two issues under proj_web; issue_99 under a
        // different project (for isolation tests).
        edges: vec![
            ResourceParentEdge {
                resource_type: ResourceType("issue".into()),
                resource_id: ResourceId("issue_42".into()),
                parent: ScopeRef::Project {
                    workspace_id: WorkspaceId("ws_acme".into()),
                    project_id: ProjectId("proj_web".into()),
                },
            },
            ResourceParentEdge {
                resource_type: ResourceType("issue".into()),
                resource_id: ResourceId("issue_43".into()),
                parent: ScopeRef::Project {
                    workspace_id: WorkspaceId("ws_acme".into()),
                    project_id: ProjectId("proj_web".into()),
                },
            },
            ResourceParentEdge {
                resource_type: ResourceType("issue".into()),
                resource_id: ResourceId("issue_99".into()),
                parent: ScopeRef::Project {
                    workspace_id: WorkspaceId("ws_other".into()),
                    project_id: ProjectId("proj_other".into()),
                },
            },
        ],
    }
}

// ---------------------------------------------------------------------------
// Consumer-owned role catalog: Oversight's roles and grants
// ---------------------------------------------------------------------------

fn acct(id: &str) -> PrincipalRef {
    PrincipalRef::Account {
        account_id: AccountId(id.into()),
    }
}

fn service(id: &str) -> PrincipalRef {
    PrincipalRef::Service {
        service_id: id.into(),
    }
}

fn proj_web() -> ScopeRef {
    ScopeRef::Project {
        workspace_id: WorkspaceId("ws_acme".into()),
        project_id: ProjectId("proj_web".into()),
    }
}

fn issue_scope(id: &str) -> ScopeRef {
    ScopeRef::Resource {
        resource_type: ResourceType("issue".into()),
        resource_id: ResourceId(id.into()),
    }
}

/// Build an `AuthzApi` with:
/// - Oversight's resource model registered (types, actions, instance edges)
/// - Consumer-defined roles: `oversight_viewer` and `oversight_contributor`
/// - A `RequireApproval` gate on `issue.close` at project scope
/// - Ada (human) and agent:coder both bound to `oversight_contributor` at proj_web
fn build_oversight_api() -> AuthzApi {
    let mut api = AuthzApi::new();

    // --- 1. Register the consumer's ResourceModel ---
    api.register_resource_model(&oversight_resource_model_registration());

    // --- 2. Consumer's role catalog (Oversight owns these; IAM core is unaware) ---
    //
    // `oversight_viewer`: read-only access to issues.
    let viewer_role = RoleId("oversight_viewer".into());
    api.policy_mut().add_grant(Grant {
        id: GrantId("g_viewer_read".into()),
        subject: GrantSubject::Role(viewer_role),
        action_pattern: ActionPattern("issue.read".into()),
        scope: ScopeRef::Global,
        effect: Effect::Allow,
    });

    // `oversight_contributor`: read + write + advance (not close — gated separately).
    let contributor_role = RoleId("oversight_contributor".into());
    for (idx, pattern) in ["issue.read", "issue.write", "issue.advance"]
        .iter()
        .enumerate()
    {
        api.policy_mut().add_grant(Grant {
            id: GrantId(format!("g_contributor_{idx}")),
            subject: GrantSubject::Role(contributor_role.clone()),
            action_pattern: ActionPattern((*pattern).into()),
            scope: ScopeRef::Global,
            effect: Effect::Allow,
        });
    }

    // --- 3. RequireApproval gate on issue.close at project scope ---
    //
    // Any principal bound to the contributor role at proj_web must obtain
    // approval to close an issue; RequireApproval beats the default-deny but
    // forces the obligation step.
    api.policy_mut().add_grant(Grant {
        id: GrantId("g_close_requires_approval".into()),
        subject: GrantSubject::Role(contributor_role.clone()),
        action_pattern: ActionPattern("issue.close".into()),
        scope: proj_web(),
        effect: Effect::RequireApproval,
    });

    // --- 4. Bind Ada and agent:coder to the contributor role at proj_web ---
    api.policy_mut().bind_role(RoleBinding {
        principal: acct("acct_ada"),
        role: contributor_role.clone(),
        scope: proj_web(),
    });
    api.policy_mut().bind_role(RoleBinding {
        principal: service("agent:coder"),
        role: contributor_role,
        scope: proj_web(),
    });

    api
}

// ---------------------------------------------------------------------------
// Test 1: authorize — allow / deny / default-deny
// ---------------------------------------------------------------------------

#[test]
fn authorize_allow_deny_default_deny_on_registered_model() {
    let api = build_oversight_api();

    // Allow: ada (contributor) may write issue_42 which lives under proj_web.
    let outcome = api.authorize(&AuthorizationRequest::direct(
        acct("acct_ada"),
        ActionKey("issue.write".into()),
        issue_scope("issue_42"),
    ));
    assert_eq!(
        outcome.decision,
        AuthorizationDecision::Allow,
        "contributor must be allowed to write an issue under their project"
    );
    assert_eq!(outcome.reason, "allowed_by_grant");

    // Allow: read action on same issue.
    let read = api.authorize(&AuthorizationRequest::direct(
        acct("acct_ada"),
        ActionKey("issue.read".into()),
        issue_scope("issue_42"),
    ));
    assert_eq!(read.decision, AuthorizationDecision::Allow);

    // Deny / default-deny: stranger has no binding.
    let denied = api.authorize(&AuthorizationRequest::direct(
        acct("acct_stranger"),
        ActionKey("issue.write".into()),
        issue_scope("issue_42"),
    ));
    assert_eq!(
        denied.decision,
        AuthorizationDecision::Deny,
        "an unbound principal must be denied (default-deny)"
    );
    assert_eq!(denied.reason, "default_deny");

    // Deny: ada is bound at proj_web, not at proj_other — isolation holds.
    let isolated = api.authorize(&AuthorizationRequest::direct(
        acct("acct_ada"),
        ActionKey("issue.write".into()),
        issue_scope("issue_99"), // lives under ws_other/proj_other
    ));
    assert_eq!(
        isolated.decision,
        AuthorizationDecision::Deny,
        "a project-scoped binding must not reach a different project's issues"
    );

    // Deny: ada tries an action outside her role.
    let not_in_role = api.authorize(&AuthorizationRequest::direct(
        acct("acct_ada"),
        ActionKey("oversight.configure".into()),
        ScopeRef::Global,
    ));
    assert_eq!(
        not_in_role.decision,
        AuthorizationDecision::Deny,
        "an action outside the contributor role must be denied"
    );

    // Structural check: the consumer model is confined to its own namespaces.
    let model = ResourceModel::from_registration(&oversight_resource_model_registration());
    assert_eq!(
        oversight().confines(&model),
        Ok(()),
        "the registered model must stay within Oversight's declared namespaces"
    );
}

// ---------------------------------------------------------------------------
// Test 2: principal chain [human, agent] — conjunctive evaluation
// ---------------------------------------------------------------------------

#[test]
fn principal_chain_human_agent_is_conjunctive() {
    let api = build_oversight_api();

    // Both ada (human) and agent:coder hold the contributor role at proj_web.
    // A chain [agent:coder on_behalf_of ada] resolves Allow for issue.write
    // because BOTH links clear the grant.
    let both_allowed = api.authorize(&AuthorizationRequest {
        principal: service("agent:coder"),
        on_behalf_of: vec![acct("acct_ada")],
        action: ActionKey("issue.write".into()),
        scope: issue_scope("issue_42"),
    });
    assert_eq!(
        both_allowed.decision,
        AuthorizationDecision::Allow,
        "both links in the chain hold the grant — must Allow"
    );

    // Agent acting on behalf of a stranger: agent has the grant but stranger
    // does not — the chain is conjunctive so the whole request is Deny.
    let chain_fails = api.authorize(&AuthorizationRequest {
        principal: service("agent:coder"),
        on_behalf_of: vec![acct("acct_stranger")],
        action: ActionKey("issue.write".into()),
        scope: issue_scope("issue_42"),
    });
    assert_eq!(
        chain_fails.decision,
        AuthorizationDecision::Deny,
        "one link missing the grant collapses the whole chain to Deny"
    );

    // Human acting on behalf of an unauthorised agent: symmetrical check.
    let ada_for_rogue = api.authorize(&AuthorizationRequest {
        principal: acct("acct_ada"),
        on_behalf_of: vec![service("agent:rogue")],
        action: ActionKey("issue.write".into()),
        scope: issue_scope("issue_42"),
    });
    assert_eq!(
        ada_for_rogue.decision,
        AuthorizationDecision::Deny,
        "an unauthorised agent in the chain must block the whole request"
    );
}

// ---------------------------------------------------------------------------
// Test 3: visible() — list filtering
// ---------------------------------------------------------------------------

#[test]
fn visible_filters_issue_list_to_what_the_caller_can_read() {
    let api = build_oversight_api();

    // The candidate list: ada has proj_web contributor access, so she can see
    // issue_42 and issue_43 but not issue_99 (different project/workspace).
    let candidates = vec![
        issue_scope("issue_42"),
        issue_scope("issue_43"),
        issue_scope("issue_99"),
    ];

    let visible = api.core().visible(
        &acct("acct_ada"),
        &ActionKey("issue.read".into()),
        &candidates,
    );
    assert_eq!(
        visible,
        vec![issue_scope("issue_42"), issue_scope("issue_43")],
        "visible() must return only the scopes the caller can read, in input order"
    );

    // A stranger sees nothing: no grants → empty list.
    let none_visible = api.core().visible(
        &acct("acct_stranger"),
        &ActionKey("issue.read".into()),
        &candidates,
    );
    assert!(
        none_visible.is_empty(),
        "an unbound principal must see no candidates"
    );

    // visible() excludes RequireApproval scopes: ada cannot close-filter a
    // list via visible() because issue.close resolves to RequireApproval, not
    // Allow, so the list endpoint should not include those items.
    let close_visible = api.core().visible(
        &acct("acct_ada"),
        &ActionKey("issue.close".into()),
        &candidates[..2], // just issue_42 and issue_43
    );
    assert!(
        close_visible.is_empty(),
        "RequireApproval is not Allow, so visible() must exclude it"
    );
}

// ---------------------------------------------------------------------------
// Test 4 + 5: RequireApproval, obligation discharge, and capability token
// ---------------------------------------------------------------------------

fn signing_authority() -> AccessTokenAuthority {
    AccessTokenAuthority::new(LocalSeedSigner::new("oversight-cap-key", [11u8; 32]))
}

const IAT: i64 = 1_900_000_000;
const EXP: i64 = 1_900_003_600;

/// Closing an issue returns RequireApproval, carries an obligation the caller
/// must discharge, and the discharge produces a verifiable capability token.
#[tokio::test]
async fn require_approval_produces_obligation_and_discharge_mints_capability_token() {
    let api = build_oversight_api();

    // RequireApproval: ada asks to close an issue she holds via the gated role.
    let outcome = api.authorize(&AuthorizationRequest::direct(
        acct("acct_ada"),
        ActionKey("issue.close".into()),
        issue_scope("issue_42"),
    ));
    assert_eq!(
        outcome.decision,
        AuthorizationDecision::RequireApproval,
        "issue.close must be gated as RequireApproval for the contributor role"
    );
    let obligation = outcome
        .obligation
        .as_ref()
        .expect("RequireApproval must carry an ApprovalObligation");
    assert!(
        obligation.obligation_id.starts_with("obl_"),
        "obligation_id must use the obl_ prefix"
    );
    assert_eq!(
        obligation.policy_id, "g_close_requires_approval",
        "obligation must name the deciding grant"
    );

    // Re-querying the same request yields the exact same obligation_id —
    // content-addressed, so a retry never produces a second obligation.
    let re_queried = api.authorize(&AuthorizationRequest::direct(
        acct("acct_ada"),
        ActionKey("issue.close".into()),
        issue_scope("issue_42"),
    ));
    assert_eq!(
        re_queried.obligation.as_ref().map(|o| &o.obligation_id),
        outcome.obligation.as_ref().map(|o| &o.obligation_id),
        "re-querying must return the same obligation_id (content-addressed)"
    );

    // Discharge: the obligation is converted to a capability token.
    // Create the discharge service with its own authority instance; use
    // signing_authority() again below for JWKS — same seed, identical public key.
    let discharge_service = ApprovalDischargeService::new(signing_authority());
    let epoch = LeaseEpoch::initial();

    let discharge_result = discharge_service
        .discharge(DischargeRequest {
            obligation_id: obligation.obligation_id.clone(),
            iss: "https://iam.oversight.example".into(),
            sub: "acct_ada".into(),
            aud: "oversight-approval-gate".into(),
            jti: "cap-close-issue_42".into(),
            iat: IAT,
            exp: EXP,
            epoch,
            scope: vec!["issue.close".into()],
        })
        .await
        .unwrap();

    let token = match discharge_result {
        DischargeOutcome::Minted(t) => t,
        DischargeOutcome::AlreadyDischarged => panic!("expected first discharge to mint"),
    };

    // Verify the capability token — all claims must reflect the discharge.
    // signing_authority() constructs an authority with the same seed, producing
    // the same public key for verification.
    let jwks = signing_authority().jwks();
    let claims = verify_capability(
        &token,
        &jwks,
        CapabilityCheck {
            audience: "oversight-approval-gate",
            epoch,
            now: IAT + 1,
        },
    )
    .unwrap();

    assert_eq!(
        claims.obligation.as_deref(),
        Some(obligation.obligation_id.as_str()),
        "the token must be bound to the obligation_id"
    );
    assert_eq!(claims.sub, "acct_ada");
    assert_eq!(claims.scope, vec!["issue.close".to_owned()]);
    assert_eq!(claims.epoch, epoch);
    assert!(
        claims.parent.is_none(),
        "a discharge token is a root capability, not an attenuated one"
    );

    // Idempotency: discharging the same obligation_id a second time must not
    // issue a new grant.
    let second = discharge_service
        .discharge(DischargeRequest {
            obligation_id: obligation.obligation_id.clone(),
            iss: "https://iam.oversight.example".into(),
            sub: "acct_ada".into(),
            aud: "oversight-approval-gate".into(),
            jti: "cap-close-issue_42-dup".into(),
            iat: IAT,
            exp: EXP,
            epoch,
            scope: vec!["issue.close".into()],
        })
        .await
        .unwrap();
    assert_eq!(
        second,
        DischargeOutcome::AlreadyDischarged,
        "re-discharging the same obligation must be a no-op"
    );

    // Epoch advance fences the outstanding token immediately — all outstanding
    // discharge tokens are invalidated in one step.
    let next_epoch = epoch.next();
    let fenced = verify_capability(
        &token,
        &jwks,
        CapabilityCheck {
            audience: "oversight-approval-gate",
            epoch: next_epoch,
            now: IAT + 1,
        },
    )
    .unwrap_err();
    assert_eq!(
        fenced,
        CapabilityError::EpochFenced,
        "advancing the epoch must fence outstanding tokens immediately"
    );
}

// ---------------------------------------------------------------------------
// Test 6 + 7: resource-create consistency — outbox (remote) and embedded paths
// ---------------------------------------------------------------------------
//
// When Oversight creates a new issue it must write the scope edge and creator
// grant so the resource becomes authorizable.
//
// Remote path: consumer enqueues a ResourceProvision in a transactional outbox
//   alongside the domain row write (one local transaction); a relay propagates
//   it to IAM asynchronously.  Until it lands, authorization fails closed.
// Embedded path: same payload applied directly inside the shared-database
//   transaction — no relay, no eventual-consistency window.
//
// Both paths must yield identical authorization outcomes after the provision is
// applied.

/// A `ProvisionTransport` that applies a `ResourceProvision` directly to a
/// `PolicySet`, modelling the IAM endpoint a remote relay would call in
/// production (which would ultimately write to the same policy store).
struct PolicyTransport(Mutex<PolicySet>);

impl PolicyTransport {
    fn new(policy: PolicySet) -> Self {
        Self(Mutex::new(policy))
    }

    fn evaluate(&self, request: &AuthorizationRequest) -> AuthorizationDecision {
        self.0
            .lock()
            .expect("mutex not poisoned")
            .evaluate(request)
            .decision
    }
}

impl ProvisionTransport for PolicyTransport {
    fn provision(&self, provision: &ResourceProvision) -> Result<(), RemoteError> {
        let mut policy = self.0.lock().expect("mutex not poisoned");

        // Scope edges must land before grants so a grant anchored at the new
        // resource always resolves its parent scope immediately.
        for edge in &provision.scope_edges {
            policy.scope_graph_mut().assign_resource_parent(
                edge.resource_type.clone(),
                edge.resource_id.clone(),
                edge.parent.clone(),
            );
        }

        for g in &provision.grants {
            policy.add_grant(Grant {
                id: GrantId(g.id.clone()),
                subject: match &g.subject {
                    GrantSubjectRef::Principal { principal } => {
                        GrantSubject::Principal(principal.clone())
                    }
                    GrantSubjectRef::Role { role_id } => {
                        GrantSubject::Role(RoleId(role_id.clone()))
                    }
                    GrantSubjectRef::Group { .. } => {
                        unreachable!("test provisions use only Principal/Role subjects")
                    }
                },
                action_pattern: ActionPattern(g.action_pattern.clone()),
                scope: g.scope.clone(),
                effect: match g.effect {
                    GrantEffect::Allow => Effect::Allow,
                    GrantEffect::RequireApproval => Effect::RequireApproval,
                    GrantEffect::Deny => Effect::Deny,
                },
            });
        }

        Ok(())
    }
}

/// The `ResourceProvision` the Oversight consumer emits when it creates issue_77:
/// - a scope edge anchoring issue_77 under proj_web
/// - a creator grant giving ada full issue.* authority over the new issue
fn issue_77_provision() -> ResourceProvision {
    ResourceProvision {
        idempotency_key: "issue:issue_77".into(),
        epoch: 1,
        grants: vec![GrantSnapshot {
            id: "g_issue_77_creator".into(),
            subject: GrantSubjectRef::Principal {
                principal: acct("acct_ada"),
            },
            action_pattern: "issue.*".into(),
            scope: issue_scope("issue_77"),
            effect: GrantEffect::Allow,
        }],
        scope_edges: vec![ResourceParentEdge {
            resource_type: ResourceType("issue".into()),
            resource_id: ResourceId("issue_77".into()),
            parent: proj_web(),
        }],
    }
}

/// A minimal `PolicySet` with the Oversight resource model and standard role
/// wiring, used as the starting state for the remote/embedded path tests.
fn base_policy() -> PolicySet {
    let mut policy = PolicySet::new();

    let model = ResourceModel::from_registration(&oversight_resource_model_registration());
    policy.register_resource_model(&model);

    let contributor_role = RoleId("oversight_contributor".into());
    for (idx, pattern) in ["issue.read", "issue.write", "issue.advance"]
        .iter()
        .enumerate()
    {
        policy.add_grant(Grant {
            id: GrantId(format!("g_contributor_{idx}")),
            subject: GrantSubject::Role(contributor_role.clone()),
            action_pattern: ActionPattern((*pattern).into()),
            scope: ScopeRef::Global,
            effect: Effect::Allow,
        });
    }
    policy.bind_role(RoleBinding {
        principal: acct("acct_ada"),
        role: contributor_role.clone(),
        scope: proj_web(),
    });
    policy.bind_role(RoleBinding {
        principal: service("agent:coder"),
        role: contributor_role,
        scope: proj_web(),
    });

    policy
}

/// Before any provision lands, authorization against the new resource fails
/// closed — default-deny, never over-permits — because no scope edge is
/// registered and no creator grant exists yet.
#[test]
fn authorization_fails_closed_before_provision_lands() {
    let policy = base_policy();

    // issue_77 has no scope edge: the ancestor walk cannot reach proj_web, so
    // there is no matching grant — default-deny even for a legitimate contributor.
    let denied = policy
        .evaluate(&AuthorizationRequest::direct(
            acct("acct_ada"),
            ActionKey("issue.write".into()),
            issue_scope("issue_77"),
        ))
        .decision;
    assert_eq!(
        denied,
        AuthorizationDecision::Deny,
        "no scope edge → no ancestor walk → default-deny before provision lands"
    );
}

/// Remote (outbox) path: enqueue → drain → grant lands → authorization resolves.
///
/// The relay delivers the provision in sequence order.  Until the drain
/// completes, authorization fails closed.  After the drain the creator grant
/// is present and the new issue is authorizable.  Re-delivery is a no-op
/// (idempotent by grant id and scope edge key).
#[test]
fn resource_create_remote_outbox_path_consistency() {
    // --- Consumer's "domain write + outbox enqueue" (one local transaction) ---
    let outbox = InMemoryOutbox::new();
    outbox.enqueue(issue_77_provision()).unwrap();
    assert_eq!(
        outbox.pending().unwrap().len(),
        1,
        "one pending provision before drain"
    );

    // --- Relay drains to IAM (the transport applies grants to the policy) ---
    let transport = PolicyTransport::new(base_policy());
    let relay = OutboxRelay::new(outbox, transport);
    let report = relay.drain().unwrap();
    assert!(
        report.is_complete(),
        "drain must complete with no error: {report:?}"
    );
    assert_eq!(report.delivered, 1);
    assert_eq!(report.remaining, 0);

    // All records now delivered; a second drain is a no-op.
    let second = relay.drain().unwrap();
    assert_eq!(second.delivered, 0);
    assert!(second.is_complete());

    // --- Post-drain: creator grant present → Allow ---
    let allowed = relay.transport().evaluate(&AuthorizationRequest::direct(
        acct("acct_ada"),
        ActionKey("issue.write".into()),
        issue_scope("issue_77"),
    ));
    assert_eq!(
        allowed,
        AuthorizationDecision::Allow,
        "after the provision lands, the creator may write the new issue"
    );

    // Strangers remain denied — the provision does not open the resource to
    // everyone, only to the declared grant subjects.
    let denied = relay.transport().evaluate(&AuthorizationRequest::direct(
        acct("acct_stranger"),
        ActionKey("issue.write".into()),
        issue_scope("issue_77"),
    ));
    assert_eq!(
        denied,
        AuthorizationDecision::Deny,
        "the creator grant must not grant access to unrelated principals"
    );

    // Idempotency: re-delivering the same provision must not change the outcome.
    let outbox2 = InMemoryOutbox::new();
    outbox2.enqueue(issue_77_provision()).unwrap();
    let transport2 = PolicyTransport::new({
        // Rebuild policy from the current state of the first transport.
        // For idempotency we start from a clean base + apply once already.
        let mut p = base_policy();
        let prov = issue_77_provision();
        for edge in &prov.scope_edges {
            p.scope_graph_mut().assign_resource_parent(
                edge.resource_type.clone(),
                edge.resource_id.clone(),
                edge.parent.clone(),
            );
        }
        for g in &prov.grants {
            p.add_grant(Grant {
                id: GrantId(g.id.clone()),
                subject: GrantSubject::Principal(acct("acct_ada")),
                action_pattern: ActionPattern(g.action_pattern.clone()),
                scope: g.scope.clone(),
                effect: Effect::Allow,
            });
        }
        p
    });
    let relay2 = OutboxRelay::new(outbox2, transport2);
    relay2.drain().unwrap();
    let redelivery_result = relay2.transport().evaluate(&AuthorizationRequest::direct(
        acct("acct_ada"),
        ActionKey("issue.write".into()),
        issue_scope("issue_77"),
    ));
    assert_eq!(
        redelivery_result,
        AuthorizationDecision::Allow,
        "re-delivery must be idempotent — still allowed after second application"
    );
}

/// Embedded path: applying the same `ResourceProvision` directly to a
/// `PolicySet` (simulating a single shared-database transaction) produces
/// authorization behaviour identical to the remote outbox path.
#[test]
fn resource_create_embedded_path_is_consistent_with_outbox_path() {
    let mut policy = base_policy();
    let provision = issue_77_provision();

    // Embedded application: no relay, no transport — the consumer calls this
    // directly inside the transaction that writes the domain row.
    for edge in &provision.scope_edges {
        policy.scope_graph_mut().assign_resource_parent(
            edge.resource_type.clone(),
            edge.resource_id.clone(),
            edge.parent.clone(),
        );
    }
    for g in &provision.grants {
        policy.add_grant(Grant {
            id: GrantId(g.id.clone()),
            subject: match &g.subject {
                GrantSubjectRef::Principal { principal } => {
                    GrantSubject::Principal(principal.clone())
                }
                GrantSubjectRef::Role { role_id } => GrantSubject::Role(RoleId(role_id.clone())),
                GrantSubjectRef::Group { .. } => {
                    unreachable!("test provisions use only Principal/Role subjects")
                }
            },
            action_pattern: ActionPattern(g.action_pattern.clone()),
            scope: g.scope.clone(),
            effect: match g.effect {
                GrantEffect::Allow => Effect::Allow,
                GrantEffect::RequireApproval => Effect::RequireApproval,
                GrantEffect::Deny => Effect::Deny,
            },
        });
    }

    // Same authorization outcome as the remote outbox path.
    let allowed = policy
        .evaluate(&AuthorizationRequest::direct(
            acct("acct_ada"),
            ActionKey("issue.write".into()),
            issue_scope("issue_77"),
        ))
        .decision;
    assert_eq!(
        allowed,
        AuthorizationDecision::Allow,
        "embedded path must produce the same Allow outcome as the outbox path"
    );

    let denied = policy
        .evaluate(&AuthorizationRequest::direct(
            acct("acct_stranger"),
            ActionKey("issue.write".into()),
            issue_scope("issue_77"),
        ))
        .decision;
    assert_eq!(
        denied,
        AuthorizationDecision::Deny,
        "embedded path must not widen access beyond the declared grant subjects"
    );
}
