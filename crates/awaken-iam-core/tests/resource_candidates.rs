//! Native PDP enumeration is the oracle: a plan may admit false positives but
//! must never discard an Allow, including immutable migration predecessors.
use awaken_iam_contract::*;
use awaken_iam_core::{GroupId, PolicySet, ResourceCandidateError};

fn account(id: &str) -> PrincipalRef {
    PrincipalRef::Account {
        account_id: AccountId(id.into()),
    }
}
fn service(id: &str) -> PrincipalRef {
    PrincipalRef::Service {
        service_id: id.into(),
    }
}
fn workspace(id: &str) -> ScopeRef {
    ScopeRef::Workspace {
        workspace_id: WorkspaceId(id.into()),
    }
}
fn project(id: &str) -> ScopeRef {
    ScopeRef::Project {
        workspace_id: WorkspaceId("w".into()),
        project_id: ProjectId(id.into()),
    }
}
fn query() -> ResourceCandidateRequest {
    ResourceCandidateRequest {
        mode: ResourceAuthorizationMode::Scoped,
        request: AuthorizationRequest::direct(
            account("alice"),
            ActionKey("business::read".into()),
            project("p"),
        ),
        resource_type: Some("document".into()),
        access: AuthorizationAccess::Read,
    }
}
fn constraint(id: &str, data_scope: AuthorizationDataScope) -> GrantConstraint {
    GrantConstraint {
        grant_id: id.into(),
        data_scope,
        readable_fields: None,
        writable_fields: None,
        amount_range: None,
        prohibit_initiator: false,
    }
}
fn grant(id: &str, subject: GrantSubjectRef, effect: GrantEffect) -> GrantSnapshot {
    GrantSnapshot {
        id: id.into(),
        subject,
        action_pattern: "business::read".into(),
        scope: ScopeRef::Global,
        effect,
    }
}
fn role() -> GrantSubjectRef {
    GrantSubjectRef::Role {
        role_id: "business:reader".into(),
    }
}
fn document(scope: AuthorizationDataScope) -> AuthorizationProfileDocument {
    AuthorizationProfileDocument {
        resource_model: ResourceModelRegistration {
            actions: vec![ActionKey("business::read".into())],
            ..Default::default()
        },
        action_scope_rules: vec![ActionScopeRule {
            action_pattern: "business::read".into(),
            allowed_scope_kinds: vec![ScopeKind::Workspace, ScopeKind::Project],
        }],
        grants: vec![grant("read", role(), GrantEffect::Allow)],
        grant_constraints: vec![constraint("read", scope)],
        role_bindings: vec![RoleBindingSnapshot {
            principal: account("alice"),
            role_id: "business:reader".into(),
            scope: project("p"),
        }],
        permission_bundles: vec![PermissionBundleMetadata {
            role_id: "business:reader".into(),
            key: "read".into(),
            name: "Read".into(),
            owner_scope: workspace("w"),
            source_id: "test".into(),
            source_revision: "1".into(),
            source_digest: "test".into(),
        }],
        ..Default::default()
    }
}
fn policy(document: AuthorizationProfileDocument) -> PolicySet {
    PolicySet::from_profile(&AuthorizationProfile {
        namespace: NamespaceId("business".into()),
        revision: 1,
        lifecycle: ProfileLifecycle::Active,
        document,
        checksum: "fixture".into(),
        created_at: Timestamp("2026-11-10T00:00:00Z".into()),
    })
}
fn matches(
    predicate: &ResourceCandidatePredicate,
    facts: &AuthorizationContext,
    scope: &ScopeRef,
) -> bool {
    match predicate {
        ResourceCandidatePredicate::All => true,
        ResourceCandidatePredicate::None => false,
        ResourceCandidatePredicate::OwnerIn { principals } => facts
            .owner
            .as_ref()
            .is_some_and(|value| principals.contains(value)),
        ResourceCandidatePredicate::ResponsibleIn { principals } => facts
            .responsible
            .as_ref()
            .is_some_and(|value| principals.contains(value)),
        ResourceCandidatePredicate::GroupAny { groups } => facts
            .groups
            .as_ref()
            .is_some_and(|values| values.iter().any(|value| groups.contains(value))),
        ResourceCandidatePredicate::ResourceIdsOrPredecessors { resource_ids } => {
            facts
                .resource_id
                .as_ref()
                .is_some_and(|value| resource_ids.contains(value))
                || facts
                    .predecessors
                    .iter()
                    .any(|value| &value.scope == scope && resource_ids.contains(&value.resource_id))
        }
        ResourceCandidatePredicate::And { predicates } => predicates
            .iter()
            .all(|predicate| matches(predicate, facts, scope)),
        ResourceCandidatePredicate::Or { predicates } => predicates
            .iter()
            .any(|predicate| matches(predicate, facts, scope)),
    }
}

fn oracle(policy: &PolicySet, query: &ResourceCandidateRequest, now: i64) -> (usize, usize) {
    let plan = policy.resource_candidates(query, now).unwrap();
    assert!(plan.predicate.within_limits());
    let mut allowed = 0;
    let mut excluded = 0;
    for owner in [None, Some(account("alice")), Some(account("bob"))] {
        for responsible in [None, Some(account("alice")), Some(service("agent"))] {
            for groups in [
                None,
                Some(vec![]),
                Some(vec!["team-a".into()]),
                Some(vec!["team-a".into(), "team-b".into()]),
            ] {
                for id in ["one", "two", "migrated"] {
                    for predecessors in [
                        vec![],
                        vec![AuthorizationPredecessor {
                            resource_id: "one".into(),
                            scope: query.request.scope.clone(),
                        }],
                        vec![AuthorizationPredecessor {
                            resource_id: "two".into(),
                            scope: project("foreign"),
                        }],
                    ] {
                        let facts = AuthorizationContext {
                            evaluated_at: Some(now),
                            resource_id: Some(id.into()),
                            resource_type: Some("document".into()),
                            owner: owner.clone(),
                            responsible: responsible.clone(),
                            groups: groups.clone(),
                            predecessors,
                            access: AuthorizationAccess::Read,
                            fields: Some(vec!["label".into()]),
                            amount: Some(AuthorizationAmount {
                                currency: "CNY".into(),
                                minor_units: 100,
                            }),
                            initiator: Some(account("bob")),
                            ..Default::default()
                        };
                        let decision = policy.evaluate_resource(&ResourceAuthorizationRequest {
                            request: query.request.clone(),
                            context: facts.clone(),
                        });
                        let candidate = matches(&plan.predicate, &facts, &query.request.scope);
                        if decision.decision == AuthorizationDecision::Allow {
                            allowed += 1;
                            assert!(
                                candidate,
                                "native Allow excluded by {:?}; facts={facts:?}",
                                plan.predicate
                            );
                        }
                        if !candidate {
                            excluded += 1;
                        }
                    }
                }
            }
        }
    }
    (allowed, excluded)
}

#[test]
fn owner_and_responsible_are_real_sparse_native_supersets() {
    for scope in [
        AuthorizationDataScope::Owner,
        AuthorizationDataScope::Responsible,
    ] {
        let policy = policy(document(scope));
        let (allowed, excluded) = oracle(&policy, &query(), 100);
        assert!(
            allowed > 0 && excluded > 0,
            "neither a stub All nor a vacuous empty plan"
        );
    }
}

#[test]
fn empty_role_paths_cannot_hide_direct_group_or_platform_allow_alternatives() {
    for subject in [
        GrantSubjectRef::Principal {
            principal: account("alice"),
        },
        GrantSubjectRef::Group {
            group_id: "team-a".into(),
        },
    ] {
        let mut doc = document(AuthorizationDataScope::Owner);
        doc.role_bindings.clear();
        doc.grants
            .push(grant("alternative", subject, GrantEffect::Allow));
        doc.grant_constraints
            .push(constraint("alternative", AuthorizationDataScope::Owner));
        let mut native = policy(doc);
        native.add_group_member(GroupId("team-a".into()), account("alice"));
        let (allowed, excluded) = oracle(&native, &query(), 100);
        assert!(allowed > 0 && excluded > 0);
    }
    // Core has no special controller/admin role name. An actual native global
    // wildcard Allow remains broad even when every named role is empty.
    let mut doc = document(AuthorizationDataScope::Owner);
    doc.role_bindings.clear();
    let mut platform = grant(
        "platform",
        GrantSubjectRef::Principal {
            principal: account("alice"),
        },
        GrantEffect::Allow,
    );
    platform.action_pattern = "*".into();
    doc.grants.push(platform);
    let native = policy(doc);
    assert_eq!(
        native.resource_candidates(&query(), 100).unwrap().predicate,
        ResourceCandidatePredicate::All
    );
    assert!(oracle(&native, &query(), 100).0 > 0);
}

#[test]
fn grant_union_and_delegation_intersection_keep_both_native_constraints() {
    let mut doc = document(AuthorizationDataScope::Owner);
    doc.grants
        .push(grant("responsible", role(), GrantEffect::Allow));
    doc.grant_constraints.push(constraint(
        "responsible",
        AuthorizationDataScope::Responsible,
    ));
    let union = policy(doc.clone());
    assert!(matches!(
        union.resource_candidates(&query(), 100).unwrap().predicate,
        ResourceCandidatePredicate::Or { .. }
    ));
    oracle(&union, &query(), 100);
    doc.grants.push(grant(
        "agent",
        GrantSubjectRef::Principal {
            principal: service("agent"),
        },
        GrantEffect::Allow,
    ));
    doc.grant_constraints
        .push(constraint("agent", AuthorizationDataScope::Responsible));
    let policy = policy(doc);
    let mut query = query();
    query.request.on_behalf_of.push(service("agent"));
    let plan = policy.resource_candidates(&query, 100).unwrap();
    assert!(matches!(
        plan.predicate,
        ResourceCandidatePredicate::And { .. }
    ));
    let (allowed, excluded) = oracle(&policy, &query, 100);
    assert!(allowed > 0 && excluded > 0);
    query.request.on_behalf_of.push(service("ungranted"));
    assert_eq!(
        policy.resource_candidates(&query, 100).unwrap().predicate,
        ResourceCandidatePredicate::None
    );
    assert_eq!(oracle(&policy, &query, 100).0, 0);
}

#[test]
fn live_group_paths_and_binding_group_share_native_roster_and_limits() {
    let mut doc = document(AuthorizationDataScope::BindingGroup);
    doc.role_bindings.clear();
    doc.group_role_bindings.push(GroupRoleBindingSnapshot {
        group_id: "team-a".into(),
        role_id: "business:reader".into(),
        scope: project("p"),
    });
    doc.binding_limits.push(RoleBindingLimit {
        subject: GrantSubjectRef::Group {
            group_id: "team-a".into(),
        },
        role_id: "business:reader".into(),
        scope: project("p"),
        expires_at: Some(200),
        resource_ids: Some(vec!["one".into()]),
    });
    let mut policy = policy(doc);
    assert_eq!(
        policy.resource_candidates(&query(), 100).unwrap().predicate,
        ResourceCandidatePredicate::None
    );
    policy.add_group_member(GroupId("team-a".into()), account("alice"));
    let (allowed, excluded) = oracle(&policy, &query(), 100);
    assert!(allowed > 0 && excluded > 0);
    assert_eq!(oracle(&policy, &query(), 200).0, 0);
    let before_expiry = policy.resource_candidates(&query(), 100).unwrap();
    let after_expiry = policy.resource_candidates(&query(), 200).unwrap();
    let after_clock_rollback = policy.resource_candidates(&query(), 50).unwrap();
    assert_eq!(before_expiry, after_expiry);
    assert_eq!(after_expiry, after_clock_rollback);
    assert!(
        after_expiry
            .broadening_reasons
            .contains(&ResourceCandidateReason::ExpiryDeferred)
    );
    assert!(oracle(&policy, &query(), 50).0 > 0);
    policy.remove_group_member(&GroupId("team-a".into()), &account("alice"));
    assert_eq!(
        policy.resource_candidates(&query(), 100).unwrap().predicate,
        ResourceCandidatePredicate::None
    );
}

#[test]
fn native_binding_ids_include_same_scope_predecessors_and_intersect_limits_per_row() {
    let mut doc = document(AuthorizationDataScope::Owner);
    for id in ["one", "two"] {
        doc.binding_limits.push(RoleBindingLimit {
            subject: GrantSubjectRef::Principal {
                principal: account("alice"),
            },
            role_id: "business:reader".into(),
            scope: project("p"),
            expires_at: None,
            resource_ids: Some(vec![id.into()]),
        });
    }
    let policy = policy(doc);
    let query = query();
    let facts = AuthorizationContext {
        evaluated_at: Some(100),
        owner: Some(account("alice")),
        resource_id: Some("migrated".into()),
        predecessors: vec![
            AuthorizationPredecessor {
                resource_id: "one".into(),
                scope: project("p"),
            },
            AuthorizationPredecessor {
                resource_id: "two".into(),
                scope: project("p"),
            },
        ],
        ..Default::default()
    };
    assert_eq!(
        policy
            .evaluate_resource(&ResourceAuthorizationRequest {
                request: query.request.clone(),
                context: facts.clone()
            })
            .decision,
        AuthorizationDecision::Allow
    );
    assert!(matches(
        &policy.resource_candidates(&query, 100).unwrap().predicate,
        &facts,
        &query.request.scope
    ));
    oracle(&policy, &query, 100);
}

#[test]
fn physical_workspace_and_project_scopes_are_never_inferred_from_a_display_project() {
    let mut doc = document(AuthorizationDataScope::Owner);
    doc.role_bindings[0].scope = workspace("w");
    let policy = policy(doc);
    for scope in [workspace("w"), project("p"), project("sibling")] {
        let mut query = query();
        query.request.scope = scope;
        assert!(oracle(&policy, &query, 100).0 > 0);
    }
    let mut foreign = query();
    foreign.request.scope = workspace("foreign");
    assert_eq!(
        policy.resource_candidates(&foreign, 100).unwrap().predicate,
        ResourceCandidatePredicate::None
    );
    assert_eq!(oracle(&policy, &foreign, 100).0, 0);
}

#[test]
fn deny_and_approval_are_deferred_while_actual_pdp_keeps_precedence() {
    for effect in [GrantEffect::Deny, GrantEffect::RequireApproval] {
        let mut doc = document(AuthorizationDataScope::Owner);
        doc.grants.push(grant("ceiling", role(), effect));
        doc.grant_constraints
            .push(constraint("ceiling", AuthorizationDataScope::Responsible));
        let policy = policy(doc);
        let plan = policy.resource_candidates(&query(), 100).unwrap();
        assert!(
            plan.broadening_reasons
                .contains(&if effect == GrantEffect::Deny {
                    ResourceCandidateReason::DenyDeferred
                } else {
                    ResourceCandidateReason::ApprovalDeferred
                })
        );
        assert!(oracle(&policy, &query(), 100).0 > 0);
    }
}

#[test]
fn additional_conjunctive_constraints_preserve_necessary_owner_candidates() {
    for index in 0..4 {
        let mut doc = document(AuthorizationDataScope::Owner);
        let constraint = &mut doc.grant_constraints[0];
        match index {
            0 => {
                constraint.amount_range = Some(AuthorizationAmountRange {
                    currency: "CNY".into(),
                    minimum: Some(1),
                    maximum: Some(1000),
                })
            }
            1 => constraint.prohibit_initiator = true,
            2 => constraint.readable_fields = Some(vec!["label".into()]),
            _ => constraint.writable_fields = Some(vec![]),
        }
        let policy = policy(doc);
        let plan = policy.resource_candidates(&query(), 100).unwrap();
        assert_eq!(
            plan.predicate,
            ResourceCandidatePredicate::OwnerIn {
                principals: vec![account("alice")]
            }
        );
        assert_eq!(
            plan.broadening_reasons,
            vec![ResourceCandidateReason::ComplexGrantConstraint]
        );
        let (allowed, excluded) = oracle(&policy, &query(), 100);
        assert!(allowed > 0 && excluded > 0);
    }
}

#[test]
fn constrained_grant_alternatives_and_delegation_keep_native_allow_rows_without_authorizing_fields()
{
    let mut doc = document(AuthorizationDataScope::Owner);
    doc.grant_constraints[0].readable_fields = Some(vec!["label".into()]);
    doc.grant_constraints[0].amount_range = Some(AuthorizationAmountRange {
        currency: "CNY".into(),
        minimum: Some(1),
        maximum: Some(1000),
    });
    doc.grant_constraints[0].prohibit_initiator = true;
    for (id, subject, data_scope, field) in [
        (
            "alice-responsible",
            role(),
            AuthorizationDataScope::Responsible,
            "private",
        ),
        (
            "agent-responsible",
            GrantSubjectRef::Principal {
                principal: service("agent"),
            },
            AuthorizationDataScope::Responsible,
            "label",
        ),
        (
            "agent-owner",
            GrantSubjectRef::Principal {
                principal: service("agent"),
            },
            AuthorizationDataScope::Owner,
            "private",
        ),
    ] {
        doc.grants.push(grant(id, subject, GrantEffect::Allow));
        let mut required = constraint(id, data_scope);
        required.readable_fields = Some(vec![field.into()]);
        doc.grant_constraints.push(required);
    }
    let native = policy(doc);
    let mut query = query();
    query.request.on_behalf_of.push(service("agent"));
    let plan = native.resource_candidates(&query, 100).unwrap();
    assert!(matches!(
        plan.predicate,
        ResourceCandidatePredicate::And { .. }
    ));
    assert!(
        plan.broadening_reasons
            .contains(&ResourceCandidateReason::ComplexGrantConstraint)
    );
    let (mut allowed, mut excluded, mut selected_but_denied) = (0, 0, 0);
    for owner in [
        None,
        Some(account("alice")),
        Some(service("agent")),
        Some(account("bob")),
    ] {
        for responsible in [
            None,
            Some(account("alice")),
            Some(service("agent")),
            Some(account("bob")),
        ] {
            for fields in [
                None,
                Some(vec![]),
                Some(vec!["label".into()]),
                Some(vec!["private".into()]),
                Some(vec!["label".into(), "private".into()]),
            ] {
                for amount in [
                    None,
                    Some(AuthorizationAmount {
                        currency: "CNY".into(),
                        minor_units: 100,
                    }),
                    Some(AuthorizationAmount {
                        currency: "CNY".into(),
                        minor_units: 2000,
                    }),
                    Some(AuthorizationAmount {
                        currency: "USD".into(),
                        minor_units: 100,
                    }),
                ] {
                    for initiator in [
                        None,
                        Some(account("alice")),
                        Some(service("agent")),
                        Some(account("bob")),
                    ] {
                        let facts = AuthorizationContext {
                            evaluated_at: Some(100),
                            resource_id: Some("one".into()),
                            resource_type: query.resource_type.clone(),
                            owner: owner.clone(),
                            responsible: responsible.clone(),
                            fields: fields.clone(),
                            amount: amount.clone(),
                            initiator,
                            access: AuthorizationAccess::Read,
                            ..Default::default()
                        };
                        let outcome = native.evaluate_resource(&ResourceAuthorizationRequest {
                            request: query.request.clone(),
                            context: facts.clone(),
                        });
                        let selected = matches(&plan.predicate, &facts, &query.request.scope);
                        if outcome.decision == AuthorizationDecision::Allow {
                            allowed += 1;
                            assert!(
                                selected,
                                "native Allow lost its necessary positive path: {facts:?}"
                            );
                        } else if selected {
                            selected_but_denied += 1;
                        }
                        if !selected {
                            excluded += 1;
                        }
                    }
                }
            }
        }
    }
    assert!(
        allowed > 0 && excluded > 0,
        "real sparse superset, neither empty nor All"
    );
    assert!(
        selected_but_denied > 0,
        "candidate matching cannot discharge field/amount/SoD constraints"
    );
}

#[test]
fn finite_plan_budget_never_turns_large_native_id_grants_into_an_empty_set() {
    let mut doc = document(AuthorizationDataScope::Owner);
    doc.binding_limits.push(RoleBindingLimit {
        subject: GrantSubjectRef::Principal {
            principal: account("alice"),
        },
        role_id: "business:reader".into(),
        scope: project("p"),
        expires_at: None,
        resource_ids: Some(vec!["one".into(); RESOURCE_CANDIDATE_VALUE_MAX + 1]),
    });
    let policy = policy(doc);
    let plan = policy.resource_candidates(&query(), 100).unwrap();
    assert_eq!(plan.predicate, ResourceCandidatePredicate::All);
    assert_eq!(
        plan.broadening_reasons,
        vec![ResourceCandidateReason::PlanBudgetExceeded]
    );
    assert!(oracle(&policy, &query(), 100).0 > 0);
}

#[test]
fn personal_or_write_capability_never_silently_selects_an_ordinary_plan() {
    let policy = policy(document(AuthorizationDataScope::Owner));
    let mut query = query();
    query.mode = ResourceAuthorizationMode::PersonalDelegation;
    assert_eq!(
        policy.resource_candidates(&query, 100),
        Err(ResourceCandidateError::UnsupportedMode)
    );
    query.mode = ResourceAuthorizationMode::Scoped;
    query.access = AuthorizationAccess::Write;
    assert_eq!(
        policy.resource_candidates(&query, 100),
        Err(ResourceCandidateError::UnsupportedAccess)
    );
}
