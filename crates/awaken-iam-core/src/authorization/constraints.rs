//! Closed relationship/field checks inside the existing policy evaluator.

use awaken_iam_contract::{
    AuthorizationAccess, AuthorizationContext, AuthorizationDataScope, GrantSubjectRef,
    PrincipalRef, ResourceAuthorizationRequest, ScopeRef,
};

use super::{AuthorizationTrace, Effect, Grant, GrantSubject, PolicySet, RoleId};

pub(super) enum ConstraintMatch {
    Matches,
    Excluded,
    MissingFacts,
}

pub(super) fn binding_time_allows(expiry: Option<i64>, evaluated_at: Option<i64>) -> bool {
    expiry.is_none_or(|expiry| evaluated_at.is_some_and(|now| now >= 0 && now < expiry))
}

impl PolicySet {
    /// Evaluate the same effect lattice with owner-resolved resource facts.
    pub fn evaluate_resource(&self, request: &ResourceAuthorizationRequest) -> AuthorizationTrace {
        let chain = request.request.principal_chain().collect::<Vec<_>>();
        self.evaluate_chain_context(
            &chain,
            &request.request.action,
            &request.request.scope,
            Some(&request.context),
        )
    }

    pub(super) fn bundle_owner_allows(&self, role: &RoleId, scope: &ScopeRef) -> bool {
        self.active_profiles
            .iter()
            .flat_map(|profile| &profile.document.permission_bundles)
            .filter(|bundle| bundle.role_id == role.0)
            .all(|bundle| self.scope_graph.covers(&bundle.owner_scope, scope))
    }

    pub(super) fn binding_limit_allows(
        &self,
        subject: &GrantSubjectRef,
        role: &RoleId,
        binding_scope: &ScopeRef,
        target_scope: &ScopeRef,
        context: Option<&AuthorizationContext>,
    ) -> bool {
        self.matching_binding_limits(subject, role, binding_scope)
            .all(|limit| {
                if !binding_time_allows(
                    limit.expires_at,
                    context.and_then(|facts| facts.evaluated_at),
                ) {
                    return false;
                }
                limit.resource_ids.as_ref().is_none_or(|allowed| {
                    context
                        .is_some_and(|facts| resource_limit_matches(allowed, facts, target_scope))
                })
            })
    }

    pub(super) fn matching_binding_limits<'a>(
        &'a self,
        subject: &'a GrantSubjectRef,
        role: &'a RoleId,
        binding_scope: &'a ScopeRef,
    ) -> impl Iterator<Item = &'a awaken_iam_contract::RoleBindingLimit> + 'a {
        self.binding_limits.iter().filter(move |limit| {
            &limit.subject == subject && limit.role_id == role.0 && &limit.scope == binding_scope
        })
    }

    pub(super) fn constraint_matches(
        &self,
        grant: &Grant,
        principal: &PrincipalRef,
        scope: &ScopeRef,
        context: Option<&AuthorizationContext>,
    ) -> ConstraintMatch {
        let Some(constraint) = self.grant_constraints.get(&grant.id) else {
            return ConstraintMatch::Matches;
        };
        let Some(facts) = context else {
            return ConstraintMatch::MissingFacts;
        };
        let related = match constraint.data_scope {
            AuthorizationDataScope::AuthorizedScope => true,
            AuthorizationDataScope::Owner => {
                let Some(owner) = &facts.owner else {
                    return ConstraintMatch::MissingFacts;
                };
                owner == principal
            }
            AuthorizationDataScope::Responsible => {
                let Some(responsible) = &facts.responsible else {
                    return ConstraintMatch::MissingFacts;
                };
                responsible == principal
            }
            AuthorizationDataScope::BindingGroup => {
                let Some(groups) = &facts.groups else {
                    return ConstraintMatch::MissingFacts;
                };
                match &grant.subject {
                    GrantSubject::Group(group) => groups.contains(&group.0),
                    GrantSubject::Role(role) => self.group_role_bindings.iter().any(|binding| {
                        &binding.role == role
                            && self.group_contains(&binding.group, principal)
                            && self.scope_graph.covers(&binding.scope, scope)
                            && groups.contains(&binding.group.0)
                            && self.binding_limit_allows(
                                &GrantSubjectRef::Group {
                                    group_id: binding.group.0.clone(),
                                },
                                role,
                                &binding.scope,
                                scope,
                                context,
                            )
                    }),
                    GrantSubject::Principal(_) => false,
                }
            }
        };
        if !related {
            return ConstraintMatch::Excluded;
        }
        if constraint.prohibit_initiator {
            let Some(initiator) = &facts.initiator else {
                return ConstraintMatch::MissingFacts;
            };
            if initiator == principal {
                return ConstraintMatch::Excluded;
            }
        }
        if let Some(range) = &constraint.amount_range {
            let Some(amount) = &facts.amount else {
                return ConstraintMatch::MissingFacts;
            };
            if amount.currency != range.currency {
                return ConstraintMatch::MissingFacts;
            }
            if range
                .minimum
                .is_some_and(|minimum| amount.minor_units < minimum)
                || range
                    .maximum
                    .is_some_and(|maximum| amount.minor_units > maximum)
            {
                return ConstraintMatch::Excluded;
            }
        }
        let allowed = match facts.access {
            AuthorizationAccess::Read => &constraint.readable_fields,
            AuthorizationAccess::Write => &constraint.writable_fields,
            AuthorizationAccess::Operate => {
                if constraint.readable_fields.is_some() || constraint.writable_fields.is_some() {
                    return ConstraintMatch::MissingFacts;
                }
                return ConstraintMatch::Matches;
            }
        };
        if let Some(allowed) = allowed {
            let Some(requested) = &facts.fields else {
                return ConstraintMatch::MissingFacts;
            };
            let matches = match grant.effect {
                Effect::Allow => requested.iter().all(|field| allowed.contains(field)),
                Effect::Deny | Effect::RequireApproval => {
                    requested.iter().any(|field| allowed.contains(field))
                }
            };
            if !matches {
                return ConstraintMatch::Excluded;
            }
        }
        ConstraintMatch::Matches
    }
}

fn resource_limit_matches(
    allowed: &[String],
    facts: &AuthorizationContext,
    scope: &ScopeRef,
) -> bool {
    let Some(id) = facts.resource_id.as_ref().filter(|id| !id.is_empty()) else {
        return false;
    };
    if allowed.contains(id) {
        return true;
    }
    let predecessors = &facts.predecessors;
    if predecessors.len() > 32
        || predecessors.iter().any(|p| {
            &p.scope != scope
                || p.resource_id.is_empty()
                || p.resource_id.len() > 512
                || p.resource_id.chars().any(char::is_control)
                || &p.resource_id == id
        })
        || predecessors
            .iter()
            .map(|p| &p.resource_id)
            .collect::<std::collections::BTreeSet<_>>()
            .len()
            != predecessors.len()
    {
        return false;
    }
    predecessors
        .iter()
        .any(|p| allowed.contains(&p.resource_id))
}
