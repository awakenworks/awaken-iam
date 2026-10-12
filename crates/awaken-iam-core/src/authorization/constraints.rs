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
        context: Option<&AuthorizationContext>,
    ) -> bool {
        self.binding_limits
            .iter()
            .filter(|limit| {
                &limit.subject == subject
                    && limit.role_id == role.0
                    && &limit.scope == binding_scope
            })
            .all(|limit| {
                if let Some(expiry) = limit.expires_at
                    && !context
                        .and_then(|facts| facts.evaluated_at)
                        .is_some_and(|now| now >= 0 && now < expiry)
                {
                    return false;
                }
                limit.resource_ids.as_ref().is_none_or(|allowed| {
                    context
                        .and_then(|facts| facts.resource_id.as_ref())
                        .is_some_and(|id| allowed.contains(id))
                })
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
