//! Compile native Allow paths into a bounded positive superset. This does not
//! evaluate a Resource, enumerate product data or replace the native PDP.
use super::{Effect, Grant, GrantSubject, PolicySet, RoleId};
use awaken_iam_contract::{
    AuthorizationAccess, AuthorizationDataScope, GrantSubjectRef, PrincipalRef,
    RESOURCE_AUTHORIZATION_CHAIN_MAX, RESOURCE_CANDIDATE_NODE_MAX, RESOURCE_CANDIDATE_VALUE_MAX,
    ResourceAuthorizationMode, ResourceCandidatePlan, ResourceCandidatePredicate as Predicate,
    ResourceCandidateReason as Reason, ResourceCandidateRequest, ScopeRef,
};

#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum ResourceCandidateError {
    #[error("personal delegation candidate planning is unsupported")]
    UnsupportedMode,
    #[error("candidate planning supports ordinary scoped reads only")]
    UnsupportedAccess,
    #[error("candidate planning requires a current nonnegative server time")]
    InvalidTime,
}

struct Budget {
    nodes: usize,
    values: usize,
}
#[derive(Debug)]
struct Limit;

impl Budget {
    fn charge(&mut self, values: usize) -> Result<(), Limit> {
        self.nodes = self.nodes.saturating_add(1);
        self.values = self.values.saturating_add(values);
        if self.nodes > RESOURCE_CANDIDATE_NODE_MAX || self.values > RESOURCE_CANDIDATE_VALUE_MAX {
            Err(Limit)
        } else {
            Ok(())
        }
    }
    fn strings(&mut self, values: &[String]) -> Result<(), Limit> {
        if values
            .iter()
            .any(|value| value.len() > 512 || value.chars().any(char::is_control))
        {
            return Err(Limit);
        }
        self.charge(values.len())
    }
    fn principal(&mut self, principal: &PrincipalRef) -> Result<(), Limit> {
        let value = match principal {
            PrincipalRef::Account { account_id } => &account_id.0,
            PrincipalRef::Service { service_id } => service_id,
            PrincipalRef::ApiToken { token_id } => token_id,
        };
        if value.len() > 512 || value.chars().any(char::is_control) {
            return Err(Limit);
        }
        self.charge(1)
    }
    fn combine(&mut self, conjunction: bool, terms: Vec<Predicate>) -> Result<Predicate, Limit> {
        self.charge(0)?;
        let mut kept = Vec::new();
        for term in terms {
            match (conjunction, term) {
                (true, Predicate::None) => return Ok(Predicate::None),
                (false, Predicate::All) => return Ok(Predicate::All),
                (true, Predicate::All) | (false, Predicate::None) => {}
                (true, Predicate::And { predicates }) | (false, Predicate::Or { predicates }) => {
                    kept.extend(predicates)
                }
                (_, other) => kept.push(other),
            }
        }
        Ok(match kept.len() {
            0 if conjunction => Predicate::All,
            0 => Predicate::None,
            1 => kept.pop().unwrap(),
            _ if conjunction => Predicate::And { predicates: kept },
            _ => Predicate::Or { predicates: kept },
        })
    }
}

fn reason(reasons: &mut Vec<Reason>, value: Reason) {
    if !reasons.contains(&value) {
        reasons.push(value);
    }
}

impl PolicySet {
    /// Plan against the *same* current native PolicySet used for evaluation.
    /// The caller supplies trusted server time; resource data remains entirely
    /// consumer-owned. Every native Allow belongs to this candidate superset.
    pub fn resource_candidates(
        &self,
        request: &ResourceCandidateRequest,
        evaluated_at: i64,
    ) -> Result<ResourceCandidatePlan, ResourceCandidateError> {
        if request.mode != ResourceAuthorizationMode::Scoped {
            return Err(ResourceCandidateError::UnsupportedMode);
        }
        if request.access != AuthorizationAccess::Read {
            return Err(ResourceCandidateError::UnsupportedAccess);
        }
        if evaluated_at < 0 {
            return Err(ResourceCandidateError::InvalidTime);
        }
        let mut reasons = Vec::new();
        let mut budget = Budget {
            nodes: 0,
            values: 0,
        };
        let all = |value, observed: &[Reason]| {
            let mut reasons = observed.to_vec();
            reason(&mut reasons, value);
            ResourceCandidatePlan {
                predicate: Predicate::All,
                broadening_reasons: reasons,
            }
        };
        if request.request.on_behalf_of.len() >= RESOURCE_AUTHORIZATION_CHAIN_MAX {
            return Ok(all(Reason::PlanBudgetExceeded, &reasons));
        }
        if self.profile_governs(&request.request.action)
            && !self.scope_kind_allowed(&request.request.action, &request.request.scope)
        {
            return Ok(ResourceCandidatePlan {
                predicate: Predicate::None,
                broadening_reasons: reasons,
            });
        }
        let mut chain = Vec::new();
        for principal in request.request.principal_chain() {
            let mut alternatives = Vec::new();
            for grant in &self.grants {
                if !grant.action_pattern.matches(&request.request.action)
                    || !self
                        .scope_graph
                        .covers(&grant.scope, &request.request.scope)
                {
                    continue;
                }
                if grant.effect != Effect::Allow {
                    reason(
                        &mut reasons,
                        if grant.effect == Effect::Deny {
                            Reason::DenyDeferred
                        } else {
                            Reason::ApprovalDeferred
                        },
                    );
                    continue;
                }
                let term = match self.grant_candidate(
                    grant,
                    principal,
                    &request.request.scope,
                    &mut budget,
                    &mut reasons,
                ) {
                    Ok(term) => term,
                    Err(_) => return Ok(all(Reason::PlanBudgetExceeded, &reasons)),
                };
                if term == Predicate::None {
                    continue;
                }
                if self
                    .grant_constraints
                    .get(&grant.id)
                    .is_some_and(|constraint| {
                        constraint.amount_range.is_some()
                            || constraint.prohibit_initiator
                            || constraint.readable_fields.is_some()
                            || constraint.writable_fields.is_some()
                    })
                {
                    // These checks are additional conjuncts after native data
                    // scope matching. Deferring them broadens this Allow path
                    // while preserving its necessary owner/group/id selectors.
                    // The actual row/field PDP still enforces every conjunct.
                    reason(&mut reasons, Reason::ComplexGrantConstraint);
                }
                alternatives.push(term);
            }
            match budget.combine(false, alternatives) {
                Ok(term) => chain.push(term),
                Err(_) => return Ok(all(Reason::PlanBudgetExceeded, &reasons)),
            }
        }
        let predicate = match budget.combine(true, chain) {
            Ok(predicate) if predicate.within_limits() => predicate,
            _ => return Ok(all(Reason::PlanBudgetExceeded, &reasons)),
        };
        Ok(ResourceCandidatePlan {
            predicate,
            broadening_reasons: reasons,
        })
    }

    fn binding_candidate(
        &self,
        subject: &GrantSubjectRef,
        role: &RoleId,
        binding_scope: &ScopeRef,
        budget: &mut Budget,
        reasons: &mut Vec<Reason>,
    ) -> Result<Predicate, Limit> {
        let mut terms = Vec::new();
        for limit in self.matching_binding_limits(subject, role, binding_scope) {
            // Time can move backwards and freshness is not a time lease. An
            // expired path may therefore become active again without a policy
            // fence change. Keep its necessary positive selectors and let the
            // unchanged current native PDP enforce expiry on every actual use.
            if limit.expires_at.is_some() {
                reason(reasons, Reason::ExpiryDeferred);
            }
            if let Some(ids) = &limit.resource_ids {
                if ids.is_empty() {
                    return Ok(Predicate::None);
                }
                budget.strings(ids)?;
                terms.push(Predicate::ResourceIdsOrPredecessors {
                    resource_ids: ids.clone(),
                });
            }
        }
        budget.combine(true, terms)
    }

    fn data_candidate(
        &self,
        grant: &Grant,
        principal: &PrincipalRef,
        group: Option<&crate::GroupId>,
        budget: &mut Budget,
    ) -> Result<Predicate, Limit> {
        let scope = self
            .grant_constraints
            .get(&grant.id)
            .map(|value| value.data_scope)
            .unwrap_or_default();
        match scope {
            AuthorizationDataScope::AuthorizedScope => {
                budget.charge(0)?;
                Ok(Predicate::All)
            }
            AuthorizationDataScope::Owner => {
                budget.principal(principal)?;
                Ok(Predicate::OwnerIn {
                    principals: vec![principal.clone()],
                })
            }
            AuthorizationDataScope::Responsible => {
                budget.principal(principal)?;
                Ok(Predicate::ResponsibleIn {
                    principals: vec![principal.clone()],
                })
            }
            AuthorizationDataScope::BindingGroup => match group {
                Some(group) => {
                    budget.strings(std::slice::from_ref(&group.0))?;
                    Ok(Predicate::GroupAny {
                        groups: vec![group.0.clone()],
                    })
                }
                None => Ok(Predicate::None),
            },
        }
    }

    fn grant_candidate(
        &self,
        grant: &Grant,
        principal: &PrincipalRef,
        scope: &ScopeRef,
        budget: &mut Budget,
        reasons: &mut Vec<Reason>,
    ) -> Result<Predicate, Limit> {
        match &grant.subject {
            GrantSubject::Principal(named) if named == principal => {
                self.data_candidate(grant, principal, None, budget)
            }
            GrantSubject::Group(group) if self.group_contains(group, principal) => {
                self.data_candidate(grant, principal, Some(group), budget)
            }
            GrantSubject::Role(role) => {
                let mut paths = Vec::new();
                for binding in self
                    .applicable_role_bindings(principal, scope)
                    .filter(|binding| binding.role == role)
                {
                    let limit = self.binding_candidate(
                        &binding.subject,
                        role,
                        binding.scope,
                        budget,
                        reasons,
                    )?;
                    if limit == Predicate::None {
                        continue;
                    }
                    let related = self.data_candidate(grant, principal, binding.group, budget)?;
                    paths.push(budget.combine(true, vec![limit, related])?);
                }
                budget.combine(false, paths)
            }
            _ => Ok(Predicate::None),
        }
    }
}
