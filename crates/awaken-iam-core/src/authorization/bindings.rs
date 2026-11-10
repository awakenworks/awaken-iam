//! Native role eligibility shared by PDP evaluation and positive planning.
use super::*;

pub(super) struct ApplicableRoleBinding<'a> {
    pub role: &'a RoleId,
    pub subject: GrantSubjectRef,
    pub scope: &'a ScopeRef,
    pub group: Option<&'a GroupId>,
}

impl PolicySet {
    pub(super) fn applicable_role_bindings<'a>(
        &'a self,
        principal: &'a PrincipalRef,
        scope: &'a ScopeRef,
    ) -> impl Iterator<Item = ApplicableRoleBinding<'a>> + 'a {
        let direct = self
            .role_bindings
            .iter()
            .filter(move |binding| {
                &binding.principal == principal
                    && self.scope_graph.covers(&binding.scope, scope)
                    && self.bundle_owner_allows(&binding.role, scope)
            })
            .map(move |binding| ApplicableRoleBinding {
                role: &binding.role,
                subject: GrantSubjectRef::Principal {
                    principal: principal.clone(),
                },
                scope: &binding.scope,
                group: None,
            });
        let groups = self
            .group_role_bindings
            .iter()
            .filter(move |binding| {
                self.group_contains(&binding.group, principal)
                    && self.scope_graph.covers(&binding.scope, scope)
                    && self.bundle_owner_allows(&binding.role, scope)
            })
            .map(|binding| ApplicableRoleBinding {
                role: &binding.role,
                subject: GrantSubjectRef::Group {
                    group_id: binding.group.0.clone(),
                },
                scope: &binding.scope,
                group: Some(&binding.group),
            });
        direct.chain(groups)
    }
}
