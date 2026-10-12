//! Validation of metadata and limits on existing profile policy records.

use std::collections::HashSet;

use awaken_iam_contract::{
    AuthorizationDataScope, AuthorizationProfileDocument, GrantSubjectRef, NamespaceId, ScopeRef,
};

pub(super) fn validate(
    namespace: &NamespaceId,
    document: &AuthorizationProfileDocument,
    errors: &mut Vec<String>,
) {
    let mut grants = HashSet::new();
    for grant in &document.grants {
        if !grants.insert(&grant.id) {
            errors.push(format!("duplicate grant id {}", grant.id));
        }
    }
    let mut constrained = HashSet::new();
    for constraint in &document.grant_constraints {
        if !constrained.insert(&constraint.grant_id) {
            errors.push(format!(
                "duplicate grant constraint {}",
                constraint.grant_id
            ));
        }
        let Some(grant) = document
            .grants
            .iter()
            .find(|grant| grant.id == constraint.grant_id)
        else {
            errors.push(format!(
                "constraint references unknown grant {}",
                constraint.grant_id
            ));
            continue;
        };
        if constraint.data_scope == AuthorizationDataScope::BindingGroup
            && matches!(grant.subject, GrantSubjectRef::Principal { .. })
        {
            errors.push(format!(
                "binding_group needs a Role or Group grant: {}",
                grant.id
            ));
        }
        for fields in [&constraint.readable_fields, &constraint.writable_fields]
            .into_iter()
            .flatten()
        {
            let mut seen = HashSet::new();
            for field in fields {
                if !valid_text(field, 240) || field == "*" || !seen.insert(field) {
                    errors.push(format!(
                        "invalid or duplicate field constraint on {}",
                        grant.id
                    ));
                }
            }
        }
        if let Some(range) = &constraint.amount_range {
            if range.currency.len() != 3
                || !range.currency.bytes().all(|byte| byte.is_ascii_uppercase())
            {
                errors.push(format!(
                    "amount range needs an exact uppercase currency on {}",
                    grant.id
                ));
            }
            if range.minimum.is_none() && range.maximum.is_none()
                || matches!((range.minimum, range.maximum), (Some(minimum), Some(maximum)) if minimum > maximum)
            {
                errors.push(format!("amount range has invalid bounds on {}", grant.id));
            }
        }
    }
    let prefix = format!("{}:", namespace.0);
    let mut bundles = HashSet::new();
    let mut keys = HashSet::new();
    for bundle in &document.permission_bundles {
        if !bundle.role_id.starts_with(&prefix) || !bundles.insert(&bundle.role_id) {
            errors.push(format!(
                "invalid or duplicate bundle role {}",
                bundle.role_id
            ));
        }
        if !document.grants.iter().any(|grant| {
            matches!(&grant.subject,
            GrantSubjectRef::Role { role_id } if role_id == &bundle.role_id)
        }) {
            errors.push(format!("bundle has no Role grants: {}", bundle.role_id));
        }
        if !valid_text(&bundle.key, 128)
            || !keys.insert((&bundle.owner_scope, &bundle.key))
            || !valid_text(&bundle.name, 240)
        {
            errors.push(format!(
                "invalid or duplicate bundle identity {}",
                bundle.role_id
            ));
        }
        if !matches!(
            bundle.owner_scope,
            ScopeRef::Org { .. } | ScopeRef::Workspace { .. } | ScopeRef::Project { .. }
        ) {
            errors.push(format!(
                "bundle owner must be an enterprise scope: {}",
                bundle.role_id
            ));
        }
        if !valid_text(&bundle.source_id, 512)
            || !valid_text(&bundle.source_revision, 240)
            || !bundle
                .source_digest
                .strip_prefix("sha256:")
                .is_some_and(|digest| {
                    digest.len() == 64 && digest.bytes().all(|byte| byte.is_ascii_hexdigit())
                })
        {
            errors.push(format!(
                "bundle source must identify an exact revision: {}",
                bundle.role_id
            ));
        }
        for binding in &document.role_bindings {
            if binding.role_id == bundle.role_id
                && !structurally_possible(&bundle.owner_scope, &binding.scope)
            {
                errors.push(format!(
                    "role binding is outside bundle owner: {}",
                    bundle.role_id
                ));
            }
        }
        for binding in &document.group_role_bindings {
            if binding.role_id == bundle.role_id
                && !structurally_possible(&bundle.owner_scope, &binding.scope)
            {
                errors.push(format!(
                    "Group binding is outside bundle owner: {}",
                    bundle.role_id
                ));
            }
        }
    }
    let mut limits = HashSet::new();
    for limit in &document.binding_limits {
        let identity = serde_json::to_string(&(&limit.subject, &limit.role_id, &limit.scope))
            .expect("binding identity serializes");
        if !limits.insert(identity) {
            errors.push(format!("duplicate binding limit for {}", limit.role_id));
        }
        let exists = match &limit.subject {
            GrantSubjectRef::Principal { principal } => {
                document.role_bindings.iter().any(|binding| {
                    &binding.principal == principal
                        && binding.role_id == limit.role_id
                        && binding.scope == limit.scope
                })
            }
            GrantSubjectRef::Group { group_id } => {
                document.group_role_bindings.iter().any(|binding| {
                    &binding.group_id == group_id
                        && binding.role_id == limit.role_id
                        && binding.scope == limit.scope
                })
            }
            GrantSubjectRef::Role { .. } => false,
        };
        if !exists || limit.expires_at.is_some_and(|expiry| expiry <= 0) {
            errors.push(format!(
                "binding limit references an invalid binding: {}",
                limit.role_id
            ));
        }
        if let Some(ids) = &limit.resource_ids {
            let unique = ids.iter().collect::<HashSet<_>>();
            if ids.is_empty()
                || unique.len() != ids.len()
                || ids.iter().any(|id| !valid_text(id, 512))
            {
                errors.push(format!("exact resource set is invalid: {}", limit.role_id));
            }
        }
    }
}

fn valid_text(value: &str, maximum: usize) -> bool {
    !value.trim().is_empty()
        && value == value.trim()
        && value.chars().count() <= maximum
        && !value.chars().any(char::is_control)
}

/// Org/resource ancestry is resolved by the current PDP scope graph at runtime.
fn structurally_possible(owner: &ScopeRef, binding: &ScopeRef) -> bool {
    match (owner, binding) {
        (_, ScopeRef::Global | ScopeRef::Namespace { .. }) => false,
        (ScopeRef::Org { org_id: owner }, ScopeRef::Org { org_id: binding }) => owner == binding,
        (ScopeRef::Org { .. }, _) => true,
        (
            ScopeRef::Workspace {
                workspace_id: owner,
            },
            ScopeRef::Workspace {
                workspace_id: binding,
            },
        )
        | (
            ScopeRef::Workspace {
                workspace_id: owner,
            },
            ScopeRef::Project {
                workspace_id: binding,
                ..
            },
        ) => owner == binding,
        (ScopeRef::Project { .. }, ScopeRef::Project { .. }) => owner == binding,
        (_, ScopeRef::Resource { .. }) => true,
        _ => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use awaken_iam_contract::{
        AuthorizationAmountRange, GrantConstraint, GrantEffect, GrantSnapshot,
    };

    fn document() -> AuthorizationProfileDocument {
        AuthorizationProfileDocument {
            grants: vec![GrantSnapshot {
                id: "business:read".into(),
                subject: GrantSubjectRef::Role {
                    role_id: "business:sales".into(),
                },
                action_pattern: "business::customer.read".into(),
                scope: ScopeRef::Global,
                effect: GrantEffect::Allow,
            }],
            ..Default::default()
        }
    }

    #[test]
    fn constraints_reject_unknown_grants_duplicate_fields_and_invalid_amounts() {
        let mut document = document();
        document.grant_constraints.push(GrantConstraint {
            grant_id: "business:missing".into(),
            data_scope: AuthorizationDataScope::Owner,
            readable_fields: None,
            writable_fields: None,
            amount_range: None,
            prohibit_initiator: false,
        });
        let mut errors = Vec::new();
        validate(&NamespaceId("business".into()), &document, &mut errors);
        assert!(errors.iter().any(|error| error.contains("unknown grant")));
        document.grant_constraints[0].grant_id = "business:read".into();
        document.grant_constraints[0].readable_fields = Some(vec!["name".into(), "name".into()]);
        document.grant_constraints[0].amount_range = Some(AuthorizationAmountRange {
            currency: "cny".into(),
            minimum: Some(200),
            maximum: Some(100),
        });
        errors.clear();
        validate(&NamespaceId("business".into()), &document, &mut errors);
        assert_eq!(errors.len(), 3);
    }

    #[test]
    fn exact_object_limits_require_a_real_binding_and_nonempty_object_set() {
        let mut document = document();
        document
            .binding_limits
            .push(awaken_iam_contract::RoleBindingLimit {
                subject: GrantSubjectRef::Group {
                    group_id: "flow:team:sales".into(),
                },
                role_id: "business:sales".into(),
                scope: ScopeRef::Global,
                expires_at: Some(0),
                resource_ids: Some(Vec::new()),
            });
        let mut errors = Vec::new();
        validate(&NamespaceId("business".into()), &document, &mut errors);
        assert!(errors.iter().any(|error| error.contains("binding")));
        assert!(errors.iter().any(|error| error.contains("resource set")));
    }

    #[test]
    fn foreign_group_reference_does_not_transfer_roster_ownership() {
        use awaken_iam_contract::{
            ActionKey, ActionScopeRule, GroupRoleBindingSnapshot, GroupRosterSnapshot, ScopeKind,
        };
        let mut document = document();
        document
            .resource_model
            .actions
            .push(ActionKey("business::customer.read".into()));
        document.action_scope_rules.push(ActionScopeRule {
            action_pattern: "business::customer.read".into(),
            allowed_scope_kinds: vec![ScopeKind::Global],
        });
        document.group_role_bindings.push(GroupRoleBindingSnapshot {
            group_id: "flow:team:sales".into(),
            role_id: "business:sales".into(),
            scope: ScopeRef::Global,
        });
        assert!(
            super::super::validate_document(&NamespaceId("business".into()), &document).is_empty()
        );
        document.group_rosters.push(GroupRosterSnapshot {
            group_id: "flow:team:sales".into(),
            members: Vec::new(),
        });
        assert!(
            super::super::validate_document(&NamespaceId("business".into()), &document)
                .iter()
                .any(|error| error.contains("outside namespace"))
        );
    }
}
