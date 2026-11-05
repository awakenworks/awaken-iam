//! One request's original native Service role references, not an Allow cache.

use std::collections::HashMap;

use awaken_iam_contract::{PrincipalRef, ScopeRef};
use awaken_iam_core::{RoleBinding, RoleBindingRepository, RoleId};

use super::{DaemonState, PolicyStore};

#[derive(Default)]
pub(super) struct CurrentServiceRoles {
    bindings: HashMap<(PrincipalRef, String, ScopeRef), bool>,
}

impl CurrentServiceRoles {
    pub(super) fn contains<S: PolicyStore>(
        &mut self,
        state: &DaemonState<S>,
        principal: &PrincipalRef,
        role: &str,
        scope: &ScopeRef,
    ) -> Result<bool, crate::AdminError> {
        if !matches!(principal, PrincipalRef::Service { .. }) {
            return Ok(false);
        }
        let key = (principal.clone(), role.to_owned(), scope.clone());
        if let Some(current) = self.bindings.get(&key) {
            return Ok(*current);
        }
        let current = RoleBindingRepository::contains_exact(
            state.admin.store(),
            &RoleBinding {
                principal: principal.clone(),
                role: RoleId(role.to_owned()),
                scope: scope.clone(),
            },
        )?;
        self.bindings.insert(key, current);
        Ok(current)
    }
}

#[cfg(test)]
mod tests;
