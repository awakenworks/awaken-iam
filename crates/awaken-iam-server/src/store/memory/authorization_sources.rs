//! Native authorization-source repositories and their atomic observation epochs.
use super::*;

impl AccountRepository for InMemoryStore {
    fn get(&self, id: &AccountId) -> RepositoryResult<Option<Account>> {
        Ok(self.identity.lock().unwrap().accounts.get(&id.0).cloned())
    }

    fn upsert(&self, account: Account) -> RepositoryResult<()> {
        let mut identity = checked_lock(&self.identity, "identity")?;
        let mut fence = checked_lock(&self.fence, "fence")?;
        let epoch = next_authorization_epoch(*fence)?;
        identity.accounts.insert(account.id.0.clone(), account);
        fence.epoch = epoch;
        Ok(())
    }

    fn list(&self) -> RepositoryResult<Vec<Account>> {
        Ok(self
            .identity
            .lock()
            .unwrap()
            .accounts
            .values()
            .cloned()
            .collect())
    }
}

impl ApiTokenOwnerRepository for InMemoryStore {
    fn record_api_token_owner(&self, id: &ApiTokenId, owner: &AccountId) -> RepositoryResult<()> {
        let mut guard = checked_lock(&self.identity, "identity")?;
        if !guard.api_tokens.contains_key(&id.0) {
            return Err(RepositoryError::NotFound(format!("api token {}", id.0)));
        }
        let mut fence = checked_lock(&self.fence, "fence")?;
        let epoch = next_authorization_epoch(*fence)?;
        guard.api_token_owners.insert(id.0.clone(), owner.clone());
        fence.epoch = epoch;
        Ok(())
    }

    fn api_token_owner(&self, id: &ApiTokenId) -> RepositoryResult<Option<AccountId>> {
        let guard = checked_lock(&self.identity, "identity")?;
        // An erased token takes its ownership record with it.
        Ok(guard
            .api_tokens
            .contains_key(&id.0)
            .then(|| guard.api_token_owners.get(&id.0).cloned())
            .flatten())
    }
}

impl ApiTokenRepository for InMemoryStore {
    fn create(&self, token: ApiToken) -> RepositoryResult<()> {
        let authz = checked_lock(&self.authz, "authz")?;
        let mut guard = checked_lock(&self.identity, "identity")?;
        let mut scopes = vec![ScopeRef::Workspace {
            workspace_id: token.workspace.clone(),
        }];
        if let Some(previous) = guard.api_tokens.get(&token.id.0) {
            scopes.push(ScopeRef::Workspace {
                workspace_id: previous.workspace.clone(),
            });
        }
        ensure_admitted(&authz, &scopes, &[])?;
        if guard.api_tokens.contains_key(&token.id.0) {
            return Err(RepositoryError::Conflict(format!(
                "api token {} already exists",
                token.id.0
            )));
        }
        if guard.api_tokens_by_prefix.contains_key(&token.prefix.0) {
            return Err(RepositoryError::Conflict(format!(
                "api token prefix {} already exists",
                token.prefix.0
            )));
        }
        let mut fence = checked_lock(&self.fence, "fence")?;
        let epoch = next_authorization_epoch(*fence)?;
        guard
            .api_tokens_by_prefix
            .insert(token.prefix.0.clone(), token.id.0.clone());
        guard.api_tokens.insert(token.id.0.clone(), token);
        fence.epoch = epoch;
        Ok(())
    }

    fn get(&self, id: &ApiTokenId) -> RepositoryResult<Option<ApiToken>> {
        Ok(self.identity.lock().unwrap().api_tokens.get(&id.0).cloned())
    }

    fn get_by_prefix(&self, prefix: &ApiTokenPrefix) -> RepositoryResult<Option<ApiToken>> {
        let guard = self.identity.lock().unwrap();
        Ok(guard
            .api_tokens_by_prefix
            .get(&prefix.0)
            .and_then(|id| guard.api_tokens.get(id))
            .cloned())
    }

    fn list_for_principal(&self, principal: &PrincipalRef) -> RepositoryResult<Vec<ApiToken>> {
        let guard = self.identity.lock().unwrap();
        let mut found: Vec<ApiToken> = guard
            .api_tokens
            .values()
            .filter(|token| &token.principal == principal)
            .cloned()
            .collect();
        found.sort_by(|a, b| a.id.0.cmp(&b.id.0));
        Ok(found)
    }

    fn update(&self, token: ApiToken) -> RepositoryResult<()> {
        let authz = checked_lock(&self.authz, "authz")?;
        let mut guard = checked_lock(&self.identity, "identity")?;
        let mut scopes = vec![ScopeRef::Workspace {
            workspace_id: token.workspace.clone(),
        }];
        if let Some(previous) = guard.api_tokens.get(&token.id.0) {
            scopes.push(ScopeRef::Workspace {
                workspace_id: previous.workspace.clone(),
            });
        }
        ensure_admitted(&authz, &scopes, &[])?;
        if !guard.api_tokens.contains_key(&token.id.0) {
            return Err(RepositoryError::NotFound(format!(
                "api token {} does not exist",
                token.id.0
            )));
        }
        let mut fence = checked_lock(&self.fence, "fence")?;
        let epoch = next_authorization_epoch(*fence)?;
        guard
            .api_tokens_by_prefix
            .insert(token.prefix.0.clone(), token.id.0.clone());
        guard.api_tokens.insert(token.id.0.clone(), token);
        fence.epoch = epoch;
        Ok(())
    }
}

impl OrgRepository for InMemoryStore {
    fn get(&self, id: &OrgId) -> RepositoryResult<Option<Organization>> {
        Ok(match self.authz.lock().unwrap().orgs.get(&id.0) {
            Some(StoredOrganization::Live(org)) => Some(org.clone()),
            _ => None,
        })
    }

    fn upsert(&self, org: Organization) -> RepositoryResult<()> {
        let mut authz = checked_lock(&self.authz, "authz")?;
        ensure_admitted(
            &authz,
            &[ScopeRef::Org {
                org_id: org.id.clone(),
            }],
            &[],
        )?;
        let mut fence = checked_lock(&self.fence, "fence")?;
        let epoch = next_authorization_epoch(*fence)?;
        authz
            .orgs
            .insert(org.id.0.clone(), StoredOrganization::Live(org));
        fence.epoch = epoch;
        Ok(())
    }

    fn list(&self) -> RepositoryResult<Vec<Organization>> {
        Ok(self
            .authz
            .lock()
            .unwrap()
            .orgs
            .values()
            .filter_map(|row| match row {
                StoredOrganization::Live(org) => Some(org.clone()),
                StoredOrganization::Erased(_) => None,
            })
            .collect())
    }

    fn remove(&self, id: &OrgId) -> RepositoryResult<()> {
        let mut authz = checked_lock(&self.authz, "authz")?;
        if !matches!(authz.orgs.get(&id.0), Some(StoredOrganization::Live(_))) {
            return Err(RepositoryError::NotFound(format!(
                "organization {} not found",
                id.0
            )));
        }
        let mut fence = checked_lock(&self.fence, "fence")?;
        let epoch = next_authorization_epoch(*fence)?;
        authz.orgs.remove(&id.0);
        fence.epoch = epoch;
        Ok(())
    }
}

impl GroupRepository for InMemoryStore {
    fn get(&self, id: &GroupId) -> RepositoryResult<Option<Group>> {
        Ok(self.authz.lock().unwrap().groups.get(&id.0).cloned())
    }

    fn upsert(&self, group: Group) -> RepositoryResult<()> {
        let mut authz = checked_lock(&self.authz, "authz")?;
        let mut scopes = vec![ScopeRef::Org {
            org_id: group.org.clone(),
        }];
        if let Some(previous) = authz.groups.get(&group.id.0) {
            scopes.push(ScopeRef::Org {
                org_id: previous.org.clone(),
            });
        }
        ensure_admitted(&authz, &scopes, &[group.id.0.clone()])?;
        let mut fence = checked_lock(&self.fence, "fence")?;
        let epoch = next_authorization_epoch(*fence)?;
        authz.groups.insert(group.id.0.clone(), group);
        fence.epoch = epoch;
        Ok(())
    }

    fn list(&self) -> RepositoryResult<Vec<Group>> {
        Ok(self
            .authz
            .lock()
            .unwrap()
            .groups
            .values()
            .cloned()
            .collect())
    }

    fn remove(&self, id: &GroupId) -> RepositoryResult<()> {
        let mut authz = checked_lock(&self.authz, "authz")?;
        ensure_admitted(&authz, &[], &[id.0.clone()])?;
        let mut fence = checked_lock(&self.fence, "fence")?;
        let epoch = next_authorization_epoch(*fence)?;
        authz
            .groups
            .remove(&id.0)
            .map(|_| ())
            .ok_or_else(|| RepositoryError::NotFound(format!("group {} not found", id.0)))?;
        fence.epoch = epoch;
        Ok(())
    }
}

impl GrantRepository for InMemoryStore {
    fn put(&self, grant: Grant) -> RepositoryResult<()> {
        let mut authz = checked_lock(&self.authz, "authz")?;
        grants::admit_grant(&authz, &grant)?;
        let mut fence = checked_lock(&self.fence, "fence")?;
        let epoch = next_authorization_epoch(*fence)?;
        authz.grants.insert(grant.id.0.clone(), grant);
        fence.epoch = epoch;
        Ok(())
    }

    fn get(&self, id: &GrantId) -> RepositoryResult<Option<Grant>> {
        Ok(self.authz.lock().unwrap().grants.get(&id.0).cloned())
    }

    fn list(&self) -> RepositoryResult<Vec<Grant>> {
        Ok(self
            .authz
            .lock()
            .unwrap()
            .grants
            .values()
            .cloned()
            .collect())
    }

    fn remove(&self, id: &GrantId) -> RepositoryResult<()> {
        let mut authz = checked_lock(&self.authz, "authz")?;
        if let Some(previous) = authz.grants.get(&id.0) {
            let groups = if let GrantSubject::Group(group) = &previous.subject {
                vec![group.0.clone()]
            } else {
                vec![]
            };
            ensure_admitted(&authz, &[previous.scope.clone()], &groups)?;
        }
        let mut fence = checked_lock(&self.fence, "fence")?;
        let epoch = next_authorization_epoch(*fence)?;
        authz
            .grants
            .remove(&id.0)
            .map(|_| ())
            .ok_or_else(|| RepositoryError::NotFound(format!("grant {} not found", id.0)))?;
        fence.epoch = epoch;
        Ok(())
    }
}

impl RoleBindingRepository for InMemoryStore {
    fn contains_exact(&self, binding: &RoleBinding) -> RepositoryResult<bool> {
        let key = json_key(
            &(&binding.principal, &binding.role.0, &binding.scope),
            "role binding",
        )?;
        Ok(checked_lock(&self.authz, "authz")?
            .role_bindings
            .contains_key(&key))
    }

    fn add(&self, binding: RoleBinding) -> RepositoryResult<()> {
        let key = json_key(
            &(&binding.principal, &binding.role.0, &binding.scope),
            "role binding",
        )?;
        let mut authz = checked_lock(&self.authz, "authz")?;
        ensure_admitted(&authz, &[binding.scope.clone()], &[])?;
        let mut fence = checked_lock(&self.fence, "fence")?;
        let epoch = next_authorization_epoch(*fence)?;
        authz.role_bindings.insert(key, binding);
        fence.epoch = epoch;
        Ok(())
    }

    fn list_for_principal(&self, principal: &PrincipalRef) -> RepositoryResult<Vec<RoleBinding>> {
        Ok(self
            .authz
            .lock()
            .unwrap()
            .role_bindings
            .values()
            .filter(|binding| &binding.principal == principal)
            .cloned()
            .collect())
    }

    fn list(&self) -> RepositoryResult<Vec<RoleBinding>> {
        Ok(self
            .authz
            .lock()
            .unwrap()
            .role_bindings
            .values()
            .cloned()
            .collect())
    }

    fn remove(&self, binding: &RoleBinding) -> RepositoryResult<()> {
        let key = json_key(
            &(&binding.principal, &binding.role.0, &binding.scope),
            "role binding",
        )?;
        let mut authz = checked_lock(&self.authz, "authz")?;
        ensure_admitted(&authz, &[binding.scope.clone()], &[])?;
        let mut fence = checked_lock(&self.fence, "fence")?;
        let epoch = next_authorization_epoch(*fence)?;
        authz
            .role_bindings
            .remove(&key)
            .map(|_| ())
            .ok_or_else(|| RepositoryError::NotFound("role binding not found".to_owned()))?;
        fence.epoch = epoch;
        Ok(())
    }

    fn replace_scoped(
        &self,
        principal: &PrincipalRef,
        scope: &ScopeRef,
        managed_roles: &[RoleId],
        replacement_roles: &[RoleId],
    ) -> RepositoryResult<()> {
        let managed: BTreeSet<&str> = managed_roles.iter().map(|role| role.0.as_str()).collect();
        let mut guard = checked_lock(&self.authz, "authz")?;
        ensure_admitted(&guard, &[scope.clone()], &[])?;
        let replacements = replacement_roles
            .iter()
            .map(|role| {
                let binding = RoleBinding {
                    principal: principal.clone(),
                    role: role.clone(),
                    scope: scope.clone(),
                };
                let key = json_key(
                    &(&binding.principal, &binding.role.0, &binding.scope),
                    "role binding",
                )?;
                Ok((key, binding))
            })
            .collect::<RepositoryResult<Vec<_>>>()?;
        let mut fence = checked_lock(&self.fence, "fence")?;
        let epoch = next_authorization_epoch(*fence)?;
        guard.role_bindings.retain(|_, binding| {
            &binding.principal != principal
                || &binding.scope != scope
                || !managed.contains(binding.role.0.as_str())
        });
        for (key, binding) in replacements {
            guard.role_bindings.insert(key, binding);
        }
        fence.epoch = epoch;
        Ok(())
    }
}

impl ResourceModelRepository for InMemoryStore {
    fn put_edge(&self, edge: ResourceEdge) -> RepositoryResult<()> {
        let key = format!("{}\u{1f}{}", edge.resource_type.0, edge.resource_id.0);
        let mut authz = checked_lock(&self.authz, "authz")?;
        edge_admission(&authz, &edge)?;
        let mut fence = checked_lock(&self.fence, "fence")?;
        let epoch = next_authorization_epoch(*fence)?;
        authz.resource_edges.insert(key, edge);
        fence.epoch = epoch;
        Ok(())
    }

    fn remove_edge(
        &self,
        resource_type: &ResourceType,
        resource_id: &ResourceId,
    ) -> RepositoryResult<()> {
        let key = format!("{}\u{1f}{}", resource_type.0, resource_id.0);
        let mut authz = checked_lock(&self.authz, "authz")?;
        ensure_admitted(
            &authz,
            &[ScopeRef::Resource {
                resource_type: resource_type.clone(),
                resource_id: resource_id.clone(),
            }],
            &[],
        )?;
        let mut fence = checked_lock(&self.fence, "fence")?;
        let epoch = next_authorization_epoch(*fence)?;
        authz.resource_edges.remove(&key);
        fence.epoch = epoch;
        Ok(())
    }

    fn list_edges(&self) -> RepositoryResult<Vec<ResourceEdge>> {
        Ok(self
            .authz
            .lock()
            .unwrap()
            .resource_edges
            .values()
            .cloned()
            .collect())
    }

    fn put_workspace_org(&self, edge: WorkspaceOrgEdge) -> RepositoryResult<()> {
        let mut authz = checked_lock(&self.authz, "authz")?;
        let mut scopes = vec![
            ScopeRef::Workspace {
                workspace_id: edge.workspace_id.clone(),
            },
            ScopeRef::Org {
                org_id: edge.org_id.clone(),
            },
        ];
        if let Some(previous) = authz.workspace_orgs.get(&edge.workspace_id.0) {
            scopes.push(ScopeRef::Org {
                org_id: previous.org_id.clone(),
            });
        }
        ensure_admitted(&authz, &scopes, &[])?;
        let mut fence = checked_lock(&self.fence, "fence")?;
        let epoch = next_authorization_epoch(*fence)?;
        authz
            .workspace_orgs
            .insert(edge.workspace_id.0.clone(), edge);
        fence.epoch = epoch;
        Ok(())
    }

    fn workspace_org(
        &self,
        workspace_id: &WorkspaceId,
    ) -> RepositoryResult<Option<WorkspaceOrgEdge>> {
        Ok(self
            .authz
            .lock()
            .unwrap()
            .workspace_orgs
            .get(&workspace_id.0)
            .cloned())
    }

    fn list_workspace_orgs(&self) -> RepositoryResult<Vec<WorkspaceOrgEdge>> {
        Ok(self
            .authz
            .lock()
            .unwrap()
            .workspace_orgs
            .values()
            .cloned()
            .collect())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn exhausted_epoch_refuses_prerequisite_writes_before_memory_publication() {
        let store = InMemoryStore::new();
        let at = Timestamp("2026-11-10T00:00:00Z".into());
        let account = Account {
            id: AccountId("epoch-reader".into()),
            status: awaken_iam_contract::AccountStatus::Active,
            display_name: None,
            created_at: at.clone(),
            updated_at: at.clone(),
        };
        AccountRepository::upsert(&store, account.clone()).unwrap();
        let org = Organization {
            id: OrgId("epoch-org".into()),
            display_name: None,
            owner: PrincipalRef::Account {
                account_id: account.id.clone(),
            },
            created_at: at.clone(),
            updated_at: at.clone(),
        };
        OrgRepository::upsert(&store, org.clone()).unwrap();
        let group = Group {
            id: GroupId("epoch-team".into()),
            org: org.id,
            display_name: None,
            members: vec![],
            created_at: at.clone(),
            updated_at: at,
        };
        GroupRepository::upsert(&store, group.clone()).unwrap();
        store.fence.lock().unwrap().epoch = i64::MAX as u64;
        let before = store.fence().unwrap();
        let mut disabled = account.clone();
        disabled.status = awaken_iam_contract::AccountStatus::Disabled;
        assert!(AccountRepository::upsert(&store, disabled).is_err());
        assert_eq!(
            AccountRepository::get(&store, &account.id).unwrap(),
            Some(account)
        );
        assert!(GroupRepository::remove(&store, &group.id).is_err());
        assert_eq!(
            GroupRepository::get(&store, &group.id).unwrap(),
            Some(group)
        );
        assert_eq!(store.fence().unwrap(), before);
    }
}
