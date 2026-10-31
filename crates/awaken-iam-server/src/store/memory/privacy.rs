//! Original memory organization lifecycle and scoped admission. No second map.
use super::*;

pub(super) fn ensure_admitted(
    authz: &Authz,
    scopes: &[ScopeRef],
    groups: &[String],
) -> RepositoryResult<()> {
    for row in authz.orgs.values() {
        if let StoredOrganization::Erased(terminal) = row {
            terminal.ensure_admitted(scopes, groups)?;
        }
    }
    Ok(())
}

pub(super) fn edge_admission(authz: &Authz, edge: &ResourceEdge) -> RepositoryResult<()> {
    let mut scopes = vec![
        edge.parent.clone(),
        ScopeRef::Resource {
            resource_type: edge.resource_type.clone(),
            resource_id: edge.resource_id.clone(),
        },
    ];
    let key = format!("{}\u{1f}{}", edge.resource_type.0, edge.resource_id.0);
    if let Some(previous) = authz.resource_edges.get(&key) {
        scopes.push(previous.parent.clone());
    }
    ensure_admitted(authz, &scopes, &[])
}

pub(super) fn invitation_admission(authz: &Authz, candidate: &Invitation) -> RepositoryResult<()> {
    let mut scopes = vec![ScopeRef::Org {
        org_id: candidate.org_id.clone(),
    }];
    scopes.extend(
        candidate
            .bindings
            .iter()
            .map(|binding| binding.scope.clone()),
    );
    if let Some(previous) = authz.invitations.get(&candidate.id.0) {
        scopes.push(ScopeRef::Org {
            org_id: previous.org_id.clone(),
        });
        scopes.extend(
            previous
                .bindings
                .iter()
                .map(|binding| binding.scope.clone()),
        );
    }
    ensure_admitted(authz, &scopes, &[])
}

pub(super) fn provision_admission(
    authz: &Authz,
    provision: &ResourceProvision,
) -> RepositoryResult<()> {
    let mut scopes = vec![ScopeRef::Org {
        org_id: provision.org_id.clone(),
    }];
    let mut groups = Vec::new();
    for edge in &provision.scope_edges {
        edge_admission(
            authz,
            &ResourceEdge {
                resource_type: edge.resource_type.clone(),
                resource_id: edge.resource_id.clone(),
                parent: edge.parent.clone(),
            },
        )?;
    }
    for grant in &provision.grants {
        scopes.push(grant.scope.clone());
        if let GrantSubjectRef::Group { group_id } = &grant.subject {
            groups.push(group_id.clone());
        }
        if let Some(previous) = authz.grants.get(&grant.id) {
            scopes.push(previous.scope.clone());
            if let GrantSubject::Group(group) = &previous.subject {
                groups.push(group.0.clone());
            }
        }
    }
    for retired in &provision.retirements {
        scopes.push(ScopeRef::Resource {
            resource_type: retired.resource_type.clone(),
            resource_id: retired.resource_id.clone(),
        });
        let key = format!("{}\u{1f}{}", retired.resource_type.0, retired.resource_id.0);
        if let Some(previous) = authz.resource_edges.get(&key) {
            scopes.push(previous.parent.clone());
        }
        for grant_id in &retired.grant_ids {
            if let Some(previous) = authz.grants.get(grant_id) {
                scopes.push(previous.scope.clone());
                if let GrantSubject::Group(group) = &previous.subject {
                    groups.push(group.0.clone());
                }
            }
        }
    }
    ensure_admitted(authz, &scopes, &groups)
}

impl OrgPrivacyRepository for InMemoryStore {
    fn erase_org_privacy(&self, id: &OrgId) -> RepositoryResult<bool> {
        self.erase_org_privacy_with_audit(
            id,
            crate::admin_api::organization_erasure_audit(id, crate::clock::now_timestamp()),
        )
        .map(|receipt| receipt.changed)
    }

    fn erase_org_privacy_with_audit(
        &self,
        id: &OrgId,
        audit: AuditEvent,
    ) -> RepositoryResult<OrgPrivacyCommitReceipt> {
        if id.0.trim().is_empty() {
            return Err(RepositoryError::Conflict(
                "empty organization identity".into(),
            ));
        }
        // One atomic owner order: authz -> identity -> audit -> policy fence.
        // Keep authz through token removal; no late scoped writer can interleave.
        let mut authz = checked_lock(&self.authz, "authz")?;
        let mut identity = checked_lock(&self.identity, "identity")?;
        let mut audits = checked_lock(&self.audit, "audit")?;
        let mut fence = checked_lock(&self.fence, "fence")?;
        let terminal = match authz.orgs.get(&id.0) {
            Some(StoredOrganization::Erased(value)) => Some(value),
            _ => None,
        };
        let known = matches!(authz.orgs.get(&id.0), Some(StoredOrganization::Live(_)));
        let (next_version, confirmed) =
            match plan_org_privacy_commit(id, terminal, known, fence.version)? {
                OrgPrivacyCommitPlan::Replay(receipt) => return Ok(receipt),
                OrgPrivacyCommitPlan::Publish {
                    erasure_version,
                    confirmed_organization,
                } => (erasure_version, confirmed_organization),
            };
        let workspace_edges = authz.workspace_orgs.values().cloned().collect::<Vec<_>>();
        let resource_edges = authz.resource_edges.values().cloned().collect::<Vec<_>>();
        let privacy = OrganizationPrivacyScope::resolve(id, &workspace_edges, &resource_edges);
        let group_ids = authz
            .groups
            .values()
            .filter(|group| &group.org == id)
            .map(|group| group.id.0.clone())
            .collect::<BTreeSet<_>>();
        let authz_before = authz.orgs.len()
            + authz.groups.len()
            + authz.grants.len()
            + authz.role_bindings.len()
            + authz.invitations.len()
            + authz.resource_edges.len()
            + authz.workspace_orgs.len();

        authz.groups.retain(|_, group| &group.org != id);
        authz
            .invitations
            .retain(|_, invitation| &invitation.org_id != id);
        authz.workspace_orgs.retain(|_, edge| &edge.org_id != id);
        authz
            .role_bindings
            .retain(|_, binding| !privacy.contains(&binding.scope));
        authz.grants.retain(|_, grant| {
            !privacy.contains(&grant.scope)
                && !matches!(
                    &grant.subject,
                    GrantSubject::Group(group) if group_ids.contains(&group.0)
                )
        });
        authz.resource_edges.retain(|_, edge| {
            !privacy.contains(&edge.parent)
                && !privacy.contains(&ScopeRef::Resource {
                    resource_type: edge.resource_type.clone(),
                    resource_id: edge.resource_id.clone(),
                })
        });
        let authz_after = authz.orgs.len()
            + authz.groups.len()
            + authz.grants.len()
            + authz.role_bindings.len()
            + authz.invitations.len()
            + authz.resource_edges.len()
            + authz.workspace_orgs.len();
        let token_count = identity.api_tokens.len();
        identity
            .api_tokens
            .retain(|_, token| !privacy.contains_workspace(&token.workspace.0));
        let retained_token_ids = identity.api_tokens.keys().cloned().collect::<BTreeSet<_>>();
        identity
            .api_tokens_by_prefix
            .retain(|_, token_id| retained_token_ids.contains(token_id));

        let changed =
            confirmed || authz_before != authz_after || token_count != identity.api_tokens.len();
        let terminal = OrgPrivacyTerminal {
            scope: privacy,
            group_ids,
            erasure_version: next_version,
            confirmed_organization: confirmed,
        };
        let receipt = terminal.receipt(next_version, changed, true)?;
        authz
            .orgs
            .insert(id.0.clone(), StoredOrganization::Erased(terminal));
        audits.push(audit);
        fence.version = next_version;
        Ok(receipt)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[derive(PartialEq, Eq)]
    struct AffectedState {
        orgs: Vec<Organization>,
        terminals: Vec<OrgPrivacyTerminal>,
        groups: Vec<Group>,
        grants: Vec<Grant>,
        bindings: Vec<RoleBinding>,
        invitations: Vec<Invitation>,
        edges: Vec<ResourceEdge>,
        workspaces: Vec<WorkspaceOrgEdge>,
        tokens: Vec<ApiToken>,
        prefixes: BTreeMap<String, String>,
        audit: Vec<AuditEvent>,
        fence: Fence,
    }
    fn observe_only_for_test(store: &InMemoryStore) -> AffectedState {
        // Test-only forensic observation of bytes/data, NOT a validity repair,
        // business receipt or production poison recovery strategy.
        let authz = store
            .authz
            .lock()
            .unwrap_or_else(|error| error.into_inner());
        let identity = store
            .identity
            .lock()
            .unwrap_or_else(|error| error.into_inner());
        let audit = store
            .audit
            .lock()
            .unwrap_or_else(|error| error.into_inner());
        let fence = store
            .fence
            .lock()
            .unwrap_or_else(|error| error.into_inner());
        AffectedState {
            orgs: authz
                .orgs
                .values()
                .filter_map(|row| {
                    if let StoredOrganization::Live(value) = row {
                        Some(value.clone())
                    } else {
                        None
                    }
                })
                .collect(),
            terminals: authz
                .orgs
                .values()
                .filter_map(|row| {
                    if let StoredOrganization::Erased(value) = row {
                        Some(value.clone())
                    } else {
                        None
                    }
                })
                .collect(),
            groups: authz.groups.values().cloned().collect(),
            grants: authz.grants.values().cloned().collect(),
            bindings: authz.role_bindings.values().cloned().collect(),
            invitations: authz.invitations.values().cloned().collect(),
            edges: authz.resource_edges.values().cloned().collect(),
            workspaces: authz.workspace_orgs.values().cloned().collect(),
            tokens: identity.api_tokens.values().cloned().collect(),
            prefixes: identity.api_tokens_by_prefix.clone(),
            audit: audit.clone(),
            fence: *fence,
        }
    }

    #[test]
    fn poisoned_participants_cannot_emit_first_or_replayed_privacy_receipts() {
        // CF2 poison decision table: P1 each of authz/identity/audit/fence poisoned
        // BEFORE new erasure -> Backend error, no payload/terminal/audit/version
        // change; P2 same cuts AFTER a valid terminal commit -> no authoritative
        // replay ACK from possibly inconsistent participants. All four guards
        // must be acquired before mutation. The test never clears poison.
        for already_terminal in [false, true] {
            for participant in 0..4 {
                let store = InMemoryStore::new();
                let id = OrgId("poison-org".into());
                let at = Timestamp("2026-10-30T00:00:00Z".into());
                OrgRepository::upsert(
                    &store,
                    Organization {
                        id: id.clone(),
                        display_name: Some("private".into()),
                        owner: PrincipalRef::Service {
                            service_id: "owner".into(),
                        },
                        created_at: at.clone(),
                        updated_at: at.clone(),
                    },
                )
                .unwrap();
                ResourceModelRepository::put_workspace_org(
                    &store,
                    WorkspaceOrgEdge {
                        workspace_id: WorkspaceId("poison-workspace".into()),
                        org_id: id.clone(),
                    },
                )
                .unwrap();
                GrantRepository::put(
                    &store,
                    Grant {
                        id: GrantId("poison-grant".into()),
                        subject: GrantSubject::Principal(PrincipalRef::Service {
                            service_id: "owner".into(),
                        }),
                        action_pattern: ActionPattern("read".into()),
                        scope: ScopeRef::Org { org_id: id.clone() },
                        effect: Effect::Allow,
                    },
                )
                .unwrap();
                ApiTokenRepository::create(
                    &store,
                    ApiToken {
                        id: ApiTokenId("poison-token".into()),
                        prefix: ApiTokenPrefix("poison-prefix".into()),
                        principal: PrincipalRef::Service {
                            service_id: "owner".into(),
                        },
                        secret_hash: "test-hash".into(),
                        workspace: WorkspaceId("poison-workspace".into()),
                        created_at: at.clone(),
                        expires_at: None,
                        revoked_at: None,
                    },
                )
                .unwrap();
                if already_terminal {
                    store
                        .erase_org_privacy_with_audit(
                            &id,
                            crate::admin_api::organization_erasure_audit(&id, at.clone()),
                        )
                        .unwrap();
                }
                let before = observe_only_for_test(&store);
                let poison =
                    std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| match participant {
                        0 => {
                            let _guard = store.authz.lock().unwrap();
                            panic!("injected authz panic");
                        }
                        1 => {
                            let _guard = store.identity.lock().unwrap();
                            panic!("injected identity panic");
                        }
                        2 => {
                            let _guard = store.audit.lock().unwrap();
                            panic!("injected audit panic");
                        }
                        _ => {
                            let _guard = store.fence.lock().unwrap();
                            panic!("injected fence panic");
                        }
                    }));
                assert!(poison.is_err());
                assert!(
                    matches!(
                        store.erase_org_privacy_with_audit(
                            &id,
                            crate::admin_api::organization_erasure_audit(&id, at.clone())
                        ),
                        Err(RepositoryError::Backend(_))
                    ),
                    "P1/P2 no exact receipt"
                );
                assert!(
                    matches!(
                        store.erase_org_privacy(&id),
                        Err(RepositoryError::Backend(_))
                    ),
                    "legacy bool cannot synthesize success"
                );
                assert!(
                    observe_only_for_test(&store) == before,
                    "P1/P2 affected state/audit/version unchanged"
                );
            }
        }
    }
}
