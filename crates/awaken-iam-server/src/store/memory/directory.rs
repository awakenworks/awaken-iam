//! Product-neutral Directory persistence in the shared in-memory IAM state.

use super::*;

fn product_space_key(space: &ProductSpaceRef) -> String {
    format!("{}\u{1f}{}", space.product, space.space_id)
}

fn advance_revision(authz: &mut Authz) -> u64 {
    authz.directory_revision = authz.directory_revision.max(1) + 1;
    authz.directory_revision
}

impl DirectoryRepository for InMemoryStore {
    fn create_directory_node(
        &self,
        node: DirectoryNode,
        placement: Option<ProductSpacePlacement>,
        actor: &PrincipalRef,
    ) -> RepositoryResult<u64> {
        node.validate()
            .map_err(|error| RepositoryError::Conflict(error.to_string()))?;
        if let Some(placement) = &placement {
            node.validate_placement(placement)
                .map_err(|error| RepositoryError::Conflict(error.to_string()))?;
        }
        let mut authz = self.authz.lock().unwrap();
        if !authz.orgs.contains_key(&node.org_id.0) {
            return Err(RepositoryError::NotFound(format!(
                "organization {}",
                node.org_id.0
            )));
        }
        if authz.directory_nodes.contains_key(&node.id.0) {
            return Err(RepositoryError::Conflict(format!(
                "directory node {} already exists",
                node.id.0
            )));
        }
        if let Some(parent_id) = &node.parent_id {
            let parent = authz.directory_nodes.get(&parent_id.0).ok_or_else(|| {
                RepositoryError::NotFound(format!("directory parent {}", parent_id.0))
            })?;
            if parent.org_id != node.org_id || parent.archived {
                return Err(RepositoryError::Conflict(
                    "directory parent must be live and in the same organization".into(),
                ));
            }
        }
        if authz.directory_nodes.values().any(|existing| {
            existing.org_id == node.org_id
                && existing.parent_id == node.parent_id
                && existing.slug == node.slug
        }) {
            return Err(RepositoryError::Conflict(format!(
                "directory slug {} already exists under this parent",
                node.slug
            )));
        }
        if let Some(placement) = &placement
            && authz
                .product_space_bindings
                .contains_key(&product_space_key(&placement.product_space))
        {
            return Err(RepositoryError::Conflict(format!(
                "product space {}/{} is already placed",
                placement.product_space.product, placement.product_space.space_id
            )));
        }
        let at = node.updated_at.clone();
        let node_id = node.id.0.clone();
        authz.directory_nodes.insert(node_id.clone(), node);
        if let Some(placement) = placement {
            authz
                .product_space_bindings
                .insert(product_space_key(&placement.product_space), placement);
        }
        let revision = advance_revision(&mut authz);
        drop(authz);
        self.audit.lock().unwrap().push(AuditEvent {
            at,
            actor: Some(actor.clone()),
            action: "directory.node.create".into(),
            detail: format!("directory node {node_id}"),
        });
        Ok(revision)
    }

    fn directory_node(&self, id: &DirectoryNodeId) -> RepositoryResult<Option<DirectoryNode>> {
        Ok(self
            .authz
            .lock()
            .unwrap()
            .directory_nodes
            .get(&id.0)
            .cloned())
    }

    fn directory_children(
        &self,
        org_id: &OrgId,
        parent_id: Option<&DirectoryNodeId>,
    ) -> RepositoryResult<Vec<DirectoryNode>> {
        let mut nodes = self
            .authz
            .lock()
            .unwrap()
            .directory_nodes
            .values()
            .filter(|node| {
                !node.archived && &node.org_id == org_id && node.parent_id.as_ref() == parent_id
            })
            .cloned()
            .collect::<Vec<_>>();
        nodes.sort_by(|left, right| left.slug.cmp(&right.slug));
        Ok(nodes)
    }

    fn move_directory_node(
        &self,
        id: &DirectoryNodeId,
        parent_id: Option<&DirectoryNodeId>,
        updated_at: &Timestamp,
        actor: &PrincipalRef,
    ) -> RepositoryResult<u64> {
        if parent_id == Some(id) {
            return Err(RepositoryError::Conflict(
                "a directory node cannot be its own parent".into(),
            ));
        }
        let mut authz = self.authz.lock().unwrap();
        let current = authz
            .directory_nodes
            .get(&id.0)
            .cloned()
            .ok_or_else(|| RepositoryError::NotFound(format!("directory node {}", id.0)))?;
        if current.archived {
            return Err(RepositoryError::NotFound(format!(
                "live directory node {}",
                id.0
            )));
        }
        if current.parent_id.as_ref() == parent_id {
            return Ok(authz.directory_revision.max(1));
        }
        if let Some(parent_id) = parent_id {
            let parent = authz.directory_nodes.get(&parent_id.0).ok_or_else(|| {
                RepositoryError::NotFound(format!("directory parent {}", parent_id.0))
            })?;
            if parent.archived || parent.org_id != current.org_id {
                return Err(RepositoryError::Conflict(
                    "directory parent must be live and in the same organization".into(),
                ));
            }
            let mut cursor = Some(parent_id.clone());
            while let Some(candidate) = cursor {
                if candidate == *id {
                    return Err(RepositoryError::Conflict(
                        "directory move would create a cycle".into(),
                    ));
                }
                cursor = authz
                    .directory_nodes
                    .get(&candidate.0)
                    .and_then(|node| node.parent_id.clone());
            }
        }
        if authz.directory_nodes.values().any(|existing| {
            existing.id != current.id
                && existing.org_id == current.org_id
                && existing.parent_id.as_ref() == parent_id
                && existing.slug == current.slug
        }) {
            return Err(RepositoryError::Conflict(format!(
                "directory slug {} already exists under the target parent",
                current.slug
            )));
        }
        let node = authz.directory_nodes.get_mut(&id.0).unwrap();
        node.parent_id = parent_id.cloned();
        node.updated_at = updated_at.clone();
        let revision = advance_revision(&mut authz);
        drop(authz);
        self.audit.lock().unwrap().push(AuditEvent {
            at: updated_at.clone(),
            actor: Some(actor.clone()),
            action: "directory.node.move".into(),
            detail: format!("directory node {}", id.0),
        });
        Ok(revision)
    }

    fn archive_directory_node(
        &self,
        id: &DirectoryNodeId,
        updated_at: &Timestamp,
        actor: &PrincipalRef,
    ) -> RepositoryResult<u64> {
        let mut authz = self.authz.lock().unwrap();
        let node = authz
            .directory_nodes
            .get(id.0.as_str())
            .cloned()
            .ok_or_else(|| RepositoryError::NotFound(format!("directory node {}", id.0)))?;
        if node.archived {
            return Ok(authz.directory_revision.max(1));
        }
        if authz
            .directory_nodes
            .values()
            .any(|child| !child.archived && child.parent_id.as_ref() == Some(id))
        {
            return Err(RepositoryError::Conflict(
                "a directory node with live children cannot be archived".into(),
            ));
        }
        let node = authz.directory_nodes.get_mut(&id.0).unwrap();
        node.archived = true;
        node.updated_at = updated_at.clone();
        let revision = advance_revision(&mut authz);
        drop(authz);
        self.audit.lock().unwrap().push(AuditEvent {
            at: updated_at.clone(),
            actor: Some(actor.clone()),
            action: "directory.node.archive".into(),
            detail: format!("directory node {}", id.0),
        });
        Ok(revision)
    }

    fn restore_directory_node(
        &self,
        id: &DirectoryNodeId,
        updated_at: &Timestamp,
        actor: &PrincipalRef,
    ) -> RepositoryResult<u64> {
        let mut authz = self.authz.lock().unwrap();
        let current = authz
            .directory_nodes
            .get(&id.0)
            .cloned()
            .ok_or_else(|| RepositoryError::NotFound(format!("directory node {}", id.0)))?;
        if !current.archived {
            return Ok(authz.directory_revision.max(1));
        }
        if let Some(parent_id) = &current.parent_id {
            let parent = authz.directory_nodes.get(&parent_id.0).ok_or_else(|| {
                RepositoryError::NotFound(format!("directory parent {}", parent_id.0))
            })?;
            if parent.archived || parent.org_id != current.org_id {
                return Err(RepositoryError::Conflict(
                    "directory parent must be live and in the same organization".into(),
                ));
            }
        }
        let node = authz.directory_nodes.get_mut(&id.0).unwrap();
        node.archived = false;
        node.updated_at = updated_at.clone();
        let revision = advance_revision(&mut authz);
        drop(authz);
        self.audit.lock().unwrap().push(AuditEvent {
            at: updated_at.clone(),
            actor: Some(actor.clone()),
            action: "directory.node.restore".into(),
            detail: format!("directory node {}", id.0),
        });
        Ok(revision)
    }

    fn update_directory_node(
        &self,
        id: &DirectoryNodeId,
        name: &str,
        slug: &str,
        description: Option<&str>,
        updated_at: &Timestamp,
        actor: &PrincipalRef,
    ) -> RepositoryResult<u64> {
        let mut authz = self.authz.lock().unwrap();
        let current = authz
            .directory_nodes
            .get(&id.0)
            .cloned()
            .filter(|node| !node.archived)
            .ok_or_else(|| RepositoryError::NotFound(format!("live directory node {}", id.0)))?;
        let mut updated = current.clone();
        updated.name = name.to_owned();
        updated.slug = slug.to_owned();
        updated.description = description.map(str::to_owned);
        updated.updated_at = updated_at.clone();
        updated
            .validate()
            .map_err(|error| RepositoryError::Conflict(error.to_string()))?;
        if updated.name == current.name
            && updated.slug == current.slug
            && updated.description == current.description
        {
            return Ok(authz.directory_revision.max(1));
        }
        if authz.directory_nodes.values().any(|sibling| {
            sibling.id != current.id
                && sibling.org_id == current.org_id
                && sibling.parent_id == current.parent_id
                && sibling.slug == updated.slug
        }) {
            return Err(RepositoryError::Conflict(format!(
                "directory slug {} already exists under this parent",
                updated.slug
            )));
        }
        authz.directory_nodes.insert(id.0.clone(), updated);
        let revision = advance_revision(&mut authz);
        drop(authz);
        self.audit.lock().unwrap().push(AuditEvent {
            at: updated_at.clone(),
            actor: Some(actor.clone()),
            action: "directory.node.update".into(),
            detail: format!("directory node {}", id.0),
        });
        Ok(revision)
    }

    fn product_space_binding(
        &self,
        product_space: &ProductSpaceRef,
    ) -> RepositoryResult<Option<ProductSpacePlacement>> {
        Ok(self
            .authz
            .lock()
            .unwrap()
            .product_space_bindings
            .get(&product_space_key(product_space))
            .cloned())
    }

    fn directory_revision(&self) -> RepositoryResult<u64> {
        Ok(self.authz.lock().unwrap().directory_revision.max(1))
    }
}
