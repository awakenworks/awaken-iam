//! Application boundary for user-visible hierarchy and product-space placement.
//!
//! This context shares IAM deployment infrastructure but does not mutate or
//! version authorization policy. Products retain stable business identifiers;
//! Directory owns only their movable presentation placement.

use awaken_iam_contract::{
    CreateDirectoryNode, DirectoryMutationAck, DirectoryNodeDto, DirectoryNodeId,
    MoveDirectoryNode, OrgId, ProductSpaceBinding, ProductSpaceRef, Timestamp, UpdateDirectoryNode,
};
use awaken_iam_core::{DirectoryNode, DirectoryRepo};

use crate::admin_api::{AdminError, AdminResult};

/// One application service over the selected Directory repository adapter.
#[derive(Debug, Clone)]
pub struct DirectoryApi<S> {
    store: S,
}

impl<S: DirectoryRepo> DirectoryApi<S> {
    pub fn new(store: S) -> Self {
        Self { store }
    }

    pub fn create_node(&self, request: CreateDirectoryNode) -> AdminResult<DirectoryMutationAck> {
        let node = DirectoryNode::from(request.node);
        node.validate()
            .map_err(|error| AdminError::Invalid(error.to_string()))?;
        if let Some(binding) = &request.binding {
            node.validate_binding(binding)
                .map_err(|error| AdminError::Invalid(error.to_string()))?;
        }
        Ok(DirectoryMutationAck {
            revision: self.store.create_directory_node(node, request.binding)?,
        })
    }

    pub fn node(&self, id: &DirectoryNodeId) -> AdminResult<Option<DirectoryNodeDto>> {
        Ok(self.store.directory_node(id)?.map(DirectoryNodeDto::from))
    }

    pub fn children(
        &self,
        org_id: &OrgId,
        parent_id: Option<&DirectoryNodeId>,
    ) -> AdminResult<Vec<DirectoryNodeDto>> {
        Ok(self
            .store
            .directory_children(org_id, parent_id)?
            .into_iter()
            .map(DirectoryNodeDto::from)
            .collect())
    }

    pub fn move_node(
        &self,
        id: &DirectoryNodeId,
        request: MoveDirectoryNode,
    ) -> AdminResult<DirectoryMutationAck> {
        Ok(DirectoryMutationAck {
            revision: self.store.move_directory_node(
                id,
                request.parent_id.as_ref(),
                &request.updated_at,
            )?,
        })
    }

    pub fn update_node(
        &self,
        id: &DirectoryNodeId,
        request: UpdateDirectoryNode,
    ) -> AdminResult<DirectoryMutationAck> {
        Ok(DirectoryMutationAck {
            revision: self.store.update_directory_node(
                id,
                &request.name,
                &request.slug,
                request.description.as_deref(),
                &request.updated_at,
            )?,
        })
    }

    pub fn archive_node(
        &self,
        id: &DirectoryNodeId,
        at: &Timestamp,
    ) -> AdminResult<DirectoryMutationAck> {
        Ok(DirectoryMutationAck {
            revision: self.store.archive_directory_node(id, at)?,
        })
    }

    pub fn product_space_binding(
        &self,
        product_space: &ProductSpaceRef,
    ) -> AdminResult<Option<ProductSpaceBinding>> {
        Ok(self.store.product_space_binding(product_space)?)
    }

    pub fn revision(&self) -> AdminResult<u64> {
        Ok(self.store.directory_revision()?)
    }
}
