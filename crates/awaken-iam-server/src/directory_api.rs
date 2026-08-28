//! Application boundary for user-visible hierarchy and product-space placement.
//!
//! This context shares IAM deployment infrastructure but does not mutate or
//! version authorization policy. Products retain stable business identifiers;
//! Directory owns the generated node identity, canonical slug, audit actor,
//! timestamps, active state, and movable presentation placement.

use awaken_iam_contract::{
    CreateDirectoryNode, DirectoryChildrenView, DirectoryMutationAck, DirectoryNodeId,
    DirectoryNodeMutationResult, DirectoryNodeView, EnsureProductSpacePlacement, MoveDirectoryNode,
    OrgId, PrincipalRef, ProductId, ProductSpaceLifecycleResult, ProductSpacePlacement,
    ProductSpacePlacementResult, ProductSpacePlacementStatus, ProductSpaceRef,
    RetireProductSpacePlacement, Timestamp, UpdateDirectoryNode,
};
use awaken_iam_core::{DirectoryNode, DirectoryRepository, RepositoryError};
use base64::Engine as _;
use sha2::{Digest, Sha256};

use crate::admin_api::{AdminError, AdminResult};

/// Authenticated application-command metadata supplied by the composition edge.
///
/// It is deliberately not part of the wire request: HTTP derives it after
/// authentication and embedded products provide their service principal. This
/// prevents callers from choosing their own audit actor or persistence time.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DirectoryCommandContext {
    pub actor: PrincipalRef,
    pub at: Timestamp,
    product_id: Option<ProductId>,
}

impl DirectoryCommandContext {
    pub fn new(actor: PrincipalRef, at: Timestamp) -> Self {
        Self {
            actor,
            at,
            product_id: None,
        }
    }

    pub fn service(service_id: impl Into<String>, at: Timestamp) -> Self {
        Self::new(
            PrincipalRef::Service {
                service_id: service_id.into(),
            },
            at,
        )
    }

    /// Bind an embedded or authenticated product caller to its own namespace.
    pub fn product_service(
        product_id: ProductId,
        service_id: impl Into<String>,
        at: Timestamp,
    ) -> Self {
        let mut context = Self::service(service_id, at);
        context.product_id = Some(product_id);
        context
    }

    fn authorize(&self, product_id: &ProductId) -> AdminResult<()> {
        if self
            .product_id
            .as_ref()
            .is_some_and(|allowed| allowed != product_id)
        {
            return Err(AdminError::Invalid(format!(
                "product caller may not place product {product_id}"
            )));
        }
        Ok(())
    }
}

/// One application service over the selected Directory repository adapter.
#[derive(Debug, Clone)]
pub struct DirectoryApi<S> {
    store: S,
}

impl<S: DirectoryRepository> DirectoryApi<S> {
    pub fn new(store: S) -> Self {
        Self { store }
    }

    /// Create a user-managed folder. Product spaces must use
    /// [`Self::ensure_product_space_placement`], the canonical placement command.
    pub fn create_node(
        &self,
        request: CreateDirectoryNode,
        context: DirectoryCommandContext,
    ) -> AdminResult<DirectoryNodeMutationResult> {
        let node = DirectoryNode {
            id: random_node_id()?,
            org_id: request.org_id,
            parent_id: request.parent_id,
            name: request.name,
            slug: canonical_slug(&request.preferred_slug, None),
            description: request.description,
            archived: false,
            created_at: context.at.clone(),
            updated_at: context.at.clone(),
        };
        node.validate()
            .map_err(|error| AdminError::Invalid(error.to_string()))?;
        let revision = self
            .store
            .create_directory_node(node.clone(), None, &context.actor)?;
        Ok(DirectoryNodeMutationResult {
            revision,
            node: node.into(),
        })
    }

    /// Idempotently create or restore the one IAM-owned placement for a stable
    /// product space. Exact retries never overwrite a user's later move or
    /// metadata edits.
    pub fn ensure_product_space_placement(
        &self,
        request: EnsureProductSpacePlacement,
        context: DirectoryCommandContext,
    ) -> AdminResult<ProductSpacePlacementResult> {
        validate_product_space(&request.product_space)?;
        context.authorize(&request.product_space.product_id)?;
        if request.name.trim().is_empty() {
            return Err(AdminError::Invalid(
                "directory node name must not be empty".into(),
            ));
        }
        if let Some(existing) = self
            .store
            .product_space_placement(&request.org_id, &request.product_space)?
        {
            return self.existing_placement(existing, &request.org_id, context);
        }

        let parent_id = request
            .parent_product_space
            .as_ref()
            .map(|parent| self.resolve_live_parent(parent, &request.org_id))
            .transpose()?;
        let node = DirectoryNode {
            id: product_space_node_id(&request.org_id, &request.product_space),
            org_id: request.org_id.clone(),
            parent_id,
            name: request.name,
            slug: canonical_slug(
                &request.preferred_slug,
                Some((&request.org_id, &request.product_space)),
            ),
            description: request.description,
            archived: false,
            created_at: context.at.clone(),
            updated_at: context.at.clone(),
        };
        let placement = ProductSpacePlacement {
            product_space: request.product_space.clone(),
            org_id: request.org_id.clone(),
            node_id: node.id.clone(),
            status: ProductSpacePlacementStatus::Active,
        };
        node.validate()
            .map_err(|error| AdminError::Invalid(error.to_string()))?;
        node.validate_placement(&placement)
            .map_err(|error| AdminError::Invalid(error.to_string()))?;

        match self.store.create_directory_node(
            node.clone(),
            Some(placement.clone()),
            &context.actor,
        ) {
            Ok(revision) => Ok(ProductSpacePlacementResult {
                revision,
                node: node.into(),
                placement,
                created: true,
            }),
            Err(error @ RepositoryError::Conflict(_)) => {
                // Cause: a concurrent exact ensure may win the unique
                // product-space key. Effect: converge on that authoritative
                // placement rather than exposing a spurious conflict.
                if let Some(existing) = self
                    .store
                    .product_space_placement(&request.org_id, &request.product_space)?
                {
                    self.existing_placement(existing, &request.org_id, context)
                } else {
                    Err(error.into())
                }
            }
            Err(error) => Err(error.into()),
        }
    }

    fn existing_placement(
        &self,
        placement: ProductSpacePlacement,
        expected_org: &OrgId,
        context: DirectoryCommandContext,
    ) -> AdminResult<ProductSpacePlacementResult> {
        if &placement.org_id != expected_org {
            return Err(AdminError::AlreadyExists(
                "product space is already placed in another organization".into(),
            ));
        }
        let node = self
            .store
            .directory_node(&placement.node_id)?
            .ok_or_else(|| {
                AdminError::Backend("product placement points to a missing node".into())
            })?;
        let revision = if placement.status == ProductSpacePlacementStatus::Retired || node.archived
        {
            self.store.set_product_space_placement_status(
                expected_org,
                &placement.product_space,
                ProductSpacePlacementStatus::Active,
                &context.at,
                &context.actor,
            )?
        } else {
            self.store.directory_revision(expected_org)?
        };
        let placement = ProductSpacePlacement {
            status: ProductSpacePlacementStatus::Active,
            ..placement
        };
        let node = if node.archived {
            self.store
                .directory_node(&placement.node_id)?
                .ok_or_else(|| {
                    AdminError::Backend("activated placement points to a missing node".into())
                })?
        } else {
            node
        };
        Ok(ProductSpacePlacementResult {
            revision,
            node: node.into(),
            placement,
            created: false,
        })
    }

    /// Idempotently retire one product space while preserving its stable
    /// binding and user-managed Directory node.
    pub fn retire_product_space_placement(
        &self,
        request: RetireProductSpacePlacement,
        context: DirectoryCommandContext,
    ) -> AdminResult<ProductSpaceLifecycleResult> {
        validate_product_space(&request.product_space)?;
        context.authorize(&request.product_space.product_id)?;
        let placement = self
            .store
            .product_space_placement(&request.org_id, &request.product_space)?
            .ok_or_else(|| AdminError::NotFound("product space has no placement".into()))?;
        let changed = placement.status != ProductSpacePlacementStatus::Retired;
        let revision = self.store.set_product_space_placement_status(
            &request.org_id,
            &request.product_space,
            ProductSpacePlacementStatus::Retired,
            &context.at,
            &context.actor,
        )?;
        let node = self
            .store
            .directory_node(&placement.node_id)?
            .ok_or_else(|| AdminError::Backend("placement points to a missing node".into()))?;
        Ok(ProductSpaceLifecycleResult {
            revision,
            node: node.into(),
            placement: ProductSpacePlacement {
                status: ProductSpacePlacementStatus::Retired,
                ..placement
            },
            changed,
        })
    }

    fn resolve_live_parent(
        &self,
        product_space: &ProductSpaceRef,
        org_id: &OrgId,
    ) -> AdminResult<DirectoryNodeId> {
        validate_product_space(product_space)?;
        let placement = self
            .store
            .product_space_placement(org_id, product_space)?
            .ok_or_else(|| AdminError::NotFound("parent product space has no placement".into()))?;
        if &placement.org_id != org_id {
            return Err(AdminError::Invalid(
                "parent product space belongs to another organization".into(),
            ));
        }
        if placement.status != ProductSpacePlacementStatus::Active {
            return Err(AdminError::NotFound(
                "parent product-space placement is retired".into(),
            ));
        }
        let parent = self
            .store
            .directory_node(&placement.node_id)?
            .filter(|node| !node.archived)
            .ok_or_else(|| AdminError::NotFound("parent Directory node is not live".into()))?;
        Ok(parent.id)
    }

    pub fn node(&self, id: &DirectoryNodeId) -> AdminResult<Option<DirectoryNodeView>> {
        Ok(self.store.directory_node(id)?.map(DirectoryNodeView::from))
    }

    pub fn children(
        &self,
        org_id: &OrgId,
        parent_id: Option<&DirectoryNodeId>,
    ) -> AdminResult<DirectoryChildrenView> {
        let (revision, nodes) = self.store.directory_children(org_id, parent_id)?;
        Ok(DirectoryChildrenView {
            org_id: org_id.clone(),
            revision,
            nodes: nodes.into_iter().map(DirectoryNodeView::from).collect(),
        })
    }

    pub fn move_node(
        &self,
        id: &DirectoryNodeId,
        request: MoveDirectoryNode,
        context: DirectoryCommandContext,
    ) -> AdminResult<DirectoryMutationAck> {
        Ok(DirectoryMutationAck {
            revision: self.store.move_directory_node(
                id,
                request.parent_id.as_ref(),
                &context.at,
                &context.actor,
            )?,
        })
    }

    pub fn update_node(
        &self,
        id: &DirectoryNodeId,
        request: UpdateDirectoryNode,
        context: DirectoryCommandContext,
    ) -> AdminResult<DirectoryMutationAck> {
        Ok(DirectoryMutationAck {
            revision: self.store.update_directory_node(
                id,
                &request.name,
                &request.slug,
                request.description.as_deref(),
                &context.at,
                &context.actor,
            )?,
        })
    }

    pub fn archive_node(
        &self,
        id: &DirectoryNodeId,
        context: DirectoryCommandContext,
    ) -> AdminResult<DirectoryMutationAck> {
        Ok(DirectoryMutationAck {
            revision: self
                .store
                .archive_directory_node(id, &context.at, &context.actor)?,
        })
    }

    pub fn restore_node(
        &self,
        id: &DirectoryNodeId,
        context: DirectoryCommandContext,
    ) -> AdminResult<DirectoryMutationAck> {
        Ok(DirectoryMutationAck {
            revision: self
                .store
                .restore_directory_node(id, &context.at, &context.actor)?,
        })
    }

    pub fn product_space_placement(
        &self,
        org_id: &OrgId,
        product_space: &ProductSpaceRef,
    ) -> AdminResult<Option<ProductSpacePlacement>> {
        Ok(self.store.product_space_placement(org_id, product_space)?)
    }

    pub fn revision(&self, org_id: &OrgId) -> AdminResult<u64> {
        Ok(self.store.directory_revision(org_id)?)
    }
}

fn validate_product_space(product_space: &ProductSpaceRef) -> AdminResult<()> {
    if product_space.space_id.trim().is_empty()
        || product_space.space_id.trim() != product_space.space_id
    {
        return Err(AdminError::Invalid(
            "product space id must not be empty or contain surrounding whitespace".into(),
        ));
    }
    Ok(())
}

fn random_node_id() -> AdminResult<DirectoryNodeId> {
    let mut bytes = [0_u8; 18];
    getrandom::fill(&mut bytes).map_err(|error| {
        AdminError::Backend(format!("directory id entropy unavailable: {error}"))
    })?;
    Ok(DirectoryNodeId(format!(
        "folder_{}",
        base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(bytes)
    )))
}

fn product_space_node_id(org_id: &OrgId, product_space: &ProductSpaceRef) -> DirectoryNodeId {
    let digest = product_space_digest(org_id, product_space);
    DirectoryNodeId(format!(
        "space_{}",
        base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(&digest[..18])
    ))
}

fn product_space_digest(org_id: &OrgId, product_space: &ProductSpaceRef) -> [u8; 32] {
    Sha256::digest(
        format!(
            "{}\u{1f}{}\u{1f}{}",
            org_id.0, product_space.product_id, product_space.space_id
        )
        .as_bytes(),
    )
    .into()
}

fn canonical_slug(raw: &str, product_space: Option<(&OrgId, &ProductSpaceRef)>) -> String {
    let mut base = String::with_capacity(raw.len());
    let mut previous_hyphen = false;
    for byte in raw.bytes().map(|byte| byte.to_ascii_lowercase()) {
        if byte.is_ascii_alphanumeric() {
            base.push(char::from(byte));
            previous_hyphen = false;
        } else if !base.is_empty() && !previous_hyphen {
            base.push('-');
            previous_hyphen = true;
        }
    }
    while base.ends_with('-') {
        base.pop();
    }
    if base.is_empty() {
        base.push_str("space");
    }
    let Some((org_id, product_space)) = product_space else {
        base.truncate(50);
        return base.trim_end_matches('-').to_owned();
    };
    let digest = product_space_digest(org_id, product_space);
    let suffix = digest[..6]
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect::<String>();
    let max_base_len = 50 - suffix.len() - 1;
    base.truncate(base.len().min(max_base_len));
    let base = base.trim_end_matches('-');
    format!("{base}-{suffix}")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn product_space_identity_owns_deterministic_node_and_unique_slug() {
        // Cause/effect decision table: C1=same product coordinate and label,
        // C2=different coordinate with same label. R1(C1) -> identical IAM id
        // and slug for idempotent replay; R2(C2) -> different id and suffix so
        // sibling labels cannot create a second product-side collision policy.
        let first = ProductSpaceRef {
            product_id: ProductId::new("workforce").unwrap(),
            space_id: "workspace/one".into(),
        };
        let second = ProductSpaceRef {
            product_id: ProductId::new("workforce").unwrap(),
            space_id: "workspace/two".into(),
        };
        let org = OrgId("acme".into());
        assert_eq!(
            product_space_node_id(&org, &first),
            product_space_node_id(&org, &first)
        );
        assert_eq!(
            canonical_slug("My Workspace", Some((&org, &first))),
            canonical_slug("My Workspace", Some((&org, &first)))
        );
        assert_ne!(
            product_space_node_id(&org, &first),
            product_space_node_id(&org, &second)
        );
        assert_ne!(
            product_space_node_id(&org, &first),
            product_space_node_id(&OrgId("other".into()), &first)
        );
        assert_ne!(
            canonical_slug("My Workspace", Some((&org, &first))),
            canonical_slug("My Workspace", Some((&org, &second)))
        );
    }
}
