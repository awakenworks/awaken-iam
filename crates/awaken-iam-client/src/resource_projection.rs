//! Explicit support for IAM's existing versioned, product-owned projection wire.
use crate::{RemoteError, RemoteIamClient};
use awaken_iam_contract::{ResourceProjectionBatch, ResourceProjectionReceipt};

/// Mandatory capability; legacy outbox transports cannot claim versioned support.
pub trait ResourceProjectionTransport {
    fn apply_resource_projection(
        &self,
        request: &ResourceProjectionBatch,
    ) -> Result<ResourceProjectionReceipt, RemoteError>;
}

impl<T: ResourceProjectionTransport> RemoteIamClient<T> {
    /// Submit the unchanged confirmed batch once. The native product-owner
    /// endpoint validates its authority, stream, epoch, key and payload digest.
    /// This response is a context-bound acknowledgement, not an independent
    /// body/owner proof or current registration/authorization qualification.
    ///
    /// A transport failure leaves the original command unknown: keep its key
    /// and complete body. Stale means this invocation did not apply the older
    /// batch; it does NOT prove a prior lost-ack invocation never applied, and
    /// must not turn that original Unknown into either failure or success.
    pub fn apply_resource_projection(
        &self,
        request: &ResourceProjectionBatch,
    ) -> Result<ResourceProjectionReceipt, RemoteError> {
        validate_request(request)?;
        let receipt = self.transport().apply_resource_projection(request)?;
        validate(request, &receipt)?;
        Ok(receipt)
    }
}

pub(crate) fn validate_request(request: &ResourceProjectionBatch) -> Result<(), RemoteError> {
    if request.epoch == 0
        || request.idempotency_key.trim().is_empty()
        || request.idempotency_key.len() > 160
        || request.projection_id.trim().is_empty()
        || request.projection_id.len() > 160
    {
        return Err(RemoteError::new(
            "projection coordinates are required".into(),
        ));
    }
    Ok(())
}

pub(crate) fn validate(
    request: &ResourceProjectionBatch,
    receipt: &ResourceProjectionReceipt,
) -> Result<(), RemoteError> {
    if request.epoch == 0
        || receipt.epoch != request.epoch
        || receipt.idempotency_key != request.idempotency_key
        || receipt.version == 0
    {
        return Err(RemoteError::new(
            "projection acknowledgement does not match the submitted key/epoch".into(),
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use awaken_iam_contract::{OrgId, ProductId};
    struct Never;
    impl ResourceProjectionTransport for Never {
        fn apply_resource_projection(
            &self,
            _: &ResourceProjectionBatch,
        ) -> Result<ResourceProjectionReceipt, RemoteError> {
            panic!("invalid coordinates reached a write transport");
        }
    }
    #[test]
    fn invalid_projection_coordinates_never_reach_a_write_transport() {
        let baseline = ResourceProjectionBatch {
            product_id: ProductId::new("native").unwrap(),
            org_id: OrgId("org".into()),
            projection_id: "stream".into(),
            idempotency_key: "key".into(),
            epoch: 1,
            grants: vec![],
            scope_edges: vec![],
            retirements: vec![],
        };
        for invalid in 0..4 {
            let mut request = baseline.clone();
            match invalid {
                0 => request.epoch = 0,
                1 => request.idempotency_key = " ".into(),
                2 => request.projection_id = " ".into(),
                _ => request.idempotency_key = "x".repeat(161),
            }
            assert!(
                RemoteIamClient::new(Never)
                    .apply_resource_projection(&request)
                    .is_err()
            );
        }
    }
}
