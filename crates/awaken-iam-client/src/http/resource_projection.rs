use super::*;
use awaken_iam_contract::{ResourceProjectionBatch, ResourceProjectionReceipt};

impl crate::ResourceProjectionTransport for HttpAuthzTransport {
    fn apply_resource_projection(
        &self,
        request: &ResourceProjectionBatch,
    ) -> Result<ResourceProjectionReceipt, RemoteError> {
        crate::resource_projection::validate_request(request)?;
        // A lost acknowledgement is not permission to repeat a write. A caller
        // may explicitly retry its same confirmed batch; it must never re-key
        // or reinterpret Stale as proof that the original attempt did not apply.
        let response = self
            .with_headers(
                self.client
                    .post(self.url("/v1/authz/resource-provisions"))
                    .json(request),
            )?
            .send()
            .map_err(|error| RemoteError::new(format!("request failed: {error}")))?;
        let receipt = Self::decode(response)?;
        crate::resource_projection::validate(request, &receipt)?;
        Ok(receipt)
    }
}

#[cfg(test)]
mod tests {
    use super::super::tests::{Reply, StubServer, transport};
    use super::*;
    use crate::ResourceProjectionTransport;
    use awaken_iam_contract::{OrgId, ProductId, ResourceProjectionDisposition};

    fn batch() -> ResourceProjectionBatch {
        ResourceProjectionBatch {
            product_id: ProductId::new("native-product").unwrap(),
            org_id: OrgId("organization".into()),
            projection_id: "agent-target".into(),
            idempotency_key: "same-original-key".into(),
            epoch: 1,
            grants: vec![],
            scope_edges: vec![],
            retirements: vec![],
        }
    }
    fn ack(disposition: ResourceProjectionDisposition) -> ResourceProjectionReceipt {
        ResourceProjectionReceipt {
            idempotency_key: "same-original-key".into(),
            epoch: 1,
            version: 4,
            disposition,
        }
    }

    #[test]
    fn projection_http_uses_the_versioned_body_and_preserves_each_native_disposition() {
        for disposition in [
            ResourceProjectionDisposition::Applied,
            ResourceProjectionDisposition::Replayed,
            ResourceProjectionDisposition::Stale,
        ] {
            let expected = ack(disposition);
            let server =
                StubServer::start(vec![Reply::Ok(serde_json::to_string(&expected).unwrap())]);
            let client = crate::RemoteIamClient::new(transport(&server));
            assert_eq!(
                client.apply_resource_projection(&batch()).unwrap(),
                expected
            );
            let requests = server.requests();
            assert_eq!(requests.len(), 1);
            assert!(requests[0].starts_with("POST /v1/authz/resource-provisions "));
            let body = requests[0].split_once("\r\n\r\n").unwrap().1;
            assert_eq!(
                serde_json::from_str::<ResourceProjectionBatch>(body).unwrap(),
                batch()
            );
            assert!(serde_json::from_str::<awaken_iam_contract::ResourceProvision>(body).is_err());
        }
    }

    #[test]
    fn projection_http_never_retries_a_write_even_with_legacy_default_retries() {
        // The second reply is consumed only by a deliberate second caller
        // invocation with the SAME batch. A retry-runner regression makes the
        // first assertion actually fail instead of being hidden by the fixture.
        let expected = ack(ResourceProjectionDisposition::Applied);
        let server = StubServer::start(vec![
            Reply::Status(503),
            Reply::Ok(serde_json::to_string(&expected).unwrap()),
        ]);
        let mut adapter = transport(&server);
        adapter.max_retries = DEFAULT_MAX_RETRIES;
        let failed = adapter.apply_resource_projection(&batch());
        assert!(failed.is_err());
        assert_eq!(server.requests().len(), 1);
        assert_eq!(
            adapter.apply_resource_projection(&batch()).unwrap(),
            expected
        );
        let requests = server.requests();
        assert_eq!(requests.len(), 2);
        assert_eq!(requests[0], requests[1]);
    }

    #[test]
    fn projection_http_rejects_foreign_or_missing_ack_and_keeps_errors() {
        let mut wrong_key = ack(ResourceProjectionDisposition::Applied);
        wrong_key.idempotency_key = "foreign".into();
        let mut wrong_epoch = ack(ResourceProjectionDisposition::Applied);
        wrong_epoch.epoch = 2;
        let mut missing_version = ack(ResourceProjectionDisposition::Applied);
        missing_version.version = 0;
        let replies = [
            Reply::Status(404),
            Reply::Status(403),
            Reply::Status(503),
            Reply::Ok("{}".into()),
            Reply::Ok(serde_json::to_string(&wrong_key).unwrap()),
            Reply::Ok(serde_json::to_string(&wrong_epoch).unwrap()),
            Reply::Ok(serde_json::to_string(&missing_version).unwrap()),
        ];
        for reply in replies {
            let server = StubServer::start(vec![reply]);
            assert!(
                transport(&server)
                    .apply_resource_projection(&batch())
                    .is_err()
            );
            assert_eq!(server.requests().len(), 1);
        }
    }
}
