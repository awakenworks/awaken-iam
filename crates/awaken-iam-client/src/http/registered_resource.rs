use super::*;
use awaken_iam_contract::{
    RegisteredResourceAuthorizationEvaluation, RegisteredResourceAuthorizationRequest,
};
impl crate::RegisteredResourceAuthzTransport for HttpAuthzTransport {
    fn authorize_registered_resource(
        &self,
        request: &RegisteredResourceAuthorizationRequest,
    ) -> Result<RegisteredResourceAuthorizationEvaluation, RemoteError> {
        // A failed current evaluation aborts this attempt. A later healthy
        // decision must require an explicit new caller request, even when this
        // transport retains legacy retries for its other protocol methods.
        let response = self
            .with_headers(
                self.client
                    .post(self.url("/v1/authorize/resource/registered"))
                    .json(request),
            )?
            .send()
            .map_err(|error| RemoteError::new(format!("request failed: {error}")))?;
        let result = Self::decode(response)?;
        crate::registered_resource::validate(request, &result)?;
        Ok(result)
    }
}

#[cfg(test)]
mod tests {
    use super::super::tests::{Reply, StubServer, transport};
    use super::*;
    use crate::RegisteredResourceAuthzTransport;
    fn question() -> RegisteredResourceAuthorizationRequest {
        serde_json::from_value(serde_json::json!({"authorization":{"request":{"principal":{"kind":"account","account_id":"owner"},"action":"awaken.workspace::agent.use","scope":{"kind":"resource","resource_type":"awaken.agent","resource_id":"agent"}},"context":{}},"namespace":"awaken.workspace","product_id":"awaken","workspace_id":"workspace","resource_type":"awaken.agent"})).unwrap()
    }
    #[test]
    fn strict_transport_never_retries_an_old_route_or_qualifies_a_legacy_allow() {
        for reply in [Reply::Status(404),Reply::Status(503),Reply::Ok(r#"{"decision":"allow","reason":"legacy","matched_grants":[],"matched_roles":[]}"#.into()),
            Reply::Ok(r#"{"evaluation":{"outcome":{"decision":"allow","reason":"legacy","matched_grants":[],"matched_roles":[]}}}"#.into())] {
            let server=StubServer::start(vec![reply]);
            assert!(transport(&server).authorize_registered_resource(&question()).is_err());
            let requests=server.requests();assert_eq!(requests.len(),1);
            assert!(requests[0].starts_with("POST /v1/authorize/resource/registered "));
            assert!(requests[0].contains("\"product_id\":\"awaken\""));
        }
    }
}
