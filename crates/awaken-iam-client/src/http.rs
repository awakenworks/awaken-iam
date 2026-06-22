//! Concrete HTTP [`AuthzTransport`] over reqwest's blocking client.
//!
//! This is the production byte-transport for remote mode: it shapes each
//! authorization/entitlement request into the JSON bodies of the remote
//! protocol (`docs/design/remote-protocol.md`), calls the IAM daemon's
//! `/v1` endpoints, and decodes the reasoned response DTOs. The surrounding
//! [`RemoteIamClient`](crate::RemoteIamClient) owns the fail-closed contract —
//! it maps any [`RemoteError`] this transport returns to a deny — so this layer
//! concentrates on the parts every consumer would otherwise re-implement:
//! base-url joining, the service-principal bearer, a single request timeout, and
//! a bounded retry of transient (connection / 5xx) failures.
//!
//! The transport is deliberately blocking: [`AuthzTransport`] is a synchronous
//! trait (a product service asks for a decision and waits on it), so a blocking
//! client keeps the seam free of an async runtime requirement at every call
//! site. The client is `Send + Sync` and cheaply cloneable, so one instance is
//! shared across a service's request handlers.

use std::time::Duration;

use awaken_iam_contract::{
    AuthorizationOutcome, AuthorizationRequest, BatchAuthorizationRequest,
    BatchAuthorizationResponse, EntitlementCheckResponse, EntitlementRequest, NamespaceId,
    PolicySnapshot, ResourceModelRegistered, ResourceModelRegistration, SignerSetSnapshot,
};
use reqwest::StatusCode;
use reqwest::blocking::{Client, RequestBuilder, Response};

use crate::{AuthzTransport, RemoteError};

/// Default per-request timeout when the caller does not specify one.
pub const DEFAULT_TIMEOUT: Duration = Duration::from_secs(3);

/// Default number of *extra* attempts after the first on a transient failure.
pub const DEFAULT_MAX_RETRIES: u32 = 2;

/// Configuration for [`HttpAuthzTransport`].
///
/// `base_url` is the IAM daemon root (e.g. `https://iam.example.com`); the `/v1`
/// paths are appended by the transport. `audience` and `service_token` carry the
/// caller's service-principal identity per the protocol's "auth of the caller"
/// rule — the *transport* principal is the service, while the *subject* travels
/// inside each request body.
#[derive(Debug, Clone)]
pub struct HttpTransportConfig {
    /// Root URL of the IAM daemon, without a trailing `/v1`.
    pub base_url: String,
    /// Audience this caller is scoped to, sent as `X-Iam-Audience` when set.
    pub audience: Option<String>,
    /// Service-principal bearer token, sent as `Authorization: Bearer` when set.
    pub service_token: Option<String>,
    /// Per-request timeout (connect + read). Failing closed depends on this
    /// firing, so a remote that hangs cannot wedge a caller indefinitely.
    pub timeout: Duration,
    /// Extra attempts after the first on a transient (connection / 5xx) error.
    pub max_retries: u32,
}

impl HttpTransportConfig {
    /// Configuration pointing at `base_url` with the default timeout and retry
    /// budget and no caller credentials.
    pub fn new(base_url: impl Into<String>) -> Self {
        Self {
            base_url: base_url.into(),
            audience: None,
            service_token: None,
            timeout: DEFAULT_TIMEOUT,
            max_retries: DEFAULT_MAX_RETRIES,
        }
    }

    /// Set the caller's audience scope.
    pub fn with_audience(mut self, audience: impl Into<String>) -> Self {
        self.audience = Some(audience.into());
        self
    }

    /// Set the service-principal bearer token.
    pub fn with_service_token(mut self, token: impl Into<String>) -> Self {
        self.service_token = Some(token.into());
        self
    }

    /// Set the per-request timeout.
    pub fn with_timeout(mut self, timeout: Duration) -> Self {
        self.timeout = timeout;
        self
    }

    /// Set the number of extra attempts after the first.
    pub fn with_max_retries(mut self, max_retries: u32) -> Self {
        self.max_retries = max_retries;
        self
    }
}

/// Concrete HTTP transport for the remote authorization protocol.
///
/// Holds one reqwest blocking [`Client`] (a connection pool) plus the resolved
/// configuration. Construct it once per process and hand it to
/// [`RemoteIamClient::new`](crate::RemoteIamClient::new).
#[derive(Debug, Clone)]
pub struct HttpAuthzTransport {
    client: Client,
    base_url: String,
    audience: Option<String>,
    service_token: Option<String>,
    max_retries: u32,
}

impl HttpAuthzTransport {
    /// Build a transport from `config`, constructing the underlying client with
    /// the configured timeout. Fails only if the platform cannot initialise the
    /// TLS/HTTP stack.
    pub fn new(config: HttpTransportConfig) -> Result<Self, RemoteError> {
        let client = Client::builder()
            .timeout(config.timeout)
            .build()
            .map_err(|err| RemoteError(format!("build http client: {err}")))?;
        Ok(Self::with_client(client, config))
    }

    /// Build a transport over a caller-provided client, e.g. to share a pool or
    /// inject custom TLS roots. The client's own timeout still applies; the
    /// config's `timeout` field is ignored on this path.
    pub fn with_client(client: Client, config: HttpTransportConfig) -> Self {
        Self {
            client,
            base_url: config.base_url.trim_end_matches('/').to_string(),
            audience: config.audience,
            service_token: config.service_token,
            max_retries: config.max_retries,
        }
    }

    /// Join the configured base URL with a `/v1`-rooted path.
    fn url(&self, path: &str) -> String {
        format!("{}{}", self.base_url, path)
    }

    /// Attach the caller's audience and bearer headers to a request.
    fn with_headers(&self, mut builder: RequestBuilder) -> RequestBuilder {
        if let Some(audience) = &self.audience {
            builder = builder.header("X-Iam-Audience", audience);
        }
        if let Some(token) = &self.service_token {
            builder = builder.bearer_auth(token);
        }
        builder
    }

    /// Run `make_request` up to `1 + max_retries` times, retrying only when the
    /// failure is transient (a connection-level error, or a `5xx` response).
    /// Permanent failures (`4xx`, decode errors) are returned immediately so a
    /// misconfigured caller is not masked by retries.
    fn send_with_retry<F>(&self, make_request: F) -> Result<Response, RemoteError>
    where
        F: Fn() -> RequestBuilder,
    {
        let mut attempt = 0;
        loop {
            let result = self.with_headers(make_request()).send();
            let transient = match &result {
                // A connection/timeout error has no status; treat as transient.
                Err(err) => !err.is_decode(),
                Ok(response) => response.status().is_server_error(),
            };
            if !transient || attempt >= self.max_retries {
                return result.map_err(|err| RemoteError(format!("request failed: {err}")));
            }
            attempt += 1;
        }
    }

    /// Decode a successful JSON response into `T`, mapping a non-success status
    /// or a decode failure to a [`RemoteError`].
    fn decode<T: serde::de::DeserializeOwned>(response: Response) -> Result<T, RemoteError> {
        let status = response.status();
        if status != StatusCode::OK {
            return Err(RemoteError(format!("unexpected status {status}")));
        }
        response
            .json::<T>()
            .map_err(|err| RemoteError(format!("decode response: {err}")))
    }
}

impl AuthzTransport for HttpAuthzTransport {
    fn authorize(
        &self,
        request: &AuthorizationRequest,
    ) -> Result<AuthorizationOutcome, RemoteError> {
        let response =
            self.send_with_retry(|| self.client.post(self.url("/v1/authorize")).json(request))?;
        Self::decode(response)
    }

    fn authorize_batch(
        &self,
        request: &BatchAuthorizationRequest,
    ) -> Result<BatchAuthorizationResponse, RemoteError> {
        let response = self.send_with_retry(|| {
            self.client
                .post(self.url("/v1/authorize/batch"))
                .json(request)
        })?;
        Self::decode(response)
    }

    fn check_entitlement(
        &self,
        request: &EntitlementRequest,
    ) -> Result<EntitlementCheckResponse, RemoteError> {
        let response = self.send_with_retry(|| {
            self.client
                .post(self.url("/v1/entitlements/check"))
                .json(request)
        })?;
        Self::decode(response)
    }

    fn fetch_snapshot(&self) -> Result<PolicySnapshot, RemoteError> {
        let response = self.send_with_retry(|| self.client.get(self.url("/v1/authz/snapshot")))?;
        Self::decode(response)
    }

    fn register_resource_model(
        &self,
        registration: &ResourceModelRegistration,
    ) -> Result<ResourceModelRegistered, RemoteError> {
        let response = self.send_with_retry(|| {
            self.client
                .post(self.url("/v1/authz/resource-model"))
                .json(registration)
        })?;
        Self::decode(response)
    }

    fn fetch_signers(&self, namespace_id: &NamespaceId) -> Result<SignerSetSnapshot, RemoteError> {
        let path = format!("/v1/namespaces/{}/signers", namespace_id.0);
        let response = self.send_with_retry(|| self.client.get(self.url(&path)))?;
        Self::decode(response)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use awaken_iam_contract::{
        AccountId, ActionKey, AuthorizationDecision, EntitlementDecision, PrincipalRef, ScopeRef,
    };
    use std::io::{Read, Write};
    use std::net::TcpListener;
    use std::sync::Arc;
    use std::thread;

    /// What a stub endpoint should answer with for a single request.
    #[derive(Clone)]
    enum Reply {
        /// Send `200 OK` with this JSON body.
        Ok(String),
        /// Send this status with an empty body (e.g. `500`, `403`).
        Status(u16),
    }

    /// A throwaway single-threaded HTTP/1.1 server that answers a scripted list
    /// of replies in order, recording the raw request lines it received. It lets
    /// the transport be exercised end to end (request shaping, retry, decode)
    /// with no network dependency and no extra crates.
    struct StubServer {
        addr: String,
        requests: Arc<std::sync::Mutex<Vec<String>>>,
        handle: Option<thread::JoinHandle<()>>,
    }

    impl StubServer {
        fn start(replies: Vec<Reply>) -> Self {
            let listener = TcpListener::bind("127.0.0.1:0").unwrap();
            let addr = format!("http://{}", listener.local_addr().unwrap());
            let requests = Arc::new(std::sync::Mutex::new(Vec::new()));
            let recorded = Arc::clone(&requests);
            let handle = thread::spawn(move || {
                for reply in replies {
                    let (mut stream, _) = match listener.accept() {
                        Ok(pair) => pair,
                        Err(_) => return,
                    };
                    let mut buf = [0u8; 4096];
                    let n = stream.read(&mut buf).unwrap_or(0);
                    recorded
                        .lock()
                        .unwrap()
                        .push(String::from_utf8_lossy(&buf[..n]).to_string());
                    let payload = match reply {
                        Reply::Ok(body) => format!(
                            "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                            body.len(),
                            body
                        ),
                        Reply::Status(code) => format!(
                            "HTTP/1.1 {code} STATUS\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
                        ),
                    };
                    let _ = stream.write_all(payload.as_bytes());
                    let _ = stream.flush();
                }
            });
            Self {
                addr,
                requests,
                handle: Some(handle),
            }
        }

        fn requests(&self) -> Vec<String> {
            self.requests.lock().unwrap().clone()
        }
    }

    impl Drop for StubServer {
        fn drop(&mut self) {
            if let Some(handle) = self.handle.take() {
                let _ = handle.join();
            }
        }
    }

    fn transport(server: &StubServer) -> HttpAuthzTransport {
        HttpAuthzTransport::new(
            HttpTransportConfig::new(&server.addr)
                .with_max_retries(0)
                .with_timeout(Duration::from_secs(2)),
        )
        .unwrap()
    }

    fn auth_request(action: &str) -> AuthorizationRequest {
        AuthorizationRequest::direct(
            PrincipalRef::Account {
                account_id: AccountId("acct_1".into()),
            },
            ActionKey(action.into()),
            ScopeRef::Global,
        )
    }

    #[test]
    fn authorize_posts_request_and_decodes_outcome() {
        let body = r#"{"decision":"allow","reason":"allowed_by_grant","matched_grants":["g1"],"matched_roles":[]}"#;
        let server = StubServer::start(vec![Reply::Ok(body.into())]);
        let transport = transport(&server);

        let outcome = transport.authorize(&auth_request("pack.read")).unwrap();
        assert_eq!(outcome.decision, AuthorizationDecision::Allow);
        assert_eq!(outcome.matched_grants, vec!["g1".to_string()]);

        drop(transport);
        let recorded = server.requests();
        assert!(recorded[0].starts_with("POST /v1/authorize "));
        assert!(recorded[0].contains("pack.read"));
    }

    #[test]
    fn entitlement_check_decodes_decision() {
        let body = r#"{"decision":"allow","reason":"plan_entitles"}"#;
        let server = StubServer::start(vec![Reply::Ok(body.into())]);
        let transport = transport(&server);

        let response = transport
            .check_entitlement(&EntitlementRequest {
                principal: PrincipalRef::Account {
                    account_id: AccountId("acct_1".into()),
                },
                entitlement: "pack.read".into(),
                resource: None,
            })
            .unwrap();
        assert_eq!(response.decision, EntitlementDecision::Allow);

        drop(transport);
        assert!(server.requests()[0].starts_with("POST /v1/entitlements/check "));
    }

    #[test]
    fn snapshot_is_fetched_with_get() {
        let body = r#"{"version":7,"grants":[],"role_bindings":[],"scope_graph":{"namespace_orgs":[],"workspace_orgs":[],"resource_parents":[]}}"#;
        let server = StubServer::start(vec![Reply::Ok(body.into())]);
        let transport = transport(&server);

        assert_eq!(transport.fetch_snapshot().unwrap().version, 7);

        drop(transport);
        assert!(server.requests()[0].starts_with("GET /v1/authz/snapshot "));
    }

    #[test]
    fn non_success_status_is_a_transport_error() {
        let server = StubServer::start(vec![Reply::Status(403)]);
        let transport = transport(&server);
        let err = transport.authorize(&auth_request("pack.read")).unwrap_err();
        assert!(err.0.contains("403"), "unexpected error: {}", err.0);
    }

    #[test]
    fn server_error_is_retried_then_succeeds() {
        let body =
            r#"{"decision":"deny","reason":"default_deny","matched_grants":[],"matched_roles":[]}"#;
        let server = StubServer::start(vec![Reply::Status(503), Reply::Ok(body.into())]);
        let transport = HttpAuthzTransport::new(
            HttpTransportConfig::new(&server.addr)
                .with_max_retries(1)
                .with_timeout(Duration::from_secs(2)),
        )
        .unwrap();

        let outcome = transport.authorize(&auth_request("pack.delete")).unwrap();
        assert_eq!(outcome.decision, AuthorizationDecision::Deny);

        drop(transport);
        assert_eq!(
            server.requests().len(),
            2,
            "the 503 should have been retried"
        );
    }

    #[test]
    fn retries_are_bounded_and_then_fail_closed() {
        // Two 500s but only one retry: the transport gives up and surfaces the
        // error, which the RemoteIamClient turns into a deny.
        let server = StubServer::start(vec![Reply::Status(500), Reply::Status(500)]);
        let transport = HttpAuthzTransport::new(
            HttpTransportConfig::new(&server.addr)
                .with_max_retries(1)
                .with_timeout(Duration::from_secs(2)),
        )
        .unwrap();

        let err = transport.authorize(&auth_request("pack.read")).unwrap_err();
        assert!(err.0.contains("500"), "unexpected error: {}", err.0);

        drop(transport);
        assert_eq!(
            server.requests().len(),
            2,
            "first attempt plus exactly one retry"
        );
    }

    #[test]
    fn headers_carry_the_service_principal() {
        let body = r#"{"decision":"allow","reason":"allowed_by_grant","matched_grants":[],"matched_roles":[]}"#;
        let server = StubServer::start(vec![Reply::Ok(body.into())]);
        let transport = HttpAuthzTransport::new(
            HttpTransportConfig::new(&server.addr)
                .with_audience("packs-service")
                .with_service_token("svc-token-abc")
                .with_max_retries(0),
        )
        .unwrap();

        transport.authorize(&auth_request("pack.read")).unwrap();

        drop(transport);
        let recorded = server.requests();
        assert!(recorded[0].contains("x-iam-audience: packs-service"));
        assert!(recorded[0].contains("authorization: Bearer svc-token-abc"));
    }
}
