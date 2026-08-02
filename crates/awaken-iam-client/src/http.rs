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

use std::path::PathBuf;
use std::time::Duration;

use awaken_iam_contract::{
    AcceptInvitation, AcceptedInvitation, ActivateAuthorizationProfile, AdminMutationAck,
    AuthorizationOutcome, AuthorizationProfile, AuthorizationProfileActivated,
    AuthorizationProfileValidation, AuthorizationRequest, BatchAuthorizationRequest,
    BatchAuthorizationResponse, CreateAuthorizationProfile, CreateInvitation,
    EntitlementCheckResponse, EntitlementRequest, GrantSnapshot, InvitationDto, InvitationId,
    InvitationQuery, IssuedInvitation, MembershipQuery, NamespaceId, OrgDto, PolicySnapshot,
    ResendInvitation, ResourceModelRegistered, ResourceModelRegistration, RoleBindingSnapshot,
    RoleDto, ScopeMembershipQuery, SignerSetSnapshot, TokenIntrospectionRequest,
    TokenIntrospectionResponse, UserInfo, WorkspaceOrgEdge,
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
    /// File containing the service-principal bearer token. The file is read for
    /// every request attempt so projected credential rotation needs no restart.
    pub service_token_file: Option<PathBuf>,
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
            service_token_file: None,
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

    /// Read the service-principal bearer from `path` for every request attempt.
    pub fn with_service_token_file(mut self, path: impl Into<PathBuf>) -> Self {
        self.service_token_file = Some(path.into());
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
    service_token_file: Option<PathBuf>,
    max_retries: u32,
}

impl HttpAuthzTransport {
    /// Build a transport from `config`, constructing the underlying client with
    /// the configured timeout. Fails only if the platform cannot initialise the
    /// TLS/HTTP stack.
    pub fn new(config: HttpTransportConfig) -> Result<Self, RemoteError> {
        Self::validate_credential_source(&config)?;
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
            service_token_file: config.service_token_file,
            max_retries: config.max_retries,
        }
    }

    fn validate_credential_source(config: &HttpTransportConfig) -> Result<(), RemoteError> {
        if config.service_token.is_some() && config.service_token_file.is_some() {
            return Err(RemoteError(
                "service_token and service_token_file are mutually exclusive".to_owned(),
            ));
        }
        Ok(())
    }

    /// Join the configured base URL with a `/v1`-rooted path.
    fn url(&self, path: &str) -> String {
        format!("{}{}", self.base_url, path)
    }

    /// Attach the caller's audience and bearer headers to a request.
    fn with_headers(&self, mut builder: RequestBuilder) -> Result<RequestBuilder, RemoteError> {
        if self.service_token.is_some() && self.service_token_file.is_some() {
            return Err(RemoteError(
                "service_token and service_token_file are mutually exclusive".to_owned(),
            ));
        }
        if let Some(audience) = &self.audience {
            builder = builder.header("X-Iam-Audience", audience);
        }
        let projected_token = self
            .service_token_file
            .as_ref()
            .map(|path| {
                std::fs::read_to_string(path)
                    .map_err(|error| {
                        RemoteError(format!(
                            "read service token file {}: {error}",
                            path.display()
                        ))
                    })
                    .and_then(|token| {
                        let token = token.trim().to_owned();
                        if token.is_empty() {
                            Err(RemoteError(format!(
                                "service token file {} is empty",
                                path.display()
                            )))
                        } else {
                            Ok(token)
                        }
                    })
            })
            .transpose()?;
        if let Some(token) = projected_token.as_ref().or(self.service_token.as_ref()) {
            builder = builder.bearer_auth(token);
        }
        Ok(builder)
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
            let result = self.with_headers(make_request())?.send();
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

    fn introspect_token(
        &self,
        request: &TokenIntrospectionRequest,
    ) -> Result<TokenIntrospectionResponse, RemoteError> {
        let response = self.send_with_retry(|| {
            self.client
                .post(self.url("/v1/tokens/introspect"))
                .json(request)
        })?;
        Self::decode(response)
    }

    fn create_org(&self, org: &OrgDto) -> Result<AdminMutationAck, RemoteError> {
        let response =
            self.send_with_retry(|| self.client.post(self.url("/v1/admin/orgs")).json(org))?;
        Self::decode(response)
    }

    fn list_orgs(&self) -> Result<Vec<OrgDto>, RemoteError> {
        let response = self.send_with_retry(|| self.client.get(self.url("/v1/admin/orgs")))?;
        Self::decode(response)
    }

    fn get_org(&self, org_id: &str) -> Result<Option<OrgDto>, RemoteError> {
        let path = format!("/v1/admin/orgs/{org_id}");
        let response = self.send_with_retry(|| self.client.get(self.url(&path)))?;
        if response.status() == StatusCode::NOT_FOUND {
            return Ok(None);
        }
        Self::decode(response).map(Some)
    }

    fn create_role(&self, role: &RoleDto) -> Result<AdminMutationAck, RemoteError> {
        let response =
            self.send_with_retry(|| self.client.post(self.url("/v1/admin/roles")).json(role))?;
        Self::decode(response)
    }

    fn get_role(&self, role_id: &str) -> Result<Option<RoleDto>, RemoteError> {
        let path = format!("/v1/admin/roles/{role_id}");
        let response = self.send_with_retry(|| self.client.get(self.url(&path)))?;
        if response.status() == StatusCode::NOT_FOUND {
            return Ok(None);
        }
        Self::decode(response).map(Some)
    }

    fn issue_grant(&self, grant: &GrantSnapshot) -> Result<AdminMutationAck, RemoteError> {
        let response =
            self.send_with_retry(|| self.client.post(self.url("/v1/admin/grants")).json(grant))?;
        Self::decode(response)
    }

    fn get_grant(&self, grant_id: &str) -> Result<Option<GrantSnapshot>, RemoteError> {
        let path = format!("/v1/admin/grants/{grant_id}");
        let response = self.send_with_retry(|| self.client.get(self.url(&path)))?;
        if response.status() == StatusCode::NOT_FOUND {
            return Ok(None);
        }
        Self::decode(response).map(Some)
    }

    fn grant_membership(
        &self,
        binding: &RoleBindingSnapshot,
    ) -> Result<AdminMutationAck, RemoteError> {
        let response = self.send_with_retry(|| {
            self.client
                .post(self.url("/v1/admin/memberships"))
                .json(binding)
        })?;
        Self::decode(response)
    }

    fn revoke_membership(
        &self,
        binding: &RoleBindingSnapshot,
    ) -> Result<AdminMutationAck, RemoteError> {
        let response = self.send_with_retry(|| {
            self.client
                .delete(self.url("/v1/admin/memberships"))
                .json(binding)
        })?;
        Self::decode(response)
    }

    fn memberships_for_principal(
        &self,
        query: &MembershipQuery,
    ) -> Result<Vec<RoleBindingSnapshot>, RemoteError> {
        let response = self.send_with_retry(|| {
            self.client
                .post(self.url("/v1/admin/memberships/query"))
                .json(query)
        })?;
        Self::decode(response)
    }

    fn memberships_for_scope(
        &self,
        query: &ScopeMembershipQuery,
    ) -> Result<Vec<RoleBindingSnapshot>, RemoteError> {
        let response = self.send_with_retry(|| {
            self.client
                .post(self.url("/v1/admin/memberships/query-scope"))
                .json(query)
        })?;
        Self::decode(response)
    }

    fn create_invitation(
        &self,
        request: &CreateInvitation,
    ) -> Result<IssuedInvitation, RemoteError> {
        let response = self.send_with_retry(|| {
            self.client
                .post(self.url("/v1/admin/invitations"))
                .json(request)
        })?;
        Self::decode(response)
    }

    fn list_invitations(&self, query: &InvitationQuery) -> Result<Vec<InvitationDto>, RemoteError> {
        let response = self.send_with_retry(|| {
            self.client
                .post(self.url("/v1/admin/invitations/query"))
                .json(query)
        })?;
        Self::decode(response)
    }

    fn revoke_invitation(&self, id: &InvitationId) -> Result<AdminMutationAck, RemoteError> {
        let path = format!("/v1/admin/invitations/{}", id.0);
        let response = self.send_with_retry(|| self.client.delete(self.url(&path)))?;
        Self::decode(response)
    }

    fn resend_invitation(
        &self,
        id: &InvitationId,
        request: &ResendInvitation,
    ) -> Result<IssuedInvitation, RemoteError> {
        let path = format!("/v1/admin/invitations/{}/resend", id.0);
        let response = self.send_with_retry(|| self.client.post(self.url(&path)).json(request))?;
        Self::decode(response)
    }

    fn accept_invitation(
        &self,
        id: &InvitationId,
        request: &AcceptInvitation,
    ) -> Result<AcceptedInvitation, RemoteError> {
        let path = format!("/v1/admin/invitations/{}/accept", id.0);
        let response = self.send_with_retry(|| self.client.post(self.url(&path)).json(request))?;
        Self::decode(response)
    }

    fn userinfo(&self, access_token: &str) -> Result<UserInfo, RemoteError> {
        let response = self
            .client
            .get(self.url("/v1/oauth/userinfo"))
            .bearer_auth(access_token)
            .send()
            .map_err(|error| RemoteError(format!("request failed: {error}")))?;
        Self::decode(response)
    }

    fn assign_workspace_org(
        &self,
        edge: &WorkspaceOrgEdge,
    ) -> Result<AdminMutationAck, RemoteError> {
        let response = self.send_with_retry(|| {
            self.client
                .post(self.url("/v1/admin/scope/workspace-orgs"))
                .json(edge)
        })?;
        Self::decode(response)
    }

    fn create_profile(
        &self,
        request: &CreateAuthorizationProfile,
    ) -> Result<AuthorizationProfile, RemoteError> {
        let response = self.send_with_retry(|| {
            self.client
                .post(self.url("/v1/admin/authz/profiles"))
                .json(request)
        })?;
        Self::decode(response)
    }

    fn validate_profile(
        &self,
        namespace: &NamespaceId,
        revision: u64,
    ) -> Result<AuthorizationProfileValidation, RemoteError> {
        let path = format!(
            "/v1/admin/authz/profiles/{}/{revision}/validate",
            namespace.0
        );
        let response = self.send_with_retry(|| self.client.post(self.url(&path)))?;
        Self::decode(response)
    }

    fn activate_profile(
        &self,
        namespace: &NamespaceId,
        revision: u64,
        request: &ActivateAuthorizationProfile,
    ) -> Result<AuthorizationProfileActivated, RemoteError> {
        let path = format!(
            "/v1/admin/authz/profiles/{}/{revision}/activate",
            namespace.0
        );
        let response = self.send_with_retry(|| self.client.post(self.url(&path)).json(request))?;
        Self::decode(response)
    }

    fn rollback_profile(
        &self,
        namespace: &NamespaceId,
        revision: u64,
        request: &ActivateAuthorizationProfile,
    ) -> Result<AuthorizationProfileActivated, RemoteError> {
        let path = format!(
            "/v1/admin/authz/profiles/{}/{revision}/rollback",
            namespace.0
        );
        let response = self.send_with_retry(|| self.client.post(self.url(&path)).json(request))?;
        Self::decode(response)
    }

    fn active_profile(&self, namespace: &NamespaceId) -> Result<AuthorizationProfile, RemoteError> {
        let path = format!("/v1/admin/authz/profiles/{}/active", namespace.0);
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
    fn directory_pap_uses_the_canonical_admin_paths() {
        let binding_json = r#"[{"principal":{"kind":"account","account_id":"acct_1"},"role_id":"tenant-admin","scope":{"kind":"org","org_id":"acme"}}]"#;
        let server = StubServer::start(vec![
            Reply::Ok(r#"{"version":2}"#.into()),
            Reply::Ok(r#"[{"id":"acme","owner":{"kind":"account","account_id":"acct_1"},"created_at":"t","updated_at":"t"}]"#.into()),
            Reply::Ok(r#"{"version":3}"#.into()),
            Reply::Ok(r#"{"id":"tenant-admin","display_name":"Tenant administrator","action_patterns":["awaken.cloud::*"],"created_at":"t","updated_at":"t"}"#.into()),
            Reply::Ok(r#"{"version":4}"#.into()),
            Reply::Ok(binding_json.into()),
            Reply::Ok(r#"{"version":5}"#.into()),
        ]);
        let transport = transport(&server);
        let principal = PrincipalRef::Account {
            account_id: AccountId("acct_1".into()),
        };
        transport
            .create_org(&OrgDto {
                id: awaken_iam_contract::OrgId("acme".into()),
                display_name: None,
                owner: principal.clone(),
                created_at: awaken_iam_contract::Timestamp("t".into()),
                updated_at: awaken_iam_contract::Timestamp("t".into()),
            })
            .unwrap();
        assert_eq!(
            transport.list_orgs().unwrap(),
            vec![OrgDto {
                id: awaken_iam_contract::OrgId("acme".into()),
                display_name: None,
                owner: principal.clone(),
                created_at: awaken_iam_contract::Timestamp("t".into()),
                updated_at: awaken_iam_contract::Timestamp("t".into()),
            }]
        );
        transport
            .create_role(&RoleDto {
                id: "tenant-admin".into(),
                display_name: Some("Tenant administrator".into()),
                action_patterns: vec!["awaken.cloud::*".into()],
                created_at: awaken_iam_contract::Timestamp("t".into()),
                updated_at: awaken_iam_contract::Timestamp("t".into()),
            })
            .unwrap();
        assert_eq!(
            transport.get_role("tenant-admin").unwrap().unwrap().id,
            "tenant-admin"
        );
        let binding = RoleBindingSnapshot {
            principal: principal.clone(),
            role_id: "tenant-admin".into(),
            scope: ScopeRef::Org {
                org_id: awaken_iam_contract::OrgId("acme".into()),
            },
        };
        transport.grant_membership(&binding).unwrap();
        assert_eq!(
            transport
                .memberships_for_principal(&MembershipQuery { principal })
                .unwrap(),
            vec![binding]
        );
        transport
            .assign_workspace_org(&WorkspaceOrgEdge {
                workspace_id: awaken_iam_contract::WorkspaceId("ws_flow".into()),
                org_id: awaken_iam_contract::OrgId("acme".into()),
            })
            .unwrap();

        let requests = server.requests();
        assert!(requests[0].starts_with("POST /v1/admin/orgs "));
        assert!(requests[1].starts_with("GET /v1/admin/orgs "));
        assert!(requests[2].starts_with("POST /v1/admin/roles "));
        assert!(requests[3].starts_with("GET /v1/admin/roles/tenant-admin "));
        assert!(requests[4].starts_with("POST /v1/admin/memberships "));
        assert!(requests[5].starts_with("POST /v1/admin/memberships/query "));
        assert!(requests[6].starts_with("POST /v1/admin/scope/workspace-orgs "));
    }

    #[test]
    fn missing_role_is_an_empty_canonical_query() {
        let server = StubServer::start(vec![Reply::Status(404)]);
        assert_eq!(transport(&server).get_role("missing").unwrap(), None);
    }

    #[test]
    fn missing_org_is_an_empty_canonical_query() {
        let server = StubServer::start(vec![Reply::Status(404)]);
        assert_eq!(transport(&server).get_org("missing").unwrap(), None);
    }

    #[test]
    fn grant_pap_uses_the_canonical_admin_paths() {
        let grant_json = r#"{"id":"tenant-admin-console","subject":{"kind":"role","role_id":"tenant-admin"},"action_pattern":"console.tenant.admin.access","scope":{"kind":"global"},"effect":"allow"}"#;
        let server = StubServer::start(vec![
            Reply::Ok(r#"{"version":6}"#.into()),
            Reply::Ok(grant_json.into()),
        ]);
        let grant = GrantSnapshot {
            id: "tenant-admin-console".into(),
            subject: awaken_iam_contract::GrantSubjectRef::Role {
                role_id: "tenant-admin".into(),
            },
            action_pattern: "console.tenant.admin.access".into(),
            scope: ScopeRef::Global,
            effect: awaken_iam_contract::GrantEffect::Allow,
        };
        let transport = transport(&server);
        transport.issue_grant(&grant).unwrap();
        assert_eq!(transport.get_grant(&grant.id).unwrap(), Some(grant));

        let requests = server.requests();
        assert!(requests[0].starts_with("POST /v1/admin/grants "));
        assert!(requests[1].starts_with("GET /v1/admin/grants/tenant-admin-console "));
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

    #[test]
    fn projected_service_token_is_reloaded_for_each_request() {
        let body = r#"{"decision":"allow","reason":"allowed_by_grant","matched_grants":[],"matched_roles":[]}"#;
        let server = StubServer::start(vec![Reply::Ok(body.into()), Reply::Ok(body.into())]);
        let path = std::env::temp_dir().join(format!(
            "awaken-iam-service-token-{}-{}",
            std::process::id(),
            std::thread::current().name().unwrap_or("test")
        ));
        std::fs::write(&path, "first-token\n").unwrap();
        let transport = HttpAuthzTransport::new(
            HttpTransportConfig::new(&server.addr)
                .with_service_token_file(&path)
                .with_max_retries(0),
        )
        .unwrap();

        transport.authorize(&auth_request("pack.read")).unwrap();
        std::fs::write(&path, "second-token\n").unwrap();
        transport.authorize(&auth_request("pack.read")).unwrap();

        drop(transport);
        let recorded = server.requests();
        assert!(recorded[0].contains("authorization: Bearer first-token"));
        assert!(recorded[1].contains("authorization: Bearer second-token"));
        std::fs::remove_file(path).unwrap();
    }

    #[test]
    fn invalid_projected_service_token_fails_before_network_io() {
        let missing = std::env::temp_dir().join(format!(
            "awaken-iam-missing-service-token-{}",
            std::process::id()
        ));
        let _ = std::fs::remove_file(&missing);
        let transport = HttpAuthzTransport::new(
            HttpTransportConfig::new("http://127.0.0.1:9")
                .with_service_token_file(&missing)
                .with_max_retries(0),
        )
        .unwrap();
        let error = transport.authorize(&auth_request("pack.read")).unwrap_err();
        assert!(error.0.contains("read service token file"));

        std::fs::write(&missing, " \n").unwrap();
        let error = transport.authorize(&auth_request("pack.read")).unwrap_err();
        assert!(error.0.contains("is empty"));
        std::fs::remove_file(missing).unwrap();
    }

    #[test]
    fn static_and_projected_service_tokens_are_rejected_as_duplicate_sources() {
        let error = HttpAuthzTransport::new(
            HttpTransportConfig::new("http://127.0.0.1:9")
                .with_service_token("static")
                .with_service_token_file("/projected/token"),
        )
        .unwrap_err();
        assert!(error.0.contains("mutually exclusive"));
    }

    #[test]
    fn introspect_token_posts_to_introspect_path_and_decodes_response() {
        use awaken_iam_contract::{ApiTokenStatus, TokenIntrospectionRequest, WorkspaceId};
        let body = r#"{"principal":{"kind":"service","service_id":"ci"},"workspace":"ws_1","status":"active"}"#;
        let server = StubServer::start(vec![Reply::Ok(body.into())]);
        let transport = transport(&server);

        let request = TokenIntrospectionRequest {
            token: String::from("sk-awaken-pfx.secret"),
        };
        let response = transport.introspect_token(&request).unwrap();
        assert_eq!(
            response.principal,
            PrincipalRef::Service {
                service_id: "ci".into()
            }
        );
        assert_eq!(response.workspace, WorkspaceId("ws_1".into()));
        assert_eq!(response.status, ApiTokenStatus::Active);

        drop(transport);
        assert!(server.requests()[0].starts_with("POST /v1/tokens/introspect "));
    }

    #[test]
    fn introspect_token_surfaces_401_as_remote_error() {
        use awaken_iam_contract::TokenIntrospectionRequest;
        let server = StubServer::start(vec![Reply::Status(401)]);
        let transport = transport(&server);

        let err = transport
            .introspect_token(&TokenIntrospectionRequest {
                token: String::from("sk-awaken-bad.token"),
            })
            .unwrap_err();
        assert!(err.0.contains("401"), "unexpected error: {}", err.0);
    }
}
