//! Production reqwest transports for reaching **upstream** identity providers.
//!
//! The login adapters in `awaken-iam-core` —
//! [`GoogleOidcProvider`](awaken_iam_core::GoogleOidcProvider),
//! [`GenericOAuthProvider`](awaken_iam_core::GenericOAuthProvider), and
//! [`GithubProviderAdapter`](awaken_iam_core::GithubProviderAdapter) — are pure:
//! they build the requests and normalize the responses but delegate every byte of
//! network I/O to a trait seam so the domain crate carries no HTTP client. Those
//! seams ([`HttpTransport`](awaken_iam_core::HttpTransport) for the OIDC family,
//! [`GithubTransport`](awaken_iam_core::GithubTransport) for GitHub's REST dialect)
//! shipped with only test stubs, so the daemon could construct an adapter but could
//! not actually reach Google's token/JWKS endpoints, an OIDC provider's discovery
//! document and userinfo endpoint, or GitHub's `GET /user` / `GET /user/emails`.
//!
//! This module supplies the concrete production implementations over reqwest's
//! blocking client, mirroring the consumer-side
//! [`HttpAuthzTransport`](awaken_iam_client::HttpAuthzTransport): construct one per
//! process, share it across logins. Blocking (not async) keeps the seams — which
//! are synchronous traits — free of a runtime requirement at every call site.
//!
//! - [`ReqwestHttpTransport`] drives the OIDC family: it executes an arbitrary
//!   [`HttpRequest`](awaken_iam_core::HttpRequest) and returns the response body on
//!   a `2xx`, surfacing anything else as a failure string, exactly as the seam's
//!   contract requires.
//! - [`ReqwestGithubTransport`] drives GitHub: it holds the deployment client
//!   **secret** (intentionally absent from the shared provider config), attaches a
//!   `User-Agent` (which the GitHub API requires), and decodes the three REST
//!   responses into the core DTOs.

use std::time::Duration;

use awaken_iam_core::{
    GithubAccessToken, GithubEmail, GithubTokenRequest, GithubTransport, GithubTransportError,
    GithubUser, HttpRequest, HttpTransport,
};
use reqwest::Method;
use reqwest::blocking::{Client, RequestBuilder};

/// Default per-request timeout (connect + read) for upstream calls.
///
/// Upstream IdP endpoints are interactive-login dependencies, so a hung provider
/// must not wedge a login indefinitely; the timeout bounds every attempt.
pub const DEFAULT_TIMEOUT: Duration = Duration::from_secs(10);

/// Default GitHub REST API base used when a deployment does not run GitHub
/// Enterprise. The `/user` and `/user/emails` paths are appended to it.
pub const DEFAULT_GITHUB_API_BASE: &str = "https://api.github.com";

/// Default `User-Agent` sent on GitHub API calls. GitHub rejects requests that
/// omit a `User-Agent`, so a non-empty default is always present.
pub const DEFAULT_GITHUB_USER_AGENT: &str = "awaken-iam";

/// Build a blocking [`Client`] with `timeout`, mapping a stack-init failure to a
/// human-readable string (the only way [`Client::builder`] fails).
fn build_client(timeout: Duration) -> Result<Client, String> {
    Client::builder()
        .timeout(timeout)
        .build()
        .map_err(|err| format!("build http client: {err}"))
}

/// Production [`HttpTransport`] for the OIDC provider family (Google + generic).
///
/// Owns one reqwest blocking [`Client`] (a connection pool). Cheaply cloneable and
/// `Send + Sync`, so one instance is shared across every OIDC login of a
/// deployment.
#[derive(Debug, Clone)]
pub struct ReqwestHttpTransport {
    client: Client,
}

impl ReqwestHttpTransport {
    /// Build a transport with the default timeout. Fails only if the platform
    /// cannot initialise the TLS/HTTP stack.
    pub fn new() -> Result<Self, String> {
        Self::with_timeout(DEFAULT_TIMEOUT)
    }

    /// Build a transport whose client uses `timeout` for every request.
    pub fn with_timeout(timeout: Duration) -> Result<Self, String> {
        Ok(Self {
            client: build_client(timeout)?,
        })
    }

    /// Build a transport over a caller-provided client, e.g. to share a pool or
    /// inject custom TLS roots. The client's own timeout applies.
    pub fn with_client(client: Client) -> Self {
        Self { client }
    }
}

impl HttpTransport for ReqwestHttpTransport {
    fn execute(&self, request: &HttpRequest) -> Result<Vec<u8>, String> {
        let method = match request.method {
            "GET" => Method::GET,
            "POST" => Method::POST,
            other => return Err(format!("unsupported http method {other}")),
        };
        let mut builder = self.client.request(method, &request.url);
        for (name, value) in &request.headers {
            builder = builder.header(name.as_str(), value.as_str());
        }
        if !request.body.is_empty() {
            builder = builder.body(request.body.clone());
        }

        let response = builder
            .send()
            .map_err(|err| format!("request to {} failed: {err}", request.url))?;
        let status = response.status();
        let body = response
            .bytes()
            .map_err(|err| format!("reading response body from {} failed: {err}", request.url))?;
        if status.is_success() {
            Ok(body.to_vec())
        } else {
            Err(format!(
                "upstream {} responded with status {status}",
                request.url
            ))
        }
    }
}

/// Production [`GithubTransport`] over reqwest's blocking client.
///
/// Holds the deployment OAuth client **secret** — deliberately kept off the shared
/// provider config — plus the REST API base and a `User-Agent`. Construct once per
/// process and hand it to
/// [`GithubProviderAdapter::new`](awaken_iam_core::GithubProviderAdapter::new).
#[derive(Debug, Clone)]
pub struct ReqwestGithubTransport {
    client: Client,
    client_secret: String,
    api_base: String,
    user_agent: String,
}

impl ReqwestGithubTransport {
    /// Build a transport that redeems codes with `client_secret`, reading from the
    /// public GitHub API with the default timeout and user agent. Fails only if
    /// the platform cannot initialise the TLS/HTTP stack.
    pub fn new(client_secret: impl Into<String>) -> Result<Self, String> {
        Ok(Self {
            client: build_client(DEFAULT_TIMEOUT)?,
            client_secret: client_secret.into(),
            api_base: DEFAULT_GITHUB_API_BASE.to_owned(),
            user_agent: DEFAULT_GITHUB_USER_AGENT.to_owned(),
        })
    }

    /// Point the REST reads at a different API base, e.g. a GitHub Enterprise
    /// host. The trailing slash is trimmed so paths join cleanly.
    #[must_use]
    pub fn with_api_base(mut self, api_base: impl Into<String>) -> Self {
        self.api_base = api_base.into().trim_end_matches('/').to_owned();
        self
    }

    /// Override the `User-Agent` sent on GitHub API calls.
    #[must_use]
    pub fn with_user_agent(mut self, user_agent: impl Into<String>) -> Self {
        self.user_agent = user_agent.into();
        self
    }

    /// Replace the underlying client, e.g. to share a pool or set a custom
    /// timeout. The client's own timeout applies.
    #[must_use]
    pub fn with_client(mut self, client: Client) -> Self {
        self.client = client;
        self
    }

    /// Start a `GET` against an absolute API URL with the bearer token, the
    /// required `User-Agent`, and GitHub's JSON `Accept`.
    fn authed_get(&self, url: &str, access_token: &str) -> RequestBuilder {
        self.client
            .get(url)
            .bearer_auth(access_token)
            .header("user-agent", &self.user_agent)
            .header("accept", "application/vnd.github+json")
    }

    /// Read and decode a `GET` whose `2xx` body is JSON `T`, mapping every failure
    /// (transport, non-success status, malformed JSON) to a [`GithubTransportError`].
    fn read_json<T: serde::de::DeserializeOwned>(
        builder: RequestBuilder,
        what: &str,
    ) -> Result<T, GithubTransportError> {
        let response = builder
            .send()
            .map_err(|err| GithubTransportError(format!("{what} request failed: {err}")))?;
        let status = response.status();
        let body = response.bytes().map_err(|err| {
            GithubTransportError(format!("reading {what} response failed: {err}"))
        })?;
        if !status.is_success() {
            return Err(GithubTransportError(format!(
                "{what} responded with status {status}"
            )));
        }
        serde_json::from_slice(&body).map_err(|err| {
            GithubTransportError(format!("{what} response was not valid JSON: {err}"))
        })
    }
}

impl GithubTransport for ReqwestGithubTransport {
    fn exchange_code(
        &self,
        request: &GithubTokenRequest<'_>,
    ) -> Result<GithubAccessToken, GithubTransportError> {
        // GitHub answers the token exchange with this JSON shape when asked, and
        // returns a `200` with an `error` field rather than an HTTP error on a bad
        // code; the adapter inspects that field, so this layer only decodes.
        let form = [
            ("grant_type", "authorization_code"),
            ("client_id", request.client_id),
            ("client_secret", self.client_secret.as_str()),
            ("code", request.code),
            ("redirect_uri", request.redirect_uri),
        ];
        let response = self
            .client
            .post(request.token_endpoint)
            .header("accept", "application/json")
            .header("user-agent", &self.user_agent)
            .form(&form)
            .send()
            .map_err(|err| GithubTransportError(format!("token request failed: {err}")))?;
        let status = response.status();
        let body = response
            .bytes()
            .map_err(|err| GithubTransportError(format!("reading token response failed: {err}")))?;
        serde_json::from_slice(&body).map_err(|err| {
            GithubTransportError(format!(
                "token response (status {status}) was not valid JSON: {err}"
            ))
        })
    }

    fn fetch_user(&self, access_token: &str) -> Result<GithubUser, GithubTransportError> {
        let url = format!("{}/user", self.api_base);
        Self::read_json(self.authed_get(&url, access_token), "user")
    }

    fn fetch_emails(&self, access_token: &str) -> Result<Vec<GithubEmail>, GithubTransportError> {
        let url = format!("{}/user/emails", self.api_base);
        Self::read_json(self.authed_get(&url, access_token), "user emails")
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{Read, Write};
    use std::net::TcpListener;
    use std::sync::Arc;
    use std::sync::Mutex;
    use std::thread;

    /// A scripted reply the stub server sends for one accepted connection.
    #[derive(Clone)]
    enum Reply {
        /// `200 OK` with this JSON body.
        Ok(String),
        /// This status code with an empty body (e.g. `403`, `500`).
        Status(u16),
    }

    /// A throwaway single-threaded HTTP/1.1 server that answers a scripted list of
    /// replies in order, recording the raw request bytes it received. It exercises
    /// the transports end to end (request shaping, status handling, decode) with no
    /// network dependency and no extra crates — the same approach the client crate
    /// uses for its `HttpAuthzTransport`.
    struct StubServer {
        addr: String,
        requests: Arc<Mutex<Vec<String>>>,
        handle: Option<thread::JoinHandle<()>>,
    }

    impl StubServer {
        fn start(replies: Vec<Reply>) -> Self {
            let listener = TcpListener::bind("127.0.0.1:0").unwrap();
            let addr = format!("http://{}", listener.local_addr().unwrap());
            let requests = Arc::new(Mutex::new(Vec::new()));
            let recorded = Arc::clone(&requests);
            let handle = thread::spawn(move || {
                for reply in replies {
                    let (mut stream, _) = match listener.accept() {
                        Ok(pair) => pair,
                        Err(_) => return,
                    };
                    let mut buf = [0u8; 8192];
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

    fn http_transport() -> ReqwestHttpTransport {
        ReqwestHttpTransport::with_timeout(Duration::from_secs(2)).unwrap()
    }

    #[test]
    fn http_get_returns_body_on_success() {
        let server = StubServer::start(vec![Reply::Ok(r#"{"keys":[]}"#.into())]);
        let transport = http_transport();

        let url = format!("{}/oauth2/v3/certs", server.addr);
        let body = transport
            .execute(&HttpRequest::get(url).with_header("accept", "application/json"))
            .unwrap();
        assert_eq!(body, br#"{"keys":[]}"#);

        drop(transport);
        let recorded = server.requests();
        assert!(recorded[0].starts_with("GET /oauth2/v3/certs "));
        assert!(
            recorded[0]
                .to_lowercase()
                .contains("accept: application/json")
        );
    }

    #[test]
    fn http_post_sends_body_and_returns_response() {
        let server = StubServer::start(vec![Reply::Ok(r#"{"id_token":"abc"}"#.into())]);
        let transport = http_transport();

        let url = format!("{}/token", server.addr);
        let body = transport
            .execute(
                &HttpRequest::post(url, "grant_type=authorization_code&code=xyz".into())
                    .with_header("content-type", "application/x-www-form-urlencoded"),
            )
            .unwrap();
        assert_eq!(body, br#"{"id_token":"abc"}"#);

        drop(transport);
        let recorded = server.requests();
        assert!(recorded[0].starts_with("POST /token "));
        // The form body is placed on the wire verbatim.
        assert!(recorded[0].contains("grant_type=authorization_code&code=xyz"));
    }

    #[test]
    fn http_non_success_status_is_a_failure_string() {
        let server = StubServer::start(vec![Reply::Status(503)]);
        let transport = http_transport();

        let url = format!("{}/token", server.addr);
        let err = transport
            .execute(&HttpRequest::get(url))
            .expect_err("non-2xx surfaces as error");
        assert!(err.contains("503"), "unexpected error: {err}");
    }

    #[test]
    fn http_connection_failure_is_a_failure_string() {
        // Nothing is listening on this port; the send fails at the transport level.
        let transport = http_transport();
        let err = transport
            .execute(&HttpRequest::get("http://127.0.0.1:1/token".into()))
            .expect_err("connection refused surfaces as error");
        assert!(err.contains("failed"), "unexpected error: {err}");
    }

    #[test]
    fn http_rejects_unsupported_method() {
        let transport = http_transport();
        let request = HttpRequest {
            method: "DELETE",
            url: "http://127.0.0.1/whatever".into(),
            headers: Vec::new(),
            body: String::new(),
        };
        let err = transport
            .execute(&request)
            .expect_err("unsupported method rejected");
        assert!(err.contains("DELETE"), "unexpected error: {err}");
    }

    fn github_transport(server: &StubServer) -> ReqwestGithubTransport {
        ReqwestGithubTransport::new("client-secret")
            .unwrap()
            .with_client(
                Client::builder()
                    .timeout(Duration::from_secs(2))
                    .build()
                    .unwrap(),
            )
            .with_api_base(&server.addr)
    }

    #[test]
    fn github_exchange_code_posts_form_and_decodes_token() {
        let server = StubServer::start(vec![Reply::Ok(
            r#"{"access_token":"gho_abc","token_type":"bearer","scope":"read:user,user:email"}"#
                .into(),
        )]);
        let token_endpoint = format!("{}/login/oauth/access_token", server.addr);
        let transport = github_transport(&server);

        let token = transport
            .exchange_code(&GithubTokenRequest {
                token_endpoint: &token_endpoint,
                client_id: "client-123",
                code: "auth-code",
                redirect_uri: "https://app.example/cb",
            })
            .unwrap();
        assert_eq!(token.access_token.as_deref(), Some("gho_abc"));

        drop(transport);
        let recorded = server.requests();
        assert!(recorded[0].starts_with("POST /login/oauth/access_token "));
        // Client id, the transport-held secret, and the code all reach the wire.
        assert!(recorded[0].contains("client_id=client-123"));
        assert!(recorded[0].contains("client_secret=client-secret"));
        assert!(recorded[0].contains("code=auth-code"));
        // GitHub requires a User-Agent on every request.
        assert!(recorded[0].to_lowercase().contains("user-agent:"));
    }

    #[test]
    fn github_fetch_user_decodes_profile_with_bearer_and_user_agent() {
        let server = StubServer::start(vec![Reply::Ok(
            r#"{"id":42,"login":"ada","name":"Ada Lovelace","avatar_url":"https://img/a.png"}"#
                .into(),
        )]);
        let transport = github_transport(&server);

        let user = transport.fetch_user("gho_abc").unwrap();
        assert_eq!(user.id, 42);
        assert_eq!(user.login, "ada");

        drop(transport);
        let recorded = server.requests();
        assert!(recorded[0].starts_with("GET /user "));
        assert!(recorded[0].contains("authorization: Bearer gho_abc"));
        assert!(
            recorded[0]
                .to_lowercase()
                .contains("user-agent: awaken-iam")
        );
    }

    #[test]
    fn github_fetch_emails_decodes_address_list() {
        let server = StubServer::start(vec![Reply::Ok(
            r#"[{"email":"ada@example.com","primary":true,"verified":true},
                {"email":"alt@example.com","primary":false,"verified":false}]"#
                .into(),
        )]);
        let transport = github_transport(&server);

        let emails = transport.fetch_emails("gho_abc").unwrap();
        assert_eq!(emails.len(), 2);
        assert_eq!(emails[0].email, "ada@example.com");
        assert!(emails[0].primary && emails[0].verified);

        drop(transport);
        assert!(server.requests()[0].starts_with("GET /user/emails "));
    }

    #[test]
    fn github_fetch_user_non_success_is_a_transport_error() {
        let server = StubServer::start(vec![Reply::Status(401)]);
        let transport = github_transport(&server);

        let err = transport
            .fetch_user("bad-token")
            .expect_err("401 surfaces as a transport error");
        assert!(err.0.contains("401"), "unexpected error: {}", err.0);
    }

    #[test]
    fn github_fetch_user_malformed_json_is_a_transport_error() {
        let server = StubServer::start(vec![Reply::Ok("not-json".into())]);
        let transport = github_transport(&server);

        let err = transport
            .fetch_user("gho_abc")
            .expect_err("malformed JSON surfaces as a transport error");
        assert!(err.0.contains("valid JSON"), "unexpected error: {}", err.0);
    }
}
