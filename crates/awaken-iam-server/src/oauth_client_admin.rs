//! Admin API to register, rotate, and deregister downstream OAuth clients.
//!
//! Where [`PolicyAdminApi`](crate::PolicyAdminApi) administers the authorization
//! model, this is the Policy Administration Point for the *product clients* that
//! integrate against IAM as an OAuth authorization server (the provider posture
//! in [auth server](../../../docs/design/auth-server.md)). It persists each
//! [`RegisteredClient`] through the [`OAuthClientRepo`] port so the registry the
//! authorization server enforces is durable rather than an in-memory seed — the
//! server rebuilds its [`OAuthClientRegistry`] from the store via
//! [`OAuthClientAdminApi::registry`].
//!
//! Like the other admin seams it speaks in logical request/response values and
//! is framework-agnostic; a deployment maps these methods onto its router:
//!
//! | Route | Method on [`OAuthClientAdminApi`] |
//! |---|---|
//! | `POST /v1/admin/oauth-clients` | [`OAuthClientAdminApi::register`] |
//! | `POST /v1/admin/oauth-clients/{id}/rotate-secret` | [`OAuthClientAdminApi::rotate_secret`] |
//! | `DELETE /v1/admin/oauth-clients/{id}` | [`OAuthClientAdminApi::deregister`] |
//! | `GET /v1/admin/oauth-clients` | [`OAuthClientAdminApi::list_clients`] |
//! | `GET /v1/admin/oauth-clients/{id}` | [`OAuthClientAdminApi::get_client`] |
//!
//! Every mutation appends an [`AuditEvent`] and bumps a monotonic snapshot
//! version, matching the discipline of the policy PAP.

use awaken_iam_contract::Timestamp;
use awaken_iam_core::{
    AuditEvent, AuditSink, EntropySource, OAuthClientRegistry, OAuthClientRepo, RegisteredClient,
};
use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;

use crate::admin_api::{AdminError, AdminResult};

/// Bytes of entropy drawn for a freshly minted client secret (256 bits).
const SECRET_BYTES: usize = 32;

/// A registration domain event over the OAuth client registry.
///
/// Each variant records one administrative change applied through the
/// [`OAuthClientAdminApi`]; events feed the audit trail and bump the snapshot
/// version a synced consumer fences against.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum OAuthClientEvent {
    /// A new client was registered.
    Registered(String),
    /// A confidential client's secret was rotated.
    SecretRotated(String),
    /// A client was deregistered.
    Deregistered(String),
}

impl OAuthClientEvent {
    /// Stable snake_case action key recorded in the audit trail.
    pub fn action(&self) -> &'static str {
        match self {
            OAuthClientEvent::Registered(_) => "oauth_client.register",
            OAuthClientEvent::SecretRotated(_) => "oauth_client.rotate_secret",
            OAuthClientEvent::Deregistered(_) => "oauth_client.deregister",
        }
    }

    /// Human-readable detail captured alongside the event in the audit trail.
    pub fn detail(&self) -> String {
        match self {
            OAuthClientEvent::Registered(id)
            | OAuthClientEvent::SecretRotated(id)
            | OAuthClientEvent::Deregistered(id) => format!("oauth client {id}"),
        }
    }
}

/// The cleartext secret a confidential client authenticates with, returned
/// exactly once at registration or rotation.
///
/// Only the hash is persisted, so this value is the single chance the caller
/// has to deliver the secret to the integrating product — it is never
/// recoverable afterwards.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IssuedClientSecret {
    /// Client the secret authenticates.
    pub client_id: String,
    /// The cleartext secret to hand to the client out of band.
    pub secret: String,
}

/// Policy Administration Point over the downstream OAuth client registry.
///
/// `S` is any store implementing [`OAuthClientRepo`] and [`AuditSink`]; the
/// in-memory [`InMemoryStore`](crate::InMemoryStore) backs tests and local mode,
/// and a database adapter backs the service. Mutating methods append an
/// [`OAuthClientEvent`] and advance the [snapshot version](OAuthClientAdminApi::version);
/// read methods never advance it.
#[derive(Debug)]
pub struct OAuthClientAdminApi<S> {
    store: S,
    version: u64,
    events: Vec<OAuthClientEvent>,
}

impl<S> OAuthClientAdminApi<S>
where
    S: OAuthClientRepo + AuditSink,
{
    /// Build the PAP over `store` at initial snapshot version 1.
    pub fn new(store: S) -> Self {
        Self {
            store,
            version: 1,
            events: Vec::new(),
        }
    }

    /// The current monotonic snapshot version. It advances by one on every
    /// successful mutation.
    pub fn version(&self) -> u64 {
        self.version
    }

    /// The domain events emitted so far, in application order.
    pub fn events(&self) -> &[OAuthClientEvent] {
        &self.events
    }

    /// Read-only access to the underlying store.
    pub fn store(&self) -> &S {
        &self.store
    }

    /// Append `event` to the audit trail and advance the snapshot version.
    ///
    /// The audit record is written first; only once it is durable is the version
    /// bumped and the event retained, so a failed audit write leaves the version
    /// unchanged.
    fn commit(&mut self, event: OAuthClientEvent, at: Timestamp) -> AdminResult<u64> {
        self.store.record(AuditEvent {
            at,
            actor: None,
            action: event.action().to_owned(),
            detail: event.detail(),
        })?;
        self.version += 1;
        self.events.push(event);
        Ok(self.version)
    }

    /// Register a client, failing closed when its `client_id` already exists.
    ///
    /// The caller supplies a fully-formed [`RegisteredClient`] (public or
    /// confidential); a confidential client's secret is already hashed into it
    /// by [`RegisteredClient::confidential`].
    pub fn register(&mut self, client: RegisteredClient, at: Timestamp) -> AdminResult<u64> {
        if OAuthClientRepo::get(&self.store, &client.client_id)?.is_some() {
            return Err(AdminError::AlreadyExists(format!(
                "oauth client {}",
                client.client_id
            )));
        }
        let id = client.client_id.clone();
        OAuthClientRepo::upsert(&self.store, client)?;
        self.commit(OAuthClientEvent::Registered(id), at)
    }

    /// Rotate a confidential client's secret, returning the fresh cleartext
    /// secret exactly once.
    ///
    /// A new high-entropy secret is minted from `entropy`, hashed at rest, and
    /// written in place while the client's redirect URIs and allowed scopes are
    /// preserved. Fails closed when the client is absent, or when it is a public
    /// (PKCE-only) client with no secret to rotate.
    pub fn rotate_secret(
        &mut self,
        client_id: &str,
        entropy: &mut impl EntropySource,
        at: Timestamp,
    ) -> AdminResult<IssuedClientSecret> {
        let existing = OAuthClientRepo::get(&self.store, client_id)?
            .ok_or_else(|| AdminError::NotFound(format!("oauth client {client_id}")))?;
        if existing.secret_hash.is_none() {
            return Err(AdminError::Invalid(format!(
                "oauth client {client_id} is public and has no secret to rotate"
            )));
        }

        let secret = mint_secret(entropy);
        let rotated = RegisteredClient::confidential(
            existing.client_id.clone(),
            &secret,
            existing.redirect_uris.clone(),
            existing.allowed_scopes.clone(),
        );
        OAuthClientRepo::upsert(&self.store, rotated)?;
        self.commit(OAuthClientEvent::SecretRotated(client_id.to_owned()), at)?;
        Ok(IssuedClientSecret {
            client_id: client_id.to_owned(),
            secret,
        })
    }

    /// Deregister a client, failing closed when it is absent.
    pub fn deregister(&mut self, client_id: &str, at: Timestamp) -> AdminResult<u64> {
        OAuthClientRepo::remove(&self.store, client_id)?;
        self.commit(OAuthClientEvent::Deregistered(client_id.to_owned()), at)
    }

    /// Resolve a registered client by id.
    pub fn get_client(&self, client_id: &str) -> AdminResult<Option<RegisteredClient>> {
        Ok(OAuthClientRepo::get(&self.store, client_id)?)
    }

    /// List every registered client.
    pub fn list_clients(&self) -> AdminResult<Vec<RegisteredClient>> {
        Ok(OAuthClientRepo::list(&self.store)?)
    }

    /// Hydrate an [`OAuthClientRegistry`] from the persisted clients.
    ///
    /// This is the seam the authorization server uses to enforce the durable
    /// registry: an administrative change made here is reflected the next time
    /// the server rebuilds its registry.
    pub fn registry(&self) -> AdminResult<OAuthClientRegistry> {
        Ok(OAuthClientRegistry::load(&self.store)?)
    }
}

/// Mint a fresh URL-safe base64 client secret from `entropy`.
fn mint_secret(entropy: &mut impl EntropySource) -> String {
    let mut buf = [0u8; SECRET_BYTES];
    entropy.fill_bytes(&mut buf);
    URL_SAFE_NO_PAD.encode(buf)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::InMemoryStore;
    use awaken_iam_contract::AccountId;
    use awaken_iam_core::{
        OAuthAuthorizationRequest, OAuthAuthorizationServer, TokenRedemption, hash_session_token,
    };

    /// Deterministic entropy: each draw is a fixed, distinct byte pattern.
    struct SeqEntropy {
        next: u8,
    }

    impl EntropySource for SeqEntropy {
        fn fill_bytes(&mut self, buf: &mut [u8]) {
            for byte in buf.iter_mut() {
                *byte = self.next;
            }
            self.next = self.next.wrapping_add(1);
        }
    }

    fn at() -> Timestamp {
        Timestamp("2026-06-21T00:00:00Z".into())
    }

    fn api() -> OAuthClientAdminApi<InMemoryStore> {
        OAuthClientAdminApi::new(InMemoryStore::new())
    }

    fn confidential() -> RegisteredClient {
        RegisteredClient::confidential(
            "product-web",
            "initial-secret",
            vec!["https://product.example/cb".into()],
            ["openid", "email"],
        )
    }

    #[test]
    fn register_persists_bumps_version_and_audits() {
        let mut api = api();
        assert_eq!(api.version(), 1);
        let version = api.register(confidential(), at()).unwrap();
        assert_eq!(version, 2);
        assert_eq!(api.list_clients().unwrap().len(), 1);
        assert_eq!(
            api.events(),
            &[OAuthClientEvent::Registered("product-web".into())]
        );
        let audit = AuditSink::events(api.store()).unwrap();
        assert_eq!(audit.len(), 1);
        assert_eq!(audit[0].action, "oauth_client.register");
    }

    #[test]
    fn register_is_conflict_on_duplicate_id() {
        let mut api = api();
        api.register(confidential(), at()).unwrap();
        assert_eq!(
            api.register(confidential(), at()),
            Err(AdminError::AlreadyExists("oauth client product-web".into()))
        );
        // A failed register does not advance the version.
        assert_eq!(api.version(), 2);
    }

    #[test]
    fn rotate_secret_replaces_the_hash_and_returns_a_fresh_secret() {
        let mut api = api();
        api.register(confidential(), at()).unwrap();
        let issued = api
            .rotate_secret("product-web", &mut SeqEntropy { next: 7 }, at())
            .unwrap();
        assert_eq!(issued.client_id, "product-web");

        let stored = api.get_client("product-web").unwrap().unwrap();
        // The new secret verifies; the prior one no longer does.
        assert_eq!(stored.secret_hash, Some(hash_session_token(&issued.secret)));
        assert_ne!(
            stored.secret_hash,
            Some(hash_session_token("initial-secret"))
        );
        // Redirect URIs and scopes are preserved across rotation.
        assert_eq!(stored.redirect_uris, vec!["https://product.example/cb"]);
        assert_eq!(api.version(), 3);
        assert!(matches!(
            api.events().last().unwrap(),
            OAuthClientEvent::SecretRotated(_)
        ));
    }

    #[test]
    fn rotate_secret_rejects_public_and_missing_clients() {
        let mut api = api();
        api.register(
            RegisteredClient::public("spa", vec!["https://spa.example/cb".into()], ["openid"]),
            at(),
        )
        .unwrap();
        assert!(matches!(
            api.rotate_secret("spa", &mut SeqEntropy { next: 1 }, at()),
            Err(AdminError::Invalid(_))
        ));
        assert!(matches!(
            api.rotate_secret("ghost", &mut SeqEntropy { next: 1 }, at()),
            Err(AdminError::NotFound(_))
        ));
        // Neither rejection advanced the version.
        assert_eq!(api.version(), 2);
    }

    #[test]
    fn deregister_removes_and_requires_existence() {
        let mut api = api();
        api.register(confidential(), at()).unwrap();
        api.deregister("product-web", at()).unwrap();
        assert!(api.list_clients().unwrap().is_empty());
        assert!(matches!(
            api.deregister("product-web", at()),
            Err(AdminError::NotFound(_))
        ));
    }

    #[test]
    fn registry_hydrates_and_backs_a_live_authorization_server() {
        let mut api = api();
        api.register(confidential(), at()).unwrap();
        let issued = api
            .rotate_secret("product-web", &mut SeqEntropy { next: 3 }, at())
            .unwrap();

        // The registry rebuilt from the store carries the rotated client, and a
        // server over it authenticates a full authorization-code redemption with
        // the freshly rotated secret.
        let registry = api.registry().unwrap();
        let mut server = OAuthAuthorizationServer::new(registry, SeqEntropy { next: 100 });
        let request = OAuthAuthorizationRequest {
            client_id: "product-web".into(),
            redirect_uri: "https://product.example/cb".into(),
            scopes: vec!["openid".into(), "email".into()],
            code_challenge: None,
            code_challenge_method: None,
            nonce: None,
            state: None,
        };
        let now = Timestamp("2026-06-21T00:00:00Z".into());
        let expires_at = Timestamp("2026-06-21T00:05:00Z".into());
        let code = server
            .issue_code(
                AccountId("acct_ada".into()),
                &request,
                now.clone(),
                expires_at,
            )
            .unwrap();

        let grant = server
            .redeem_code(
                &TokenRedemption {
                    client_id: "product-web".into(),
                    client_secret: Some(issued.secret.clone()),
                    code: code.code,
                    redirect_uri: "https://product.example/cb".into(),
                    code_verifier: None,
                },
                now,
            )
            .unwrap();
        assert_eq!(grant.account_id, AccountId("acct_ada".into()));
        assert_eq!(grant.scopes, vec!["openid".to_owned(), "email".to_owned()]);
    }
}
