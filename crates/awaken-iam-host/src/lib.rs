//! Assembly and auth-middleware layer for embedding or connecting Awaken IAM.
//!
//! Products embed IAM in-process (`Local` mode via [`embed_local`]) or delegate to a
//! remote daemon (`Remote` mode via [`connect_remote`]), or bypass auth entirely
//! (`Open` mode for dev/test). This crate packages the boot recipe and the axum
//! bearer-auth middleware so every product shares one assembly instead of
//! hand-rolling it.
//!
//! ## Dependency footprint
//!
//! `awaken-iam-server` (and thus `rusqlite` + `axum`) arrive transitively via
//! this crate. A host that only needs `Open` or `Remote` mode still pulls in the
//! full server crate — that trade-off is accepted in favour of a single
//! consistently-versioned assembly for all three modes.
//!
//! ## Quick start
//!
//! ```rust,ignore
//! use awaken_iam_host::{HostConfig, embed_local, auth_layer};
//!
//! let cfg = HostConfig::local_in_memory();
//! let handle = embed_local(&cfg).expect("IAM init");
//! let app = axum::Router::new()
//!     .route("/api/widgets", axum::routing::get(list_widgets))
//!     .layer(auth_layer(handle.gate, MyRouteActions));
//! ```

mod config;
mod gate;
mod local;
mod middleware;
mod remote;

pub use config::{HostConfig, HostConfigError, HostMode};
pub use gate::{IamGate, LocalIamState};
pub use local::{EmbedError, LocalHandle, embed_local};
pub use middleware::{
    AuthError, IamAuthLayer, IamAuthService, RouteActions, TokenWorkspace, auth_layer,
};
pub use remote::{ConnectError, RemoteHandle, connect_remote};

// Convenience re-exports so callers rarely need to reach into sub-crates.
pub use awaken_iam_client::{IamClientMode, RemoteIamClient};
pub use awaken_iam_contract::{ActionKey, JsonWebKey, Jwks, PrincipalRef, ScopeRef, WorkspaceId};
pub use awaken_iam_server::AuthzApi;
pub use awaken_iam_server::{
    AccessTokenAuthority, AccessTokenClaims, AccessTokenError, AccessTokenRevocations,
    LocalSeedSigner, verify_access_token, verify_active_access_token,
};
