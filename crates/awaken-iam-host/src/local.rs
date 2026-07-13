use std::sync::{Arc, Mutex};

use awaken_iam_contract::{ApiTokenId, PrincipalRef, Timestamp, WorkspaceId};
use awaken_iam_core::{
    ApiTokenDirectory, ApiTokenMinter, EntitlementEngine, IamError, IssuedApiToken, MintApiToken,
    OsEntropy, RoleId,
};
use awaken_iam_preset::{seed_named_roles, seed_runtime_roles};
use awaken_iam_server::{
    AccessTokenAuthority, AuthzApi, LocalSeedSigner, SqliteBackend, sqlite_migrated_store,
};

use crate::{HostConfig, gate::IamGate, gate::LocalIamState};

/// Error returned by [`embed_local`] and [`LocalHandle`] operations.
#[derive(Debug, thiserror::Error)]
pub enum EmbedError {
    #[error("IAM store error: {0}")]
    Store(String),
    #[error("IAM role seeding failed: {0}")]
    Seeding(String),
    #[error("IAM token operation failed: {0}")]
    Token(String),
}

impl From<IamError> for EmbedError {
    fn from(err: IamError) -> Self {
        EmbedError::Token(err.to_string())
    }
}

/// Handle returned by [`embed_local`].
pub struct LocalHandle {
    /// Authorization and authentication gate — pass to [`auth_layer`](crate::auth_layer).
    pub gate: IamGate,
    /// API-token minter backed by the OS CSPRNG.
    pub minter: ApiTokenMinter<OsEntropy>,
    /// Shared local IAM state (authz + directory), also held by the gate.
    state: Arc<Mutex<LocalIamState>>,
    /// Cleartext bootstrap admin token.
    pub admin_token: String,
    /// JWT signing authority (present when [`HostConfig::seal_key`] is set).
    pub jwt_authority: Option<AccessTokenAuthority>,
}

impl LocalHandle {
    /// Mint a new API token and register it with the gate.
    pub fn mint_api_token(&mut self, request: MintApiToken) -> Result<IssuedApiToken, EmbedError> {
        let mut guard = self.state.lock().expect("local state lock");
        let LocalIamState { authz, directory } = &mut *guard;
        self.minter
            .mint(directory, authz.policy_mut(), request)
            .map_err(EmbedError::from)
    }

    /// Revoke an API token by id.
    pub fn revoke_api_token(&self, id: &ApiTokenId, now: Timestamp) -> Result<(), EmbedError> {
        self.state
            .lock()
            .expect("local state lock")
            .directory
            .revoke(id, now)
            .map_err(EmbedError::from)
    }
}

/// Assemble an embedded IAM deployment from `cfg`.
pub fn embed_local(cfg: &HostConfig) -> Result<LocalHandle, EmbedError> {
    let backend = open_backend(cfg.data_dir.as_deref())?;
    let store =
        sqlite_migrated_store(backend, "iam").map_err(|e| EmbedError::Store(e.to_string()))?;

    let now = Timestamp("2026-01-01T00:00:00Z".into());
    seed_named_roles(&store, &now).map_err(|e| EmbedError::Seeding(e.to_string()))?;
    seed_runtime_roles(&store, &now).map_err(|e| EmbedError::Seeding(e.to_string()))?;

    let mut directory = ApiTokenDirectory::new();
    let mut minter = ApiTokenMinter::new(OsEntropy);

    let mut authz = AuthzApi::with_entitlements(EntitlementEngine::default_allow());

    let issued = minter
        .mint(
            &mut directory,
            authz.policy_mut(),
            MintApiToken {
                id: ApiTokenId("tok_bootstrap_admin".into()),
                principal: PrincipalRef::Service {
                    service_id: "iam-host-bootstrap".into(),
                },
                workspace: WorkspaceId("wrkspc_admin".into()),
                role: RoleId("admin".into()),
                created_at: Timestamp("2026-01-01T00:00:00Z".into()),
                expires_at: None,
            },
        )
        .map_err(EmbedError::from)?;

    let jwt_authority = cfg
        .seal_key
        .map(|seed| AccessTokenAuthority::new(LocalSeedSigner::new("host-key", seed)));

    let jwks = jwt_authority.as_ref().map(|a| a.jwks());

    let state = Arc::new(Mutex::new(LocalIamState { authz, directory }));

    let gate = IamGate::local(Arc::clone(&state), jwks)
        .with_audience_opt(cfg.audience.clone())
        .with_issuer_opt(cfg.issuer.clone());

    if let Some(ref dir) = cfg.data_dir {
        write_admin_token(dir, &issued.secret)?;
    }

    Ok(LocalHandle {
        gate,
        minter,
        state,
        admin_token: issued.secret,
        jwt_authority,
    })
}

fn open_backend(data_dir: Option<&std::path::Path>) -> Result<SqliteBackend, EmbedError> {
    if let Some(dir) = data_dir {
        let path = dir.join("iam.db");
        SqliteBackend::open_path(path).map_err(|e| EmbedError::Store(e.to_string()))
    } else {
        SqliteBackend::open_in_memory().map_err(|e| EmbedError::Store(e.to_string()))
    }
}

fn write_admin_token(dir: &std::path::Path, token: &str) -> Result<(), EmbedError> {
    use std::fs;
    use std::io::Write;

    let path = dir.join("iam-admin-token");
    let mut file = fs::OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .open(&path)
        .map_err(|e| EmbedError::Token(format!("cannot open admin token file: {e}")))?;

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&path, fs::Permissions::from_mode(0o600))
            .map_err(|e| EmbedError::Token(format!("cannot set 0600 on admin token: {e}")))?;
    }

    file.write_all(token.as_bytes())
        .map_err(|e| EmbedError::Token(format!("cannot write admin token: {e}")))?;
    Ok(())
}
