use std::sync::{Arc, Mutex, MutexGuard};

use awaken_iam_contract::{AccountId, ApiTokenId, PrincipalRef, Timestamp, WorkspaceId};
use awaken_iam_core::{
    ApiTokenDirectory, ApiTokenMinter, EntitlementEngine, IamError, IssuedApiToken,
    IssuedServiceAccountToken, MintApiToken, OsEntropy, RoleId,
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
    fn lock_state(
        state: &Mutex<LocalIamState>,
    ) -> Result<MutexGuard<'_, LocalIamState>, EmbedError> {
        state
            .lock()
            .map_err(|_| EmbedError::Store("local IAM state is unavailable".into()))
    }

    /// Mint a new API token and register it with the gate.
    pub fn mint_api_token(&mut self, request: MintApiToken) -> Result<IssuedApiToken, EmbedError> {
        let mut guard = Self::lock_state(&self.state)?;
        let LocalIamState { authz, directory } = &mut *guard;
        let prepared = self
            .minter
            .prepare(directory, request)
            .map_err(EmbedError::from)?;
        Ok(prepared.publish(authz.policy_mut()))
    }

    /// Mint a service-account API token through the accountable admin path:
    /// the principal must be a service, the request must carry an expiry, and
    /// `owner` is recorded as the human accountable for the key (ADR-0017).
    pub fn mint_service_account_token(
        &mut self,
        request: MintApiToken,
        owner: AccountId,
    ) -> Result<IssuedServiceAccountToken, EmbedError> {
        let mut guard = Self::lock_state(&self.state)?;
        let LocalIamState { authz, directory } = &mut *guard;
        let prepared = self
            .minter
            .prepare_service_account(directory, request, owner.clone())
            .map_err(|error| EmbedError::Token(error.to_string()))?;
        let issued = prepared.publish(authz.policy_mut());
        Ok(IssuedServiceAccountToken { issued, owner })
    }

    /// Revoke every live API token of one service account, returning the ids
    /// newly revoked. Already-revoked tokens keep their original stamp.
    pub fn revoke_service_account_tokens(
        &self,
        service_id: &str,
        now: Timestamp,
    ) -> Result<Vec<ApiTokenId>, EmbedError> {
        Ok(Self::lock_state(&self.state)?.directory.revoke_principal(
            &PrincipalRef::Service {
                service_id: service_id.to_owned(),
            },
            now,
        ))
    }

    /// Revoke an API token by id.
    pub fn revoke_api_token(&self, id: &ApiTokenId, now: Timestamp) -> Result<(), EmbedError> {
        Self::lock_state(&self.state)?
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

    let mut authz = AuthzApi::with_entitlements(EntitlementEngine::unlicensed());

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

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};

    use awaken_iam_contract::{ActionKey, ScopeRef};
    use awaken_iam_core::{ActionPattern, Effect, Grant, GrantId, GrantSubject};
    use axum::Router;
    use axum::body::Body;
    use axum::http::{Request, StatusCode};
    use axum::routing::get;
    use tower::ServiceExt;

    use crate::{AuthReject, RouteActions, auth_layer};

    fn poison(state: Arc<Mutex<LocalIamState>>) {
        assert!(
            std::thread::spawn(move || {
                let _guard = state.lock().unwrap();
                panic!("injected failure in the original paired IAM state");
            })
            .join()
            .is_err()
        );
    }

    #[tokio::test]
    async fn poisoned_local_handle_is_inert_and_jwt_keeps_its_independent_authority() {
        // L1 healthy bootstrap state -> the original token authenticates.
        // L2 poison that SAME directory+policy -> every mint/revoke Result
        // refuses, no empty-success bulk revoke, no mutation or poison clear.
        // L3 a signed JWT depends only on immutable JWKS, so auth-only still
        // succeeds; the separate actual-PDP test below must refuse effects.
        let mut handle =
            embed_local(&HostConfig::local_in_memory().with_seal_key([7; 32])).unwrap();
        let now = Timestamp("2030-01-01T00:00:00Z".into());
        let claims = awaken_iam_server::AccessTokenClaims {
            iss: "https://iam.example".into(),
            sub: "account".into(),
            subject_kind: awaken_iam_server::AccessTokenSubjectKind::Account,
            aud: "https://product.example".into(),
            exp: 2_000_000_100,
            iat: 2_000_000_000,
            jti: "jwt-independent".into(),
            scope: vec![],
        };
        let jwt = handle
            .jwt_authority
            .as_ref()
            .unwrap()
            .mint(&claims)
            .await
            .unwrap();
        assert!(
            handle
                .gate
                .authenticate_verified(&handle.admin_token, &now, 2_000_000_000)
                .is_ok()
        );
        let before = {
            let state = handle.state.lock().unwrap();
            (
                state.authz.snapshot(),
                state
                    .directory
                    .token(&ApiTokenId("tok_bootstrap_admin".into()))
                    .cloned(),
            )
        };
        poison(handle.state.clone());
        assert_eq!(
            handle
                .gate
                .authenticate_verified(&handle.admin_token, &now, 2_000_000_000),
            Err(AuthReject::Unavailable)
        );
        assert!(
            handle
                .gate
                .authenticate_verified(&jwt, &now, 2_000_000_000)
                .is_ok()
        );
        let request = MintApiToken {
            id: ApiTokenId("must-not-be-minted".into()),
            principal: PrincipalRef::Service {
                service_id: "service".into(),
            },
            workspace: WorkspaceId("workspace".into()),
            role: RoleId("admin".into()),
            created_at: now.clone(),
            expires_at: Some(Timestamp("2031-01-01T00:00:00Z".into())),
        };
        assert!(matches!(
            handle.mint_api_token(request.clone()),
            Err(EmbedError::Store(_))
        ));
        assert!(matches!(
            handle.mint_service_account_token(request, AccountId("owner".into())),
            Err(EmbedError::Store(_))
        ));
        assert!(matches!(
            handle.revoke_api_token(&ApiTokenId("tok_bootstrap_admin".into()), now.clone()),
            Err(EmbedError::Store(_))
        ));
        assert!(matches!(
            handle.revoke_service_account_tokens("iam-host-bootstrap", now),
            Err(EmbedError::Store(_))
        ));
        assert!(handle.state.is_poisoned());
        // Forensic test-only inspection is not production recovery. Verify the
        // paired state is unchanged and unavailable after ALL refused paths.
        let state = handle.state.lock().err().unwrap().into_inner();
        assert_eq!(state.authz.snapshot(), before.0);
        assert_eq!(
            state
                .directory
                .token(&ApiTokenId("tok_bootstrap_admin".into())),
            before.1.as_ref()
        );
        assert!(
            state
                .directory
                .token(&ApiTokenId("must-not-be-minted".into()))
                .is_none()
        );
    }

    #[derive(Clone)]
    struct PoisonDuringScope {
        state: Arc<Mutex<LocalIamState>>,
        poison_after_authentication: bool,
    }

    impl RouteActions for PoisonDuringScope {
        fn action_for(&self, _: &axum::http::Method, _: &str) -> Option<ActionKey> {
            Some(ActionKey("product.read".into()))
        }

        fn scope_for(
            &self,
            _: &axum::http::Method,
            _: &axum::http::Uri,
            _: &axum::http::Extensions,
        ) -> ScopeRef {
            if self.poison_after_authentication {
                poison(self.state.clone());
            }
            ScopeRef::Global
        }
    }

    #[tokio::test]
    async fn middleware_preserves_availability_before_and_after_authentication() {
        // C1=valid credential,C2=explicit grant,C3=poison before directory auth,
        // C4=poison in the original scope hook AFTER successful authentication.
        // M1(C1,C2,!C3,!C4)->200/one handler; M2(C3)->503/zero;
        // M3(C4)->503/zero (a precheck-only patch would miss this row);
        // M4(C1,!C2)->403/zero; M5(!C1)->401/zero. Same Gate/PDP/state per row,
        // no substitute evaluator, catch-unwind or nested state-lock reentry.
        for (before, after, grant, valid, expected) in [
            (false, false, true, true, StatusCode::OK),
            (true, false, true, true, StatusCode::SERVICE_UNAVAILABLE),
            (false, true, true, true, StatusCode::SERVICE_UNAVAILABLE),
            (false, false, false, true, StatusCode::FORBIDDEN),
            (false, false, true, false, StatusCode::UNAUTHORIZED),
        ] {
            let handle = embed_local(&HostConfig::local_in_memory()).unwrap();
            if grant {
                handle
                    .state
                    .lock()
                    .unwrap()
                    .authz
                    .policy_mut()
                    .add_grant(Grant {
                        id: GrantId("explicit-product-read".into()),
                        subject: GrantSubject::Principal(PrincipalRef::Service {
                            service_id: "iam-host-bootstrap".into(),
                        }),
                        action_pattern: ActionPattern("product.read".into()),
                        scope: ScopeRef::Global,
                        effect: Effect::Allow,
                    });
            }
            if before {
                poison(handle.state.clone());
            }
            let hits = Arc::new(AtomicUsize::new(0));
            let called = hits.clone();
            let app = Router::new()
                .route(
                    "/",
                    get(move || {
                        let called = called.clone();
                        async move {
                            called.fetch_add(1, Ordering::SeqCst);
                            StatusCode::OK
                        }
                    }),
                )
                .layer(auth_layer(
                    handle.gate.clone(),
                    PoisonDuringScope {
                        state: handle.state.clone(),
                        poison_after_authentication: after,
                    },
                ));
            let token = if valid {
                handle.admin_token.as_str()
            } else {
                "sk-awaken-invalid.secret"
            };
            let response = app
                .oneshot(
                    Request::builder()
                        .uri("/")
                        .header("authorization", format!("Bearer {token}"))
                        .body(Body::empty())
                        .unwrap(),
                )
                .await
                .unwrap();
            assert_eq!(response.status(), expected);
            assert_eq!(
                hits.load(Ordering::SeqCst),
                usize::from(expected == StatusCode::OK)
            );
            assert_eq!(handle.state.is_poisoned(), before || after);
        }
    }

    #[test]
    fn rejected_prepared_mints_leave_the_original_policy_version_unchanged() {
        // R1 invalid basic expiry, R2 non-service accountable mint, R3 missing
        // accountable expiry all reject BEFORE policy_mut (which advances the
        // live version). Same Core preparation laws choose every error; Host
        // neither duplicates their checks nor constructs a temporary PDP/Dir.
        let mut handle = embed_local(&HostConfig::local_in_memory()).unwrap();
        let before = handle.state.lock().unwrap().authz.snapshot();
        let mut request = MintApiToken {
            id: ApiTokenId("rejected".into()),
            principal: PrincipalRef::Service {
                service_id: "service".into(),
            },
            workspace: WorkspaceId("workspace".into()),
            role: RoleId("admin".into()),
            created_at: Timestamp("2030-01-01T00:00:00Z".into()),
            expires_at: Some(Timestamp("2029-01-01T00:00:00Z".into())),
        };
        assert!(handle.mint_api_token(request.clone()).is_err());
        request.principal = PrincipalRef::Account {
            account_id: AccountId("account".into()),
        };
        request.expires_at = Some(Timestamp("2031-01-01T00:00:00Z".into()));
        assert!(
            handle
                .mint_service_account_token(request.clone(), AccountId("owner".into()))
                .is_err()
        );
        request.principal = PrincipalRef::Service {
            service_id: "service".into(),
        };
        request.expires_at = None;
        assert!(
            handle
                .mint_service_account_token(request, AccountId("owner".into()))
                .is_err()
        );
        let state = handle.state.lock().unwrap();
        assert_eq!(state.authz.snapshot(), before);
        assert!(
            state
                .directory
                .token(&ApiTokenId("rejected".into()))
                .is_none()
        );
    }
}
