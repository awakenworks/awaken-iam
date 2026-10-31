//! Durable access-token signing seed for self-hosted deployments (ADR-0017).
//!
//! A standalone daemon without an injected KMS [`Signer`](crate::Signer) keeps
//! its Ed25519 seed in the shared store so every restart and every replica
//! signs with the same key under the same public-key-derived `kid`. Whoever
//! can read this table can mint IAM tokens; it carries the same protection
//! requirements as the database credentials themselves. Managed deployments
//! inject a KMS signer instead and never call this.

use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;

use super::*;
use crate::access_token::{AccessTokenAuthority, LocalSeedSigner, derived_kid};

impl<B: SqlConn> SqlStore<B> {
    /// Return the deployment's persisted signing authority, persisting
    /// `candidate_seed` first when no key exists yet.
    ///
    /// The insert is conflict-free and the oldest row (by `created_at`, then
    /// `kid`) wins, so replicas racing on an empty table converge on one key.
    pub fn durable_access_token_authority(
        &self,
        candidate_seed: [u8; 32],
    ) -> RepositoryResult<AccessTokenAuthority> {
        let created_at = crate::clock::now_timestamp();
        let table = self.table("signing_keys");
        let select = format!("SELECT kid, seed FROM {table} ORDER BY created_at, kid LIMIT 1");
        if self.backend.query(&select, &[])?.is_empty() {
            let insert = format!(
                "INSERT INTO {table} (kid, seed, created_at) VALUES (?, ?, ?) \
                 ON CONFLICT (kid) DO NOTHING"
            );
            self.backend.execute(
                &insert,
                &[
                    p(derived_kid(&candidate_seed)),
                    p(URL_SAFE_NO_PAD.encode(candidate_seed)),
                    p(created_at.0.clone()),
                ],
            )?;
        }
        let rows = self.backend.query(&select, &[])?;
        let row = rows
            .first()
            .ok_or_else(|| RepositoryError::Backend("signing key was not persisted".into()))?;
        let kid = req(row, 0, "signing_key.kid")?;
        let seed: [u8; 32] = URL_SAFE_NO_PAD
            .decode(req(row, 1, "signing_key.seed")?)
            .ok()
            .and_then(|bytes| bytes.try_into().ok())
            .ok_or_else(|| RepositoryError::Backend("stored signing seed is malformed".into()))?;
        if kid != derived_kid(&seed) {
            return Err(RepositoryError::Backend(
                "stored signing key id does not match its key".into(),
            ));
        }
        Ok(AccessTokenAuthority::new(LocalSeedSigner::new(kid, seed)))
    }
}

#[cfg(test)]
mod tests {
    use crate::store::sqlite::{SqliteBackend, migrated_store};
    use crate::verify_access_token;
    use crate::{AccessTokenClaims, AccessTokenSubjectKind, SqlConn, derived_kid};

    fn claims() -> AccessTokenClaims {
        AccessTokenClaims {
            iss: "https://iam.example".into(),
            sub: "acct_ada".into(),
            subject_kind: AccessTokenSubjectKind::Account,
            aud: "flow".into(),
            exp: 4_102_444_800,
            iat: 1_700_000_000,
            jti: "jti-restart".into(),
            scope: Vec::new(),
            act: None,
        }
    }

    /// Restart decision table over one SQLite file:
    ///
    /// | start | table | candidate seed | effect |
    /// |---|---|---|---|
    /// | first | empty | A | persist A; kid = derived_kid(A) |
    /// | restart | holds A | B | keep A; same kid and JWKS; old tokens verify |
    /// | tampered row | kid ≠ derived kid | any | refuse to start |
    #[tokio::test]
    async fn signing_key_survives_restart_with_one_derived_kid() {
        let path = std::env::temp_dir().join(format!(
            "iam-signing-key-{}-{}.sqlite",
            std::process::id(),
            crate::clock::unix_seconds()
        ));
        let first = migrated_store(SqliteBackend::open_path(&path).unwrap(), "iam")
            .unwrap()
            .durable_access_token_authority([1u8; 32])
            .unwrap();
        assert_eq!(first.active_kid(), derived_kid(&[1u8; 32]));
        let token = first.mint(&claims()).await.unwrap();

        let store = migrated_store(SqliteBackend::open_path(&path).unwrap(), "iam").unwrap();
        let restarted = store.durable_access_token_authority([2u8; 32]).unwrap();
        assert_eq!(restarted.active_kid(), first.active_kid());
        assert_eq!(restarted.jwks(), first.jwks());
        verify_access_token(&token, &restarted.jwks()).unwrap();

        store
            .backend()
            .execute("UPDATE iam_signing_keys SET kid = 'iam-access-key-1'", &[])
            .unwrap();
        assert!(store.durable_access_token_authority([3u8; 32]).is_err());
        drop(store);
        let _ = std::fs::remove_file(&path);
    }
}
