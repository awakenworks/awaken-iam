//! Token/binding commands use the original policy transaction and row laws.
use super::*;
use awaken_iam_core::api_token_revocation_stamp;

impl<B: SqlConn> SqlStore<B> {
    /// Commit a prepared basic token and its exact workspace binding atomically.
    /// The caller publishes its borrowed Core mutation only after this ACK.
    /// This operation does not persist an additional accountable service owner,
    /// cleartext handoff, PAP audit or additional version semantics.
    pub fn commit_api_token_mint(
        &self,
        token: &ApiToken,
        binding: &RoleBinding,
    ) -> RepositoryResult<()> {
        self.with_authorization_change(|transaction| {
            if token.principal != binding.principal
                || !matches!(&binding.scope, ScopeRef::Workspace { workspace_id } if workspace_id == &token.workspace)
            {
                return Err(RepositoryError::Conflict("token and binding identities do not agree".into()));
            }
            self.insert_api_token_in(transaction, token)?;
            self.insert_role_binding_in(transaction, binding)
        })
    }

    /// Revoke the frozen identity and return its authoritative first stamp.
    /// A concurrently completed revoke can advance None to the stored stamp;
    /// immutable identity drift or contradictory existing stamps refuse in tx.
    pub fn commit_api_token_revocation(
        &self,
        expected: &ApiToken,
        now: &Timestamp,
    ) -> RepositoryResult<Timestamp> {
        self.with_policy_transaction(|transaction, _| {
            let current = self
                .read_token_with(&expected.id, |sql, params| transaction.query(sql, params))?
                .ok_or_else(|| {
                    RepositoryError::NotFound(format!("api token {} does not exist", expected.id.0))
                })?;
            if !same_token_identity(expected, &current)
                || expected
                    .revoked_at
                    .as_ref()
                    .is_some_and(|stamp| current.revoked_at.as_ref() != Some(stamp))
            {
                return Err(RepositoryError::Conflict(
                    "stored token differs from the prepared revocation".into(),
                ));
            }
            let stamp = api_token_revocation_stamp(current.revoked_at.as_ref(), now);
            if current.revoked_at.is_none() {
                let mut revoked = current.clone();
                revoked.revoked_at = Some(stamp.clone());
                self.update_api_token_in(transaction, &revoked, Some(&current))?;
                self.advance_authorization_epoch(transaction)?;
            } else {
                self.admit_api_token_in(transaction, &current, Some(&current))?;
            }
            Ok(stamp)
        })
    }

    fn admit_api_token_in(
        &self,
        transaction: &mut dyn SqlTransaction,
        token: &ApiToken,
        previous: Option<&ApiToken>,
    ) -> RepositoryResult<()> {
        let mut scopes = vec![ScopeRef::Workspace {
            workspace_id: token.workspace.clone(),
        }];
        if let Some(previous) = previous {
            scopes.push(ScopeRef::Workspace {
                workspace_id: previous.workspace.clone(),
            });
        }
        self.ensure_scope_admission(transaction, &scopes, &[])
    }

    pub(super) fn insert_api_token_in(
        &self,
        transaction: &mut dyn SqlTransaction,
        token: &ApiToken,
    ) -> RepositoryResult<()> {
        let previous =
            self.read_token_with(&token.id, |sql, params| transaction.query(sql, params))?;
        self.admit_api_token_in(transaction, token, previous.as_ref())?;
        let principal = json_encode(&token.principal, "principal")?;
        let sql = format!(
            "INSERT INTO {t} (id, prefix, principal, secret_hash, workspace, created_at, expires_at, revoked_at) VALUES (?, ?, ?j, ?, ?, ?, ?, ?)",
            t = self.table("api_tokens")
        );
        transaction.execute(
            &sql,
            &[
                p(token.id.0.clone()),
                p(token.prefix.0.clone()),
                p(principal),
                p(token.secret_hash.clone()),
                p(token.workspace.0.clone()),
                p(token.created_at.0.clone()),
                token.expires_at.as_ref().map(|t| t.0.clone()),
                token.revoked_at.as_ref().map(|t| t.0.clone()),
            ],
        )?;
        Ok(())
    }

    pub(super) fn update_api_token_in(
        &self,
        transaction: &mut dyn SqlTransaction,
        token: &ApiToken,
        previous: Option<&ApiToken>,
    ) -> RepositoryResult<()> {
        self.admit_api_token_in(transaction, token, previous)?;
        let principal = json_encode(&token.principal, "principal")?;
        let sql = format!(
            "UPDATE {t} SET prefix = ?, principal = ?j, secret_hash = ?, workspace = ?, created_at = ?, expires_at = ?, revoked_at = ? WHERE id = ?",
            t = self.table("api_tokens")
        );
        let affected = transaction.execute(
            &sql,
            &[
                p(token.prefix.0.clone()),
                p(principal),
                p(token.secret_hash.clone()),
                p(token.workspace.0.clone()),
                p(token.created_at.0.clone()),
                token.expires_at.as_ref().map(|t| t.0.clone()),
                token.revoked_at.as_ref().map(|t| t.0.clone()),
                p(token.id.0.clone()),
            ],
        )?;
        if affected == 0 {
            return Err(RepositoryError::NotFound(format!(
                "api token {} does not exist",
                token.id.0
            )));
        }
        Ok(())
    }

    pub(super) fn insert_role_binding_in(
        &self,
        transaction: &mut dyn SqlTransaction,
        binding: &RoleBinding,
    ) -> RepositoryResult<()> {
        self.ensure_scope_admission(transaction, std::slice::from_ref(&binding.scope), &[])?;
        self.require_live_effect_scopes(transaction, std::slice::from_ref(&binding.scope))?;
        let principal = json_encode(&binding.principal, "principal")?;
        let scope = json_encode(&binding.scope, "binding scope")?;
        let sql = format!(
            "INSERT INTO {t} (principal, role, scope) VALUES (?j, ?, ?j) ON CONFLICT (principal, role, scope) DO NOTHING",
            t = self.table("role_bindings")
        );
        transaction.execute(&sql, &[p(principal), p(binding.role.0.clone()), p(scope)])?;
        Ok(())
    }
}

fn same_token_identity(expected: &ApiToken, stored: &ApiToken) -> bool {
    expected.id == stored.id
        && expected.prefix == stored.prefix
        && expected.principal == stored.principal
        && expected.secret_hash == stored.secret_hash
        && expected.workspace == stored.workspace
        && expected.created_at == stored.created_at
        && expected.expires_at == stored.expires_at
}
