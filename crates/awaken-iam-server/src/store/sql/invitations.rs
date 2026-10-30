//! Original invitation lifecycle: claim/replacement/bindings under one policy
//! transaction. Existing integration tests exercise this same repository port.
use super::*;

impl<B: SqlConn> SqlStore<B> {
    pub(super) fn read_invitation_with(
        &self,
        id: &InvitationId,
        query: impl FnOnce(&str, &[SqlParam]) -> RepositoryResult<Vec<SqlRow>>,
    ) -> RepositoryResult<Option<Invitation>> {
        let sql = format!(
            "SELECT {} FROM {} WHERE id=?",
            invitation_columns(),
            self.table("invitations")
        );
        query(&sql, &[p(id.0.clone())])?
            .first()
            .map(decode_invitation)
            .transpose()
    }
}

impl<B: SqlConn> InvitationRepository for SqlStore<B> {
    fn create_invitation(&self, invitation: Invitation) -> RepositoryResult<()> {
        self.with_policy_transaction(|transaction,_| {
            self.invitation_admission(transaction,&invitation)?;
            self.require_live_effect_scopes(transaction,&invitation.bindings.iter().map(|binding| binding.scope.clone()).collect::<Vec<_>>())?;

        let bindings = json_encode(&invitation.bindings, "invitation bindings")?;
        let invited_by = json_encode(&invitation.invited_by, "invitation inviter")?;
        let sql = format!(
            "INSERT INTO {} (id,idempotency_key,org_id,email,bindings,invited_by,token_hash,status,expires_at,created_at,updated_at,accepted_by_account_id) \
             VALUES (?,?,?,?,?j,?j,?,?,?,?,?,?)",
            self.table("invitations")
        );
        transaction.execute(
            &sql,
            &[
                p(invitation.id.0),
                p(invitation.idempotency_key),
                p(invitation.org_id.0),
                p(invitation.email),
                p(bindings),
                p(invited_by),
                p(invitation.token_hash),
                p(encode_invitation_status(invitation.status)),
                p(invitation.expires_at.0),
                p(invitation.created_at.0),
                p(invitation.updated_at.0),
                invitation.accepted_by_account_id.map(|id| id.0),
            ],
        )?;
        Ok(())

        })
    }

    fn get_invitation(&self, id: &InvitationId) -> RepositoryResult<Option<Invitation>> {
        self.read_invitation_with(id, |sql, params| self.backend.query(sql, params))
    }

    fn get_invitation_by_idempotency(
        &self,
        org_id: &OrgId,
        key: &str,
    ) -> RepositoryResult<Option<Invitation>> {
        let sql = format!(
            "SELECT {} FROM {} WHERE org_id = ? AND idempotency_key = ?",
            invitation_columns(),
            self.table("invitations")
        );
        self.backend
            .query(&sql, &[p(org_id.0.clone()), p(key.to_owned())])?
            .first()
            .map(decode_invitation)
            .transpose()
    }

    fn list_invitations_for_org(&self, org_id: &OrgId) -> RepositoryResult<Vec<Invitation>> {
        let sql = format!(
            "SELECT {} FROM {} WHERE org_id = ? ORDER BY created_at, id",
            invitation_columns(),
            self.table("invitations")
        );
        self.backend
            .query(&sql, &[p(org_id.0.clone())])?
            .iter()
            .map(decode_invitation)
            .collect()
    }

    fn replace_pending_invitation(
        &self,
        invitation: Invitation,
        expected: &str,
    ) -> RepositoryResult<bool> {
        self.with_policy_transaction(|transaction,_| {
            self.invitation_admission(transaction,&invitation)?;
            self.require_live_effect_scopes(transaction,&invitation.bindings.iter().map(|binding| binding.scope.clone()).collect::<Vec<_>>())?;

        let bindings = json_encode(&invitation.bindings, "invitation bindings")?;
        let invited_by = json_encode(&invitation.invited_by, "invitation inviter")?;
        let sql = format!(
            "UPDATE {} SET email=?,bindings=?j,invited_by=?j,token_hash=?,status=?,expires_at=?,updated_at=?,accepted_by_account_id=? \
             WHERE id=? AND status='pending' AND token_hash=?",
            self.table("invitations")
        );
        Ok(transaction.execute(
            &sql,
            &[
                p(invitation.email),
                p(bindings),
                p(invited_by),
                p(invitation.token_hash),
                p(encode_invitation_status(invitation.status)),
                p(invitation.expires_at.0),
                p(invitation.updated_at.0),
                invitation.accepted_by_account_id.map(|id| id.0),
                p(invitation.id.0),
                p(expected.to_owned()),
            ],
        )? == 1)

        })
    }

    fn accept_pending_invitation(
        &self,
        id: &InvitationId,
        expected: &str,
        account_id: &AccountId,
        at: &Timestamp,
    ) -> RepositoryResult<Option<Invitation>> {
        self.with_policy_transaction(|transaction,_| {

        let current = self.read_invitation_with(id,|sql,params| transaction.query(sql,params))?
            .ok_or_else(|| RepositoryError::NotFound("invitation not found".into()))?;
        self.invitation_admission(transaction,&current)?;
        if current.status == InvitationStatus::Accepted
            && current.accepted_by_account_id.as_ref() == Some(account_id)
            && current.token_hash == expected
        {
            return Ok(Some(current));
        }
        let mut writes = vec![SqlWrite {
            sql: format!(
                "UPDATE {} SET status='accepted',accepted_by_account_id=?,updated_at=? WHERE id=? AND status='pending' AND token_hash=?",
                self.table("invitations")
            ),
            params: vec![
                p(account_id.0.clone()),
                p(at.0.clone()),
                p(id.0.clone()),
                p(expected.to_owned()),
            ],
        }];
        self.require_live_effect_scopes(transaction,&current.bindings.iter().map(|binding| binding.scope.clone()).collect::<Vec<_>>())?;
        let principal = json_encode(
            &PrincipalRef::Account {
                account_id: account_id.clone(),
            },
            "principal",
        )?;
        for target in &current.bindings {
            let scope = json_encode(&target.scope, "binding scope")?;
            writes.push(SqlWrite {
                sql: format!(
                    "INSERT INTO {bindings} (principal,role,scope) \
                     SELECT ?j,?,?j WHERE EXISTS (SELECT 1 FROM {invites} WHERE id=? AND status='accepted' AND accepted_by_account_id=? AND token_hash=?) \
                     ON CONFLICT (principal,role,scope) DO NOTHING",
                    bindings = self.table("role_bindings"), invites = self.table("invitations")
                ),
                params: vec![p(principal.clone()), p(target.role_id.clone()), p(scope), p(id.0.clone()), p(account_id.0.clone()), p(expected.to_owned())],
            });
        }
        let affected = transaction.execute_checked(&writes, &[])?;
        if affected.first().copied() != Some(1) {
            return Ok(None);
        }
        self.read_invitation_with(id,|sql,params| transaction.query(sql,params))

        })
    }
}

fn decode_invitation(row: &SqlRow) -> RepositoryResult<Invitation> {
    let status = match req(row, 7, "invitation.status")?.as_str() {
        "pending" => InvitationStatus::Pending,
        "accepted" => InvitationStatus::Accepted,
        "revoked" => InvitationStatus::Revoked,
        "expired" => InvitationStatus::Expired,
        other => {
            return Err(RepositoryError::Backend(format!(
                "invalid invitation status {other}"
            )));
        }
    };
    Ok(Invitation {
        id: InvitationId(req(row, 0, "invitation.id")?),
        idempotency_key: req(row, 1, "invitation.idempotency_key")?,
        org_id: OrgId(req(row, 2, "invitation.org_id")?),
        email: req(row, 3, "invitation.email")?,
        bindings: json_decode::<Vec<InvitationBinding>>(
            &req(row, 4, "invitation.bindings")?,
            "invitation bindings",
        )?,
        invited_by: json_decode::<PrincipalRef>(
            &req(row, 5, "invitation.invited_by")?,
            "invitation inviter",
        )?,
        token_hash: req(row, 6, "invitation.token_hash")?,
        status,
        expires_at: Timestamp(req(row, 8, "invitation.expires_at")?),
        created_at: Timestamp(req(row, 9, "invitation.created_at")?),
        updated_at: Timestamp(req(row, 10, "invitation.updated_at")?),
        accepted_by_account_id: opt(row, 11).map(AccountId),
    })
}

fn invitation_columns() -> &'static str {
    "id, idempotency_key, org_id, email, CAST(bindings AS TEXT), \
     CAST(invited_by AS TEXT), token_hash, status, expires_at, created_at, \
     updated_at, accepted_by_account_id"
}

fn encode_invitation_status(status: InvitationStatus) -> &'static str {
    match status {
        InvitationStatus::Pending => "pending",
        InvitationStatus::Accepted => "accepted",
        InvitationStatus::Revoked => "revoked",
        InvitationStatus::Expired => "expired",
    }
}
