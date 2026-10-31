//! Grant writes shared by single and batch issuance, so both paths apply the
//! same admission, projection-ownership and upsert rules in one transaction.

use awaken_iam_core::{AuditEvent, Grant, GrantSubject, RepositoryError, RepositoryResult};

use super::{
    SqlConn, SqlStore, SqlTransaction, encode_effect, encode_grant_subject, json_encode, p,
};
use crate::GrantBatchStore;

impl<B: SqlConn> SqlStore<B> {
    /// Admit and upsert one grant inside the caller's policy transaction.
    pub(super) fn write_grant(
        &self,
        transaction: &mut dyn SqlTransaction,
        grant: &Grant,
    ) -> RepositoryResult<()> {
        let groups = if let GrantSubject::Group(group) = &grant.subject {
            vec![group.0.clone()]
        } else {
            vec![]
        };
        self.grant_admission(
            transaction,
            std::slice::from_ref(&grant.id.0),
            std::slice::from_ref(&grant.scope),
            &groups,
        )?;
        self.require_raw_grant_effect(transaction, &grant.id.0, &grant.scope)?;

        let subject = encode_grant_subject(&grant.subject)?;
        let scope = json_encode(&grant.scope, "grant scope")?;
        let sql = format!(
            "INSERT INTO {t} (id, subject, action_pattern, scope, effect) \
             VALUES (?, ?j, ?, ?j, ?) \
             ON CONFLICT (id) DO UPDATE SET subject = excluded.subject, \
             action_pattern = excluded.action_pattern, scope = excluded.scope, \
             effect = excluded.effect \
             WHERE NOT EXISTS (SELECT 1 FROM {owners} WHERE grant_id = excluded.id)",
            t = self.table("grants"),
            owners = self.table("resource_projection_grant_owners")
        );
        if transaction.execute(
            &sql,
            &[
                p(grant.id.0.clone()),
                p(subject),
                p(grant.action_pattern.0.clone()),
                p(scope),
                p(encode_effect(grant.effect)),
            ],
        )? == 0
        {
            return Err(RepositoryError::Conflict(
                "grant belongs to a product projection".into(),
            ));
        }
        Ok(())
    }
}

impl<B: SqlConn> GrantBatchStore for SqlStore<B> {
    fn put_grants(&self, grants: &[Grant], audits: Vec<AuditEvent>) -> RepositoryResult<u64> {
        self.with_policy_transaction(|transaction, version| {
            let next_version = version
                .checked_add(1)
                .filter(|value| *value <= i64::MAX as u64)
                .ok_or_else(|| RepositoryError::Backend("IAM policy version exhausted".into()))?;
            for grant in grants {
                self.write_grant(transaction, grant)?;
            }
            let audit_sql = format!(
                "INSERT INTO {} (at, actor, action, detail) VALUES (?, ?j, ?, ?)",
                self.table("audit_events")
            );
            for audit in audits {
                let actor = audit
                    .actor
                    .as_ref()
                    .map(|actor| json_encode(actor, "audit actor"))
                    .transpose()?;
                transaction.execute(
                    &audit_sql,
                    &[p(audit.at.0), actor, p(audit.action), p(audit.detail)],
                )?;
            }
            if transaction.execute(
                &format!(
                    "UPDATE {} SET version = version + 1 WHERE id = 1",
                    self.table("fence")
                ),
                &[],
            )? != 1
            {
                return Err(RepositoryError::Backend(
                    "IAM freshness fence is missing".into(),
                ));
            }
            Ok(next_version)
        })
    }
}
