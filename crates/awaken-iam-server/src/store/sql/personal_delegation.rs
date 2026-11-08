//! One portable, durable consent owner for SQLite and PostgreSQL.
use super::*;
use awaken_iam_contract::{ListPersonalDelegations, PersonalDelegation, PersonalDelegationPage};
use awaken_iam_core::PersonalDelegationRepository;

fn decode(row: &SqlRow) -> RepositoryResult<PersonalDelegation> {
    let descriptor = row
        .first()
        .and_then(Option::as_deref)
        .ok_or_else(|| RepositoryError::Backend("missing personal consent".into()))?;
    let mut value: PersonalDelegation =
        serde_json::from_str(descriptor).map_err(|e| RepositoryError::Backend(e.to_string()))?;
    value.revoked_at = row
        .get(1)
        .and_then(Option::as_deref)
        .map(str::parse::<i64>)
        .transpose()
        .map_err(|e| RepositoryError::Backend(e.to_string()))?;
    value.version = if value.revoked_at.is_some() { 2 } else { 1 };
    Ok(value)
}

impl<B: SqlConn> PersonalDelegationRepository for SqlStore<B> {
    fn create_personal_delegation(
        &self,
        value: PersonalDelegation,
    ) -> RepositoryResult<PersonalDelegation> {
        if value.version != 1 || value.revoked_at.is_some() {
            return Err(RepositoryError::Conflict(
                "new consent must be live version one".into(),
            ));
        }
        let table = self.table("personal_delegations");
        let mut result = None;
        self.backend.with_transaction(&mut |tx| {
            tx.execute(&format!("INSERT INTO {table} (id, owner, request_key, descriptor, revoked_at) VALUES (?, ?, ?, ?j, NULL) ON CONFLICT DO NOTHING"),
                &[p(value.id.clone()), p(value.owner.0.clone()), p(value.consent.request_key.clone()), p(serde_json::to_string(&value).map_err(|e| RepositoryError::Backend(e.to_string()))?)])?;
            let rows = tx.query(&format!("SELECT CAST(descriptor AS TEXT), revoked_at FROM {table} WHERE owner=? AND request_key=?"), &[p(value.owner.0.clone()),p(value.consent.request_key.clone())])?;
            let stored = rows.first().map(decode).transpose()?.ok_or_else(|| RepositoryError::Conflict("personal consent identity collision".into()))?;
            if stored.id != value.id || stored.owner != value.owner || stored.service_id != value.service_id || stored.consent != value.consent {
                return Err(RepositoryError::Conflict("original consent key has different content".into()));
            }
            result = Some(stored); Ok(())
        })?;
        result.ok_or_else(|| {
            RepositoryError::Backend("consent transaction returned no receipt".into())
        })
    }
    fn personal_delegation(&self, id: &str) -> RepositoryResult<Option<PersonalDelegation>> {
        self.backend
            .query(
                &format!(
                    "SELECT CAST(descriptor AS TEXT), revoked_at FROM {} WHERE id=?",
                    self.table("personal_delegations")
                ),
                &[p(id.to_owned())],
            )?
            .first()
            .map(decode)
            .transpose()
    }
    fn list_personal_delegations(
        &self,
        owner: &AccountId,
        query: &ListPersonalDelegations,
    ) -> RepositoryResult<PersonalDelegationPage> {
        if !(1..=100).contains(&query.limit)
            || query.after.as_ref().is_some_and(|cursor| {
                cursor.is_empty() || cursor.len() > 300 || cursor.trim() != cursor
            })
        {
            return Err(RepositoryError::Conflict(
                "invalid personal consent page".into(),
            ));
        }
        // The interpolated limit is a validated integer, never caller SQL.
        let rows = self.backend.query(
            &format!(
                "SELECT CAST(descriptor AS TEXT), revoked_at FROM {} WHERE owner=? AND id>? ORDER BY id ASC LIMIT {}",
                self.table("personal_delegations"), u32::from(query.limit) + 1
            ),
            &[p(owner.0.clone()), p(query.after.clone().unwrap_or_default())],
        )?;
        let mut items = rows
            .iter()
            .map(decode)
            .collect::<RepositoryResult<Vec<_>>>()?;
        let more = items.len() > usize::from(query.limit);
        items.truncate(usize::from(query.limit));
        let next_cursor = more.then(|| items.last().expect("nonempty bounded page").id.clone());
        Ok(PersonalDelegationPage { items, next_cursor })
    }
    fn revoke_personal_delegation(
        &self,
        id: &str,
        owner: &AccountId,
        at: i64,
    ) -> RepositoryResult<PersonalDelegation> {
        let table = self.table("personal_delegations");
        let mut result = None;
        self.backend.with_transaction(&mut |tx| {
            tx.execute(&format!("UPDATE {table} SET revoked_at=? WHERE id=? AND owner=? AND revoked_at IS NULL"), &[p(at.to_string()),p(id.to_owned()),p(owner.0.clone())])?;
            let rows = tx.query(&format!("SELECT CAST(descriptor AS TEXT), revoked_at FROM {table} WHERE id=? AND owner=?"), &[p(id.to_owned()),p(owner.0.clone())])?;
            result = rows.first().map(decode).transpose()?; Ok(())
        })?;
        result.ok_or_else(|| RepositoryError::NotFound("personal consent".into()))
    }
}
