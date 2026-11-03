//! The original generic real-backend harness owns these token command rules.
use super::*;
use awaken_iam_core::{ApiTokenDirectory, ApiTokenMinter, MintApiToken, OsEntropy, PolicySet};

pub(super) fn request(id: &str) -> MintApiToken {
    MintApiToken {
        id: ApiTokenId(id.into()),
        principal: service("atomic-token-owner"),
        workspace: WorkspaceId("atomic-workspace".into()),
        role: RoleId("atomic-role".into()),
        created_at: ts("2026-06-19T00:00:00Z"),
        expires_at: None,
    }
}

pub(super) fn exercise<B: SqlConn>(store: &SqlStore<B>) {
    // A1 coherent token+binding -> both commit, then same prepared value can
    // publish. A2 principal/workspace incoherence -> neither row. A3 every
    // immutable coordinate drift -> Conflict/no revoke; A4 success/replay or a
    // prior durable revoke -> first stamp retained. Original SQL/PG harnesses
    // invoke this once on their own backend; no second database or fake store.
    let mut directory = ApiTokenDirectory::new();
    let mut policy = PolicySet::new();
    let mut minter = ApiTokenMinter::new(OsEntropy);
    for cause in ["principal", "workspace", "scope"] {
        let pending = minter
            .prepare(&mut directory, request("atomic-refused"))
            .unwrap();
        let mut binding = pending.binding().clone();
        match cause {
            "principal" => binding.principal = service("foreign-owner"),
            "workspace" => {
                binding.scope = ScopeRef::Workspace {
                    workspace_id: WorkspaceId("foreign-workspace".into()),
                }
            }
            _ => binding.scope = ScopeRef::Global,
        }
        assert!(matches!(
            store.commit_api_token_mint(pending.token(), &binding),
            Err(RepositoryError::Conflict(_))
        ));
        drop(pending);
        assert!(
            directory
                .token(&ApiTokenId("atomic-refused".into()))
                .is_none()
        );
        assert!(
            ApiTokenRepository::get(store, &ApiTokenId("atomic-refused".into()))
                .unwrap()
                .is_none()
        );
    }
    let pending = minter
        .prepare(&mut directory, request("atomic-committed"))
        .unwrap();
    let frozen = pending.token().clone();
    let binding = pending.binding().clone();
    store
        .commit_api_token_mint(pending.token(), pending.binding())
        .unwrap();
    assert_eq!(
        ApiTokenRepository::get(store, &frozen.id).unwrap(),
        Some(frozen.clone())
    );
    assert!(
        RoleBindingRepository::list_for_principal(store, &binding.principal)
            .unwrap()
            .contains(&binding)
    );
    let issued = pending.publish(&mut policy);
    assert!(
        directory
            .authenticate(&issued.secret, &ts("2026-06-19T01:00:00Z"))
            .is_ok()
    );
    for cause in [
        "prefix",
        "principal",
        "hash",
        "workspace",
        "created",
        "expiry",
    ] {
        let mut foreign = frozen.clone();
        match cause {
            "prefix" => foreign.prefix = ApiTokenPrefix("foreign-prefix".into()),
            "principal" => foreign.principal = service("foreign-owner"),
            "hash" => foreign.secret_hash.push('x'),
            "workspace" => foreign.workspace = WorkspaceId("foreign-workspace".into()),
            "created" => foreign.created_at = ts("2025-06-19T00:00:00Z"),
            _ => foreign.expires_at = Some(ts("2027-06-19T00:00:00Z")),
        }
        assert!(
            matches!(
                store.commit_api_token_revocation(&foreign, &ts("2026-06-19T01:00:00Z")),
                Err(RepositoryError::Conflict(_))
            ),
            "{cause}"
        );
        assert_eq!(
            ApiTokenRepository::get(store, &frozen.id).unwrap(),
            Some(frozen.clone())
        );
    }
    let first = ts("2026-06-19T01:00:00Z");
    // Another durable writer can complete the exact revoke before this live
    // projection catches up. The prepared original slot accepts only its stamp.
    assert_eq!(
        store.commit_api_token_revocation(&frozen, &first).unwrap(),
        first
    );
    let pending = directory.prepare_revoke(&frozen.id).unwrap();
    let stamp = store
        .commit_api_token_revocation(pending.token(), &ts("2026-06-19T02:00:00Z"))
        .unwrap();
    assert_eq!(stamp, first);
    let revoked = pending.publish(stamp);
    assert_eq!(revoked.revoked_at, Some(first.clone()));
    assert_eq!(
        ApiTokenRepository::get(store, &frozen.id).unwrap(),
        Some(revoked.clone())
    );
    assert!(
        directory
            .authenticate(&issued.secret, &ts("2026-06-19T03:00:00Z"))
            .is_err()
    );
    // A5: durable B and an already-frozen Some(A!=B) are contradictory;
    // preserve the exact durable row and original live B, and never publish.
    let mut conflicting = revoked.clone();
    conflicting.revoked_at = Some(ts("2026-06-19T00:30:00Z"));
    assert!(matches!(
        store.commit_api_token_revocation(&conflicting, &ts("2026-06-19T03:30:00Z")),
        Err(RepositoryError::Conflict(_))
    ));
    assert_eq!(
        ApiTokenRepository::get(store, &frozen.id).unwrap(),
        Some(revoked.clone())
    );
    assert_eq!(directory.token(&frozen.id), Some(&revoked));
    let pending = directory.prepare_revoke(&frozen.id).unwrap();
    let stamp = store
        .commit_api_token_revocation(pending.token(), &ts("2026-06-19T04:00:00Z"))
        .unwrap();
    assert_eq!(pending.publish(stamp).revoked_at, Some(first));
    let mut missing = frozen;
    missing.id = ApiTokenId("atomic-missing".into());
    assert!(matches!(
        store.commit_api_token_revocation(&missing, &ts("2026-06-19T05:00:00Z")),
        Err(RepositoryError::NotFound(_))
    ));
}
