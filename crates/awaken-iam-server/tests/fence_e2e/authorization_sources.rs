//! Native prerequisite writes publish their observation in the same commit.
use awaken_iam_contract::{Account, AccountId, AccountStatus, OrgId, PrincipalRef, Timestamp};
use awaken_iam_contract::{
    ApiToken, ApiTokenId, AuthorizationProfileDocument, CreateAuthorizationProfile, NamespaceId,
    PrepareScopedAuthorizationProfile, ResourceId, ResourceType, ScopeRef, WorkspaceId,
    WorkspaceOrgEdge,
};
use awaken_iam_contract::{
    ExternalIdentity, ExternalIdentityClaims, ExternalIdentityId, ExternalSubject,
    IdentityProviderKey, InvitationBinding, InvitationId, InvitationStatus,
};
use awaken_iam_core::{AccountIdentityRepository, Invitation, InvitationRepository};
use awaken_iam_core::{
    AccountRepository, Group, GroupId, GroupRepository, OrgRepository, Organization,
};
use awaken_iam_core::{
    ActionPattern, ApiTokenDirectory, ApiTokenMinter, ApiTokenOwnerRepository, ApiTokenRepository,
    AuthorizationProfileRepository, Effect, Grant, GrantId, GrantRepository, GrantSubject,
    MintApiToken, OsEntropy, PolicySet, ResourceEdge, ResourceModelRepository, RoleBinding,
    RoleBindingRepository, RoleId,
};
use awaken_iam_server::{Dialect, Fence, FenceStore, InMemoryStore, SqlConn, SqlStore};

fn at() -> Timestamp {
    Timestamp("2026-11-10T00:00:00Z".into())
}
fn actor() -> PrincipalRef {
    PrincipalRef::Account {
        account_id: AccountId("source-reader".into()),
    }
}
fn account(status: AccountStatus) -> Account {
    Account {
        id: AccountId("source-reader".into()),
        status,
        display_name: None,
        created_at: at(),
        updated_at: at(),
    }
}
fn group(members: Vec<PrincipalRef>) -> Group {
    Group {
        id: GroupId("source-team".into()),
        org: OrgId("source-org".into()),
        display_name: None,
        members,
        created_at: at(),
        updated_at: at(),
    }
}

fn grant() -> Grant {
    Grant {
        id: GrantId("source-grant".into()),
        subject: GrantSubject::Principal(actor()),
        action_pattern: ActionPattern("source::read".into()),
        scope: ScopeRef::Org {
            org_id: OrgId("source-org".into()),
        },
        effect: Effect::Allow,
    }
}
fn binding(role: &str) -> RoleBinding {
    RoleBinding {
        principal: actor(),
        role: RoleId(role.into()),
        scope: ScopeRef::Org {
            org_id: OrgId("source-org".into()),
        },
    }
}
fn edge() -> ResourceEdge {
    ResourceEdge {
        resource_type: ResourceType("source-document".into()),
        resource_id: ResourceId("source-row".into()),
        parent: ScopeRef::Org {
            org_id: OrgId("source-org".into()),
        },
    }
}
fn token() -> ApiToken {
    ApiTokenMinter::new(OsEntropy)
        .mint(
            &mut ApiTokenDirectory::new(),
            &mut PolicySet::new(),
            MintApiToken {
                id: ApiTokenId("source-token".into()),
                principal: PrincipalRef::Service {
                    service_id: "source-service".into(),
                },
                workspace: WorkspaceId("source-workspace".into()),
                role: RoleId("source-token-reader".into()),
                created_at: at(),
                expires_at: None,
            },
        )
        .unwrap()
        .token
}
fn publication(key: &str) -> PrepareScopedAuthorizationProfile {
    PrepareScopedAuthorizationProfile {
        request_key: key.into(),
        workspace_id: WorkspaceId("source-workspace".into()),
        profile: CreateAuthorizationProfile {
            namespace: NamespaceId("source.namespace".into()),
            document: AuthorizationProfileDocument::default(),
            created_at: at(),
        },
        expected_active_revision: None,
    }
}
fn provisioned_account() -> Account {
    let mut account = account(AccountStatus::Active);
    account.id = AccountId("provisioned-source-reader".into());
    account
}
fn identity() -> ExternalIdentity {
    ExternalIdentity {
        id: ExternalIdentityId("source-identity".into()),
        account_id: provisioned_account().id,
        provider_key: IdentityProviderKey("source-provider".into()),
        claims: ExternalIdentityClaims {
            subject: ExternalSubject("source-subject".into()),
            email: None,
            email_verified: None,
            display_name: None,
            username: None,
            avatar_url: None,
            locale: None,
        },
        first_seen_at: at(),
        last_seen_at: at(),
    }
}
fn invitation() -> Invitation {
    Invitation {
        id: InvitationId("source-invitation".into()),
        idempotency_key: "source-invitation-intent".into(),
        org_id: OrgId("source-org".into()),
        email: "source-reader@example.test".into(),
        bindings: vec![InvitationBinding {
            role_id: "invitation-reader".into(),
            scope: binding("invitation-reader").scope,
        }],
        invited_by: actor(),
        token_hash: "fixture-invitation-hash".into(),
        status: InvitationStatus::Pending,
        expires_at: Timestamp("2099-01-01T00:00:00Z".into()),
        created_at: at(),
        updated_at: at(),
        accepted_by_account_id: None,
    }
}

fn seed<S: AccountRepository + GroupRepository + OrgRepository>(store: &S) {
    OrgRepository::upsert(
        store,
        Organization {
            id: OrgId("source-org".into()),
            display_name: None,
            owner: actor(),
            created_at: at(),
            updated_at: at(),
        },
    )
    .unwrap();
    AccountRepository::upsert(store, account(AccountStatus::Active)).unwrap();
    GroupRepository::upsert(store, group(vec![actor()])).unwrap();
}
fn changed<S: FenceStore>(store: &S, before: Fence) -> Fence {
    let after = store.fence().unwrap();
    assert_eq!(
        after.version, before.version,
        "PAP domain event versions retain their owner"
    );
    assert_eq!(
        after.epoch,
        before.epoch + 1,
        "the native write publishes one shared observation"
    );
    after
}
fn exercise<
    S: awaken_iam_server::PolicyStore
        + AccountRepository
        + AccountIdentityRepository
        + ApiTokenRepository
        + ApiTokenOwnerRepository
        + AuthorizationProfileRepository,
>(
    store: &S,
) {
    seed(store);
    let before = store.fence().unwrap();
    AccountIdentityRepository::provision(store, provisioned_account(), identity()).unwrap();
    let before = changed(store, before);
    AccountRepository::upsert(store, account(AccountStatus::Disabled)).unwrap();
    let before = changed(store, before);
    assert_eq!(
        AccountRepository::get(store, &account(AccountStatus::Disabled).id)
            .unwrap()
            .unwrap()
            .status,
        AccountStatus::Disabled
    );
    GroupRepository::upsert(store, group(vec![])).unwrap();
    let before = changed(store, before);
    assert!(
        GroupRepository::get(store, &group(vec![]).id)
            .unwrap()
            .unwrap()
            .members
            .is_empty()
    );
    GroupRepository::remove(store, &group(vec![]).id).unwrap();
    let before = changed(store, before);
    assert!(
        GroupRepository::get(store, &group(vec![]).id)
            .unwrap()
            .is_none()
    );
    assert!(GroupRepository::remove(store, &group(vec![]).id).is_err());
    assert_eq!(
        store.fence().unwrap(),
        before,
        "failed native writes do not publish an epoch"
    );
    GrantRepository::put(store, grant()).unwrap();
    let before = changed(store, before);
    GrantRepository::remove(store, &grant().id).unwrap();
    let before = changed(store, before);
    assert!(GrantRepository::get(store, &grant().id).unwrap().is_none());
    RoleBindingRepository::add(store, binding("source-reader")).unwrap();
    let before = changed(store, before);
    RoleBindingRepository::replace_scoped(
        store,
        &actor(),
        &binding("source-reader").scope,
        &[
            RoleId("source-reader".into()),
            RoleId("source-writer".into()),
        ],
        &[RoleId("source-writer".into())],
    )
    .unwrap();
    let before = changed(store, before);
    assert!(!RoleBindingRepository::contains_exact(store, &binding("source-reader")).unwrap());
    assert!(RoleBindingRepository::contains_exact(store, &binding("source-writer")).unwrap());
    RoleBindingRepository::remove(store, &binding("source-writer")).unwrap();
    let before = changed(store, before);
    ResourceModelRepository::put_workspace_org(
        store,
        WorkspaceOrgEdge {
            workspace_id: WorkspaceId("source-workspace".into()),
            org_id: OrgId("source-org".into()),
        },
    )
    .unwrap();
    let before = changed(store, before);
    ResourceModelRepository::put_edge(store, edge()).unwrap();
    let before = changed(store, before);
    ResourceModelRepository::remove_edge(store, &edge().resource_type, &edge().resource_id)
        .unwrap();
    let before = changed(store, before);
    assert!(
        ResourceModelRepository::list_edges(store)
            .unwrap()
            .is_empty()
    );
    InvitationRepository::create_invitation(store, invitation()).unwrap();
    assert_eq!(
        store.fence().unwrap(),
        before,
        "a pending invitation has not materialized permission"
    );
    InvitationRepository::accept_pending_invitation(
        store,
        &invitation().id,
        &invitation().token_hash,
        &AccountId("source-reader".into()),
        &at(),
    )
    .unwrap()
    .unwrap();
    let before = changed(store, before);
    assert!(RoleBindingRepository::contains_exact(store, &binding("invitation-reader")).unwrap());
    InvitationRepository::accept_pending_invitation(
        store,
        &invitation().id,
        &invitation().token_hash,
        &AccountId("source-reader".into()),
        &at(),
    )
    .unwrap()
    .unwrap();
    assert_eq!(
        store.fence().unwrap(),
        before,
        "accepted invitation replay cannot materialize permission twice"
    );
    let mut token = token();
    ApiTokenRepository::create(store, token.clone()).unwrap();
    let before = changed(store, before);
    ApiTokenOwnerRepository::record_api_token_owner(
        store,
        &token.id,
        &AccountId("source-reader".into()),
    )
    .unwrap();
    let before = changed(store, before);
    token.revoked_at = Some(at());
    ApiTokenRepository::update(store, token.clone()).unwrap();
    let before = changed(store, before);
    assert_eq!(
        ApiTokenRepository::get(store, &token.id).unwrap(),
        Some(token)
    );
    let request = publication("first-pin");
    AuthorizationProfileRepository::prepare_profile_publication(
        store,
        request.clone(),
        actor(),
        "first-digest".into(),
        "first-checksum".into(),
    )
    .unwrap();
    let before = changed(store, before);
    AuthorizationProfileRepository::prepare_profile_publication(
        store,
        request,
        actor(),
        "first-digest".into(),
        "first-checksum".into(),
    )
    .unwrap();
    assert_eq!(
        store.fence().unwrap(),
        before,
        "original intent replay cannot publish another namespace pin"
    );
    AuthorizationProfileRepository::prepare_profile_publication(
        store,
        publication("later-draft"),
        actor(),
        "next-digest".into(),
        "next-checksum".into(),
    )
    .unwrap();
    assert_eq!(
        store.fence().unwrap(),
        before,
        "later inactive drafts retain the same decision family"
    );
    assert_eq!(
        AuthorizationProfileRepository::profile_publication_workspace(
            store,
            &NamespaceId("source.namespace".into())
        )
        .unwrap(),
        Some(WorkspaceId("source-workspace".into()))
    );
}

#[test]
fn memory_native_authorization_prerequisites_advance_the_shared_epoch() {
    exercise(&InMemoryStore::new());
}
#[test]
fn sqlite_native_authorization_prerequisites_advance_the_shared_epoch() {
    exercise(&awaken_iam_server::sqlite_in_memory_store("source_epoch_conformance").unwrap());
}
#[test]
fn postgres_native_authorization_prerequisites_advance_the_shared_epoch() {
    let Ok(url) = std::env::var("IAM_TEST_POSTGRES_URL") else {
        return;
    };
    let prefix = format!(
        "source_epoch_{:x}",
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    );
    exercise(&awaken_iam_server::postgres_migrated_store(&url, &prefix).unwrap());
}

fn rollback<B: SqlConn>(store: SqlStore<B>, prefix: &str) {
    seed(&store);
    let original_token = token();
    ApiTokenRepository::create(&store, original_token.clone()).unwrap();
    InvitationRepository::create_invitation(&store, invitation()).unwrap();
    let before = store.fence().unwrap();
    // Both generated identifiers belong to this test's explicitly migrated
    // prefix. The trigger fails the epoch update after the real source write.
    match store.backend().dialect() {
        Dialect::Sqlite => {
            store.backend().execute(&format!("CREATE TRIGGER {prefix}_reject_epoch BEFORE UPDATE OF epoch ON {prefix}_fence WHEN NEW.epoch <> OLD.epoch BEGIN SELECT RAISE(ABORT, 'test epoch publication rejected'); END"), &[]).unwrap();
        }
        Dialect::Postgres => {
            store.backend().execute(&format!("CREATE FUNCTION {prefix}_reject_epoch() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RAISE EXCEPTION 'test epoch publication rejected'; END $$"), &[]).unwrap();
            store.backend().execute(&format!("CREATE TRIGGER {prefix}_reject_epoch BEFORE UPDATE OF epoch ON {prefix}_fence FOR EACH ROW WHEN (NEW.epoch <> OLD.epoch) EXECUTE FUNCTION {prefix}_reject_epoch()"), &[]).unwrap();
        }
    }
    assert!(AccountRepository::upsert(&store, account(AccountStatus::Disabled)).is_err());
    assert_eq!(
        AccountRepository::get(&store, &account(AccountStatus::Active).id)
            .unwrap()
            .unwrap()
            .status,
        AccountStatus::Active
    );
    assert!(
        AccountIdentityRepository::provision(&store, provisioned_account(), identity()).is_err()
    );
    assert!(
        AccountRepository::get(&store, &provisioned_account().id)
            .unwrap()
            .is_none()
    );
    assert!(
        awaken_iam_core::ExternalIdentityRepository::get_by_key(&store, &identity().key())
            .unwrap()
            .is_none()
    );
    assert!(
        InvitationRepository::accept_pending_invitation(
            &store,
            &invitation().id,
            &invitation().token_hash,
            &AccountId("source-reader".into()),
            &at()
        )
        .is_err()
    );
    assert_eq!(
        InvitationRepository::get_invitation(&store, &invitation().id)
            .unwrap()
            .unwrap()
            .status,
        InvitationStatus::Pending
    );
    assert!(!RoleBindingRepository::contains_exact(&store, &binding("invitation-reader")).unwrap());
    assert!(GroupRepository::upsert(&store, group(vec![])).is_err());
    assert_eq!(
        GroupRepository::get(&store, &group(vec![]).id)
            .unwrap()
            .unwrap(),
        group(vec![actor()])
    );
    assert!(GrantRepository::put(&store, grant()).is_err());
    assert!(GrantRepository::get(&store, &grant().id).unwrap().is_none());
    assert!(RoleBindingRepository::add(&store, binding("source-reader")).is_err());
    assert!(!RoleBindingRepository::contains_exact(&store, &binding("source-reader")).unwrap());
    assert!(ResourceModelRepository::put_edge(&store, edge()).is_err());
    assert!(
        ResourceModelRepository::list_edges(&store)
            .unwrap()
            .is_empty()
    );
    assert!(
        ResourceModelRepository::put_workspace_org(
            &store,
            WorkspaceOrgEdge {
                workspace_id: WorkspaceId("source-workspace".into()),
                org_id: OrgId("source-org".into())
            }
        )
        .is_err()
    );
    assert!(
        ResourceModelRepository::workspace_org(&store, &WorkspaceId("source-workspace".into()))
            .unwrap()
            .is_none()
    );
    let mut revoked = original_token.clone();
    revoked.revoked_at = Some(at());
    assert!(ApiTokenRepository::update(&store, revoked).is_err());
    assert_eq!(
        ApiTokenRepository::get(&store, &original_token.id).unwrap(),
        Some(original_token.clone())
    );
    assert!(
        ApiTokenOwnerRepository::record_api_token_owner(
            &store,
            &original_token.id,
            &AccountId("source-reader".into())
        )
        .is_err()
    );
    assert!(
        ApiTokenOwnerRepository::api_token_owner(&store, &original_token.id)
            .unwrap()
            .is_none()
    );
    assert!(OrgRepository::remove(&store, &OrgId("source-org".into())).is_err());
    assert!(
        OrgRepository::get(&store, &OrgId("source-org".into()))
            .unwrap()
            .is_some()
    );
    assert!(
        AuthorizationProfileRepository::prepare_profile_publication(
            &store,
            publication("rejected-pin"),
            actor(),
            "digest".into(),
            "checksum".into()
        )
        .is_err()
    );
    assert!(
        AuthorizationProfileRepository::profile_publication_workspace(
            &store,
            &NamespaceId("source.namespace".into())
        )
        .unwrap()
        .is_none()
    );
    assert!(
        AuthorizationProfileRepository::get_profile(
            &store,
            &NamespaceId("source.namespace".into()),
            1
        )
        .unwrap()
        .is_none()
    );
    assert!(GroupRepository::remove(&store, &group(vec![]).id).is_err());
    assert_eq!(
        GroupRepository::get(&store, &group(vec![]).id)
            .unwrap()
            .unwrap(),
        group(vec![actor()])
    );
    assert_eq!(
        store.fence().unwrap(),
        before,
        "neither a source write nor a false epoch may escape rollback"
    );
}
#[test]
fn sqlite_epoch_publication_failure_rolls_back_the_actual_account_and_roster_writes() {
    rollback(
        awaken_iam_server::sqlite_in_memory_store("source_epoch_rollback").unwrap(),
        "source_epoch_rollback",
    );
}
#[test]
fn postgres_epoch_publication_failure_rolls_back_the_actual_account_and_roster_writes() {
    let Ok(url) = std::env::var("IAM_TEST_POSTGRES_URL") else {
        return;
    };
    let prefix = format!(
        "source_rollback_{:x}",
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    );
    rollback(
        awaken_iam_server::postgres_migrated_store(&url, &prefix).unwrap(),
        &prefix,
    );
}
