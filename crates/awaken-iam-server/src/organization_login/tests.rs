use super::*;
use std::collections::HashMap;
use std::sync::Mutex;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

#[derive(Default)]
struct Broker {
    entries: Mutex<HashMap<String, BrokerConnection>>,
    reads: AtomicUsize,
    writes: AtomicUsize,
    lose_reply: AtomicBool,
    lose_read_after_write: AtomicBool,
    unavailable: AtomicBool,
}

impl IdentityBroker for Broker {
    // This test adapter deliberately uses snake_case rather than Dex's wire
    // spelling. The same IAM command/recovery table must pass for either codec.
    fn encode_oidc(
        &self,
        value: &OidcLoginConfiguration,
    ) -> Result<Vec<u8>, OrganizationLoginError> {
        serde_json::to_vec(value).map_err(|_| OrganizationLoginError::Invalid)
    }
    fn decode_oidc(&self, bytes: &[u8]) -> Result<OidcLoginConfiguration, OrganizationLoginError> {
        serde_json::from_slice(bytes).map_err(|_| OrganizationLoginError::Unavailable)
    }
    fn list(&self) -> Result<Vec<BrokerConnection>, OrganizationLoginError> {
        self.reads.fetch_add(1, Ordering::SeqCst);
        if self.unavailable.load(Ordering::SeqCst) {
            return Err(OrganizationLoginError::Unavailable);
        }
        Ok(self.entries.lock().unwrap().values().cloned().collect())
    }
    fn create(&self, value: &BrokerConnection) -> Result<bool, OrganizationLoginError> {
        if self.entries.lock().unwrap().contains_key(&value.id) {
            return Ok(false);
        }
        self.replace(value)?;
        Ok(true)
    }
    fn replace(&self, value: &BrokerConnection) -> Result<(), OrganizationLoginError> {
        self.writes.fetch_add(1, Ordering::SeqCst);
        self.entries
            .lock()
            .unwrap()
            .insert(value.id.clone(), value.clone());
        if self.lose_read_after_write.swap(false, Ordering::SeqCst) {
            self.unavailable.store(true, Ordering::SeqCst);
        }
        if self.lose_reply.swap(false, Ordering::SeqCst) {
            return Err(OrganizationLoginError::Unavailable);
        }
        Ok(())
    }
    fn remove(&self, id: &str) -> Result<(), OrganizationLoginError> {
        self.writes.fetch_add(1, Ordering::SeqCst);
        self.entries.lock().unwrap().remove(id);
        Ok(())
    }
}

#[derive(Default)]
struct Discovery {
    reject: AtomicBool,
}
impl DiscoveryCheck for Discovery {
    fn check(&self, _: &str) -> Result<(), OrganizationLoginError> {
        if self.reject.load(Ordering::SeqCst) {
            Err(OrganizationLoginError::Invalid)
        } else {
            Ok(())
        }
    }
}

#[derive(Default)]
struct Admission {
    busy: AtomicBool,
}
struct Lease;
impl MutationLease for Lease {
    fn verify(&mut self) -> Result<(), OrganizationLoginError> {
        Ok(())
    }
}
impl MutationAdmission for Admission {
    fn acquire(&self, _: &str) -> Result<Box<dyn MutationLease>, OrganizationLoginError> {
        if self.busy.load(Ordering::SeqCst) {
            Err(OrganizationLoginError::Busy)
        } else {
            Ok(Box::new(Lease))
        }
    }
}

fn fixture() -> (
    OrganizationLoginService,
    Arc<Broker>,
    Arc<Discovery>,
    Arc<Admission>,
) {
    let broker = Arc::new(Broker::default());
    let discovery = Arc::new(Discovery::default());
    let admission = Arc::new(Admission::default());
    let service = OrganizationLoginService::new(
        broker.clone(),
        discovery.clone(),
        admission.clone(),
        "https://login.platform.example/dex",
        "local-e2e",
        ProductId::new("tutor").unwrap(),
    )
    .unwrap();
    (service, broker, discovery, admission)
}

fn create() -> CreateConnection {
    CreateConnection {
        name: "School sign-in".into(),
        issuer: "https://sso.school.example/realm".into(),
        client_id: "school-client".into(),
        client_secret: "fixture".repeat(4),
        scopes: model::default_scopes(),
    }
}

#[test]
fn connection_identity_is_stable_and_separated_by_institution_issuer_and_client() {
    // DT-SSO-ID: the same immutable coordinates reuse one ID; a changed institution/issuer/client cannot reuse it.
    let a = OrgId("institution-a".into());
    let b = OrgId("institution-b".into());
    let id = connection_id(
        &ProductId::new("tutor").unwrap(),
        &a,
        "https://idp.example",
        "client",
    );
    // Frozen vector from the deployed implementation. A changed digest or
    // prefix would change broker subjects even if fresh same-input tests pass.
    assert_eq!(
        id,
        "tutor-9843299def5bff5a619bc3382474dc34-e079194dd5f237ffb2c2ebbd"
    );
    assert_eq!(
        id,
        connection_id(
            &ProductId::new("tutor").unwrap(),
            &a,
            "https://idp.example",
            "client"
        )
    );
    assert_eq!(id.len(), 63);
    assert_ne!(
        id,
        connection_id(
            &ProductId::new("tutor").unwrap(),
            &b,
            "https://idp.example",
            "client"
        )
    );
    assert_ne!(
        id,
        connection_id(
            &ProductId::new("tutor").unwrap(),
            &a,
            "https://other.example",
            "client"
        )
    );
    assert_ne!(
        id,
        connection_id(
            &ProductId::new("tutor").unwrap(),
            &a,
            "https://idp.example",
            "other"
        )
    );
}

#[test]
fn product_scopes_keep_deployed_ids_and_refuse_another_registered_product() {
    // Causes: C1 same product/org/issuer/client, C2 a different ProductId over
    // the SAME broker and OrgId, C3 changed ID/client/secret, C4 a retry after
    // migration. P1 C1+C4 => exact deployed ID/version and no new record;
    // P2 C2 => empty list and NotFound for read/update/delete/login hint, with
    // no writes. P3 each product can independently create its own connection.
    // Product identity is data; the two product lengths exercise ID admission.
    let (first, broker, discovery, admission) = fixture();
    let org = OrgId("same-org".into());
    let existing = first.create(&org, create()).unwrap();
    let before = broker.writes.load(Ordering::SeqCst);
    let second = OrganizationLoginService::new(
        broker.clone(),
        discovery,
        admission,
        "https://login.platform.example/dex",
        "local-e2e",
        ProductId::new("another-product").unwrap(),
    )
    .unwrap();
    assert!(second.list(&org).unwrap().is_empty());
    assert_eq!(
        second.selected(&org, &existing.id),
        Err(OrganizationLoginError::NotFound)
    );
    assert!(second.login_hint(&org, &existing.id).is_err());
    assert!(matches!(
        second.update(
            &org,
            &existing.id,
            UpdateConnection {
                name: "changed".into(),
                client_secret: None,
                version: existing.version.clone()
            }
        ),
        Err(OrganizationLoginError::NotFound)
    ));
    assert_eq!(
        second.remove(&org, &existing.id, &existing.version),
        Err(OrganizationLoginError::NotFound)
    );
    assert_eq!(broker.writes.load(Ordering::SeqCst), before);
    assert_eq!(first.create(&org, create()).unwrap().id, existing.id);
    assert_eq!(broker.writes.load(Ordering::SeqCst), before);
    let other = second.create(&org, create()).unwrap();
    assert_ne!(other.id, existing.id);
    assert_eq!(second.list(&org).unwrap()[0].id, other.id);
    assert_eq!(first.list(&org).unwrap()[0].id, existing.id);
}

#[test]
fn configured_views_and_public_login_options_never_expose_credentials() {
    // DT-SSO-1: valid input + successful publication => one entry, broker callback, public routing-only option.
    let (service, broker, _, _) = fixture();
    let org = OrgId("institution-a".into());
    let view = service.create(&org, create()).unwrap();
    assert!(view.credential_configured);
    assert_eq!(
        view.callback_uri,
        "https://login.platform.example/dex/callback"
    );
    assert!(
        !serde_json::to_string(&view)
            .unwrap()
            .contains(&create().client_secret)
    );
    assert!(!format!("{:?}", broker.entries.lock().unwrap()).contains(&create().client_secret));
    let options = service.options(&org).unwrap();
    assert_eq!(options.len(), 1);
    let value = serde_json::to_value(&options[0]).unwrap();
    assert_eq!(value.as_object().unwrap().len(), 3);
    let url = url::Url::parse(&format!(
        "https://accounts.example{}",
        options[0].login_path
    ))
    .unwrap();
    assert_eq!(url.path(), "/v1/auth/login/local-e2e");
    assert!(
        url.query_pairs()
            .any(|(k, v)| k == "organization_id" && v == org.0)
    );
}

#[test]
fn another_institution_cannot_read_select_change_or_remove_the_connection() {
    // DT-SSO-2: a connection outside the requested institution => empty public list / 404 before broker mutation.
    let (service, broker, _, _) = fixture();
    let a = OrgId("institution-a".into());
    let b = OrgId("institution-b".into());
    let view = service.create(&a, create()).unwrap();
    assert!(service.list(&b).unwrap().is_empty());
    assert_eq!(
        service.selected(&b, &view.id),
        Err(OrganizationLoginError::NotFound)
    );
    assert_eq!(
        service.remove(&b, &view.id, &view.version),
        Err(OrganizationLoginError::NotFound)
    );
    let writes = broker.writes.load(Ordering::SeqCst);
    assert!(matches!(
        service.update(
            &b,
            &view.id,
            UpdateConnection {
                name: "Other".into(),
                client_secret: None,
                version: view.version
            }
        ),
        Err(OrganizationLoginError::NotFound)
    ));
    assert_eq!(writes, broker.writes.load(Ordering::SeqCst));
}

#[test]
fn secret_rotation_keeps_identity_and_stale_edits_conflict_but_exact_retries_replay() {
    // DT-SSO-3/4: expected version + new secret => same identity, new version; stale different content => conflict.
    // The same desired PUT with the old version is an idempotent retry and must not write again.
    let (service, broker, _, _) = fixture();
    let org = OrgId("institution-a".into());
    let old = service.create(&org, create()).unwrap();
    let request = || UpdateConnection {
        name: "Institution login".into(),
        client_secret: Some("rotated-secret".into()),
        version: old.version.clone(),
    };
    let new = service.update(&org, &old.id, request()).unwrap();
    assert_eq!(old.id, new.id);
    assert_ne!(old.version, new.version);
    let writes = broker.writes.load(Ordering::SeqCst);
    assert_eq!(
        service.update(&org, &old.id, request()).unwrap().version,
        new.version
    );
    assert_eq!(writes, broker.writes.load(Ordering::SeqCst));
    assert!(matches!(
        service.update(
            &org,
            &old.id,
            UpdateConnection {
                name: "Stale".into(),
                client_secret: None,
                version: old.version
            }
        ),
        Err(OrganizationLoginError::Conflict)
    ));
}

#[test]
fn failed_discovery_and_invalid_inputs_have_no_broker_side_effect() {
    // DT-SSO-5: invalid syntax or rejected discovery => no connection, lease or broker write.
    let (service, broker, discovery, _) = fixture();
    let org = OrgId("institution-a".into());
    for issuer in [
        "http://idp.example",
        "https://user:secret@idp.example",
        "https://idp.example?query=1",
        "https://idp.example#fragment",
    ] {
        let mut request = create();
        request.issuer = issuer.into();
        assert!(matches!(
            service.create(&org, request),
            Err(OrganizationLoginError::Invalid)
        ));
    }
    discovery.reject.store(true, Ordering::SeqCst);
    assert!(matches!(
        service.create(&org, create()),
        Err(OrganizationLoginError::Invalid)
    ));
    assert_eq!(broker.writes.load(Ordering::SeqCst), 0);
    assert_eq!(broker.reads.load(Ordering::SeqCst), 0);
}

#[test]
fn a_lost_reply_is_confirmed_from_the_broker_instead_of_blindly_repeated() {
    // DT-SSO-6: the mutation applied but its reply was lost; an authoritative matching read makes it successful.
    let (service, broker, _, _) = fixture();
    let org = OrgId("institution-a".into());
    broker.lose_reply.store(true, Ordering::SeqCst);
    let view = service.create(&org, create()).unwrap();
    assert_eq!(
        service.create(&org, create()).unwrap().version,
        view.version
    );
    assert_eq!(broker.writes.load(Ordering::SeqCst), 1);
}

#[test]
fn an_unconfirmed_operation_stays_uncertain_and_a_retry_never_restores_old_state() {
    // DT-SSO-7: both the write result and confirming read are unavailable => unknown outcome, no rollback write.
    // Once reads recover, the exact retry observes the published state without another mutation.
    let (service, broker, _, _) = fixture();
    let org = OrgId("institution-a".into());
    broker.lose_reply.store(true, Ordering::SeqCst);
    broker.lose_read_after_write.store(true, Ordering::SeqCst);
    assert!(matches!(
        service.create(&org, create()),
        Err(OrganizationLoginError::Uncertain)
    ));
    broker.unavailable.store(false, Ordering::SeqCst);
    assert!(service.create(&org, create()).is_ok());
    assert_eq!(broker.writes.load(Ordering::SeqCst), 1);
}

#[test]
fn removal_is_versioned_and_terminal_retries_are_idempotent() {
    // DT-SSO-8: a stale delete does nothing; confirmed removal hides the option, then a retry is a no-op.
    let (service, broker, _, _) = fixture();
    let org = OrgId("institution-a".into());
    let view = service.create(&org, create()).unwrap();
    assert_eq!(
        service.remove(&org, &view.id, "stale"),
        Err(OrganizationLoginError::Conflict)
    );
    service.remove(&org, &view.id, &view.version).unwrap();
    let writes = broker.writes.load(Ordering::SeqCst);
    service.remove(&org, &view.id, &view.version).unwrap();
    assert_eq!(writes, broker.writes.load(Ordering::SeqCst));
    assert!(service.options(&org).unwrap().is_empty());
}

#[test]
fn an_admission_conflict_prevents_any_write() {
    // DT-SSO-9: another mutation holds the distributed key => busy; this call never changes the broker.
    let (service, broker, _, admission) = fixture();
    let org = OrgId("institution-a".into());
    admission.busy.store(true, Ordering::SeqCst);
    assert!(matches!(
        service.create(&org, create()),
        Err(OrganizationLoginError::Busy)
    ));
    assert_eq!(broker.writes.load(Ordering::SeqCst), 0);
}

#[test]
fn input_contract_cannot_change_issuer_client_scopes_or_security_flags_during_rotation() {
    // DT-SSO-10: updates contain only name/secret/version; immutable identity and broker security flags are not inputs.
    for field in [
        "issuer",
        "client_id",
        "scopes",
        "insecureSkipEmailVerified",
        "rootCAs",
    ] {
        let mut body = serde_json::json!({"name":"School","version":"version"});
        body[field] = serde_json::json!("unexpected");
        assert!(serde_json::from_value::<UpdateConnection>(body).is_err());
    }
}

#[test]
fn a_login_hint_preserves_iam_proofs_and_only_decorates_the_configured_broker() {
    // DT-SSO-HINT: selected owned connection + exact broker endpoint + state/PKCE => routing decoration only.
    // Foreign origin/path, missing proof, weaker PKCE or existing hint/prompt rejects. No callback/session is minted here.
    let (service, _, _, _) = fixture();
    let org = OrgId("institution-a".into());
    let view = service.create(&org, create()).unwrap();
    let hint = service.login_hint(&org, &view.id).unwrap();
    let base = "https://login.platform.example/dex/auth?client_id=broker&redirect_uri=https%3A%2F%2Faccounts.example%2Fcallback&state=one-state&code_challenge=one-proof&code_challenge_method=S256";
    let result = url::Url::parse(&hint.apply(base).unwrap()).unwrap();
    for (key, value) in [
        ("state", "one-state"),
        ("code_challenge", "one-proof"),
        ("prompt", "login"),
    ] {
        assert!(result.query_pairs().any(|(k, v)| k == key && v == value));
    }
    assert!(
        result
            .query_pairs()
            .any(|(key, value)| key == "connector_id" && value == view.id)
    );
    for invalid in [
        base.replace("login.platform.example", "foreign.example"),
        base.replace("/dex/auth", "/dex/token"),
        base.replace("state=one-state&", ""),
        base.replace("S256", "plain"),
        format!("{base}&connector_id=other"),
        format!("{base}&prompt=none"),
    ] {
        assert!(hint.apply(&invalid).is_err());
    }
}
