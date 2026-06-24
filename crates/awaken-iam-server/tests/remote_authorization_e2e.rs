//! End-to-end check of the remote authorization protocol.
//!
//! A product service in remote mode reaches IAM only through the
//! [`AuthzTransport`] seam and the wire DTOs. This test stands the server-side
//! [`AuthzApi`] up behind a transport that serialises every request and response
//! through JSON — exactly the bytes a real HTTP transport would carry — so the
//! contract shapes, the server assembly, and the client's fail-closed mapping
//! are exercised together against the current authorization core.

use std::cell::RefCell;

use awaken_iam_client::{AuthzTransport, IamClient, IamClientMode, RemoteError, RemoteIamClient};
use awaken_iam_contract::{
    AccountId, ActionKey, AuthorizationDecision, AuthorizationOutcome, AuthorizationRequest,
    BatchAuthorizationRequest, BatchAuthorizationResponse, EntitlementCheckResponse,
    EntitlementDecision, EntitlementRequest, NamespaceId, NamespaceOwner, OrgId, PolicySnapshot,
    PrincipalRef, ResourceId, ResourceModelRegistered, ResourceModelRegistration,
    ResourceParentEdge, ResourceType, ResourceTypeRegistration, ScopeRef, SignerKey,
    SignerKeyAlgorithm, SignerKeyFingerprint, SignerKeyId, SignerKeyStatus, SignerSetSnapshot,
    Timestamp,
};
use awaken_iam_core::{
    ActionPattern, Effect, EntitlementCatalog, EntitlementEngine, Grant, GrantId, GrantSubject,
    IamCore, Plan, PlanId, PlanTier, PolicySet,
};
use awaken_iam_server::{AuthzApi, IamServer};

/// Transport that drives the in-process [`AuthzApi`] through JSON, modelling the
/// wire hop without a real socket. When `online` is false every call reports a
/// transport error so the fail-closed path can be exercised.
struct JsonLoopbackTransport {
    api: RefCell<AuthzApi>,
    online: bool,
}

impl JsonLoopbackTransport {
    fn online(api: AuthzApi) -> Self {
        Self {
            api: RefCell::new(api),
            online: true,
        }
    }

    fn offline(api: AuthzApi) -> Self {
        Self {
            api: RefCell::new(api),
            online: false,
        }
    }

    fn roundtrip<Req: serde::Serialize, Resp: serde::de::DeserializeOwned>(
        &self,
        request: &Req,
        handle: impl FnOnce(&AuthzApi, &str) -> String,
    ) -> Result<Resp, RemoteError> {
        if !self.online {
            return Err(RemoteError("offline".into()));
        }
        let body = serde_json::to_string(request).map_err(|err| RemoteError(err.to_string()))?;
        let response = handle(&self.api.borrow(), &body);
        serde_json::from_str(&response).map_err(|err| RemoteError(err.to_string()))
    }
}

impl AuthzTransport for JsonLoopbackTransport {
    fn authorize(
        &self,
        request: &AuthorizationRequest,
    ) -> Result<AuthorizationOutcome, RemoteError> {
        self.roundtrip(request, |api, body| {
            let parsed: AuthorizationRequest = serde_json::from_str(body).unwrap();
            serde_json::to_string(&api.authorize(&parsed)).unwrap()
        })
    }

    fn authorize_batch(
        &self,
        request: &BatchAuthorizationRequest,
    ) -> Result<BatchAuthorizationResponse, RemoteError> {
        self.roundtrip(request, |api, body| {
            let parsed: BatchAuthorizationRequest = serde_json::from_str(body).unwrap();
            serde_json::to_string(&api.authorize_batch(&parsed)).unwrap()
        })
    }

    fn check_entitlement(
        &self,
        request: &EntitlementRequest,
    ) -> Result<EntitlementCheckResponse, RemoteError> {
        self.roundtrip(request, |api, body| {
            let parsed: EntitlementRequest = serde_json::from_str(body).unwrap();
            serde_json::to_string(&api.check_entitlement(&parsed)).unwrap()
        })
    }

    fn register_resource_model(
        &self,
        registration: &ResourceModelRegistration,
    ) -> Result<ResourceModelRegistered, RemoteError> {
        if !self.online {
            return Err(RemoteError("offline".into()));
        }
        let body =
            serde_json::to_string(registration).map_err(|err| RemoteError(err.to_string()))?;
        let parsed: ResourceModelRegistration =
            serde_json::from_str(&body).map_err(|err| RemoteError(err.to_string()))?;
        let registered = self.api.borrow_mut().register_resource_model(&parsed);
        serde_json::from_str(&serde_json::to_string(&registered).unwrap())
            .map_err(|err| RemoteError(err.to_string()))
    }

    fn fetch_snapshot(&self) -> Result<PolicySnapshot, RemoteError> {
        if !self.online {
            return Err(RemoteError("offline".into()));
        }
        serde_json::from_str(&serde_json::to_string(&self.api.borrow().snapshot()).unwrap())
            .map_err(|err| RemoteError(err.to_string()))
    }

    fn fetch_signers(&self, namespace_id: &NamespaceId) -> Result<SignerSetSnapshot, RemoteError> {
        if !self.online {
            return Err(RemoteError("offline".into()));
        }
        serde_json::from_str(
            &serde_json::to_string(&self.api.borrow().signers(namespace_id)).unwrap(),
        )
        .map_err(|err| RemoteError(err.to_string()))
    }
}

fn service(id: &str) -> PrincipalRef {
    PrincipalRef::Service {
        service_id: id.into(),
    }
}

fn publish_api() -> AuthzApi {
    let mut catalog = EntitlementCatalog::new();
    catalog.upsert_plan(Plan::new(
        PlanId("pro".into()),
        PlanTier::Pro,
        ["pack.read"],
    ));
    catalog.assign(
        PrincipalRef::Account {
            account_id: AccountId("acct_1".into()),
        },
        PlanId("pro".into()),
    );

    let mut core = IamCore::new();
    core.policy_mut().add_grant(Grant {
        id: GrantId("g_publish".into()),
        subject: GrantSubject::Principal(service("publisher")),
        action_pattern: ActionPattern("pack.*".into()),
        scope: ScopeRef::Global,
        effect: Effect::Allow,
    });
    AuthzApi::from_parts(core, EntitlementEngine::local(catalog))
}

fn authorize_request(action: &str) -> AuthorizationRequest {
    AuthorizationRequest::direct(
        service("publisher"),
        ActionKey(action.into()),
        ScopeRef::Global,
    )
}

#[test]
fn remote_mode_resolves_authorization_over_the_wire() {
    // The product binds to one `IamClient` type; `remote` mode is selected by
    // configuration, with an in-process `IamServer` as the `local` alternative.
    let client: IamClientMode<IamServer, RemoteIamClient<JsonLoopbackTransport>> =
        IamClientMode::Remote(RemoteIamClient::new(JsonLoopbackTransport::online(
            publish_api(),
        )));
    assert!(client.is_remote());

    // A covered action is allowed; an uncovered one defaults to deny.
    assert_eq!(
        client.authorize(authorize_request("pack.publish")),
        AuthorizationDecision::Allow
    );
    assert_eq!(
        client.authorize(authorize_request("image.push")),
        AuthorizationDecision::Deny
    );
}

#[test]
fn remote_outcome_carries_the_decision_trace() {
    let client = RemoteIamClient::new(JsonLoopbackTransport::online(publish_api()));
    let outcome = client
        .authorize_outcome(&authorize_request("pack.publish"))
        .unwrap();
    assert_eq!(outcome.decision, AuthorizationDecision::Allow);
    assert_eq!(outcome.reason, "allowed_by_grant");
    assert_eq!(outcome.matched_grants, vec!["g_publish".to_owned()]);

    let batch = client
        .authorize_batch(&BatchAuthorizationRequest {
            requests: vec![
                authorize_request("pack.publish"),
                authorize_request("image.push"),
            ],
        })
        .unwrap();
    assert_eq!(batch.outcomes.len(), 2);
    assert_eq!(batch.outcomes[0].decision, AuthorizationDecision::Allow);
    assert_eq!(batch.outcomes[1].decision, AuthorizationDecision::Deny);
}

#[test]
fn remote_entitlement_check_reports_plan_reason() {
    let client = RemoteIamClient::new(JsonLoopbackTransport::online(publish_api()));
    let response = client
        .check_entitlement_response(&EntitlementRequest {
            principal: PrincipalRef::Account {
                account_id: AccountId("acct_1".into()),
            },
            entitlement: "pack.read".into(),
            resource: None,
        })
        .unwrap();
    assert_eq!(response.decision, EntitlementDecision::Allow);
    assert_eq!(response.reason, "plan_entitles");
}

#[test]
fn remote_mode_fails_closed_when_iam_is_unreachable() {
    let client = RemoteIamClient::new(JsonLoopbackTransport::offline(publish_api()));
    // An IAM that cannot answer denies; it never degrades to allow.
    assert_eq!(
        client.authorize(authorize_request("pack.publish")),
        AuthorizationDecision::Deny
    );
    assert_eq!(
        client.check_entitlement(EntitlementRequest {
            principal: PrincipalRef::Account {
                account_id: AccountId("acct_1".into()),
            },
            entitlement: "pack.read".into(),
            resource: None,
        }),
        EntitlementDecision::Deny
    );
}

#[test]
fn synced_snapshot_matches_remote_authorize() {
    let client = RemoteIamClient::new(JsonLoopbackTransport::online(publish_api()));
    let snapshot = client.fetch_snapshot().unwrap();
    let local = PolicySet::from_snapshot(&snapshot);

    for action in ["pack.publish", "pack.read", "image.push"] {
        let request = authorize_request(action);
        let local_outcome = local.evaluate(&request).to_outcome();
        let remote_outcome = client.authorize_outcome(&request).unwrap();
        // Local evaluation from the synced snapshot is byte-identical to remote.
        assert_eq!(local_outcome, remote_outcome);
    }
}

#[test]
fn remote_mode_fetches_signer_set_under_the_version_fence() {
    let namespace = NamespaceId("acme".into());
    let mut api = publish_api();
    api.trust_mut().set_namespace_owner(NamespaceOwner {
        namespace_id: namespace.clone(),
        owner_org_id: OrgId("org_acme".into()),
        created_at: Timestamp("2026-06-20T00:00:00Z".into()),
    });
    api.trust_mut()
        .register_signer_key(SignerKey {
            id: SignerKeyId("key_1".into()),
            namespace_id: namespace.clone(),
            fingerprint: SignerKeyFingerprint("fp_abc".into()),
            algorithm: SignerKeyAlgorithm::Ed25519,
            public_key: "base64-public-key".into(),
            status: SignerKeyStatus::Active,
            label: None,
            registered_at: Timestamp("2026-06-20T00:00:00Z".into()),
            revoked_at: None,
        })
        .unwrap();
    let fenced = api.signers(&namespace).version;

    let client = RemoteIamClient::new(JsonLoopbackTransport::online(api));
    let set = client.fetch_signers(&namespace).unwrap();
    // Pack Hub receives the active signer set over the wire under the shared
    // version fence, so it can cache and re-sync exactly as it does the snapshot.
    assert_eq!(set.namespace_id, namespace);
    assert_eq!(set.version, fenced);
    assert_eq!(set.signers.len(), 1);
    assert_eq!(
        set.signers[0].fingerprint,
        SignerKeyFingerprint("fp_abc".into())
    );
    assert!(set.signers[0].is_active());
}

#[test]
fn remote_mode_signer_fetch_fails_closed_when_iam_is_unreachable() {
    let client = RemoteIamClient::new(JsonLoopbackTransport::offline(publish_api()));
    // An unreachable IAM yields a transport error, never a stale signer set.
    assert!(client.fetch_signers(&NamespaceId("acme".into())).is_err());
}

#[test]
fn registering_a_resource_model_over_the_wire_resolves_open_scopes() {
    // A consumer teaches IAM, over the wire, that issue:42 nests under a project
    // it already holds a grant at. After registration the remote `authorize`
    // resolves the open resource scope up to that project, and the registered
    // edge rides the snapshot so a synced consumer answers identically.
    let mut core = IamCore::new();
    core.policy_mut().add_grant(Grant {
        id: GrantId("g_proj".into()),
        subject: GrantSubject::Principal(service("publisher")),
        action_pattern: ActionPattern("issue.*".into()),
        scope: ScopeRef::Project {
            workspace_id: awaken_iam_contract::WorkspaceId("ws_main".into()),
            project_id: awaken_iam_contract::ProjectId("proj_web".into()),
        },
        effect: Effect::Allow,
    });
    let client = RemoteIamClient::new(JsonLoopbackTransport::online(AuthzApi::from_parts(
        core,
        EntitlementEngine::default_allow(),
    )));

    let issue_scope = ScopeRef::Resource {
        resource_type: ResourceType("issue".into()),
        resource_id: ResourceId("42".into()),
    };
    let close_issue = AuthorizationRequest::direct(
        service("publisher"),
        ActionKey("issue.close".into()),
        issue_scope.clone(),
    );

    // Before registration the open scope has no ancestry, so it falls through to
    // default-deny — the fail-closed posture holds for unregistered resources.
    assert_eq!(
        client.authorize(close_issue.clone()),
        AuthorizationDecision::Deny
    );

    let registered = client
        .register_resource_model(&ResourceModelRegistration {
            resource_types: vec![ResourceTypeRegistration {
                resource_type: ResourceType("issue".into()),
                parent_type: None,
                actions: vec![ActionKey("issue.close".into())],
            }],
            actions: Vec::new(),
            edges: vec![ResourceParentEdge {
                resource_type: ResourceType("issue".into()),
                resource_id: ResourceId("42".into()),
                parent: ScopeRef::Project {
                    workspace_id: awaken_iam_contract::WorkspaceId("ws_main".into()),
                    project_id: awaken_iam_contract::ProjectId("proj_web".into()),
                },
            }],
        })
        .unwrap();
    assert!(registered.version >= 1);

    // The project grant now covers the issue resource through the registered edge.
    assert_eq!(client.authorize(close_issue), AuthorizationDecision::Allow);

    // A synced consumer rebuilds the same ancestry from the snapshot.
    let snapshot = client.fetch_snapshot().unwrap();
    assert_eq!(snapshot.version, registered.version);
    let local = PolicySet::from_snapshot(&snapshot);
    assert_eq!(
        local
            .evaluate(&AuthorizationRequest::direct(
                service("publisher"),
                ActionKey("issue.close".into()),
                issue_scope,
            ))
            .decision,
        AuthorizationDecision::Allow
    );
}
