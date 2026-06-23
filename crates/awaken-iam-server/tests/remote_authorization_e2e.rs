//! End-to-end check of the remote authorization protocol.
//!
//! A product service in remote mode reaches IAM only through the
//! [`AuthzTransport`] seam and the wire DTOs. This test stands the server-side
//! [`AuthzApi`] up behind a transport that serialises every request and response
//! through JSON — exactly the bytes a real HTTP transport would carry — so the
//! contract shapes, the server assembly, and the client's fail-closed mapping
//! are exercised together against the current authorization core.

use awaken_iam_client::{AuthzTransport, IamClient, IamClientMode, RemoteError, RemoteIamClient};
use awaken_iam_contract::{
    AccountId, ActionKey, AuthorizationDecision, AuthorizationOutcome, AuthorizationRequest,
    BatchAuthorizationRequest, BatchAuthorizationResponse, EntitlementCheckResponse,
    EntitlementDecision, EntitlementRequest, PolicySnapshot, PrincipalRef, ScopeRef,
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
    api: AuthzApi,
    online: bool,
}

impl JsonLoopbackTransport {
    fn roundtrip<Req: serde::Serialize, Resp: serde::de::DeserializeOwned>(
        &self,
        request: &Req,
        handle: impl FnOnce(&AuthzApi, &str) -> String,
    ) -> Result<Resp, RemoteError> {
        if !self.online {
            return Err(RemoteError("offline".into()));
        }
        let body = serde_json::to_string(request).map_err(|err| RemoteError(err.to_string()))?;
        let response = handle(&self.api, &body);
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

    fn fetch_snapshot(&self) -> Result<PolicySnapshot, RemoteError> {
        if !self.online {
            return Err(RemoteError("offline".into()));
        }
        serde_json::from_str(&serde_json::to_string(&self.api.snapshot()).unwrap())
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
        IamClientMode::Remote(RemoteIamClient::new(JsonLoopbackTransport {
            api: publish_api(),
            online: true,
        }));
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
    let client = RemoteIamClient::new(JsonLoopbackTransport {
        api: publish_api(),
        online: true,
    });
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
    let client = RemoteIamClient::new(JsonLoopbackTransport {
        api: publish_api(),
        online: true,
    });
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
    let client = RemoteIamClient::new(JsonLoopbackTransport {
        api: publish_api(),
        online: false,
    });
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
    let client = RemoteIamClient::new(JsonLoopbackTransport {
        api: publish_api(),
        online: true,
    });
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
