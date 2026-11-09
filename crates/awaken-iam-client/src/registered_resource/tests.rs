use super::*;
use awaken_iam_contract::*;
fn request() -> RegisteredResourceAuthorizationRequest {
    RegisteredResourceAuthorizationRequest {
        authorization: ResourceAuthorizationRequest {
            request: AuthorizationRequest::direct(
                PrincipalRef::Account {
                    account_id: AccountId("a".into()),
                },
                ActionKey("awaken.workspace::agent.use".into()),
                ScopeRef::Resource {
                    resource_type: ResourceType("awaken.agent".into()),
                    resource_id: ResourceId("issuer/workspace/agent".into()),
                },
            ),
            context: Default::default(),
        },
        namespace: NamespaceId("awaken.workspace".into()),
        product_id: ProductId::new("awaken").unwrap(),
        workspace_id: WorkspaceId("w".into()),
        resource_type: ResourceType("awaken.agent".into()),
    }
}
fn qualified() -> RegisteredResourceAuthorizationEvaluation {
    let request = request();
    RegisteredResourceAuthorizationEvaluation {
        evaluation: AuthorizationEvaluation {
            outcome: AuthorizationOutcome {
                decision: AuthorizationDecision::Allow,
                reason: "allowed_by_grant".into(),
                matched_grants: vec![],
                matched_roles: vec![],
                obligation: None,
            },
            freshness: Some(format!("iam-fence-v1:{}", "a".repeat(64))),
        },
        registration: Some(ResourceRegistrationQualification {
            namespace: request.namespace,
            profile_revision: 1,
            profile_checksum: format!("sha256:{}", "b".repeat(64)),
            action: request.authorization.request.action,
            product_id: request.product_id,
            workspace_id: request.workspace_id,
            resource_type: request.resource_type,
            resource_id: ResourceId("issuer/workspace/agent".into()),
            projection_id: "agent:original".into(),
            projection_epoch: 2,
        }),
    }
}
#[test]
fn strict_allow_needs_complete_matching_native_registration_and_freshness() {
    let original = qualified();
    assert!(validate(&request(), &original).is_ok());
    for change in 0..14 {
        let mut altered = original.clone();
        match change {
            0 => altered.registration = None,
            1 => altered.evaluation.freshness = None,
            2 => altered.evaluation.freshness = Some("cached-allow".into()),
            3 => altered.registration.as_mut().unwrap().namespace = NamespaceId("foreign".into()),
            4 => {
                altered.registration.as_mut().unwrap().product_id = ProductId::new("other").unwrap()
            }
            5 => altered.registration.as_mut().unwrap().workspace_id = WorkspaceId("other".into()),
            6 => {
                altered.registration.as_mut().unwrap().resource_type = ResourceType("other".into())
            }
            7 => altered.registration.as_mut().unwrap().resource_id = ResourceId("other".into()),
            8 => {
                altered.registration.as_mut().unwrap().action =
                    ActionKey("awaken.workspace::agent.edit".into())
            }
            9 => altered.registration.as_mut().unwrap().profile_revision = 0,
            10 => altered
                .registration
                .as_mut()
                .unwrap()
                .profile_checksum
                .clear(),
            11 => altered.registration.as_mut().unwrap().projection_id.clear(),
            12 => altered.evaluation.freshness = Some(format!("iam-fence-v1:{}", "A".repeat(64))),
            13 => {
                altered.registration.as_mut().unwrap().profile_checksum = "unknown-checksum".into()
            }
            _ => unreachable!(),
        }
        assert!(validate(&request(), &altered).is_err(), "case {change}");
    }
    let mut wrong_question = request();
    wrong_question.authorization.request.scope = ScopeRef::Global;
    assert!(validate(&wrong_question, &original).is_err());
}
struct Transport(RegisteredResourceAuthorizationEvaluation);
impl RegisteredResourceAuthzTransport for Transport {
    fn authorize_registered_resource(
        &self,
        _: &RegisteredResourceAuthorizationRequest,
    ) -> Result<RegisteredResourceAuthorizationEvaluation, RemoteError> {
        Ok(self.0.clone())
    }
}
#[test]
fn alternate_transport_cannot_return_an_unqualified_allow_and_denials_stay_denials() {
    let mut legacy = qualified();
    legacy.registration = None;
    assert!(
        RemoteIamClient::new(Transport(legacy.clone()))
            .authorize_registered_resource(&request())
            .is_err()
    );
    for decision in [
        AuthorizationDecision::Deny,
        AuthorizationDecision::RequireApproval,
    ] {
        legacy.evaluation.outcome.decision = decision;
        legacy.evaluation.freshness = None;
        let result = RemoteIamClient::new(Transport(legacy.clone()))
            .authorize_registered_resource(&request())
            .unwrap();
        assert_eq!(result.evaluation.outcome.decision, decision);
    }
}
#[test]
fn registered_wire_does_not_decode_an_old_allow_or_accept_unknown_fields() {
    let result = qualified();
    let mut body = serde_json::to_value(&result).unwrap();
    assert!(
        serde_json::from_value::<RegisteredResourceAuthorizationEvaluation>(
            serde_json::to_value(&result.evaluation.outcome).unwrap()
        )
        .is_err()
    );
    body["registration"]["caller_supplied_authority"] = true.into();
    assert!(serde_json::from_value::<RegisteredResourceAuthorizationEvaluation>(body).is_err());
    let mut question = serde_json::to_value(request()).unwrap();
    question["owner"] = "forged".into();
    assert!(serde_json::from_value::<RegisteredResourceAuthorizationRequest>(question).is_err());
}
