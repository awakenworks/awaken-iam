//! Message proofs must fail at the actual generic Account credential owners.
use super::tests::fixture;
use super::*;
use awaken_iam_core::{ClientDelegation, ClientTokenExchangePolicy, RegisteredClient};

async fn message(
    api: &mut AuthApi,
    signer: &AccessTokenAuthority,
    mut claims: ChannelAssertionClaims,
) -> ChannelPrincipalGrant {
    claims.iat = crate::clock::unix_seconds() as i64;
    claims.exp = claims.iat + 120;
    let assertion = signer.sign_claims(&claims).await.unwrap();
    api.authenticate_channel(
        "flow-channel",
        Some("mock-client-secret"),
        &assertion,
        claims.iat,
    )
    .await
    .unwrap()
}

#[tokio::test]
async fn channel_message_proof_is_not_a_userinfo_account_bearer() {
    let (mut api, _, signer, claims) = fixture();
    let grant = message(&mut api, &signer, claims).await;
    assert!(
        api.userinfo_for_access_token(&grant.access_token).is_err(),
        "a message-only proof was accepted by actual Account UserInfo"
    );
}

#[tokio::test]
async fn channel_message_proof_is_not_a_general_exchange_subject() {
    let (mut api, _, signer, claims) = fixture();
    // Even an explicitly admitted consumer cannot turn a message proof into
    // an ordinary Account token. The rejection must be structural, not merely
    // an absent client exchange configuration or mismatched audience.
    api.register_oauth_client(
        RegisteredClient::confidential(
            "proof-consumer",
            "mock-proof-consumer-secret",
            vec!["https://consumer.example/cb".into()],
            [format!("channel.message:{}", claims.body_sha256)],
        )
        .with_token_exchange(ClientTokenExchangePolicy {
            audiences: Default::default(),
            delegation: Some(ClientDelegation {
                service_id: "proof-consumer-service".into(),
                audiences: ["product".into()].into(),
                subject_audiences: ["urn:awaken:iam:channel-principal".into()].into(),
            }),
        }),
    )
    .unwrap();
    let grant = message(&mut api, &signer, claims).await;
    let result = api
        .exchange_access_token(crate::AccessTokenExchange {
            client_id: "proof-consumer".into(),
            client_secret: Some("mock-proof-consumer-secret".into()),
            subject_token: grant.access_token,
            subject_token_type: crate::SUBJECT_TOKEN_TYPE_ACCESS_TOKEN.into(),
            actor_token: None,
            actor_token_type: None,
            requested_token_type: None,
            audience: Some("product".into()),
            resource: None,
            scope: None,
            issuer: "https://iam.example".into(),
            now: crate::clock::unix_seconds() as i64,
        })
        .await;
    assert!(
        result.is_err(),
        "a message-only proof was accepted by actual general Account exchange"
    );
}
