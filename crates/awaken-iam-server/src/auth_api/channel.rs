//! The channel grant authenticates one exact message; it issues no refreshable
//! bearer or ambient Account credential. Redelivery can recover the same proof
//! coordinates while every grant rereads the native identity and Group owners.
use super::*;
use awaken_iam_contract::{ChannelAssertionClaims, ChannelPrincipalGrant, OrgId};
use awaken_iam_core::{GroupId, GroupRepository};
use std::collections::BTreeMap;

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ChannelVerifier {
    pub issuer: String,
    pub client_id: String,
    pub installation_id: String,
    pub connector_id: String,
    pub provider_key: IdentityProviderKey,
    pub audience: String,
    pub org_id: OrgId,
    /// An explicit native IAM Group defining members admitted by this install.
    pub membership_group: String,
    /// Only these native Group ids may enter routing facts.
    pub routing_groups: Vec<String>,
    pub keys: Jwks,
    pub enabled: bool,
}
#[derive(Default)]
pub(super) struct ChannelAuthentication {
    verifiers: BTreeMap<(String, String, String, String), ChannelVerifier>,
    groups: Option<Arc<dyn GroupRepository>>,
}
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum ChannelAuthenticationError {
    #[error("channel assertion rejected")]
    Rejected,
    #[error("channel authentication dependency unavailable")]
    Unavailable,
}
impl<E: EntropySource + Clone> AuthApi<E> {
    pub fn with_channel_groups(mut self, groups: Arc<dyn GroupRepository>) -> Self {
        self.channel_authentication.groups = Some(groups);
        self
    }
    pub fn register_channel_verifier(
        &mut self,
        verifier: ChannelVerifier,
    ) -> Result<(), ChannelAuthenticationError> {
        if [
            &verifier.issuer,
            &verifier.client_id,
            &verifier.installation_id,
            &verifier.connector_id,
            &verifier.provider_key.0,
            &verifier.audience,
            &verifier.org_id.0,
            &verifier.membership_group,
        ]
        .iter()
        .any(|s| s.trim().is_empty())
            || verifier.routing_groups.len() > 64
        {
            return Err(ChannelAuthenticationError::Rejected);
        }
        let key = (
            verifier.issuer.clone(),
            verifier.client_id.clone(),
            verifier.installation_id.clone(),
            verifier.connector_id.clone(),
        );
        if self.channel_authentication.verifiers.contains_key(&key) {
            return Err(ChannelAuthenticationError::Rejected);
        }
        self.channel_authentication.verifiers.insert(key, verifier);
        Ok(())
    }
    pub async fn authenticate_channel(
        &mut self,
        client_id: &str,
        client_secret: Option<&str>,
        assertion: &str,
        now: i64,
    ) -> Result<ChannelPrincipalGrant, ChannelAuthenticationError> {
        let result = self
            .admit_channel(client_id, client_secret, assertion, now)
            .await;
        self.audit.push(AuthAuditEvent::ChannelAuthentication {
            accepted: result.is_ok(),
            at: crate::clock::timestamp(u64::try_from(now).unwrap_or(0)),
        });
        result
    }
    async fn admit_channel(
        &self,
        client_id: &str,
        client_secret: Option<&str>,
        assertion: &str,
        now: i64,
    ) -> Result<ChannelPrincipalGrant, ChannelAuthenticationError> {
        use ChannelAuthenticationError::{Rejected, Unavailable};
        if assertion.len() > 16384 || now < 0 {
            return Err(Rejected);
        }
        let client = self
            .oauth_provider
            .authenticate_client(client_id, client_secret)
            .map_err(|e| match e {
                OAuthProviderError::StorageUnavailable => Unavailable,
                _ => Rejected,
            })?;
        if client.secret_hash.is_none() {
            return Err(Rejected);
        }
        let hint: ChannelAssertionClaims =
            crate::decode_unverified_claims(assertion).map_err(|_| Rejected)?;
        let verifier = self
            .channel_authentication
            .verifiers
            .get(&(
                hint.iss.clone(),
                client_id.to_owned(),
                hint.installation_id.clone(),
                hint.connector_id.clone(),
            ))
            .filter(|v| v.enabled)
            .ok_or(Rejected)?;
        let claims: ChannelAssertionClaims =
            crate::verify_signed_claims(assertion, &verifier.keys).map_err(|_| Rejected)?;
        if claims.iss != verifier.issuer
            || client_id != verifier.client_id
            || claims.aud != verifier.audience
            || claims.installation_id != verifier.installation_id
            || claims.connector_id != verifier.connector_id
            || claims.iat < 0
            || claims.iat > now
            || claims.exp <= now
            || claims
                .exp
                .checked_sub(claims.iat)
                .is_none_or(|ttl| !(1..=120).contains(&ttl))
            || [&claims.sub, &claims.jti, &claims.message_id]
                .iter()
                .any(|s| s.trim().is_empty())
            || claims.body_sha256.len() != 64
            || !claims.body_sha256.bytes().all(|b| b.is_ascii_hexdigit())
        {
            return Err(Rejected);
        }
        let identity = self
            .external_identities
            .get_by_key(&awaken_iam_contract::ExternalIdentityKey {
                provider_key: verifier.provider_key.clone(),
                subject: ExternalSubject(claims.sub),
            })
            .map_err(|_| Unavailable)?
            .ok_or(Rejected)?;
        let account = self
            .accounts
            .get(&identity.account_id)
            .map_err(|_| Unavailable)?
            .filter(|a| a.status == AccountStatus::Active)
            .ok_or(Rejected)?;
        let principal = PrincipalRef::Account {
            account_id: account.id,
        };
        let groups = self
            .channel_authentication
            .groups
            .as_ref()
            .ok_or(Unavailable)?;
        let member = groups
            .get(&GroupId(verifier.membership_group.clone()))
            .map_err(|_| Unavailable)?
            .ok_or(Rejected)?;
        if member.org != verifier.org_id || !member.contains(&principal) {
            return Err(Rejected);
        }
        let mut group_refs = Vec::new();
        for id in &verifier.routing_groups {
            let group = groups
                .get(&GroupId(id.clone()))
                .map_err(|_| Unavailable)?
                .ok_or(Unavailable)?;
            if group.org != verifier.org_id {
                return Err(Rejected);
            }
            if group.contains(&principal) {
                group_refs.push(id.clone());
            }
        }
        group_refs.sort();
        group_refs.dedup();
        // A namespaced, message-bound proof reference. Never log the assertion.
        use sha2::{Digest, Sha256};
        let evidence_id = format!("channel:{:x}", Sha256::digest(assertion.as_bytes()));
        if self.access_revocations.is_revoked(&evidence_id) {
            return Err(Rejected);
        }
        let scope = format!("channel.message:{}", claims.body_sha256);
        let access_token = self
            .tokens
            .mint(&AccessTokenClaims {
                iss: self.iam_issuer.clone(),
                sub: identity.account_id.0,
                subject_kind: crate::AccessTokenSubjectKind::Account,
                aud: "urn:awaken:iam:channel-principal".into(),
                exp: claims.exp,
                iat: claims.iat,
                jti: evidence_id.clone(),
                scope: vec![scope.clone()],
            })
            .await
            .map_err(|_| Unavailable)?;
        Ok(ChannelPrincipalGrant {
            access_token,
            token_type: "Bearer".into(),
            expires_in: claims.exp - now,
            scope,
            principal,
            evidence_id,
            installation_id: claims.installation_id,
            connector_id: claims.connector_id,
            message_id: claims.message_id,
            body_sha256: claims.body_sha256,
            expires_at: claims.exp,
            group_refs,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{InMemoryStore, LocalSeedSigner};
    use awaken_iam_contract::{ChannelAssertionClaims, ExternalIdentityClaims};
    use awaken_iam_core::{
        AccountRepository, ExternalIdentityRepository, Group, GroupRepository, RegisteredClient,
    };
    fn fixture() -> (
        AuthApi,
        InMemoryStore,
        AccessTokenAuthority,
        ChannelAssertionClaims,
    ) {
        let store = InMemoryStore::new();
        let timestamp = Timestamp("2026-11-05T00:00:00Z".into());
        AccountRepository::upsert(
            &store,
            Account {
                id: AccountId("alice".into()),
                status: AccountStatus::Active,
                display_name: None,
                created_at: timestamp.clone(),
                updated_at: timestamp.clone(),
            },
        )
        .unwrap();
        ExternalIdentityRepository::link(
            &store,
            ExternalIdentity {
                id: ExternalIdentityId("external-alice".into()),
                account_id: AccountId("alice".into()),
                provider_key: IdentityProviderKey("feishu:tenant:app".into()),
                claims: ExternalIdentityClaims {
                    subject: ExternalSubject("ou_alice".into()),
                    email: None,
                    email_verified: None,
                    display_name: None,
                    username: None,
                    avatar_url: None,
                    locale: None,
                },
                first_seen_at: timestamp.clone(),
                last_seen_at: timestamp.clone(),
            },
        )
        .unwrap();
        GroupRepository::upsert(
            &store,
            Group {
                id: GroupId("members".into()),
                org: OrgId("org".into()),
                display_name: None,
                members: vec![PrincipalRef::Account {
                    account_id: AccountId("alice".into()),
                }],
                created_at: timestamp.clone(),
                updated_at: timestamp,
            },
        )
        .unwrap();
        let signer = AccessTokenAuthority::new(LocalSeedSigner::new("mock-verifier", [17; 32]));
        let mut api = AuthApi::new()
            .with_issuer("https://iam.example")
            .with_identity_repositories(
                Arc::new(store.clone()),
                Arc::new(store.clone()),
                Arc::new(store.clone()),
            )
            .with_channel_groups(Arc::new(store.clone()));
        api.register_oauth_client(RegisteredClient::confidential(
            "flow-channel",
            "mock-client-secret",
            vec!["https://flow.example/cb".into()],
            ["openid"],
        ))
        .unwrap();
        api.register_channel_verifier(ChannelVerifier {
            issuer: "https://flow.example/channel".into(),
            client_id: "flow-channel".into(),
            installation_id: "tenant:app".into(),
            connector_id: "connector-1".into(),
            provider_key: IdentityProviderKey("feishu:tenant:app".into()),
            audience: "iam:channel".into(),
            org_id: OrgId("org".into()),
            membership_group: "members".into(),
            routing_groups: vec!["members".into()],
            keys: signer.jwks(),
            enabled: true,
        })
        .unwrap();
        let claims = ChannelAssertionClaims {
            iss: "https://flow.example/channel".into(),
            aud: "iam:channel".into(),
            sub: "ou_alice".into(),
            jti: "message-proof-1".into(),
            iat: 1000,
            exp: 1120,
            installation_id: "tenant:app".into(),
            connector_id: "connector-1".into(),
            message_id: "message-1".into(),
            body_sha256: "ab".repeat(32),
        };
        (api, store, signer, claims)
    }
    #[tokio::test]
    async fn registered_channel_proof_is_message_bound_idempotent_and_current() {
        let (mut api, store, signer, claims) = fixture();
        let assertion = signer.sign_claims(&claims).await.unwrap();
        let original = api
            .authenticate_channel("flow-channel", Some("mock-client-secret"), &assertion, 1000)
            .await
            .unwrap();
        assert_eq!(
            original.principal,
            PrincipalRef::Account {
                account_id: AccountId("alice".into())
            }
        );
        assert_eq!(original.group_refs, vec!["members"]);
        let replay = api
            .authenticate_channel("flow-channel", Some("mock-client-secret"), &assertion, 1001)
            .await
            .unwrap();
        assert_eq!(replay.evidence_id, original.evidence_id);
        assert_eq!(replay.access_token, original.access_token);
        assert_eq!(replay.expires_at, original.expires_at);
        assert_eq!(replay.expires_in, 119);
        let token: AccessTokenClaims =
            crate::verify_signed_claims(&replay.access_token, &api.jwks()).unwrap();
        assert_eq!(token.aud, "urn:awaken:iam:channel-principal");
        assert_eq!(
            token.scope,
            vec![format!("channel.message:{}", claims.body_sha256)]
        );
        let mut group = GroupRepository::get(&store, &GroupId("members".into()))
            .unwrap()
            .unwrap();
        group.members.clear();
        GroupRepository::upsert(&store, group).unwrap();
        assert_eq!(
            api.authenticate_channel("flow-channel", Some("mock-client-secret"), &assertion, 1002)
                .await
                .unwrap_err(),
            ChannelAuthenticationError::Rejected
        );
    }
    #[tokio::test]
    async fn one_verifier_can_authenticate_three_exact_installations_without_overwriting() {
        let (mut api, store, signer, claims) = fixture();
        let existing = api
            .channel_authentication
            .verifiers
            .values()
            .next()
            .unwrap()
            .clone();
        assert_eq!(
            api.register_channel_verifier(existing.clone()),
            Err(ChannelAuthenticationError::Rejected)
        );
        let original = ExternalIdentityRepository::get_by_key(
            &store,
            &awaken_iam_contract::ExternalIdentityKey {
                provider_key: existing.provider_key.clone(),
                subject: ExternalSubject(claims.sub.clone()),
            },
        )
        .unwrap()
        .unwrap();
        for platform in ["dingtalk", "wecom"] {
            let mut installation = existing.clone();
            installation.installation_id = format!("{platform}:tenant:bot");
            installation.connector_id = format!("connector-{platform}");
            installation.provider_key = IdentityProviderKey(format!("{platform}:tenant:bot"));
            let mut identity = original.clone();
            identity.id = ExternalIdentityId(format!("external-{platform}"));
            identity.provider_key = installation.provider_key.clone();
            if platform == "dingtalk" {
                let bob = AccountId("bob".into());
                AccountRepository::upsert(
                    &store,
                    Account {
                        id: bob.clone(),
                        status: AccountStatus::Active,
                        display_name: None,
                        created_at: original.first_seen_at.clone(),
                        updated_at: original.last_seen_at.clone(),
                    },
                )
                .unwrap();
                identity.account_id = bob.clone();
                let mut members = GroupRepository::get(&store, &GroupId("members".into()))
                    .unwrap()
                    .unwrap();
                members
                    .members
                    .push(PrincipalRef::Account { account_id: bob });
                GroupRepository::upsert(&store, members).unwrap();
            }
            // Deliberately identical provider subject: the namespace is the
            // trusted installation's native provider key, never bare user id.
            ExternalIdentityRepository::link(&store, identity).unwrap();
            api.register_channel_verifier(installation).unwrap();
        }
        for platform in ["feishu", "dingtalk", "wecom"] {
            let mut proof = claims.clone();
            if platform != "feishu" {
                proof.installation_id = format!("{platform}:tenant:bot");
                proof.connector_id = format!("connector-{platform}");
            }
            let signed = signer.sign_claims(&proof).await.unwrap();
            let grant = api
                .authenticate_channel("flow-channel", Some("mock-client-secret"), &signed, 1000)
                .await
                .unwrap();
            assert_eq!(
                grant.principal,
                PrincipalRef::Account {
                    account_id: AccountId(
                        if platform == "dingtalk" {
                            "bob"
                        } else {
                            "alice"
                        }
                        .into()
                    )
                }
            );
            assert_eq!(grant.installation_id, proof.installation_id);
            assert_eq!(grant.connector_id, proof.connector_id);
            proof.connector_id = "foreign-connector".into();
            let mismatch = signer.sign_claims(&proof).await.unwrap();
            assert_eq!(
                api.authenticate_channel(
                    "flow-channel",
                    Some("mock-client-secret"),
                    &mismatch,
                    1000
                )
                .await
                .unwrap_err(),
                ChannelAuthenticationError::Rejected
            );
        }
    }
    #[tokio::test]
    async fn channel_proof_matrix_refuses_signature_scope_time_unknown_identity_and_client() {
        let (mut api, _, signer, claims) = fixture();
        for cause in [
            "issuer",
            "audience",
            "installation",
            "connector",
            "unknown_sender",
            "future",
            "expired",
            "long_lived",
            "empty_message",
            "bad_digest",
        ] {
            let mut bad = claims.clone();
            match cause {
                "issuer" => bad.iss = "other".into(),
                "audience" => bad.aud = "other".into(),
                "installation" => bad.installation_id = "other".into(),
                "connector" => bad.connector_id = "other".into(),
                "unknown_sender" => bad.sub = "unbound".into(),
                "future" => bad.iat = 1001,
                "expired" => bad.exp = 1000,
                "long_lived" => bad.exp = 1121,
                "empty_message" => bad.message_id.clear(),
                "bad_digest" => bad.body_sha256 = "xyz".into(),
                _ => unreachable!(),
            }
            let assertion = signer.sign_claims(&bad).await.unwrap();
            assert_eq!(
                api.authenticate_channel(
                    "flow-channel",
                    Some("mock-client-secret"),
                    &assertion,
                    1000
                )
                .await
                .unwrap_err(),
                ChannelAuthenticationError::Rejected,
                "{cause}"
            );
        }
        let rogue = AccessTokenAuthority::new(LocalSeedSigner::new("mock-verifier", [18; 32]));
        let forged = rogue.sign_claims(&claims).await.unwrap();
        assert!(
            api.authenticate_channel("flow-channel", Some("mock-client-secret"), &forged, 1000)
                .await
                .is_err()
        );
        let signed = signer.sign_claims(&claims).await.unwrap();
        for secret in [None, Some("wrong")] {
            assert!(
                api.authenticate_channel("flow-channel", secret, &signed, 1000)
                    .await
                    .is_err()
            );
        }
        assert!(
            api.authenticate_channel("other", Some("mock-client-secret"), &signed, 1000)
                .await
                .is_err()
        );
    }
    #[tokio::test]
    async fn disabled_account_and_cross_org_routing_groups_never_authenticate() {
        let (mut api, store, signer, claims) = fixture();
        let signed = signer.sign_claims(&claims).await.unwrap();
        let mut account = AccountRepository::get(&store, &AccountId("alice".into()))
            .unwrap()
            .unwrap();
        account.status = AccountStatus::Disabled;
        AccountRepository::upsert(&store, account).unwrap();
        assert!(
            api.authenticate_channel("flow-channel", Some("mock-client-secret"), &signed, 1000)
                .await
                .is_err()
        );
        let mut account = AccountRepository::get(&store, &AccountId("alice".into()))
            .unwrap()
            .unwrap();
        account.status = AccountStatus::Active;
        AccountRepository::upsert(&store, account).unwrap();
        let mut group = GroupRepository::get(&store, &GroupId("members".into()))
            .unwrap()
            .unwrap();
        group.org = OrgId("foreign".into());
        GroupRepository::upsert(&store, group).unwrap();
        assert!(
            api.authenticate_channel("flow-channel", Some("mock-client-secret"), &signed, 1000)
                .await
                .is_err()
        );
    }
    #[tokio::test]
    async fn channel_group_outage_never_reuses_a_previous_authenticated_snapshot() {
        let (mut api, store, signer, claims) = fixture();
        let assertion = signer.sign_claims(&claims).await.unwrap();
        api.authenticate_channel("flow-channel", Some("mock-client-secret"), &assertion, 1000)
            .await
            .unwrap();
        api.channel_authentication.groups = None;
        assert_eq!(
            api.authenticate_channel("flow-channel", Some("mock-client-secret"), &assertion, 1001)
                .await
                .unwrap_err(),
            ChannelAuthenticationError::Unavailable
        );
        api.channel_authentication.groups = Some(Arc::new(store.clone()));
        let mut group = GroupRepository::get(&store, &GroupId("members".into()))
            .unwrap()
            .unwrap();
        group.members.clear();
        GroupRepository::upsert(&store, group).unwrap();
        assert_eq!(
            api.authenticate_channel("flow-channel", Some("mock-client-secret"), &assertion, 1002)
                .await
                .unwrap_err(),
            ChannelAuthenticationError::Rejected
        );
    }
    #[tokio::test]
    async fn channel_http_grant_requires_client_and_message_proof_and_never_returns_refresh() {
        use axum::{
            body::{Body, to_bytes},
            http::Request,
        };
        use tower::ServiceExt as _;
        let (api, _, signer, mut claims) = fixture();
        claims.iat = crate::clock::unix_seconds() as i64;
        claims.exp = claims.iat + 120;
        let assertion = signer.sign_claims(&claims).await.unwrap();
        let app = crate::op_http::op_router(
            Arc::new(tokio::sync::Mutex::new(api)),
            "https://iam.example",
            crate::op_http::ProviderLoginRouteOwner::Iam,
        );
        let base = url::form_urlencoded::Serializer::new(String::new())
            .append_pair(
                "grant_type",
                awaken_iam_contract::CHANNEL_ASSERTION_GRANT_TYPE,
            )
            .append_pair("client_id", "flow-channel")
            .append_pair("client_secret", "mock-client-secret")
            .append_pair("assertion", &assertion)
            .finish();
        for suffix in [
            "&audience=flow",
            "&scope=admin",
            "&refresh_token=untrusted",
            "&actor_token=untrusted",
            "&subject_token=untrusted",
            "&requested_token_type=anything",
        ] {
            let response = app
                .clone()
                .oneshot(
                    Request::post("/v1/oauth/token")
                        .header("content-type", "application/x-www-form-urlencoded")
                        .body(Body::from(format!("{base}{suffix}")))
                        .unwrap(),
                )
                .await
                .unwrap();
            assert_eq!(response.status(), 400, "{suffix}");
            let value: serde_json::Value =
                serde_json::from_slice(&to_bytes(response.into_body(), 65536).await.unwrap())
                    .unwrap();
            assert_eq!(value["error"], "invalid_request");
        }
        let response = app
            .oneshot(
                Request::post("/v1/oauth/token")
                    .header("content-type", "application/x-www-form-urlencoded")
                    .body(Body::from(base))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), 200);
        let grant: serde_json::Value =
            serde_json::from_slice(&to_bytes(response.into_body(), 65536).await.unwrap()).unwrap();
        assert!(grant.get("refresh_token").is_none());
        assert_eq!(grant["message_id"], "message-1");
        assert_eq!(
            grant["principal"],
            serde_json::to_value(PrincipalRef::Account {
                account_id: AccountId("alice".into())
            })
            .unwrap()
        );
    }
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    #[ignore = "requires FLOW_CHANNEL_ADAPTER_TEST_BINARY from the qualified Flow worktree"]
    async fn channel_native_owner_composes_with_flow_http_adapter_and_revocation() {
        let binary = std::env::var("FLOW_CHANNEL_ADAPTER_TEST_BINARY")
            .expect("separately built Flow adapter test executable");
        let (api, store, _, _) = fixture();
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let endpoint = format!("http://{}/v1/oauth/token", listener.local_addr().unwrap());
        let app = crate::op_http::op_router(
            Arc::new(tokio::sync::Mutex::new(api)),
            "https://iam.example",
            crate::op_http::ProviderLoginRouteOwner::Iam,
        );
        let server = tokio::spawn(async move {
            axum::serve(listener, app).await.unwrap();
        });
        for revoked in [false, true] {
            if revoked {
                let mut account = AccountRepository::get(&store, &AccountId("alice".into()))
                    .unwrap()
                    .unwrap();
                account.status = AccountStatus::Disabled;
                AccountRepository::upsert(&store, account).unwrap();
            }
            let (binary, endpoint) = (binary.clone(), endpoint.clone());
            let output=tokio::task::spawn_blocking(move || {
                let mut command=std::process::Command::new(binary);
                command.args(["--ignored","--exact","channel::tests::channel_native_iam_http_grant_resolves_current_account_without_fallback","--nocapture"])
                    .env("FLOW_CHANNEL_TEST_TOKEN_ENDPOINT",endpoint).env("NO_PROXY","127.0.0.1,localhost,::1")
                    .env_remove("HTTP_PROXY").env_remove("HTTPS_PROXY").env_remove("ALL_PROXY");
                if revoked {command.env("FLOW_CHANNEL_TEST_EXPECT_REJECT","1");} else {command.env_remove("FLOW_CHANNEL_TEST_EXPECT_REJECT");}
                command.output().unwrap()
            }).await.unwrap();
            assert!(
                output.status.success(),
                "Flow native adapter cohort failed: {}",
                String::from_utf8_lossy(&output.stdout)
            );
        }
        server.abort();
    }
}
