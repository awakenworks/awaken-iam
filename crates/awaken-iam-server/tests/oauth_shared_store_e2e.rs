//! Deployment-level downstream OAuth proof over the canonical SQL repositories.

use std::sync::{Arc, Barrier};

use awaken_iam_contract::{AccountId, Timestamp};
use awaken_iam_core::{
    AuthCodeRepo, EntropySource, OAuthAuthorizationRequest, OAuthAuthorizationServer,
    OAuthClientRepo, OAuthProviderError, RegisteredClient, TokenRedemption,
};
use awaken_iam_server::sqlite_in_memory_store;

#[derive(Clone)]
struct TestEntropy(u8);

impl EntropySource for TestEntropy {
    fn fill_bytes(&mut self, bytes: &mut [u8]) {
        bytes.fill(self.0);
        self.0 = self.0.wrapping_add(1);
    }
}

fn now() -> Timestamp {
    Timestamp("2026-08-13T00:00:00Z".into())
}

fn expires() -> Timestamp {
    Timestamp("2026-08-13T00:05:00Z".into())
}

fn request() -> OAuthAuthorizationRequest {
    OAuthAuthorizationRequest {
        client_id: "awaken-runtime".into(),
        redirect_uri: "https://awaken.example/v1/oauth/browser/callback".into(),
        scopes: vec!["openid".into(), "email".into()],
        code_challenge: None,
        code_challenge_method: None,
        nonce: None,
        state: Some("browser-state".into()),
    }
}

fn redemption(code: String) -> TokenRedemption {
    TokenRedemption {
        client_id: "awaken-runtime".into(),
        client_secret: Some("client-secret".into()),
        code,
        redirect_uri: "https://awaken.example/v1/oauth/browser/callback".into(),
        code_verifier: None,
    }
}

/// SQL multi-replica cause/effect decision table:
/// C1=A and B use separate authorization-server instances over one migrated
/// SqlStore, C2=A upserts the client, C3=A issues a live code. Effects:
/// E1=B sees the client immediately; E2=B redeems A's code; E3=replay fails.
/// R1(C1,C2,!C3)->E1; R2(C1,C2,C3)->E2; R3(after E2)->E3. This proves the
/// production repository path, not an in-process registry hydration shortcut.
#[test]
fn sql_store_shares_clients_and_codes_across_authorization_servers() {
    let store = Arc::new(sqlite_in_memory_store("iam").expect("migrate IAM store"));
    let clients: Arc<dyn OAuthClientRepo> = store.clone();
    let codes: Arc<dyn AuthCodeRepo> = store;
    let mut first =
        OAuthAuthorizationServer::with_repositories(clients.clone(), codes.clone(), TestEntropy(1));
    let mut second = OAuthAuthorizationServer::with_repositories(clients, codes, TestEntropy(2));
    first
        .register_client(RegisteredClient::confidential(
            "awaken-runtime",
            "client-secret",
            vec!["https://awaken.example/v1/oauth/browser/callback".into()],
            ["openid", "email"],
        ))
        .unwrap();
    assert!(
        second
            .authenticate_client("awaken-runtime", Some("client-secret"))
            .is_ok()
    );
    let issued = first
        .issue_code(AccountId("acct-1".into()), &request(), now(), expires())
        .unwrap();
    assert!(
        second
            .redeem_code(&redemption(issued.code.clone()), now())
            .is_ok()
    );
    assert_eq!(
        first.redeem_code(&redemption(issued.code), now()),
        Err(OAuthProviderError::InvalidGrant)
    );
}

/// SQL CAS decision table: C1=one live shared-store code and C2=two replicas
/// redeem it concurrently with valid bindings. R1(C1,C2) permits exactly one
/// grant and requires the other result to be InvalidGrant. This exercises the
/// conditional SQL update under actual thread interleaving.
#[test]
fn sql_store_concurrent_redeem_has_one_cas_winner() {
    let store = Arc::new(sqlite_in_memory_store("iam").expect("migrate IAM store"));
    let clients: Arc<dyn OAuthClientRepo> = store.clone();
    let codes: Arc<dyn AuthCodeRepo> = store;
    let mut issuer =
        OAuthAuthorizationServer::with_repositories(clients.clone(), codes.clone(), TestEntropy(3));
    issuer
        .register_client(RegisteredClient::confidential(
            "awaken-runtime",
            "client-secret",
            vec!["https://awaken.example/v1/oauth/browser/callback".into()],
            ["openid", "email"],
        ))
        .unwrap();
    let issued = issuer
        .issue_code(AccountId("acct-1".into()), &request(), now(), expires())
        .unwrap();
    let barrier = Arc::new(Barrier::new(2));
    let handles = [4, 5].map(|seed| {
        let clients = clients.clone();
        let codes = codes.clone();
        let barrier = barrier.clone();
        let redemption = redemption(issued.code.clone());
        std::thread::spawn(move || {
            let mut replica =
                OAuthAuthorizationServer::with_repositories(clients, codes, TestEntropy(seed));
            barrier.wait();
            replica.redeem_code(&redemption, now())
        })
    });
    let results = handles.map(|handle| handle.join().unwrap());
    assert_eq!(results.iter().filter(|result| result.is_ok()).count(), 1);
    assert_eq!(
        results
            .iter()
            .filter(|result| **result == Err(OAuthProviderError::InvalidGrant))
            .count(),
        1
    );
}
