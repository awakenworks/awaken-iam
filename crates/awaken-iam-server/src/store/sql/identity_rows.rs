//! Row decoding for identity and downstream OAuth records.
//!
//! Keeping these conversions together makes the storage boundary explicit and
//! leaves the repository implementations in the parent module focused on query
//! and transaction behavior.

use awaken_iam_contract::{
    Account, AccountId, ExternalIdentity, ExternalIdentityClaims, ExternalIdentityId,
    IdentityProviderKey, OAuthLoginState, OAuthLoginStateId, Session, SessionId, Timestamp,
};
use awaken_iam_core::{RegisteredClient, RepositoryResult, StoredAuthorizationCode};

use super::{SqlRow, json_decode, opt, req};

pub(super) fn decode_account(row: &SqlRow) -> RepositoryResult<Account> {
    Ok(Account {
        id: AccountId(req(row, 0, "account.id")?),
        status: json_decode(
            &format!("\"{}\"", req(row, 1, "account.status")?),
            "account status",
        )?,
        display_name: opt(row, 2),
        created_at: Timestamp(req(row, 3, "account.created_at")?),
        updated_at: Timestamp(req(row, 4, "account.updated_at")?),
    })
}

pub(super) fn decode_external(row: &SqlRow) -> RepositoryResult<ExternalIdentity> {
    let claims: ExternalIdentityClaims = json_decode(&req(row, 3, "identity.claims")?, "claims")?;
    Ok(ExternalIdentity {
        id: ExternalIdentityId(req(row, 0, "identity.id")?),
        account_id: AccountId(req(row, 1, "identity.account_id")?),
        provider_key: IdentityProviderKey(req(row, 2, "identity.provider_key")?),
        claims,
        first_seen_at: Timestamp(req(row, 4, "identity.first_seen_at")?),
        last_seen_at: Timestamp(req(row, 5, "identity.last_seen_at")?),
    })
}

pub(super) fn decode_session(row: &SqlRow) -> RepositoryResult<Session> {
    Ok(Session {
        id: SessionId(req(row, 0, "session.id")?),
        account_id: AccountId(req(row, 1, "session.account_id")?),
        token_hash: req(row, 2, "session.token_hash")?,
        external_identity_id: opt(row, 3).map(ExternalIdentityId),
        created_at: Timestamp(req(row, 4, "session.created_at")?),
        last_seen_at: Timestamp(req(row, 5, "session.last_seen_at")?),
        expires_at: Timestamp(req(row, 6, "session.expires_at")?),
        revoked_at: opt(row, 7).map(Timestamp),
    })
}

pub(super) fn decode_login_flow(row: &SqlRow) -> RepositoryResult<OAuthLoginState> {
    Ok(OAuthLoginState {
        id: OAuthLoginStateId(req(row, 0, "login_flow.id")?),
        provider_key: IdentityProviderKey(req(row, 1, "login_flow.provider_key")?),
        state_hash: req(row, 2, "login_flow.state_hash")?,
        nonce_hash: opt(row, 3),
        pkce_verifier_hash: opt(row, 4),
        return_to: opt(row, 5),
        created_at: Timestamp(req(row, 6, "login_flow.created_at")?),
        expires_at: Timestamp(req(row, 7, "login_flow.expires_at")?),
        consumed_at: opt(row, 8).map(Timestamp),
    })
}

pub(super) fn decode_oauth_client(row: &SqlRow) -> RepositoryResult<RegisteredClient> {
    Ok(RegisteredClient {
        client_id: req(row, 0, "oauth_client.client_id")?,
        redirect_uris: json_decode(
            &req(row, 1, "oauth_client.redirect_uris")?,
            "oauth redirect URIs",
        )?,
        allowed_scopes: json_decode(
            &req(row, 2, "oauth_client.allowed_scopes")?,
            "oauth allowed scopes",
        )?,
        secret_hash: opt(row, 3),
    })
}

pub(super) fn decode_auth_code(row: &SqlRow) -> RepositoryResult<StoredAuthorizationCode> {
    Ok(StoredAuthorizationCode {
        code_hash: req(row, 0, "oauth_code.code_hash")?,
        client_id: req(row, 1, "oauth_code.client_id")?,
        redirect_uri: req(row, 2, "oauth_code.redirect_uri")?,
        account_id: AccountId(req(row, 3, "oauth_code.account_id")?),
        scopes: json_decode(&req(row, 4, "oauth_code.scopes")?, "oauth code scopes")?,
        code_challenge: opt(row, 5),
        nonce: opt(row, 6),
        expires_at: Timestamp(req(row, 7, "oauth_code.expires_at")?),
        consumed_at: opt(row, 8).map(Timestamp),
    })
}
