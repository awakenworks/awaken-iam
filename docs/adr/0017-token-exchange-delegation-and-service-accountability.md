# ADR-0017 - Token exchange, delegation and service-account accountability

- **Status:** Proposed
- **Implementation:** done
- **Date:** 2026-10-31
- **Related:** ADR-0008, ADR-0010

## Context

An enterprise web app (a public browser client using Authorization Code +
PKCE) and a stateless business command service use IAM. The browser needs
separate access tokens for Flow (reads) and for the business service
(commands), and the business service must call Flow on behalf of the signed-in
user so Flow can see both who asked and which service acted. Relying parties
verify IAM JWTs with `IamGate::verify_jwt`, which requires an exact `aud`.

Before this decision `/v1/oauth/token` admitted only `authorization_code` and
`refresh_token`. `AuthApi::exchange_token` was a library-only RFC 8693
federation path that mints Service tokens from foreign issuers' assertions.
`AccessTokenClaims` carried no actor. Public OAuth clients skipped the
HTTPS-or-loopback redirect check confidential clients had. Service-account API
tokens could be minted without an accountable human or an expiry, and could be
revoked only one by one.

## Decision

**I1 - Exchange between IAM access tokens.** `POST /v1/oauth/token` accepts
`grant_type=urn:ietf:params:oauth:grant-type:token-exchange` with
`subject_token_type=urn:ietf:params:oauth:token-type:access_token`. Each
registered client carries an administrator-owned `token_exchange` policy
(empty by default) that admits two uses, both issuing an ordinary IAM access
token with the same `typ`, signer and JWKS:

- *Audience exchange.* Any registered client may re-target a token IAM issued
  to it (`aud` = its client id) onto an audience in `token_exchange.audiences`.
  `sub` and `subject_kind` (Account) are unchanged, no actor is recorded, the
  scope is the requested subset (default: the subject scope narrowed to the
  client's registered scopes), and `exp` is at most one hour and never later
  than the subject token.
- *Delegation.* A confidential client with `token_exchange.delegation`
  authenticates with its secret and is the actor: the issued token keeps the
  user as `sub` and records `act = {sub: delegation.service_id, subject_kind:
  service}`, `aud` is one of `delegation.audiences`, scope is a subset as
  above, and `exp` is at most 300 seconds and never later than the subject.
  The subject token must be issued to that client itself or to one of
  `delegation.subject_audiences` (for example the browser client).

The actor is the authenticated confidential client, which RFC 8693 §1.1
permits. `actor_token` is refused: IAM has no service credential a command
service could hold other than its client secret (workload federation requires
an external issuer), and a second proof would duplicate client
authentication. Delegation is single-level: a subject token that already
carries `act` is refused, and a nested `act` fails decoding.

The target audience alone selects the use, so exchange and delegation audience
sets must be disjoint; delegation requires a confidential client; identifiers
must be non-empty and unpadded; a client cannot target its own id. The policy
is validated on registration and on `PUT
/v1/admin/oauth-clients/{id}/token-exchange`, is preserved across secret
rotation, and is stored in identity migration 6 (`NULL` = empty policy).

Refusals use RFC 6749/8693 codes: `invalid_client` (401) for unknown clients
or failed authentication; `invalid_request` for a missing subject token or
audience, foreign token types and any `actor_token`; `invalid_target` for an
audience outside the allowlists and for `resource`; `unauthorized_client` for a
client without a policy; `invalid_scope` for widened scope; `invalid_grant` for
a subject token that is malformed, foreign-issued, expired, revoked (IAM's own
`jti` denylist), a Service principal, already delegated, issued to an
unaccepted audience, or whose account is missing or disabled;
`temporarily_unavailable` (503) when storage fails. Every outcome appends
`AccessTokenExchanged` (client, subject, actor, audience, scope, issued `jti`,
subject `jti`) or `AccessTokenExchangeRejected` (client, reason) to the
existing `AuthApi` audit trail. Discovery advertises the grant.

Revoking a subject token does not revoke tokens already derived from it; their
lifetime is bounded by the subject expiry and, for delegation, 300 seconds.

**I2 - One redirect rule.** Public and confidential clients share the rule in
`OAuthClientAdminApi::register`: every redirect URI is HTTPS, or HTTP on
`127.0.0.1`, `[::1]` or `localhost`, with no fragment or embedded credentials.

**I3 - Actor claim.** The optional `act` claim travels beside, not inside,
`AccessTokenClaims`: `DelegatedAccessTokenClaims {claims, act}` flattens both
into one JWT payload, is minted with `AccessTokenAuthority::mint_delegated`
and read with `verify_delegated_access_token`. `AccessTokenClaims` keeps its
exact shape, so library callers that build it with struct literals (Awaken,
Flow test fixtures) compile unchanged. `act` is omitted when absent, so direct
tokens are byte-identical to before. The plain `verify_access_token` ignores
`act`; delegated tokens are only issued for audiences whose relying parties
verify through `IamGate` or `verify_delegated_access_token`.
`IamGate::authenticate_verified` and `IamGate::verify_jwt` return
`VerifiedBearer {principal, workspace, actor, access_token}`; existing
accessors keep their shapes. The host middleware inserts a `TokenActor`
extension and authorizes a delegated request as the actor with the user as the
conjunctive `on_behalf_of` link, so the effective permission is the
intersection of the user's and the service's.

**I4 - Service-account accountability.** The rule is enforced at the
administrative service-account mint path, not in the shared types:
`ApiTokenMinter::mint_service_account(directory, policy, request, owner)` and
`LocalHandle::mint_service_account_token` refuse a non-service principal or a
missing expiry (`ServiceAccountTokenError`) and record the accountable owner
beside the token (`ApiTokenDirectory::owner`; durably
`ApiTokenOwnerRepository`, identity migration 7's nullable `owner` column).
IAM serves no HTTP endpoint that mints API tokens, so this method is the
boundary every administrative surface must use. `MintApiToken`, `ApiToken`,
`ApiTokenView`, `IamError` and the generic `ApiTokenMinter::mint` are
unchanged, so existing library callers compile and behave exactly as before;
they are outside the accountability guarantee. All live tokens of one principal are revoked
together by `ApiTokenDirectory::revoke_principal`,
`AuthzApi::revoke_api_tokens_for_principal`,
`LocalHandle::revoke_service_account_tokens` and, durably,
`revoke_api_tokens_for_principal` over the repository; earlier revocation
stamps are kept. The embedded host's bootstrap admin token keeps using the
generic mint because no accountable account exists before the first
administrator.

**Token-endpoint client authentication.** Delegation relies on confidential
client authentication, so `/v1/oauth/token` accepts `client_secret_basic`
(RFC 6749 §2.3.1), `client_secret_post` and `none` for every grant, and
discovery advertises `token_endpoint_auth_methods_supported`. Presenting two
methods, or a body `client_id` that differs from the Basic one, is
`invalid_request`; a malformed or failed Basic authentication is
`invalid_client` with a `WWW-Authenticate: Basic` challenge. Malformed bodies
answer `invalid_request`, never a framework 422.

**Stable signing keys.** Relying parties cache the JWKS by `kid`, so a key
must never change under a kid. Generated keys take
`iam-ed25519-<first 128 bits of base64url SHA-256(public key)>`. The
standalone daemon persists its seed in the configured store (identity
migration 8); restarts and replicas load the oldest stored key and refuse to
start when its stored kid does not match the key. The stored seed has the
same protection requirements as the database credentials; managed
deployments inject a KMS signer instead.

## Migration

Migrations 6 and 7 only add nullable columns; migration 8 adds the signing
key table, populated on the daemon's next start. That start publishes a new
kid, so tokens signed by the previous, unpersisted key stop verifying once it
is gone, as they already did on every restart. Existing OAuth clients admit no
exchange until an administrator sets a policy. Existing service-account tokens
have no recorded owner and, when minted without expiry, never expire; they
stay valid until revoked. Operators should list each service account's tokens,
mint owned and expiring replacements, and revoke the account's legacy tokens
with the bulk revocation. Existing public clients whose redirect URIs are plain
HTTP on a network host keep working, but cannot be registered again until the
URI is HTTPS or loopback.

## Validation

HTTP tests through the real OP router cover each admitted use and every
refusal above, including scope widening, foreign audience, expired, revoked
and disabled subjects, a Service subject, a nested actor, `actor_token`,
missing or wrong client secrets, the 300-second and subject-expiry bounds and
the audit records. Admin HTTP tests cover the public-client redirect rule and
policy validation, persistence, replacement and rotation over SQLite. Host
tests cover actor exposure, conjunctive authorization requests and the
middleware extension. Core, host and SQL tests cover the service-account
mint path, the unchanged generic mint, owner persistence, legacy owner-less
rows and bulk revocation.
Token-endpoint tests cover every client-authentication row above and the
discovery document; SQLite restart tests cover key persistence, a stable kid
and refusal of a tampered kid.


## Current Account projection

OIDC UserInfo projects a current Account rather than treating a valid token
signature as an Account row. Bearer subjects must have the Account kind;
Service and Account identifiers remain distinct even when their strings match.
Cookie and bearer projections both read the original Account repository on
each request and refuse missing or disabled Accounts. Repository failure is
unavailable, with no fallback to a previously projected identity.

UserInfo remains a profile projection. Consumers must retain the separately
verified actor and consent when authorizing delegated operations; the projected
subject does not turn a delegated call into a direct human call.
