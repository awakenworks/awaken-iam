# Identity and auth server

This document specifies the Identity & Federation plane: how `awaken-iam` logs
users in with Google and GitHub, brokers identity for every product, and manages
sessions and tokens. It realizes the model in
[domain model](domain-model.md#ubiquitous-language) and follows
[ADR-0002](../adr/0002-iam-consolidation.md) decision 4. The shape is
adapted from a proven reference federation-broker OAuth server.

## Posture: IAM is the broker

```text
product web app ──PKCE──▶ awaken-iam (OpenID Provider) ──OAuth──▶ Google / GitHub
       ▲                        │                                     │
       └──── IAM session ◀──────┴──────── normalized claims ◀─────────┘
```

IAM is an **OpenID Provider (OP)** to product clients and an **OAuth client (RP)**
to Google/GitHub. Products never hold Google/GitHub secrets, never talk to them
directly, and never choose the upstream provider on the user's behalf — they
redirect to IAM's single OP authorization endpoint and trust IAM-issued identity.
One integration, one place to rotate secrets, one audit point.

The production issuer for AwakenWorks-hosted identity is
`https://accounts.awakenworks.com`. Product consoles and commercial account
management live under `https://cloud.awakenworks.com`, but the OIDC issuer stays
stable at the accounts host so relying-party configuration and token validation
do not move when the console evolves.

Those domains are production defaults, not hard-coded constants. A deployment may
configure its issuer, public client ids, redirect-uri allowlist, scopes, session
cookie policy, provider registry, and JWKS/key rotation policy. The discovery
document is generated from that deployment configuration, so product clients read
`authorization_endpoint`, `token_endpoint`, `userinfo_endpoint`, and `jwks_uri`
from `/.well-known/openid-configuration` instead of constructing URLs.

## Provider adapter (genericity)

A provider is data + a small adapter, so the set is config-driven. We ship two
vendor adapters (Google OIDC, GitHub OAuth2), a deterministic fake (tests), and a
**generic config-driven adapter** (`GenericOAuthProvider`) that speaks the
standard authorization-code + userinfo flow for *any* compliant OIDC/OAuth2
provider. Onboarding a new upstream IdP — Microsoft Entra, Okta, Auth0, a
self-hosted Keycloak — is then configuration (its endpoints, client id, and a
deployment secret), not a new adapter. The two vendor adapters remain only where
a provider deviates from the standard (GitHub has no id_token; Google pins issuer
and JWKS).

```rust
trait IdentityProvider {
    fn authorization_url(&self, cfg, req) -> Result<Redirect, ProviderError>;
    fn exchange_code(&self, cfg, code) -> Result<TokenResponse, ProviderError>;
    fn fetch_claims(&self, cfg, token) -> Result<ExternalIdentityClaims, ProviderError>;
}
```

Config loads from environment, never hardcoded (`GOOGLE_CLIENT_ID`,
`GITHUB_CLIENT_ID`, …); see [provider setup](provider-setup.md) for the operator
runbook (upstream app registration, callback URLs, env vars, local vs prod).
Each adapter normalizes the upstream profile into the
single `ExternalIdentityClaims` shape; the rest of IAM never sees a
provider-specific field. Adding a provider later is: enum variant + config +
`From<UpstreamProfile> for ExternalIdentityClaims`. The core login flow is
untouched. This adapter is the [ACL](domain-model.md#context-map) over upstream
IdPs.

> Google is OIDC (id_token + `email_verified`); GitHub is OAuth2 (no id_token —
> claims come from the user/emails API, and email may be private). The adapter
> hides that difference; account identity is `(provider, subject)` regardless.

## Product login flow

Product clients integrate only with the OP surface advertised by
`/.well-known/openid-configuration`:

```text
1. GET  /.well-known/openid-configuration
        discovers authorization_endpoint, token_endpoint, userinfo_endpoint,
        and jwks_uri for the issuer, e.g. https://accounts.awakenworks.com.
2. GET  /v1/oauth/authorize?client_id&redirect_uri&response_type=code
        &scope=openid email profile&state&code_challenge
        starts the unified login. IAM may show an account chooser, provider
        picker, enterprise SSO routing, or an already-authenticated session.
3.      IAM completes whichever upstream provider flow the user chose.
4.      IAM redirects back to the product's registered redirect_uri with a code.
5. POST /v1/oauth/token
        the product redeems the code with PKCE, then calls /v1/oauth/userinfo.
```

The product never calls a provider-specific login URL as its normal entrypoint.
That keeps GitHub, Google, enterprise SSO, account chooser, and future factors
inside IAM's bounded context.

Native desktop products use the same discovery and authorization endpoint
through `awaken-iam-client`'s loopback PKCE adapter. When the browser has no IAM
session, the authorization endpoint renders IAM's configured provider choices;
the chosen provider login receives the original, server-reconstructed authorize
request as its safe relative `return_to`. The provider callback establishes the
canonical IAM session and resumes that same authorization request. Products do
not build provider pickers, retain upstream credentials, or call a
provider-specific login route directly.

The client adapter stores the short-lived access token and rotating refresh
token through the existing `CredentialCache` port. The current filesystem
adapter is owner-only (`0600`), writes atomically, and redacts token material;
it is the compatibility implementation until an operating-system keychain
adapter is introduced behind that port. Expired access credentials are
refreshed through the same adapter before startup or before an authenticated
product request. The adapter exposes a non-interactive cache/refresh operation
for request paths: a live credential is returned, a matching rotating grant is
refreshed, and missing or incompatible state reports that interaction is
required. Product UI coordination may then start the existing interactive
operation and display its authorization URL; it does not implement OAuth or
persist a second login state. Invalid refresh credentials return to that same
interactive authorization flow.

Hosted browser products may proxy `/v1/oauth/*` to this same OP and use
`/v1/oauth/browser/start` plus `/v1/oauth/browser/callback`. These two pages are
the canonical browser PKCE adapter: the start page creates state/verifier values
under the product origin, authorization uses the configured IAM issuer and its
SSO cookie, and the callback validates state before same-origin code redemption.
It stores only the short-lived access token under
`awaken.product.session-bearer`; products do not copy this protocol or receive
an upstream provider credential.

| Registered product coordinate | Return path | Browser state | Result |
|---|---|---|---|
| exact HTTPS redirect | same-origin absolute path | matching | redeem once and enter product |
| unknown redirect/client | any | any | OP rejects; no token |
| exact | external or scheme-relative | any | bootstrap rejects |
| exact | exact | absent/mismatched | callback rejects before redemption |

## Local product bootstrap

Local consoles reuse the same session bounded context without introducing an
OAuth provider or exposing an automation credential to browser JavaScript:

```text
1. CLI starts the local host and prints a five-minute, one-time setup token.
2. Browser POSTs that token to /v1/auth/local/exchange on the same origin.
3. IAM consumes the hashed challenge and establishes its canonical Session.
4. Browser receives an HttpOnly, SameSite=Strict local session cookie.
5. Product middleware resolves that cookie to an Account principal and evaluates
   the same product action and scope policy used for bearer credentials.
6. DELETE /v1/session revokes the session and clears the cookie.
7. Persistent local compositions reopen the same `SessionRepo` after restart,
   so an unexpired, unrevoked cookie continues without another setup exchange.
```

The setup token is a bootstrap handoff, not a reusable API credential. It is
never persisted by the browser. API tokens remain the credential for CLI and
automation clients. The canonical `SessionRepo` stores only the opaque
cookie's hash plus session metadata; authentication refresh and logout update
that same row. Setup challenges remain in memory and are never a recovery
credential.

Hosted and standalone server compositions use the identical session port with a
different adapter: every replica receives the same Postgres-backed
`SqlStore<PostgresBackend>` as its `SessionRepo`. A cookie established by one
replica is therefore resolvable by another replica and survives process
replacement. PostgreSQL unavailability fails session creation, resolution, and
logout closed; the server never falls back to an in-memory session directory.
SQLite remains the single-process local adapter and is not an HA server store.

The downstream authorization server follows the same one-store rule. Its
`OAuthClientRepo` is the authoritative registered-client directory and its
`AuthCodeRepo` holds only hashed, short-lived authorization-code records. A
durable composition injects the same `SqlStore` behind both ports; it never
hydrates a process-local client snapshot or keeps issued codes in a replica.
Code redemption first validates the stored client, redirect URI, expiry, and
PKCE binding, then performs one conditional consume (`unconsumed && live`) in
the repository. That compare-and-set is the replay boundary: two replicas may
race to redeem one valid code, but exactly one succeeds. Validation failure does
not consume the code, while repository failure rejects issuance or redemption
as temporarily unavailable rather than falling back to memory.

```text
authorize on replica A -> OAuthClientRepo.get -> AuthCodeRepo.create(hash only)
token on replica B     -> OAuthClientRepo.get -> AuthCodeRepo.get
                                            -> validate all bindings
                                            -> consume_if_live (atomic CAS)
                                            -> mint tokens
```

Upstream provider correlation follows the same one-store rule. `LoginFlowRepo`
stores only state, nonce, and PKCE hashes plus expiry/consumption metadata. The
start response sets two short-lived, hardened cookies: an opaque login-row id
and an HttpOnly proof containing the one-time nonce/PKCE verifier. On callback,
any replica loads and atomically consumes the shared row, then verifies the
browser proof against its hashes before exchanging the provider code. The proof
is cleared with the login-id cookie. There is no process-local pending map and
load-balancer affinity is not a correctness requirement.

```text
start on replica A    -> LoginFlowRepo.start(hashes) -> browser id+proof cookies
callback on replica B -> LoginFlowRepo.get/consume -> verify proof -> provider exchange
```

## Provider login subflow

Provider-specific routes are IAM-internal browser routes used after the unified
authorization endpoint has selected a provider, or operator/debug deep links.
They are not the discovery `authorization_endpoint` for product clients.

```text
1. GET  /v1/auth/login/{provider}?client_id&redirect_uri&code_challenge
        IAM creates a single-use LoginFlow (state, nonce, PKCE verifier hashes),
        redirects to the provider authorization URL.
2.      user authenticates at Google/GitHub.
3. GET  /v1/auth/callback/{provider}?code&state
        IAM consumes the LoginFlow (once, unexpired), exchanges code, fetches and
        normalizes claims.
4.      LoginService resolves (provider, subject) by the linking policy below,
        mutating the directory at most once:
          a. existing link        -> select its Account, refresh mutable claims
          b. existing link, but a *different* session is live
                                  -> fail closed (duplicate-subject protection)
          c. unknown subject, session live
                                  -> link the subject to the session's Account
          d. unknown subject, no session, verified email already on an Account
                                  -> EmailMatchPending; re-resolve with explicit
                                     confirmation to link, else nothing changes
          e. otherwise            -> create Account + ExternalIdentity
5.      IAM establishes a Session and returns to the unified authorization flow,
        which then issues the product authorization code.
```

Identity is keyed by `(provider, subject)` only; email is never an identity key.
A later login with a changed email selects the same account by its subject and
never forks one. A verified email **never silently selects an account** — path
(d) surfaces the candidate and links it only after explicit user confirmation;
an unverified email never reaches an existing account. Current-session linking
(c) lets a signed-in user attach a second provider to their account, while
duplicate-subject protection (b) refuses to re-point an already-owned subject at
a different account. The single-use challenge and the unexpired/unrevoked session
are the two login invariants the core already enforces.

Hosted deployments persist Account and ExternalIdentity through the same shared
IAM repository used by every replica. First-account creation and its initial
identity link are one atomic command; a concurrent first login either commits
both rows or observes the winning `(provider, subject)` link. Repository failure
fails closed and never falls back to a process-local directory. Product services
and physical Cells retain only the resulting AccountId as a principal reference;
they never create or copy a user record.

**Unlink.** Detaching an external identity requires that the link exist and
belong to the account being unlinked, and it may not remove an account's *last*
sign-in method — unlinking the last identity would orphan the account, so it
fails closed. Both ownership and last-identity checks are enforced by the core.

## Sessions and tokens

Two token families, mirroring the reference design:

| Token | Form | Lifetime | Purpose |
|---|---|---|---|
| Session cookie | opaque, hashed at rest | session | browser → product/IAM |
| Access token | JWT, asymmetric (RS256/EdDSA), `kid` in header | short (≈1h) | bearer for service APIs |
| Refresh token | opaque, stored, **rotated** | long | renew access token |
| API token | opaque, hashed, principal-scoped | until revoked | service / automation principals |
| Capability token | JWT, asymmetric, scope-narrowed, epoch-fenced | short, bounded | sub-process / sandbox delegation |

Rules adopted from the reference's hard-won lessons:

- **Refresh-token rotation with reuse detection.** Each refresh issues a new
  token and retires the old; replay of a retired token revokes the whole chain
  (theft signal).
- **Revocation is real.** Logout invalidates immediately; `jti` enables
  access-token revocation; revocations are audited.
- **JWKS, not shared secrets.** Verifiers fetch public keys from
  `/.well-known/jwks.json`; signing keys live in a KMS/secret store with `kid`
  versioning and rotation — never in plain env.
- **No information leak.** Auth errors are uniform (a wrong provider subject and
  an unknown account look the same); 401 vs 403 vs 422 are used consistently.
- **Capabilities attenuate, never widen.** A capability token is signed by the
  same key as an access token but carries a distinct `typ`, a lease `epoch`, and
  a scope set. A holder derives a child only by *narrowing* — subset scope,
  inherited audience and epoch, no later expiry — so a parent hands a sandbox
  strictly less authority for a bounded time. Verification checks signature,
  audience, and epoch, so advancing the lease epoch invalidates every outstanding
  token at once. This realizes permission mechanism 7.

## Canonical API paths

One canonical tree, learned from the reference's normalization ADR — never two
paths for one job:

```http
GET    /v1/oauth/authorize              # unified OP authorization endpoint
GET    /v1/auth/login/{provider}
GET    /v1/auth/callback/{provider}
POST   /v1/auth/local/exchange           # one-time local CLI-to-browser bootstrap
GET    /v1/session                      # current session
DELETE /v1/session                      # logout
POST   /v1/tokens                       # mint API token
DELETE /v1/tokens/{id}
POST   /v1/oauth/token                  # authorization_code, refresh_token, token-exchange grants
POST   /v1/oauth/revoke                 # RFC 7009
GET    /v1/oauth/userinfo               # OIDC userinfo
GET    /.well-known/jwks.json           # RFC 7517
GET    /.well-known/openid-configuration
```

Authorization and entitlement endpoints live alongside under the same `/v1` tree;
see [remote protocol](remote-protocol.md).

Implementation note: `/.well-known/openid-configuration` must advertise
`/v1/oauth/authorize` as `authorization_endpoint`. Advertising
`/v1/auth/login/{provider}` or an unparameterized provider-login route is a
contract bug because a relying party does not know which upstream provider a user
will choose.

## Federated workload identity (token exchange)

An external workload — a CI job, a cloud function, another cloud's STS — already
holds an assertion from its own issuer. Rather than provision and rotate a
long-lived IAM secret for it, IAM accepts that assertion and exchanges it for a
short-lived IAM access token, following **RFC 8693**. IAM is the broker here too:
a workload federates through one trust anchor instead of every product minting
its own machine credentials.

The exchange is a single `POST /v1/oauth/token` with
`grant_type=urn:ietf:params:oauth:grant-type:token-exchange`, carrying the
upstream assertion as `subject_token`:

```text
1. The workload presents subject_token (an upstream JWT) and subject_token_type.
2. IAM reads the assertion's *untrusted* `iss` only to select which trusted
   external issuer's published keys to verify against, then verifies the
   signature against them.
3. IAM validates the value claims: issuer match, accepted audience, and the
   expiry / not-before window.
4. IAM resolves the verified `(issuer, subject)` to a configured workload
   binding — the service principal and scopes it may assume. A valid assertion is
   necessary but never sufficient: with no binding the exchange fails closed.
5. IAM mints its own access token for that service principal, signed by the same
   key it publishes at `/.well-known/jwks.json`, so the issued token verifies
   identically to every other IAM access token. No long-lived secret is stored on
   either side.
```

A **trusted external issuer** is data: its `iss`, the accepted `aud` values, the
public keys IAM verifies its assertions against (the issuer's own JWKS), and the
subject→principal bindings it authorizes. Adding a federation later is a registry
entry, not a code change. Every exchange — issued or rejected — is audited, and a
rejection collapses to a coarse RFC 8693 OAuth error code so the wire response
never distinguishes an unknown issuer from a bad signature from a missing
binding, matching the **no information leak** rule above.

> **MVP shortcut.** Upstream assertions are verified as `EdDSA`/`Ed25519` JWTs,
> the single algorithm IAM signs and publishes with elsewhere, and subject
> mapping is by exact match. The registry, binding, request, and response shapes
> are kept extensible so a later ADR can add RS256 upstream verification or
> subject-pattern matching without a wire break.

## Caller authentication

Products call IAM as a service principal (`PrincipalRef::Service` / `ApiToken`)
identified by `audience`. The human subject travels inside the request/session;
the transport principal is the product service. IAM authorizes the subject, not
the carrier — the same separation the [remote protocol](remote-protocol.md) uses.

IAM access-token claims preserve that distinction explicitly. `sub` is the
opaque principal identifier and `subject_kind` is its category. Account is the
omitted backward-compatible default; workload exchange and other service-token
issuers set `subject_kind: service`. A verifier reconstructs the exact
`PrincipalRef` and never guesses from an identifier prefix.

## What this plane does not do

- It does not store connector/third-party credentials or secrets for product
  tools — those stay product-side (ADR-0001 guardrail).
- It does not own product session *semantics* (what a workspace session means);
  it issues and validates the identity, products attach meaning.
