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
to Google/GitHub. Products never hold Google/GitHub secrets or talk to them
directly — they redirect to IAM and trust IAM-issued identity. One integration,
one place to rotate secrets, one audit point.

## Provider adapter (genericity)

A provider is data + a small adapter, so the set is config-driven. We ship
Google, GitHub, and a deterministic fake (tests) — and no more (YAGNI).

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

## Login flow

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
5.      IAM establishes a Session and returns to the product redirect_uri.
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
GET    /v1/auth/login/{provider}
GET    /v1/auth/callback/{provider}
GET    /v1/session                      # current session
DELETE /v1/session                      # logout
POST   /v1/tokens                       # mint API token
DELETE /v1/tokens/{id}
POST   /v1/oauth/token                  # authorization_code + refresh_token grants
POST   /v1/oauth/revoke                 # RFC 7009
GET    /v1/oauth/userinfo               # OIDC userinfo
GET    /.well-known/jwks.json           # RFC 7517
GET    /.well-known/openid-configuration
```

Authorization and entitlement endpoints live alongside under the same `/v1` tree;
see [remote protocol](remote-protocol.md).

## Caller authentication

Products call IAM as a service principal (`PrincipalRef::Service` / `ApiToken`)
identified by `audience`. The human subject travels inside the request/session;
the transport principal is the product service. IAM authorizes the subject, not
the carrier — the same separation the [remote protocol](remote-protocol.md) uses.

## What this plane does not do

- It does not store connector/third-party credentials or secrets for product
  tools — those stay product-side (ADR-0001 guardrail).
- It does not own product session *semantics* (what a workspace session means);
  it issues and validates the identity, products attach meaning.
