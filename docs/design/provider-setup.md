# Third-party login provider setup

This guide is the operator runbook for the upstream identity providers
`awaken-iam` brokers: the per-vendor **Google** (OpenID Connect) and **GitHub**
(OAuth 2.0) adapters, plus the **generic OIDC / OAuth 2.0 adapter** that onboards
any compliant provider — Microsoft Entra, Okta, Auth0, Keycloak — by
configuration alone. It covers registering the upstream OAuth application, the
exact callback URLs IAM expects, the environment variables each adapter reads,
and how local and production deployments differ. It complements the
architectural model in the [auth server](auth-server.md) design; read that first
for *why* IAM is the broker, then this for *how* to wire a real provider.

IAM is the OAuth client (relying party) to Google/GitHub and the OpenID Provider
to product apps. Products never register their own Google/GitHub apps — there is
exactly one upstream app per provider, owned by the IAM deployment, so secrets
rotate in one place ([auth server](auth-server.md#posture-iam-is-the-broker)).

## Provider keys and callback URLs

Each provider is addressed by a stable **provider key** that appears in the login
and callback routes:

| Provider | Key | Family | Login route | Callback route |
|---|---|---|---|---|
| Google | `google` | OIDC | `GET /v1/auth/login/google` | `GET /v1/auth/callback/google` |
| GitHub | `github` | OAuth 2.0 | `GET /v1/auth/login/github` | `GET /v1/auth/callback/github` |
| Generic | `<key>` | OIDC / OAuth 2.0 | `GET /v1/auth/login/<key>` | `GET /v1/auth/callback/<key>` |

The generic adapter's provider key is chosen by the operator at configuration
time (for example `entra`, `okta`, `keycloak`); it slots into the same login and
callback routes as the per-vendor keys.

The **callback URL** (also called the redirect URI / authorized redirect) you
register with the upstream provider is the IAM origin plus the callback route:

```text
https://<iam-host>/v1/auth/callback/google
https://<iam-host>/v1/auth/callback/github
```

The registered value must match the `*_REDIRECT_URI` IAM sends on the wire
**byte for byte** (scheme, host, port, path, no trailing slash) — a mismatch is
the single most common cause of `redirect_uri_mismatch` at the upstream
provider. Register one callback per environment (local, staging, production); do
not reuse a production app's callback for local development.

## Google (OpenID Connect)

Google is an OIDC provider: the callback returns an `id_token` IAM verifies
against Google's published JWKS, and `email_verified` is authoritative.

### Register the OAuth app

1. Open the [Google Cloud Console](https://console.cloud.google.com/) and select
   (or create) a project for the deployment.
2. Configure the **OAuth consent screen** (External for public sign-in, or
   Internal for a Workspace-only deployment). Add the `openid`, `email`, and
   `profile` scopes — the defaults IAM's Google adapter requests.
3. Under **APIs & Services → Credentials**, create an **OAuth client ID** of type
   **Web application**.
4. Add the callback URL above to **Authorized redirect URIs**. Add one entry per
   environment you run from this app.
5. Copy the generated **Client ID** and **Client secret** into the deployment
   secret store (see [secret references](#secret-references)).

### Endpoints

The adapter ships Google's canonical endpoints as defaults, so a standard
deployment configures only the client id, secret, and redirect URI:

| Purpose | Value |
|---|---|
| Issuer | `https://accounts.google.com` |
| Authorization | `https://accounts.google.com/o/oauth2/v2/auth` |
| Token | `https://oauth2.googleapis.com/token` |
| JWKS | `https://www.googleapis.com/oauth2/v3/certs` |

### Environment variables

| Variable | Required | Meaning |
|---|---|---|
| `GOOGLE_CLIENT_ID` | yes | Public OAuth client id. |
| `GOOGLE_CLIENT_SECRET` | yes | OAuth client secret (deployment secret). |
| `GOOGLE_REDIRECT_URI` | yes | Absolute callback URL registered above. |
| `GOOGLE_SCOPES` | no | Space-separated scopes; defaults to `openid email profile`. |

## GitHub (OAuth 2.0)

GitHub speaks plain OAuth 2.0: there is no `id_token`, so IAM reads the
authenticated user from the REST API (`GET /user`, `GET /user/emails`). Email may
be private, so IAM requests `user:email` and prefers the verified primary
address. Account identity is the immutable numeric user **id**, not the mutable
`login`.

### Register the OAuth app

1. Open **GitHub → Settings → Developer settings → OAuth Apps → New OAuth App**
   (a personal app, or an organization-owned app under the org's settings).
2. Set **Homepage URL** to the IAM origin.
3. Set **Authorization callback URL** to the GitHub callback above. A classic
   OAuth app allows a single callback, so register a separate app per
   environment.
4. Create the app, then generate a **client secret**.
5. Copy the **Client ID** and **Client secret** into the deployment secret store.

Classic GitHub OAuth apps do not support PKCE and GitHub issues no `id_token`, so
IAM mints neither a PKCE verifier nor an OIDC nonce for this provider.

### Endpoints

| Purpose | Value |
|---|---|
| Authorization | `https://github.com/login/oauth/authorize` |
| Token | `https://github.com/login/oauth/access_token` |
| User API | `https://api.github.com/user`, `https://api.github.com/user/emails` |

### Environment variables

| Variable | Required | Meaning |
|---|---|---|
| `GITHUB_CLIENT_ID` | yes | Public OAuth client id. |
| `GITHUB_CLIENT_SECRET` | yes | OAuth client secret (deployment secret). |
| `GITHUB_REDIRECT_URI` | yes | Absolute callback URL registered above. |
| `GITHUB_SCOPES` | no | Space-separated scopes; defaults to `read:user user:email`. |

## Generic OIDC / OAuth 2.0 provider (configuration-only)

Beyond the two hand-written vendor adapters, IAM ships a **generic adapter** that
speaks the standard authorization-code flow from configuration alone. Any
compliant OpenID Connect or OAuth 2.0 server — Microsoft Entra ID, Okta, Auth0, a
self-hosted Keycloak, an internal IdP — is onboarded by **registering its
endpoints and client credentials, not by writing code**. This is the escape
hatch that keeps "add another IdP" a config change.

### OIDC discovery: issuer URL is enough

For a compliant **OpenID Connect** provider the adapter performs
[discovery](https://openid.net/specs/openid-connect-discovery-1_0.html): given
only the `issuer_url`, it fetches

```text
<issuer_url>/.well-known/openid-configuration
```

and reads the `authorization_endpoint`, `token_endpoint`, and
`userinfo_endpoint` from that document. So a discovery-capable provider needs
**only its issuer URL, client id, and client secret** — no endpoint wiring at
all. Endpoints you *do* configure explicitly always win over discovery, so a
provider with a non-standard layout (or a plain OAuth 2.0 server with no
discovery document) can pin each endpoint by hand and skip the well-known fetch
entirely.

The trailing slash on the issuer is normalized, so both
`https://idp.example` and `https://idp.example/` resolve the same document.

### Register the upstream app

1. In the provider's admin console, register a new **web / confidential OAuth
   client** (the exact name varies: "App registration" on Entra, "Application"
   on Okta/Auth0, "Client" on Keycloak).
2. Add the callback URL — the IAM origin plus the provider's callback route — to
   the client's **redirect URIs**, byte-for-byte as IAM sends it:

   ```text
   https://<iam-host>/v1/auth/callback/<key>
   ```

3. Grant the standard OIDC scopes `openid`, `email`, `profile` (the adapter's
   defaults) so userinfo returns a subject, email, and profile claims.
4. Copy the **issuer URL**, **client id**, and **client secret** into the
   deployment configuration and secret store.

### Configuration

The public fields live in the provider's `IdentityProviderConfig`; the client
secret and userinfo endpoint are deployment material kept out of the contract:

| Field | Required | Source | Meaning |
|---|---|---|---|
| `provider_key` | yes | config | Operator-chosen key in the login/callback routes. |
| `kind` | yes | config | `oidc` (enables discovery) or `oauth2`. |
| `issuer_url` | yes for OIDC | config | Base URL whose `/.well-known/openid-configuration` supplies the endpoints. |
| `authorization_endpoint` | only if not discoverable | config | Overrides the discovered value. |
| `token_endpoint` | only if not discoverable | config | Overrides the discovered value. |
| `client_id` | yes | config | Public OAuth client id. |
| Client secret | yes | secret store | OAuth client secret used at the token endpoint. |
| Userinfo endpoint | only if not discoverable | secret/config | Overrides the discovered value. |
| Scopes | no | config | Defaults to `openid email profile`. |

For a discovery-capable OIDC provider the required set collapses to
`provider_key`, `kind = oidc`, `issuer_url`, `client_id`, and the client secret —
everything else is resolved at login time from the well-known document.

A plain **OAuth 2.0** provider (no `id_token`, often no discovery document)
configures `kind = oauth2` and pins `authorization_endpoint`, `token_endpoint`,
and the userinfo endpoint explicitly; the adapter then reads the authenticated
subject from userinfo exactly as the OIDC path does.

### Endpoints (worked example: Keycloak)

For an issuer of `https://idp.example/realms/acme`, discovery resolves to:

| Purpose | Value |
|---|---|
| Discovery | `https://idp.example/realms/acme/.well-known/openid-configuration` |
| Authorization | `https://idp.example/realms/acme/protocol/openid-connect/auth` |
| Token | `https://idp.example/realms/acme/protocol/openid-connect/token` |
| Userinfo | `https://idp.example/realms/acme/protocol/openid-connect/userinfo` |

Only the issuer is configured; the other three rows are read from the discovery
document at login time.

## Secret references

Client secrets are **deployment secrets** and never belong in tracked files
(guardrail [G5](../../AGENTS.md#architecture-guardrails)) or in the shared
`IdentityProviderConfig` DTO — that contract carries only the public client id.
Adapters read configuration from the environment, never from hardcoded values
([auth server](auth-server.md#provider-adapter-genericity)).

- **Local development** — copy [`.env.example`](../../.env.example) to a
  git-ignored `.env` and fill in real values. `.env` is ignored by
  [`.gitignore`](../../.gitignore); only `.env.example` (placeholders only) is
  tracked.
- **Production** — inject the variables from the platform secret manager
  (Kubernetes `Secret`, cloud secret store, CI/CD secret) into the process
  environment. Do not bake secrets into images or config maps. Rotate by
  updating the secret store and restarting; because IAM is the only holder, no
  product app changes.

Signing keys for IAM-issued tokens are separate and live in a KMS / secret store
with `kid` rotation, never in plain env
([auth server](auth-server.md#sessions-and-tokens)).

## Local vs production configuration

| Concern | Local | Production |
|---|---|---|
| IAM origin | `http://localhost:8080` | `https://<iam-host>` (TLS required) |
| Google redirect | `http://localhost:8080/v1/auth/callback/google` | `https://<iam-host>/v1/auth/callback/google` |
| GitHub redirect | `http://localhost:8080/v1/auth/callback/github` | `https://<iam-host>/v1/auth/callback/github` |
| Upstream app | dev/test OAuth app | dedicated production OAuth app |
| Secret source | git-ignored `.env` | platform secret manager |
| Cookie `Secure` | off over plain `http` | on (HTTPS only) |

Google permits `http://localhost` redirect URIs for development; production must
be `https`. GitHub likewise accepts a `localhost` callback for a dev app. Always
use a **distinct upstream app per environment** so revoking or rotating a dev
secret never touches production.

For login flows that need no upstream provider at all — local smoke tests, CI —
use the deterministic [fake provider](auth-server.md#provider-adapter-genericity)
keyed `fake`, which requires no secrets.

## Real provider smoke tests

CI exercises the fake provider by default and never depends on a live Google or
GitHub app. Smoke tests against a *real* provider are **opt-in** and gated on two
conditions, so they stay dormant unless an operator deliberately enables them:

1. the provider's opt-in flag is set to a truthy value, and
2. that provider's client id, client secret, and redirect URI are all present in
   the environment (the same variables documented above).

| Provider | Opt-in flag | Required configuration |
|---|---|---|
| Google | `IAM_E2E_REAL_GOOGLE` | `GOOGLE_CLIENT_ID`, `GOOGLE_CLIENT_SECRET`, `GOOGLE_REDIRECT_URI` |
| GitHub | `IAM_E2E_REAL_GITHUB` | `GITHUB_CLIENT_ID`, `GITHUB_CLIENT_SECRET`, `GITHUB_REDIRECT_URI` |

A truthy flag is any non-empty value other than `0`, `false`, `no`, or `off`
(case-insensitive). With the flag unset — the CI default — the smoke test reports
why it skipped and passes without touching provider configuration. When enabled,
it builds the real provider adapter from the environment and asserts the
authorization redirect targets the upstream endpoint and round-trips the
configured client id, redirect URI, and scopes — catching the misconfigured
client id or `redirect_uri_mismatch` that breaks a real login, without standing
up a browser or reaching a live endpoint.

Opt in for a single run by exporting the flag alongside an already-configured
[`.env`](../../.env.example) (never commit the flag or secrets), for example
`IAM_E2E_REAL_GOOGLE=1 cargo test -p awaken-iam-core --test provider_smoke`.
