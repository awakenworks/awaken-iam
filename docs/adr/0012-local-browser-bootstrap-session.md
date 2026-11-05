# ADR-0012 - Reuse IAM sessions for local browser bootstrap

- **Status:** Proposed
- **Implementation:** done
- **Date:** 2026-07-28
- **Related:** ADR-0002, ADR-0010

## Context

Local product consoles need a safe first-use path without requiring a cloud
identity provider. Products previously exposed long-lived management bearer
tokens to browser JavaScript or could implement their own local login/session
track. Both choices duplicate IAM responsibility: bearer tokens are intended for
automation, while IAM already owns opaque browser sessions, revocation, and
principal resolution.

## Decision

`awaken-iam-server::SessionGateway` remains the only browser-session authority.
IAM adds a short-lived, single-use local setup challenge that stores only a hash
and exchanges into that existing session authority. The CLI displays the
cleartext setup token once; `POST /v1/auth/local/exchange` consumes it and sets
an HttpOnly, `SameSite=Strict` cookie. `GET /v1/session` and
`DELETE /v1/session` remain the canonical current-session and logout paths.

The local HTTP cookie has a non-`__Host-` name because loopback development does
not use TLS; hosted deployments retain the secure `__Host-` cookie default.
The exchange rejects a browser `Origin` that does not match `Host`. Products
attach the shared session gateway to `IamGate`, so cookie identities and bearer
identities enter the same authorization policy and route-action mapping.

API tokens remain the canonical credential for CLI and automation. No browser
stores a management token in local storage, and products do not add a second
session table, cookie parser, or setup-token implementation.

## Consequences

- Awaken and awaken-flow share one local authentication lifecycle and error
  contract while retaining product-owned roles and actions.
- A copied setup token is useful only during its five-minute window and only
  once; logout revokes the server-side session.
- A process restart invalidates outstanding setup challenges and sessions in
  the initial in-memory implementation. Persistent session storage is a
  separate durability concern and must replace the directory behind
  `SessionGateway`, not create another authentication path.
- Products must mount the IAM router before their protected routes and use the
  returned, session-enabled `IamGate`.

## Amendment — 2026-08-10: durable local browser sessions

The initial in-memory consequence is superseded for persistent local
deployments. `SessionGateway` now uses the existing
`awaken_iam_core::SessionRepository` port as its only session backing. Its default
adapter remains the existing `InMemoryStore` for tests and explicitly
ephemeral composition, while local products inject the same migrated
`SqlStore<SqliteBackend>` that already owns `iam.identity` under their typed
data directory.

Static ownership remains unchanged:

| Owner | Responsibility |
|---|---|
| `SessionGateway` | mint, cookie parsing, liveness, activity refresh, logout |
| `SessionRepository` | create, token-hash lookup, activity/revocation persistence |
| local product composition | select its existing `iam.sqlite` adapter |
| browser | retain only the opaque HttpOnly cookie |

On every authentication, the Gateway resolves the token hash from the
repository, rejects unknown, expired, or revoked rows, and writes the refreshed
`last_seen_at` through the same repository. Logout persists `revoked_at`
before clearing the cookie. Repository failures fail closed. After a process
restart, the unchanged cookie therefore resolves through the reopened
`iam.sqlite`; the newly issued setup challenge is needed only by a browser
without a live session. Setup challenges remain deliberately transient,
five-minute, and single-use.

## Amendment — 2026-11-06: owner-authorized recovery without restart

Reuse unchanged: `SessionGateway`, `SessionRepository`, `IamGate`, exchange,
current-session and logout remain the only browser authentication path.
Modify: `LocalSetupGateway` may rotate its existing challenge in place, retaining
the account chosen at startup; `LocalBrowserAuth` exposes that operation to its
host. New public anonymous issuance routes and additional stores are absent.
The product owns the privileged operator entry and its PDP authorization.

Rotation replaces only the challenge hash, expiry and consumed marker under the
same mutex as exchange. The previous token immediately fails; a renewed token
still expires after five minutes and exchanges once. Already established cookies
are neither revoked nor reissued. Missing challenge, invalid time window or
unavailable state fails closed without replacing the current challenge. A lost
rotation response permits another explicit owner-authorized rotation; an unknown
exchange response must first be resolved through the canonical session read.

