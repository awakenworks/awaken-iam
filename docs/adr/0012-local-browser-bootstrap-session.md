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
