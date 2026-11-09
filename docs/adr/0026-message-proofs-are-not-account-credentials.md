# ADR 0026: Keep channel message proofs outside the Account credential family

- **Status:** Proposed
- **Implementation:** done

## Context

A registered channel verifier authenticates an exact message and resolves the current
native Account and installation membership. This is not an interactive Account login,
a customer-record authorization, or a person's confirmation of a business write.

A message proof encoded as an ordinary Account access token can reach consumers which
correctly verify an access token but do not enforce its message audience. A denylist at
one endpoint leaves other Account credential consumers exposed.

## Decision

Use a separately published, signed channel-message proof payload. It binds issuer,
principal, evidence reference, installation, connector, message, body digest and validity
window. Its wire shape deliberately lacks the required subject and standard validity
coordinates of an Account access token. Generic Account token decoding therefore fails
before UserInfo, exchange, owner consent management, or product authentication can treat
it as a person credential. No generic verifier exception is introduced.

Retain the historical response field `access_token` only as an explicit compatibility
carrier for this proof. Its `token_type` identifies the dedicated proof family, never
Bearer. Existing Flow channel consumers discard that field and consume the trusted,
message-matching native response; they receive no ambient Account credential. The
proof does not authorize a product operation, replace current PDP evaluation, or
establish a customer's business-record scope.

Registration is deployment-owned. Every authentication rereads the native external
identity, active Account, installation membership, and permitted routing Groups.
Dependency failures remain unavailable, with no cached or guessed Account fallback.
No product runtime, connector secret, or business approval is stored in IAM.

## Validation

The [test design](../design/channel-message-proof-testing.md) separates pure contracts,
native HTTP, SQL backends and the separately built Flow consumer probe. A real old
message bearer accepting UserInfo or general exchange must make the new rejection
assertions fail before the dedicated proof implementation is qualified.
