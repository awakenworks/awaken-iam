# ADR-0023 - Bounded direct-owner personal consent listing

- **Status:** Proposed
- **Implementation:** done
- **Date:** 2026-11-09
- **Related:** ADR-0019, ADR-0022

## Context

A consent management surface needs the authority's complete owner inventory,
including revoked and expired records. A product-local list of remembered grant
identifiers cannot establish that inventory and must not become another consent
store. The existing direct-owner management bearer already fences creation,
individual reads and revocation.

## Decision

Add `GET /v1/personal-delegations?limit=50&after=<next_cursor>` to the same
native router. It uses the existing management audience and scope, requires a
current active account, and rejects service, delegated and personal-credential
families. The bearer alone selects the owner; owner selectors and other unknown
query fields are rejected.

The response is `{items: PersonalDelegation[], next_cursor: string|null}`.
`limit` defaults to 50 and must be between 1 and 100 inclusive. Entries are
ordered by their opaque native identifier ascending, not by chronology. The
cursor is the last emitted identifier and is only an exclusive ordering bound;
it never changes the owner fence. `next_cursor` is null only after the last
page. Revoked, expired and not-yet-effective records remain visible. Concurrent
creation is not a snapshot: consumers refresh from the first page to discover
new entries and must not label a partial traversal as the complete inventory.

Use a bounded keyset query through the existing shared SQLite/PostgreSQL SQL
adapter. Append authorization migration 14 for the `(owner, id)` index; retain
all existing migration bodies and receipts. No product data or credential cache
is added.

The owner-purpose bearer can be obtained by a public registered client using
real authorization-code PKCE followed by ordinary audience exchange. Client
registration must admit `iam.personal-delegation.manage` and the exchange target
`iam-personal-delegations`. The code grant must actually contain that scope.
Exchange uses the client's own access-token audience, omits secret, actor and
resource parameters, and returns the same account without an actor claim.
An `openid`-only grant cannot be upgraded to the management scope.

## Consequences

Products can compose native create, list, read and revoke without persisting a
local authorization inventory. Listing is observation of consent records, not
an authorization decision; each use still requires live consent and current
policy. Failed listing or exchange cannot fall back to remembered grants.

## Validation

The same repository conformance scenario runs on SQLite and PostgreSQL and
checks stable pages, owner isolation, lifecycle visibility and bounds. Native
HTTP tests cover purpose, principal and expiry fences, malformed queries and
continuation. A seeded live SQL session drives the real public PKCE authorize
and code redemption routes, then the real token exchange and listing routes;
wrong verifier, code replay and `openid` scope escalation are refused. These
are native protocol tests, not a deployed product browser acceptance claim.
