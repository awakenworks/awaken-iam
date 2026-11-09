# Channel message proof test design

This design qualifies the [channel contract](../../crates/awaken-iam-contract/src/channel.rs)
and [native authentication owner](../../crates/awaken-iam-server/src/auth_api/channel.rs),
under [ADR 0026](../adr/0026-message-proofs-are-not-account-credentials.md).

## Required invariants

A message proof is not an interactive Account credential, customer-record permission,
consent, business command confirmation, or general token-exchange subject. Registration
selects an exact issuer/client/installation/connector and native provider namespace.
Only that installation's current active Account and native Group membership authenticate.
Routing Groups are current observations and never grants. Every actual operation still
requires its own native policy and product-data boundary.

The response retains `access_token` only as a compatibility carrier. The dedicated
`token_type`, signed JWT `typ`, and distinct payload prevent replay as Account tokens.
No new message-proof authorization endpoint or ambient credential exchange is introduced.

## Matrix

| Boundary | Positive evidence | Refusal / fault evidence |
| --- | --- | --- |
| Signature and registration | Exact signed message resolves native Account | Foreign signature, issuer, audience, installation, connector, unknown sender |
| Message validity | Exact id, digest and bounded time survive | Empty id, invalid digest, future, expired and overlong assertion |
| Native identity | Current Account and installation Group reread | Disabled Account, removed member, foreign-org Group, unavailable dependency |
| Proof family | Signature validates only as dedicated message proof | Actual access/delegated verifiers, native UserInfo and general exchange refuse |
| Payload isolation | Required message coordinates retained | Even access-family re-signing cannot decode proof as Account claims |
| Owner management | Genuine public PKCE + admitted audience exchange can list owner consents | Message proof cannot list/create/read/revoke; no owner records added |
| Native storage | Credential-family, PKCE, sender and membership checks on migrated SQLite and PostgreSQL | Real fixture Group-table failure yields 503 after prior successful authentication |
| Flow composition | Separately built native adapter resolves active sender, rejects disabled sender | Exact consumer response decoding must not reject dedicated token_type; no broad Bearer retained |

## Qualification procedure

1. Add the actual UserInfo and explicitly admitted general-exchange rejection assertions
   while the old channel implementation still mints Account tokens. Both must fail for
   the real accepted result, using current time to avoid an expired-token false positive.
2. Restore the dedicated family and run all channel cases. Verify generic parsers and
   actual HTTP endpoints; do not infer isolation only from required field names.
3. Run the SQL matrix on SQLite and an explicitly required private PostgreSQL fixture.
   PostgreSQL absence is not backend evidence. The fault drops only this test's namespaced
   Group table and must not affect unrelated tables or instances.
4. Run the normally ignored Flow probe with an explicitly selected separately built
   native consumer executable. The probe starts only an isolated loopback test listener;
   successful process exit plus its exact completion marker are required. Report its
   consumer source qualification separately from server fixture and unit evidence.
5. Run the complete repository checks and normal commit/push hooks on the final source.

## Scope limits

These tests do not implement customer SMS verification, prove a customer-company binding,
serve a support queue, authorize connector setup, or approve an outgoing reply. Existing
person-confirmed business command and original-key recovery contracts remain required.
