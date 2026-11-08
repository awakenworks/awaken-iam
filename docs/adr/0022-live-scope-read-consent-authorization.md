# ADR-0022 - Live authorization of scope-level personal reads

- **Status:** Proposed
- **Implementation:** done
- **Date:** 2026-11-09
- **Related:** ADR-0019

## Context

A scope-level read credential has no opaque native execution target. Signature
verification checks its signed family and lifetime, while ordinary policy
checks know neither its grant identifier nor whether that consent was revoked.
Minting again before each read is a useful consumer practice but does not fence
reuse of an already issued credential. Scope reads need the same live compound
consent check as targeted execution.

## Decision

Amend ADR-0019's compound authorization contract. The existing
`POST /v1/authorize/personal-delegation` accepts an absent target only when the
signed purpose is `read`. An `execute` still requires its exact signed target
and revision. `original_outcome` remains ineligible for compound execution or
scope-read authorization. Existing targeted JSON requests retain their shape.

For every admitted scope read IAM checks the current consent, owner account,
recipient client and service identity, audience, action, scope, validity and
revocation. It then evaluates the current service-and-owner policy with the
consumer's native facts. Missing or unavailable state cannot yield Allow.
Consumers must invoke this endpoint at each native read admission; a locally
verified signature or cached ordinary policy is insufficient. The native owner
still fences HTTP routes, MCP tools, row and field access. Consent adds no
transport or business permission.

Revocation denies the next admission using the same already issued token. This
does not claim that a cross-service revocation can atomically cancel bytes that
an earlier admitted operation has already returned.

## Consequences

The shared authorization DTO represents the target as optional. Native consumer
constructors wrap execution targets explicitly and send no target for reads.
The same endpoint, repository and current PDP are reused; no second consent
store, credential cache, background identity or fallback permission is added.
Consumers pin a cohort containing this live-read contract before enabling it.

## Validation

`personal_delegation_e2e` mints a read token and authorizes it through the native
HTTP endpoint, then reuses that exact token after consent revocation, owner
account disablement, recipient withdrawal and human/service policy withdrawal.
Action, scope, audience and conjunctive identity substitutions are refused;
targeted execution and original-result recovery retain their prior fences.
The remote client's tests distinguish explicit refusal from unavailable/decode
failures. Composing products separately exercise HTTP and MCP ingress with
revoked, expired and cross-scope tokens and an unavailable IAM dependency.
