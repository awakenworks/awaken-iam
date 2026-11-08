# ADR-0024 - Authorization freshness is observation, not authority

- **Status:** Proposed
- **Implementation:** done
- **Date:** 2026-11-09
- **Related:** ADR-0022, ADR-0023

## Context

Native consumers need to reject a collection cursor after the authority that
qualified its earlier page changes. The shared store already advances its
policy version and revocation epoch transactionally. A product cache or a
locally verified token does not prove that those counters remain current.
Request identity also needs the issuer configured on the actual verifier;
product namespaces and caller arguments cannot supply it.

## Decision

Preserve the existing Resource and personal-delegation authorization JSON.
Successful native PDP responses additionally carry the opaque
`x-awaken-authorization-freshness` observation. It fingerprints both components
of the existing shared-store fence. The response is unavailable if the fence
cannot be read or changes across the decision. Scoped and ordinary Resource
PDP responses use the same source. A separate client evaluation method requires
valid metadata for an Allow; legacy transports or servers cannot manufacture a
qualification from an old Allow, reason, policy cache or missing epoch.
Explicit denial remains denial even when no qualification can be returned.

This observation grants nothing. Consumers must re-run current authentication,
live consent and all native row/field decisions on every page. They may bind the
observation into a short-lived authenticated cursor together with the verified
person/actor/grant and exact query coordinates. Changed or unavailable evidence
requires rejection or a fresh first page. It is not a token or lease, and must
never replace an authority decision.

Expose `IamGate::expected_issuer()` as read-only metadata of the same verifier
configuration. Missing or malformed configuration remains absent. Its presence
does not authenticate an account. Composing products derive a Person only from
an actually verified Account plus this trusted issuer, never caller input or a
product namespace; Open mode cannot establish that Person.

## Consequences

The old DTO and endpoint shape remain compatible. New consumers deliberately
refuse a server or local adapter lacking the complete native freshness source.
No credential store, product index, authorization cache or second policy epoch
is introduced. Issuer metadata reuses the configured verification authority.

## Validation

The same SQLite/PostgreSQL native HTTP scenario compares observations across grant, membership and revocation
fence changes, retaining current Allow/Deny and unavailable behavior. A real
SQL epoch write during admission cannot qualify an Allow. Transport
tests exercise missing, malformed, duplicate and changing metadata, explicit
refusal and dependency failure, with no fallback to an earlier Allow. Verifier
metadata tests distinguish exact configured issuer from missing/blank values.
Products separately qualify cursor privacy and per-row/field enforcement.
