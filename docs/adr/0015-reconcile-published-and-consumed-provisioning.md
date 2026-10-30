# ADR-0015 - Reconcile published and consumed provisioning boundaries

- **Status:** Accepted
- **Implementation:** done
- **Date:** 2026-10-21
- **Related:** ADR-0003, ADR-0007, ADR-0014

## Context

GitHub main and the consumer's pinned IAM track evolved independently. Both
used authz migration 8 and `/v1/authz/resource-provisions`, with different
schema and request meanings. Replaying a branch must retain published replica
fences, projection ownership and tombstones, as well as the consumer's atomic
resource provisioning and authoritative profile publication evidence.

## Decision

Preserve the public projection protocol. New atomic clients use
`/v1/authz/resource-provision-transactions`; the composed projection endpoint
also accepts the earlier atomic request and delegates to the same owner. Strict
request shapes prevent malformed projections from falling through to an atomic
command. Both paths retain the existing product credential and tenant checks.
The generic daemon store role acquires no projection capability requirement.

Public authz migration 8 retains its exact canonical SQL and checksum. The
Foundation published-legacy mechanism accepts only the exact consumed v8
receipt as an additional historical identity. Append-only migration 9 creates
the deterministic atomic schema. For the exact consumed v8 receipt, the existing
single-applier transaction first saves its two atomic tables, applies the pinned
public projection schema, runs migration 9, and restores the atomic rows. Any
failure rolls the entire bundle back. Existing receipts and rows remain intact; arbitrary checksum drift is rejected. No schema ledger is
rewritten and no database is deleted.

## Validation

Real SQLite tests upgrade both historical v8 tracks, retain rows and receipts,
verify both schema families, replay the migration and reject unknown drift.
Composed HTTP tests retain both request protocols, stable replay receipts and
unchanged authorization snapshots on malformed or unauthenticated commands.
Existing projection ownership, tombstone, PostgreSQL and replica refresh tests
remain part of the server suite.
