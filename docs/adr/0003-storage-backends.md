# ADR-0003 - Pluggable storage backends (Postgres and SQLite)

- **Status:** Proposed
- **Implementation:** planned
- **Date:** 2026-06-21
- **Related:** ADR-0002

## Context

[ADR-0002](0002-iam-consolidation.md) makes `awaken-iam` the system of record
for identity, authorization, and entitlement, and
[deployment](../design/deployment.md) ships it two ways from one codebase —
**embedded** (a library in a host process, sharing that host's database) and
**standalone** (its own process and database). Both reuse the same
`awaken-iam-server` assembly; only the pool and the router host differ.

The design so far names exactly one database: every storage reference is to
**Postgres**. `deployment.md` builds a `PgPool`; `high-availability.md` assumes
Postgres streaming replication, a managed failover (Patroni / RDS / Cloud SQL),
and a `pg_advisory_lock`-guarded migration; `store/migration.rs` declares
`up_sql` as a "Postgres DDL template". Today none of this is built past the
in-memory adapter — the real database adapter is still planned — so the backend
choice is a design decision, not a retrofit.

The deployments IAM must serve do not all want the same database. A standalone,
cloud, multi-node, highly available control plane wants Postgres. But an embedded
library co-located in a single-process host, a local developer run, and a small
single-tenant deployment want a **zero-operations, file-backed** store with no
server to provision. SQLite serves exactly that band and is the conventional
companion to Postgres for "one codebase, two operational scales".

The architecture already anticipates this. The core declares storage-free
[repository contracts](../design/domain-model.md#repository contracts-and-adapters-hexagonal); the
server-owned `store/` module provides adapters; `IamStore<Pool>` is generic over
the pool handle and `MigrationExecutor` is a trait. What is Postgres-specific is
not the architecture — it is the **DDL dialect**, the **migration concurrency
guard**, and the **prose in the docs**.

## Decision

1. **Support at least Postgres and SQLite, both as edge adapters over the same
   repository contracts.** A backend is a `store/` adapter implementing the core's repository
   repository contracts plus a `MigrationExecutor`; `contract`, `core`, and `client` stay
   storage-free and never learn the backend. Adding SQLite (or a later MySQL)
   changes only the edge. The in-memory adapter remains, backing tests and the
   `local` client where no durability is needed.

2. **Backend selects by deployment scenario, recorded as a matrix.**

   | Backend | Serves | Not for |
   |---|---|---|
   | **SQLite** | embedded, local, single-process, development, small single-tenant | multi-node HA (single writer) |
   | **Postgres** | standalone, microservice, cloud, multi-node, highly available | — |
   | **In-memory** | tests, ephemeral `local` client | any durable deployment |

   This maps onto the deployment goals directly: the embedded and local roles can
   run on SQLite; the standalone, microservice, and cloud-authorization roles run
   on Postgres. The choice is configuration, not a code fork — the same assembly
   and the same `local | remote` client mode (ADR-0002 decision 2) sit above
   either backend.

3. **SQLite does not back the high-availability topology, and this is a stated
   boundary, not a gap.** [High availability](../design/high-availability.md) is
   *N identical stateless nodes against one shared store* whose freshness rides a
   `version` / `epoch` fence advanced in that shared store. SQLite is a
   single-writer, single-host file: it serves one process correctly and is
   trivially consistent for it, but it cannot be the *shared* store many nodes
   advance a common fence in. A deployment that needs more than one node uses
   Postgres. Configuring SQLite for a multi-node deployment is a misconfiguration
   the docs must call out, not a supported mode.

4. **Schema is authored dialect-neutral and rendered per dialect; a per-step
   override is the escape hatch.** The migration plan extends the existing
   `{prefix}` token mechanism with a small **portable type-token vocabulary** —
   for example `{json}`, `{timestamptz}`, `{blob}`, `{pk_autoinc}` — that the
   backend's executor substitutes alongside the prefix when rendering a step's
   SQL. One template per migration renders against either backend, so the schema
   has a single source of truth. For the rare step that genuinely cannot be
   expressed neutrally (a Postgres partial index, a `GENERATED` column), a
   `Migration` may carry an **optional per-dialect SQL override** for that step.
   This is the dialect-aware option from the assessment, chosen over a
   common-subset DDL (which would surrender Postgres's `JSONB` / `TIMESTAMPTZ`
   richness that IAM's claims and timestamps want) and over two full parallel SQL
   strings per migration (which drift).

5. **Checksum identity is the neutral template; a per-dialect override is
   checksummed separately.** The ledger already records the SHA-256 of the
   canonical, un-prefixed template as a migration's stable identity. That stays:
   the neutral template — not the rendered, dialect-specific SQL — is the recorded
   identity, so the same migration is one identity across both backends and the
   table prefix. A per-dialect override (decision 4) is a distinct input and is
   checksummed as its own value so its drift is detected independently. Type-token
   rendering is executor code, versioned with the binary, not part of the recorded
   identity.

6. **The migration concurrency guard is a backend-neutral "single-applier"
   contract.** Append-only, checksum-verified, idempotent bundles are unchanged.
   How a backend guarantees exactly one node applies a pending bundle while others
   wait is the adapter's concern: Postgres uses a `pg_advisory_lock`; SQLite
   relies on its single-writer semantics (`BEGIN IMMEDIATE`). The design names the
   *guarantee* (single applier, then ledger verification), not the Postgres
   primitive.

## Consequences

- The store layer gains two concrete adapters (a Postgres adapter and a SQLite
  adapter) behind the existing repository contracts, plus the type-token renderer in the
  migration plan. `contract`, `core`, and `client` are untouched; the ADR-0001
  guardrails hold.
- `store/migration.rs` changes: `Migration.up_sql` is reframed as a
  dialect-neutral template over the prefix and type tokens, gains the optional
  per-dialect override, and the checksum doc clarifies neutral-template identity.
- The design docs become backend-parametric. `deployment.md` no longer hardcodes
  `PgPool`; `high-availability.md` states the SQLite single-node boundary and
  renames the advisory lock to the single-applier guard. The deployment matrix
  above is the canonical reference both link to.
- A future backend (MySQL, libSQL, …) is the same seam: an adapter, a type-token
  mapping, and a row in the matrix — never a change to core, contract, client, or
  the bundle structure.
- Operational expectations are explicit per backend: SQLite carries no
  replication or failover story and is fail-closed single-node; Postgres keeps
  the HA story in [high availability](../design/high-availability.md). Neither
  backend changes the engine's default-deny, fail-closed posture.

## Amendment: synchronous Postgres runtime ownership (2026-08-12)

The Postgres adapter owns the complete synchronous-driver boundary, not only
the final `Client` destructor. The `postgres` client enters its private Tokio
runtime during ordinary queries and transactions as well as shutdown. When an
embedded or standalone Axum handler calls a synchronous repository port from
an already-entered Tokio runtime, `PostgresBackend` executes that driver call
on a scoped plain OS thread and synchronously returns its result. Callers that
already run outside Tokio retain the direct path.

This remains one storage adapter and one source of SQL/transaction truth. HTTP
routers, `AuthApi`, and embedding products must not grow parallel database
executors or Postgres-specific session repositories.

```text
Axum/AuthApi -> repository port -> PostgresBackend
                                -> direct call (plain caller)
                                -> scoped plain thread (Tokio caller)
                                -> one shared Client/transaction
```

| Caller context | Driver operation | Adapter boundary | Outcome |
|---|---|---|---|
| no entered Tokio runtime | query/transaction | direct | original result |
| entered Tokio runtime | query/transaction | scoped plain thread | original result |
| entered Tokio runtime | direct driver call | forbidden | nested-runtime panic |
| either | backend error | same selected boundary | unchanged fail-closed error |

