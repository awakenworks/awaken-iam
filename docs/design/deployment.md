# Deployment and storage

`awaken-iam` ships two ways from one codebase:

- **embedded** — a library co-located in another process, sharing that host's
  database; and
- **standalone** — its own process with its own database.

One mechanism makes both safe: IAM owns **scope-partitioned, self-contained
migration bundles** with no cross-component coupling, adopting the
`awaken-sql-migration` pattern. The deployment choice is then just *which pool
and router host IAM*, not a code fork.

The database **backend** is likewise a choice, not a fork. IAM supports at least
**Postgres** and **SQLite** behind the same repository ports; the backend is an
edge adapter, and `contract`, `core`, and `client` never learn which one runs.
See [ADR-0003](../adr/0003-storage-backends.md) for the backend decision, the
DDL-dialect strategy, and the scenario matrix:

| Backend | Serves | Not for |
|---|---|---|
| **SQLite** | embedded, local, single-process, development, small single-tenant | multi-node HA (single writer) |
| **Postgres** | standalone, microservice, cloud, multi-node, highly available | — |
| **In-memory** | tests, ephemeral `local` client | any durable deployment |

Running either mode highly available is the operational reading of this same
assembly — N stateless nodes against one HA store. That topology requires
Postgres; SQLite is single-writer and serves the single-node embedded/local band
only. See [high availability](high-availability.md).

> "Migration" here means **schema** migration (owning IAM's tables). It is
> unrelated to the capability [migration plan](migration-strategy.md) (moving IAM
> capability in from other services). Two different migrations.

## Principle: bundles are split-or-aggregate safe

IAM declares its DDL as append-only, checksum-verified **migration bundles**, one
per subdomain scope:

```text
iam.identity     accounts, external identities, sessions, api tokens
iam.authz        roles, grants, memberships, resource-model registry
iam.entitlement  plans, subscriptions
iam.namespace    namespace ownership, signers        (only if split out)
```

Two rules keep them split-or-aggregate safe — the whole point:

1. **No bundle hard-couples to another bundle.** Bundles version independently;
   none assumes another has run.
2. **No cross-component foreign key.** No IAM table references another
   component's tables, and references *between* IAM subdomains are by id resolved
   in the domain, not by DB-level FK across bundles. Cross-component references
   are by id, resolved at the API layer.

This is the discipline that lets IAM aggregate with siblings or be extracted
later, unchanged.

## Table prefix and ledger

The store is constructed with a prefix:

```rust
IamStore::with_prefix(pool, "iam")
//  -> iam_accounts, iam_grants, …  and ledger  iam_schema_migrations
```

`pool` is whatever connection handle the chosen backend supplies — a Postgres
pool or a SQLite connection — so the prefix and ledger discipline below is
backend-independent.

- **embedded** — uses the host's pool (a shared Postgres pool, or a SQLite
  connection for a single-process host); the distinct `iam` prefix and IAM's own
  `iam_schema_migrations` ledger isolate it inside the shared database, next to
  siblings using their own prefixes and ledgers.
- **standalone** — its own DSN/database; identical code, different pool. A
  standalone cloud/HA deployment uses Postgres (see the matrix above).

## Partition by scope (two senses)

- **Component scope** — the bundle ids and table prefix above. This is what makes
  IAM deployable split or aggregated.
- **Tenant scope** — IAM's own [`ScopeRef`](iam-model.md#scoperef)
  (org / namespace / workspace / project …) partitions tenant data *within* one
  database (a scoped column / `WHERE scope = …`), so multi-tenancy works the same
  whether embedded or standalone.

The two are orthogonal: component scope decides *where the tables live*, tenant
scope decides *whose rows they hold*.

## Assembly

Both modes reuse the same `awaken-iam-server` assembly; only the pool and the
router host differ.

```text
embedded:   host builds the shared pool (Postgres) or opens a SQLite connection
            -> IamStore::with_prefix(pool, "iam"); store.migrate()  (runs iam.* bundles)
            -> mount IAM /v1 routes onto the host router
            -> in-process callers use the local IamClient (no network hop)

standalone: iam-daemon builds its own pool (Postgres for cloud/HA)
            -> IamStore::with_prefix(pool, "iam"); store.migrate()
            -> serve the canonical /v1 API
            -> remote callers use the remote IamClient
```

`store.migrate()` renders each bundle's dialect-neutral DDL for the active
backend; see [ADR-0003](../adr/0003-storage-backends.md) for the type-token
rendering and the single-applier migration guard.

The client SDK's `local | remote` mode (see [remote protocol](remote-protocol.md))
mirrors the deployment: embedded → local, standalone → remote. A consumer swaps
deployment by changing configuration, not code.

## What IAM owns here

- Its migration bundles (DDL), its table prefix, and the store adapter that
  implements the core's [repository ports](domain-model.md#ports-and-adapters-hexagonal).
- In embedded mode it owns its **schema within** the shared database, not the
  pool lifecycle (the host owns the pool).

## Crate placement

The backend adapters (Postgres and SQLite) and the `awaken-sql-migration`
dependency live in the server layer (`awaken-iam-server`, or a small
`awaken-iam-store` module it owns). Each backend is a thin edge adapter over the
shared repository ports and a `MigrationExecutor`; they differ only in the
connection handle, the DDL-token rendering, and the single-applier guard (see
[ADR-0003](../adr/0003-storage-backends.md)). `contract`, `core`, and `client`
stay storage-free, preserving the [guardrails](../../AGENTS.md): the core
declares ports; only the edge knows SQL. An in-memory adapter backs tests and the
`local` client.
