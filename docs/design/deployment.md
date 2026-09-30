# Deployment and storage

`awaken-iam` ships two ways from one codebase:

- **embedded** — a library co-located in another process, sharing that host's
  database; and
- **standalone** — its own process with its own database.

One mechanism makes both safe: IAM owns **scope-partitioned, self-contained
migration bundles** with no cross-component coupling, built on the shared
`awaken-scoped-migration` foundation crate. The deployment choice is then just
*which pool and router host IAM*, not a code fork.

The database **backend** is likewise a choice, not a fork. IAM supports at least
**Postgres** and **SQLite** behind the same repository contracts; the backend is an
edge adapter, and `contract`, `core`, and `client` never learn which one runs.
See [ADR-0003](../adr/0003-storage-backends.md) for the backend decision, the
DDL-dialect strategy, and the scenario matrix:

| Backend | Serves | Not for |
|---|---|---|
| **SQLite** | embedded, local, single-process, development, small single-tenant | multi-node HA (single writer) |
| **Postgres** | standalone, microservice, cloud, multi-node, highly available | — |
| **Process memory** | tests only | every deployed mode |

Running either mode highly available is the operational reading of this same
assembly — N stateless nodes against one HA store. That topology requires
Postgres; SQLite is single-writer and serves the single-node embedded/local band
only. See [high availability](high-availability.md).

The same rule applies specifically to browser authorization: durable server
composition injects the shared SQL adapter through IAM's canonical
`SessionRepository`; it does not retain a process-local session cache or introduce a
separate browser-session database. Repository failure rejects the request, so
an unhealthy replica cannot silently mint or accept an unshared session.

Downstream product OAuth uses that same adapter through `OAuthClientRepository` and
`AuthCodeRepository`. Registered product clients and the single-use authorization
code transition are therefore shared across replicas and process replacement;
no deployment affinity is required for `/v1/oauth/authorize` followed by
`/v1/oauth/token`. The code repository stores a hash, never the browser bearer,
and its conditional live-to-consumed update is the atomic replay fence.

Upstream provider login uses the existing `LoginFlowRepository` on that same adapter.
The shared row contains only state/nonce/PKCE hashes and the single-use fence;
the browser returns the cleartext nonce and verifier in a short-lived,
HttpOnly correlation-proof cookie. Any replica can therefore consume the row
and verify the proof without a process-local pending map or sticky routing.

> "Migration" here means **schema** migration (owning IAM's tables). It is
> unrelated to the capability [migration plan](migration-strategy.md) (moving IAM
> capability in from other services). Two different migrations.

## Principle: bundles are split-or-aggregate safe

IAM declares its DDL as append-only, checksum-verified **migration bundles**, one
per subdomain scope:

```text
iam.identity     accounts, external identities, login flows, sessions, api tokens,
                 OAuth clients and authorization codes
iam.authz        roles, grants, memberships, resource-model registry,
                 organizations and groups
iam.directory    arbitrary Directory nodes, product-space placements and revision
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

Ledger structure is not IAM-local. `awaken-scoped-migration::LedgerSchema` owns
the two table names, unconditional bootstrap SQL, generation stamp, and the
presence decision. Each driver acquires a namespace lock, probes both tables,
creates both only when both are absent, validates when both are present, and
fails on partial state. IAM therefore has no conditional DDL or second ledger
definition.

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

Both modes reuse the same `awaken-iam-server` assembly and the same canonical
`/v1` route manifest; they differ only by the pool, the router host, and one
seam: the standalone daemon additionally serves the `/v1/admin/*`
administration control plane so the remote console can manage policy over the
wire, whereas the embedded host administers in-process and does not expose that
seam (the Administration Point split in [ADR-0002](../adr/0002-iam-consolidation.md)).

```text
embedded:   host builds the shared pool (Postgres) or opens a SQLite connection
            -> IamStore::with_prefix(pool, "iam"); store.migrate()  (runs iam.* bundles)
            -> mount IAM /v1 routes onto the host router
            -> in-process callers use the local IamClient (no network hop)
            -> policy administration stays in-process (no /v1/admin/* seam)

standalone: iam-daemon opens its own store (SQLite in the current binary;
            Postgres is the cloud/HA target)
            -> IamStore::with_prefix(pool, "iam"); store.migrate()
            -> serve the canonical /v1 API plus the /v1/admin/* admin seam
            -> remote callers use the remote IamClient; the console administers
               policy over /v1/admin/*
```

The current `iam-daemon` binary wires a persistent SQLite store through
`IAM_DATABASE_PATH`. The shared SQL adapter and resource-projection transaction
are also tested against Postgres, but the binary's Postgres DSN selection and
multi-replica deployment wiring remain a separate release gate. Set
`IAM_DIRECTORY_PRODUCT_TOKENS=tutor=<secret>` for Tutor's product-scoped
resource-model and versioned projection requests; `IAM_ADMIN_TOKEN` remains
independent for organization, workspace and global policy administration.

`store.migrate()` renders each bundle's dialect-neutral DDL for the active
backend; see [ADR-0003](../adr/0003-storage-backends.md) for the type-token
rendering and the single-applier migration guard.

Directory uses the same assembly without joining the authorization bounded
context. Embedded products call `DirectoryApi` directly over the migrated
SQLite/Postgres store; hosted products call the same application path through
`/v1/admin/directory/*`. Node, optional initial placement, audit, and
Directory-revision writes form one database transaction. The Directory revision
is independent of the policy version because placement changes do not change
authorization.

The client SDK's `local | remote` mode (see [remote protocol](remote-protocol.md))
mirrors the deployment: embedded → local, standalone → remote. A consumer swaps
deployment by changing configuration, not code.

## What IAM owns here

- Its migration bundles (DDL), its table prefix, and the store adapter that
  implements the core's [repository contracts](domain-model.md#repository contracts-and-adapters-hexagonal).
- In embedded mode it owns its **schema within** the shared database, not the
  pool lifecycle (the host owns the pool).

## Crate placement

The backend adapters (Postgres and SQLite) and the `awaken-scoped-migration`
dependency live in the server layer (`awaken-iam-server`, or a small
`awaken-iam-store` module it owns). Each backend is a thin edge adapter over the
shared repository contracts and a `MigrationExecutor`; they differ only in the
connection handle and lock/execution calls. Bundle planning, token rendering,
ledger naming, bootstrap DDL, and bootstrap decisions come from foundation (see
[ADR-0003](../adr/0003-storage-backends.md)). `contract`, `core`, and `client`
stay storage-free, preserving the [guardrails](../../AGENTS.md): the core
declares repository contracts; only the edge knows SQL. The process-memory
adapter backs tests only. A local client is a call mode, not a persistence mode;
deployed local composition still uses migrated SQLite.
