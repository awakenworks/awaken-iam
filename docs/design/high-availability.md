# High availability and operations

High availability is a **deployment property, not a feature**. It is the
operational reading of the same assembly described in
[deployment](deployment.md): run more than one of the identical node against one
highly available store. IAM adds no consensus, no leader election, and no
node-to-node messaging to get there — three rules already in the design make
every node interchangeable, and this document is the argument that they suffice.

This topology requires **Postgres** as the shared store. SQLite — the other
supported backend ([ADR-0003](../adr/0003-storage-backends.md)) — is a
single-writer file: it serves the single-node embedded/local band correctly and
is trivially consistent there, but it is not the *shared* store many nodes
advance a common fence in (rule 3 below). Configuring SQLite for a multi-node
deployment is a misconfiguration, not a degraded mode. Everything below assumes
Postgres.

## The three rules

1. **All authoritative state lives in the shared store.** Between requests a node
   holds nothing of record. Accounts, sessions, API tokens, grants, and
   memberships are rows in IAM's
   [prefixed tables](deployment.md#table-prefix-and-ledger); the policy `version`
   and token `epoch` that fence them (rule 3) belong there too. Losing a node then
   drops zero authoritative state.

   The rule includes downstream OAuth clients and authorization codes. Client
   lookup reads the shared repository, and redemption atomically consumes a
   live code there; neither relies on a hydrated per-node registry, sticky
   routing, or a best-effort cache synchronization loop.

2. **Every node is identical and stateless.** Same assembly, same migration
   bundles, same `/v1` surface (see [assembly](deployment.md#assembly)). A load
   balancer may route any request to any node; there is no affinity and no sticky
   session. Scaling is adding replicas.

3. **Freshness rides the existing fence.** The monotonic `version` carried by
   snapshots and signer sets, and the token `epoch`, already propagate grant
   changes and revocations (see [remote protocol](remote-protocol.md#caching-and-freshness)
   and [permission mechanisms](permission-mechanisms.md) #7, #12). HA's only added
   requirement is that these counters are **advanced in the shared store**, so a
   bump on one node is visible to every node on the next read or sync. No separate
   invalidation channel exists or is needed.

## Topology

```text
                 load balancer  (health-checked)
              ┌────────┼────────┐
         iam-daemon  iam-daemon  iam-daemon     N stateless replicas
              └────────┼────────┘
                 shared Postgres
              (primary + standby; Patroni / managed RDS handles DB failover)
```

Standalone mode runs N `iam-daemon` replicas behind the balancer. Embedded mode
inherits its host's HA: IAM's tables live in the host database and IAM's routes
are mounted on the host router, so if the host runs highly available, so does
IAM — IAM contributes its stateless half and nothing more.

## Data layer

Postgres owns durability and its own availability: streaming replication with
automatic failover through Patroni or a managed service (RDS / Cloud SQL). IAM
does **not** re-implement replication, quorum, or consensus; it treats the store
as a single logical, highly available endpoint and reconnects across a failover.

Concurrent node startup is safe because the
[migration bundles](deployment.md#principle-bundles-are-split-or-aggregate-safe)
are append-only, checksum-verified, and idempotent. The `MigrationExecutor`
honours a backend-neutral **single-applier guard** so exactly one node applies a
pending bundle while the others wait and then verify the ledger — the Postgres
adapter implements it with a `pg_advisory_lock`
([ADR-0003](../adr/0003-storage-backends.md)). No bundle hard-couples to another,
so a rolling deploy that briefly mixes node versions stays safe.

## Freshness and revocation across nodes

There is one source of truth, so there is no split-brain to reconcile:

- A grant, role, or membership change advances the policy `version` **in the same
  transaction** as the write.
- A session revoke or capability-lease change bumps the principal/token `epoch`
  in the store.
- Caches — the remote client's snapshot cache and any in-node decision cache — are
  keyed by `version` and validated against `epoch`; a bump invalidates them on the
  next read. Security-sensitive writes evaluate fresh, as the
  [remote protocol](remote-protocol.md#caching-and-freshness) already requires.

Propagation is therefore bounded by the consumer's sync interval, not by any
node-to-node delivery. That is the deliberate simplicity: changes are eventual
within one sync and never inconsistent, because every node reads the same fence.

## Degraded operation

Failure is fail-closed, consistent with the engine's default-deny posture:

- **Store unreachable.** A node serves at most cached reads and answers any
  request it cannot evaluate fresh as `Deny(iam_unavailable)` — never `Allow` (see
  [failure semantics](remote-protocol.md#failure-semantics)). Writes (login, grant
  changes) are refused with a visible error, not queued.
- **Node unhealthy.** A node failing its readiness probe is removed from the load
  balancer; its in-flight requests fail closed rather than degrade open.

## Health and rollout

- `/healthz` — liveness: the process is up.
- `/readyz` — readiness: the store is reachable and the node's own migrations are
  applied. The balancer and orchestrator route only ready nodes.
- **Rolling deploy.** Because nodes are stateless and bundles are
  forward-compatible, drain and replace one node at a time. Mixed versions coexist
  during the window; the table prefix, the independent ledger, and the
  append-only bundles guarantee it.

## What HA deliberately does not add

The boundary that keeps this simple — the store is the single source of truth, so
nothing else has to coordinate:

- no leader election and no Raft / etcd / consensus inside IAM;
- no sticky sessions or node affinity — any node serves any caller;
- no bespoke cache-invalidation bus — the `version` / `epoch` fence carries it;
- no new wire protocol — the `/v1` surface and snapshot sync are unchanged.

HA is purely running N of the same node against one highly available store.

## Status

This document is the target the edge adapters build to; it introduces no new IAM
concept. The mechanisms it composes — the versioned fence, epoch-fenced tokens,
scope-partitioned bundles, and the stateless assembly — are designed; the
stateless assembly and the bundle plan exist, the rest is not yet wired.

Today the policy `version` and token `epoch` are **in-memory per node**, so a
single process is already correct, and the fence now rides the store rather than
per-node memory. Making every node interchangeable per the three rules is the
remaining work, all of it edge adapters over existing ports, none of it a change
to `contract`, `core`, or `client`. Wired at the edge today:

- store-backed `version` / `epoch` advancement, advanced in the same step as the
  change it fences (the policy administration point bumps the store fence with
  each mutation; the in-memory adapter holds it under its lock);
- the backend-neutral single-applier guard on the `MigrationExecutor` — the
  migration run acquires it before applying and releases it after, success or
  failure, so concurrent node startup is safe (Postgres renders it as a
  `pg_advisory_lock`, SQLite is a single writer);
- the `/healthz` (liveness) and `/readyz` (readiness: store reachable and this
  node's migrations applied) probes on the assembly and daemon.

Still pending:

- the backend repository adapters and `MigrationExecutor`s behind the
  [migration plan](deployment.md#crate-placement) — Postgres for this HA
  topology, SQLite for the single-node band
  ([ADR-0003](../adr/0003-storage-backends.md)) — with the dialect-token
  rendering they share (only an in-memory adapter exists today);
- an HTTP server binding the manifested `/v1` routes and probes (the assembly
  produces a route manifest, not yet a served router).
