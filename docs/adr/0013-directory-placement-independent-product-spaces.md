# ADR-0013: Directory placement is independent from product-space identity

- **Status:** Accepted
- **Implementation:** done
- **Date:** 2026-08-27
- **Deciders:** Awaken IAM maintainers
- **Amends:** ADR-0001 and ADR-0002

## Context

Agents, Objects, and Workforce need one user-visible hierarchy, but their
business containers do not share a fixed `Org/Workspace/Project` model. Cloud
and Flow currently persist overlapping Workspace/Project directory metadata,
while IAM already owns Organization identity, the authorization graph, the
embedded/remote administration path, SQLite/Postgres adapters, and scoped
migrations. A second Directory service, client, server, or repository would
duplicate those mechanisms.

Directory placement must also be movable without rewriting product aggregates
or changing permission. A hierarchy encoded in product ids or `ScopeRef` cannot
meet that requirement.

## Decision

1. The existing IAM Directory supporting subdomain gains arbitrary-depth
   `DirectoryNode` placement below an immutable `OrgId` tenant partition. It
   does not add a new crate, client, server, host, database, or transport.
2. `ProductSpaceRef { product_id, space_id }` is an open, opaque product identity.
   `ProductSpacePlacement` places that stable identity at one Directory node.
   Products own the space and its business rules; IAM owns only placement.
3. A node has an optional direct parent, not a tier. Parent changes stay inside
   one Org, reject cycles, and never alter product-space or authorization ids.
4. Directory mutations advance an independent `revision`. They do not advance
   the authorization policy `version`, because a display move is not a policy
   change.
5. `EnsureProductSpacePlacement` is the one product-space compiler. IAM derives
   node identity, canonical unique slug, active state, timestamp, and audit actor;
   a caller supplies only its stable `ProductSpaceRef`, Org, optional parent
   product space, and display metadata. Exact retries return the existing
   placement without overwriting later user moves or metadata edits; retries
   restore an archived placement.
6. One Directory repository transaction writes a node mutation, optional initial
   placement, audit entry, and revision advance. SQLite and Postgres execute the
   same shared SQL plan. Embedded callers invoke `DirectoryApi` directly; remote
   callers use the same authenticated `/v1/admin/directory/*` surface.
7. A product commits its business aggregate first and then ensures the Directory
   projection. A failed projection is repaired by idempotent reconciliation; IAM
   never becomes the transaction owner for product state.
8. The compatibility `WorkspaceId`, `ProjectId`, and fixed `ScopeRef` variants
   remain until consumers complete their own migrations. They are not the new
   Directory model and no new fixed level is added.

## Static structure

```text
awaken-iam-contract  Directory commands, views, and ProductSpaceRef
        |
awaken-iam-core      DirectoryNode invariants + DirectoryRepository
        |
awaken-iam-server    DirectoryApi + shared SqlStore + iam.directory bundle
        |
awaken-iam-client    existing remote client and HTTP adapter
        |
Agents / Flow / Cloud anti-corruption adapters
```

The dependency remains one-way from products to IAM. `DirectoryApi` is an
independent application boundary and does not depend on `PolicyAdminApi` or
authorization policy. Directory never depends on product runtime code and never
stores Issues, Workflows, Runs, Resources, Canvas artifacts, or execution
placement.

## Dynamic behavior

```text
ensure product-space placement
  -> authenticate caller / derive service principal and server time
  -> resolve existing placement: return unchanged, or restore if archived
  -> otherwise resolve optional parent ProductSpaceRef
  -> derive node id and canonical unique slug
  -> transaction(node + placement + audit + directory revision)
  -> concurrent exact ensure resolves the winning placement
  -> any write failure rolls back all IAM effects

move node
  -> authenticate -> load node and target ancestry
  -> reject missing/archived/cross-Org/cycle/slug conflict
  -> transaction(parent update + audit + directory revision)
  -> product id and policy version remain unchanged

remote unavailable / invalid hierarchy / persistence failure
  -> product fact remains authoritative
  -> record/retry the same ensure command through reconciliation
  -> no product-local directory write or fallback authority
```

## Consequences

- Products may present any hierarchy without teaching their domain logic a new
  level or coordinating fixed enums.
- Local and hosted deployments use identical semantics and migrations; only the
  call transport differs.
- Existing Cloud and Flow scope metadata is input to a one-time projection
  migration; duplicate product-side Directory compilers are then retired.
- The process-memory adapter is test-only. Local production remains embedded,
  but persists through migrated SQLite; hosted production uses Postgres.
- Directory availability is a control-plane dependency. Products may cache a
  revision-fenced read projection, but a cache never becomes a write authority.

## Rejected alternatives

- New `awaken-directory` crates or service: duplicates IAM client/server/host,
  store selection, migrations, admin authentication, and audit.
- Fixed `Org/Workspace/Project` Directory tiers: couples presentation to one
  product and makes arbitrary reorganization a schema/model change.
- Reuse product business tables as the Directory: moving a label would rewrite
  business ownership and authorization.
- Synchronize Cloud, Flow, and IAM stores: preserves multiple writers and makes
  temporary disagreement an expected state.

## Amendment: organization-scoped authority and product credentials

The implementation review found that the accepted decision still left a global
placement key and freshness fence, an unvalidated product string, Directory
methods mixed into the authorization transport, and a second process-memory
Directory repository. Those details contradicted the stated Org aggregate and
single-authority decisions. The implementation therefore tightens them as
follows:

- The wire field is `product_id`; `ProductId` validates canonical open product
  identities, and product credentials are bound to exactly one such identity.
- Placement identity and the independent Directory revision are scoped by Org.
  A children read returns its Org revision and nodes from one database statement.
- `EnsureProductSpacePlacement` is the canonical product-space command.
  Remote callers use a complete `DirectoryClient` separate from
  `AuthzTransport`.
- Directory has no process-memory repository. Tests exercise the production SQL
  repository over migrated in-memory SQLite; local production persists SQLite
  and hosted production persists PostgreSQL.
- Migration V0003 preserves existing placements while rebuilding the placement
  key and freshness fence as Org-scoped authority.

## Amendment: product-space lifecycle and operator observation

Product lifecycle cannot be represented by `DirectoryNode.archived`. A node is
user-managed presentation and may contain other live nodes; a product retiring
its space must neither fail because the node has children nor silently move or
archive user structure. The placement therefore owns an independent
`active`/`retired` lifecycle:

- `EnsureProductSpacePlacement` creates or activates the one stable placement.
  It still restores an archived node when the product is active, preserving the
  existing node identity, parent, and metadata.
- `RetireProductSpacePlacement` idempotently retires the binding without
  deleting or moving its node. Reactivation reuses the same binding and node.
- Both transitions are one Directory repository transaction with one audit
  record and one revision advance. Exact retries are no-ops.
- Product credentials may ensure, retire, and query only their own ProductId.
- Operator observation is a read projection over authoritative placement and
  product facts. It owns no writable state and is not a customer-facing
  Directory surface.

Migration V0004 adds the placement lifecycle with existing rows defaulting to
`active`. Products reconcile active parents before children and retire children
before parents; temporary failures retry the same canonical commands.
