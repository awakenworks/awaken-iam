# ADR-0013: Directory placement is independent from product-space identity

- **Status:** Proposed
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
2. `ProductSpaceRef { product, space_id }` is an open, opaque product identity.
   `ProductSpaceBinding` places that stable identity at one Directory node.
   Products own the space and its business rules; IAM owns only placement.
3. A node has an optional direct parent, not a tier. Parent changes stay inside
   one Org, reject cycles, and never alter product-space or authorization ids.
4. Directory mutations advance an independent `revision`. They do not advance
   the authorization policy `version`, because a display move is not a policy
   change.
5. One Directory repository transaction writes a node mutation, optional initial binding,
   audit entry, and revision advance. SQLite and Postgres execute the same shared
   SQL plan. Embedded callers invoke `DirectoryApi` directly; remote callers use the
   same guarded `/v1/admin/directory/*` surface through `AuthzTransport`.
6. The compatibility `WorkspaceId`, `ProjectId`, and fixed `ScopeRef` variants
   remain until consumers complete their own migrations. They are not the new
   Directory model and no new fixed level is added.

## Static structure

```text
awaken-iam-contract  Directory DTOs and ProductSpaceRef
        |
awaken-iam-core      DirectoryNode invariants + DirectoryRepo
        |
awaken-iam-server    DirectoryApi + shared SqlStore + iam.directory V0001
        |
awaken-iam-client    existing AuthzTransport, HTTP adapter
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
create node (+ optional space binding)
  -> authenticate admin caller
  -> validate node, parent tenant/liveness, sibling slug, binding identity
  -> transaction(node + binding + audit + directory revision)
  -> success with revision; any write failure rolls back all effects

move node
  -> authenticate -> load node and target ancestry
  -> reject missing/archived/cross-Org/cycle/slug conflict
  -> transaction(parent update + audit + directory revision)
  -> product id and policy version remain unchanged

remote unavailable / invalid hierarchy / persistence failure
  -> fail closed; no product-local compatibility write or fallback authority
```

## Consequences

- Products may present any hierarchy without teaching their domain logic a new
  level or coordinating fixed enums.
- Local and hosted deployments use identical semantics and migrations; only the
  call transport differs.
- Existing Cloud and Flow scope metadata can be migrated into this authority,
  then their duplicate directory writers and tables can be retired.
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
