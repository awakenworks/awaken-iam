# ADR-0016 - Organization erasure admission and atomic publication

- **Status:** Accepted
- **Implementation:** in-progress
- **Date:** 2026-10-30
- **Related:** ADR-0003, ADR-0008, ADR-0010, ADR-0013, ADR-0015

## Context

Organization privacy cleanup currently selects its scope closure before the
shared SQL transaction. Deleting an Org and its Directory fence also discards
the evidence needed to refuse a late create, provisioning command or descendant
write. PAP audit and policy-version publication follow cleanup in another
commit, so losing the first response can leave an unpublished change.

The existing IAM repositories, projection ownership/epochs/tombstones and
backend transaction owners remain authoritative. A Cloud-side precheck or
process mutex cannot close a cross-process write race.

## Decision

Keep a material-free terminal identity in the original Org lifecycle owner.
Live Org reads and lists retain their existing shape and omit erased identities.
All Org-related mutation paths use the same terminal admission under the
existing shared fence before reading the scope closure or changing data.
Existing resource projection ownership and retirement facts remain canonical;
minimal refusal keys cover only identities not already represented there.
Account data, other Orgs and global append-only audit retain their own owners.
Retained opaque refusal keys are explicit privacy-policy data, not a claim of
zero-trace deletion.

Extend the original `SqlConn` transaction owner with a borrowed query/execute
context. The original write-list and checked-write operations delegate to this
one runner. SQLite keeps `BEGIN IMMEDIATE`; Postgres keeps its original
connection/TLS/plain-thread ownership and invokes an operation exactly once.
A callback or SQL error rolls back, a commit error is returned, and no caller
may publish its captured result before successful commit. The callback is
object-safe and `Send` so existing `dyn SqlConn` callers and the scoped-thread
Postgres adapter preserve their boundaries.

The PAP erasure operation commits terminal identity, payload cleanup, its
original `AuditEvent` and the original global policy-version publication
atomically. Core owns the single publication decision and terminal-row facts.
One neutral data definition in the existing IAM contract carries `changed`,
`admission_changed`, `confirmed_organization`, the stored `erasure_version`,
and the current `observed_policy_version`; Core and HTTP use that same type. Both coordinates refer to the original policy fence;
neither is a new clock or a serialization-schema version. The independent
`receipt_version` names only this data format. Exact retry cannot
advance erasure again, and the old admin acknowledgement projects the current
observed policy version rather than regressing to an earlier receipt.
The existing bool erasure port delegates to the same cleanup kernel and keeps
its payload-change/repeated-no-change result contract. The direct compatibility
entry reuses the existing server wall-clock conversion and original deletion
audit projection; PAP forwards its original caller audit input.

A first negative admission changes policy even if it removes zero payload rows:
it publishes/audits once with `changed=false`. Its confirmation remains false
when IAM never knew the identity, or a legacy writer physically removed it.
An old current-policy acknowledgement cannot turn that unknown history into
certifiable erasure. Exact replay returns the original erasure coordinate and
current global policy version without a second audit/publication.

Append authz migration 10 without altering the consumed v8 bridge or any v1–9
body. It rebuilds only the original Org table to allow material-free terminal
rows; live rows preserve their original payload. Terminal rows contain no name,
owner or Org timestamps. Legacy resource/group/workspace refusal keys are retained
only where existing projection ownership/tombstones do not already own them.

Cloud retains its own DEK custody owner and exact destruction intent/receipt.
IAM supplies identity admission and publication, not a DEK registry or product
runtime state. A cohort may enable certificate completion only after both
owners have qualified the same target and their late-write cases.

## Behavior and consistency

A mutating command acquires the original transaction/fence, then reads Org and
scope-owner facts and applies canonical admission. A late writer that commits
first is included in the erasure closure; one that follows erasure observes the
terminal identity and is refused. Reads for privacy closure, mutations,
audit/version and the final receipt share the same commit boundary. Failures
roll back together; response loss is recovered from that boundary's facts.
No new journal, registry, service, invalidation channel or resource epoch is
introduced. A larger resource epoch or an old projection receipt cannot revive
an erased Org.

## Compatibility and qualification

Preserve published wire shapes and errors, the existing migration history,
the two recognized v8 receipts and append-only v9, and projection/retirement
rules. Add schema changes only after the current cohort's final migration.
A physically deleted legacy identity without trusted closure evidence cannot
be assigned invented terminal history. Mixed old destructive writers and new
terminal rows require an explicit migration/cohort qualification.

Retain all original repository, bool/version, SQL, remote and migration tests.
Extend the existing shared SQLite/Postgres fixtures with read-after-write,
callback/query/write failure, rollback and concurrent late-writer rules. Source
review is not a compilation, proof or deployment result; those gates remain
required before delivery.

## Original projection authority during privacy cleanup

Raw repository writes cannot bypass the existing product projection owner or
retirement fact just because the active payload row is absent. New raw effects
use the original owner/tombstone predicate; a historical raw receipt remains
separate from permission for a new effect. No additional resource epoch or
registry is created.

Privacy scope resolution also consumes positive original projection ownership
and retirement facts. That keeps independent administrative grants/bindings
inside the known Org closure after the active parent edge is retired. The
existing Core resolver has one closure loop; its old entry uses an empty seed
set. Projected identities remain excluded from the Org's legacy refusal keys.
Contradictory foreign ownership fails closed instead of being reassigned.
Unknown historical generic orphans still cannot acquire invented Org lineage.

The changed memory privacy/evidence boundary fails closed on a poisoned authz,
identity, audit or fence mutex. All required guards are acquired before mutation;
a possibly inconsistent state cannot emit even a replay receipt. Ordinary
changed scoped mutations also use checked acquisition for the guards they own.
Tests may inspect poisoned data to prove inertness, but production never repairs
poison or treats forensic inspection as consistency evidence.
