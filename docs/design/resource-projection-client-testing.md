# Versioned projection client acceptance

The client targets the existing `POST /v1/authz/resource-provisions` owner with
`ResourceProjectionBatch`, including its product, organization, stable stream,
original key, positive epoch and complete desired grants/edges/retirements.
It never falls back to the other `ResourceProvision` transaction family.

The native owner validates current authenticated product authority and its
persisted stream. Equal epoch requires the same key and complete body digest
for replay. An older epoch returns `Stale` without applying that invocation.
The published acknowledgement contains key, epoch, policy version and disposition.
HTTP associates it with the submitted request; it is a context-bound ack, not an
independent body/owner proof, immutable historical outcome or a grant. The SDK
can independently reject a foreign key/epoch or invalid policy version only.

Transport acceptance must record exactly one POST even when legacy retry count
is two. Script a 503 followed by a healthy acknowledgement: the first invocation
must fail after one request, and an explicit second invocation must preserve the
same complete request and key. Replacing this method with the old retry runner
must make that assertion fail; restore exact bytes and rerun positive cases.
Test 403, 404, 503, missing JSON fields, foreign keys, foreign epochs and zero
versions without fallback requests. Preserve all three native dispositions.

A lost acknowledgement remains Unknown. A later Stale result does not prove the
original invocation never committed. It may be marked superseded by an explicit
new intent, but must not be re-keyed or called an original success/failure.
Current strict registration and authorization are separate current observations;
they do not resolve that historical Unknown.

Native owner acceptance must retain the existing real SQLite/PostgreSQL stream,
key/body conflicts, stale delivery, product ownership, canonical parent and
transaction rollback coverage. Protected HTTP must reject an actual wrong
product credential; client roles or labels provide no authority. Transport
fixtures, native owner SQL, protected HTTP and consumer adoption are distinct
claims. Any request requiring immutable recovery after later epochs needs an
actual stored owner outcome protocol; an echoed request or current head is not
such evidence.
