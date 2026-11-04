# ADR-0021 - Scoped profile publication and original-intent recovery

- **Status:** Proposed
- **Implementation:** in-progress
- **Date:** 2026-11-05
- **Related:** ADR-0011, ADR-0014, ADR-0018

## Context

A tenant policy publisher must not hold IAM's global administration key. A
namespace grant and an unrelated Workspace grant cannot be combined into a new
namespace/Workspace pair. Profile creation also needs original-request recovery:
an uncertain activation must not create a new draft or reactivate a superseded
policy. Products continue to own their policy language and business facts.

## Decision

Use IAM's existing grant authority to bind the whole publication target. The
scoped API authenticates an owned, live service-account API token and requires
the current PDP to allow an exact action containing the namespace on the exact
Workspace scope. Its deciding capability must be an exact direct service grant
at that same scope; wildcard, Org, Global and unrelated namespace authority do
not qualify. A control plane provisions these finite capabilities after it has
verified the product binding. This is administration authority, never personal
consent or a product business permission. Namespace signer ownership remains
the independent trust fact specified by ADR-0004.

Before a write, the native owner validates profile-local identifiers, canonical
Workspace ownership, Group organization, finite constraints and scope closure.
No roster, resource topology or cross-Workspace binding enters through policy
publication. Actual child ownership and signed Pack/source adoption remain the
product owner's checks. The scoped publisher cannot reach the generic admin
routes and receives no global administration credential.

Account subjects must currently be active members of the Workspace's Org;
non-account subjects must be the scoped publisher itself. A distinct runtime
service needs a separately owned transport-grant protocol, not an arbitrary
foreign service reference in a tenant profile. Unknown or noncanonical supplied
fields fail before native draft creation, including nested constraint fields.
The finite baseline read returns current policy and native publication history;
an empty active head after retirement never means initial absence.

IAM persists one original request key and fingerprint with the immutable draft
revision in one repository transaction, using the existing profile store. A
different body under the same key conflicts. The first scoped intent also
pins that namespace to its Workspace; subsequent intents cannot reassign it,
even after retirement. This binding is retained in the native intent history. Activation reuses the native head
CAS. An original activated or superseded revision is reported from native
history instead of being activated again. Current head and the original effect
are distinct receipt fields. Reads and retries still require current scoped
authority; an old key never bypasses access control.

Cloud owns the confirmed publication plan, per-owner checkpoints and readiness
coordination. It retains the original serialized request, key and expected head
after a lost response. It does not claim an atomic transaction across profiles,
Groups, product configuration and transport projections. Flow's deterministic
compiler supplies product policy semantics; IAM does not copy that compiler.

## Consequences

Scoped publication can be deployed without another permission database or
product credential store. Existing operator administration remains compatible.
A new shared capability stays unavailable until exact publisher grants, native
scope enforcement, durable recovery and composing-product receipts are proven.

## Validation

The implementation must test exact versus wildcard/foreign capabilities,
cross-Org Groups, invalid scopes, current token/policy revocation, native CAS,
same-key body conflict, concurrent preparation, process reopen, lost activation
responses and superseded-revision recovery. SQLite mechanism evidence and
explicitly isolated PostgreSQL conformance are separate claims. Product binding,
source admission and multi-owner readiness require composition acceptance.
