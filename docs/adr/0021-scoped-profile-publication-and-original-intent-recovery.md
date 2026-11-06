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

Account subjects must currently be active members of the Workspace's Org.
Direct non-account grants remain restricted to the scoped publisher itself.
A runtime Service role reference (including its binding limits) must match an
independently provisioned native role binding with the exact principal, role
and scope. The existing tenant-access administration protocol owns that binding;
scoped publication cannot create or restore it. Runtime decisions reobserve this
same owner and remove unavailable Service role references from the request-local
native evaluator. Company Group rosters contribute Account members only; they
cannot supply an alternate Service role after its native reference is revoked.
This keeps the publication and runtime principals distinct without a second
grant store or policy interpreter. Unknown or noncanonical supplied fields fail
before native draft creation, including nested constraint fields.
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

Initial activation also checks never-published history inside the same native
head transaction. Retirement makes the active head empty but cannot make an
unactivated old draft eligible for initial activation again. A fresh scoped
request against retired history is refused; explicit operator recovery remains
with the separate generic PAP authority. This prevents an empty-head ABA without
making unrelated namespaces share one publication revision.

Preparation and activation also reuse the native erased-Org admission fence at
the intent's explicit Workspace, including an empty profile. SQL activation
reads admission after its policy-version marker and commits through that same
fence; a concurrent privacy commit invalidates the activation CAS. Original
intent recovery remains a read and cannot recreate the erased scope.

Cloud owns the confirmed publication plan, per-owner checkpoints and readiness
coordination. It retains the original serialized request, key and expected head
after a lost response. It does not claim an atomic transaction across profiles,
Groups, product configuration and transport projections. Flow's deterministic
compiler supplies product policy semantics; IAM does not copy that compiler.

## Consequences

### Current scoped decisions

Publication admission is not continuing membership. For a namespace pinned by
the native scoped-publication owner, daemon PDP calls must evaluate only its
current active revision at that exact Workspace. An absent or retired head
denies, including when a base policy grants a wildcard. Every Account in the
authenticated principal chain must still be active and hold an exact native
Org membership. Workspace roles and immutable profile bindings cannot supply
that membership. Native Groups are read at decision time and contribute only
while owned by that Org. Non-account callers must be explicitly named in the
profile; a company Group cannot introduce an unrelated service identity.

The scoped router installs the native Account-repository decision port. A daemon
that finds a scoped namespace without that port fails closed. The explicit
Workspace/profile decision endpoint also refuses unpinned namespaces, so a
shared consumer cannot fall back to legacy grants before first publication.
Decisions retain the original policy-version fence and the server clock; a
changed fence or unavailable source returns no Allow. This is a remote daemon
contract. Offline snapshot consumers remain unqualified for shared scoped
decisions until their current membership facts and admission are integrated.

The internal current-resource decision hook uses this same dispatch. In
particular, the personal-delegation compound endpoint cannot substitute a valid
signed consent for current scoped admission. Revoked native Org membership
denies its still-live execution credential on every replica; a missing scoped
decision port is unavailable. Consent identity, target fencing and monotonic
revocation keep their original owner and do not create another policy evaluator.

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

The standalone token-introspection route uses the same durable API-token
verification owner as scoped publication. Newly issued keys and revocation are
read from native storage on every request, independently of policy snapshot
markers. The response retains the verified credential's Workspace binding;
product adapters must preserve it when selecting a tenant. Storage failure is
unavailable rather than permission to reuse a previous identity.

Scoped publication derives the service principal and credential Workspace from
one original native token observation. Personnel admission may project its audit
actor from that same record; the scoped publisher must not reauthenticate the
secret or combine identity from one read with scope from another. Each new
request still verifies the current durable token, owner and native policy. This
introduces no authentication cache or change to revocation or request budgets.

The runtime-role reference protocol (2026-11-06) uses request-local observations
of the existing role repository, never a reusable Allow cache. Original profile
documents and checksums remain immutable; an ephemeral evaluator unbinds only
Service role tuples that their native owner no longer supplies. Missing role
authority is unavailable, not a profile-derived permission. Existing publishers
that assign themselves profile roles also need the independently provisioned
native binding; direct publisher grants keep their existing behavior. Initial
provisioning and migration must establish these exact references explicitly,
and retries must never restore references removed after confirmation.

Current Service references use an exact native repository lookup of principal,
role and scope against the existing role-binding primary key. Neither publication
nor a scoped decision enumerates a shared service's bindings in other tenants.
Repeated references may share an observation within one request only. An adapter
without this bounded primitive fails unavailable instead of using a full scan.

Scoped retirement uses a separate exact Workspace and namespace grant. It
resolves the original publication key and retires only that revision through
the native active-head comparison. The service authorized to withdraw policy
may differ from the original publisher. Replays recover the original retired
or superseded effect, including across replicas. Retirement keeps the original
publication history and leaves the scoped data plane closed without an active
head. The initial-absence activation rule still rejects a retired namespace.

A composed application can activate a bounded set of prepared originals in
one Workspace. A single current owned Service must hold the direct exact
`activate-set` grant at every selected namespace and match each original
publisher. Native admission compares the complete original intents and
revalidates their current subjects. SQL compares every predecessor and the
admitting policy fence in one transaction and advances the fence once. Any
conflict rolls back the whole set. Replaying a fully observed effect reads the
originals. A mixture of prepared and earlier effects is a conflict.
Application and product readiness remain with the composing owner.
