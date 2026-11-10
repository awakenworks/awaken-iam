# Resource candidate and contextual batch test design

## Authority and oracle

[ADR 0027](../adr/0027-scoped-contextual-batches-and-positive-resource-candidates.md)
defines a positive candidate superset and an ordered batch of actual contextual
PDP decisions. A candidate match is never an Allow. Test fixtures compare the
planner against the existing native PDP rather than a second rule evaluator.
The property is one-way: every native Allow must be selected; extra candidates
are permitted and explain deferred constraints.

The [Core oracle suite](../../crates/awaken-iam-core/tests/resource_candidates.rs)
enumerates resource relations and compares actual native row/field decisions
with the produced positive predicate. The existing permission-bundle tests
remain owners of role eligibility and actual limit/constraint enforcement.
Candidate tests cannot qualify a different policy family, legacy wildcard
fallback, or an externally reconstructed profile.

## Behavior matrix

| Case | Expected result | Owning evidence |
| --- | --- | --- |
| Owner, Responsible and live binding-group grants | Every native Allow is a candidate; unrelated relations remain excluded when expressible | Core PDP oracle |
| Multiple grants and delegated callers | Grant union and principal-chain intersection | Core PDP oracle |
| Empty role paths alongside direct/group alternatives | No permitted alternative is discarded | Core structural matching and native oracle |
| Workspace-owned versus Project-owned Resource | Plan for actual native physical owner scope | Core oracle; product storage integration separately |
| Exact id or trusted predecessor | Include identity and same-scope predecessors; retain independent conjunctive limits | Core oracle |
| Expired binding and later clock rollback | Plan retains necessary positive selectors with ExpiryDeferred; current PDP still enforces time | Core multi-time oracle; native HTTP expired-limit case |
| Deny, approval, amount, initiator separation or fields | No subtractive candidate shortcut; preserve native outcome, broaden with reason where required | Core oracle and batch-versus-single HTTP |
| Owner plus field/amount/initiator conjuncts | Retain necessary Owner selectors, include every native Allow, and still deny private fields, excessive amounts and self-initiated operations in the actual PDP | Core alternative/delegation matrix and native scoped HTTP |
| Excessive candidate nodes/values or chain | Explicit bounded validation or conservative All, never truncated None | Contract and Core budget tests |
| Unknown operator or malformed metadata | Reject; no fallback | Contract and concrete SDK |
| Ordered mixed contextual questions | Batch full outcomes equal scalar native outcomes in input order | Native scoped HTTP and concrete SDK |
| Too many rows, different chain, Workspace or namespace | Reject whole batch without partial results | Native HTTP |
| Personal mode or unsupported candidate access | Explicit unsupported capability; no ordinary-chain consent | Core, SDK and native HTTP |
| Missing, administrator, unowned, wildcard, foreign or revoked service credential | Refuse capability; exact current native read grant is required | Native HTTP |
| Current group/account changes | Recompute current native prerequisites; changed observation invalidates old plan | Native HTTP with real SQLite |
| Raw grant, role binding, scope, token or first namespace-owner mutation | Same-commit epoch change even without a PAP event-version change; reads and original intent replay remain stable | Shared Memory/SQLite/PostgreSQL fence conformance |
| Account identity provision or invitation acceptance | Account/binding creation and observation publish together; accepted invitation replay stays stable | Shared native fence conformance and SQL rollback fault |
| Epoch publication fails after a source write | Source row, membership, ownership and namespace pin roll back together with the fence | Real SQLite/PostgreSQL trigger fault |
| Memory epoch exhausted | Refuse before publishing Account or roster changes | Memory owner unit test |
| Epoch changes with unchanged event version | Hydrated native PDP re-reads current roles and rosters; no old Allow under new metadata | Native HTTP source-epoch regression |
| Policy epoch changes during shared admission | 503 without freshness or partial decisions | Native HTTP deterministic real-store race |
| Store failure | Unavailable rather than a cached decision or an empty plan | Native HTTP fault |
| Foreign profile contents change while native fence stays fixed | Scalar/batch/plan remain on native authority, including inherited ceilings | Mixed-source native HTTP |
| Foreign scoped declaration but native scoped owner absent | Unavailable; cannot enter legacy wildcard fallback or publish None | Mixed-source native HTTP with same-source absence control |
| Absent, malformed, duplicate or mismatched native freshness | Concrete SDK refuses response; positional result count must match | SDK transport tests |
| Embedded candidate read | Does not mutate policy version or create authorization | AuthzApi unit owner |
| Unsupported custom or embedded gate provider | Explicit capability refusal; endpoint hint is None | SDK defaults and host gate owner |
| Configured endpoint contains credential-bearing URL parts | Endpoint hint withheld; normal bearer configuration never appears in it | Concrete SDK source-hint test |

## Existing test owners

- [Contract](../../crates/awaken-iam-contract/src/resource_candidates.rs): closed
  wire shape, finite nested predicate validation.
- [Core](../../crates/awaken-iam-core/tests/resource_candidates.rs): native PDP
  superset oracle, scope/lineage/clock/budget behavior; rerun the existing
  permission-bundle owner because structural role matching is shared.
- [Scoped HTTP](../../crates/awaken-iam-server/tests/scoped_profile_http_e2e/resource_reads.rs):
  actual SQLite, current native repositories, authenticated HTTP and mixed-source
  counterexamples. Rerun the complete scoped-profile owner, registered-resource
  owner and personal scoped-membership caller for shared admission changes.
- [Fence race](../../crates/awaken-iam-server/tests/admin_http_e2e/freshness.rs):
  actual epoch mutation during native admission and legacy PDP refresh after
  raw native role/roster changes without a PAP version change.
- [Native source fence](../../crates/awaken-iam-server/tests/fence_e2e/authorization_sources.rs):
  shared Memory/SQLite/PostgreSQL source-write conformance, original namespace
  intent replay, and real SQL epoch-publication failures after source writes.
  The [memory owner](../../crates/awaken-iam-server/src/store/memory/authorization_sources.rs)
  separately checks exhaustion before data publication.
- [SDK transport](../../crates/awaken-iam-client/src/http/resource_reads_tests.rs),
  [consumer defaults](../../crates/awaken-iam-client/src/scoped_publication.rs)
  and [host gate](../../crates/awaken-iam-host/src/gate/scoped.rs): concrete
  metadata, context preservation, source hints and unsupported-provider behavior.

## Qualification and limits

Pure tests establish contract interpretation and native PolicySet equivalence.
SQLite HTTP tests establish real source/admission/fence composition. PostgreSQL
qualification must use its explicitly supplied test database and existing SQL
conformance owners; skipped fixture-dependent cases are not PostgreSQL evidence.
Shared native profile/capability changes require the affected scalar and
registered-resource regressions as well as the new endpoints.

A composing product must separately prove trusted owner/relations/predecessor
indexes, candidate SQL superset behavior, global ordering/keyset pagination,
current row/field PDP enforcement, source-domain comparisons and actual sparse
business reads. No source test substitutes for its deployed product acceptance.
Timing, scan amplification and memory claims require measured representative
workloads. An All plan is correct but does not establish sparse search speed.

Freshness is not a lease. Multi-time oracle fixtures cover expiry and clock
rollback; tests must not turn a prior Allow into reusable authority. Endpoint
qualification separates configured authorities, not independent databases behind
one URL or restore incarnations with reused counters. Operational source
continuity and supported native HA topology remain prerequisites.

## Recorded focused qualification

On 2026-11-10, an earlier affected-owner run completed on Linux with **503 passed,
0 failed and 2 ignored**. This covered the contract, Core candidate and existing
permission-bundle tests, concrete client and host, server library, native fence,
scoped/registered/personal HTTP, administrative HTTP and SQL-store owners.

The native fence owner completed all ten cases, including actual SQLite and
PostgreSQL source-write conformance and epoch-publication rollback faults.
PostgreSQL cases used a real PostgreSQL 16.15 instance with persistent storage,
`fsync`, `synchronous_commit` and `full_page_writes` enabled; they did not take
the missing-fixture return path. The native HTTP epoch-refresh cases also ran
against this database.

The two ignored server-library cases require the separate Flow channel probe
and PostgreSQL TLS/CA fixtures. They remain unverified by this focused run; it
does not establish channel composition or verified TLS behavior. These results
are affected-owner qualification, not the repository-wide gate, deployment
acceptance, migration rehearsal, or a throughput claim.
The counts qualify the source exercised by that run; candidate-selector changes
require renewed Core and native HTTP owner evidence.
