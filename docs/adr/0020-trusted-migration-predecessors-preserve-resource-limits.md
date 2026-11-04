# ADR 0020: Trusted migration predecessors preserve exact resource limits

- **Status:** Proposed
- **Implementation:** done — `awaken-iam-contract/src/resource_authorization.rs`, `awaken-iam-core/src/authorization/constraints.rs` (workspace checks and PostgreSQL qualification passed).

Replacing a product Resource with a differently identified aggregate must not
silently discard an existing exact-resource binding. Ownership and team facts
remain product-owned; IAM must not copy the product's records or store lineage.

`AuthorizationContext.predecessors` carries at most 32 immutable predecessors,
proved by the operation owner. Each contains its original ID and the same scope
as the current operation. The actual target ID remains `resource_id`. Missing
target identity, cross-scope predecessors, duplicates and malformed lists cannot
satisfy a predecessor-based exact-resource limit.

The existing policy evaluator may match a binding's `resource_ids` against a
qualified predecessor. This applies equally to deny and approval effects. It
does not grant an action, introduce a role, expand a scope, bypass a live Group,
change ownership, suppress a field restriction, remove an expiry, or revive a
revoked delegation. Consumers must still explicitly adopt the replacement
type's action permissions. An empty predecessor list keeps existing behavior
and is omitted from the wire representation.

Only a trusted operation owner may supply these facts. A product must fence the
retired source, exact target, same-scope lineage and allowed type/revision pair
in its own immutable migration protocol. Resource properties, browser flags and
caller-supplied predecessor IDs are not proof. Flow retains the real migration
actor separately from inherited business relationships and creation history.

The regression `qualified_predecessors_preserve_exact_resource_limits_without_creating_permissions`
in `awaken-iam-core/tests/permission_bundles.rs` exercises exact limits, foreign
scope, duplicates, bounds, ownership, expiry, undeclared actions and explicit deny.
