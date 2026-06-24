# ADR-0004 - Namespace-to-signer ownership is IAM's, not the registry's

- **Status:** Proposed
- **Implementation:** planned
- **Date:** 2026-06-24
- **Related:** ADR-0001, ADR-0002

## Context

Two designs describe the namespace-to-signer binding — the record that says
*which public signing keys are trusted to sign on a namespace's behalf* — and
both currently read as if they store it.

On the IAM side, [the namespace trust model](../design/namespace-trust-model.md)
makes the binding a first-class IAM record: `Signer` rows hang off a
`Namespace`, registration and revocation are `namespace.signer.manage` actions,
and the model exposes `lookup_signer(ns, key_id)` and `active_signers(ns)` as the
verification-time surface. This is already built: `awaken-iam-contract` defines
`SignerKey` / `SignerKeyId` / `SignerKeyFingerprint` / `SignerKeyStatus`, and
`awaken-iam-core::trust::NamespaceTrustDirectory` holds the bindings and answers
the lookups.

On the registry side, the publishing/registry service (Pack Hub) has a storage
model that *also* names the binding — `SignerMetadata` and a `NamespaceSigner`
association — so that download-time and publish-time verification can read a
key's status without a network hop. Read literally, that makes the registry a
second writer of the same fact: register a key in IAM and the registry's table is
stale; register it in the registry and IAM's grant/authorization view is stale.
A revoked key that is honored anywhere is a trust-root failure, so a binding with
two authoritative writers is not a tidiness problem — it is a security defect.

Nothing depends on the duplication yet (the registry adapter is not built), so
this is a boundary decision to make once, not a migration to unwind.

## Decision

1. **`awaken-iam` is the single source of truth for the namespace-to-signer
   binding.** The authoritative records are IAM's `NamespaceOwner` and
   `SignerKey` (public key material, fingerprint, status, lifecycle timestamps),
   held behind the core's trust port. Registration and revocation happen only
   through IAM's `namespace.signer.manage` action. There is exactly one writer of
   *who may sign for a namespace*, and it is IAM. This follows directly from
   ADR-0001: signer registration is identity/trust, which IAM owns, not product
   runtime data, which it must not.

2. **The registry never persists the binding as authoritative.** Pack Hub's
   `SignerMetadata` / `NamespaceSigner` are reframed as a **read-only projection**
   of IAM's signer set, not a system of record. The registry MAY cache the active
   signer set (and revocations) it reads from IAM for offline/edge verification,
   but a cache is derived state: it is never written by the registry's own API,
   carries no independent lifecycle, and is reconciled from IAM, never merged back.
   This removes the double-write entirely — there is no second writer to drift.

3. **The binding crosses the boundary as a contract read, fenced by the snapshot
   version.** The registry obtains signers through `lookup_signer` /
   `active_signers` — in-process for the embedded role, over the
   [remote protocol](../design/remote-protocol.md) for the standalone role — and
   caches them under the authorization snapshot `version` fence
   ([authorization engine](../design/authorization-engine.md#snapshot)), so a
   revocation propagates on the next sync and download-time verification stays
   possible offline. The cache freshness rides the same fence the rest of IAM's
   read model does; it does not invent its own consistency story.

4. **The split of cryptographic responsibility is unchanged.** IAM stores only
   **public** key material and answers *who may sign*; the registry performs
   signature creation/verification, `pack.lock` canonicalization, and content
   hashing, and stores blobs. Private-key custody is never IAM's. This ADR moves
   no crypto into IAM and no grants into the registry; it only names which side
   *owns the row* the other side *reads*.

## Consequences

- The registry's storage model drops `SignerMetadata` / `NamespaceSigner` as
  owned tables and keeps, at most, a clearly-labelled cache of IAM's signer set
  keyed by namespace and fingerprint, invalidated by the snapshot version. Its
  publish/download paths read the binding through the IAM seam, not a local
  source of truth.
- No new IAM surface is needed: the trust directory, the `SignerKey` contract
  types, and the `lookup_signer` / `active_signers` API already satisfy the
  reader. Guardrails **G1** and **G4** hold — no registry runtime vocabulary
  enters `awaken-iam-contract`, and IAM gains no dependency on the registry.
- Revocation has a single authoritative effect: flipping a key to `Revoked` in
  IAM is the one trust-root signal, and every reader observes it on the next
  fence advance. There is no path by which a key revoked in IAM stays honored in
  a registry-owned table.
- A future second registry-style consumer is the same seam: it reads
  `active_signers` and caches under the fence, never adding a third writer.
