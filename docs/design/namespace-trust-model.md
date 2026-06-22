# Namespace trust model

This document defines how `awaken-iam` owns namespace identity, ownership, and
the namespace-to-signer binding that a publishing/registry consumer's signature
and trust model depends on. It extends [IAM model](iam-model.md) at
`ScopeRef::Namespace`.

## Split of responsibility

```text
awaken-iam owns          |  the registry service owns
-------------------------|----------------------------------
namespace ownership       |  package blobs / CAS
signer registration       |  per-file blake3 + content_hash
namespace -> signer set   |  pack.lock canonicalization
authorize(publish/signer) |  signature verification at publish/download
```

IAM answers *who may publish under this namespace and with which signer
identity*. the registry service performs the cryptographic verification and stores artifacts.
IAM never sees blobs; the registry service never stores grants.

## Records

```text
Namespace {
  id,                # NamespaceId, the publishing scope
  org_id,            # owning org (governance/billing)
  status,            # active | suspended
  created_at,
}

Signer {
  id,
  namespace_id,
  public_key,        # ed25519 verifying key (public material only)
  key_format,        # e.g. "ed25519"
  label?,
  status,            # active | revoked
  registered_by,     # PrincipalRef that registered the key
  registered_at,
  revoked_at?,
}
```

A namespace has one or more active signers. IAM stores only **public** key
material; private keys never reach IAM (it is not a secrets store). Revocation is
a status flip, idempotent, and is the trust-root signal the registry service reads at
verification time.

## Actions and scope

All checks resolve `ScopeRef::Namespace { namespace_id }`:

```text
namespace.manage          # create/configure the namespace, transfer ownership
namespace.signer.manage   # register / revoke signer keys
namespace.signer.use      # publish under a specific registered signer
pack.publish              # publish a version into the namespace
pack.yank                 # yank a version
pack.read                 # read / resolve / list (private namespaces)
```

Role bundles at namespace scope (from [IAM model](iam-model.md#grant-and-rolebinding)):
`namespace_owner`, `publisher`, `maintainer`, `reader`, `signer_admin`.

## Publish authorization flow

```text
the registry service receives: principal, namespace, signer_key_id, pack.lock

1. authorize(principal, pack.publish,          namespace)   -> allow/deny
2. authorize(principal, namespace.signer.use,  namespace)   -> allow/deny
3. signer = iam.lookup_signer(namespace, signer_key_id)
   reject if signer is absent, revoked, or namespace-mismatched
4. check_entitlement(principal, pack.publish, "<namespace>/<pkg>")  # plan/private
5. the registry service verifies the ed25519 signature over pack.lock with signer.public_key
6. the registry service stores blobs + content_hash; IAM is not involved past step 4
```

Steps 1–4 are IAM; steps 5–6 are the registry service. The signer lookup (step 3) is the new
surface this model adds: it binds an authorization decision to a concrete trust
anchor, so "allowed to publish" and "publishing with a trusted key" cannot drift
apart.

## Trust-root distribution

the registry service fetches a namespace's active signer set (and revocations) from IAM and
may cache it under the snapshot `version` fence
([authorization engine](authorization-engine.md#snapshot)). Download-time
verification uses the same cached set, so offline/edge verification stays
possible while revocation still propagates on the next sync.

## Lookup API

```rust
fn lookup_signer(&self, ns: &NamespaceId, key_id: &SignerId) -> Option<Signer>;
fn active_signers(&self, ns: &NamespaceId) -> Vec<Signer>;
```

Exposed over the [remote protocol](remote-protocol.md) for the standalone Pack
Hub service and in-process for the embedded role.

## Out of scope

- Signature creation, `pack.lock` canonicalization, and content hashing — Pack
  Hub.
- Private-key custody — never in IAM.
- Paid/private visibility policy — the [entitlement plane](entitlements.md).
