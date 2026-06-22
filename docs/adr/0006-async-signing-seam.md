# ADR-0006 - The token signing seam is async

- **Status:** Proposed
- **Implementation:** done
- **Date:** 2026-06-23
- **Related:** ADR-0005

## Context

Token signing was factored behind a `Signer` seam so a managed deployment can
hold the issuer key in a KMS/HSM instead of an in-process Ed25519 seed (the open
repo keeps `LocalSeedSigner` for dev/self-host). The seam was introduced
**synchronously**: `Signer::sign(&[u8]) -> Result<Vec<u8>, SignerError>`.

A KMS/HSM signing operation is a remote (or device) round-trip. With a
synchronous `sign`, a KMS-backed signer must either block the async runtime for
the duration of every mint or hide a `block_on`, which starves the executor under
load. Since every token IAM issues — access tokens, OIDC `id_token`s, capability
tokens — is minted through `AccessTokenAuthority::sign_jwt` on a call path that is
already reachable from async axum handlers, the seam is better modelled async end
to end so the remote call yields the runtime instead of blocking it.

## Decision

We will make the signing seam **async**:

1. `Signer::sign` is `async fn sign(&self, &[u8]) -> Result<Vec<u8>, SignerError>`
   (the trait is `#[async_trait]` so it stays object-safe behind
   `Box<dyn Signer>`). `kid()` and `public_jwk()` stay synchronous — the public
   half is fetched once when the signer is built and cached, so JWKS publication
   never crosses the (possibly remote) signer boundary.
2. The whole minting path is async: `AccessTokenAuthority::{sign_jwt, mint,
   sign_claims}`, the free functions `mint_capability` / `attenuate` /
   `mint_id_token`, and the `AuthApi` grant methods (`mint_access_token`,
   `exchange_token`, `issue_token_grant`, `redeem_op_code`,
   `refresh_token_grant`, `op_refresh_token_grant`,
   `redeem_authorization_code`). It terminates at the already-async axum layer.
3. `LocalSeedSigner` implements the async seam with an immediate (non-blocking)
   local signature, so the open repo self-hosts unchanged.

## Consequences

- Easier: a KMS/HSM signer does its remote round-trip without blocking the
  runtime; one signing path still covers every token family and rotation; the
  open repo is unaffected via `LocalSeedSigner`.
- Harder: the minting path is async throughout, so its callers and tests run on a
  Tokio runtime (`#[tokio::test]`), and `#[async_trait]` adds a boxed-future
  allocation per sign — negligible next to a network/KMS call.
- New dependency: `async-trait` in `awaken-iam-server`.

## Alternatives considered

- **Keep `sign` synchronous, block inside the KMS signer:** rejected — it blocks
  an executor thread per mint (or hides a `block_on`), degrading throughput
  exactly when issuance is busy.
- **Native `async fn` in trait (no `async-trait`):** rejected — return-position
  `impl Trait` in trait methods is not object-safe, and the seam must be
  `Box<dyn Signer>` to inject an arbitrary signer; `async-trait` keeps it dyn-safe.
- **A blocking-thread offload (`spawn_blocking`) at each call site:** rejected —
  it pushes the concern to every caller and still wraps a fundamentally async
  remote call in a thread; an async seam expresses it once, correctly.
