# Changelog

## 0.1.2-dev

_(unreleased)_

## 0.1.1 - 2026-07-01

- Facade crate (`awaken-iam`) re-exports the full consumed surface: access-token
  value types, license-claim types, GitHub/Google login provider adapters, and the
  persistent-store contract shapes, so consumers can depend on the single
  `awaken-iam` entry point at an immutable tag rather than pinning an internal
  SHA rev.
- The token signing seam (`Signer`) is now async, so a KMS/HSM-backed signer can
  do a remote round-trip without blocking the runtime; `LocalSeedSigner` stays the
  in-process self-host default. The whole minting path is async (ADR-0006).
- Release/versioning contract: the repo is consumed at immutable `vX.Y.Z` tags;
  see RELEASING.md and ADR-0007.
- Initial repository scaffold.
