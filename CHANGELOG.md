# Changelog

## 0.1.0-dev

- The token signing seam (`Signer`) is now async, so a KMS/HSM-backed signer can
  do a remote round-trip without blocking the runtime; `LocalSeedSigner` stays the
  in-process self-host default. The whole minting path is async (ADR-0006).
- Release/versioning contract: the repo is consumed at immutable `vX.Y.Z` tags;
  see RELEASING.md and ADR-0007.
- Initial repository scaffold.
