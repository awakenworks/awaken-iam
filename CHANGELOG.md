# Changelog

## 0.2.0-dev

_(unreleased; no release or publication is implied)_

- Breaking Rust API: `AuthReject` and `AuthError` include `Unavailable`.
  Credential rejection stays distinct from an unavailable authentication or
  authorization authority; the shared HTTP middleware maps the latter to 503.
- Breaking Rust API: `RemoteError` has private diagnostic/status fields with
  `new`, `response`, `message`, and `status` accessors instead of a public tuple
  constructor/field. HTTP status comes from the existing transport response;
  diagnostic strings are not authorization evidence.
- Breaking Rust API: browser attachment/builders and bulk service-account token
  revocation return `Result` through their existing methods. Poisoned locks are
  refused without recovery, partial browser exchange, or empty-success revoke.
- Existing JWT verification remains independent of mutable Local IAM state;
  protected routes still evaluate the same PDP through its fallible interface.

## 0.1.2-dev

_(unreleased)_

- The original Gate decision `Result` methods preserve local poison and remote
  unavailability; legacy infallible decisions remain fail-closed.

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
