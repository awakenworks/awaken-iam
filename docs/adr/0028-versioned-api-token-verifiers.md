# ADR 0028 — Versioned API token verifiers

- **Status:** Proposed
- **Implementation:** done
- **Date:** 2026-11-12
- **Owner:** IAM Core API token minting and authentication

## Context

IAM generates each API token secret from 32 CSPRNG bytes. The public prefix
locates its persisted row. The original minter stores an Argon2 PHC string,
and both directory and repository authentication execute Argon2 per request.

A composing Flow debug-build fixture reached its 900-second setup timeout
while creating Resources through real HTTP. An eight-second userspace CPU
sample contained 355 samples with zero lost samples and concentrated in the
Argon2 block-filling stack. That observation qualifies this debug cohort.
Production throughput requires the composing product's actual build and load
measurement.

Automatically generated OAuth credentials require resistance to guessing.
IAM's 256-bit random secret exceeds the 128-bit minimum guessing-resistance
bound in RFC 6749 section 10.10. [RFC 6749](https://www.rfc-editor.org/rfc/rfc6749.html#section-10.10)

NIST's lookup-secret guidance uses an approved hash for stored secrets and
adds password hashing below its specified security-strength threshold. The
section concerns one-time lookup secrets. This decision applies its entropy
rationale to IAM-generated reusable bearer secrets. [NIST SP 800-63B-4](https://pages.nist.gov/800-63-4/sp800-63b.html#look-up-secret-verifiers)

## Decision

The existing [API token owner](../../crates/awaken-iam-core/src/api_token.rs)
stores newly minted verifiers in the existing `ApiToken.secret_hash` string
using the versioned representation `sha256:v1:<digest>`. The digest is exactly
32 bytes encoded as canonical unpadded base64url, yielding 43 characters.
The input to SHA-256 is the concatenation below.

```text
ASCII("awaken-iam/api-token/v1\0")
u64_big_endian(prefix_utf8_byte_length)
prefix_utf8_bytes
raw_32_byte_secret
```

The domain ends in one NUL byte. The length field binds the public prefix's
boundary. The minter obtains the secret through its existing `EntropySource`,
whose production adapter uses the OS CSPRNG, then encodes it for the presented
credential. The v1 verifier requires a canonical 43-character secret decoding
to exactly 32 bytes and compares the computed and stored 32-byte digests with
`subtle` constant-time equality. Unsupported versions, malformed encodings,
padding, truncation, wrong secrets and copied verifiers under another prefix
fail authentication.

Existing PHC verifiers follow the original Argon2 `PasswordVerifier` path,
including the historical presented-token scheme. New-format canonical secret
validation applies within the v1 branch. A stored PHC credential retains its
original verification cost until the operator rotates it.

Every repository-backed authentication loads the current row through
`ApiTokenRepository::get_by_prefix`, verifies its credential, and checks live
revocation and expiry. The existing principal, Workspace, role binding and PDP
owners determine authority. The verifier performs a read-only authentication
operation, so concurrent credential revocation has its existing store owner.

## Adoption and recovery

Deploy compatible readers to every node sharing the token repository before
new-format minting is admitted. Old binaries recognize their historical PHC
format. The composing deployment's quiesced cutover can stop the old cohort,
start the compatible cohort and then admit credential minting.

Rotate a stored credential through the existing mint command with a new token
id, verify that credential through its real authentication entry, and revoke
the previous token through its existing owner. Root credential rotation follows
the embedding product's existing startup protocol. Authentication itself writes
no replacement row.

A restored backup carries the verifier formats captured in that backup.
Recovery must pair its application readers with those formats. A downgrade
after minting v1 credentials requires compatible readers or credential
reissuance under the chosen recovery protocol.

## Validation

| Boundary | Required observation | Existing owner |
|---|---|---|
| Mint and verification | 32-byte generated secret, canonical persisted format, correct roundtrip, prefix binding | Core API token tests |
| Invalid input | Wrong secret, malformed digest/secret, unknown version, padding, truncation and noncanonical encoding refuse | Core API token tests |
| Historical rows | Original PHC verifier and presented-token scheme authenticate, with wrong-secret and malformed-hash refusal | Core API token tests |
| Current authority | Revocation, expiry boundary, Workspace attribution and policy evaluation remain observable through live entries | Core and server token tests |
| Persistence | Reopen retains both verifier formats, repository failure preserves its typed failure, revocation is visible through a separate handle | Existing SQL store token tests |
| Embedding product | Restart, root rotation, revoke and expire exercise stored authentication through real request middleware | Flow IAM engine token tests |
| Performance | Compare the same supported secret and verifier under dev/release profiles, then run original sparse and sustained HTTP owners | Core experiment and composing Flow E2E owners |

Repository integration uses IAM's existing `pnpm check` and normal Git hooks.
Observed hash timings cover credential verification. End-to-end load reports
include storage, policy evaluation and the product request path.

## Consequences

IAM keeps one private version dispatcher at its existing credential owner.
The persisted token field and repository ports carry both formats. SHA-256 and
constant-time comparison use the owner's existing dependencies.

The security argument relies on minting high-entropy random secrets. Any future
user-chosen or lower-entropy credential family needs its own verifier decision.
Bearer delivery, protected transport, credential disclosure handling and live
revocation remain part of the token lifecycle.
