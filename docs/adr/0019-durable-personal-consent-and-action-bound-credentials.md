# ADR-0019 - Durable personal consent and action-bound credentials

- **Status:** Proposed
- **Implementation:** done
- **Date:** 2026-11-04
- **Related:** ADR-0003, ADR-0014, ADR-0017

## Context

RFC 8693 delegation requires a live user token and expires within 300 seconds.
A service-account owner is accountability metadata, not consent to act as that
person. Persisting a person's refresh token in a product would create another
credential owner. Encoding consent in an authorization profile would let profile
rollback resurrect withdrawn consent. Consent is not a principal or a Role.

## Decision

IAM owns PersonalDelegation: immutable owner, recipient client and actual service,
audience, finite exact actions/scopes and validity window. Only a direct Account
token for audience `iam-personal-delegations` with scope
`iam.personal-delegation.manage` may create, read or revoke its own consent.
The recipient must be confidential, explicitly admitted by client scope
`iam.personal-delegation`, and have matching native delegation admission.

Consent grants no business permission. Recording consent cannot resolve product
amount, initiator or relationship facts. Every execution checks the current
human and service policy conjunctively with those native-owner facts; unavailable
facts remain unavailable and policy constraints remain effective. A client's
registration, account liveness and consent are checked on every compound use.

Authz migration 12 stores the immutable descriptor and first revocation stamp.
One repository implementation uses the shared SQL transaction seam for SQLite
and PostgreSQL. An owner's original request key identifies one exact creation
intent; replay returns the same current receipt before later validity/policy
gates. A different body conflicts. Revocation is monotonic and creation replay
cannot reset it. No product runtime data or user credential is stored here.

An authenticated recipient mints a separate `iam-personal-delegation+jwt`
family for one exact action, scope, opaque target ID/revision and purpose.
Its lifetime is at most 300 seconds; execution also ends at consent expiry.
Legacy bearer verification rejects the new family. Host opt-in signature
verification is restricted to remote IAM with configured issuer/audience; the
consumer must fence its concrete native route and target before accepting it.

`POST /v1/authorize/personal-delegation` verifies the signed binding, current
consent/account/client and exact human/service chain, then invokes the original
current PDP with owner-resolved ResourceAuthorizationRequest. A cached policy
or valid signature alone cannot establish live consent. Revocation therefore
denies already issued execution credentials on the next operation evaluation.

After expiry/revocation, the same admitted recipient may mint an
`original_outcome` credential bound to the original target and request key.
It never authorizes execution through the compound endpoint. Its consumer must
permit only the original outcome read, require current native read permission,
and match the accepted native audit's grant ID and original key. A missing
accepted effect is a negative lookup, never permission to retry a new write.

## Validation

`cargo test -p awaken-iam-server --test personal_delegation_e2e` covers SQL
concurrent intent creation, immutable body conflict, first-stamp revocation,
non-resurrection, direct owner consent, family/audience/expiry fencing, exact
target binding, current service policy withdrawal, immediate revocation and
read-only recovery minting. PostgreSQL conformance requires an explicitly
isolated `IAM_TEST_POSTGRES_URL`; absence is not PostgreSQL qualification.
The composing product separately qualifies native route fencing and original
outcome audit matching on its verified runtime cohort.
