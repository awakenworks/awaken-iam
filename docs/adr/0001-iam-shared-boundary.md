# ADR-0001 - IAM as shared control plane

- **Status:** Proposed
- **Implementation:** planned
- **Date:** 2026-06-22

## Context

Oversight Cloud, Awaken Next Cloud, and Oversight Pack Hub all need the same identity, organization, namespace, workspace, grant, and entitlement concepts. Duplicating those concepts in each product would fragment login, publishing permissions, installation permissions, and audit identities.

## Decision

`awaken-iam` is the shared control-plane boundary for global accounts, organizations, namespace ownership, scope references, grants, authorization decisions, API/session claims, and entitlement checks.

Product services remain owners of their runtime domain data. IAM does not store or execute Issues, Workflows, WorkProducts, connector credentials, package blobs, or agent runs.

## Consequences

Shared contract types live in `awaken-iam-contract`. Core grant/scope evaluation lives in `awaken-iam-core`. Product services integrate through `awaken-iam-client` or future protocol endpoints, not through server internals.
