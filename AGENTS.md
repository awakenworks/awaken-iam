# AGENTS.md

Shared instructions for AI agents working in this repository.

## Project

- **Name:** Awaken IAM — shared identity, authorization, scope, and entitlement control plane.
- **Version:** `0.1.0-dev` (pre-release; APIs unstable, crates unpublished).
- **File size limit:** keep source files under ~2000 lines; split before then.

## Core rules

- Ship production-ready code. No placeholders, dead scaffolding, or hidden runtime shortcuts.
- Search before adding. Prefer extending existing crates and contracts over duplication.
- IAM owns identity/authorization/entitlement contracts and evaluation only; it must not own product runtime data such as Issues, Workflows, WorkProducts, connector credentials, or pack blobs.
- Work in logical sections: implement, test, verify, then commit.

## Architecture guardrails

- **G1 — Contract boundary.** `awaken-iam-contract` contains shared DTOs only and must not depend on `awaken-iam-core`, `awaken-iam-client`, or `awaken-iam-server`. _Enforcer:_ `xtask guardrail-lints`.
- **G2 — Core/server boundary.** `awaken-iam-core` may depend on `awaken-iam-contract`, but not on `awaken-iam-server`. _Enforcer:_ `xtask guardrail-lints`.
- **G3 — Client/server boundary.** `awaken-iam-client` may depend on contract types, but not on server implementation. _Enforcer:_ `xtask guardrail-lints`.
- **G4 — No product runtime ownership.** IAM crates must not depend on product runtime crates (`oversight-*`, `awaken-next-*`, `oversight-pack-hub-*`) unless an explicit future ADR introduces a contract-only dependency. _Enforcer:_ `xtask guardrail-lints`.
- **G5 — No secrets in source.** No API keys, tokens, or passwords in tracked files. _Enforcer:_ `scripts/ci/check_secrets.py`.

## Documentation ownership

| Location | Owns |
|---|---|
| `docs/adr/` | Architecture decisions |
| `docs/design/` | Long-lived design |
| `contracts/` | Generated/published protocol contracts |
| `AGENTS.md` | Agent rules and guardrail index |

## Validation

Prefer the narrowest useful check. Before handoff, run relevant subsets; for broad changes run `pnpm check`.
