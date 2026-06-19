# Awaken IAM

`awaken-iam` is the shared identity, authorization, scope, and entitlement control plane for AwakenWorks services such as Oversight Cloud, Awaken Next Cloud, and Oversight Pack Hub.

## Scope

Awaken IAM owns shared control-plane concepts:

- global accounts and sessions;
- organizations / owners and memberships;
- namespaces for package publishing;
- workspace and project scope references;
- grants and authorization decisions;
- entitlement checks;
- API token/session contract shapes.

Product runtimes still own their domain data: Issues, Workflows, WorkProducts, connector bindings, credentials, runs, and package blobs.

## Development

```sh
pnpm install
pnpm hooks:install
pnpm check
```
