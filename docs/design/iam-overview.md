# IAM overview

Awaken IAM provides a shared control plane for identity, authorization, scope references, and entitlement checks across AwakenWorks services.

## Owns

- Global accounts and session/API-token claims.
- Organization / owner identity and membership.
- Namespace ownership for package publishing.
- Scope references for org, namespace, workspace, and project.
- Arbitrary user-visible Directory placement of stable product spaces inside an Org partition.
- Grants and authorization decisions.
- Entitlement check contracts.

## Does not own

- Oversight Issues, Workflows, WorkProducts, FlowInstallations, ConnectorBindings, or CredentialSources.
- Pack Hub package blobs or component indexes.
- Awaken runtime execution state.
- Product-space business lifecycle or data; Directory stores placement only.
