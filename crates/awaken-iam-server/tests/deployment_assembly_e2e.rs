//! End-to-end check that one assembly ships both deployments.
//!
//! The [deployment design](../../../docs/design/deployment.md) promises two
//! deployments from one assembly: *embedded* (a library on the host's pool whose
//! in-process callers use the local [`IamClient`]) and *standalone* (the
//! `iam-daemon` on its own pool whose callers use the remote [`IamClient`]). This
//! test stands both up from the shared [`IamAssembly`] over the same migration
//! executor seam, configures the identical grant policy into each, and proves the
//! local in-process answer equals the answer a remote caller gets over the wire —
//! the mirror the design guarantees, with only the pool and the client mode
//! differing.

use awaken_iam_client::{AuthzTransport, IamClient, IamClientMode, RemoteError, RemoteIamClient};
use awaken_iam_contract::{
    AuthorizationOutcome, AuthorizationRequest, BatchAuthorizationRequest,
    BatchAuthorizationResponse, EntitlementCheckResponse, EntitlementRequest, NamespaceId,
    PolicySnapshot, ResourceModelRegistered, ResourceModelRegistration, SignerSetSnapshot,
};
use awaken_iam_server::{
    AuthzApi, Deployment, IamAssembly, IamDaemon, RecordingExecutor, RouteSpec,
};

use awaken_iam_contract::{ActionKey, AuthorizationDecision, PrincipalRef, ScopeRef};
use awaken_iam_core::{ActionPattern, Effect, Grant, GrantId, GrantSubject};

fn service(id: &str) -> PrincipalRef {
    PrincipalRef::Service {
        service_id: id.into(),
    }
}

fn request(action: &str) -> AuthorizationRequest {
    AuthorizationRequest::direct(service("svc"), ActionKey(action.into()), ScopeRef::Global)
}

/// Grant `svc` the `pack.*` family at global scope, the shared policy both
/// deployments are configured with.
fn grant_pack_family(authz: &mut AuthzApi) {
    authz.policy_mut().add_grant(Grant {
        id: GrantId("g1".into()),
        subject: GrantSubject::Principal(service("svc")),
        action_pattern: ActionPattern("pack.*".into()),
        scope: ScopeRef::Global,
        effect: Effect::Allow,
    });
}

/// Remote transport that reaches the standalone daemon's [`AuthzApi`] across a
/// JSON hop, modelling the wire without a socket. Borrows the daemon's API so the
/// remote client and the daemon share one policy, exactly as a real deployment.
struct DaemonTransport<'a> {
    api: &'a AuthzApi,
}

impl AuthzTransport for DaemonTransport<'_> {
    fn authorize(
        &self,
        request: &AuthorizationRequest,
    ) -> Result<AuthorizationOutcome, RemoteError> {
        let body = serde_json::to_string(request).map_err(|e| RemoteError(e.to_string()))?;
        let parsed = serde_json::from_str(&body).map_err(|e| RemoteError(e.to_string()))?;
        Ok(self.api.authorize(&parsed))
    }

    fn authorize_batch(
        &self,
        request: &BatchAuthorizationRequest,
    ) -> Result<BatchAuthorizationResponse, RemoteError> {
        let body = serde_json::to_string(request).map_err(|e| RemoteError(e.to_string()))?;
        let parsed = serde_json::from_str(&body).map_err(|e| RemoteError(e.to_string()))?;
        Ok(self.api.authorize_batch(&parsed))
    }

    fn check_entitlement(
        &self,
        request: &EntitlementRequest,
    ) -> Result<EntitlementCheckResponse, RemoteError> {
        let body = serde_json::to_string(request).map_err(|e| RemoteError(e.to_string()))?;
        let parsed = serde_json::from_str(&body).map_err(|e| RemoteError(e.to_string()))?;
        Ok(self.api.check_entitlement(&parsed))
    }

    fn register_resource_model(
        &self,
        _registration: &ResourceModelRegistration,
    ) -> Result<ResourceModelRegistered, RemoteError> {
        // This parity fixture borrows the daemon's API immutably to compare
        // decisions; registration is a mutating endpoint exercised in the remote
        // protocol e2e instead.
        Err(RemoteError(
            "registration not exercised by this fixture".into(),
        ))
    }

    fn fetch_snapshot(&self) -> Result<PolicySnapshot, RemoteError> {
        Ok(self.api.snapshot())
    }

    fn fetch_signers(&self, namespace_id: &NamespaceId) -> Result<SignerSetSnapshot, RemoteError> {
        Ok(self.api.signers(namespace_id))
    }
}

#[test]
fn embedded_and_standalone_decide_identically_from_one_assembly() {
    // Embedded: host pool, local client.
    let mut embedded = IamAssembly::embedded(RecordingExecutor::new()).expect("embedded assembly");
    grant_pack_family(embedded.authz_mut());
    assert_eq!(embedded.deployment(), Deployment::Embedded);
    assert!(embedded.deployment().is_local_client());
    let local: IamClientMode<&AuthzApi, RemoteIamClient<DaemonTransport>> =
        IamClientMode::Local(embedded.local_client());
    assert!(local.is_local());

    // Standalone: the daemon's own pool, remote client.
    let mut daemon = IamDaemon::start(RecordingExecutor::new()).expect("standalone daemon");
    grant_pack_family(daemon.assembly_mut().authz_mut());
    assert_eq!(daemon.assembly().deployment(), Deployment::Standalone);
    assert!(!daemon.assembly().deployment().is_local_client());
    let remote_client = RemoteIamClient::new(DaemonTransport {
        api: daemon.assembly().authz(),
    });
    let remote: IamClientMode<&AuthzApi, RemoteIamClient<DaemonTransport>> =
        IamClientMode::Remote(remote_client);
    assert!(remote.is_remote());

    // The local (embedded) and remote (standalone) answers match action for
    // action — the deployment is a configuration choice, not a behaviour change.
    for action in ["pack.publish", "pack.read", "image.push", "org.manage"] {
        let local_decision = local.authorize(request(action));
        let remote_decision = remote.authorize(request(action));
        assert_eq!(
            local_decision, remote_decision,
            "embedded and standalone disagree on {action}"
        );
    }
    // And the granted family is actually allowed, the rest denied — proving the
    // shared policy is live in both, not a vacuous all-deny match.
    assert_eq!(
        local.authorize(request("pack.publish")),
        AuthorizationDecision::Allow
    );
    assert_eq!(
        remote.authorize(request("image.push")),
        AuthorizationDecision::Deny
    );
}

#[test]
fn both_deployments_mount_the_shared_v1_surface() {
    let embedded = IamAssembly::embedded(RecordingExecutor::new()).expect("embedded");
    let daemon = IamDaemon::start(RecordingExecutor::new()).expect("daemon");

    // The shared /v1 surface both deployments mount spans both halves of /v1 from
    // the one assembly.
    let routes = embedded.routes();
    assert!(routes.contains(&RouteSpec {
        method: awaken_iam_server::HttpMethod::Post,
        path: "/v1/authorize",
    }));
    assert!(routes.contains(&RouteSpec {
        method: awaken_iam_server::HttpMethod::Get,
        path: "/v1/session",
    }));

    // Every embedded route is also mounted by the standalone daemon: the shared
    // surface is identical, the daemon only adds to it.
    for spec in embedded.routes() {
        assert!(
            daemon.routes().contains(&spec),
            "standalone must also mount the shared route {}",
            spec.path
        );
    }

    // The policy-administration management seam is standalone-only: the daemon
    // serves /v1/admin/* over the wire, the embedded host does not.
    assert!(daemon.routes().contains(&RouteSpec {
        method: awaken_iam_server::HttpMethod::Post,
        path: "/v1/admin/orgs",
    }));
    assert!(
        embedded
            .routes()
            .iter()
            .all(|r| !r.path.starts_with("/v1/admin")),
        "embedded must not mount the admin seam over HTTP"
    );
}

#[test]
fn a_drifted_ledger_aborts_assembly_in_both_modes() {
    let mut embedded_executor = RecordingExecutor::new();
    embedded_executor.force_checksum("iam.authz", "0001_authz", "deadbeef");
    assert!(IamAssembly::embedded(embedded_executor).is_err());

    let mut standalone_executor = RecordingExecutor::new();
    standalone_executor.force_checksum("iam.authz", "0001_authz", "deadbeef");
    assert!(IamDaemon::start(standalone_executor).is_err());
}
