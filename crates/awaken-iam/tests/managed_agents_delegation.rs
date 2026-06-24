//! Managed-agents cutover contract test, exercised against the **real** IAM
//! engines through the public `awaken-iam` facade — the surface awaken-next's
//! managed agents integrate against.
//!
//! Where `consumer_support.rs` proves the entitlement plane alone gates *who* may
//! run an agent, which model tier, and how many runs, this test pins the second
//! half of the managed-agents reuse described in
//! `docs/adr/0004-consumers-reuse-iam-authz.md`: once a parent agent's run clears
//! the entitlement gate, it delegates to a sub-agent / sandbox with an
//! **attenuated capability token** (permission mechanism 7). The parent mints a
//! scope-narrowed, epoch-fenced token and derives a child that holds *strictly
//! less* authority for a *bounded* time; the sandbox verifies it holder-
//! independently against the published JWKS; and advancing the sandbox lease epoch
//! fences every outstanding token out at once.
//!
//! Both planes stay independent and reused, not reimplemented: entitlement
//! answers eligibility, capability tokens carry delegated runtime authority, and
//! IAM owns neither the run loop nor the in-sandbox enforcement.

use awaken_iam::{
    AccessTokenAuthority, AttenuateCapability, CapabilityCheck, CapabilityError,
    EntitlementCatalog, EntitlementDecision, EntitlementEngine, EntitlementRequest, LeaseEpoch,
    LocalSeedSigner, MintCapability, Plan, PlanId, PlanTier, PrincipalRef, Quota, attenuate,
    mint_capability, verify_capability,
};

fn agent(id: &str) -> PrincipalRef {
    PrincipalRef::Service {
        service_id: id.into(),
    }
}

/// The IAM deployment's signing authority. A capability token is signed by the
/// same asymmetric key as an access token and verified against the same published
/// JWKS, so a sandbox needs only the public keys to check a delegated token.
fn authority() -> AccessTokenAuthority {
    AccessTokenAuthority::new(LocalSeedSigner::new("iam-cap-key-1", [7u8; 32]))
}

/// The managed-agents run gate: a parent may run only when the entitlement plane
/// allows the `agent.run` feature, the requested model tier, and the metered run
/// count is within the plan's quota. Mirrors the gate awaken-next applies before
/// it spends any runtime authority on a parent agent.
fn parent_may_run(
    engine: &EntitlementEngine,
    parent: &PrincipalRef,
    model_tier: &str,
    observed_runs: u64,
) -> bool {
    let req = |feature: &str| EntitlementRequest {
        principal: parent.clone(),
        entitlement: feature.into(),
        resource: Some("workspace:ws_acme".into()),
    };
    let may_run = engine.check_entitlement(&req("agent.run")) == EntitlementDecision::Allow;
    let may_use_model = engine.check_entitlement(&req(model_tier)) == EntitlementDecision::Allow;
    let within_quota = engine
        .check_quota(&req("agent.run"), observed_runs)
        .decision
        == EntitlementDecision::Allow;
    may_run && may_use_model && within_quota
}

const IAT: i64 = 1_900_000_000;
const PARENT_EXP: i64 = 1_900_003_600;

/// The runtime authority a parent agent carries into its sandbox lease, minted as
/// a root capability the parent can later attenuate for its sub-agents.
fn parent_capability(epoch: LeaseEpoch) -> MintCapability {
    MintCapability {
        iss: "https://iam.example".into(),
        sub: "agent:planner".into(),
        aud: "awaken-sandbox-runner".into(),
        jti: "cap-planner-root".into(),
        iat: IAT,
        exp: PARENT_EXP,
        epoch,
        scope: vec![
            "fs.read".into(),
            "fs.write".into(),
            "net.fetch".into(),
            "model.invoke".into(),
        ],
        obligation: None,
    }
}

/// End-to-end managed-agents cutover: the entitlement plane gates the parent run,
/// then the parent delegates a strictly-narrower capability to a sub-agent the
/// sandbox verifies on its own. The two planes compose; neither is reimplemented.
#[tokio::test]
async fn managed_agent_gates_run_then_delegates_attenuated_capability() {
    // --- Plane 1: entitlement gates the parent run (reused, already proven). ---
    let planner = agent("agent:planner");
    let free = agent("agent:free-runner");

    let mut catalog = EntitlementCatalog::new();
    catalog.upsert_plan(
        Plan::new(
            PlanId("team".into()),
            PlanTier::Team,
            ["agent.run", "model.strong_access"],
        )
        .with_quota("agent.run", Quota::Limited(50)),
    );
    catalog.assign(planner.clone(), PlanId("team".into()));
    let engine = EntitlementEngine::local(catalog);

    // The entitled planner clears the gate; a free runner with no plan fails
    // closed and never reaches delegation.
    assert!(parent_may_run(&engine, &planner, "model.strong_access", 3));
    assert!(!parent_may_run(&engine, &free, "model.strong_access", 0));
    // A tier the plan does not carry is refused even for the entitled planner.
    assert!(!parent_may_run(
        &engine,
        &planner,
        "model.frontier_access",
        0
    ));

    // --- Plane 2: the cleared parent delegates to a sub-agent / sandbox. ---
    let authority = authority();
    let epoch = LeaseEpoch::initial();
    let parent_token = mint_capability(&authority, parent_capability(epoch))
        .await
        .unwrap();

    // The parent hands a sub-agent strictly less authority for a bounded time: a
    // subset scope, a distinct delegate subject, and an earlier expiry.
    let child_token = attenuate(
        &authority,
        &parent_token,
        epoch,
        IAT + 1,
        AttenuateCapability {
            jti: "cap-subagent".into(),
            iat: IAT + 1,
            exp: IAT + 600,
            scope: vec!["fs.read".into(), "model.invoke".into()],
            sub: Some("agent:planner/sub:summarize".into()),
        },
    )
    .await
    .unwrap();

    // The sandbox verifies the delegated token holder-independently, using only
    // the published JWKS plus the current lease epoch.
    let claims = verify_capability(
        &child_token,
        &authority.jwks(),
        CapabilityCheck {
            audience: "awaken-sandbox-runner",
            epoch,
            now: IAT + 2,
        },
    )
    .unwrap();
    assert_eq!(claims.sub, "agent:planner/sub:summarize");
    assert_eq!(claims.parent.as_deref(), Some("cap-planner-root"));
    assert_eq!(
        claims.scope,
        vec!["fs.read".to_owned(), "model.invoke".into()]
    );
    assert!(
        claims.exp <= PARENT_EXP,
        "the child never outlasts its parent"
    );
}

/// A sub-agent can never gain authority its parent lacked: attenuation only
/// narrows scope and only shortens the bounded window — both fail closed.
#[tokio::test]
async fn delegation_only_narrows_never_widens() {
    let authority = authority();
    let epoch = LeaseEpoch::initial();
    let parent_token = mint_capability(&authority, parent_capability(epoch))
        .await
        .unwrap();

    // A scope the parent never held cannot be added by a child.
    let widened = attenuate(
        &authority,
        &parent_token,
        epoch,
        IAT + 1,
        AttenuateCapability {
            jti: "cap-subagent".into(),
            iat: IAT + 1,
            exp: IAT + 600,
            scope: vec!["fs.read".into(), "admin.all".into()],
            sub: None,
        },
    )
    .await
    .unwrap_err();
    assert_eq!(widened, CapabilityError::ScopeNotSubset);

    // A child may not outlast the parent's bounded delegation window.
    let extended = attenuate(
        &authority,
        &parent_token,
        epoch,
        IAT + 1,
        AttenuateCapability {
            jti: "cap-subagent".into(),
            iat: IAT + 1,
            exp: PARENT_EXP + 1,
            scope: vec!["fs.read".into()],
            sub: None,
        },
    )
    .await
    .unwrap_err();
    assert_eq!(extended, CapabilityError::ExpiryNotBounded);
}

/// Re-provisioning the sandbox advances the lease epoch, which fences every
/// outstanding delegated token out at once — a stale sub-agent token stops
/// verifying and a stale parent can no longer mint new sub-agents.
#[tokio::test]
async fn advancing_the_sandbox_lease_revokes_outstanding_delegations() {
    let authority = authority();
    let epoch = LeaseEpoch::initial();
    let parent_token = mint_capability(&authority, parent_capability(epoch))
        .await
        .unwrap();
    let child_token = attenuate(
        &authority,
        &parent_token,
        epoch,
        IAT + 1,
        AttenuateCapability {
            jti: "cap-subagent".into(),
            iat: IAT + 1,
            exp: IAT + 600,
            scope: vec!["fs.read".into()],
            sub: None,
        },
    )
    .await
    .unwrap();
    let jwks = authority.jwks();

    // Valid at the epoch it was minted under.
    verify_capability(
        &child_token,
        &jwks,
        CapabilityCheck {
            audience: "awaken-sandbox-runner",
            epoch,
            now: IAT + 2,
        },
    )
    .unwrap();

    // The sandbox lease advances; the outstanding sub-agent token is fenced out.
    let next = epoch.next();
    let fenced = verify_capability(
        &child_token,
        &jwks,
        CapabilityCheck {
            audience: "awaken-sandbox-runner",
            epoch: next,
            now: IAT + 2,
        },
    )
    .unwrap_err();
    assert_eq!(fenced, CapabilityError::EpochFenced);

    // The stale parent can no longer mint a fresh sub-agent against the new lease.
    let stale = attenuate(
        &authority,
        &parent_token,
        next,
        IAT + 2,
        AttenuateCapability {
            jti: "cap-subagent-2".into(),
            iat: IAT + 2,
            exp: IAT + 600,
            scope: vec!["fs.read".into()],
            sub: None,
        },
    )
    .await
    .unwrap_err();
    assert_eq!(stale, CapabilityError::EpochFenced);
}
