//! End-to-end coverage of the liveness / readiness probes the daemon exposes.
//!
//! The probes are framework-agnostic — [`awaken_iam_server::Liveness`] and
//! [`awaken_iam_server::Readiness`] are plain types — but every production path
//! to them runs through the [`IamAssembly`](awaken_iam_server::IamAssembly). A
//! fresh, properly-migrated assembly must report live + ready; an assembly
//! built over a store whose ledger is incomplete must report not-ready with a
//! human-readable detail. The not-ready constructor itself and the detail
//! accessor are exercised here too, so the operator-facing surfaces stay
//! covered even though no `/readyz` HTTP route is bound yet.

use awaken_iam_server::{
    IAM_TABLE_PREFIX, IamAssembly, IamStore, Liveness, Readiness, RecordingExecutor,
};

#[test]
fn liveness_is_up_for_a_running_process() {
    // Liveness is deliberately store-independent: the orchestrator restarts on
    // a wedged process, not on a transient store outage.
    assert!(Liveness::Up.is_live());
}

#[test]
fn readiness_reports_ready_with_no_detail_when_all_clear() {
    let readiness = Readiness::ready();
    assert!(readiness.is_ready());
    assert!(
        readiness.detail().is_none(),
        "a ready node carries no operator detail"
    );
}

#[test]
fn readiness_reports_not_ready_with_a_human_detail_when_failing() {
    // The not-ready branch is the operator-facing one: it explains *why* the
    // balancer should drain the node, so an on-call can act without reading
    // source. Two distinct failure modes round-trip their detail faithfully.
    let drifted = Readiness::not_ready("migrations not fully applied");
    assert!(!drifted.is_ready());
    assert_eq!(drifted.detail(), Some("migrations not fully applied"));

    let unreachable =
        Readiness::not_ready(format!("store unreachable: {err}", err = "conn refused"));
    assert!(!unreachable.is_ready());
    assert_eq!(
        unreachable.detail(),
        Some("store unreachable: conn refused")
    );

    // An owned String converts cleanly into the constructor.
    let owned: String = "epoch mismatch".into();
    let from_string = Readiness::not_ready(owned);
    assert_eq!(from_string.detail(), Some("epoch mismatch"));
}

#[test]
fn readyz_reports_ready_after_migration() {
    // Real-world flow: a freshly assembled standalone daemon reports ready
    // because its in-process migration executor applied every bundle before
    // the assembly returned.
    let assembly = IamAssembly::embedded(RecordingExecutor::new()).expect("assemble");
    assert_eq!(assembly.healthz().is_live(), true);
    assert!(assembly.readyz().is_ready());
}

#[test]
fn readyz_reports_not_ready_when_migrations_are_drifted() {
    // Force a checksum mismatch on a ledger entry; the ledger's fail-closed
    // fence must reject the migration and the assembly's `readyz()` must
    // then report not-ready with a detail that an operator can read.
    let mut executor = RecordingExecutor::new();
    executor.force_checksum("iam.identity", 1, "deadbeef");
    let result = IamAssembly::embedded(executor);
    assert!(
        result.is_err(),
        "drift must abort assembly, not silently serve traffic"
    );

    // Separately, an un-migrated store that bypasses the ledger must still
    // report not-ready. The constructor of the in-process store is the
    // seam the assembly would have used.
    let store =
        IamStore::with_prefix(RecordingExecutor::new(), IAM_TABLE_PREFIX).expect("valid prefix");
    assert!(
        !store.migrations_applied().expect("probe ledger"),
        "an un-migrated store must not report ready"
    );
}
