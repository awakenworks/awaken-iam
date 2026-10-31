//! Fenced replacement of one principal's Team access (ADR-0018).
//!
//! The wire body of `POST /v1/admin/principal-access/team-replacements`. A
//! consumer that changes a person's access (for example a personnel owner)
//! sends the complete intended end state; IAM applies it in one policy
//! transaction under a per-(Workspace, principal) fence. Group ids are exact
//! IAM group ids, carried as strings like the other admin contracts.

use serde::{Deserialize, Serialize};

use crate::{PrincipalRef, WorkspaceId};

/// The consumer's ordering token for one access plan.
///
/// `generation` strictly increases between plans of the same principal in the
/// same Workspace; a resumed plan repeats its own generation and `plan_id`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AccessFence {
    pub generation: u64,
    pub plan_id: String,
}

/// Replace a principal's membership of the managed groups and its Workspace
/// suspension in one fenced commit.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TeamAccessReplacement {
    pub workspace_id: WorkspaceId,
    pub principal: PrincipalRef,
    /// Every group whose membership this command owns for the principal.
    pub managed: Vec<String>,
    /// The groups the principal belongs to afterwards; a subset of `managed`.
    pub teams: Vec<String>,
    /// Keep a Workspace-wide deny for the principal (a departure).
    pub suspended: bool,
    pub fence: AccessFence,
}

/// The committed outcome, read back inside the same transaction.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TeamAccessReceipt {
    pub workspace_id: WorkspaceId,
    pub principal: PrincipalRef,
    /// Managed groups that contain the principal after the commit, sorted.
    pub teams: Vec<String>,
    pub suspended: bool,
    pub fence: AccessFence,
    /// Policy version after the commit.
    pub version: u64,
}
