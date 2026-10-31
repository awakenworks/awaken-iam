//! `POST /v1/admin/grants/batch`: issue many grants under one policy version.
//!
//! The request keeps the default body limit of every non-profile route, so a
//! very large seed is sent as several batches; each batch is atomic.

use awaken_iam_contract::GrantBatch;
use awaken_iam_core::Grant;
use axum::{Json, extract::State, http::HeaderMap, response::Response};

use super::{PolicyDelta, SharedDaemonState, apply_delta, grant_from_dto};
use crate::PolicyStore;

pub(super) async fn issue_grants(
    State(state): State<SharedDaemonState<impl PolicyStore>>,
    headers: HeaderMap,
    Json(batch): Json<GrantBatch>,
) -> Response {
    let grants: Vec<Grant> = batch.grants.into_iter().map(grant_from_dto).collect();
    let delta = PolicyDelta::UpsertGrants(grants.clone());
    apply_delta(
        &state,
        &headers,
        move |admin, at| admin.issue_grants(grants, at),
        Some(delta),
    )
}
