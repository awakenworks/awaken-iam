//! Guarded product projections, atomic provisioning and legacy wire dispatch.

use super::*;

/// Mount product-scoped resource-model and versioned projection commands beside
/// the generic daemon router. Only durable projection stores implement this
/// extension; callers cannot accidentally serve the route over an unversioned
/// in-memory adapter.
pub fn projection_router<S>(state: SharedDaemonState<S>) -> Router
where
    S: PolicyStore + ResourceProjectionStore + 'static,
{
    Router::new()
        .route(
            "/v1/authz/resource-model",
            post(register_product_resource_model::<S>),
        )
        .route(
            "/v1/authz/resource-provisions",
            post(resource_provision_command::<S>),
        )
        .with_state(state)
}

async fn register_product_resource_model<S: PolicyStore + ResourceProjectionStore>(
    State(state): State<SharedDaemonState<S>>,
    headers: HeaderMap,
    Json(request): Json<ProductResourceModelRequest>,
) -> Response {
    let mut guard = lock(&state);
    if let Some(rejection) =
        authorize_product_projection(&guard.auth, &headers, &request.product_id)
    {
        if directory_credential_access(&guard.auth, &headers).is_ok() {
            if audit_projection_rejection(
                guard.admin.store(),
                &headers,
                request.product_id.as_str(),
                "resource-model",
                "credential_scope",
            )
            .is_err()
            {
                return error_response(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "audit_error",
                    "rejection audit failed",
                );
            }
        }
        return rejection;
    }
    match guard.admin.store().register_product_model(&request) {
        Ok(receipt) => match guard.refresh_authorization(receipt.version) {
            Ok(()) => Json(receipt).into_response(),
            Err(error) => admin_error_response(&error),
        },
        Err(error) => {
            if audit_projection_rejection(
                guard.admin.store(),
                &headers,
                request.product_id.as_str(),
                "resource-model",
                &error.to_string(),
            )
            .is_err()
            {
                return error_response(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "audit_error",
                    "rejection audit failed",
                );
            }
            projection_error_response(error)
        }
    }
}

// The published projection endpoint also accepts the earlier unpublished
// atomic command. Strict request types prevent malformed projection requests
// from falling through to a less constrained command. New clients use the
// explicit transaction endpoint; neither path widens the generic store role.
#[derive(Deserialize)]
#[serde(untagged)]
enum ResourceProvisionCommand {
    Projection(ResourceProjectionBatch),
    Atomic(ResourceProvision),
}

async fn resource_provision_command<S: PolicyStore + ResourceProjectionStore>(
    State(state): State<SharedDaemonState<S>>,
    headers: HeaderMap,
    Json(command): Json<ResourceProvisionCommand>,
) -> Response {
    match command {
        ResourceProvisionCommand::Projection(batch) => {
            project_product_resources(State(state), headers, Json(batch)).await
        }
        ResourceProvisionCommand::Atomic(command) => {
            provision_resource(State(state), headers, Json(command)).await
        }
    }
}

async fn project_product_resources<S: PolicyStore + ResourceProjectionStore>(
    State(state): State<SharedDaemonState<S>>,
    headers: HeaderMap,
    Json(batch): Json<ResourceProjectionBatch>,
) -> Response {
    let mut guard = lock(&state);
    if let Some(rejection) = authorize_product_projection(&guard.auth, &headers, &batch.product_id)
    {
        if directory_credential_access(&guard.auth, &headers).is_ok() {
            if audit_projection_rejection(
                guard.admin.store(),
                &headers,
                batch.product_id.as_str(),
                &batch.projection_id,
                "credential_scope",
            )
            .is_err()
            {
                return error_response(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "audit_error",
                    "rejection audit failed",
                );
            }
        }
        return rejection;
    }
    match guard.admin.store().apply_projection(&batch) {
        Ok(receipt) => match guard.refresh_authorization(receipt.version) {
            Ok(()) => Json(receipt).into_response(),
            Err(error) => admin_error_response(&error),
        },
        Err(error) => {
            if audit_projection_rejection(
                guard.admin.store(),
                &headers,
                batch.product_id.as_str(),
                &batch.projection_id,
                &error.to_string(),
            )
            .is_err()
            {
                return error_response(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "audit_error",
                    "rejection audit failed",
                );
            }
            projection_error_response(error)
        }
    }
}

fn authorize_product_projection(
    auth: &AdminAuthPolicy,
    headers: &HeaderMap,
    product: &ProductId,
) -> Option<Response> {
    match directory_credential_access(auth, headers) {
        Ok(DirectoryCredentialAccess::Administrator) => None,
        Ok(DirectoryCredentialAccess::Product(owned)) if &owned == product => None,
        Ok(DirectoryCredentialAccess::Product(_)) => Some(error_response(
            StatusCode::FORBIDDEN,
            "product_mismatch",
            "credential belongs to another product",
        )),
        Err(rejection) => Some(rejection.into_response()),
    }
}

fn projection_error_response(error: RepositoryError) -> Response {
    match error {
        RepositoryError::Conflict(detail) => {
            error_response(StatusCode::CONFLICT, "projection_conflict", &detail)
        }
        RepositoryError::NotFound(detail) => {
            error_response(StatusCode::NOT_FOUND, "not_found", &detail)
        }
        RepositoryError::Backend(_) => error_response(
            StatusCode::INTERNAL_SERVER_ERROR,
            "backend_error",
            "resource projection failed",
        ),
    }
}

fn audit_projection_rejection<S: PolicyStore>(
    store: &S,
    headers: &HeaderMap,
    product: &str,
    projection: &str,
    reason: &str,
) -> Result<(), RepositoryError> {
    AuditSink::record(
        store,
        AuditEvent {
            at: now_timestamp(),
            actor: Some(admin_actor(headers)),
            action: "resource_projection.reject".into(),
            detail: format!("product={product}; projection={projection}; reason={reason}"),
        },
    )
}

pub(super) async fn provision_resource(
    State(state): State<SharedDaemonState<impl PolicyStore>>,
    headers: HeaderMap,
    Json(command): Json<ResourceProvision>,
) -> Response {
    let mut guard = lock(&state);
    match directory_credential_access(&guard.auth, &headers) {
        Ok(DirectoryCredentialAccess::Administrator) => {}
        Ok(DirectoryCredentialAccess::Product(product)) if product == command.product_id => {}
        Ok(DirectoryCredentialAccess::Product(_)) => {
            return error_response(
                StatusCode::FORBIDDEN,
                "forbidden",
                "product credential does not own this resource provision",
            );
        }
        Err(rejection) => return rejection.into_response(),
    }
    match guard.admin.provision_resource(command, now_timestamp()) {
        Ok(receipt) => match guard.refresh_authorization(receipt.version) {
            Ok(()) => (StatusCode::OK, Json::<ResourceProvisionReceipt>(receipt)).into_response(),
            Err(error) => admin_error_response(&error),
        },
        Err(error) => admin_error_response(&error),
    }
}
