//! A separate capability: legacy transports cannot claim strict registration.
use crate::{RemoteError, RemoteIamClient};
use awaken_iam_contract::{
    AuthorizationDecision, RegisteredResourceAuthorizationEvaluation,
    RegisteredResourceAuthorizationRequest, ScopeRef,
};

pub trait RegisteredResourceAuthzTransport {
    fn authorize_registered_resource(
        &self,
        request: &RegisteredResourceAuthorizationRequest,
    ) -> Result<RegisteredResourceAuthorizationEvaluation, RemoteError>;
}

impl<T: RegisteredResourceAuthzTransport> RemoteIamClient<T> {
    pub fn authorize_registered_resource(
        &self,
        request: &RegisteredResourceAuthorizationRequest,
    ) -> Result<RegisteredResourceAuthorizationEvaluation, RemoteError> {
        let evaluation = self.transport().authorize_registered_resource(request)?;
        validate(request, &evaluation)?;
        Ok(evaluation)
    }
}

pub(crate) fn validate(
    request: &RegisteredResourceAuthorizationRequest,
    result: &RegisteredResourceAuthorizationEvaluation,
) -> Result<(), RemoteError> {
    if result.evaluation.outcome.decision != AuthorizationDecision::Allow {
        return Ok(());
    }
    let fail =
        || RemoteError::new("current resource registration qualification is unavailable".into());
    let fresh = result.evaluation.freshness.as_deref().ok_or_else(fail)?;
    if !fresh.strip_prefix("iam-fence-v1:").is_some_and(|digest| {
        digest.len() == 64
            && digest
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    }) {
        return Err(fail());
    }
    let proof = result.registration.as_ref().ok_or_else(fail)?;
    let ScopeRef::Resource {
        resource_type,
        resource_id,
    } = &request.authorization.request.scope
    else {
        return Err(fail());
    };
    if proof.namespace != request.namespace
        || proof.product_id != request.product_id
        || proof.workspace_id != request.workspace_id
        || proof.action != request.authorization.request.action
        || &proof.resource_type != resource_type
        || proof.resource_type != request.resource_type
        || &proof.resource_id != resource_id
        || proof.profile_revision == 0
        || !proof
            .profile_checksum
            .strip_prefix("sha256:")
            .is_some_and(|digest| {
                digest.len() == 64
                    && digest
                        .bytes()
                        .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
            })
        || proof.projection_id.is_empty()
        || proof
            .action
            .0
            .split_once("::")
            .map(|(namespace, _)| namespace)
            != Some(request.namespace.0.as_str())
    {
        return Err(fail());
    }
    Ok(())
}

#[cfg(test)]
mod tests;
