//! Native HTTP projection of the finite publication contract.
use super::*;
use crate::{ScopedProfileConsumer, ScopedProfilePublisher};
use awaken_iam_contract::{
    ActivateScopedAuthorizationProfiles, PrepareScopedAuthorizationProfile,
    ScopedAuthorizationProfileBaseline, ScopedAuthorizationProfileReceipt, WorkspaceId,
};

impl HttpAuthzTransport {
    fn scoped_workspace_url(
        &self,
        workspace: &WorkspaceId,
        suffix: &[&str],
    ) -> Result<reqwest::Url, RemoteError> {
        let mut url = reqwest::Url::parse(&self.url("/v1/scoped-authz/workspaces"))
            .map_err(|error| RemoteError::new(error.to_string()))?;
        url.path_segments_mut()
            .map_err(|_| RemoteError::new("IAM base URL cannot carry path segments".into()))?
            .push(&workspace.0)
            .extend(suffix);
        Ok(url)
    }

    fn scoped_profile_url(
        &self,
        workspace: &WorkspaceId,
        namespace: &NamespaceId,
        suffix: &[&str],
    ) -> Result<reqwest::Url, RemoteError> {
        let mut path = vec!["profiles", namespace.0.as_str()];
        path.extend_from_slice(suffix);
        self.scoped_workspace_url(workspace, &path)
    }
}

impl ScopedProfileConsumer for HttpAuthzTransport {
    fn configured_endpoint(&self) -> Option<&str> {
        HttpAuthzTransport::configured_endpoint(self)
    }
    fn authorize_scoped_resources_evaluation(
        &self,
        workspace: &WorkspaceId,
        namespace: &NamespaceId,
        request: &awaken_iam_contract::ResourceAuthorizationBatchRequest,
    ) -> Result<awaken_iam_contract::ResourceAuthorizationBatchEvaluation, RemoteError> {
        use awaken_iam_contract::{RESOURCE_AUTHORIZATION_BATCH_MAX, ResourceAuthorizationMode};
        if request.mode != ResourceAuthorizationMode::Scoped {
            return Err(RemoteError::response(
                501,
                "personal contextual batch capability is unsupported".into(),
            ));
        }
        if request.requests.len() > RESOURCE_AUTHORIZATION_BATCH_MAX {
            return Err(RemoteError::response(
                400,
                "contextual batch exceeds the native limit".into(),
            ));
        }
        let url = self.scoped_profile_url(workspace, namespace, &["authorize-resources"])?;
        let response = self.send_with_retry(|| self.client.post(url.clone()).json(request))?;
        let freshness = Self::evaluation_freshness(&response)?;
        let value: awaken_iam_contract::ResourceAuthorizationBatchEvaluation =
            Self::decode(response)?;
        if freshness.as_ref() != Some(&value.freshness)
            || value.outcomes.len() != request.requests.len()
        {
            return Err(RemoteError::new(
                "contextual batch lost its native freshness or positional results".into(),
            ));
        }
        Ok(value)
    }
    fn scoped_resource_candidates(
        &self,
        workspace: &WorkspaceId,
        namespace: &NamespaceId,
        request: &awaken_iam_contract::ResourceCandidateRequest,
    ) -> Result<awaken_iam_contract::ResourceCandidateEvaluation, RemoteError> {
        if request.mode != awaken_iam_contract::ResourceAuthorizationMode::Scoped
            || request.access != awaken_iam_contract::AuthorizationAccess::Read
        {
            return Err(RemoteError::response(
                501,
                "candidate capability supports ordinary scoped reads only".into(),
            ));
        }
        let url = self.scoped_profile_url(workspace, namespace, &["resource-candidates"])?;
        let response = self.send_with_retry(|| self.client.post(url.clone()).json(request))?;
        let freshness = Self::evaluation_freshness(&response)?;
        let value: awaken_iam_contract::ResourceCandidateEvaluation = Self::decode(response)?;
        if freshness.as_ref() != Some(&value.freshness) || !value.plan.predicate.within_limits() {
            return Err(RemoteError::new(
                "candidate plan lost its native freshness or exceeded finite limits".into(),
            ));
        }
        Ok(value)
    }
    fn authorize_scoped_resource_evaluation(
        &self,
        workspace: &WorkspaceId,
        namespace: &NamespaceId,
        request: &awaken_iam_contract::ResourceAuthorizationRequest,
    ) -> Result<awaken_iam_contract::AuthorizationEvaluation, RemoteError> {
        let url = self.scoped_profile_url(workspace, namespace, &["authorize"])?;
        Self::decode_evaluation(
            self.send_with_retry(|| self.client.post(url.clone()).json(request))?,
        )
    }
    fn authorize_scoped_resource(
        &self,
        workspace: &WorkspaceId,
        namespace: &NamespaceId,
        request: &awaken_iam_contract::ResourceAuthorizationRequest,
    ) -> Result<awaken_iam_contract::AuthorizationOutcome, RemoteError> {
        let url = self.scoped_profile_url(workspace, namespace, &["authorize"])?;
        Self::decode(self.send_with_retry(|| self.client.post(url.clone()).json(request))?)
    }
}

impl ScopedProfilePublisher for HttpAuthzTransport {
    fn scoped_profile_baseline(
        &self,
        workspace: &WorkspaceId,
        namespace: &NamespaceId,
    ) -> Result<ScopedAuthorizationProfileBaseline, RemoteError> {
        let url = self.scoped_profile_url(workspace, namespace, &[])?;
        Self::decode(self.send_with_retry(|| self.client.get(url.clone()))?)
    }
    fn prepare_scoped_profile(
        &self,
        request: &PrepareScopedAuthorizationProfile,
    ) -> Result<ScopedAuthorizationProfileReceipt, RemoteError> {
        let url = self.scoped_profile_url(
            &request.workspace_id,
            &request.profile.namespace,
            &["publications"],
        )?;
        Self::decode(self.send_with_retry(|| self.client.post(url.clone()).json(request))?)
    }
    fn scoped_profile_receipt(
        &self,
        workspace: &WorkspaceId,
        namespace: &NamespaceId,
        key: &str,
    ) -> Result<ScopedAuthorizationProfileReceipt, RemoteError> {
        let url = self.scoped_profile_url(workspace, namespace, &["publications", key])?;
        Self::decode(self.send_with_retry(|| self.client.get(url.clone()))?)
    }
    fn activate_scoped_profile(
        &self,
        workspace: &WorkspaceId,
        namespace: &NamespaceId,
        key: &str,
    ) -> Result<ScopedAuthorizationProfileReceipt, RemoteError> {
        let url =
            self.scoped_profile_url(workspace, namespace, &["publications", key, "activate"])?;
        Self::decode(self.send_with_retry(|| self.client.post(url.clone()))?)
    }
    fn activate_scoped_profile_set(
        &self,
        workspace: &WorkspaceId,
        request: &ActivateScopedAuthorizationProfiles,
    ) -> Result<Vec<ScopedAuthorizationProfileReceipt>, RemoteError> {
        let url = self.scoped_workspace_url(workspace, &["activate-publication-set"])?;
        Self::decode(self.send_with_retry(|| self.client.post(url.clone()).json(request))?)
    }
    fn retire_scoped_profile(
        &self,
        workspace: &WorkspaceId,
        namespace: &NamespaceId,
        key: &str,
    ) -> Result<ScopedAuthorizationProfileReceipt, RemoteError> {
        let url =
            self.scoped_profile_url(workspace, namespace, &["publications", key, "retire"])?;
        Self::decode(self.send_with_retry(|| self.client.post(url.clone()))?)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn publication_coordinates_remain_separate_encoded_segments() {
        let client =
            HttpAuthzTransport::new(HttpTransportConfig::new("http://localhost:1")).unwrap();
        let url = client
            .scoped_profile_url(
                &WorkspaceId("a/b".into()),
                &NamespaceId("tenant.a".into()),
                &["publications", "key/other?x"],
            )
            .unwrap();
        assert!(
            url.path()
                .contains("a%2Fb/profiles/tenant.a/publications/key%2Fother%3Fx")
        );
        assert!(url.query().is_none());
    }
}
