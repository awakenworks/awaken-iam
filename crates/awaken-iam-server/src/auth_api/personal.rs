//! Client authentication for the explicitly mounted durable-consent protocol.
use super::*;
impl<E: EntropySource + Clone> AuthApi<E> {
    pub(crate) fn personal_recipient(
        &self,
        id: &str,
        secret: &str,
    ) -> Result<RegisteredClient, OAuthProviderError> {
        let client = self.oauth_provider.authenticate_client(id, Some(secret))?;
        if !client.is_confidential() {
            return Err(OAuthProviderError::InvalidClientSecret);
        }
        Ok(client)
    }
}
