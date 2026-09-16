use awaken_iam_contract::ExternalIdentityKey;
use awaken_iam_core::{RepositoryError, RepositoryResult};

use super::InMemoryStore;

pub(super) fn json_key<T: serde::Serialize>(value: &T, what: &str) -> RepositoryResult<String> {
    serde_json::to_string(value)
        .map_err(|err| RepositoryError::Backend(format!("encode {what}: {err}")))
}

pub(super) fn external_key(key: &ExternalIdentityKey) -> String {
    format!("{}\u{1f}{}", key.provider_key.0, key.subject.0)
}

impl std::fmt::Debug for InMemoryStore {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("InMemoryStore").finish_non_exhaustive()
    }
}

impl InMemoryStore {
    /// Create an empty store.
    pub fn new() -> Self {
        Self::default()
    }
}
