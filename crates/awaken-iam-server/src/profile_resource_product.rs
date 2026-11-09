//! Resource ownership is carried by immutable PAP history, not name prefixes.
use awaken_iam_contract::{AuthorizationProfileDocument, ProductId};
use awaken_iam_core::{RepositoryError, RepositoryResult};

pub(crate) fn ensure_owner<'a>(
    history: impl IntoIterator<Item = &'a AuthorizationProfileDocument>,
    proposed: Option<&ProductId>,
) -> RepositoryResult<()> {
    for document in history {
        if let Some(owner) = document.resource_product.as_ref() {
            if Some(owner) != proposed {
                return Err(RepositoryError::Conflict(
                    "profile resource product cannot be removed or changed".into(),
                ));
            }
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn first_product_declaration_survives_missing_and_changed_successors() {
        let unowned = AuthorizationProfileDocument::default();
        let mut owned = unowned.clone();
        owned.resource_product = Some(ProductId::new("awaken").unwrap());
        assert!(ensure_owner([&unowned], owned.resource_product.as_ref()).is_ok());
        assert!(ensure_owner([&unowned, &owned], owned.resource_product.as_ref()).is_ok());
        assert!(ensure_owner([&owned], None).is_err());
        assert!(ensure_owner([&owned], Some(&ProductId::new("other").unwrap())).is_err());
    }
    #[test]
    fn absent_bridge_preserves_exact_legacy_document_and_checksum_input() {
        let legacy = r#"{"resource_model":{"resource_types":[],"actions":[],"edges":[]},"action_scope_rules":[],"grants":[],"role_bindings":[],"group_rosters":[],"group_role_bindings":[]}"#;
        let parsed: AuthorizationProfileDocument = serde_json::from_str(legacy).unwrap();
        assert_eq!(serde_json::to_string(&parsed).unwrap(), legacy);
        let mut explicit = parsed;
        explicit.resource_product = Some(ProductId::new("awaken").unwrap());
        assert_ne!(
            serde_json::to_string(&explicit).unwrap(),
            legacy,
            "adoption is an explicit new checksummed revision"
        );
    }
}
