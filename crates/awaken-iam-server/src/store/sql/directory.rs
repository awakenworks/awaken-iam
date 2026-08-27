//! Product-neutral Directory persistence over the shared SQL adapter.

use super::*;

fn decode_directory_node(row: &SqlRow) -> RepositoryResult<DirectoryNode> {
    let archived = match req(row, 6, "directory_node.archived")?.as_str() {
        "0" => false,
        "1" => true,
        other => {
            return Err(RepositoryError::Backend(format!(
                "invalid directory archived flag {other}"
            )));
        }
    };
    Ok(DirectoryNode {
        id: DirectoryNodeId(req(row, 0, "directory_node.id")?),
        org_id: OrgId(req(row, 1, "directory_node.org_id")?),
        parent_id: opt(row, 2)
            .filter(|parent| !parent.is_empty())
            .map(DirectoryNodeId),
        name: req(row, 3, "directory_node.name")?,
        slug: req(row, 4, "directory_node.slug")?,
        description: opt(row, 5),
        archived,
        created_at: Timestamp(req(row, 7, "directory_node.created_at")?),
        updated_at: Timestamp(req(row, 8, "directory_node.updated_at")?),
    })
}

fn decode_product_space_placement(row: &SqlRow) -> RepositoryResult<ProductSpacePlacement> {
    Ok(ProductSpacePlacement {
        product_space: ProductSpaceRef {
            product_id: ProductId::new(req(row, 0, "product_space.product")?).map_err(|error| {
                RepositoryError::Backend(format!("invalid stored product id: {error}"))
            })?,
            space_id: req(row, 1, "product_space.space_id")?,
        },
        org_id: OrgId(req(row, 2, "product_space.org_id")?),
        node_id: DirectoryNodeId(req(row, 3, "product_space.node_id")?),
    })
}

const DIRECTORY_NODE_COLUMNS: &str = "id, org_id, parent_id, name, slug, description, CAST(archived AS TEXT), created_at, updated_at";
const JOINED_DIRECTORY_NODE_COLUMNS: &str = "node.id, node.org_id, node.parent_id, node.name, node.slug, node.description, CAST(node.archived AS TEXT), node.created_at, node.updated_at";

impl<B: SqlConn> DirectoryRepository for SqlStore<B> {
    fn create_directory_node(
        &self,
        node: DirectoryNode,
        placement: Option<ProductSpacePlacement>,
        actor: &PrincipalRef,
    ) -> RepositoryResult<u64> {
        node.validate()
            .map_err(|error| RepositoryError::Conflict(error.to_string()))?;
        if let Some(placement) = &placement {
            node.validate_placement(placement)
                .map_err(|error| RepositoryError::Conflict(error.to_string()))?;
        }
        let org_exists = self.backend.query(
            &format!("SELECT id FROM {} WHERE id = ?", self.table("orgs")),
            &[p(node.org_id.0.clone())],
        )?;
        if org_exists.is_empty() {
            return Err(RepositoryError::NotFound(format!(
                "organization {}",
                node.org_id.0
            )));
        }
        if self.directory_node(&node.id)?.is_some() {
            return Err(RepositoryError::Conflict(format!(
                "directory node {} already exists",
                node.id.0
            )));
        }
        if let Some(parent_id) = &node.parent_id {
            let parent = self.directory_node(parent_id)?.ok_or_else(|| {
                RepositoryError::NotFound(format!("directory parent {}", parent_id.0))
            })?;
            if parent.archived || parent.org_id != node.org_id {
                return Err(RepositoryError::Conflict(
                    "directory parent must be live and in the same organization".into(),
                ));
            }
        }
        // The transaction's unique key is the authoritative sibling-slug
        // check. Avoid a pre-read here: a new organization has no revision row
        // until this first command initializes it, and a pre-read would still
        // race another writer before the command mutex is acquired.
        if let Some(placement) = &placement
            && self
                .product_space_placement(&placement.org_id, &placement.product_space)?
                .is_some()
        {
            return Err(RepositoryError::Conflict(format!(
                "product space {}/{} is already placed",
                placement.product_space.product_id, placement.product_space.space_id
            )));
        }

        let nodes = self.table("directory_nodes");
        let bindings = self.table("product_space_bindings");
        let audit = self.table("audit_events");
        let fence = self.table("directory_fence");
        let parent_key = node
            .parent_id
            .as_ref()
            .map_or_else(String::new, |id| id.0.clone());
        let mut writes = vec![
            SqlWrite {
                sql: format!(
                    "INSERT INTO {fence} (org_id, revision) VALUES (?, 1) \
                     ON CONFLICT (org_id) DO NOTHING"
                ),
                params: vec![p(node.org_id.0.clone())],
            },
            SqlWrite {
                // This no-op update is the portable Directory command mutex. Every
                // structural mutation in one organization acquires it before
                // rechecking its condition.
                sql: format!("UPDATE {fence} SET revision = revision WHERE org_id = ?"),
                params: vec![p(node.org_id.0.clone())],
            },
        ];
        let (insert_sql, insert_params) = if node.parent_id.is_some() {
            (
                format!(
                    "INSERT INTO {nodes} \
                     (id, org_id, parent_id, name, slug, description, archived, created_at, updated_at) \
                     SELECT ?, ?, ?, ?, ?, ?, 0, ?, ? \
                     WHERE EXISTS (SELECT 1 FROM {nodes} \
                                   WHERE id = ? AND org_id = ? AND archived = 0)"
                ),
                vec![
                    p(node.id.0.clone()),
                    p(node.org_id.0.clone()),
                    p(parent_key.clone()),
                    p(node.name),
                    p(node.slug),
                    node.description,
                    p(node.created_at.0),
                    p(node.updated_at.0.clone()),
                    p(parent_key),
                    p(node.org_id.0.clone()),
                ],
            )
        } else {
            (
                format!(
                    "INSERT INTO {nodes} \
                     (id, org_id, parent_id, name, slug, description, archived, created_at, updated_at) \
                     SELECT ?, ?, ?, ?, ?, ?, 0, ?, ? \
                     WHERE EXISTS (SELECT 1 FROM {} WHERE id = ?)",
                    self.table("orgs")
                ),
                vec![
                    p(node.id.0.clone()),
                    p(node.org_id.0.clone()),
                    p(String::new()),
                    p(node.name),
                    p(node.slug),
                    node.description,
                    p(node.created_at.0),
                    p(node.updated_at.0.clone()),
                    p(node.org_id.0.clone()),
                ],
            )
        };
        writes.push(SqlWrite {
            sql: insert_sql,
            params: insert_params,
        });
        if let Some(placement) = placement {
            writes.push(SqlWrite {
                sql: format!(
                    "INSERT INTO {bindings} (product, space_id, org_id, node_id) VALUES (?, ?, ?, ?)"
                ),
                params: vec![
                    p(placement.product_space.product_id.as_str().to_owned()),
                    p(placement.product_space.space_id),
                    p(placement.org_id.0),
                    p(placement.node_id.0),
                ],
            });
        }
        writes.push(SqlWrite {
            sql: format!("INSERT INTO {audit} (at, actor, action, detail) VALUES (?, ?j, ?, ?)"),
            params: vec![
                p(node.updated_at.0),
                p(json_encode(actor, "directory actor")?),
                p("directory.node.create"),
                p(format!("directory node {}", node.id.0)),
            ],
        });
        writes.push(SqlWrite {
            sql: format!("UPDATE {fence} SET revision = revision + 1 WHERE org_id = ?"),
            params: vec![p(node.org_id.0.clone())],
        });
        let required = (1..writes.len())
            .map(|index| (index, 1))
            .collect::<Vec<_>>();
        self.backend
            .execute_transaction_checked(&writes, &required)?;
        self.directory_revision(&node.org_id)
    }

    fn directory_node(&self, id: &DirectoryNodeId) -> RepositoryResult<Option<DirectoryNode>> {
        let sql = format!(
            "SELECT {DIRECTORY_NODE_COLUMNS} FROM {} WHERE id = ?",
            self.table("directory_nodes")
        );
        self.backend
            .query(&sql, &[p(id.0.clone())])?
            .first()
            .map(decode_directory_node)
            .transpose()
    }

    fn directory_children(
        &self,
        org_id: &OrgId,
        parent_id: Option<&DirectoryNodeId>,
    ) -> RepositoryResult<(u64, Vec<DirectoryNode>)> {
        let params = [
            p(org_id.0.clone()),
            p(parent_id.map_or_else(String::new, |parent| parent.0.clone())),
        ];
        let sql = format!(
            "SELECT {JOINED_DIRECTORY_NODE_COLUMNS}, CAST(fence.revision AS TEXT) \
             FROM {} fence LEFT JOIN {} node \
               ON node.org_id = fence.org_id AND node.parent_id = ? AND node.archived = 0 \
             WHERE fence.org_id = ? ORDER BY node.slug",
            self.table("directory_fence"),
            self.table("directory_nodes")
        );
        let rows = self
            .backend
            .query(&sql, &[params[1].clone(), params[0].clone()])?;
        let revision = rows
            .first()
            .and_then(|row| row.get(9))
            .and_then(Option::as_deref)
            .map(str::parse)
            .transpose()
            .map_err(|error| {
                RepositoryError::Backend(format!("invalid directory revision: {error}"))
            })?
            .unwrap_or(1);
        let nodes = rows
            .iter()
            .filter(|row| row.first().and_then(Option::as_deref).is_some())
            .map(decode_directory_node)
            .collect::<RepositoryResult<Vec<_>>>()?;
        Ok((revision, nodes))
    }

    fn move_directory_node(
        &self,
        id: &DirectoryNodeId,
        parent_id: Option<&DirectoryNodeId>,
        updated_at: &Timestamp,
        actor: &PrincipalRef,
    ) -> RepositoryResult<u64> {
        if parent_id == Some(id) {
            return Err(RepositoryError::Conflict(
                "a directory node cannot be its own parent".into(),
            ));
        }
        let current = self
            .directory_node(id)?
            .filter(|node| !node.archived)
            .ok_or_else(|| RepositoryError::NotFound(format!("live directory node {}", id.0)))?;
        if current.parent_id.as_ref() == parent_id {
            return self.directory_revision(&current.org_id);
        }
        if let Some(parent_id) = parent_id {
            let parent = self
                .directory_node(parent_id)?
                .filter(|node| !node.archived)
                .ok_or_else(|| {
                    RepositoryError::NotFound(format!("directory parent {}", parent_id.0))
                })?;
            if parent.org_id != current.org_id {
                return Err(RepositoryError::Conflict(
                    "directory parent must be in the same organization".into(),
                ));
            }
            let mut cursor = Some(parent);
            while let Some(candidate) = cursor {
                if candidate.id == *id {
                    return Err(RepositoryError::Conflict(
                        "directory move would create a cycle".into(),
                    ));
                }
                cursor = candidate
                    .parent_id
                    .as_ref()
                    .map(|ancestor| self.directory_node(ancestor))
                    .transpose()?
                    .flatten();
            }
        }
        if self
            .directory_children(&current.org_id, parent_id)?
            .1
            .iter()
            .any(|sibling| sibling.id != current.id && sibling.slug == current.slug)
        {
            return Err(RepositoryError::Conflict(format!(
                "directory slug {} already exists under the target parent",
                current.slug
            )));
        }
        let nodes = self.table("directory_nodes");
        let fence = self.table("directory_fence");
        let parent_key = parent_id.map_or_else(String::new, |parent| parent.0.clone());
        let writes = [
            SqlWrite {
                sql: format!("UPDATE {fence} SET revision = revision WHERE org_id = ?"),
                params: vec![p(current.org_id.0.clone())],
            },
            SqlWrite {
                sql: format!(
                    "WITH RECURSIVE ancestry(id, parent_id) AS (\
                       SELECT id, parent_id FROM {nodes} WHERE id = ? \
                       UNION ALL \
                       SELECT node.id, node.parent_id FROM {nodes} node \
                       JOIN ancestry child ON node.id = child.parent_id \
                       WHERE child.parent_id <> ''\
                     ) \
                     UPDATE {nodes} SET parent_id = ?, updated_at = ? \
                     WHERE id = ? AND archived = 0 \
                       AND (? = '' OR EXISTS (SELECT 1 FROM {nodes} parent \
                           WHERE parent.id = ? AND parent.org_id = ? AND parent.archived = 0)) \
                       AND NOT EXISTS (SELECT 1 FROM ancestry WHERE id = ?) \
                       AND NOT EXISTS (SELECT 1 FROM {nodes} sibling \
                           WHERE sibling.org_id = ? AND sibling.parent_id = ? \
                             AND sibling.slug = ? AND sibling.id <> ?)"
                ),
                params: vec![
                    p(parent_key.clone()),
                    p(parent_key.clone()),
                    p(updated_at.0.clone()),
                    p(id.0.clone()),
                    p(parent_key.clone()),
                    p(parent_key.clone()),
                    p(current.org_id.0.clone()),
                    p(id.0.clone()),
                    p(current.org_id.0.clone()),
                    p(parent_key),
                    p(current.slug),
                    p(id.0.clone()),
                ],
            },
            SqlWrite {
                sql: format!(
                    "INSERT INTO {} (at, actor, action, detail) VALUES (?, ?j, ?, ?)",
                    self.table("audit_events")
                ),
                params: vec![
                    p(updated_at.0.clone()),
                    p(json_encode(actor, "directory actor")?),
                    p("directory.node.move"),
                    p(format!("directory node {}", id.0)),
                ],
            },
            SqlWrite {
                sql: format!(
                    "UPDATE {} SET revision = revision + 1 WHERE org_id = ?",
                    self.table("directory_fence")
                ),
                params: vec![p(current.org_id.0.clone())],
            },
        ];
        self.backend
            .execute_transaction_checked(&writes, &[(0, 1), (1, 1), (2, 1), (3, 1)])?;
        self.directory_revision(&current.org_id)
    }

    fn archive_directory_node(
        &self,
        id: &DirectoryNodeId,
        updated_at: &Timestamp,
        actor: &PrincipalRef,
    ) -> RepositoryResult<u64> {
        let node = self
            .directory_node(id)?
            .ok_or_else(|| RepositoryError::NotFound(format!("directory node {}", id.0)))?;
        if node.archived {
            return self.directory_revision(&node.org_id);
        }
        let live_children = self.directory_children(&node.org_id, Some(id))?.1;
        if !live_children.is_empty() {
            return Err(RepositoryError::Conflict(
                "a directory node with live children cannot be archived".into(),
            ));
        }
        let nodes = self.table("directory_nodes");
        let fence = self.table("directory_fence");
        let writes = [
            SqlWrite {
                sql: format!("UPDATE {fence} SET revision = revision WHERE org_id = ?"),
                params: vec![p(node.org_id.0.clone())],
            },
            SqlWrite {
                sql: format!(
                    "UPDATE {nodes} SET archived = 1, updated_at = ? \
                     WHERE id = ? AND archived = 0 \
                       AND NOT EXISTS (SELECT 1 FROM {nodes} child \
                           WHERE child.parent_id = ? AND child.archived = 0)"
                ),
                params: vec![p(updated_at.0.clone()), p(id.0.clone()), p(id.0.clone())],
            },
            SqlWrite {
                sql: format!(
                    "INSERT INTO {} (at, actor, action, detail) VALUES (?, ?j, ?, ?)",
                    self.table("audit_events")
                ),
                params: vec![
                    p(updated_at.0.clone()),
                    p(json_encode(actor, "directory actor")?),
                    p("directory.node.archive"),
                    p(format!("directory node {}", id.0)),
                ],
            },
            SqlWrite {
                sql: format!(
                    "UPDATE {} SET revision = revision + 1 WHERE org_id = ?",
                    self.table("directory_fence")
                ),
                params: vec![p(node.org_id.0.clone())],
            },
        ];
        self.backend
            .execute_transaction_checked(&writes, &[(0, 1), (1, 1), (2, 1), (3, 1)])?;
        self.directory_revision(&node.org_id)
    }

    fn restore_directory_node(
        &self,
        id: &DirectoryNodeId,
        updated_at: &Timestamp,
        actor: &PrincipalRef,
    ) -> RepositoryResult<u64> {
        let node = self
            .directory_node(id)?
            .ok_or_else(|| RepositoryError::NotFound(format!("directory node {}", id.0)))?;
        if !node.archived {
            return self.directory_revision(&node.org_id);
        }
        let nodes = self.table("directory_nodes");
        let fence = self.table("directory_fence");
        let writes = [
            SqlWrite {
                sql: format!("UPDATE {fence} SET revision = revision WHERE org_id = ?"),
                params: vec![p(node.org_id.0.clone())],
            },
            SqlWrite {
                sql: format!(
                    "UPDATE {nodes} SET archived = 0, updated_at = ? \
                     WHERE id = ? AND archived = 1 \
                       AND (parent_id = '' OR EXISTS (SELECT 1 FROM {nodes} parent \
                         WHERE parent.id = {nodes}.parent_id \
                           AND parent.org_id = ? AND parent.archived = 0))"
                ),
                params: vec![
                    p(updated_at.0.clone()),
                    p(id.0.clone()),
                    p(node.org_id.0.clone()),
                ],
            },
            SqlWrite {
                sql: format!(
                    "INSERT INTO {} (at, actor, action, detail) VALUES (?, ?j, ?, ?)",
                    self.table("audit_events")
                ),
                params: vec![
                    p(updated_at.0.clone()),
                    p(json_encode(actor, "directory actor")?),
                    p("directory.node.restore"),
                    p(format!("directory node {}", id.0)),
                ],
            },
            SqlWrite {
                sql: format!("UPDATE {fence} SET revision = revision + 1 WHERE org_id = ?"),
                params: vec![p(node.org_id.0.clone())],
            },
        ];
        self.backend
            .execute_transaction_checked(&writes, &[(0, 1), (1, 1), (2, 1), (3, 1)])?;
        self.directory_revision(&node.org_id)
    }

    fn update_directory_node(
        &self,
        id: &DirectoryNodeId,
        name: &str,
        slug: &str,
        description: Option<&str>,
        updated_at: &Timestamp,
        actor: &PrincipalRef,
    ) -> RepositoryResult<u64> {
        let current = self
            .directory_node(id)?
            .filter(|node| !node.archived)
            .ok_or_else(|| RepositoryError::NotFound(format!("live directory node {}", id.0)))?;
        let mut updated = current.clone();
        updated.name = name.to_owned();
        updated.slug = slug.to_owned();
        updated.description = description.map(str::to_owned);
        updated.updated_at = updated_at.clone();
        updated
            .validate()
            .map_err(|error| RepositoryError::Conflict(error.to_string()))?;
        if updated.name == current.name
            && updated.slug == current.slug
            && updated.description == current.description
        {
            return self.directory_revision(&current.org_id);
        }

        let nodes = self.table("directory_nodes");
        let writes = [
            SqlWrite {
                sql: format!(
                    "UPDATE {} SET revision = revision WHERE org_id = ?",
                    self.table("directory_fence")
                ),
                params: vec![p(current.org_id.0.clone())],
            },
            SqlWrite {
                sql: format!(
                    "UPDATE {nodes} SET name = ?, slug = ?, description = ?, updated_at = ? \
                     WHERE id = ? AND archived = 0 \
                       AND NOT EXISTS (SELECT 1 FROM {nodes} sibling \
                         WHERE sibling.org_id = ? AND sibling.parent_id = ? \
                           AND sibling.slug = ? AND sibling.id <> ?)"
                ),
                params: vec![
                    p(name.to_owned()),
                    p(slug.to_owned()),
                    description.map(str::to_owned),
                    p(updated_at.0.clone()),
                    p(id.0.clone()),
                    p(current.org_id.0.clone()),
                    p(current
                        .parent_id
                        .map_or_else(String::new, |parent| parent.0)),
                    p(slug.to_owned()),
                    p(id.0.clone()),
                ],
            },
            SqlWrite {
                sql: format!(
                    "INSERT INTO {} (at, actor, action, detail) VALUES (?, ?j, ?, ?)",
                    self.table("audit_events")
                ),
                params: vec![
                    p(updated_at.0.clone()),
                    p(json_encode(actor, "directory actor")?),
                    p("directory.node.update"),
                    p(format!("directory node {}", id.0)),
                ],
            },
            SqlWrite {
                sql: format!(
                    "UPDATE {} SET revision = revision + 1 WHERE org_id = ?",
                    self.table("directory_fence")
                ),
                params: vec![p(current.org_id.0.clone())],
            },
        ];
        self.backend
            .execute_transaction_checked(&writes, &[(0, 1), (1, 1), (2, 1), (3, 1)])?;
        self.directory_revision(&current.org_id)
    }

    fn product_space_placement(
        &self,
        org_id: &OrgId,
        product_space: &ProductSpaceRef,
    ) -> RepositoryResult<Option<ProductSpacePlacement>> {
        let sql = format!(
            "SELECT product, space_id, org_id, node_id FROM {} \
             WHERE org_id = ? AND product = ? AND space_id = ?",
            self.table("product_space_bindings")
        );
        self.backend
            .query(
                &sql,
                &[
                    p(org_id.0.clone()),
                    p(product_space.product_id.as_str().to_owned()),
                    p(product_space.space_id.clone()),
                ],
            )?
            .first()
            .map(decode_product_space_placement)
            .transpose()
    }

    fn directory_revision(&self, org_id: &OrgId) -> RepositoryResult<u64> {
        let sql = format!(
            "SELECT CAST(revision AS TEXT) FROM {} WHERE org_id = ?",
            self.table("directory_fence")
        );
        let rows = self.backend.query(&sql, &[p(org_id.0.clone())])?;
        let revision = rows
            .first()
            .and_then(|row| row.first())
            .and_then(Option::as_deref);
        revision.map_or(Ok(1), |revision| {
            revision.parse().map_err(|error| {
                RepositoryError::Backend(format!("invalid directory revision: {error}"))
            })
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use awaken_iam_core::{AuditSink, OrgRepository, Organization};

    #[derive(Debug, Clone)]
    struct FailingTransaction {
        inner: crate::SqliteBackend,
        fail_at: usize,
    }

    impl SqlConn for FailingTransaction {
        fn dialect(&self) -> Dialect {
            self.inner.dialect()
        }

        fn execute(&self, sql: &str, params: &[SqlParam]) -> RepositoryResult<u64> {
            self.inner.execute(sql, params)
        }

        fn query(&self, sql: &str, params: &[SqlParam]) -> RepositoryResult<Vec<SqlRow>> {
            self.inner.query(sql, params)
        }

        fn execute_transaction(&self, writes: &[SqlWrite]) -> RepositoryResult<Vec<u64>> {
            self.inner.execute_transaction(writes)
        }

        fn execute_transaction_checked(
            &self,
            writes: &[SqlWrite],
            required: &[(usize, u64)],
        ) -> RepositoryResult<Vec<u64>> {
            let mut writes = writes.to_vec();
            writes[self.fail_at].sql = "invalid SQL injected by Directory rollback test".into();
            self.inner.execute_transaction_checked(&writes, required)
        }
    }

    fn timestamp() -> Timestamp {
        Timestamp("2026-08-27T00:00:00Z".into())
    }

    fn actor() -> PrincipalRef {
        PrincipalRef::Service {
            service_id: "directory-rollback-test".into(),
        }
    }

    #[test]
    fn every_create_write_failure_rolls_back_all_directory_effects() {
        // Cause-effect decision table: for each transaction write W1 fence init,
        // W2 Org mutex, W3 node, W4 placement, W5 audit, W6 revision, inject one
        // backend failure -> no node, placement or Directory audit survives.
        // This traces the repository's all-or-nothing effect at every boundary.
        for fail_at in 0..6 {
            let backend = crate::SqliteBackend::open_in_memory().unwrap();
            let authoritative =
                crate::sqlite_migrated_store(backend.clone(), "directory_rollback").unwrap();
            let org_id = OrgId("acme".into());
            OrgRepository::upsert(
                &authoritative,
                Organization {
                    id: org_id.clone(),
                    display_name: None,
                    owner: actor(),
                    created_at: timestamp(),
                    updated_at: timestamp(),
                },
            )
            .unwrap();
            let node_id = DirectoryNodeId("node-a".into());
            let product_space = ProductSpaceRef {
                product_id: ProductId::new("agents").unwrap(),
                space_id: "workspace/a".into(),
            };
            let failing = SqlStore::with_prefix(
                FailingTransaction {
                    inner: backend,
                    fail_at,
                },
                "directory_rollback",
            )
            .unwrap();
            let result = DirectoryRepository::create_directory_node(
                &failing,
                DirectoryNode {
                    id: node_id.clone(),
                    org_id: org_id.clone(),
                    parent_id: None,
                    name: "Agents".into(),
                    slug: "agents".into(),
                    description: None,
                    archived: false,
                    created_at: timestamp(),
                    updated_at: timestamp(),
                },
                Some(ProductSpacePlacement {
                    product_space: product_space.clone(),
                    org_id: org_id.clone(),
                    node_id: node_id.clone(),
                }),
                &actor(),
            );
            assert!(
                matches!(result, Err(RepositoryError::Backend(_))),
                "W{fail_at}"
            );
            assert!(
                DirectoryRepository::directory_node(&authoritative, &node_id)
                    .unwrap()
                    .is_none(),
                "W{fail_at}"
            );
            assert!(
                DirectoryRepository::product_space_placement(
                    &authoritative,
                    &org_id,
                    &product_space
                )
                .unwrap()
                .is_none(),
                "W{fail_at}"
            );
            assert!(
                AuditSink::events(&authoritative)
                    .unwrap()
                    .iter()
                    .all(|event| !event.action.starts_with("directory.")),
                "W{fail_at}"
            );
        }
    }
}
