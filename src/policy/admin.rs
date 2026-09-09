//! Operational tooling for policy stores: JSON export/import on S3.

use casbin::{CoreApi, DefaultModel, Enforcer, MgmtApi};
use serde::{Deserialize, Serialize};

use super::{RBAC_MODEL, adapter::OxkvAdapter};

/// A portable snapshot of every policy rule in a store.
#[derive(Debug, Serialize, Deserialize)]
pub struct PolicyDump {
    /// Permission rules (`p`), each as `[sub, obj, act]`.
    pub p: Vec<Vec<String>>,
    /// Group-membership rules (`g`), each as `[user, group]`.
    pub g: Vec<Vec<String>>,
}

/// Result of an import: how many rules/groups were newly written and how
/// many were skipped because they already existed (imports are idempotent).
#[derive(Debug, PartialEq, Eq)]
pub struct ImportReport {
    /// Newly written permission rules.
    pub rules_added: usize,
    /// Newly written group memberships.
    pub groups_added: usize,
    /// Entries already present in the store and left untouched.
    pub duplicates: usize,
}

/// Reads every policy rule from an OxKV store.
pub async fn export_s3(s3_store: oxkv::OxKvStore) -> anyhow::Result<PolicyDump> {
    use anyhow::Context as _;
    let model = DefaultModel::from_str(RBAC_MODEL)
        .await
        .context("failed to parse RBAC model")?;
    let enforcer = Enforcer::new(model, OxkvAdapter::new(s3_store))
        .await
        .context("failed to open policy store")?;
    Ok(PolicyDump {
        p: enforcer.get_policy(),
        g: enforcer.get_grouping_policy(),
    })
}

/// Writes `dump`'s rules into an S3 store. Idempotent.
pub async fn import_s3(
    s3_store: oxkv::OxKvStore,
    dump: &PolicyDump,
) -> anyhow::Result<ImportReport> {
    use anyhow::Context as _;
    let model = DefaultModel::from_str(RBAC_MODEL)
        .await
        .context("failed to parse RBAC model")?;
    let mut enforcer = Enforcer::new(model, OxkvAdapter::new(s3_store))
        .await
        .context("failed to open policy store")?;

    let mut report = ImportReport {
        rules_added: 0,
        groups_added: 0,
        duplicates: 0,
    };
    for rule in &dump.p {
        if enforcer.add_policy(rule.clone()).await? {
            report.rules_added += 1;
        } else {
            report.duplicates += 1;
        }
    }
    for link in &dump.g {
        if enforcer.add_grouping_policy(link.clone()).await? {
            report.groups_added += 1;
        } else {
            report.duplicates += 1;
        }
    }
    Ok(report)
}

/// Deprecated file-based export shim — use [`export_s3`].
#[deprecated(note = "Use export_s3/import_s3 with OxKvStore")]
#[allow(missing_docs)]
pub async fn export(_store_path: &std::path::Path) -> anyhow::Result<PolicyDump> {
    anyhow::bail!("export(Path) removed — use export_s3(OxKvStore) via --config")
}

/// Deprecated file-based import shim — use [`import_s3`].
#[deprecated(note = "Use export_s3/import_s3 with OxKvStore")]
#[allow(missing_docs)]
pub async fn import(
    _store_path: &std::path::Path,
    _dump: &PolicyDump,
) -> anyhow::Result<ImportReport> {
    anyhow::bail!("import(Path) removed — use import_s3(OxKvStore, dump) via --config")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::db::{build_test_store, build_test_store_new_session};
    use std::sync::Arc;

    #[tokio::test]
    async fn export_import_round_trip() -> anyhow::Result<()> {
        let shared =
            Arc::new(object_store::memory::InMemory::new()) as Arc<dyn object_store::ObjectStore>;
        let src_prefix = format!("admin-test-src-{}-{}", std::process::id(), {
            use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
            URL_SAFE_NO_PAD.encode(rand::random::<[u8; 6]>())
        });
        let dst_prefix = format!("{src_prefix}-dst");
        let src_store = build_test_store_new_session(shared.clone(), &src_prefix).await;
        let _dst_store = build_test_store_new_session(shared.clone(), &dst_prefix).await;

        let dump = PolicyDump {
            p: vec![vec!["admin".into(), "doc".into(), "read".into()]],
            g: vec![vec!["user-1".into(), "admin".into()]],
        };
        import_s3(src_store, &dump).await?;

        // Fresh handle, hence a new fencing session over the same prefix
        // (superseding the previous session via epoch fencing); the previous
        // handle is dead by now.
        let src_store2 = build_test_store_new_session(shared.clone(), &src_prefix).await;
        let dump = export_s3(src_store2).await?;
        let dump_bytes = serde_json::to_vec_pretty(&dump)?;

        let dump: PolicyDump = serde_json::from_slice(&dump_bytes)?;
        let dst_store2 = build_test_store_new_session(shared.clone(), &dst_prefix).await;
        let report = import_s3(dst_store2, &dump).await?;
        assert_eq!(report.rules_added, 1);
        assert_eq!(report.groups_added, 1);

        let dump: PolicyDump = serde_json::from_slice(&dump_bytes)?;
        let dst_store3 = build_test_store_new_session(shared, &dst_prefix).await;
        let again = import_s3(dst_store3, &dump).await?;
        assert_eq!(again.rules_added, 0);
        assert_eq!(again.groups_added, 0);
        assert_eq!(again.duplicates, 2);
        Ok(())
    }

    #[tokio::test]
    async fn import_rejects_invalid_entries_via_validation_hook() {
        // The adapter enforces PolicyRuleValidator on every write path
        // itself (see encode_rule), so an invalid dump fails the import
        // instead of being persisted.
        let store = build_test_store("admin-test-invalid").await;
        let dump = PolicyDump {
            p: vec![vec!["only-one-field".to_string()]],
            g: vec![],
        };
        assert!(import_s3(store, &dump).await.is_err());
    }
}
