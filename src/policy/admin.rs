//! Operational tooling for policy stores. It exports and imports JSON on S3.

use casbin::{CoreApi, DefaultModel, Enforcer, MgmtApi};
use serde::{Deserialize, Serialize};

use super::{RBAC_MODEL, adapter::OxkvAdapter};
use crate::records::{ChangeSink, WalOp};

/// A portable snapshot of every policy rule in a store.
#[derive(Debug, Serialize, Deserialize)]
pub struct PolicyDump {
    /// Permission rules (`p`), each as `[sub, obj, act]`.
    pub p: Vec<Vec<String>>,
    /// Group-membership rules (`g`), each as `[user, group]`.
    pub g: Vec<Vec<String>>,
}

/// The result of an import. It counts the rules and groups that the import
/// wrote for the first time. It also counts the entries that the import
/// skipped, because the entry already existed. An import is idempotent.
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

/// Writes the rules of `dump` into an S3 store. Running the function
/// again does not change the result.
///
/// The function announces the new rules to `feed` when the feed is wired.
/// A replica can therefore replay the import instead of discovering it only
/// through a full recalculation.
pub async fn import_s3(
    s3_store: oxkv::OxKvStore,
    dump: &PolicyDump,
    feed: Option<std::sync::Arc<dyn ChangeSink>>,
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
            if let Some(feed) = &feed {
                feed.append(WalOp::PolicyRuleAdd {
                    sub: rule.first().cloned().unwrap_or_default(),
                    obj: rule.get(1).cloned().unwrap_or_default(),
                    act: rule.get(2).cloned().unwrap_or_default(),
                })
                .await
                .context("append policy change feed")?;
            }
        } else {
            report.duplicates += 1;
        }
    }
    for link in &dump.g {
        if enforcer.add_grouping_policy(link.clone()).await? {
            report.groups_added += 1;
            if let Some(feed) = &feed {
                feed.append(WalOp::GroupAdd {
                    user: link.first().cloned().unwrap_or_default(),
                    group: link.get(1).cloned().unwrap_or_default(),
                })
                .await
                .context("append policy change feed")?;
            }
        } else {
            report.duplicates += 1;
        }
    }
    Ok(report)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::db::{build_test_store, build_test_store_new_session};
    use crate::sync::wal::Wal;
    use std::sync::Arc;

    #[tokio::test]
    async fn export_import_round_trip() -> anyhow::Result<()> {
        let shared =
            Arc::new(object_store::memory::InMemory::new()) as Arc<dyn object_store::ObjectStore>;
        let src_prefix = crate::db::test_prefix("admin-src");
        let dst_prefix = crate::db::test_prefix("admin-dst");
        let src_store = build_test_store_new_session(shared.clone(), &src_prefix).await;
        let _dst_store = build_test_store_new_session(shared.clone(), &dst_prefix).await;

        let dump = PolicyDump {
            p: vec![vec!["admin".into(), "doc".into(), "read".into()]],
            g: vec![vec!["user-1".into(), "admin".into()]],
        };
        let wal = Wal::new(build_test_store(&crate::db::test_prefix("admin-wal")).await);
        import_s3(src_store, &dump, Some(Arc::new(wal.clone()))).await?;
        assert_eq!(wal.head().await?, 2);

        // The code uses a fresh handle. The handle starts a new fencing
        // session over the same prefix. Epoch fencing supersedes the
        // previous session, so the previous handle is dead by now.
        let src_store2 = build_test_store_new_session(shared.clone(), &src_prefix).await;
        let dump = export_s3(src_store2).await?;
        let dump_bytes = serde_json::to_vec_pretty(&dump)?;

        let dump: PolicyDump = serde_json::from_slice(&dump_bytes)?;
        let dst_store2 = build_test_store_new_session(shared.clone(), &dst_prefix).await;
        let report = import_s3(dst_store2, &dump, None).await?;
        assert_eq!(report.rules_added, 1);
        assert_eq!(report.groups_added, 1);

        let dump: PolicyDump = serde_json::from_slice(&dump_bytes)?;
        let dst_store3 = build_test_store_new_session(shared, &dst_prefix).await;
        let again = import_s3(dst_store3, &dump, None).await?;
        assert_eq!(again.rules_added, 0);
        assert_eq!(again.groups_added, 0);
        assert_eq!(again.duplicates, 2);
        Ok(())
    }

    #[tokio::test]
    async fn import_rejects_invalid_entries_through_the_validator() {
        // The adapter enforces PolicyRuleValidator on every write path
        // itself (see encode_rule). The dump therefore fails the import
        // instead of being persisted.
        let store = build_test_store(&crate::db::test_prefix("admin-invalid")).await;
        let dump = PolicyDump {
            p: vec![vec!["only-one-field".to_string()]],
            g: vec![],
        };
        assert!(import_s3(store, &dump, None).await.is_err());
    }
}
