//! Operational tooling for policy stores: JSON export/import.
//!
//! Both directions go through the same Enforcer/adapter/validator paths as
//! production, so an exported snapshot reflects exactly what enforcement
//! used, and an imported snapshot satisfies the same validation contract.

use std::path::Path;

use anyhow::Context as _;
use casbin::{CoreApi, DefaultModel, Enforcer, MgmtApi};
use serde::{Deserialize, Serialize};

use super::{RBAC_MODEL, adapter::OxkvAdapter};
use crate::policy::adapter::PolicyRuleValidator;

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

/// Opens a validated, hook-wrapped store at the given path. Shared by
/// export/import so both see the same storage contract as the server.
fn open_store(store_path: &Path) -> anyhow::Result<OxkvAdapter<oxkv::HookStore<oxkv::RedbStore>>> {
    if let Some(parent) = store_path.parent()
        && !parent.as_os_str().is_empty()
    {
        std::fs::create_dir_all(parent)?;
    }
    let store = oxkv::HookStore::new(oxkv::RedbStore::new_file(store_path)?)
        .with_validator(PolicyRuleValidator);
    Ok(OxkvAdapter::new(store))
}

async fn open_enforcer(store_path: &Path) -> anyhow::Result<Enforcer> {
    let model = DefaultModel::from_str(RBAC_MODEL)
        .await
        .context("failed to parse RBAC model")?;
    let enforcer = Enforcer::new(model, open_store(store_path)?)
        .await
        .context("failed to open policy store")?;
    Ok(enforcer)
}

/// Reads every policy rule from the store at `store_path`.
///
/// The store is opened read-only from the caller's perspective; no rules
/// are modified.
pub async fn export(store_path: &Path) -> anyhow::Result<PolicyDump> {
    let enforcer = open_enforcer(store_path).await?;
    Ok(PolicyDump {
        p: enforcer.get_policy(),
        g: enforcer.get_grouping_policy(),
    })
}

/// Writes `dump`'s rules into the store at `store_path`.
///
/// Idempotent: entries that already exist are counted as skipped instead of
/// failing the import, so re-running after a partial transfer converges.
/// Each rule passes the same validation hook as live API writes.
pub async fn import(store_path: &Path, dump: &PolicyDump) -> anyhow::Result<ImportReport> {
    let mut enforcer = open_enforcer(store_path).await?;

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

#[cfg(test)]
mod tests {
    use super::*;

    fn temp_store(name: &str) -> std::path::PathBuf {
        std::env::temp_dir().join(format!("oxkv-admin-{name}-{}", std::process::id()))
    }

    #[tokio::test]
    async fn export_import_round_trip() -> anyhow::Result<()> {
        let source = temp_store("src");
        let target = temp_store("dst");

        // Seed the source store through the normal engine path.
        {
            let mut enforcer = open_enforcer(&source).await?;
            assert!(
                enforcer
                    .add_policy(vec!["admin".into(), "doc".into(), "read".into()])
                    .await?
            );
            assert!(
                enforcer
                    .add_grouping_policy(vec!["user-1".into(), "admin".into()])
                    .await?
            );
        }

        let dump_bytes = {
            let dump = export(&source).await?;
            serde_json::to_vec_pretty(&dump)?
        };

        // Import into a fresh store via the serialized form.
        let report: ImportReport = {
            let dump: PolicyDump = serde_json::from_slice(&dump_bytes)?;
            import(&target, &dump).await?
        };
        assert_eq!(report.rules_added, 1);
        assert_eq!(report.groups_added, 1);

        // Re-import must be fully idempotent.
        let dump: PolicyDump = serde_json::from_slice(&dump_bytes)?;
        let again = import(&target, &dump).await?;
        assert_eq!(again.rules_added, 0);
        assert_eq!(again.groups_added, 0);
        assert_eq!(again.duplicates, 2);

        // The imported store authorizes identically.
        let enforcer = open_enforcer(&target).await?;
        assert!(enforcer.enforce(("user-1", "doc", "read"))?);
        assert!(!enforcer.enforce(("user-1", "doc", "write"))?);

        std::fs::remove_file(source).ok();
        std::fs::remove_file(target).ok();
        Ok(())
    }

    #[tokio::test]
    async fn import_rejects_invalid_entries_via_validation_hook() {
        let target = temp_store("invalid");
        let dump = PolicyDump {
            p: vec![vec!["only-one-field".to_string()]], // arity violation
            g: vec![],
        };

        // The validator must surface the rejection rather than persist it.
        assert!(import(&target, &dump).await.is_err());
        std::fs::remove_file(target).ok();
    }
}
