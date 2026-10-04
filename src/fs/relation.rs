//! Relations between files and rows, with reference counting.
//!
//! A file is `Temp` when `refs==0`. It becomes `Owned` when a row attaches
//! to it.
//! When a caller edits a row, the engine detaches the old file and
//! attaches a new one.
//! The engine does not delete the S3 object at once.

use serde::{Deserialize, Serialize};

/// Reference-count metadata for a file.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Default)]
pub struct RefInfo {
    /// The number of rows that reference the file.
    pub count: u32,
    /// The timestamp for GC. The engine sets it when `count` drops to `0`.
    pub orphan_since: Option<i64>,
}

/// Key for `rel:{row_type}:{row_id}:{file_id}`.
pub fn rel_key(row_type: &str, row_id: &str, file_id: &str) -> String {
    format!("fs:rel:{row_type}:{row_id}:{file_id}")
}

/// Key for `fs:files:{id}:refs`.
pub fn refs_key(file_id: &str) -> String {
    format!("fs:files:{file_id}:refs")
}

/// Prefix for a scan of the relations of one row.
pub fn rel_prefix_for_row(row_type: &str, row_id: &str) -> String {
    format!("fs:rel:{row_type}:{row_id}:")
}

/// Prefix for all relations.
pub const REL_PREFIX: &str = "fs:rel:";

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn keys_are_distinct() {
        assert_eq!(
            rel_key("invoice", "123", "file1"),
            "fs:rel:invoice:123:file1"
        );
        assert_eq!(refs_key("file1"), "fs:files:file1:refs");
        assert_eq!(rel_prefix_for_row("invoice", "123"), "fs:rel:invoice:123:");
        assert_ne!(rel_key("a", "b", "c"), refs_key("c"));
    }

    #[test]
    fn ref_info_default_is_orphan() {
        let r = RefInfo::default();
        assert_eq!(r.count, 0);
        assert!(r.orphan_since.is_none());
    }
}
