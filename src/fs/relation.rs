//! File-to-row relations with reference counting.
//!
//! A file is `Temp` when `refs==0` and becomes `Owned` when attached to
//! one or more rows. Editing a row detaches the old file and attaches a
//! new one without deleting the underlying S3 object immediately.

use serde::{Deserialize, Serialize};

/// Reference-count metadata for a file.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Default)]
pub struct RefInfo {
    /// Number of rows referencing the file.
    pub count: u32,
    /// When `count` dropped to `0`, the timestamp for GC.
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

/// Prefix for scanning relations of a row.
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
        assert_eq!(rel_key("invoice", "123", "file1"), "fs:rel:invoice:123:file1");
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
