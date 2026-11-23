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

/// Escapes one part of a relation key.
///
/// The backslash escapes first. The colon escape then inserts a backslash
/// that stays single. A row type or row id without a colon or a backslash
/// keeps its bytes, so an existing key stays valid.
fn escape(value: &str) -> String {
    value.replace('\\', "\\\\").replace(':', "\\:")
}

/// Splits a relation row part at the first colon that a backslash does not
/// escape.
fn split_unescaped(value: &str) -> Option<(&str, &str)> {
    let mut escaped = false;
    for (at, ch) in value.char_indices() {
        if escaped {
            escaped = false;
            continue;
        }
        match ch {
            '\\' => escaped = true,
            ':' => return Some((&value[..at], &value[at + 1..])),
            _ => {}
        }
    }
    None
}

/// Inverts [`escape`] for one part of a relation key.
///
/// The function is lenient. A backslash before a character other than `:`
/// or `\` stays in place, so that a relation key from an older build still
/// decodes.
fn unescape(value: &str) -> String {
    let mut out = String::with_capacity(value.len());
    let mut chars = value.chars();
    while let Some(ch) = chars.next() {
        if ch != '\\' {
            out.push(ch);
            continue;
        }
        match chars.next() {
            Some(':') => out.push(':'),
            Some('\\') => out.push('\\'),
            Some(other) => {
                out.push('\\');
                out.push(other);
            }
            None => out.push('\\'),
        }
    }
    out
}

/// Key for `rel:{row_type}:{row_id}:{file_id}`.
///
/// The function escapes the row type and the row id. The row pair
/// `("a:b", "c")` and the row pair `("a", "b:c")` therefore give different
/// keys. A row id such as `12:3` also stays distinct from `12` plus a suffix
/// that starts with `3:`.
pub fn rel_key(row_type: &str, row_id: &str, file_id: &str) -> String {
    format!("fs:rel:{}:{}:{file_id}", escape(row_type), escape(row_id))
}

/// Key for `fs:files:{id}:refs`.
pub fn refs_key(file_id: &str) -> String {
    format!("fs:files:{file_id}:refs")
}

/// Prefix for a scan of the relations of one row.
pub fn rel_prefix_for_row(row_type: &str, row_id: &str) -> String {
    format!("fs:rel:{}:{}:", escape(row_type), escape(row_id))
}

/// The relation key that this crate wrote before it escaped row parts.
///
/// The function supports a relation that an older build stored. New writes
/// use [`rel_key`]. The two strings are equal when the row parts contain no
/// colon and no backslash.
pub fn legacy_rel_key(row_type: &str, row_id: &str, file_id: &str) -> String {
    format!("fs:rel:{row_type}:{row_id}:{file_id}")
}

/// The old row prefix that this crate wrote before it escaped row parts.
pub fn legacy_rel_prefix_for_row(row_type: &str, row_id: &str) -> String {
    format!("fs:rel:{row_type}:{row_id}:")
}

/// Decodes the row pair of a relation key.
///
/// The function removes the known `:{file_id}` suffix first. It then splits
/// the remainder at the first unescaped colon. That order is necessary,
/// because a row id may contain a colon.
pub fn parse_rel_key(key: &str, file_id: &str) -> Option<(String, String)> {
    let rest = key.strip_prefix(REL_PREFIX)?;
    let rest = rest.strip_suffix(file_id)?.strip_suffix(':')?;
    let (row_type, row_id) = split_unescaped(rest)?;
    if row_type.is_empty() || row_id.is_empty() {
        return None;
    }
    Some((unescape(row_type), unescape(row_id)))
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

    /// The escaped key format keeps the old bytes for a plain row.
    #[test]
    fn a_plain_row_keeps_the_legacy_key() {
        for (row_type, row_id) in [("invoice", "123"), ("report", "a_b")] {
            assert_eq!(
                rel_key(row_type, row_id, "file1"),
                legacy_rel_key(row_type, row_id, "file1")
            );
            assert_eq!(
                rel_prefix_for_row(row_type, row_id),
                legacy_rel_prefix_for_row(row_type, row_id)
            );
        }
    }

    /// A colon in the type or the id must not collide with the other split.
    #[test]
    fn a_colon_in_a_row_part_does_not_collide() {
        assert_eq!(
            rel_key("invoice", "12:3", "file1"),
            "fs:rel:invoice:12\\:3:file1"
        );
        assert_eq!(
            rel_key("invoice:12", "3", "file1"),
            "fs:rel:invoice\\:12:3:file1"
        );
        assert_ne!(rel_key("a:b", "c", "file1"), rel_key("a", "b:c", "file1"));
        assert_ne!(
            rel_prefix_for_row("a:b", "c"),
            rel_prefix_for_row("a", "b:c")
        );
    }

    #[test]
    fn parse_rel_key_keeps_a_colon_in_the_row_id() {
        let key = rel_key("invoice", "12:3", "file1");
        assert_eq!(
            parse_rel_key(&key, "file1"),
            Some(("invoice".to_string(), "12:3".to_string()))
        );
        let key = rel_key("a:b", "c", "file1");
        assert_eq!(
            parse_rel_key(&key, "file1"),
            Some(("a:b".to_string(), "c".to_string()))
        );
    }

    /// An old key without an escape still decodes.
    #[test]
    fn parse_rel_key_accepts_a_legacy_key() {
        assert_eq!(
            parse_rel_key("fs:rel:invoice:12:3:file1", "file1"),
            Some(("invoice".to_string(), "12:3".to_string()))
        );
        assert_eq!(
            parse_rel_key("fs:rel:invoice:12\\b:file1", "file1"),
            Some(("invoice".to_string(), "12\\b".to_string()))
        );
        assert_eq!(parse_rel_key("fs:rel:invoice:12:other", "file1"), None);
        assert_eq!(parse_rel_key("fs:rel::12:file1", "file1"), None);
    }

    #[test]
    fn ref_info_default_is_orphan() {
        let r = RefInfo::default();
        assert_eq!(r.count, 0);
        assert!(r.orphan_since.is_none());
    }
}
