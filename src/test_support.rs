//! Test-only helpers shared by more than one test module.
//!
//! These helpers live in one place for two reasons. They encode a *property
//! of the source tree* that more than one independent guard uses. A helper
//! that is copied into three files is a helper that someone fixes in one file
//! and not in the other two. `production_source` was exactly that helper: it
//! had three byte-identical copies. One copy carried a comment that said all
//! three copies were tested, but only two were.

/// Returns the production part of the Rust source file at `path`.
///
/// Guards use this function to check a property of the *production* code.
/// An example is the check that no hand-rolled error envelope exists outside
/// the one construction site. Another is the check that no `fs` to `sync`
/// dependency forms again. The guards scan the result of this function.
///
/// # What it strips
///
/// - Lines that contain only a comment, because they hold no code that can
///   break a guard.
/// - The test module and everything after it, because tests may cross the
///   boundary to build test data.
///
/// # Why the terminator is `#[cfg(test)]` followed by `mod`
///
/// The attribute alone is not a reliable terminator. `#[cfg(test)]` also
/// marks single *items*. `src/db.rs` has three such items at column 0
/// (`test_prefix` and two builders) before its real test module. Stopping at
/// the first attribute at column 0 therefore cut `db.rs` at line 73 of 203.
/// That silently dropped `build_scratch_store`, which is unconditional public
/// API that `sync` uses to build a snapshot in RAM.
///
/// The function therefore stops only when the attribute opens a `mod`. That
/// rule distinguishes a test module from a test-only item at any indentation.
#[cfg(test)]
pub(crate) fn production_source(path: &str) -> String {
    let src = std::fs::read_to_string(path).unwrap_or_else(|e| panic!("read {path}: {e}"));
    let lines: Vec<&str> = src.lines().collect();
    let mut out = String::new();
    let mut index = 0;

    while index < lines.len() {
        let line = lines[index];
        if line.trim_start().starts_with("//") {
            index += 1;
            continue;
        }
        // An attribute at column 0 opens the test module only if the
        // next line that is not blank declares a `mod`. Everything
        // from that line on is test-only.
        if line == "#[cfg(test)]" && next_declares_mod(&lines[index + 1..]) {
            break;
        }
        out.push_str(line);
        out.push('\n');
        index += 1;
    }

    out
}

/// Whether the next non-blank, non-comment line opens a module.
#[cfg(test)]
fn next_declares_mod(rest: &[&str]) -> bool {
    rest.iter()
        .find(|line| {
            let trimmed = line.trim();
            !trimmed.is_empty() && !trimmed.starts_with("//")
        })
        .is_some_and(|line| {
            line.trim()
                .strip_prefix("mod ")
                .is_some_and(|name| name.contains('{') || name.ends_with(';'))
        })
}

/// A file that holds every shape that has fooled `production_source`:
///
/// 1. Production code.
/// 2. An indented `#[cfg(test)]` on an item.
/// 3. More production code.
/// 4. A `#[cfg(test)]` at column 0 on a single item.
/// 5. More production code.
/// 6. The real test module.
///
/// The two `SENTINEL` strings are what a guard looks for. A test can
/// therefore report whether it saw the production code on both sides of the
/// traps.
#[cfg(test)]
pub(crate) const FIXTURE: &str = r#"pub fn before() {}
    #[cfg(test)]
    pub(crate) fn indented_test_only_item() -> u8 {
        1
    }

pub fn between_traps() {}

#[cfg(test)]
pub(crate) fn column_zero_test_only_item() -> u8 {
    2
}

pub fn after_column_zero_trap() {}

#[cfg(test)]
mod tests {
    const SENTINEL: &str = "must not be scanned";
}
"#;

/// Writes [`FIXTURE`] to a uniquely named temp file and returns its path.
#[cfg(test)]
pub(crate) fn write_fixture(label: &str) -> std::path::PathBuf {
    let path = std::env::temp_dir().join(format!(
        "rust-api-{label}-prod-source-{}-{:?}.rs",
        std::process::id(),
        std::thread::current().id()
    ));
    std::fs::write(&path, FIXTURE).expect("write the fixture");
    path
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Every structural guard in this crate uses this helper, so the helper is
    /// tested against a file that holds every shape that has fooled it.
    #[test]
    fn production_source_stops_only_at_the_test_module() {
        let path = write_fixture("shared");
        let scanned = production_source(path.to_str().expect("utf-8 path"));
        let _ = std::fs::remove_file(&path);

        // Everything above the traps is production code.
        assert!(
            scanned.contains("pub fn before() {}"),
            "production code before any trap must be scanned:\n{scanned}"
        );
        // Production code after an indented item attribute.
        assert!(
            scanned.contains("pub fn between_traps() {}"),
            "an indented #[cfg(test)] item must not end the scan:\n{scanned}"
        );
        // Production code after an attribute at column 0. This is the
        // shape that cut src/db.rs at line 73 of 203.
        assert!(
            scanned.contains("pub fn after_column_zero_trap() {}"),
            "a column-0 #[cfg(test)] item must not end the scan:\n{scanned}"
        );
        // And the test module itself is excluded.
        assert!(
            !scanned.contains("must not be scanned"),
            "the test module must be excluded:\n{scanned}"
        );
    }
}
