//! Test-only helpers shared by more than one test module.
//!
//! These live in one place because they encode a *property of the source
//! tree* that several independent guards rely on, and because a helper copied
//! into three files is a helper that will be fixed in one of them and not the
//! other two. `production_source` was exactly that: three byte-identical
//! copies, and one of the three copies carried a comment claiming all three
//! were tested when only two were.

/// Returns the production part of the Rust source file at `path`.
///
/// Guards that assert a property of the *production* code — no hand-rolled
/// error envelope outside the one construction site, no `fs`↔`sync` dependency
/// re-forming, no duplicated casbin read body — scan the result of this.
///
/// # What it strips
///
/// - comment-only lines, which carry no code to violate a guard;
/// - the test module and everything after it, since tests legitimately reach
///   across the boundary to build fixtures.
///
/// # Why the terminator is `#[cfg(test)]` followed by `mod`
///
/// The attribute alone is not a reliable terminator. `#[cfg(test)]` also
/// annotates single *items* — `src/db.rs` has three of them at column 0
/// (`test_prefix`, and two builders) before its real test module. Stopping at
/// the first column-0 attribute therefore truncated `db.rs` to line 73 of 203
/// and silently dropped `build_scratch_store`, which is unconditional public
/// API that `sync` uses to assemble a snapshot in RAM.
///
/// Stopping only when the attribute opens a `mod` is what distinguishes a
/// test module from a test-only item at any indentation.
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
        // A column-0 `#[cfg(test)]` opens the test module only if the next
        // non-blank line declares one. Everything from there on is test-only.
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

/// A file carrying every shape that has ever fooled `production_source`:
/// production code, an indented `#[cfg(test)]` on an item, more production
/// code, a column-0 `#[cfg(test)]` on a single item, more production code,
/// and only then the real test module.
///
/// The two `SENTINEL` strings are what a guard looks for, so a test can say
/// whether it saw the production code either side of the traps.
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

    /// The helper is the thing every structural guard in this crate trusts, so
    /// it is tested against a file carrying every shape that has fooled it.
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
        // Production code AFTER an indented item attribute.
        assert!(
            scanned.contains("pub fn between_traps() {}"),
            "an indented #[cfg(test)] item must not end the scan:\n{scanned}"
        );
        // Production code after a COLUMN-0 item attribute -- the shape that
        // truncated src/db.rs to line 73 of 203.
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
