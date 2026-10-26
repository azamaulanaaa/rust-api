# Contributing

Thanks for contributing. This guide covers build, test, style, commits, and pull requests.

## Prerequisites

Install the toolchain with mise:

```bash
mise install
```

mise provides Rust stable, zig, cargo-deny, cargo-dist, and cargo-llvm-cov.

## Build

```bash
mise run build
# or
cargo build --all-targets --all-features
```

`mise run build` links with zig for cross builds. CI uses plain cargo.

## Test

```bash
mise run test
# or
cargo test --all-targets --all-features
cargo test --doc
```

Integration tests use wiremock. FsEngine and PolicyEngine tests use an InMemory-backed OxKvStore. Those stores use `skip_probe(true)`. They are test-only. Do not use them in production code.

## Code style

Format with rustfmt:

```bash
cargo fmt --all
```

CI checks formatting with `cargo fmt --all --check`.

Lint with clippy:

```bash
cargo clippy --all-targets --all-features
```

CI runs clippy with `-D warnings`. unwrap and expect are denied in non-test code. The clippy config allows them in tests.

Check dependencies:

```bash
mise run licenses
mise run advisories
mise run bans
```

These run cargo-deny. See `deny.toml` for the rules.

## Documentation

Every public item must carry rustdoc. `Cargo.toml` sets `missing_docs = "deny"`. The compiler enforces this at build time. CI also runs `cargo doc --no-deps --all-features` with `RUSTDOCFLAGS="-D warnings"`.

Write doc comments in STE style. Keep sentences short. Use active voice. Put one idea in each sentence.

## Commits

Commit messages follow Conventional Commits. Use this format:

```
<type>(<scope>): <subject>
```

Scope is optional. It names the part of the crate that changed. Common types: feat, fix, docs, refactor, test, chore. Add `!` after the type or scope for a breaking change.

Examples:

```
feat(fs): add store-level WAL orphan pass
fix(sync)!: revalidate every mutable object in a replica prefix
docs(readme): apply STE to the development section
```

One logical change per commit. Keep the subject under 72 characters. Use the body to explain why, not what.

## Pull requests

1. Fork the repository and create a branch from `main`.
2. Run `mise run check` before you push. It runs lint, tests, deps, MSRV, docs, and the dist check.
3. Open the pull request against `main`.
4. Describe the change, the motivation, and the testing done.
5. Update documentation when behavior changes.
6. Keep the diff focused. Split unrelated changes into separate pull requests.

Reviewers check CI, code style, tests, and documentation. Address review comments with new commits.

## Testing notes

- FsStore and PolicyEngine tests use an InMemory-backed OxKvStore. They reach it through `#[cfg(test)]` helpers in `db.rs`. Those helpers are not public API.
- A store without a conditional-write probe suits a test backend. It does not suit production.
- Single-threaded reopen uses a new session per store.
- wiremock mocks the identity provider and S3 in integration tests.
