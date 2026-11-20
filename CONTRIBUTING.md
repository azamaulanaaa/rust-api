# Contributing

Thanks for contributing. This guide covers build, test, style, commits, and pull requests.

## Prerequisites

Install the toolchain with mise:

```bash
mise install
```

mise provides Rust stable, zig, cargo-deny, cargo-dist, and cargo-llvm-cov.

The MSRV job needs the Rust version declared by `rust-version` in `Cargo.toml`. Install it once:

```bash
mise run msrv-install
```

This command is safe to rerun. It repairs an interrupted toolchain install.

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
cargo clippy --all-targets --all-features --locked -- -D warnings
```

CI runs clippy with `-D warnings`. unwrap and expect are denied in non-test code. The clippy config allows them in tests.

Check dependencies:

```bash
mise run licenses
mise run advisories
mise run bans
mise run sources
```

These run cargo-deny. See `deny.toml` for the rules.

## Local CI

By default, checks use a `smolvm serve` server when `SMOLVM_ADDR` is set, a local microVM when smolvm and the accelerator are available, and the host otherwise. The host path prints a warning first. Set `SMOLVM_ENABLED=1` to enforce smolvm. The run then exits 3 when neither a remote server nor a local microVM is available. The checks do not run on the host in that mode. See [the smolvm document](docs/smolvm.md) for setup.

Install the hooks:

```bash
make hooks
```

This command sets `core.hooksPath` to `.githook` and marks the hook files executable.

The `pre-commit` hook calls `scripts/ci.sh` before each commit. The `pre-push` hook calls `scripts/ci.sh` before each push. The `commit-msg` hook checks the commit message with cocogitto.

Use `git --no-verify` only when you must bypass a hook. GitHub Actions still runs CI on a push.

Run all checks with the mode cascade:

```bash
make ci
# or
scripts/ci.sh
```

Run one check on demand:

```bash
make check-clippy
make check-cargo
make check-rustfmt
```

Some Rust checks skip when `cargo` is absent. For a remote run, the server image must provide Rust, cargo, and `cargo-deny`. For a local microVM, `smol/pack-build.sh` installs the tools in the pack.

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
2. Run `make ci` with your smolvm mode set. The `pre-push` hook runs the checks before the push.
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
