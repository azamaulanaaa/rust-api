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

## Local CI

The repository ships git hooks that mirror the CI workflow.

Install the hooks:

```bash
mise run hooks
```

This command sets `core.hooksPath` to `.githooks` and marks the hook files executable.

The `pre-commit` hook runs `mise run lint` when staged changes exist. The `pre-push` hook runs `.githooks/ci-local.sh` with the default jobs. The default jobs are lint, test, MSRV, docs, release config, licences, advisories, and bans.

Run one job on demand:

```bash
.githooks/ci-local.sh lint
```

Run several jobs:

```bash
.githooks/ci-local.sh lint test doc
```

Run every job, including coverage:

```bash
.githooks/ci-local.sh --all
```

Run coverage only:

```bash
.githooks/ci-local.sh coverage
```

List the job names or show the help:

```bash
.githooks/ci-local.sh --list
.githooks/ci-local.sh --help
```

The script skips a job when a required tool is missing. The warning names the tool and the install command. Run `mise install` to install the tools. The script also skips the MSRV job when the declared toolchain is not installed. It does not download the toolchain.

Set `CI_LOCAL_STRICT=1` to turn every skip into a failure:

```bash
CI_LOCAL_STRICT=1 .githooks/ci-local.sh
```

Set `CI_LOCAL_SKIP=1` to skip the `pre-push` hook for one push. Use `git push --no-verify` to bypass the hook.

The hooks are local. A push with `--no-verify` still runs CI on GitHub.

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
