# Check pipeline

This document describes the check pipeline. The pipeline uses one entry
point, [`scripts/ci.sh`](../scripts/ci.sh).

## Overview

`scripts/ci.sh` runs every `scripts/check-*.sh` script in name order. It
prints `run: <script>` before each script. It prints `all checks passed (N
scripts)` after the last script. A failed check stops the run and gives a
non-zero exit status.

The check scripts cover shell syntax, shfmt, commit history, Markdown,
Docker files, EditorConfig, secrets, workflow files, mise config, Rust
tests, clippy, rustfmt, and cargo-deny. A check script checks one area. Some
Rust check scripts skip when `cargo` is absent.

[`mise`](https://mise.jdx.dev/) installs development tools. It does not
start the check pipeline. `scripts/check-mise.sh` uses `mise` only to check
`mise.toml`.

## Where the checks run

`scripts/ci.sh` follows the smolvm mode cascade. It uses the first available
path:

1. With `SMOLVM_ADDR` set, it sends the checks to that `smolvm serve`
   server. The helper uploads the working tree and runs the checks in a
   machine on the server.
2. With `smolvm` on PATH and a working accelerator, it runs the checks in a
   local microVM. On Linux the accelerator is `/dev/kvm`. On macOS with
   Apple Silicon it is `kern.hv_support=1`.
3. Otherwise it prints a warning on stderr and runs the checks on the host.

`SMOLVM_ENABLED=1` enforces smolvm. The checks must run in the local microVM
or on the remote server. When neither path is available, the script prints
an error on stderr and exits 3. The checks do not run on the host.

`SMOLVM_ENABLED=0` selects the guest path. Only the guest sets this value.
The script then runs the check scripts directly. It does not call
`scripts/smolvm.sh`, so it does not start another machine.

For a remote run, the server image must provide the Rust toolchain and the
check tools. See [the smolvm document](smolvm.md) for the environment
variables, the API flow, the local pack, preflight, and verify steps.

## Hooks

The hooks live in `.githook/`. Run `make hooks` to set `core.hooksPath` to
`.githook` and make the hooks executable.

- `.githook/commit-msg` runs `cog verify` on the commit message. A bad
  message stops the commit.
- `.githook/pre-commit` calls `scripts/ci.sh` before each commit.
- `.githook/pre-push` calls `scripts/ci.sh` before each push.

Use `git --no-verify` only when you must bypass a hook. GitHub Actions still
runs CI on a push.

## Makefile targets

Run `make help` to list every target. The main targets are:

- `make ci` runs `scripts/ci.sh`.
- `make smolvm` runs the checks in a smolvm microVM, local or remote.
- `make smolvm-exec ARGS='...'` runs one command in the microVM, local or
  remote.
- `make smolvm-clean` removes cached packs and dangling machines.
- `make check-<area>` runs one check script. The areas include `bash`,
  `cargo`, `clippy`, `rustfmt`, `coverage`, `msrv`, `no-default-features`,
  `doc`, `release-config`, `cargo-deny-advisories`, `cargo-deny-bans`,
  `cargo-deny-licenses`, and `cargo-deny-sources`.
- `make format` runs every `scripts/format-*.sh` script in name order.
- `make hooks` installs the Git hooks.

The template also provides the `make smolvm-pack`, `make smolvm-preflight`, and `make smolvm-verify` targets. See [the smolvm document](smolvm.md).

## GitHub Actions

The workflow [`ci.yml`](../.github/workflows/ci.yml) runs on each pull
request, each push to `main` and `feature/**`, a manual dispatch, and a weekly
schedule. It has one matrix job and these extra jobs: `pr-title`,
`gitleaks`, `editorconfig`, and `dependency-review`.

The matrix runs one check per entry. The feature/rust entries are `mise`,
`jactionlint`, `bash`, `shfmt`, `commits`, `markdown`, `hadolint`,
`dockerfmt`, `dclint`, `zizmor`, `cargo`, `clippy`, `rustfmt`,
`cargo-deny-advisories`, `cargo-deny-bans`, `cargo-deny-licenses`, and
`cargo-deny-sources`.

The project entries are `coverage`, `msrv`, `no-default-features`, `doc`, and
`release-config`. The `msrv` entry uses Rust 1.89. That version must match
`rust-version` in `Cargo.toml`. The `coverage` entry runs `cargo llvm-cov`
with a 90% line floor and uploads the HTML report as the `coverage-html`
artifact. `release-config` checks that the release workflow still gates
publishing on CI.

Set these job names as required status checks on the default branch. Do this
in the repository settings on GitHub, not in the repository files.

## Add a check

1. Create `scripts/check-<area>.sh` and make it executable.
2. Start with a shebang, a short comment, and `set -euo pipefail`.
3. Check each required command with `command -v`. Print an error on stderr
   when a tool is missing. Exit non-zero.
4. Change to the repository root with `git rev-parse --show-toplevel`.
5. Collect files from `git`. Include tracked and untracked files. Exclude
   ignored files.
6. Run the tool in read-only mode. Print one short result line.
7. Add the tool to [`mise.toml`](../mise.toml) when it is a development
   dependency.
8. Run `make ci`. `scripts/ci.sh` finds the new file automatically. The file
   name sets the run order.
9. Add the check to the matrix in `ci.yml` when GitHub Actions must run it.

## Rules for a check script

- Do not use the network.
- Do not write to the working tree.
- Do not fix files.
- Do not use secrets.
- Write deterministic output.
- Print a result line. Print tool output when a check fails.
- Exit non-zero when a check fails.

## Troubleshooting

### The checks print exit code 3

`SMOLVM_ENABLED=1` is set, but no server address and no local microVM are
available. Set `SMOLVM_ADDR`, or install smolvm with a working
accelerator. Otherwise unset `SMOLVM_ENABLED` for the host fallback.

### A Rust check skips a tool

Some check scripts skip when `cargo` or `cargo-deny` is absent. Install the
tools on the host, or set `SMOLVM_SERVE_IMAGE` to a server image that carries
the toolchain.

### The hooks do not run

Run `make hooks`. Then run `git config --get core.hooksPath`. The output must
be `.githook`.
