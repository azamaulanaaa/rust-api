#!/usr/bin/env bash
# Check the Rust code against the declared MSRV.
set -euo pipefail

if ! command -v git >/dev/null 2>&1; then
  echo "error: git is not on PATH. Install git first." >&2
  exit 1
fi
cd "$(git rev-parse --show-toplevel)"

floor="$(sed -n 's/^rust-version = "\(.*\)"/\1/p' Cargo.toml | head -1)"

# Pin the MSRV toolchain with mise when mise is on PATH.
# mise installs the pinned tool when it is missing.
# The smolvm CI run installs the stable toolchain by default.
# The pinned tool makes this check pass in that run.
if command -v mise >/dev/null 2>&1; then
  run_msrv() { mise exec "rust@${floor}" -- "$@"; }
else
  # Without mise, use the cargo and rustc already on PATH.
  if ! command -v cargo >/dev/null 2>&1; then
    echo "error: cargo is not on PATH. Install cargo first." >&2
    exit 1
  fi
  run_msrv() { "$@"; }
fi

pattern="rustc ${floor}."
if [[ "$(run_msrv rustc --version)" != "$pattern"* ]]; then
  echo "error: the rustc version does not match rust-version in Cargo.toml." >&2
  echo "error: Update the msrv matrix entry in .github/workflows/ci.yml." >&2
  exit 1
fi

run_msrv cargo check --all-targets --all-features --locked
echo "checked Rust code against the declared MSRV"
