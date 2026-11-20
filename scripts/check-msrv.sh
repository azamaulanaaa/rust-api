#!/usr/bin/env bash
# Check the Rust code against the declared MSRV.
set -euo pipefail

if ! command -v git >/dev/null 2>&1; then
  echo "error: git is not on PATH. Install git first." >&2
  exit 1
fi
cd "$(git rev-parse --show-toplevel)"

if ! command -v cargo >/dev/null 2>&1; then
  echo "error: cargo is not on PATH. Install cargo first." >&2
  exit 1
fi

floor="$(sed -n 's/^rust-version = "\(.*\)"/\1/p' Cargo.toml | head -1)"
pattern="rustc ${floor}."
if [[ "$(rustc --version)" != "$pattern"* ]]; then
  echo "error: the rustc version does not match rust-version in Cargo.toml." >&2
  echo "error: Update the msrv matrix entry in .github/workflows/ci.yml." >&2
  exit 1
fi

cargo check --all-targets --all-features --locked
echo "checked Rust code against the declared MSRV"
