#!/usr/bin/env bash
# Run clippy on the Rust code when cargo is available.
set -euo pipefail

if ! command -v git >/dev/null 2>&1; then
  echo "error: git is not on PATH. Install git first." >&2
  exit 1
fi

cd "$(git rev-parse --show-toplevel)"

if ! command -v cargo >/dev/null 2>&1; then
  echo "skip: cargo is not on PATH. The clippy check did not run." >&2
  exit 0
fi

if [[ ! -f Cargo.toml ]]; then
  echo "skip: Cargo.toml is not at the repository root. The clippy check did not run." >&2
  exit 0
fi

cargo clippy --all-targets -- -D warnings
echo "checked Rust code with clippy"
