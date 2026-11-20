#!/usr/bin/env bash
# Check Rust dependency licenses against the allow list.
set -euo pipefail

if ! command -v git >/dev/null 2>&1; then
  echo "error: git is not on PATH. Install git first." >&2
  exit 1
fi

cd "$(git rev-parse --show-toplevel)"

if ! command -v cargo >/dev/null 2>&1; then
  echo "skip: cargo is not on PATH. The licenses check did not run." >&2
  exit 0
fi

if [[ ! -f Cargo.toml ]]; then
  echo "skip: Cargo.toml is not at the repository root. The licenses check did not run." >&2
  exit 0
fi

cargo deny --all-features check licenses
echo "checked Rust licenses"
