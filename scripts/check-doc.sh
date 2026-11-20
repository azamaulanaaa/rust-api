#!/usr/bin/env bash
# Check the Rust docs with warnings denied.
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

RUSTDOCFLAGS="-D warnings" cargo doc --no-deps --all-features --locked
echo "checked Rust docs"
