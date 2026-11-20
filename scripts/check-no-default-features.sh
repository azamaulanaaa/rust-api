#!/usr/bin/env bash
# Check the Rust code without default features.
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

cargo check --all-targets --all-features --no-default-features --locked
echo "checked Rust code without default features"
