#!/usr/bin/env bash
# Measure Rust test coverage with a line floor.
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

cargo llvm-cov --workspace --all-features --locked --html --output-dir target/llvm-cov --fail-under-lines 90
echo "checked Rust coverage"
