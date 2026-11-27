#!/usr/bin/env bash
# Check the WASM client build for wasm32-unknown-unknown.
# The script does not install a Rust target.
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

if ! command -v rustc >/dev/null 2>&1; then
  echo "error: rustc is not on PATH. Install the Rust toolchain first." >&2
  exit 1
fi

# Print a clear error when the target is absent. Do not install it here.
target_libdir="$(rustc --print target-libdir --target wasm32-unknown-unknown 2>/dev/null || true)"
if [[ -z "$target_libdir" || ! -d "$target_libdir" ]]; then
  cat >&2 <<'EOF'
ERROR: the wasm32-unknown-unknown target is not installed.
The WASM check did not run.
This script does not install a target.
To install the target in a disposable guest, run:
  rustup target add wasm32-unknown-unknown
Then run this script again.
EOF
  exit 1
fi

cargo check -p rust-api-client --target wasm32-unknown-unknown --locked
echo "checked the WASM client for wasm32-unknown-unknown"
