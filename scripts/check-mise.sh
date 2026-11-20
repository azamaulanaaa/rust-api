#!/usr/bin/env bash
# Check the mise config file when mise is available.
set -euo pipefail

if ! command -v git >/dev/null 2>&1; then
  echo "error: git is not on PATH. Install git first." >&2
  exit 1
fi

if ! command -v mise >/dev/null 2>&1; then
  echo "skip: mise is not on PATH. The mise config check did not run." >&2
  exit 0
fi

cd "$(git rev-parse --show-toplevel)"
mise fmt --check
echo "checked mise.toml"
