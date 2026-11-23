#!/usr/bin/env bash
# Check that the release workflow gates publishing on CI.
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
if ! command -v dist >/dev/null 2>&1; then
  echo "error: dist is not on PATH. Install cargo-dist first." >&2
  exit 1
fi

workflow=.github/workflows/release.yml
if ! grep -q 'uses: ./.github/workflows/ci.yml' "$workflow"; then
  echo "error: $workflow no longer calls ci.yml. Re-apply the checks job." >&2
  exit 1
fi
if ! grep -A4 'build-local-artifacts:' "$workflow" | grep -q '^ *- checks$'; then
  echo "error: $workflow no longer waits for checks before building." >&2
  echo "error: Re-apply checks to the needs of build-local-artifacts." >&2
  exit 1
fi
echo "release workflow is gated on CI"
dist plan --output-format=human >/dev/null
