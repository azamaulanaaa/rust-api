#!/usr/bin/env bash
# Check every GitHub Actions workflow file with zizmor.
set -euo pipefail

if ! command -v git >/dev/null 2>&1; then
  echo "error: git is not on PATH. Install git first." >&2
  exit 1
fi

if ! command -v zizmor >/dev/null 2>&1; then
  echo "error: zizmor is not on PATH. Install zizmor first." >&2
  exit 1
fi

cd "$(git rev-parse --show-toplevel)"

mapfile -d '' -t files < <(
  git ls-files -z --cached --others --exclude-standard -- \
    '.github/workflows/*.yml' '.github/workflows/*.yaml'
)

if ((${#files[@]} == 0)); then
  echo "no GitHub Actions workflow files"
  exit 0
fi

zizmor --offline --no-progress --format=plain -- "${files[@]}"
echo "checked ${#files[@]} GitHub Actions workflow files with zizmor"
