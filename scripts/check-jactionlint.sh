#!/usr/bin/env bash
# Check every GitHub Actions workflow file with jactionlint.
set -euo pipefail

if ! command -v git >/dev/null 2>&1; then
  echo "error: git is not on PATH. Install git first." >&2
  exit 1
fi

if ! command -v jactionlint >/dev/null 2>&1; then
  echo "error: jactionlint is not on PATH. Install jactionlint first." >&2
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

jactionlint --no-color -- "${files[@]}"
echo "checked ${#files[@]} GitHub Actions workflow files with jactionlint"
