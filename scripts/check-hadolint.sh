#!/usr/bin/env bash
# Check the Dockerfile and Containerfile files with hadolint.
set -euo pipefail

if ! command -v git >/dev/null 2>&1; then
  echo "error: git is not on PATH. Install git first." >&2
  exit 1
fi

if ! command -v hadolint >/dev/null 2>&1; then
  echo "error: hadolint is not on PATH. Install hadolint first." >&2
  exit 1
fi

cd "$(git rev-parse --show-toplevel)"

mapfile -d '' -t files < <(
  git ls-files -z --cached --others --exclude-standard -- \
    ':(glob)**/Dockerfile' ':(glob)**/Dockerfile.*' \
    ':(glob)**/Containerfile' ':(glob)**/Containerfile.*' \
    ':(glob)**/*.dockerfile' ':(glob)**/*.containerfile'
)

if ((${#files[@]} == 0)); then
  echo "no Dockerfile or Containerfile files"
  exit 0
fi

hadolint --no-color -- "${files[@]}"
echo "checked ${#files[@]} Dockerfile or Containerfile files with hadolint"
