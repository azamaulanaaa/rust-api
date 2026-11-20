#!/usr/bin/env bash
# Format the Dockerfile and Containerfile files with dockerfmt.
set -euo pipefail

if ! command -v git >/dev/null 2>&1; then
  echo "error: git is not on PATH. Install git first." >&2
  exit 1
fi

if ! command -v dockerfmt >/dev/null 2>&1; then
  echo "error: dockerfmt is not on PATH. Install dockerfmt first." >&2
  exit 1
fi

cd "$(git rev-parse --show-toplevel)"

mapfile -d '' -t files < <(
  git ls-files -z --cached --others --exclude-standard -- \
    ':(glob)**/Dockerfile' ':(glob)**/Dockerfile.*' ':(glob)**/Containerfile' ':(glob)**/Containerfile.*' \
    ':(glob)**/*.dockerfile' ':(glob)**/*.containerfile'
)

if ((${#files[@]} == 0)); then
  echo "no Dockerfile or Containerfile files"
  exit 0
fi

dockerfmt --write -- "${files[@]}"
echo "formatted ${#files[@]} Dockerfile or Containerfile files with dockerfmt"
