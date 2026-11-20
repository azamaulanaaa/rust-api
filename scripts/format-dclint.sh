#!/usr/bin/env bash
# Fix the Docker Compose files with dclint.
set -euo pipefail

if ! command -v git >/dev/null 2>&1; then
  echo "error: git is not on PATH. Install git first." >&2
  exit 1
fi

if ! command -v dclint >/dev/null 2>&1; then
  echo "error: dclint is not on PATH. Install dclint first." >&2
  exit 1
fi

cd "$(git rev-parse --show-toplevel)"

mapfile -d '' -t files < <(
  git ls-files -z --cached --others --exclude-standard -- \
    ':(glob)**/compose.yml' ':(glob)**/compose.yaml' \
    ':(glob)**/compose.*.yml' ':(glob)**/compose.*.yaml' \
    ':(glob)**/docker-compose.yml' ':(glob)**/docker-compose.yaml' \
    ':(glob)**/docker-compose.*.yml' ':(glob)**/docker-compose.*.yaml'
)

if ((${#files[@]} == 0)); then
  echo "no compose files"
  exit 0
fi

dclint --fix "${files[@]}"
echo "formatted ${#files[@]} Docker Compose files with dclint"
