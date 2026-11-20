#!/usr/bin/env bash
# Check every tracked and untracked Markdown file with markdownlint-cli2.
set -euo pipefail

if ! command -v git >/dev/null 2>&1; then
  echo "error: git is not on PATH. Install git first." >&2
  exit 1
fi

cd "$(git rev-parse --show-toplevel)"

if ! command -v markdownlint-cli2 >/dev/null 2>&1; then
  echo "error: markdownlint-cli2 is not on PATH. Install markdownlint-cli2 first." >&2
  exit 1
fi

# The changelog is generated, so the check skips it.
mapfile -d '' -t files < <(
  git ls-files -z --cached --others --exclude-standard -- \
    '*.md' ':(exclude)CHANGELOG.md'
)

if ((${#files[@]} == 0)); then
  echo "no Markdown files"
  exit 0
fi

markdownlint-cli2 "${files[@]}"
echo "checked ${#files[@]} Markdown files"
