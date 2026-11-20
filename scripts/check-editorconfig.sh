#!/usr/bin/env bash
# Check every tracked and untracked file with editorconfig-checker.
set -euo pipefail

if ! command -v git >/dev/null 2>&1; then
  echo "error: git is not on PATH. Install git first." >&2
  exit 1
fi

if ! command -v editorconfig-checker >/dev/null 2>&1; then
  echo "error: editorconfig-checker is not on PATH. Install editorconfig-checker first." >&2
  exit 1
fi

cd "$(git rev-parse --show-toplevel)"

mapfile -d '' -t files < <(git ls-files -z --cached --others --exclude-standard)

if ((${#files[@]} == 0)); then
  echo "no files to check"
  exit 0
fi

editorconfig-checker --no-color -- "${files[@]}"
echo "checked ${#files[@]} files with editorconfig-checker"
