#!/usr/bin/env bash
# Check the commit history against the Conventional Commits specification.
set -euo pipefail

if ! command -v git >/dev/null 2>&1; then
  echo "error: git is not on PATH. Install git first." >&2
  exit 1
fi

if ! command -v cog >/dev/null 2>&1; then
  echo "error: cog is not on PATH. Install cocogitto first." >&2
  exit 1
fi

# Git and libgit2 reject a repository that another user owns. Trust this checkout.
git config --global --add safe.directory "${GITHUB_WORKSPACE:-$PWD}"

cd "$(git rev-parse --show-toplevel)"

# Check from the latest tag. Check all commits when the repository has no tag.
if [[ -n "$(git tag --list)" ]]; then
  cog check --from-latest-tag
else
  cog check ..HEAD
fi
echo "checked commit history"
