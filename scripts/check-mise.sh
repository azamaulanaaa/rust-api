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

# The workflow installs tools from the matrix. Every name there must be a
# key in the `[tools]` table of mise.toml. A missing backend prefix, such as
# `cargo-llvm-cov` for `cargo:cargo-llvm-cov`, makes the install step fail.
mapfile -t declared < <(
  awk '
    /^\[tools\]/ { in_tools = 1; next }
    /^\[/ { in_tools = 0 }
    in_tools && /=/ {
      key = $0
      sub(/=.*/, "", key)
      gsub(/^[ \t]+|[ \t]+$/, "", key)
      gsub(/"/, "", key)
      print key
    }
  ' mise.toml | sort -u
)

mapfile -t used < <(
  awk '
    /^[ \t]*#/ { next }
    /install_args:/ && $0 !~ /matrix\.install_args/ {
      value = $0
      sub(/.*install_args:[ \t]*/, "", value)
      gsub(/["\047]/, "", value)
      count = split(value, parts, /[ \t]+/)
      for (i = 1; i <= count; i++) {
        if (parts[i] != "") {
          print parts[i]
        }
      }
    }
  ' .github/workflows/ci.yml | sed 's/@.*//' | sort -u
)

status=0
for tool in "${used[@]}"; do
  found=0
  for key in "${declared[@]}"; do
    if [[ "$tool" == "$key" ]]; then
      found=1
      break
    fi
  done
  if ((found == 0)); then
    echo "error: the workflow installs '$tool', but mise.toml does not declare it." >&2
    status=1
  fi
done

if ((status != 0)); then
  exit 1
fi
echo "checked the workflow tool names against mise.toml"
