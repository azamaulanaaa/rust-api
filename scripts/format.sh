#!/usr/bin/env bash
# Run every format script in name order.
set -euo pipefail

if ! command -v git >/dev/null 2>&1; then
  echo "error: git is not on PATH. Install git first." >&2
  exit 1
fi

cd "$(git rev-parse --show-toplevel)"

shopt -s nullglob
formatters=(scripts/format-*.sh)
shopt -u nullglob

if ((${#formatters[@]} == 0)); then
  echo "no format scripts"
  exit 0
fi

for formatter in "${formatters[@]}"; do
  echo "run: $formatter"
  "$formatter"
done

echo "all formatting applied (${#formatters[@]} scripts)"
