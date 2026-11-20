#!/usr/bin/env bash
# Scan the repository for secrets with gitleaks.
set -euo pipefail

if ! command -v git >/dev/null 2>&1; then
  echo "error: git is not on PATH. Install git first." >&2
  exit 1
fi

if ! command -v gitleaks >/dev/null 2>&1; then
  echo "error: gitleaks is not on PATH. Install gitleaks first." >&2
  exit 1
fi

cd "$(git rev-parse --show-toplevel)"

# Copy the files into a temporary directory so the scan never writes to the
# working tree. Git selects tracked and untracked files and drops ignored ones.
scratch="$(mktemp -d)"
trap 'rm -rf "$scratch"' EXIT
scan="$scratch/scan"
report="$scratch/gitleaks-report.json"
mkdir -p "$scan"

mapfile -d '' -t listed < <(git ls-files -z --cached --others --exclude-standard)

files=()
for path in "${listed[@]}"; do
  if [[ -f "$path" ]]; then
    files+=("$path")
  fi
done

if ((${#files[@]} == 0)); then
  echo "no files to scan"
  exit 0
fi

cp --parents -t "$scan" -- "${files[@]}"

if (
  cd "$scan"
  gitleaks detect --no-git --source . --no-banner --no-color \
    --log-level error --redact --report-format json --report-path "$report"
); then
  echo "no secrets found"
else
  status=$?
  if [[ -f "$report" ]]; then
    cat "$report"
  fi
  exit "$status"
fi
