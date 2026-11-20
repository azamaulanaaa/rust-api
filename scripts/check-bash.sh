#!/usr/bin/env bash
# Check every tracked and untracked bash file with shellcheck.
set -euo pipefail

if ! command -v git >/dev/null 2>&1; then
  echo "error: git is not on PATH. Install git first." >&2
  exit 1
fi

if ! command -v shellcheck >/dev/null 2>&1; then
  echo "error: shellcheck is not on PATH. Install shellcheck first." >&2
  exit 1
fi

cd "$(git rev-parse --show-toplevel)"

mapfile -d '' -t listed < <(git ls-files -z --cached --others --exclude-standard)

files=()
for path in "${listed[@]}"; do
  if [[ ! -f "$path" ]]; then
    continue
  fi
  case "$path" in
  *.sh | *.bash | *.bats)
    files+=("$path")
    continue
    ;;
  esac
  first_line=
  IFS= read -r first_line <"$path" || true
  if [[ "$first_line" != '#!'* ]]; then
    continue
  fi
  read -r -a tokens <<<"$first_line"
  for token in "${tokens[@]}"; do
    if [[ "${token##*/}" == "bash" || "${token##*/}" == "sh" ]]; then
      files+=("$path")
      break
    fi
  done
done

if ((${#files[@]} == 0)); then
  echo "no bash files"
  exit 0
fi

shellcheck -f gcc -x -- "${files[@]}"
echo "checked ${#files[@]} bash files"
