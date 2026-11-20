#!/usr/bin/env bash
# Remove the smolvm cache and dangling smolvm machines.
# Delete only machines made by this repository's tooling: the
# smolvm-build-* names from failed pack builds and the smolvm-run-*
# names from the older run path. Every other machine stays untouched.
# The cleanup is idempotent. Run it as often as you want.
set -euo pipefail

if command -v git >/dev/null 2>&1; then
  root="$(git rev-parse --show-toplevel 2>/dev/null || true)"
  if [[ -n "$root" ]]; then
    cd "$root"
  fi
fi

script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# Print the names of the remote machines made by this tool.
# Parse the JSON list with grep and sed. No jq is needed.
remote_names() {
  local body="$1"
  printf '%s' "$body" |
    grep -o '"name"[[:space:]]*:[[:space:]]*"smolvm-remote-[^"]*"' |
    sed -n 's/.*:[[:space:]]*"\(smolvm-remote-[^"]*\)".*/\1/p' |
    sort -u
}

# Print one machine name per line.
# Try the JSON list with python3 first.
# Fall back to the quiet text list when python3 is absent or the
# JSON parse fails.
list_names() {
  if command -v python3 >/dev/null 2>&1; then
    if smolvm machine list --json 2>/dev/null | python3 -c '
import json
import sys

try:
    data = json.load(sys.stdin)
except ValueError:
    sys.exit(3)

if isinstance(data, dict):
    inner = None
    for key in ("machines", "items", "data"):
        if isinstance(data.get(key), list):
            inner = data[key]
            break
    if inner is None:
        sys.exit(3)
    data = inner

if not isinstance(data, list):
    sys.exit(3)

for item in data:
    if isinstance(item, str):
        print(item)
    elif isinstance(item, dict):
        name = item.get("name") or item.get("Name") or item.get("machine")
        if name:
            print(name)
'; then
      return 0
    fi
    echo "note: the JSON machine list failed. Use the text list." >&2
  fi
  smolvm machine ls -q 2>/dev/null
}

if ! command -v smolvm >/dev/null 2>&1; then
  echo "smolvm=not_found"
  echo "note: machine cleanup was skipped. smolvm is not on PATH."
else
  if names="$(list_names)"; then
    kept=0
    while IFS= read -r name; do
      case "$name" in
      smolvm-build-* | smolvm-run-*)
        if smolvm machine delete --name "$name" --force --cascade; then
          echo "deleted=$name"
        else
          echo "delete_failed=$name" >&2
        fi
        ;;
      "")
        ;;
      *)
        kept=$((kept + 1))
        ;;
      esac
    done <<<"$names"
    echo "kept=$kept"
  else
    echo "note: machine cleanup was skipped. The machine list failed." >&2
  fi
fi

if [[ -n "${SMOLVM_SERVE_ADDR:-}" ]]; then
  # shellcheck source=scripts/smolvm-serve.sh
  source "$script_dir/smolvm-serve.sh"
  if serve_init; then
    if machine_list="$(serve_request GET /api/v1/machines 2>&1)"; then
      while IFS= read -r name; do
        [[ -n "$name" ]] || continue
        if serve_request DELETE "/api/v1/machines/${name}" >/dev/null 2>&1; then
          echo "deleted=$name"
        else
          echo "delete_failed=$name" >&2
        fi
      done < <(remote_names "$machine_list")
    else
      echo "note: the remote machine list failed." >&2
    fi

    # Delete the remote cache bases this repository can name. The serve
    # API has no list route for cache bases, so only the names derived
    # from the current repository state are known. Bases of older states
    # keep their names. Remove those by hand on the server.
    # The seed base always stays. It is never a derivable name, but the
    # variable may name one, so the loop excludes it.
    if smolvm_resources_resolve; then
      cache_bases=()
      cache_bases+=("$(serve_cache_base_name "$PWD")")
      if [[ "$SMOLVM_CPUS_VALUE" != "1" || "$SMOLVM_MEMORY_MB_VALUE" != "512" ]]; then
        cache_bases+=("$(SMOLVM_CPUS_VALUE=1 SMOLVM_MEMORY_MB_VALUE=512 serve_cache_base_name "$PWD")")
      fi
      seed_name="${SMOLVM_SERVE_CACHE_SEED-smolvm-seed.qcow2}"
      kept_bases=()
      for cache_base in "${cache_bases[@]}"; do
        if [[ -n "$seed_name" && "$cache_base" == "$seed_name" ]]; then
          echo "note: the seed base ${seed_name} stays on the server." >&2
          continue
        fi
        kept_bases+=("$cache_base")
      done
      for cache_base in "${kept_bases[@]}"; do
        if serve_request DELETE "/api/v1/cache-bases/${cache_base}" >/dev/null 2>&1; then
          echo "cache_base_removed=${cache_base}"
        else
          echo "cache_base_delete_failed=${cache_base}" >&2
        fi
      done
    fi
  fi
fi

cache=.cache/smolvm
if [[ -e "$cache" ]]; then
  rm -rf -- "$cache"
  echo "cache_removed=$cache"
else
  echo "cache_absent=$cache"
fi

exit 0
