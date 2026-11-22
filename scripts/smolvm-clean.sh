#!/usr/bin/env bash
# Remove this checkout's smolvm cache and dangling machines.
# A resource belongs to this checkout when its name carries the owner.
# Local mode uses the path token when SMOLVM_OWNER is empty. Remote mode
# requires SMOLVM_OWNER and stops before any call when it is empty.
# Machines and cache bases of another owner stay. The cleanup is
# idempotent. The script builds the full plan before it asks for
# confirmation.
set -euo pipefail

script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd -P)"

# shellcheck source=scripts/smolvm-resources.sh
source "$script_dir/smolvm-resources.sh"

assume_yes=0
dry_run=0

for arg in "$@"; do
  case "$arg" in
  --dry-run) dry_run=1 ;;
  --yes | -y) assume_yes=1 ;;
  *)
    echo "error: unknown argument: ${arg}" >&2
    echo "error: Use --dry-run, --yes, or -y." >&2
    exit 2
    ;;
  esac
done

# Resolve the repository root. The owner token must use the same path on
# every run. Fall back to the parent of this script when git is absent.
root=""
if command -v git >/dev/null 2>&1; then
  root="$(git rev-parse --show-toplevel 2>/dev/null || true)"
fi
if [[ -z "$root" ]]; then
  root="$(cd "$script_dir/.." && pwd -P)"
fi
cd "$root"

remote=0
if [[ -n "${SMOLVM_ADDR:-}" ]]; then
  remote=1
fi

# Resolve the owner before any planning. A remote command stops here
# when SMOLVM_OWNER is empty. No local cache removal happens after a
# failure.
owner="$(smolvm_resources_owner_resolve "$PWD" "$remote")" || exit 1

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

# Report whether a name looks like an older name with no owner token.
# A 12-hex token after the family prefix is one owner form. A custom
# SMOLVM_OWNER value is another form.
# The result only selects an informational note. It never selects a
# deletion.
legacy_name() {
  local name="$1"
  local family=""
  case "$name" in
  smolvm-build-*) family="smolvm-build-" ;;
  smolvm-run-*) family="smolvm-run-" ;;
  smolvm-remote-*) family="smolvm-remote-" ;;
  *) return 1 ;;
  esac
  local rest="${name#"$family"}"
  [[ ! "$rest" =~ ^[0-9a-f]{12}- ]]
}

plan_local=()
plan_remote=()
plan_bases=()
plan_cache=0
kept=0

if ! command -v smolvm >/dev/null 2>&1; then
  echo "smolvm=not_found"
  echo "note: machine cleanup was skipped. smolvm is not on PATH." >&2
else
  if names="$(list_names)"; then
    while IFS= read -r name; do
      [[ -n "$name" ]] || continue
      case "$name" in
      "smolvm-build-${owner}-"* | "smolvm-run-${owner}-"*)
        plan_local+=("$name")
        ;;
      smolvm-build-* | smolvm-run-*)
        kept=$((kept + 1))
        if legacy_name "$name"; then
          echo "note: machine ${name} does not match owner=${owner}. It stays." >&2
        fi
        ;;
      *)
        kept=$((kept + 1))
        ;;
      esac
    done <<<"$names"
  else
    echo "note: machine cleanup was skipped. The machine list failed." >&2
  fi
fi

if ((remote == 1)); then
  # shellcheck source=scripts/smolvm-serve.sh
  source "$script_dir/smolvm-serve.sh"
  if serve_init; then
    if machine_list="$(serve_request GET /api/v1/machines 2>&1)"; then
      while IFS= read -r name; do
        [[ -n "$name" ]] || continue
        case "$name" in
        "smolvm-remote-${owner}-"*)
          plan_remote+=("$name")
          ;;
        *)
          kept=$((kept + 1))
          if legacy_name "$name"; then
            echo "note: machine ${name} does not match owner=${owner}. It stays." >&2
          fi
          ;;
        esac
      done < <(remote_names "$machine_list")
    else
      echo "note: the remote machine list failed." >&2
    fi

    # Plan the remote cache bases this checkout can name. The serve
    # API has no list route for cache bases, so only the names derived
    # from the current repository state are known. Bases of older states
    # keep their names. Remove those by hand on the server.
    # The seed base always stays. It is never a derivable name, but the
    # variable may name one, so the loop excludes it.
    if smolvm_resources_resolve; then
      if cache_base="$(serve_cache_base_name "$PWD")"; then
        plan_bases+=("$cache_base")
      else
        echo "note: the cache base name was not derived." >&2
      fi
      if [[ "$SMOLVM_CPUS_VALUE" != "1" || "$SMOLVM_MEMORY_MB_VALUE" != "512" ]]; then
        if cache_base="$(SMOLVM_CPUS_VALUE=1 SMOLVM_MEMORY_MB_VALUE=512 serve_cache_base_name "$PWD")"; then
          plan_bases+=("$cache_base")
        fi
      fi
      seed_name="${SMOLVM_SERVE_CACHE_SEED-smolvm-seed.qcow2}"
      if ((${#plan_bases[@]} > 0)); then
        kept_bases=()
        for cache_base in "${plan_bases[@]}"; do
          if [[ -n "$seed_name" && "$cache_base" == "$seed_name" ]]; then
            echo "note: the seed base ${seed_name} stays on the server." >&2
            continue
          fi
          kept_bases+=("$cache_base")
        done
        plan_bases=()
        if ((${#kept_bases[@]} > 0)); then
          plan_bases=("${kept_bases[@]}")
        fi
      fi
    fi
  fi
fi

cache=.cache/smolvm
if [[ -e "$cache" ]]; then
  plan_cache=1
fi

echo "owner=${owner}"
echo "kept=${kept}"

print_plan() {
  local name
  if ((${#plan_local[@]} > 0)); then
    for name in "${plan_local[@]}"; do
      echo "plan_machine=${name}"
    done
  fi
  if ((${#plan_remote[@]} > 0)); then
    for name in "${plan_remote[@]}"; do
      echo "plan_remote_machine=${name}"
    done
  fi
  if ((${#plan_bases[@]} > 0)); then
    for name in "${plan_bases[@]}"; do
      echo "plan_cache_base=${name}"
    done
  fi
  if ((plan_cache == 1)); then
    echo "plan_cache=${cache}"
  fi
}

plan_count=$((${#plan_local[@]} + ${#plan_remote[@]} + ${#plan_bases[@]} + plan_cache))
if ((plan_count > 0)); then
  print_plan
fi

if ((dry_run == 1)); then
  echo "dry_run=1"
  exit 0
fi

# Ask one time for the whole plan. Silence never means consent.
confirm_plan() {
  if ((assume_yes == 1)); then
    return 0
  fi
  if [[ "${SMOLVM_CLEAN_ASSUME_YES:-}" == "1" ]]; then
    return 0
  fi
  if [[ ! -t 0 ]]; then
    echo "error: the cleanup needs confirmation, but stdin is not a terminal." >&2
    echo "error: Run the command with --yes to delete without a prompt." >&2
    return 2
  fi
  local answer=""
  printf 'Delete the planned resources? [y/N] ' >&2
  if ! IFS= read -r answer; then
    answer=""
  fi
  answer="$(printf '%s' "$answer" | tr '[:upper:]' '[:lower:]')"
  case "$answer" in
  y | yes) return 0 ;;
  *) return 1 ;;
  esac
}

if ((plan_count > 0)); then
  confirmation=0
  confirm_plan || confirmation=$?
  if ((confirmation == 2)); then
    exit 1
  fi
  if ((confirmation != 0)); then
    echo "clean_cancelled=1"
    exit 0
  fi
fi

if ((${#plan_local[@]} > 0)); then
  for name in "${plan_local[@]}"; do
    if smolvm machine delete --name "$name" --force --cascade; then
      echo "deleted=${name}"
    else
      echo "delete_failed=${name}" >&2
    fi
  done
fi

if ((${#plan_remote[@]} > 0)); then
  for name in "${plan_remote[@]}"; do
    if serve_request DELETE "/api/v1/machines/${name}" >/dev/null 2>&1; then
      echo "deleted=${name}"
    else
      echo "delete_failed=${name}" >&2
    fi
  done
fi

if ((${#plan_bases[@]} > 0)); then
  for cache_base in "${plan_bases[@]}"; do
    if serve_request DELETE "/api/v1/cache-bases/${cache_base}" >/dev/null 2>&1; then
      echo "cache_base_removed=${cache_base}"
    else
      echo "cache_base_delete_failed=${cache_base}" >&2
    fi
  done
fi

if ((plan_cache == 1)); then
  rm -rf -- "$cache"
  echo "cache_removed=${cache}"
else
  echo "cache_absent=${cache}"
fi

exit 0
