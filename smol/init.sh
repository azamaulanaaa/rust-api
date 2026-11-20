#!/usr/bin/env bash
# Provision the check tools inside a smolvm guest.
# Run this script from /workspace, the repository root in the guest.
# The local pack build and the remote run both use this script.
# A remote run with a cache disk mounts /cache. The downloads, the mise
# data, and the mise binary then land on /cache. A machine from a
# published base reuses them. The wiring under /etc and /usr/local/bin
# lives on the overlay and is written again on every run.
set -euo pipefail

if [[ ! -d /workspace ]]; then
  echo "error: /workspace is missing." >&2
  exit 1
fi
cd /workspace

# The cache disk is present only on a remote machine that asked for one.
cache_dir=""
if [[ -d /cache ]]; then
  cache_dir=/cache
fi

# The mode marker names what this machine brought along. A warm machine
# found the cached mise binary. A cold machine must download everything.
init_mode="cold"
if [[ -n "$cache_dir" && -x "${cache_dir}/bin/mise" ]]; then
  init_mode="warm"
fi

# Point the mise download cache and the mise data at the cache disk. The
# data directory also holds the shims.
mise_data="${HOME}/.local/share/mise"
if [[ -n "$cache_dir" ]]; then
  mise_data="${cache_dir}/mise-data"
  export MISE_DATA_DIR="$mise_data"
  export MISE_CACHE_DIR="${cache_dir}/mise-cache"
  mkdir -p "$MISE_DATA_DIR" "$MISE_CACHE_DIR"
  # The apt archive cache holds the downloaded packages.
  mkdir -p "${cache_dir}/apt-archives"
  rm -rf /var/cache/apt/archives
  ln -sfn "${cache_dir}/apt-archives" /var/cache/apt/archives
fi

# Run one provisioning step in a guest login shell.
# Print the step label and keep the exit code when the step fails.
run_step() {
  local label="$1"
  local command="$2"
  local rc
  bash -lc "set -euo pipefail; $command" || {
    rc=$?
    echo "error: $label failed." >&2
    exit "$rc"
  }
}

run_step "package install" \
  'export DEBIAN_FRONTEND=noninteractive && apt-get update && apt-get install -y --no-install-recommends bash build-essential ca-certificates curl git && rm -rf /var/lib/apt/lists/*'

# The mise binary lives on the cache disk when one is present. A machine
# from a published base finds it there and skips the download.
if [[ "$init_mode" == "warm" ]]; then
  ln -sf "${cache_dir}/bin/mise" /usr/local/bin/mise
else
  mise_path=/usr/local/bin/mise
  if [[ -n "$cache_dir" ]]; then
    mise_path="${cache_dir}/bin/mise"
    mkdir -p "${cache_dir}/bin"
  fi
  # shellcheck disable=SC2016
  run_step "mise install script" \
    "curl --fail --location --silent --show-error https://mise.run | MISE_INSTALL_PATH=${mise_path} sh"
  if [[ -n "$cache_dir" ]]; then
    ln -sf "${cache_dir}/bin/mise" /usr/local/bin/mise
  fi
fi
run_step "mise tools install" 'cd /workspace && mise install'

# The local pack build keeps its image small. The remote cache path
# keeps the cache for the next machine.
if [[ -z "$cache_dir" ]]; then
  run_step "mise cache clear" 'mise cache clear'
fi

run_step "git safe directory" 'git config --global --add safe.directory /workspace'

# The profile file covers login shells. The links cover other shell shapes.
# shellcheck disable=SC2016
run_step "mise PATH setup" \
  'shim_dir="${MISE_DATA_DIR:-$HOME/.local/share/mise}/shims"; mkdir -p /etc/profile.d; printf "export PATH=\"%s:\$PATH\"\n" "$shim_dir" > /etc/profile.d/mise.sh'
# shellcheck disable=SC2016
run_step "mise shim links" \
  'shim_dir="${MISE_DATA_DIR:-$HOME/.local/share/mise}/shims"; for shim in "$shim_dir"/*; do [ -e "$shim" ] || continue; ln -sf "$shim" "/usr/local/bin/$(basename "$shim")"; done'

echo "init complete"
echo "smolvm-init-mode=${init_mode}"
