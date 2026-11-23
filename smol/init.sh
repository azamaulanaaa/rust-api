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

# The server writes the cache disk into the kernel command line.
# A remote machine with a cache disk carries
# SMOLVM_CACHE_DISK=<device>:<mount>. A local pack build has no entry.
cache_spec=""
cache_device=""
cache_mount=""
if [[ -r /proc/cmdline ]]; then
  read -r -a cmdline_words </proc/cmdline || true
  # The kernel quotes each word. Strip one pair of double quotes.
  for word in "${cmdline_words[@]}"; do
    word="${word#\"}"
    word="${word%\"}"
    case "$word" in
    SMOLVM_CACHE_DISK=*) cache_spec="${word#SMOLVM_CACHE_DISK=}" ;;
    esac
  done
fi

# Print the size of one block device in bytes.
# Print nothing when the device has no size entry.
cache_disk_size() {
  local device="$1"
  local name="${device##*/}"
  local sectors=""
  if [[ -r "/sys/class/block/${name}/size" ]]; then
    read -r sectors <"/sys/class/block/${name}/size" || true
  fi
  if [[ -z "$sectors" ]]; then
    sectors="$(blockdev --getsz "$device" 2>/dev/null || true)"
  fi
  if [[ "$sectors" =~ ^[0-9]+$ ]]; then
    printf '%s' "$((sectors * 512))"
  fi
}

# A cache disk with no size cannot hold /cache. The server attaches a
# seed base with no size when the seed file is empty. Stop before the
# provisioning steps so the error is clear.
if [[ -n "$cache_spec" ]]; then
  cache_device="${cache_spec%%:*}"
  cache_mount="${cache_spec#*:}"
  if [[ -z "$cache_device" || "$cache_mount" == "$cache_spec" ]]; then
    echo "error: SMOLVM_CACHE_DISK is not valid: ${cache_spec}" >&2
    echo "error: Use <device>:<mount>. See docs/smolvm.md." >&2
    exit 1
  fi
  if [[ ! -b "$cache_device" ]]; then
    echo "error: The cache disk ${cache_device} is missing." >&2
    echo "error: The kernel command line set SMOLVM_CACHE_DISK=${cache_spec}." >&2
    echo "error: Recreate the seed base with a non-zero size. See docs/smolvm.md." >&2
    echo "error: Set SMOLVM_SERVE_CACHE=0 to run without the cache disk." >&2
    exit 1
  fi
  cache_size="$(cache_disk_size "$cache_device")"
  if [[ -z "$cache_size" || "$cache_size" == "0" ]]; then
    echo "error: The cache disk ${cache_device} has zero size." >&2
    echo "error: The server attached a seed base with no size." >&2
    echo "error: Recreate the seed base with a non-zero size. See docs/smolvm.md." >&2
    echo "error: Set SMOLVM_SERVE_CACHE=0 to run without the cache disk." >&2
    exit 1
  fi
fi

# The cache disk is present only on a remote machine that asked for one.
cache_dir=""
if [[ -n "$cache_mount" && -d "$cache_mount" ]]; then
  cache_dir="$cache_mount"
elif [[ -d /cache ]]; then
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
# Export the data directory with the shim PATH. A shim resolves against the
# active data directory, so a check shell must use the one this machine
# provisioned when a cache disk is mounted.
# shellcheck disable=SC2016
run_step "mise PATH setup" \
  'mise_home="${MISE_DATA_DIR:-$HOME/.local/share/mise}"; mkdir -p /etc/profile.d; printf "export MISE_DATA_DIR=\"%s\"\nexport PATH=\"%s/shims:\$PATH\"\n" "$mise_home" "$mise_home" > /etc/profile.d/mise.sh'
# shellcheck disable=SC2016
run_step "mise shim links" \
  'shim_dir="${MISE_DATA_DIR:-$HOME/.local/share/mise}/shims"; for shim in "$shim_dir"/*; do [ -e "$shim" ] || continue; ln -sf "$shim" "/usr/local/bin/$(basename "$shim")"; done'

# The client stops the machine and publishes the cache disk after init.
# Flush the disk writes now so the published base holds them.
if [[ -n "$cache_dir" ]] && grep -qF " ${cache_dir} " /proc/mounts; then
  sync
fi

echo "init complete"
echo "smolvm-init-mode=${init_mode}"
