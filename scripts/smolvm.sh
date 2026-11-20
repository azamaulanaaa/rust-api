#!/usr/bin/env bash
# Run the checks inside a smolvm microVM against the live working tree.
# SMOLVM_ENABLED=1 stops the run when smolvm is unavailable.
set -euo pipefail

# Exit code 3 means the run cannot use smolvm in enforced mode.
readonly SMOLVM_ENFORCED_RC=3

if ! command -v git >/dev/null 2>&1; then
  echo "error: git is not on PATH. Install git first." >&2
  exit 1
fi

script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

cd "$(git rev-parse --show-toplevel)"

# shellcheck source=scripts/smolvm-resources.sh
source "$script_dir/smolvm-resources.sh"
if ! smolvm_resources_resolve; then
  exit 1
fi

print_warning() {
  cat >&2 <<'EOF'
!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!
!! WARNING: smolvm or the host accelerator is not available.
!! The checks did NOT run in a microVM.
!! The checks run on the HOST instead.
!! Install smolvm and give the host a working accelerator.
!! See docs/smolvm.md for the requirements.
!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!
EOF
}

print_enforced_error() {
  cat >&2 <<'EOF'
ERROR: SMOLVM_ENABLED=1 requires smolvm.
smolvm is not on PATH, or the host accelerator is unavailable.
The checks did not run.
Install smolvm on the host.
Give the host a working accelerator.
Alternatively, set SMOLVM_SERVE_ADDR to use a remote smolvm server.
See docs/smolvm.md for the requirements.
EOF
}

# Detect whether this host can run a smolvm machine.
# Linux needs a readable /dev/kvm.
# macOS on Apple Silicon needs kern.hv_support=1.
host_accel_ok() {
  command -v smolvm >/dev/null 2>&1 || return 1
  case "$(uname -s)" in
  Linux)
    [[ -e /dev/kvm && -r /dev/kvm ]]
    ;;
  Darwin)
    case "$(uname -m)" in
    arm64 | aarch64) [[ "$(sysctl -n kern.hv_support 2>/dev/null)" == "1" ]] ;;
    *) return 1 ;;
    esac
    ;;
  *) return 1 ;;
  esac
}

if [[ "${SMOLVM_ENABLED:-}" == "0" ]]; then
  # The caller is already inside the microVM. Run the checks here.
  exec scripts/ci.sh
fi

if [[ -n "${SMOLVM_SERVE_ADDR:-}" ]]; then
  # Run the checks in a machine on the remote server. Never use the host.
  # The checks path never sends the local stdin.
  # shellcheck source=scripts/smolvm-serve.sh
  source "$script_dir/smolvm-serve.sh"
  serve_run_remote 'cd /workspace && SMOLVM_ENABLED=0 SMOLVM_GUEST=1 bash scripts/ci.sh' none || exit $?
  exit "$SERVE_GUEST_RC"
fi

if ! host_accel_ok; then
  if [[ "${SMOLVM_ENABLED:-}" == "1" ]]; then
    print_enforced_error
    exit "$SMOLVM_ENFORCED_RC"
  fi
  print_warning
  export SMOLVM_ENABLED=0
  exec scripts/ci.sh
fi

if ! command -v sha256sum >/dev/null 2>&1; then
  echo "error: sha256sum is not on PATH." >&2
  exit 1
fi

hash="$(smolvm_resources_hash_lines | sha256sum | cut -d' ' -f1)"
pack=".cache/smolvm/ci-${hash}.smolmachine"

if [[ ! -f "$pack" ]]; then
  smol/pack-build.sh "$hash"
fi

if [[ ! -f "$pack" ]]; then
  echo "error: pack was not built: $pack" >&2
  exit 1
fi

# Run the pack ephemerally. The VM is discarded on exit. Mount the
# live working tree read-only. The guest kernel enforces the mount.
# --timeout is a backstop for a hung run; Ctrl-C ends the VM on
# smolvm v1.20.2 and later. The exit code of the checks propagates.
rc=0
smolvm machine run --from "$pack" --timeout "${SMOLVM_TIMEOUT:-10m}" \
  -v "$PWD":/workspace:ro -- bash -lc \
  'cd /workspace && SMOLVM_ENABLED=0 SMOLVM_GUEST=1 bash scripts/ci.sh' || rc=$?

exit "$rc"
