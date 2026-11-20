#!/usr/bin/env bash
# Run every check script in name order.
set -euo pipefail

if ! command -v git >/dev/null 2>&1; then
  echo "error: git is not on PATH. Install git first." >&2
  exit 1
fi

cd "$(git rev-parse --show-toplevel)"

# SMOLVM_ENABLED=0 forces the host path.
# The guest sets this value, so the checks do not recurse.
# SMOLVM_ENABLED=1 enforces smolvm.
# The run stops with an error when smolvm is unavailable.
# An unset variable or any other value selects auto mode.
# Auto mode uses smolvm when possible.
# Otherwise it runs the checks on the host.

# Exit code 3 means the run cannot use smolvm in enforced mode.
readonly SMOLVM_ENFORCED_RC=3

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

print_enforced_error() {
  cat >&2 <<'EOF'
ERROR: SMOLVM_ENABLED=1 requires smolvm.
smolvm is not on PATH, or the host accelerator is unavailable.
The checks did not run.
Install smolvm on the host.
Give the host a working accelerator.
Alternatively, set SMOLVM_ADDR to use a remote smolvm server.
See docs/smolvm.md for the requirements.
EOF
}

smolvm_mode="${SMOLVM_ENABLED:-}"
if [[ "$smolvm_mode" != "0" ]]; then
  if [[ -n "${SMOLVM_ADDR:-}" ]]; then
    exec scripts/smolvm.sh
  fi
  if host_accel_ok; then
    exec scripts/smolvm.sh
  fi
  if [[ "$smolvm_mode" == "1" ]]; then
    print_enforced_error
    exit "$SMOLVM_ENFORCED_RC"
  fi
  cat >&2 <<'EOF'
!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!
!! WARNING: smolvm or the host accelerator is not available.
!! The checks did NOT run in a microVM.
!! The checks run on the HOST instead.
!! Install smolvm and give the host a working accelerator.
!! See docs/smolvm.md for the requirements.
!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!
EOF
fi

shopt -s nullglob
checks=(scripts/check-*.sh)
shopt -u nullglob

if ((${#checks[@]} == 0)); then
  echo "error: no check scripts found in scripts/." >&2
  exit 1
fi

for check in "${checks[@]}"; do
  echo "run: $check"
  "$check"
done

echo "all checks passed (${#checks[@]} scripts)"
