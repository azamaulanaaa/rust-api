#!/usr/bin/env bash
# Run one arbitrary command inside the smolvm microVM.
# The microVM shape matches scripts/smolvm.sh: the cached pack, the
# repository mounted read-only at /workspace, no network, and a
# --timeout backstop that defaults to 10m.
# The command is the user's own command. It is not trusted input,
# and it is not run on the host under any circumstances.
set -euo pipefail

script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

if command -v git >/dev/null 2>&1; then
  root="$(git rev-parse --show-toplevel 2>/dev/null || true)"
  if [[ -n "$root" ]]; then
    cd "$root"
  fi
fi

# shellcheck source=scripts/smolvm-resources.sh
source "$script_dir/smolvm-resources.sh"
if ! smolvm_resources_resolve; then
  exit 1
fi

if [[ $# -eq 0 ]]; then
  echo "usage: scripts/smolvm-exec.sh <command string>" >&2
  echo "example: scripts/smolvm-exec.sh 'which mise && mise --version'" >&2
  echo "example: make smolvm-exec ARGS='df -h /'" >&2
  exit 2
fi

# Join the arguments with spaces. Both call shapes work:
#   scripts/smolvm-exec.sh 'which mise && mise --version'
#   scripts/smolvm-exec.sh which mise
cmd="$*"

# An empty command string is a usage error.
if [[ -z "${cmd//[[:space:]]/}" ]]; then
  echo "usage: scripts/smolvm-exec.sh <command string>" >&2
  echo "example: scripts/smolvm-exec.sh 'which mise && mise --version'" >&2
  echo "example: make smolvm-exec ARGS='df -h /'" >&2
  exit 2
fi

if [[ -n "${SMOLVM_SERVE_ADDR:-}" ]]; then
  # Run the command in a machine on the remote server. Never use the host.
  # The auto mode streams a piped local stdin to the guest command.
  # shellcheck source=scripts/smolvm-serve.sh
  source "$script_dir/smolvm-serve.sh"
  echo "exec=$cmd"
  serve_run_remote \
    "cd /workspace && export SMOLVM_ENABLED=0 SMOLVM_GUEST=1 && $cmd" auto || exit $?
  exit "$SERVE_GUEST_RC"
fi

print_warning() {
  cat >&2 <<'EOF'
!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!
!! WARNING: smolvm or the host accelerator is not available.
!! No microVM available. The command was NOT executed.
!! Install smolvm and give the host a working accelerator.
!! See docs/smolvm.md for the requirements.
!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!
EOF
}

# Detect whether this host can run a smolvm machine.
# Linux needs a readable /dev/kvm.
# macOS on Apple Silicon uses the built-in hypervisor; kern.hv_support must be 1.
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

if ! host_accel_ok; then
  print_warning
  exit 1
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

echo "exec=$cmd"
rc=0
smolvm machine run --from "$pack" --timeout "${SMOLVM_TIMEOUT:-10m}" \
  -v "$PWD":/workspace:ro -- bash -lc \
  "cd /workspace && export SMOLVM_ENABLED=0 SMOLVM_GUEST=1 && $cmd" || rc=$?

exit "$rc"
