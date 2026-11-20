#!/usr/bin/env bash
# Verify the microVM isolation from inside the guest and from the host.
# Run the probe in the same shape as the real run: the pack from the
# cache, the repository mounted read-only at /workspace, no network.
# Print one key=value per line. The last line is result=isolation_held,
# result=FAILED, or result=blocked.
# Exit 0 when the isolation held. Exit 1 otherwise. Exit 2 on a usage error.
set -uo pipefail

if [ "$#" -gt 0 ]; then
  if [ "$1" = "-h" ] || [ "$1" = "--help" ]; then
    cat <<'EOF'
usage: verify.sh

Probe the isolation of the microVM from inside the guest and from the host.
Uses the same shape as a real run: the cached pack, the repository read-only
at /workspace, no network.
Exit 0 when result=isolation_held. Exit 1 otherwise. Exit 2 on a usage error.
EOF
    exit 0
  fi
  printf 'usage error: verify.sh takes no arguments\n' >&2
  exit 2
fi

if ! command -v git >/dev/null 2>&1; then
  echo "error: git is not on PATH. Install git first." >&2
  exit 2
fi

cd "$(git rev-parse --show-toplevel)" || exit 2

# shellcheck source=scripts/smolvm-resources.sh
source scripts/smolvm-resources.sh
smolvm_resources_resolve || exit 2

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

if ! command -v smolvm >/dev/null 2>&1; then
  printf 'smolvm_installed=no\n'
  printf 'note=smolvm is not on PATH; the probe cannot run\n'
  printf 'result=blocked\n'
  exit 1
fi
printf 'smolvm_installed=yes\n'

if ! host_accel_ok; then
  case "$(uname -s)" in
  Linux) printf 'accel_access=missing\n' ;;
  Darwin) printf 'accel_access=denied\n' ;;
  *) printf 'accel=unsupported\n' ;;
  esac
  printf 'note=the host cannot run a smolvm machine; see make smolvm-preflight\n'
  printf 'result=blocked\n'
  exit 1
fi
printf 'accel_access=ok\n'

if ! command -v sha256sum >/dev/null 2>&1; then
  printf 'sha256sum=missing\n'
  printf 'note=sha256sum is needed to find the cached pack\n'
  printf 'result=blocked\n'
  exit 1
fi

hash="$(smolvm_resources_hash_lines | sha256sum | cut -d' ' -f1)"
pack=".cache/smolvm/ci-${hash}.smolmachine"

# Build the pack when it is missing, as the real run does.
if [[ ! -f "$pack" ]]; then
  smol/pack-build.sh "$hash"
fi
if [[ ! -f "$pack" ]]; then
  printf 'pack=missing\n'
  printf 'note=the pack is not built; run make smolvm-pack on a host that can run smolvm\n'
  printf 'result=blocked\n'
  exit 1
fi
printf 'pack=%s\n' "$pack"

fail=0

# --- from inside the guest, in the same shape a real run uses --------------
# The guest probe checks the write refusal with touch and the network with
# bash /dev/tcp. No external probe tool is needed.
# A bash without /dev/tcp prints net=no_probe_tool. That is a FAIL, not a pass.
# The commands expand on the guest, not on this host.
# shellcheck disable=SC2016
inside="$(smolvm machine run --from "$pack" -v "$PWD:/workspace:ro" \
  --timeout "${SMOLVM_TIMEOUT:-10m}" -- bash -lc '
    if touch /workspace/ISOLATION_PROBE 2>/dev/null; then
      echo "workspace=WRITABLE"
    else
      echo "workspace=readonly"
    fi
    probe_err="$( (echo > /dev/tcp/127.0.0.1/1) 2>&1 >/dev/null )"
    case "$probe_err" in
      *"No such file"*) printf "net=no_probe_tool\n" ;;
      *)
        if (echo > /dev/tcp/example.com/80) 2>/dev/null; then
          printf "net=REACHED\n"
        else
          printf "net=blocked\n"
        fi
        ;;
    esac
  ' 2>&1 | tr -d "\r")"

printf '%s\n' "$inside" | sed 's/^/  /'

workspace="$(printf '%s\n' "$inside" | sed -n 's/^workspace=//p')"
network="$(printf '%s\n' "$inside" | sed -n 's/^net=//p')"

if [ "$workspace" = "readonly" ]; then
  printf 'inside_workspace=ok (readonly)\n'
else
  printf 'inside_workspace=FAIL expected=readonly actual=%s\n' "${workspace:-missing}"
  fail=1
fi

case "$network" in
blocked)
  printf 'inside_network=ok (blocked)\n'
  ;;
REACHED)
  printf 'inside_network=FAIL expected=blocked actual=REACHED\n'
  note="the guest reached the network; see docs/smolvm.md for what this means"
  printf 'note=%s\n' "$note"
  fail=1
  ;;
no_probe_tool)
  printf 'inside_network=FAIL expected=blocked actual=no_probe_tool\n'
  printf 'note=the guest bash has no /dev/tcp support; the network probe cannot run\n'
  fail=1
  ;;
*)
  printf 'inside_network=FAIL expected=blocked actual=%s\n' "${network:-missing}"
  fail=1
  ;;
esac

# --- from the host afterwards ------------------------------------------------
# The probe above tried to write the repository. If the read-only mount
# leaked, the evidence is sitting in the repository now.
if [ -e "$PWD/ISOLATION_PROBE" ]; then
  printf 'repo_unchanged=FAIL the read-only mount leaked; %s/ISOLATION_PROBE exists\n' "$PWD"
  rm -f "$PWD/ISOLATION_PROBE"
  if [ -e "$PWD/ISOLATION_PROBE" ]; then
    printf 'note=failed to remove %s/ISOLATION_PROBE\n' "$PWD"
  fi
  fail=1
else
  printf 'repo_unchanged=ok\n'
fi

if [ "$fail" -eq 0 ]; then
  printf 'result=isolation_held\n'
else
  printf 'result=FAILED\n'
fi
exit "$fail"
