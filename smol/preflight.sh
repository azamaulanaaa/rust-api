#!/usr/bin/env bash
# Probe whether this host is ready for the smolvm microVM.
# Read-only: starts no VM, bakes nothing, writes no smolvm state.
# Print one key=value per line. The last line is result=ready or result=blocked.
# Exit 0 when result=ready. Exit 1 when result=blocked. Exit 2 on a usage error.
set -uo pipefail

VERIFIED_VERSION="1.34.0"

at_least() { [ "$(printf '%s\n%s\n' "$1" "$2" | sort -V | head -1)" = "$2" ]; }

emit() { printf '%s=%s\n' "$1" "$2"; }
note() { printf 'note=%s\n' "$1"; }

if [ "$#" -gt 0 ]; then
  if [ "$1" = "-h" ] || [ "$1" = "--help" ]; then
    cat <<'EOF'
usage: preflight.sh

Print the key=value probe lines for this host.
Starts no VM and writes no state.
Exit 0 when result=ready. Exit 1 when result=blocked. Exit 2 on a usage error.
EOF
    exit 0
  fi
  printf 'usage error: preflight.sh takes no arguments\n' >&2
  exit 2
fi

blocked=0

SMOLVM="${SMOLVM:-$(command -v smolvm 2>/dev/null)}"
if [ -z "$SMOLVM" ]; then
  emit smolvm_installed no
  blocked=1
else
  emit smolvm_installed yes
  version="$("$SMOLVM" --version 2>/dev/null | awk '{print $NF}')"
  emit smolvm_version "${version:-unknown}"
fi

emit verified_version "$VERIFIED_VERSION"
if [ -n "${version:-}" ] && [ "$version" != "unknown" ]; then
  if [ "$version" = "$VERIFIED_VERSION" ]; then
    emit version_status match
  elif at_least "$version" "$VERIFIED_VERSION"; then
    emit version_status newer
    note "the throwaway-machine guide was verified on $VERIFIED_VERSION; this binary is $version; check each flag before you trust it"
  else
    emit version_status older
    note "this binary is older than $VERIFIED_VERSION; upgrade before you trust the microVM"
  fi
else
  emit version_status unknown
fi

kernel="$(uname -s)"
arch="$(uname -m)"
case "$arch" in aarch64 | arm64) arch=aarch64 ;; esac

case "$kernel" in
Linux)
  emit platform "linux-$arch"
  emit accel kvm
  if [ ! -e /dev/kvm ]; then
    emit accel_access missing
    blocked=1
    note "/dev/kvm does not exist; this host has no KVM"
  elif [ -r /dev/kvm ]; then
    emit accel_access ok
  else
    emit accel_access denied
    blocked=1
    note "your user cannot read /dev/kvm; add the user to the kvm group"
  fi
  emit pack_run available
  ;;
Darwin)
  emit platform "darwin-$arch"
  emit accel hypervisor_framework
  note "on macOS smolvm uses the built-in hypervisor; /dev/kvm does not exist"
  if [ "$(sysctl -n kern.hv_support 2>/dev/null)" = "1" ]; then
    emit accel_access ok
  else
    emit accel_access denied
    blocked=1
    note "sysctl kern.hv_support is not 1; the hypervisor is not available"
  fi
  # v1.24.0 to v1.29.0 broke every --oci-cache run on macOS
  # (smol-machines/smolvm#1819, fixed in v1.29.1). A pack --from run
  # is unaffected by #1819. macOS pack runs are UNVERIFIED for this
  # repository either way.
  emit pack_run unverified
  note "on macOS pack runs are UNVERIFIED for this repository; verify on a host before you trust them"
  ;;
*)
  emit platform "unsupported-$kernel"
  emit accel unknown
  emit accel_access unknown
  emit pack_run unavailable
  blocked=1
  note "this script covers macOS and Linux"
  ;;
esac

# The checks use exactly one mount and no ports and no network devices.
# On x86_64 a guest boots with at most nine devices (nine mounts on v1.23.0+).
# One mount is always inside the budget. arm64 guests have 128 IRQs.
emit planned_mounts 1
emit planned_ports 0
emit devices_requested 1
if [ "$arch" = "x86_64" ]; then
  emit device_budget 9
  emit device_budget_ok yes
else
  emit device_budget_ok not_limiting
fi

# Ctrl-C on the smolvm CLI ends the VM since v1.20.2.
emit cancel_route ctrlc
note "Ctrl-C on the smolvm CLI ends the VM since v1.20.2; make smolvm also sets a --timeout backstop"

if [ "$blocked" -eq 0 ]; then
  emit result ready
else
  emit result blocked
fi
exit "$blocked"
