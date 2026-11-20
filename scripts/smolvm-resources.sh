#!/usr/bin/env bash
# Read and validate the smolvm CPU and memory settings.
# Source this file from a smolvm script. Do not run it as a command.
# The settings come from SMOLVM_CPUS and SMOLVM_MEMORY_MB.
# The defaults are one CPU and 512 MiB of memory.

# Print an error when a value is not a positive integer.
smolvm_resources_check_integer() {
  local name="$1"
  local value="$2"
  if [[ ! "$value" =~ ^[1-9][0-9]*$ ]]; then
    echo "error: ${name} must be a positive integer." >&2
    return 1
  fi
}

# Read the two environment variables, validate them, and set the globals
# SMOLVM_CPUS_VALUE and SMOLVM_MEMORY_MB_VALUE.
smolvm_resources_resolve() {
  local cpus="${SMOLVM_CPUS-1}"
  local memory_mb="${SMOLVM_MEMORY_MB-512}"
  if ! smolvm_resources_check_integer "SMOLVM_CPUS" "$cpus"; then
    return 1
  fi
  if ! smolvm_resources_check_integer "SMOLVM_MEMORY_MB" "$memory_mb"; then
    return 1
  fi
  SMOLVM_CPUS_VALUE="$cpus"
  SMOLVM_MEMORY_MB_VALUE="$memory_mb"
}

# Print the sha256sum lines that form the pack cache key.
# Add the resource values when they differ from the defaults.
# A pack built for one resource setting is then not reused for another.
smolvm_resources_hash_lines() {
  sha256sum mise.toml smol/*.smolfile smol/pack-build.sh smol/init.sh
  if [[ "$SMOLVM_CPUS_VALUE" != "1" || "$SMOLVM_MEMORY_MB_VALUE" != "512" ]]; then
    printf 'cpus=%s\n' "$SMOLVM_CPUS_VALUE"
    printf 'memoryMb=%s\n' "$SMOLVM_MEMORY_MB_VALUE"
  fi
}

# Write the base smolfile with the resolved values to the output path.
# The base file holds placeholders. This function replaces them.
smolvm_resources_render_smolfile() {
  local output="$1"
  sed \
    -e "s|__SMOLVM_CPUS__|${SMOLVM_CPUS_VALUE}|g" \
    -e "s|__SMOLVM_MEMORY_MB__|${SMOLVM_MEMORY_MB_VALUE}|g" \
    smol/base.smolfile >"$output"
}
