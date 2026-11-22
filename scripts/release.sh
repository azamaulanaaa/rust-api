#!/usr/bin/env bash
# Run cog bump in a writable copy inside the smolvm guest.
# The guest returns a bundle. The host validates the bundle and applies it.
# SMOLVM_ENABLED=1 stops the run when smolvm is unavailable.
set -euo pipefail

# Exit code 3 means the run cannot use smolvm in enforced mode.
readonly SMOLVM_ENFORCED_RC=3

script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

name=""
email=""
branch=""
old_head=""
new_commit=""
BUMP_ARGS=()

print_host_warning() {
  cat >&2 <<'EOF'
WARNING: smolvm or the host accelerator is not available.
The release runs on the HOST. The repository can change.
Install smolvm and give the host a working accelerator to use the sandbox.
See docs/smolvm.md for the requirements.
EOF
}

print_enforced_error() {
  cat >&2 <<'EOF'
ERROR: SMOLVM_ENABLED=1 requires smolvm.
smolvm is not on PATH, or the host accelerator is unavailable.
The release did not run.
Install smolvm on the host.
Give the host a working accelerator.
Alternatively, set SMOLVM_ADDR to use a remote smolvm server.
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

# Check the host state before a guest run.
# Set name, email, branch, and old_head for the guest command.
preflight() {
  local top
  if ! top="$(git rev-parse --show-toplevel 2>/dev/null)"; then
    echo "error: this directory is not a git repository." >&2
    return 1
  fi
  cd "$top"

  if [[ -n "$(git status --porcelain)" ]]; then
    echo "error: the worktree is not clean. Commit or stash the changes first." >&2
    return 1
  fi

  if ! branch="$(git symbolic-ref --quiet --short HEAD 2>/dev/null)"; then
    echo "error: HEAD is detached. Check out a branch first." >&2
    return 1
  fi

  name="$(git config user.name || true)"
  email="$(git config user.email || true)"
  if [[ -z "$name" ]]; then
    echo "error: git user.name is empty. Set it first." >&2
    return 1
  fi
  if [[ -z "$email" ]]; then
    echo "error: git user.email is empty. Set it first." >&2
    return 1
  fi

  old_head="$(git rev-parse HEAD)"
}

# Build the arguments for cog bump.
# Add --auto unless the caller selects a version.
build_bump_args() {
  local argument
  for argument in "$@"; do
    case "$argument" in
    --auto | --version | --major | --minor | --patch)
      BUMP_ARGS=("$@")
      return 0
      ;;
    esac
  done
  BUMP_ARGS=(--auto "$@")
}

# Build the guest command. Quote every value for the guest shell.
guest_command() {
  local command
  local argument
  build_bump_args "$@"
  command="cd /workspace && SMOLVM_ENABLED=0 SMOLVM_GUEST=1 bash scripts/release-guest.sh"
  command+=" --name $(printf '%q' "$name")"
  command+=" --email $(printf '%q' "$email")"
  command+=" --branch $(printf '%q' "$branch")"
  command+=" --old-head $(printf '%q' "$old_head")"
  command+=" --"
  for argument in "${BUMP_ARGS[@]}"; do
    command+=" $(printf '%q' "$argument")"
  done
  printf '%s' "$command"
}

# Run the release on the host. This path needs no sandbox.
run_host() {
  local top
  if ! top="$(git rev-parse --show-toplevel 2>/dev/null)"; then
    echo "error: this directory is not a git repository." >&2
    return 1
  fi
  cd "$top"
  if ! command -v cog >/dev/null 2>&1; then
    echo "error: cog is not on PATH. Install cocogitto first." >&2
    return 1
  fi
  build_bump_args "$@"
  cog bump "${BUMP_ARGS[@]}"
}

# Run the release in a local smolvm machine.
run_local() {
  if ! preflight; then
    return 1
  fi

  local git_dir
  local common_dir
  if ! git_dir="$(git rev-parse --absolute-git-dir 2>/dev/null)" ||
    ! common_dir="$(git rev-parse --path-format=absolute --git-common-dir 2>/dev/null)"; then
    echo "error: the git directory was not resolved." >&2
    return 1
  fi
  if [[ "$git_dir" != "$common_dir" ]]; then
    echo "error: local release mode needs a normal checkout, not a linked worktree." >&2
    echo "error: Use a normal checkout, or set SMOLVM_ADDR for remote mode." >&2
    return 1
  fi

  # shellcheck source=scripts/smolvm-resources.sh
  source "$script_dir/smolvm-resources.sh"
  if ! command -v sha256sum >/dev/null 2>&1; then
    echo "error: sha256sum is not on PATH." >&2
    return 1
  fi
  if ! smolvm_resources_resolve; then
    return 1
  fi

  local hash
  local pack
  local log
  local rc=0

  hash="$(smolvm_resources_hash_lines | sha256sum | cut -d' ' -f1)"
  pack=".cache/smolvm/ci-${hash}.smolmachine"

  if [[ ! -f "$pack" ]]; then
    smol/pack-build.sh "$hash"
  fi
  if [[ ! -f "$pack" ]]; then
    echo "error: pack was not built: ${pack}" >&2
    return 1
  fi

  log="$(mktemp "${TMPDIR:-/tmp}/smolvm-release.XXXXXX.log")" || return 1
  smolvm machine run --from "$pack" --timeout "${SMOLVM_TIMEOUT:-10m}" \
    -v "$PWD":/workspace:ro -- bash -lc "$(guest_command "$@")" >"$log" 2>&1 || rc=$?
  finish_from_log "$log" "$rc"
}

# Run the release in a machine on a remote smolvm serve server.
run_remote() {
  if ! preflight; then
    return 1
  fi
  # shellcheck source=scripts/smolvm-serve.sh
  source "$script_dir/smolvm-serve.sh"

  local log
  local rc=0

  log="$(mktemp "${TMPDIR:-/tmp}/smolvm-release.XXXXXX.log")" || return 1
  serve_run_remote "$(guest_command "$@")" none >"$log" 2>&1 || rc=$?
  if ((rc == 0)); then
    rc="$SERVE_GUEST_RC"
  fi
  finish_from_log "$log" "$rc"
}

# Print the guest log without the base64 bundle block.
strip_bundle_block() {
  local log="$1"
  awk '
    /^__SMOLVM_RELEASE_BUNDLE_BEGIN__$/ { inside = 1; next }
    /^__SMOLVM_RELEASE_BUNDLE_END__$/ { inside = 0; next }
    !inside { print }
  ' "$log"
}

# Print the base64 text between the bundle markers.
extract_bundle_b64() {
  local log="$1"
  awk '
    /^__SMOLVM_RELEASE_BUNDLE_BEGIN__$/ { inside = 1; next }
    /^__SMOLVM_RELEASE_BUNDLE_END__$/ { inside = 0; next }
    inside { print }
  ' "$log"
}

# Decode one base64 file into another file. Try GNU base64, then BSD base64.
decode_base64_file() {
  local source="$1"
  local target="$2"
  if base64 -d <"$source" >"$target" 2>/dev/null; then
    return 0
  fi
  if base64 -D <"$source" >"$target" 2>/dev/null; then
    return 0
  fi
  return 1
}

# Print the one v tag that the bundle holds.
bundle_tag_from_heads() {
  local bundle="$1"
  local heads
  local line
  local ref
  local -a tags=()

  heads="$(git bundle list-heads "$bundle")" || return 1
  while IFS= read -r line; do
    [[ -n "$line" ]] || continue
    ref="${line##* }"
    if [[ "$ref" == refs/tags/v* ]]; then
      tags+=("${ref#refs/tags/}")
    fi
  done <<<"$heads"

  if ((${#tags[@]} != 1)); then
    echo "error: the bundle must hold exactly one v tag. It holds ${#tags[@]}." >&2
    return 1
  fi
  printf '%s' "${tags[0]}"
}

# Check the fetched version commit before any host ref changes.
# Set new_commit on success.
validate_release() {
  local tag="$1"
  local commit
  local parent_line
  local author_email
  local committer_email
  local -a fields
  local -a changed

  commit="$(git rev-parse --verify "${tag}^{commit}")" || {
    echo "error: the bundle tag does not name a commit." >&2
    return 1
  }

  parent_line="$(git rev-list --parents -n 1 "$commit")"
  read -r -a fields <<<"$parent_line"
  if ((${#fields[@]} != 2)); then
    echo "error: the version commit must have exactly one parent." >&2
    return 1
  fi
  if [[ "${fields[1]}" != "$old_head" ]]; then
    echo "error: the version commit parent is not the captured HEAD." >&2
    return 1
  fi

  if [[ "$(git rev-list --count "$old_head..$commit")" != "1" ]]; then
    echo "error: the bundle must add exactly one commit." >&2
    return 1
  fi

  mapfile -t changed < <(git diff-tree --no-commit-id --name-only -r "$commit")
  if ((${#changed[@]} != 1)) || [[ "${changed[0]}" != "CHANGELOG.md" ]]; then
    echo "error: the version commit must change only CHANGELOG.md." >&2
    return 1
  fi

  author_email="$(git show -s --format=%ae "$commit")"
  committer_email="$(git show -s --format=%ce "$commit")"
  if [[ "$author_email" != "$email" ]]; then
    echo "error: the author email does not match the host email." >&2
    return 1
  fi
  if [[ "$committer_email" != "$email" ]]; then
    echo "error: the committer email does not match the host email." >&2
    return 1
  fi

  if [[ "$(git rev-parse HEAD)" != "$old_head" ]]; then
    echo "error: the host HEAD moved during the release." >&2
    return 1
  fi
  if [[ "$(git symbolic-ref --quiet --short HEAD 2>/dev/null)" != "$branch" ]]; then
    echo "error: the host branch changed during the release." >&2
    return 1
  fi
  if [[ -n "$(git status --porcelain)" ]]; then
    echo "error: the host worktree is not clean after the guest run." >&2
    return 1
  fi

  new_commit="$commit"
}

# Delete the fetched tag. Reset the host only when the host still sits at
# the guest commit on the captured branch with a clean worktree.
rollback_release() {
  local tag="$1"
  local current_branch=""

  if git rev-parse --verify --quiet "refs/tags/${tag}" >/dev/null; then
    git tag -d "$tag" >/dev/null || true
  fi

  if [[ -z "$new_commit" ]]; then
    return 0
  fi
  if [[ "$(git rev-parse HEAD 2>/dev/null || true)" != "$new_commit" ]]; then
    return 0
  fi
  current_branch="$(git symbolic-ref --quiet --short HEAD 2>/dev/null || true)"
  if [[ "$current_branch" != "$branch" ]]; then
    return 0
  fi
  if [[ -n "$(git status --porcelain)" ]]; then
    return 0
  fi
  git reset --hard "$old_head" >/dev/null || true
}

# Validate the bundle and apply the version commit and tag to the host.
apply_release() {
  local bundle="$1"
  local tag_hint="$2"
  local tag

  new_commit=""

  if ! git bundle verify "$bundle" >/dev/null; then
    echo "error: the release bundle did not verify." >&2
    return 1
  fi

  tag="$(bundle_tag_from_heads "$bundle")" || return 1
  if [[ -n "$tag_hint" && "$tag_hint" != "$tag" ]]; then
    echo "error: the bundle tag does not match the guest tag." >&2
    return 1
  fi

  if git rev-parse --verify --quiet "refs/tags/${tag}" >/dev/null; then
    echo "error: the tag ${tag} already exists on the host." >&2
    return 1
  fi

  if ! git fetch --no-tags "$bundle" "refs/tags/${tag}:refs/tags/${tag}" >/dev/null 2>&1; then
    echo "error: the bundle tag was not fetched." >&2
    return 1
  fi

  if ! validate_release "$tag"; then
    rollback_release "$tag"
    echo "error: the release did not change the host." >&2
    return 1
  fi

  if ! git merge --ff-only "$new_commit" >/dev/null 2>&1; then
    rollback_release "$tag"
    echo "error: the host did not fast-forward to the version commit." >&2
    return 1
  fi

  echo "release: applied tag ${tag} at commit ${new_commit:0:7}."
  echo "release: the tag is local. Push it with: git push origin ${tag}"
}

# Print the guest log and apply the bundle. Exit 0 for a no-release run.
finish_from_log() {
  local log="$1"
  local rc="$2"
  local tag
  local b64
  local bundle
  local status=0

  strip_bundle_block "$log"

  if ((rc != 0)); then
    echo "error: the guest release failed with exit code ${rc}." >&2
    rm -f "$log"
    return "$rc"
  fi

  if grep -qx 'SMOLVM_RELEASE_NONE=1' "$log"; then
    echo "release: no releasable commits. The repository did not change."
    rm -f "$log"
    return 0
  fi

  if ! command -v base64 >/dev/null 2>&1; then
    echo "error: base64 is not on PATH. Install coreutils first." >&2
    rm -f "$log"
    return 1
  fi

  if ! grep -qx '__SMOLVM_RELEASE_BUNDLE_BEGIN__' "$log" ||
    ! grep -qx '__SMOLVM_RELEASE_BUNDLE_END__' "$log"; then
    echo "error: the guest bundle markers are missing." >&2
    rm -f "$log"
    return 1
  fi

  tag="$(sed -n 's/^SMOLVM_RELEASE_TAG=//p' "$log" | head -n 1)"
  if [[ -z "$tag" ]]; then
    echo "error: the guest did not report a release tag." >&2
    rm -f "$log"
    return 1
  fi

  b64="$(mktemp "${TMPDIR:-/tmp}/smolvm-release.XXXXXX.b64")" || {
    rm -f "$log"
    return 1
  }
  bundle="$(mktemp "${TMPDIR:-/tmp}/smolvm-release.XXXXXX.bundle")" || {
    rm -f "$log" "$b64"
    return 1
  }

  if ! extract_bundle_b64 "$log" >"$b64"; then
    echo "error: the guest bundle was not read." >&2
    status=1
  elif [[ ! -s "$b64" ]]; then
    echo "error: the guest bundle is empty." >&2
    status=1
  elif ! decode_base64_file "$b64" "$bundle"; then
    echo "error: the guest bundle did not decode." >&2
    status=1
  fi

  if ((status == 0)); then
    if ! apply_release "$bundle" "$tag"; then
      status=1
    fi
  fi

  rm -f "$log" "$b64" "$bundle"
  return "$status"
}

main() {
  local mode="${SMOLVM_ENABLED:-}"

  if [[ "$mode" == "0" ]]; then
    run_host "$@"
    return
  fi

  if [[ "$mode" == "1" ]]; then
    if [[ -n "${SMOLVM_ADDR:-}" ]]; then
      run_remote "$@"
      return
    fi
    if host_accel_ok; then
      run_local "$@"
      return
    fi
    print_enforced_error
    return "$SMOLVM_ENFORCED_RC"
  fi

  if [[ -n "${SMOLVM_ADDR:-}" ]]; then
    run_remote "$@"
    return
  fi
  if host_accel_ok; then
    run_local "$@"
    return
  fi
  print_host_warning
  run_host "$@"
}

if [[ "${BASH_SOURCE[0]}" == "$0" ]]; then
  main "$@"
fi
