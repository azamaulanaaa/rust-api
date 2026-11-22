#!/usr/bin/env bash
# Run a release in a writable clone inside the guest.
# The repository mount at /workspace stays read-only.
set -euo pipefail

name=""
email=""
branch=""
old_head=""

usage() {
  cat >&2 <<'EOF'
usage: scripts/release-guest.sh --name <name> --email <email> --branch <branch> --old-head <commit> [cog arguments]
EOF
}

while (($# > 0)); do
  case "$1" in
  --name)
    if (($# < 2)); then
      echo "error: --name needs a value." >&2
      usage
      exit 2
    fi
    name="$2"
    shift 2
    ;;
  --email)
    if (($# < 2)); then
      echo "error: --email needs a value." >&2
      usage
      exit 2
    fi
    email="$2"
    shift 2
    ;;
  --branch)
    if (($# < 2)); then
      echo "error: --branch needs a value." >&2
      usage
      exit 2
    fi
    branch="$2"
    shift 2
    ;;
  --old-head)
    if (($# < 2)); then
      echo "error: --old-head needs a value." >&2
      usage
      exit 2
    fi
    old_head="$2"
    shift 2
    ;;
  --)
    shift
    break
    ;;
  *)
    break
    ;;
  esac
done

if [[ -z "$name" || -z "$email" || -z "$branch" || -z "$old_head" ]]; then
  echo "error: a required release value is empty." >&2
  usage
  exit 2
fi

if ! command -v git >/dev/null 2>&1; then
  echo "error: git is not on PATH in the guest. Install git first." >&2
  exit 1
fi
if ! command -v cog >/dev/null 2>&1; then
  echo "error: cog is not on PATH in the guest. Install cocogitto first." >&2
  exit 1
fi
if ! command -v base64 >/dev/null 2>&1; then
  echo "error: base64 is not on PATH in the guest. Install coreutils first." >&2
  exit 1
fi
if ! git -C /workspace rev-parse --git-dir >/dev/null 2>&1; then
  echo "error: /workspace is not a git repository." >&2
  exit 1
fi

work_parent="$(mktemp -d "${TMPDIR:-/tmp}/smolvm-release.XXXXXX")" || exit 1
work="${work_parent}/repo"

cleanup() {
  local rc=$?
  trap - EXIT
  rm -rf -- "$work_parent"
  exit "$rc"
}
trap cleanup EXIT

if ! git clone --no-hardlinks /workspace "$work"; then
  echo "error: the guest could not clone /workspace." >&2
  exit 1
fi
cd "$work"

# Add safe.directory only when git refuses the clone ownership.
if ! git rev-parse --git-dir >/dev/null 2>&1; then
  git config --global --add safe.directory "$work"
  if ! git rev-parse --git-dir >/dev/null 2>&1; then
    echo "error: git cannot read the clone." >&2
    exit 1
  fi
fi

git remote remove origin

if ! git checkout -B "$branch" "$old_head"; then
  echo "error: the guest could not check out ${branch} at ${old_head}." >&2
  exit 1
fi

if [[ -d .githook ]]; then
  git config core.hooksPath .githook
fi
git config user.name "$name"
git config user.email "$email"

cog_rc=0
cog bump "$@" || cog_rc=$?

if ((cog_rc != 0)); then
  echo "error: cog bump failed with exit code ${cog_rc}." >&2
  exit "$cog_rc"
fi

new_head="$(git rev-parse HEAD)"
if [[ "$new_head" == "$old_head" ]]; then
  echo "SMOLVM_RELEASE_NONE=1"
  exit 0
fi

mapfile -t tags < <(git tag --points-at HEAD --list 'v*')
if ((${#tags[@]} != 1)); then
  echo "error: HEAD has ${#tags[@]} v tags. The release needs exactly one." >&2
  exit 1
fi
tag="${tags[0]}"

bundle="${work_parent}/release.bundle"
git bundle create "$bundle" "$old_head..$new_head" "refs/tags/$tag"
git bundle verify "$bundle"

echo "SMOLVM_RELEASE_TAG=$tag"
echo "release: the guest made one version commit and tag ${tag}."
echo "__SMOLVM_RELEASE_BUNDLE_BEGIN__"
base64 <"$bundle"
echo "__SMOLVM_RELEASE_BUNDLE_END__"
