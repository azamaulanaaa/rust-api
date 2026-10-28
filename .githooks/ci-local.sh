#!/usr/bin/env bash
# Mirror the GitHub Actions CI workflow on the local machine.
# This script runs the same commands and flags as .github/workflows/ci.yml.
set -uo pipefail

if ! REPO_ROOT=$(git rev-parse --show-toplevel 2>/dev/null); then
    echo "ERROR: This script must run inside a git repository." >&2
    exit 1
fi
cd "$REPO_ROOT" || exit 1

JOBS=(lint test coverage msrv doc release-config licenses advisories bans)
DEFAULT_JOBS=(lint test msrv doc release-config licenses advisories bans)

usage() {
    cat <<'EOF'
Usage: .githooks/ci-local.sh [options] [job ...]

Run the CI jobs from .github/workflows/ci.yml on the local machine.

Options:
  --all       Run every job. This includes coverage.
  --list      List the job names and exit.
  --help, -h  Show this help and exit.

Jobs:
  lint            Check formatting and run clippy.
  test            Run the unit, integration, and doc tests.
  coverage        Measure coverage with cargo-llvm-cov.
  msrv            Build against the rust-version from Cargo.toml.
  doc             Build the docs with warnings as errors.
  release-config  Check the release workflow gate and the dist plan.
  licenses        Check dependency licences with cargo deny.
  advisories      Check advisories with cargo deny.
  bans            Check bans with cargo deny.

With no job arguments, the script runs every job except coverage.
Coverage is expensive. Name it, or pass --all, to run it.

Environment:
  CI_LOCAL_STRICT=1  Turn every skipped job into a failure.

The script stops at the first failing job. It exits with that job's status.
EOF
}

list_jobs() {
    printf '%s\n' "${JOBS[@]}"
}

step() {
    echo
    echo "--- $*"
}

require_tool() {
    command -v "$1" >/dev/null 2>&1
}

skip_job() {
    local job=$1
    local reason=$2
    if [ "${CI_LOCAL_STRICT:-0}" = "1" ]; then
        echo "ERROR: $job skipped. $reason" >&2
        echo "CI_LOCAL_STRICT=1 turns this skip into a failure." >&2
        exit 1
    fi
    echo "SKIP: $job. $reason" >&2
}

toolchain_installed() {
    local want=$1
    local escaped
    escaped=${want//./\\.}
    if ! command -v rustup >/dev/null 2>&1; then
        return 1
    fi
    rustup toolchain list 2>/dev/null | awk '{print $1}' | grep -Eq "^${escaped}([.-]|$)"
}

job_lint() {
    require_tool cargo || { skip_job lint "The cargo tool is not on PATH. Run mise install."; return 0; }
    step "cargo fmt --all --check"
    cargo fmt --all --check
    step "cargo clippy --all-targets --all-features --locked -- -D warnings"
    cargo clippy --all-targets --all-features --locked -- -D warnings
}

job_test() {
    require_tool cargo || { skip_job test "The cargo tool is not on PATH. Run mise install."; return 0; }
    step "cargo test --all-targets --all-features --locked"
    cargo test --all-targets --all-features --locked
    step "cargo test --doc --locked"
    cargo test --doc --locked
}

job_coverage() {
    require_tool cargo || { skip_job coverage "The cargo tool is not on PATH. Run mise install."; return 0; }
    require_tool cargo-llvm-cov || { skip_job coverage "The cargo-llvm-cov tool is not on PATH. Run mise install."; return 0; }
    step "cargo llvm-cov --all-features --html --locked --output-dir target/llvm-cov"
    cargo llvm-cov --all-features --html --locked --output-dir target/llvm-cov
    echo "Coverage report: target/llvm-cov/html/index.html"
    echo "CI uploads this report as an artifact. This script keeps it in the target directory."
}

job_msrv() {
    require_tool cargo || { skip_job msrv "The cargo tool is not on PATH. Run mise install."; return 0; }
    local floor
    floor=$(sed -n 's/^rust-version = "\(.*\)"/\1/p' Cargo.toml | head -1)
    if [ -z "$floor" ]; then
        echo "ERROR: Cargo.toml has no rust-version." >&2
        return 1
    fi
    if ! toolchain_installed "$floor"; then
        skip_job msrv "The Rust $floor toolchain is not installed. This script does not download it. Run rustup toolchain install $floor."
        return 0
    fi
    step "cargo +$floor check --all-targets --all-features --locked"
    cargo "+$floor" check --all-targets --all-features --locked
}

job_doc() {
    require_tool cargo || { skip_job doc "The cargo tool is not on PATH. Run mise install."; return 0; }
    step 'RUSTDOCFLAGS="-D warnings" cargo doc --no-deps --all-features'
    RUSTDOCFLAGS="-D warnings" cargo doc --no-deps --all-features
}

job_release_config() {
    require_tool dist || { skip_job release-config "The dist tool is not on PATH. Run mise install."; return 0; }
    local workflow=.github/workflows/release.yml
    step "Check that $workflow still calls ci.yml"
    if ! grep -q 'uses: ./.github/workflows/ci.yml' "$workflow"; then
        echo "ERROR: $workflow no longer calls ci.yml. Re-apply the checks job." >&2
        return 1
    fi
    step "Check that build-local-artifacts still waits for checks"
    if ! grep -A4 'build-local-artifacts:' "$workflow" | grep -q '^ *- checks$'; then
        echo "ERROR: $workflow no longer waits for checks before the build. Re-apply checks to the needs of build-local-artifacts." >&2
        return 1
    fi
    echo "Release workflow is gated on CI."
    step "dist plan --output-format=human > /dev/null"
    dist plan --output-format=human > /dev/null
}

job_licenses() {
    require_tool cargo-deny || { skip_job licenses "The cargo-deny tool is not on PATH. Run mise install."; return 0; }
    step "cargo deny check licenses"
    cargo deny check licenses
}

job_advisories() {
    require_tool cargo-deny || { skip_job advisories "The cargo-deny tool is not on PATH. Run mise install."; return 0; }
    step "cargo deny check advisories"
    cargo deny check advisories
}

job_bans() {
    require_tool cargo-deny || { skip_job bans "The cargo-deny tool is not on PATH. Run mise install."; return 0; }
    step "cargo deny check bans"
    cargo deny check bans
}

run_job() {
    local job=$1
    echo
    echo "=== $job ==="
    if ( set -euo pipefail; "job_${job//-/_}" ); then
        echo "PASS: $job"
    else
        local rc=$?
        echo "FAIL: job $job failed with exit code $rc." >&2
        exit "$rc"
    fi
}

selected=()
all=0

for arg in "$@"; do
    case "$arg" in
        --help|-h)
            usage
            exit 0
            ;;
        --list)
            list_jobs
            exit 0
            ;;
        --all)
            all=1
            ;;
        -*)
            echo "ERROR: Unknown option: $arg" >&2
            echo "Run --help for usage." >&2
            exit 2
            ;;
        *)
            found=0
            for job in "${JOBS[@]}"; do
                if [ "$arg" = "$job" ]; then
                    found=1
                    break
                fi
            done
            if [ "$found" -ne 1 ]; then
                echo "ERROR: Unknown job: $arg" >&2
                echo "Run --list to see the job names." >&2
                exit 2
            fi
            selected+=("$arg")
            ;;
    esac
done

if [ "$all" -eq 1 ]; then
    run_jobs=("${JOBS[@]}")
elif [ "${#selected[@]}" -eq 0 ]; then
    run_jobs=("${DEFAULT_JOBS[@]}")
else
    run_jobs=()
    for job in "${JOBS[@]}"; do
        for want in "${selected[@]}"; do
            if [ "$job" = "$want" ]; then
                run_jobs+=("$job")
                break
            fi
        done
    done
fi

echo "Local CI: $REPO_ROOT"
for job in "${run_jobs[@]}"; do
    run_job "$job"
done

echo
echo "All selected jobs passed."
