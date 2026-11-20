# Check pipeline

This document describes the local check pipeline.

## Overview

The check pipeline is the set of scripts that check the repository. The
pipeline starts at one entry point, [`scripts/ci.sh`](../scripts/ci.sh).
`scripts/ci.sh` finds every check script. It runs each check script in
name order. A check script checks one area, such as shell syntax or the
commit history.

The `pre-commit` and `pre-push` hooks and the `Makefile` call the same
check scripts. A Git hook is a script that Git runs at a defined event.
The repository has one set of checks. The
[release workflow](release.md) uses the same commit format.

[`mise`](https://mise.jdx.dev/) installs development tools. It does not
start the check pipeline. The `pre-commit` and `pre-push` hooks run
`scripts/ci.sh` directly. `make ci` runs the same script and does not
call `mise`.

`scripts/ci.sh` can hand the run to the smolvm microVM. After the
`git` preflight it reads `SMOLVM_ENABLED`. The value `0` forces the
host path. The script prints no warning. The value `1` enforces smolvm.
The checks must run in a local microVM or on a remote server.

When enforced mode finds no usable smolvm and no remote address,
`scripts/ci.sh` prints an error on stderr and exits 3. The checks do
not run on the host. An unset variable or any other value selects auto
mode. With `smolvm` on `PATH` and a working accelerator (`/dev/kvm` on
Linux, `kern.hv_support=1` on macOS with Apple Silicon), it runs
`scripts/smolvm.sh`. Otherwise it prints a warning and runs the
checks on the host.

The microVM runs offline and mounts the repository read-only at
`/workspace`. `make smolvm-verify` checks that the isolation holds.
The [smolvm document](smolvm.md) describes this path.

Set `SMOLVM_CPUS` to change the CPU count of the microVM. Set
`SMOLVM_MEMORY_MB` to change its memory in MiB. The defaults are 1 CPU
and 512 MiB. Each value must be a positive integer. The local machine
and the remote machine both use the values. The scripts stop when a
value is not valid. See the [smolvm document](smolvm.md).

Set `SMOLVM_SERVE_ADDR` to send the checks to a remote `smolvm serve`
endpoint. `scripts/ci.sh` then calls `scripts/smolvm.sh`, which uses HTTP.
The checks run in a machine on that server. The working tree is uploaded
for each run with a portable copy of the git metadata. The client
resolves a worktree pointer on the host before upload. The checks need
the git history. The upload leaves out `.cache`, so no data comes from
the local pack cache. No host fallback exists in that mode. The
[smolvm document](smolvm.md) describes the remote flow and its security
boundary. A live run verified the API calls and remote exec. Remote mode
starts from `SMOLVM_SERVE_IMAGE`, which defaults to `debian:stable-slim`.
The `smol/init.sh` script installs the tools on every run. Remote mode
uses no pack cache. `make smolvm-pack` refuses to run while
`SMOLVM_SERVE_ADDR` is set. Unset the variable to build a local pack.
With a remote address, `make smolvm-clean` also deletes
`smolvm-remote-*` machines on the server. The full check run is not
verified over HTTP yet.

`make hooks` sets the hook path and makes the hooks executable.
`scripts/check-mise.sh` uses `mise` only to check `mise.toml`. It skips
that check when `mise` is absent.

## How the pieces fit

These commands and files form the pipeline:

- `scripts/ci.sh` runs every `scripts/check-*.sh` in name order. It
  stops when a check fails. It can hand the run to the smolvm microVM
  first. See the [smolvm document](smolvm.md).
- `make ci` runs `scripts/ci.sh`.
- `scripts/smolvm.sh` runs the checks inside a smolvm microVM against
  the live working tree. `make smolvm` calls it. The microVM is
  offline and the repository mount is read-only. With a remote address
  it uses the `smolvm serve` REST API and a machine on that server.
- `smol/verify.sh` verifies the isolation from inside the guest and
  from the host. `make smolvm-verify` calls it.
- `smol/pack-build.sh` builds the cached pack that the microVM runs
  from. `smol/init.sh` holds the provisioning steps for that build and
  for the remote run. `make smolvm-pack` calls the build script and
  refuses to run with `SMOLVM_SERVE_ADDR` set. `make smolvm-clean`
  removes the cached packs and deletes dangling `smolvm-build-*` and
  `smolvm-run-*` machines. With a remote address it also deletes
  `smolvm-remote-*` machines on the server. `make smolvm-exec` runs one
  command inside the microVM.
- `scripts/format.sh` runs every `scripts/format-*.sh` in name order. It
  stops when a formatter fails.
- `make format` runs `scripts/format.sh`.
- `.githook/commit-msg` runs `cog verify` on the commit message. A bad
  message stops the commit.
- `.githook/pre-commit` runs `scripts/ci.sh` before each commit.
- `.githook/pre-push` runs `scripts/ci.sh` before each push.
- `make hooks` sets `core.hooksPath` to `.githook`. It makes the hooks
  executable.

The `pre-commit` and `pre-push` hooks call `scripts/ci.sh` directly.
The `commit-msg` hook calls `cog verify`. No hook calls `mise`. If a
required tool is missing from `PATH`, the hook fails.

`scripts/ci.sh` prints `run: <script>` before each check. It prints
`all checks passed (N scripts)` after the last check. A failed check
stops the run. The exit status is non-zero. When the microVM handoff
happens, the guest prints these lines instead. The exit status still
propagates to the host.

## Run the checks locally

### Prerequisites

You need `git` and `make`. The checks need `cog`, `dclint`,
`dockerfmt`, `editorconfig-checker`, `gitleaks`, `hadolint`, `jactionlint`,
`markdownlint-cli2`, `shellcheck`, `shfmt`, and `zizmor` on `PATH`. `mise` is
optional. Run `make help` to list the available targets.

`make ci` runs the checks inside a smolvm microVM when `smolvm` is on
`PATH` and the host accelerator is available (`/dev/kvm` on Linux,
`kern.hv_support=1` on macOS with Apple Silicon). Without them it
prints a warning to stderr and runs the checks on the host. Set
`SMOLVM_ENABLED=1` to require smolvm. The run then fails with exit
code 3 instead of using the host. Set `SMOLVM_SERVE_ADDR` to use a
remote server instead. The remote path needs `curl` and `tar` on
`PATH`. The [smolvm document](smolvm.md) lists the requirements.

### Run all checks

Run this command:

```bash
make ci
```

Run this command from the repository root:

```bash
scripts/ci.sh
```

You can also run the script from any directory inside the repository.
`scripts/ci.sh` changes to the repository root after it starts.

`make ci` and `scripts/ci.sh` run the same checks. The `Makefile` target
calls the script.

The run stops when a check fails. Fix the problem. Then run the command
again.

### Run one check

Run these commands to check one area at a time:

```bash
make check-jactionlint
make check-bash
make check-commits
make check-dclint
make check-dockerfmt
make check-editorconfig
make check-gitleaks
make check-hadolint
make check-markdown
make check-mise
make check-shfmt
make check-zizmor
```

These targets call `scripts/check-jactionlint.sh`,
`scripts/check-bash.sh`, `scripts/check-commits.sh`,
`scripts/check-dclint.sh`, `scripts/check-dockerfmt.sh`,
`scripts/check-editorconfig.sh`, `scripts/check-gitleaks.sh`,
`scripts/check-hadolint.sh`,
`scripts/check-markdown.sh`, `scripts/check-mise.sh`,
`scripts/check-shfmt.sh`, and `scripts/check-zizmor.sh`.

Run this command from the repository root:

```bash
./scripts/check-bash.sh
```

The existing check scripts change to the repository root. A new check
script must also change to the repository root. The working tree is the
set of checked-out files in the repository.

`scripts/check-mise.sh` prints a skip message and exits 0 when `mise` is
absent. The script skips the check on purpose.

### Format the files

The checks do not change files. A check reports a problem and exits
non-zero. Use a format script to change the files.

Run this command to apply every formatter:

```bash
make format
```

`scripts/format.sh` runs each `scripts/format-*.sh` in name order. It
prints `run: <script>` before each script. It stops when a formatter
fails. It prints `all formatting applied (N scripts)` after the last
script. When no format script exists, it prints `no format scripts` and
exits 0. The run includes `scripts/format-shfmt.sh`,
`scripts/format-dockerfmt.sh`, and `scripts/format-dclint.sh`.

Run these commands to apply one formatter at a time:

```bash
make format-shfmt
make format-dockerfmt
make format-dclint
```

`scripts/format-shfmt.sh` runs `shfmt -i 2 -w` on the bash files. The
check script `scripts/check-shfmt.sh` runs `shfmt -i 2 -d` on the same
files. The check script does not write.

`scripts/format-dockerfmt.sh` runs `dockerfmt --write` on the Dockerfile
and Containerfile files. The check script `scripts/check-dockerfmt.sh`
runs `dockerfmt --check` on the same files. The check script does not
write.

`scripts/format-dclint.sh` runs `dclint --fix` on the Docker Compose
files. The check script `scripts/check-dclint.sh` runs `dclint` on the same
files. The check script does not write.

The workflow runs the check scripts only. Commit the changed files after
`make format`.

## Add a new check

1. Create `scripts/check-<area>.sh`. Replace `<area>` with the area name,
    for example `yaml`. Make the file executable:

    ```bash
    chmod +x scripts/check-<area>.sh
    ```

2. Start the file with a shebang, a short comment, and strict shell
    options:

    ```bash
    #!/usr/bin/env bash
    # Check every <area> file with <tool>.
    set -euo pipefail
    ```

3. Check each required command with `command -v`. Print an `error:`
    message to stderr when a command is missing. Exit non-zero.

4. Change to the repository root with `git rev-parse --show-toplevel`.
    Do not use a relative path or a hardcoded path.

5. Collect files from `git`. Include tracked and untracked files.
    Exclude ignored files. Do not use a hardcoded file list.

    ```bash
    mapfile -d '' -t files < <(
      git ls-files -z --cached --others --exclude-standard -- '<pattern>'
    )
    ```

    `--cached` selects tracked files. `--others` selects untracked files.
    `--exclude-standard` removes ignored files.

6. Run the tool in read-only mode. Do not pass a fix flag. Print one
    short result line. Return non-zero when the tool fails. `set -e`
    stops the script when the tool exits non-zero.

7. Add the tool to [`mise.toml`](../mise.toml) when it is a development
    dependency. Run `mise use <tool>@<major>`. Do not use `latest`. Do
    not use an exact pin unless you have a reason. A major constraint
    permits bug and security fixes.

    Some tools use a backend prefix in the `mise` key. The key can differ
    from the command name. Run this command to write
    `"npm:markdownlint-cli2" = "0"` in `mise.toml`:

    ```bash
    mise use npm:markdownlint-cli2@0
    ```

    The same command also provides the `markdownlint-cli2` command. Run
    this command to check that the command is on `PATH`:

    ```bash
    command -v markdownlint-cli2
    ```

    Do not check the `mise` key.

8. Run `make ci`. `scripts/ci.sh` finds the new file automatically. The
    file name sets the run order. A `Makefile` convenience target is
    optional for the pipeline. Add one when the repository convention
    expects a direct target.

9. Check the behavior when a check fails. Add a file with a known
    violation. Run `make ci`. Check for a non-zero exit. Remove the
    file. Check for an exit status of zero.

### When existing files fail the check

Fix the files. Do not disable the check or a rule. Add the check before
the files that must pass it. Then a bad file cannot enter the
repository. Do not add a config file that disables a rule.

### Example check script

The example is not in the repository. Do not add this file. The
example shows the required structure.

```bash
#!/usr/bin/env bash
# Check every YAML file with yamllint.
set -euo pipefail

if ! command -v git >/dev/null 2>&1; then
  echo "error: git is not on PATH. Install git first." >&2
  exit 1
fi

if ! command -v yamllint >/dev/null 2>&1; then
  echo "error: yamllint is not on PATH. Install yamllint first." >&2
  exit 1
fi

cd "$(git rev-parse --show-toplevel)"

mapfile -d '' -t files < <(
  git ls-files -z --cached --others --exclude-standard -- \
    '*.yml' '*.yaml'
)

if (( ${#files[@]} == 0 )); then
  echo "no YAML files"
  exit 0
fi

yamllint --strict "${files[@]}"
echo "checked ${#files[@]} YAML files"
```

The example file would be `scripts/check-yaml.sh`. You would install its
tool with `mise use yamllint@1`.

A `Makefile` target is optional. Add the target name to the `.PHONY`
line at the top of the [`Makefile`](../Makefile). Do this when you add a
target.

## Use `mise`

`mise` is the local installer for development tools. It does not start
the check pipeline. No check script requires `mise`. The scripts use
tools from `PATH`.

Keep one tool version list in [`mise.toml`](../mise.toml). A second list
can drift and produce different results.

## GitHub Actions

The workflow [`ci.yml`](../.github/workflows/ci.yml) runs the checks on
GitHub Actions. It runs on each pull request and each push to `main`.
The workflow has one matrix job with ten entries plus four extra jobs.

Each check job uses the `jdxcode/mise` image on the `ubuntu-24.04` runner.
The image provides `mise`, `git`, `curl`, and CA certificates. It provides
no project tool. The `dependency-review` job runs only on pull requests.
This job needs GitHub Advanced Security for private repositories.

Pin each image by digest and each action by commit SHA. Add a comment
that names the version of the pin. A fixed version gives the same result
on each run.

One matrix job runs the ten check scripts. Each matrix entry sets the
tool that its check needs. The matrix entry for `mise` installs no tool.

The workflow has no release job. The release stays local. The
[release workflow](release.md) describes the release steps.

### Required status checks

The fourteen job names are the status check names:

- `mise`
- `jactionlint`
- `bash`
- `shfmt`
- `commits`
- `markdown`
- `hadolint`
- `dockerfmt`
- `dclint`
- `zizmor`
- `PR title`
- `gitleaks`
- `editorconfig`
- `dependency-review`

`PR title` and `dependency-review` run only on pull requests.

Set these fourteen names as required status checks on the default branch.
Configure branch protection or rulesets on GitHub. Set them in the
repository settings. Do not set them in the repository files.

## Rules for a check script

A check script follows these rules:

- Do not use the network. A check that downloads data is not
  deterministic.
- Do not write to the working tree. Use a temporary directory for
  scratch files.
- Do not fix files. Report the problem and exit non-zero.
- Do not use secrets. A check must not need credentials.
- Write deterministic output. The same input gives the same result.
- Write short output. Print a result line. Print the tool output when a
  check fails.
- Exit non-zero when a check fails.

## Troubleshooting

### A required tool is not on `PATH`

Install the missing tool with your system package manager. Then open a
new shell.

If the tool is still absent, the check prints this message:

```text
error: shellcheck is not on PATH. Install shellcheck first.
```

### The `mise` config check did not run

`scripts/check-mise.sh` exits 0 when `mise` is absent. The check runs
when `mise` is on `PATH`.

The check prints this message:

```text
skip: mise is not on PATH. The mise config check did not run.
```

### The hooks do not run

Run this command:

```bash
make hooks
```

The target sets the hook path and makes the hooks executable. Then run
this command:

```bash
git config --get core.hooksPath
```

The output must be `.githook`. If the output is empty or different, run
`make hooks` again.

### A check passes on one machine but fails on another

A tool version or the environment differs. Align the tool with
[`mise.toml`](../mise.toml). Remove network access and file writes from
the check. Reproduce the problem in a clean checkout.

### `--no-verify` bypasses the hooks

`--no-verify` skips the commit or push hooks. Use it only in an
emergency. Do not use it to merge a failing change.
